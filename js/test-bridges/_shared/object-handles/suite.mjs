import test from "node:test";
import assert from "node:assert/strict";

/** @typedef {import("../register.mjs").ProcessBinding} ProcessBinding */

/**
 * Proves that a target adapter carries objects of its claimed classes as
 * session handles. Each adapter's `self-test/object-handles.test.js` calls
 * `testObjectHandles` with a function that starts a binding over a native
 * fixture for `counter.js`. The fixture is neutral; no class in it stands for
 * a protocol type. The module exports, under these reference names:
 *
 * - `openCounter(start)`, a static factory or function that returns a new
 *   `Counter` holding `start`;
 * - `openOther()`, which returns a new `Other`;
 * - `openHidden()`, which returns an object of a class the module does not
 *   export, and which the adapter therefore cannot carry;
 * - `same(left, right)`, which answers whether both arguments are one object;
 * - class `Counter`, whose instances claim `add(step)` (adds `step` and
 *   returns the new total), `self()` (returns the instance itself), `pair()`
 *   (returns `[this, { inner: this }]`) and `holds(entries)` (answers whether
 *   `entries.list[0]` and `entries.record.inner` are both the instance). A
 *   `count` that reads the total is a getter or property, not a method, so
 *   the adapter does not claim it;
 * - class `Other`, whose instances claim `name()`, which returns `"other"`;
 * - class `Tally`, whose constructor takes `start` and whose instances claim
 *   `add(step)` (adds `step` and returns the new total). A `start` that is
 *   no number or below zero makes the constructor throw the module's
 *   `CounterError` with code `bad_start` and message
 *   `a tally starts at a non-negative number`;
 * - class `Holder`, whose constructor takes a `Tally` and a label, and whose
 *   instances claim `native()` (answers whether it holds an object of the
 *   test target's own `Tally` class), `tally()` (returns the held tally),
 *   `bump(step)` (calls the held tally's `add(step)`) and `label()`;
 * - error class `CounterError`, which the test target maps.
 *
 * The test target claims the constructors of `Tally` and `Holder`. The
 * driver maps `CounterError` refusals to a class the adapter's test
 * registers before the suite runs.
 *
 * Expected values and verdicts stay in this suite.
 */

/**
 * @typedef {{ binding: ProcessBinding, operation: (name: string) => string, member: (className: string, name: string) => string, handleClass: (className: string) => string, construct: (className: string) => string }} Session
 */

/**
 * Describes `counter.js` in a started binding and names its operations.
 *
 * @param {ProcessBinding} binding
 * @returns {Session}
 */
function session(binding) {
  const members = binding.describeModule("counter.js");
  const classes = binding.moduleClasses.get("counter.js") ?? [];
  /** @param {string} className */
  const described = (className) => {
    const found = classes.find((entry) => entry.sourceExport === className);
    assert.ok(found, `counter.js declares class ${className}`);
    return found;
  };
  return {
    binding,
    operation: (name) => {
      const found = members.find((entry) => entry.sourceExport === name);
      assert.ok(found, `counter.js exports ${name}`);
      return found.id;
    },
    member: (className, name) => {
      const found = described(className).members.find((entry) => entry.sourceMember === name);
      assert.ok(found, `${className} claims ${name}`);
      return found.id;
    },
    handleClass: (className) => described(className).id,
    construct: (className) => {
      const found = described(className).construct;
      assert.ok(found, `${className} claims its constructor`);
      return found.id;
    },
  };
}

/**
 * Builds a `Tally` from 5 in the test target and checks the state its
 * constructor set: the result assertion a wrong test target must fail.
 *
 * @param {ProcessBinding} binding @returns {any} the tally's handle proxy
 */
export function constructedTally(binding) {
  binding.describeModule("counter.js");
  const tally = /** @type {any} */ (binding.construct("counter.js", "Tally", [5]));
  assert.equal(tally.add(1), 6, "the object holds the start its constructor received");
  return tally;
}

/**
 * Sends a call frame as is and returns the adapter's result.
 *
 * @param {ProcessBinding} binding @param {Record<string, unknown>} frame
 */
function raw(binding, frame) {
  const response = /** @type {any} */ (
    binding.request({ version: 1, type: "call", protocol: "dca-test-bridge/v1", ...frame })
  );
  return response.result;
}

/**
 * Registers the handle tests for one adapter.
 *
 * @param {{ id: string, start: () => Promise<ProcessBinding>, skip?: string }} options
 *   `start` returns a started binding over the fixture, in strict mode.
 *   `skip` reports every test as skipped with that reason.
 */
export function testObjectHandles(options) {
  const skip = options.skip === undefined ? {} : { skip: options.skip };
  /** @type {ProcessBinding[]} */
  const started = [];
  const start = async () => {
    const binding = await options.start();
    started.push(binding);
    return session(binding);
  };
  test.after(async () => {
    for (const binding of started) await binding.dispose();
  });

  test(
    `${options.id}: a factory's object crosses as a handle whose members run in the test target`,
    skip,
    async () => {
      const { binding, operation, member } = await start();
      const counter = /** @type {any} */ (binding.call(operation("openCounter"), [1]));
      assert.equal(counter.add(2), 3);
      assert.equal(counter.add(1), 4, "the object keeps its state in the test target");
      const again = /** @type {any} */ (binding.call(operation("openCounter"), [10]));
      assert.notEqual(again, counter);
      assert.equal(again.add(0), 10);
      // Direct calls are the ones the dispatcher sees: the factory twice and
      // three member calls. What the factory does inside the test target is not.
      assert.deepEqual(binding.routes[operation("openCounter")], { external: 2, reference: 0 });
      assert.deepEqual(binding.routes[member("Counter", "add")], { external: 3, reference: 0 });
    },
  );

  test(
    `${options.id}: a handle that comes back again is the same proxy, nested or not`,
    skip,
    async () => {
      const { binding, operation } = await start();
      const counter = /** @type {any} */ (binding.call(operation("openCounter"), [1]));
      assert.equal(counter.self(), counter);
      const [first, { inner }] = counter.pair();
      assert.equal(first, counter);
      assert.equal(inner, counter);
    },
  );

  test(
    `${options.id}: a handle argument reaches the test target as the object it names, at any depth`,
    skip,
    async () => {
      const { binding, operation, handleClass } = await start();
      const counter = /** @type {any} */ (binding.call(operation("openCounter"), [1]));
      const other = /** @type {any} */ (binding.call(operation("openCounter"), [1]));
      assert.equal(counter.holds({ list: [counter], record: { inner: counter } }), true);
      assert.equal(counter.holds({ list: [other], record: { inner: counter } }), false);
      assert.equal(binding.call(operation("same"), [counter, counter]), true);
      assert.equal(binding.call(operation("same"), [counter, other]), false);
      // A record shaped like a handle is data. The target receives a record.
      const lookalike = { $type: "Handle", class: handleClass("Counter"), handle: "h" };
      assert.equal(binding.call(operation("same"), [lookalike, counter]), false);
    },
  );

  test(
    `${options.id}: a claimed class supports only the members the test target claims`,
    skip,
    async () => {
      const { binding, operation, member, handleClass } = await start();
      const counter = /** @type {any} */ (binding.call(operation("openCounter"), [1]));
      const other = /** @type {any} */ (binding.call(operation("openOther"), []));
      assert.equal(other.name(), "other");
      assert.throws(
        () => counter.count,
        /counter\.js Counter: the test target claims no member count/,
      );
      assert.throws(() => counter.name(), /claims no member name/);
      assert.throws(() => other.add(1), /counter\.js Other: the test target claims no member add/);
      assert.equal(Object.getPrototypeOf(counter), null, "a proxy borrows no reference prototype");
      const calls = binding.externalCalls;
      // The adapter refuses frames the driver would not send, and invokes nothing.
      const receiver = binding.handles.encode(counter);
      const otherReceiver = binding.handles.encode(other);
      const refusals = [
        raw(binding, { operation: member("Counter", "add"), input: [1] }),
        raw(binding, { operation: member("Counter", "add"), input: [1], receiver: otherReceiver }),
        raw(binding, { operation: operation("same"), input: [1, 1], receiver }),
        raw(binding, {
          operation: member("Counter", "add"),
          input: [1],
          receiver: { ...receiver, handle: `${receiver?.handle}-forged` },
        }),
        raw(binding, {
          operation: member("Counter", "add"),
          input: [1],
          receiver: { ...receiver, class: handleClass("Other") },
        }),
      ];
      for (const result of refusals) {
        assert.equal(result.kind, "refusal", JSON.stringify(result));
        assert.equal(result.code, "adapter_refusal");
        assert.equal(Object.hasOwn(result, "errorType"), false);
      }
      assert.equal(counter.add(0), 1, "no refused frame reached the object");
      assert.equal(binding.externalCalls, calls + 1);
    },
  );

  test(
    `${options.id}: an object the adapter cannot carry fails the call and carries no target code`,
    skip,
    async () => {
      const { binding, operation } = await start();
      assert.throws(
        () => binding.call(operation("openHidden"), []),
        (/** @type {any} */ error) =>
          /bridge cannot carry the result of counter\.js openHidden/.test(error.message) &&
          error.code === undefined,
      );
      assert.equal(binding.uncarriedResults, 1);
    },
  );

  test(`${options.id}: a handle is valid only in the session that issued it`, skip, async () => {
    const first = await start();
    const second = await start();
    const counter = /** @type {any} */ (first.binding.call(first.operation("openCounter"), [1]));
    const calls = second.binding.externalCalls;
    assert.throws(
      () => second.binding.call(second.operation("same"), [counter, counter]),
      /bridge handle belongs to another session/,
    );
    assert.equal(second.binding.externalCalls, calls, "the driver refused before dispatch");
    // A second adapter process does not know the first one's handle.
    const foreign = raw(second.binding, {
      operation: second.member("Counter", "add"),
      input: [1],
      receiver: first.binding.handles.encode(counter),
    });
    assert.equal(foreign.kind, "refusal");
    assert.equal(foreign.code, "adapter_refusal");
    assert.match(foreign.message, /bridge handle is not live in this session/);
    await first.binding.dispose();
    assert.throws(() => counter.add(1), /bridge handle belongs to a disposed session/);
    assert.throws(
      () => second.binding.call(second.operation("same"), [counter, counter]),
      /bridge handle belongs to a disposed session/,
    );
  });

  test(
    `${options.id}: a claimed constructor builds each object in the test target and answers its handle`,
    skip,
    async () => {
      const { binding, construct } = await start();
      const tally = constructedTally(binding);
      assert.equal(tally.add(1), 7, "later calls reach the same native object");
      const second = /** @type {any} */ (binding.construct("counter.js", "Tally", [10]));
      assert.notEqual(second, tally);
      assert.notEqual(
        binding.handles.encode(second)?.handle,
        binding.handles.encode(tally)?.handle,
      );
      assert.equal(second.add(0), 10);
      assert.equal(tally.add(0), 7, "the second object has its own state");
      assert.deepEqual(binding.routes[construct("Tally")], { external: 2, reference: 0 });
      assert.equal(binding.operationName(construct("Tally")), "new counter.js Tally");
      // What the route does not promise: the proxy is no reference instance.
      assert.equal(Object.getPrototypeOf(tally), null);
    },
  );

  test(
    `${options.id}: a handle given to a constructor reaches it as the native object`,
    skip,
    async () => {
      const { binding } = await start();
      binding.describeModule("counter.js");
      const tally = /** @type {any} */ (binding.construct("counter.js", "Tally", [1]));
      const holder = /** @type {any} */ (binding.construct("counter.js", "Holder", [tally, "h"]));
      assert.equal(holder.native(), true, "the constructor received the test target's own object");
      assert.equal(holder.tally(), tally, "the held object comes back as the same proxy");
      assert.equal(holder.label(), "h");
      assert.equal(holder.bump(2), 3);
      assert.equal(tally.add(0), 3, "both objects share one native tally, not a copy");
    },
  );

  test(
    `${options.id}: a constructor that throws answers the test target's refusal, not a bridge refusal`,
    skip,
    async () => {
      const { binding, construct } = await start();
      binding.describeModule("counter.js");
      const refused = raw(binding, { operation: construct("Tally"), input: [-1] });
      assert.equal(refused.kind, "refusal", JSON.stringify(refused));
      assert.equal(refused.code, "bad_start");
      assert.equal(typeof refused.errorType, "string", "a mapped target error names its type");
      assert.throws(
        () => binding.construct("counter.js", "Tally", [-1]),
        (/** @type {any} */ error) =>
          error.code === "bad_start" && error.message === "a tally starts at a non-negative number",
      );
      assert.deepEqual(binding.routes[construct("Tally")], { external: 1, reference: 0 });
    },
  );

  test(
    `${options.id}: a constructor the test target does not claim is refused before dispatch`,
    skip,
    async () => {
      const { binding, construct } = await start();
      binding.describeModule("counter.js");
      const calls = binding.externalCalls;
      assert.throws(
        () => binding.construct("counter.js", "Hidden", []),
        /strict bridge run: new counter\.js Hidden is not claimed by the test target/,
      );
      assert.equal(binding.externalCalls, calls, "nothing was dispatched");
      // The adapter refuses a constructor frame with a receiver, and builds nothing.
      const tally = /** @type {any} */ (binding.construct("counter.js", "Tally", [1]));
      const receiver = binding.handles.encode(tally);
      const refused = raw(binding, { operation: construct("Tally"), input: [2], receiver });
      assert.equal(refused.kind, "refusal", JSON.stringify(refused));
      assert.equal(refused.code, "adapter_refusal");
      assert.equal(Object.hasOwn(refused, "errorType"), false);
    },
  );
}
