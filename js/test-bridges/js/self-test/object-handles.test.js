import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import test from "node:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { defineBridge } from "../../_shared/bridge-definition.mjs";
import { ProcessBinding } from "../../_shared/register.mjs";
import { constructedTally, testObjectHandles } from "../../_shared/object-handles/suite.mjs";

// The neutral fixture ../../_shared/object-handles/suite.mjs describes.
const COUNTER = `export class Counter {
  #count;
  constructor(start) { this.#count = start; }
  get count() { return this.#count; }
  add(step) { this.#count += step; return this.#count; }
  self() { return this; }
  pair() { return [this, { inner: this }]; }
  holds(entries) { return entries.list[0] === this && entries.record.inner === this; }
}
export class Other {
  name() { return "other"; }
}
class Hidden {}
export function openCounter(start) { return new Counter(start); }
export function openOther() { return new Other(); }
export function openHidden() { return new Hidden(); }
export function same(left, right) { return left === right; }
class Base { action() { return "base"; } }
export class Shadowed extends Base { get action() { return "getter"; } }
export function openShadowed() { return new Shadowed(); }
export class CounterError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
export class Tally {
  #total;
  constructor(start) {
    if (typeof start !== "number" || start < 0)
      throw new CounterError("bad_start", "a tally starts at a non-negative number");
    this.#total = start;
  }
  add(step) { this.#total += step; return this.#total; }
}
export class Holder {
  #tally;
  #label;
  constructor(tally, label) { this.#tally = tally; this.#label = label; }
  native() { return this.#tally instanceof Tally; }
  tally() { return this.#tally; }
  bump(step) { return this.#tally.add(step); }
  label() { return this.#label; }
}
export class Odd {
  constructor() { return { plain: true }; }
}
`;

// A plausible wrong test target: its Tally ignores the start it receives.
const WRONG_COUNTER = `export class Tally {
  #total = 0;
  constructor(start) {}
  add(step) { this.#total += step; return this.#total; }
}
`;

const targetRoot = mkdtempSync(join(tmpdir(), "dca-object-handles-"));
writeFileSync(join(targetRoot, "counter.js"), COUNTER);
const wrongRoot = mkdtempSync(join(tmpdir(), "dca-object-handles-wrong-"));
writeFileSync(join(wrongRoot, "counter.js"), WRONG_COUNTER);

const counterUrl = pathToFileURL(join(targetRoot, "counter.js")).href;
test.after(() => {
  rmSync(targetRoot, { recursive: true, force: true });
  rmSync(wrongRoot, { recursive: true, force: true });
});

const bridge = defineBridge({
  id: "js",
  adapter: fileURLToPath(new URL("../adapter.mjs", import.meta.url)),
  targetRoot,
});

// A run registers a reference module's error classes when its fallback
// instance loads. This binding loads no module, so the test registers the
// target's CounterError under the ID the js adapter gives it.
const { CounterError } = await import(counterUrl);
const counterErrorId = `error-${Buffer.from("counter.js\0CounterError").toString("base64url")}`;

testObjectHandles({
  id: "js",
  start: async () => {
    const binding = await new ProcessBinding(bridge, { mode: "strict" }).start();
    binding.registerErrorType(counterErrorId, CounterError);
    return binding;
  },
});

test("js: a constructor that returns another object fails closed after dispatch", async () => {
  const binding = await new ProcessBinding(bridge, { mode: "strict" }).start();
  try {
    binding.describeModule("counter.js");
    assert.throws(
      () => binding.construct("counter.js", "Odd", []),
      /bridge refuses the result of new counter\.js Odd: the test target answered no object of the class/,
    );
    assert.equal(binding.externalCalls, 1, "the call was dispatched and counted");
  } finally {
    await binding.dispose();
  }
});

test("js: a wrong test target whose constructor drops its input fails the result assertion", async () => {
  const wrong = defineBridge({
    id: "js",
    adapter: fileURLToPath(new URL("../adapter.mjs", import.meta.url)),
    targetRoot: wrongRoot,
  });
  const binding = await new ProcessBinding(wrong, { mode: "strict" }).start();
  try {
    assert.throws(() => constructedTally(binding), {
      name: "AssertionError",
      message: /the object holds the start its constructor received/,
    });
  } finally {
    await binding.dispose();
  }
});

test("js: a getter shadows an inherited method during class discovery", async () => {
  const binding = await new ProcessBinding(bridge, { mode: "strict" }).start();
  try {
    const members = binding.describeModule("counter.js");
    const operation = members.find((entry) => entry.sourceExport === "openShadowed");
    assert.ok(operation);
    const described = binding.moduleClasses
      .get("counter.js")
      ?.find((entry) => entry.sourceExport === "Shadowed");
    assert.ok(described);
    assert.equal(
      described.members.some((entry) => entry.sourceMember === "action"),
      false,
    );
    const shadowed = /** @type {any} */ (binding.call(operation.id, []));
    assert.throws(() => shadowed.action, /claims no member action/);
  } finally {
    await binding.dispose();
  }
});
