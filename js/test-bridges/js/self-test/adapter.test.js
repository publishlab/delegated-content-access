import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { defineBridge } from "../../_shared/bridge-definition.mjs";
import { ProcessBinding } from "../../_shared/register.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const geometryTest = join(root, "test-reference/core-shared/geometry-bounds.test.js");
const bridgePreload = join(root, "test-bridges/js/bridge.mjs");
const adapterScript = join(root, "test-bridges/js/adapter.mjs");
const bridge = defineBridge({ id: "js", adapter: adapterScript, targetRoot: root });

test("refusal errors restore mapped prototypes and native error names", () => {
  class FixtureError extends Error {}
  const binding = new ProcessBinding(/** @type {any} */ ({}));
  binding.errorTypes.set("error-fixture", {
    constructor: FixtureError,
    prototype: FixtureError.prototype,
  });
  const mapped = binding.refusalError({
    errorType: "error-fixture",
    code: "fixture_refused",
    message: "mapped",
  });
  assert.ok(mapped instanceof FixtureError);
  assert.equal(mapped.code, "fixture_refused");
  const native = binding.refusalError({
    errorType: "native-dom:InvalidCharacterError",
    code: "invalid",
    message: "native",
  });
  assert.equal(native.name, "InvalidCharacterError");
  const type = binding.refusalError({
    errorType: "native:TypeError",
    code: "type",
    message: "type",
  });
  assert.ok(type instanceof TypeError);
});

test("a rebuilt error keeps the name its class sets and the code it carried", () => {
  class NamedError extends Error {
    /** @param {string} code @param {string} message */
    constructor(code, message) {
      super(message);
      this.name = "NamedError";
      this.code = code;
    }
  }
  class UnnamedError extends Error {}
  const binding = new ProcessBinding(/** @type {any} */ ({}));
  binding.registerErrorType("error-named", NamedError);
  binding.registerErrorType("error-unnamed", UnnamedError);
  const named = binding.refusalError({ errorType: "error-named", code: "named", message: "m" });
  assert.ok(named instanceof NamedError);
  assert.equal(named.name, "NamedError");
  assert.deepEqual(
    Object.getOwnPropertyDescriptor(named, "name"),
    Object.getOwnPropertyDescriptor(new NamedError("named", "m"), "name"),
  );
  const unnamed = binding.refusalError({ errorType: "error-unnamed", code: "u", message: "m" });
  assert.equal(unnamed.name, "Error");
  assert.equal(Object.hasOwn(unnamed, "name"), false);
  const native = binding.refusalError({
    errorType: "native:TypeError",
    code: "ERR_FIXTURE",
    message: "native",
  });
  assert.ok(native instanceof TypeError);
  assert.equal(/** @type {any} */ (native).code, "ERR_FIXTURE");
});

test("mapped error IDs keep same-named constructors distinct", () => {
  class FirstError extends Error {}
  class SecondError extends Error {}
  Object.defineProperty(FirstError, "name", { value: "SameName" });
  Object.defineProperty(SecondError, "name", { value: "SameName" });
  const binding = new ProcessBinding(/** @type {any} */ ({}));
  binding.errorTypes.set("error-first", {
    constructor: FirstError,
    prototype: FirstError.prototype,
  });
  binding.errorTypes.set("error-second", {
    constructor: SecondError,
    prototype: SecondError.prototype,
  });
  const second = binding.refusalError({
    errorType: "error-second",
    code: "second",
    message: "second",
  });
  assert.ok(second instanceof SecondError);
  assert.equal(second instanceof FirstError, false);
});

test("async exports are discovered and dispatched through the async binding", async () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-async-target-"));
  writeFileSync(
    join(targetRoot, "fixture.mjs"),
    "export async function double(value) { return value * 2; }\n",
  );
  const binding = await new ProcessBinding({ ...bridge, targetRoot }).start();
  try {
    const member = binding
      .describeModule("fixture.mjs")
      .find((entry) => entry.sourceExport === "double");
    assert.ok(member);
    assert.equal(member?.callShape, "async");
    assert.equal(await binding.callAsync(member.id, [21]), 42);
  } finally {
    await binding.dispose();
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("strict mode uses a distinguishable alternate test-target result without importing a fallback", () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-target-"));
  const modulePath = join(targetRoot, "core-shared/geometryBounds.js");
  mkdirSync(dirname(modulePath), { recursive: true });
  writeFileSync(
    modulePath,
    `export function inspectPeriodGeometryBounds(chainsPerDay, periodMinutes) {
  if (!Number.isInteger(chainsPerDay) || chainsPerDay <= 0 || 1440 % chainsPerDay) return { kind: "invalidChainsPerDay" };
  const windowMinutes = 1440 / chainsPerDay;
  if (!Number.isInteger(periodMinutes) || periodMinutes <= 0 || windowMinutes % periodMinutes) return { kind: "invalidPeriodMinutes", windowMinutes };
  const positionsPerWindow = windowMinutes / periodMinutes;
  return positionsPerWindow > 288 ? { kind: "tooManyPositions", windowMinutes, positionsPerWindow } : { kind: "valid", windowMinutes, positionsPerWindow };
}\n`,
  );
  try {
    assert.match(
      execFileSync(
        process.execPath,
        ["--import", bridgePreload, "--test", "--test-reporter=tap", geometryTest],
        {
          cwd: root,
          env: {
            ...process.env,
            DCA_BRIDGE_MODE: "strict",
            DCA_TARGET_ROOT: targetRoot,
            NODE_TEST_CONTEXT: undefined,
          },
          encoding: "utf8",
        },
      ),
      /^# pass [1-9]\d*$/m,
    );
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("strict mode keeps driver-owned helper modules on the driver side", () => {
  // The alternate root claims a test helper with a sentinel answer. Only
  // implementation modules may cross, so the test must still see the real
  // helper. The geometry copy gives the strict run one real external call.
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-target-"));
  const driver = mkdtempSync(join(tmpdir(), "dca-driver-"));
  const helper = join(targetRoot, "test-reference/support/keys.js");
  const geometry = join(targetRoot, "core-shared/geometryBounds.js");
  mkdirSync(dirname(helper), { recursive: true });
  mkdirSync(dirname(geometry), { recursive: true });
  writeFileSync(helper, 'export function periodKey() { return "target-sentinel"; }\n');
  copyFileSync(join(root, "core-shared/geometryBounds.js"), geometry);
  const probe = join(driver, "helper.test.js");
  const url = (/** @type {string} */ path) => JSON.stringify(pathToFileURL(join(root, path)).href);
  writeFileSync(
    probe,
    `import test from "node:test";
import assert from "node:assert/strict";
import { periodKey } from ${url("test-reference/support/keys.js")};
import { inspectPeriodGeometryBounds } from ${url("core-shared/geometryBounds.js")};
test("the helper answers locally", () => {
  assert.deepEqual(periodKey(7), new Uint8Array(16).fill(7));
  assert.equal(inspectPeriodGeometryBounds(5, 1).kind, "valid");
});
`,
  );
  try {
    const environment = { ...process.env, DCA_BRIDGE_MODE: "strict", DCA_TARGET_ROOT: targetRoot };
    delete environment.NODE_TEST_CONTEXT;
    const run = spawnSync(process.execPath, ["--import", bridgePreload, "--test", probe], {
      cwd: root,
      env: environment,
      encoding: "utf8",
    });
    assert.equal(run.status, 0, run.stdout);
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
    rmSync(driver, { recursive: true, force: true });
  }
});

test("strict mode fails the unchanged test against a wrong test target", () => {
  // A wrong windowMinutes must turn the unchanged geometry test red. A bridge that
  // silently answered from the reference would pass here.
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-target-"));
  const modulePath = join(targetRoot, "core-shared/geometryBounds.js");
  mkdirSync(dirname(modulePath), { recursive: true });
  writeFileSync(
    modulePath,
    `export function inspectPeriodGeometryBounds(chainsPerDay, periodMinutes) {
  if (!Number.isInteger(chainsPerDay) || chainsPerDay <= 0 || 1440 % chainsPerDay) return { kind: "invalidChainsPerDay" };
  const windowMinutes = 1440 / chainsPerDay + 1;
  return { kind: "invalidPeriodMinutes", windowMinutes };
}\n`,
  );
  try {
    const environment = { ...process.env, DCA_BRIDGE_MODE: "strict", DCA_TARGET_ROOT: targetRoot };
    delete environment.NODE_TEST_CONTEXT;
    const run = spawnSync(
      process.execPath,
      ["--import", bridgePreload, "--test", "--test-reporter=tap", geometryTest],
      {
        cwd: root,
        env: environment,
        encoding: "utf8",
      },
    );
    assert.notEqual(run.status, 0, run.stdout);
    assert.match(run.stdout, /# fail [1-9]/);
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("strict mode fails a call to a function export the test target does not claim; overlay runs it on the reference", () => {
  // The test target claims only isTransportFailureCode from core-shared/errors.js.
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-target-"));
  const probeRoot = mkdtempSync(join(tmpdir(), "dca-probe-"));
  const modulePath = join(targetRoot, "core-shared/errors.js");
  mkdirSync(dirname(modulePath), { recursive: true });
  writeFileSync(
    modulePath,
    `export function isTransportFailureCode(code) { return code === "transport"; }\n`,
  );
  const probe = join(probeRoot, "probe.test.mjs");
  writeFileSync(
    probe,
    `import test from "node:test";
import assert from "node:assert/strict";
import { DcaError, WITHHELD_CODES, dcaError, isTransportFailureCode } from ${JSON.stringify(pathToFileURL(join(root, "core-shared/errors.js")).href)};
test("probe", () => {
  assert.equal(isTransportFailureCode("transport"), true);
  // A class and a value export stay the reference's in both modes.
  assert.ok(new DcaError("c", "m") instanceof Error);
  assert.equal(typeof WITHHELD_CODES, "object");
  if (process.env.DCA_BRIDGE_MODE === "strict")
    assert.throws(() => dcaError("c", "m"), {
      message: "strict bridge run: core-shared/errors.js#dcaError is not claimed by the test target",
    });
  else assert.ok(dcaError("c", "m") instanceof DcaError);
});
`,
  );
  try {
    for (const mode of ["strict", "overlay"]) {
      const environment = { ...process.env, DCA_BRIDGE_MODE: mode, DCA_TARGET_ROOT: targetRoot };
      delete environment.NODE_TEST_CONTEXT;
      const run = spawnSync(
        process.execPath,
        ["--import", bridgePreload, "--test", "--test-reporter=tap", probe],
        {
          cwd: root,
          env: environment,
          encoding: "utf8",
        },
      );
      assert.equal(run.status, 0, `${mode}\n${run.stdout}${run.stderr}`);
      assert.match(run.stdout, /^# pass 1$/m);
    }
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
    rmSync(probeRoot, { recursive: true, force: true });
  }
});

test("the JS adapter refuses to start without a target root", () => {
  const environment = { ...process.env };
  delete environment.DCA_TARGET_ROOT;
  delete environment.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, [adapterScript], {
    cwd: root,
    env: environment,
    input: "",
    encoding: "utf8",
  });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /DCA_TARGET_ROOT names the test-target root/);
});

/**
 * Starts the JS adapter on a temporary target holding `fixture.mjs` and hands
 * the started binding and the fixture's members to `body`.
 *
 * @param {string} source
 * @param {{ mode?: 'overlay'|'strict', transcriptPath?: string }} options
 * @param {(binding: ProcessBinding, member: (name: string) => string) => Promise<void>} body
 */
async function withFixture(source, options, body) {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-fixture-target-"));
  writeFileSync(join(targetRoot, "fixture.mjs"), source);
  const binding = await new ProcessBinding({ ...bridge, targetRoot }, options).start();
  try {
    const members = binding.describeModule("fixture.mjs");
    await body(binding, (name) => {
      const found = members.find((entry) => entry.sourceExport === name);
      assert.ok(found, `fixture.mjs ${name} is claimed`);
      return found.id;
    });
  } finally {
    await binding.dispose();
    rmSync(targetRoot, { recursive: true, force: true });
  }
}

const UNCARRIED_FIXTURE = `export function handle() { return { run: () => 1 }; }
export async function handleLater() { return { run: () => 1 }; }
export function fill(map) { map.filled = true; return true; }
export function refuse() { throw new TypeError("the target refused"); }
export function* numbers() { yield 1; }
export async function* later() { yield 1; }
`;

test("a result the bridge cannot carry is uncarried, not a target error", async () => {
  await withFixture(UNCARRIED_FIXTURE, { mode: "strict" }, async (binding, member) => {
    const response = /** @type {any} */ (
      binding.request({
        version: 1,
        type: "call",
        protocol: "dca-test-bridge/v1",
        operation: member("handle"),
        input: [],
      })
    );
    assert.equal(response.result.kind, "uncarried");
    assert.throws(
      () => binding.call(member("handle"), []),
      /^Error: bridge cannot carry the result of fixture\.mjs handle/,
    );
    // A call that changes its arguments has an effect the bridge cannot carry back.
    assert.throws(
      () => binding.call(member("fill"), [{}]),
      /bridge cannot carry the result of fixture\.mjs fill: the call changed its arguments/,
    );
    assert.equal(binding.externalCalls, 0);
  });
});

test("the JS adapter declares its whole answer, so the driver converts nothing it returns", async () => {
  const source = `export function empty() { return []; }
export function text() { return "k"; }
`;
  await withFixture(source, { mode: "strict" }, async (binding, member) => {
    binding.referenceShapes = {
      version: 1,
      modules: {
        "fixture.mjs": { empty: { record: {} }, text: { anyOf: ["Uint8Array", "null"] } },
      },
    };
    const response = /** @type {any} */ (
      binding.request({
        version: 1,
        type: "call",
        protocol: "dca-test-bridge/v1",
        operation: member("empty"),
        input: [],
      })
    );
    assert.equal(response.result.declared, "all");
    assert.throws(
      () => binding.call(member("empty"), []),
      /bridge refuses the result of fixture\.mjs empty: the test target declares list at the result, where the reference type admits record/,
    );
    assert.throws(
      () => binding.call(member("text"), []),
      /declares string at the result, where the reference type admits Uint8Array or null/,
    );
  });
});

test("overlay fails an uncarried call as strict does and counts it apart from external calls", async () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-bridge-"));
  const transcriptPath = join(directory, "worker.transcript.jsonl");
  try {
    await withFixture(
      UNCARRIED_FIXTURE,
      { mode: "overlay", transcriptPath },
      async (binding, member) => {
        // The test target already ran each call, so nothing reruns it.
        assert.throws(
          () => binding.call(member("handle"), []),
          /^Error: bridge cannot carry the result of fixture\.mjs handle/,
        );
        await assert.rejects(
          binding.callAsync(member("handleLater"), []),
          /^Error: bridge cannot carry the result of fixture\.mjs handleLater/,
        );
        const argument = {};
        assert.throws(
          () => binding.call(member("fill"), [argument]),
          /bridge cannot carry the result of fixture\.mjs fill: the call changed its arguments/,
        );
        assert.deepEqual(argument, {});
        // A target that throws still fails closed.
        assert.throws(() => binding.call(member("refuse"), []), {
          name: "TypeError",
          message: "the target refused",
        });
        assert.equal(binding.externalCalls, 1);
        assert.equal(binding.referenceFallbacks, 0);
        assert.equal(binding.uncarriedResults, 3);
      },
    );
    const records = readFileSync(transcriptPath, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.deepEqual(
      records.map((record) => record.event),
      ["capabilities", "module", "uncarried", "uncarried", "uncarried", "call", "final"],
    );
    assert.equal(records[2].response.result.kind, "uncarried");
    assert.deepEqual(records[4].input, [{}]);
    const final = records.at(-1);
    assert.equal(final.uncarriedResults, 3);
    assert.equal(final.externalCalls, 1);
    assert.equal(final.referenceFallbacks, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("discovery leaves generator functions to the reference", async () => {
  await withFixture(UNCARRIED_FIXTURE, {}, async (binding) => {
    const claimed = binding.moduleDescriptions
      .get("fixture.mjs")
      ?.map((entry) => entry.sourceExport);
    assert.deepEqual(claimed, ["fill", "handle", "handleLater", "refuse"]);
  });
});

test("a sync export that returns a promise still returns one through the bridge", async () => {
  const source = `export function later(value) { return Promise.resolve(value * 2); }
export function laterRefused() { return Promise.reject(new TypeError("later refused")); }
export function laterKey() {
  return crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
}
export function now(value) { if (value < 0) throw new RangeError("now refused"); return value; }
`;
  await withFixture(source, { mode: "strict" }, async (binding, member) => {
    const later = binding.call(member("later"), [21]);
    assert.ok(later instanceof Promise);
    assert.equal(await later, 42);
    const refused = binding.call(member("laterRefused"), []);
    assert.ok(refused instanceof Promise);
    await assert.rejects(refused, { name: "TypeError", message: "later refused" });
    const key = /** @type {CryptoKey} */ (await binding.call(member("laterKey"), []));
    assert.equal(key.type, "secret");
    // A plain sync export keeps its immediate return and throw.
    assert.equal(binding.call(member("now"), [3]), 3);
    assert.throws(() => binding.call(member("now"), [-1]), { name: "RangeError" });
  });
});

/**
 * A neutral class that wraps one record, on the driver side. The fixture test
 * target defines its own class of the same shape in `box.mjs`.
 */
class Box {
  #document;
  /** @param {unknown} document */
  constructor(document) {
    this.#document = document;
  }
  data() {
    return this.#document;
  }
}

const BOX_TARGET = {
  "box.mjs": `export class Box {
  #document;
  constructor(document) { this.#document = document; }
  data() { return this.#document; }
}
`,
  "fixture.mjs": `import { Box } from "./box.mjs";
const seen = (value) => (value instanceof Box ? { box: value.data() } : { plain: value });
export function unwrap(box, other) { return { first: seen(box), second: seen(other) }; }
export async function later(box) { return seen(box); }
export function echo(value) { return seen(value); }
export function touch(box) { box.data().n += 1; return true; }
`,
};

/** @param {string} sourceExport */
function boxInput(sourceExport) {
  return {
    module: "fixture.mjs",
    export: sourceExport,
    argument: 0,
    class: { module: "box.mjs", export: "Box" },
    data: "data",
    type: Box,
  };
}

test("a listed instance crosses as its data and the JS adapter rebuilds the test target's own class", async () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-input-target-"));
  for (const [name, source] of Object.entries(BOX_TARGET))
    writeFileSync(join(targetRoot, name), source);
  const binding = await new ProcessBinding(
    { ...bridge, targetRoot },
    {
      mode: "strict",
      inputs: [boxInput("unwrap"), boxInput("later"), boxInput("touch")],
    },
  ).start();
  /** @type {any[]} */
  const sent = [];
  const request = binding.request.bind(binding);
  binding.request = (message) => {
    if (message.type === "call") sent.push(message);
    return request(message);
  };
  try {
    const members = binding.describeModule("fixture.mjs");
    const member = (/** @type {string} */ name) =>
      /** @type {string} */ (members.find((entry) => entry.sourceExport === name)?.id);

    assert.deepEqual(binding.call(member("unwrap"), [new Box({ n: 1 }), 2]), {
      first: { box: { n: 1 } },
      second: { plain: 2 },
    });
    assert.deepEqual(sent.at(-1).input, [{ n: 1 }, 2]);
    assert.deepEqual(sent.at(-1).instances, [
      { argument: 0, sourceModule: "box.mjs", sourceExport: "Box" },
    ]);
    assert.deepEqual(await binding.callAsync(member("later"), [new Box({ n: 3 })]), {
      box: { n: 3 },
    });
    assert.equal(await binding.canCarryAsync([new Box({ n: 3 })], member("later")), true);

    // An unlisted argument holding the same class keeps its prior path: the
    // bridge cannot carry it, so overlay falls back and strict fails before
    // dispatch. That holds for another position and for another export.
    const before = sent.length;
    const twoBoxes = [new Box({ n: 1 }), new Box({ n: 2 })];
    assert.equal(binding.canCarry(twoBoxes, member("unwrap")), false);
    assert.throws(() => binding.call(member("unwrap"), twoBoxes), /bridge values are JSON data/);
    assert.equal(binding.canCarry([new Box({ n: 1 })], member("echo")), false);
    assert.throws(() => binding.call(member("echo"), [new Box({ n: 1 })]), /bridge values/);
    assert.deepEqual(binding.call(member("echo"), [{ n: 1 }]), { plain: { n: 1 } });
    assert.equal(sent.length, before + 1, "only the plain echo call was dispatched");

    // A listed argument holding something else also keeps its prior path. A
    // plain record crosses unmarked and meets the test target's own answer;
    // an instance of another class is no bridge value.
    assert.deepEqual(binding.call(member("unwrap"), [{ n: 1 }, 2]), {
      first: { plain: { n: 1 } },
      second: { plain: 2 },
    });
    assert.equal(Object.hasOwn(sent.at(-1), "instances"), false);
    assert.deepEqual(await binding.callAsync(member("later"), [{ n: 3 }]), { plain: { n: 3 } });
    assert.equal(Object.hasOwn(sent.at(-1), "instances"), false);
    const other = new (class Box {})();
    assert.equal(binding.canCarry([other, 2], member("unwrap")), false);
    assert.throws(() => binding.call(member("unwrap"), [other, 2]), /bridge values/);
    assert.equal(sent.length, before + 3, "only the plain calls were dispatched");

    // The data the target's instance wraps is the argument the adapter checks.
    assert.throws(
      () => binding.call(member("touch"), [new Box({ n: 1 })]),
      /bridge cannot carry the result of fixture\.mjs touch: the call changed its arguments/,
    );

    // A class coordinate the test target does not export is a refusal.
    const missing = /** @type {any} */ (
      binding.request({
        version: 1,
        type: "call",
        protocol: "dca-test-bridge/v1",
        operation: member("echo"),
        input: [{ n: 1 }],
        instances: [{ argument: 0, sourceModule: "box.mjs", sourceExport: "Missing" }],
      })
    );
    assert.equal(missing.result.kind, "refusal");
    assert.match(missing.result.message, /box\.mjs exports no class Missing/);
  } finally {
    await binding.dispose();
    rmSync(targetRoot, { recursive: true, force: true });
  }
});
