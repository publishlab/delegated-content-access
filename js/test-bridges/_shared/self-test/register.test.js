import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ProcessBinding, registerBridge } from "../register.mjs";
import { decodeValue, encodeValue } from "../serializer.mjs";

/**
 * A binding whose adapter answers module descriptions from a table, so a test
 * can hand the driver a description no shipped adapter produces.
 *
 * @param {Record<string, { id: string, sourceExport: string }[]>} modules
 */
function bindingDescribing(modules) {
  const binding = new ProcessBinding(/** @type {any} */ ({ id: "fixture" }));
  let next = 0;
  binding.request = (/** @type {any} */ request) => ({
    version: 1,
    id: `r${(next += 1)}`,
    type: "response",
    result: {
      kind: "observation",
      value: encodeValue({
        members: modules[request.sourceModule].map((member) => ({ ...member, callShape: "sync" })),
      }),
    },
  });
  return binding;
}

test("the driver refuses a member ID another module already claimed", () => {
  const binding = bindingDescribing({
    "impl/one.js": [{ id: "shared", sourceExport: "one" }],
    "impl/two.js": [{ id: "shared", sourceExport: "two" }],
  });
  binding.describeModule("impl/one.js");
  assert.throws(() => binding.describeModule("impl/two.js"), /member IDs already claimed: shared/);
  assert.equal(binding.operations.get("shared")?.sourceExport, "one");
});

test("the driver describes a module once and accepts distinct IDs across modules", () => {
  const binding = bindingDescribing({
    "impl/one.js": [{ id: "one-1", sourceExport: "one" }],
    "impl/two.js": [{ id: "two-1", sourceExport: "two" }],
  });
  const first = binding.describeModule("impl/one.js");
  assert.equal(binding.describeModule("impl/one.js"), first);
  binding.describeModule("impl/two.js");
  assert.deepEqual([...binding.operations.keys()], ["one-1", "two-1"]);
});

test("registerBridge knows only the overlay and strict modes", async () => {
  await assert.rejects(
    registerBridge(
      /** @type {any} */ ({ id: "fixture" }),
      /** @type {any} */ ({ mode: "reference" }),
    ),
    /DCA_BRIDGE_MODE "reference" is unknown; modes are overlay and strict/,
  );
});

/** @param {string} path */
function transcriptRecords(path) {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
}

test("a fallback for an input the bridge cannot carry is still logged", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-bridge-"));
  const transcriptPath = join(directory, "worker.transcript.jsonl");
  try {
    const binding = new ProcessBinding(/** @type {any} */ ({ id: "fixture" }), { transcriptPath });
    const callback = () => 7;
    assert.equal(
      binding.referenceFallback("op-local", [callback], (value) => value()),
      7,
    );
    const [route] = transcriptRecords(transcriptPath);
    assert.equal(route.event, "route");
    assert.match(route.input.uncarried, /JSON data/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a test that replaces Date and performance.now does not reach a logged, timed call", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-bridge-"));
  const transcriptPath = join(directory, "worker.transcript.jsonl");
  const binding = new ProcessBinding(/** @type {any} */ ({ id: "fixture" }), {
    transcriptPath,
    timing: true,
  });
  binding.capabilities = { valueTypes: ["list", "number"], moduleDiscovery: true };
  binding.operations.set("op-1", { id: "op-1", sourceExport: "twice", callShape: "sync" });
  binding.request = () => ({
    version: 1,
    id: "1",
    type: "response",
    result: { kind: "observation", value: 4 },
  });
  const realDate = globalThis.Date;
  const realNow = performance.now;
  const reached = () => {
    throw new Error("the bridge reached for the test's clock");
  };
  try {
    globalThis.Date = /** @type {any} */ (
      class {
        constructor() {
          reached();
        }
        static now() {
          return reached();
        }
      }
    );
    performance.now = reached;
    assert.equal(binding.call("op-1", [2]), 4);
    binding.referenceFallback("op-1", [3], (value) => value);
  } finally {
    globalThis.Date = realDate;
    performance.now = realNow;
  }
  try {
    assert.deepEqual(
      transcriptRecords(transcriptPath).map((record) => record.event),
      ["call", "route"],
    );
    assert.equal(binding.timing.calls, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

/**
 * A binding that describes `impl/one.js` with a sync `one` and an async
 * `later`, reads both by fixed reference shapes, and answers every call with
 * `result`, adding the members of `response` to the call response.
 *
 * @param {Record<string, unknown>} result @param {Record<string, unknown>} [response]
 */
function bindingAnswering(result, response = {}) {
  const binding = new ProcessBinding(/** @type {any} */ ({ id: "fixture" }), {
    referenceShapes: {
      version: 1,
      modules: { "impl/one.js": { one: { record: { key: "Uint8Array" } }, later: { record: {} } } },
    },
  });
  binding.capabilities = { valueTypes: ["list", "record", "string"], moduleDiscovery: true };
  let next = 0;
  binding.request = (/** @type {any} */ request) => ({
    version: 1,
    id: `r${(next += 1)}`,
    type: "response",
    ...(request.type === "call" ? response : {}),
    result:
      request.type === "describeModule"
        ? {
            kind: "observation",
            value: encodeValue({
              members: [
                { id: "op-one", sourceExport: "one", callShape: "sync" },
                { id: "op-later", sourceExport: "later", callShape: "async" },
              ],
            }),
          }
        : result,
  });
  binding.describeModule("impl/one.js");
  return binding;
}

test("the driver reads an answer by its reference export's return shape", async () => {
  const bytes = new TextEncoder().encode("k");
  assert.deepEqual(
    bindingAnswering({ kind: "observation", value: { key: "k" } }).call("op-one", []),
    { key: bytes },
  );
  assert.deepEqual(
    await bindingAnswering(
      { kind: "observation", value: { key: "k" } },
      { settled: "promise" },
    ).call("op-one", []),
    { key: bytes },
  );
  assert.deepEqual(
    await bindingAnswering({ kind: "observation", value: [] }).callAsync("op-later", []),
    {},
  );
});

test("an answer from an export without a recorded shape passes unchanged", () => {
  const binding = bindingAnswering({ kind: "observation", value: [] });
  binding.operations.set("op-other", { id: "op-other", sourceExport: "other", callShape: "sync" });
  assert.deepEqual(binding.call("op-other", []), []);
});

test("ignored arguments project a copy alongside a plain-data input mapping", () => {
  class Shape {}
  const binding = new ProcessBinding(/** @type {any} */ ({ id: "fixture" }), {
    referenceShapes: {
      version: 1,
      modules: {
        "core-publisher/issuerSupplyPlan.js": {
          wholeRenderIssuerSupplyPlan: { record: { ok: "boolean" } },
        },
      },
    },
    inputs: [
      {
        module: "core-publisher/issuerSupplyPlan.js",
        export: "wholeRenderIssuerSupplyPlan",
        argument: 1,
        type: Shape,
        data: "toObject",
        class: { module: "core-publisher/shape.js", export: "Shape" },
      },
    ],
    ignoredArguments: [
      {
        module: "core-publisher/issuerSupplyPlan.js",
        export: "wholeRenderIssuerSupplyPlan",
        argument: 0,
      },
    ],
  });
  binding.capabilities = {
    valueTypes: ["undefined", "record", "boolean", "string", "list"],
    moduleDiscovery: true,
  };
  binding.operations.set("op-whole", {
    id: "op-whole",
    sourceExport: "wholeRenderIssuerSupplyPlan",
    callShape: "sync",
  });
  binding.operationModules.set("op-whole", "core-publisher/issuerSupplyPlan.js");
  binding.operations.set("op-neighbor", {
    id: "op-neighbor",
    sourceExport: "other",
    callShape: "sync",
  });
  binding.operationModules.set("op-neighbor", "core-publisher/issuerSupplyPlan.js");

  const issuer = () => "not JSON data";
  const render = { content: "<p>hello</p>" };
  const input = [issuer, render];
  const projected = binding.mapInputs("op-whole", input).input;
  assert.notEqual(projected, input);
  assert.deepEqual(projected, [undefined, render]);
  assert.equal(input[0], issuer);
  assert.equal(input[1], render);
  assert.equal(binding.canCarry(input, "op-whole"), true);
  assert.equal(binding.canCarry(input, "op-neighbor"), false);

  let request;
  binding.request = (value) => {
    request = value;
    return {
      version: 1,
      id: "1",
      type: "response",
      result: { kind: "observation", value: encodeValue({ ok: true }) },
    };
  };
  assert.deepEqual(binding.call("op-whole", input), { ok: true });
  assert.deepEqual(decodeValue(request.input), [undefined, render]);
  assert.equal(input[0], issuer);
});

test("the driver refuses an answer whose declared type the reference type does not admit", async () => {
  const declaredList = { kind: "observation", value: [], declared: [{ at: [], type: "list" }] };
  await assert.rejects(
    bindingAnswering(declaredList).callAsync("op-later", []),
    /bridge refuses the result of impl\/one\.js later: the test target declares list at the result, where the reference type admits record/,
  );
  assert.throws(
    () =>
      bindingAnswering({
        kind: "observation",
        value: { key: [] },
        declared: [{ at: ["key"], type: "list" }],
      }).call("op-one", []),
    /bridge refuses the result of impl\/one\.js one: the test target declares list at key, where the reference type admits Uint8Array/,
  );
});
