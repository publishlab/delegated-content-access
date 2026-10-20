import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { defineBridge } from "../../_shared/bridge-definition.mjs";
import { ProcessBinding } from "../../_shared/register.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const geometryTest = join(root, "test-reference/core-shared/geometry-bounds.test.js");
const jsBridge = join(root, "test-bridges/js/bridge.mjs");
const loopbackBridge = join(root, "test-bridges/js-loopback/bridge.mjs");
const preload = join(root, "test-bridges/_shared/preload.mjs");
// The js adapter with the reference as its target root, set explicitly.
const bridge = defineBridge({
  id: "js",
  adapter: join(root, "test-bridges/js/adapter.mjs"),
  targetRoot: root,
});

function run(arguments_, env = {}) {
  const childEnvironment = { ...process.env, ...env };
  delete childEnvironment.NODE_TEST_CONTEXT;
  if (!("DCA_TARGET_ROOT" in env)) delete childEnvironment.DCA_TARGET_ROOT;
  return execFileSync(process.execPath, ["--test-reporter=tap", ...arguments_], {
    cwd: root,
    env: childEnvironment,
    encoding: "utf8",
  });
}

test("the persistent reference adapter observes portable geometry calls", async () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-bridge-"));
  const transcriptPath = join(directory, "worker.transcript.jsonl");
  const timingPath = join(directory, "timing.json");
  const binding = new ProcessBinding(bridge, { transcriptPath, timingPath, timing: true });
  try {
    await binding.start();
    const identity = /** @type {any} */ (binding.description).identity;
    assert.equal(identity.targetVersion, "reference");
    assert.equal(Object.hasOwn(identity, "implementationVersion"), false);
    assert.equal(binding.capabilities.moduleDiscovery, true);
    assert.deepEqual(binding.capabilities.valueTypes, [
      "null",
      "boolean",
      "string",
      "number",
      "record",
      "list",
      "undefined",
      "Uint8Array",
      "Date",
      "CryptoKey",
    ]);
    const member = binding
      .describeModule("core-shared/geometryBounds.js")
      .find((entry) => entry.sourceExport === "inspectPeriodGeometryBounds");
    assert.ok(member);
    assert.deepEqual(binding.call(member.id, [5, 1]), {
      kind: "valid",
      windowMinutes: 288,
      positionsPerWindow: 288,
    });
    await binding.dispose();
    const records = readFileSync(transcriptPath, "utf8").trim().split("\n").map(JSON.parse);
    assert.deepEqual(
      records.map((record) => record.event),
      ["capabilities", "module", "call", "final"],
    );
    assert.equal(Object.hasOwn(records[1], "expected"), false, "calls record no test expectation");
    const final = records[3];
    // The preload never sees test outcomes, so the final record states only
    // that the binding was disposed, and routes name only what was called.
    assert.equal(final.lifecycle, "disposed");
    assert.equal(Object.hasOwn(final, "verdict"), false);
    assert.deepEqual(final.routes, { [member.id]: { external: 1, reference: 0 } });
    const timing = JSON.parse(readFileSync(timingPath, "utf8"));
    assert.equal(timing.calls, 1);
    assert.equal(timing.lifecycle, "disposed");
  } finally {
    await binding.dispose();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("fallback accounting does not depend on transcript logging", () => {
  const binding = new ProcessBinding(bridge);
  assert.equal(
    binding.referenceFallback("example", [2, 3], (left, right) => left + right),
    5,
  );
  assert.equal(binding.referenceFallbacks, 1);
});

test("bridge-value capability checks happen before sync or async dispatch", async () => {
  const binding = new ProcessBinding(bridge);
  binding.capabilities = {
    valueTypes: ["list", "number"],
    moduleDiscovery: true,
  };
  binding.operations.set("op-1", { id: "op-1", sourceExport: "external", callShape: "sync" });
  binding.request = () => {
    throw new Error("a rejected bridge-value type must not dispatch");
  };
  assert.equal(binding.canCarry([1, 2]), true);
  assert.equal(binding.canCarry([new Uint8Array([1])]), false);
  assert.equal(await binding.canCarryAsync([new Uint8Array([1])]), false);
  assert.throws(
    () => binding.call("op-1", [new Uint8Array([1])]),
    /does not support runtime value types: Uint8Array/,
  );
  await assert.rejects(
    binding.callAsync("op-1", [new Uint8Array([1])]),
    /does not support runtime value types: Uint8Array/,
  );
});

test("overlay can fall back before dispatch for an unsupported async argument", async () => {
  const binding = new ProcessBinding(bridge);
  binding.capabilities = { valueTypes: ["number"], moduleDiscovery: true };
  const input = [() => 1];
  const result = (await binding.canCarryAsync(input))
    ? await binding.callAsync("op-async", input)
    : await binding.referenceFallback("op-async", input, async () => 7);
  assert.equal(result, 7);
  assert.equal(binding.referenceFallbacks, 1);
});

test("js-loopback runs the unchanged strict reference test externally while module constants stay reference-owned", () => {
  const logs = mkdtempSync(join(tmpdir(), "dca-reference-bridge-"));
  try {
    assert.match(
      run(["--import", loopbackBridge, "--test", geometryTest], {
        DCA_BRIDGE_MODE: "strict",
        DCA_LOG_DIR: logs,
      }),
      /^# pass [1-9]\d*$/m,
    );
    const records = readdirSync(logs, { withFileTypes: true }).flatMap((entry) => {
      if (!entry.isDirectory()) return [];
      return readdirSync(join(logs, entry.name))
        .filter((file) => file.endsWith(".transcript.jsonl"))
        .flatMap((file) =>
          readFileSync(join(logs, entry.name, file), "utf8")
            .trim()
            .split("\n")
            .map(JSON.parse),
        );
    });
    const final = records.find((record) => record.event === "final");
    assert.ok(final.externalCalls > 0);
    assert.equal(final.referenceFallbacks, 0);
    assert.ok(
      records
        .filter((record) => record.event === "call")
        .every(
          (record) => typeof record.operation === "string" && record.operation.startsWith("op-"),
        ),
    );
  } finally {
    rmSync(logs, { recursive: true, force: true });
  }
});

test("an unchanged eligible test runs directly, through the direct preload, and through selection", () => {
  assert.match(run(["--test", geometryTest]), /^# pass [1-9]\d*$/m);
  assert.match(run(["--import", loopbackBridge, "--test", geometryTest]), /^# pass [1-9]\d*$/m);
  assert.match(
    run(["--import", preload, "--test", geometryTest], { DCA_BRIDGE: "js-loopback" }),
    /^# pass [1-9]\d*$/m,
  );
});

test("the js bridge refuses without a target root and names js-loopback", () => {
  const environment = { ...process.env };
  delete environment.DCA_TARGET_ROOT;
  delete environment.NODE_TEST_CONTEXT;
  const refused = spawnSync(
    process.execPath,
    ["--import", jsBridge, "--test", "--test-reporter=tap", geometryTest],
    {
      cwd: root,
      env: environment,
      encoding: "utf8",
    },
  );
  // Node's test runner reports the preload's error from the test child on stdout.
  const output = `${refused.stdout}${refused.stderr}`;
  assert.notEqual(refused.status, 0);
  assert.match(output, /the js bridge needs DCA_TARGET_ROOT/);
  assert.match(output, /DCA_BRIDGE=js-loopback/);
  assert.doesNotMatch(refused.stdout, /^# pass [1-9]/m);
});

test("an overlay binding with no external call records a vacuous run", async () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-bridge-"));
  const transcriptPath = join(directory, "worker.transcript.jsonl");
  const binding = new ProcessBinding(bridge, { transcriptPath, mode: "overlay" });
  try {
    await binding.start();
    binding.referenceFallback("op-local", [1], (value) => value);
    await binding.dispose();
    const final = readFileSync(transcriptPath, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line))
      .find((record) => record.event === "final");
    assert.equal(final.evidence, "vacuous");
    assert.equal(final.mode, "overlay");
    assert.deepEqual(final.routes, { "op-local": { external: 0, reference: 1 } });
  } finally {
    await binding.dispose();
    rmSync(directory, { recursive: true, force: true });
  }
});
