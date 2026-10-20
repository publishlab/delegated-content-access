import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { bridgeIds, bridgeModule } from "../run-support.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const runner = join(root, "test-bridges/_shared/run.mjs");
const preload = join(root, "test-bridges/_shared/preload.mjs");
const geometryTest = join(root, "test-reference/core-shared/geometry-bounds.test.js");

/**
 * Writes a bridge module outside this tree. It starts the js adapter with a
 * command and arguments only, the way a compiled adapter would start.
 */
function outsideBridge() {
  const directory = mkdtempSync(join(tmpdir(), "dca-outside-bridge-"));
  const shared = (/** @type {string} */ file) =>
    JSON.stringify(pathToFileURL(join(root, "test-bridges/_shared", file)).href);
  const path = join(directory, "bridge.mjs");
  writeFileSync(
    path,
    `import { defineBridge } from ${shared("bridge-definition.mjs")};
import { bridgeEnvironment } from ${shared("environment.mjs")};
import { registerBridge } from ${shared("register.mjs")};

const bridge = defineBridge({
  id: "outside",
  command: process.execPath,
  arguments: [${JSON.stringify(join(root, "test-bridges/js/adapter.mjs"))}],
  targetRoot: ${JSON.stringify(root)},
});
const environment = bridgeEnvironment({ bridgeId: bridge.id });
const active = await registerBridge(bridge, {
  mode: process.env.DCA_BRIDGE_MODE ?? "overlay",
  transcriptPath: environment.transcriptPath,
  debug: environment.debug,
});
process.once("beforeExit", () => active.dispose());
`,
  );
  return { directory, path };
}

/** @param {string[]} arguments_ @param {Record<string, string>} env */
function run(arguments_, env) {
  const environment = { ...process.env, ...env };
  delete environment.NODE_TEST_CONTEXT;
  return spawnSync(process.execPath, arguments_, { cwd: root, env: environment, encoding: "utf8" });
}

test("DCA_BRIDGE names a bridge ID or a bridge module path", () => {
  assert.equal(bridgeModule("php", "/elsewhere"), join(root, "test-bridges/php/bridge.mjs"));
  assert.equal(bridgeModule("./mine/bridge.mjs", "/work"), "/work/mine/bridge.mjs");
});

test("bridge IDs are the directories that hold a bridge.mjs", () => {
  const expected = readdirSync(join(root, "test-bridges"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^[a-z][a-z0-9-]*$/.test(entry.name))
    .filter((entry) => existsSync(join(root, "test-bridges", entry.name, "bridge.mjs")))
    .map((entry) => entry.name)
    .sort();
  assert.deepEqual(bridgeIds(), expected);
  assert.ok(expected.includes("php"));
  assert.equal(expected.includes("_shared"), false);
});

test("an unknown bridge ID refuses and lists the discovered IDs", () => {
  assert.throws(
    () => bridgeModule("unknown", "/work"),
    (error) =>
      error instanceof Error &&
      error.message.includes('"unknown"') &&
      error.message.includes(`bridge IDs: ${bridgeIds().join(", ")}`),
  );
});

test("a directory with a leading _ or . is not a bridge ID", () => {
  for (const value of ["_shared", ".hidden", "Php", "php/"])
    assert.throws(() => bridgeModule(value, "/work"), /bridge IDs: .*php/, value);
});

test("an outside bridge module runs a direct selector and joins a named selection", () => {
  const { directory, path } = outsideBridge();
  try {
    const direct = run(["--import", preload, "--test", geometryTest], {
      DCA_BRIDGE: path,
      DCA_BRIDGE_MODE: "strict",
    });
    assert.equal(direct.status, 0, direct.stderr);
    const named = run([runner, "portable-publisher"], { DCA_BRIDGE: path });
    assert.equal(named.status, 0, named.stderr);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the runner refuses an obsolete root variable before it starts Node", () => {
  const refused = run([runner, "portable-core"], {
    DCA_BRIDGE: "js-loopback",
    DCA_PORT_ROOT: root,
  });
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /DCA_PORT_ROOT is obsolete; use DCA_TARGET_ROOT/);
  assert.doesNotMatch(refused.stdout, /# tests/);
});
