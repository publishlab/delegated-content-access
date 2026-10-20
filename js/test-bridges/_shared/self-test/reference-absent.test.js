// What this test proves about a strict run and the reference implementation.
//
// An unchanged selected test runs strict from a driver tree that holds the
// test, its driver helper, a copy of test-bridges/ and, in place of the
// reference implementation module, a stub with the same export names: each
// function throws when called, and each value export keeps the reference's
// value. The alternate test-target tree answers every call. The run passes, no
// call falls back, and no Node process of the run (test runner, test process,
// adapter child) loads a file of this js tree. So a strict run needs no
// reference implementation code: the stub's functions never run.
//
// A strict run still needs a module at every reference path the test imports,
// and evaluates it. Node's resolver needs the file, the bridge worker imports
// the module to list its exports, and the proxy imports it (register.mjs
// proxyModule) to supply its classes and value exports, which the driver always
// reads from the reference (CONTRACT.md, `value`). The geometry test's constant assertions therefore check the stub's
// copies, not the test target. The reference root is the directory above
// test-bridges/ (register.mjs registerBridge), so the driver tree carries its
// own copy of the bridge.
//
// When the test target drops a function the test needs, the strict proxy
// exports a stand-in in its place, and the run fails with a named error before
// any stub or reference function runs.

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const TEST_FILE = "test-reference/core-shared/geometry-bounds.test.js";
const HELPER = "test-reference/support/portable-test.js";
const MODULE = "core-shared/geometryBounds.js";
const STUB_CALLED = "reference implementation called";
const FALLBACK = "?dca-bridge-reference-fallback";

/**
 * The reference module's export surface without its implementation: every
 * function throws, every value export keeps the reference's value.
 */
async function referenceStub() {
  const reference = await import(pathToFileURL(join(root, MODULE)).href);
  return Object.entries(reference)
    .map(([name, value]) => {
      if (typeof value === "function")
        return `export function ${name}() { throw new Error(${JSON.stringify(`${STUB_CALLED}: ${name}`)}); }`;
      assert.deepEqual(JSON.parse(JSON.stringify(value)), value, `${name} is a JSON value`);
      return `export const ${name} = ${JSON.stringify(value)};`;
    })
    .join("\n");
}

/**
 * The driver tree: the unchanged test, its helper, the bridge and the stub.
 * The guard preload records every file each Node process of the run loads:
 * the test runner, the test process and the adapter child.
 */
async function driverTree() {
  const tree = mkdtempSync(join(tmpdir(), "dca-driver-"));
  cpSync(join(root, "test-bridges"), join(tree, "test-bridges"), {
    recursive: true,
    filter: (source) => basename(source) !== "self-test",
  });
  for (const file of [TEST_FILE, HELPER]) {
    mkdirSync(dirname(join(tree, file)), { recursive: true });
    copyFileSync(join(root, file), join(tree, file));
  }
  mkdirSync(dirname(join(tree, MODULE)), { recursive: true });
  writeFileSync(join(tree, MODULE), `${await referenceStub()}\n`);
  writeFileSync(
    join(tree, "guard.mjs"),
    `import { appendFileSync } from "node:fs";
import { registerHooks } from "node:module";
registerHooks({
  load(url, context, nextLoad) {
    if (url.startsWith("file:")) appendFileSync(${JSON.stringify(join(tree, "loaded.txt"))}, url + "\\n");
    return nextLoad(url, context);
  },
});
`,
  );
  return tree;
}

/** @param {string} source the test target's geometry module */
function targetTree(source) {
  const tree = mkdtempSync(join(tmpdir(), "dca-target-"));
  mkdirSync(dirname(join(tree, MODULE)), { recursive: true });
  writeFileSync(join(tree, MODULE), source);
  return tree;
}

/**
 * Runs the driver tree's copy of the test strict against `target`, and returns
 * the run, the final transcript record of the test process and the files it
 * loaded.
 *
 * @param {string} driver @param {string} target
 */
function strictRun(driver, target) {
  const logs = join(driver, "logs");
  const environment = {
    ...process.env,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --import=${join(driver, "guard.mjs")}`,
    DCA_BRIDGE_MODE: "strict",
    DCA_TARGET_ROOT: target,
    DCA_LOG_DIR: logs,
  };
  delete environment.NODE_TEST_CONTEXT;
  delete environment.DCA_TEST_SELECTION;
  const run = spawnSync(
    process.execPath,
    [
      "--import",
      join(driver, "test-bridges/js/bridge.mjs"),
      "--test",
      "--test-reporter=tap",
      join(driver, TEST_FILE),
    ],
    { cwd: driver, env: environment, encoding: "utf8" },
  );
  const finals = readdirSync(logs, { recursive: true, encoding: "utf8" })
    .filter((file) => file.endsWith(".transcript.jsonl"))
    .flatMap((file) =>
      readFileSync(join(logs, file), "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line)),
    )
    .filter((record) => record.event === "final" && record.entry === TEST_FILE);
  assert.equal(finals.length, 1, run.stdout + run.stderr);
  const loaded = readFileSync(join(driver, "loaded.txt"), "utf8").trim().split("\n");
  return { run, final: finals[0], loaded };
}

test("a strict run passes from the alternate test target with the reference implementation stubbed out", async () => {
  const driver = await driverTree();
  const target = targetTree(readFileSync(join(root, MODULE), "utf8"));
  try {
    const { run, final, loaded } = strictRun(driver, target);
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.match(run.stdout, /^# pass [1-9]\d*$/m);
    assert.match(run.stdout, /^# fail 0$/m);
    assert.equal(final.mode, "strict");
    assert.equal(final.referenceFallbacks, 0);
    assert.equal(final.uncarriedResults, 0);
    assert.ok(final.externalCalls > 0);
    for (const route of Object.values(final.routes)) assert.equal(route.reference, 0);
    // Every file comes from the driver tree or the test target, none from
    // this tree. The stub loads, as the proxy's fallback instance; the target
    // module loads in the adapter child.
    const inside = [driver, target].map((tree) => `${pathToFileURL(tree).href}/`);
    assert.deepEqual(
      loaded.filter((url) => !inside.some((prefix) => url.startsWith(prefix))),
      [],
    );
    assert.ok(loaded.includes(`${pathToFileURL(join(driver, MODULE)).href}${FALLBACK}`));
    assert.ok(loaded.includes(pathToFileURL(join(target, MODULE)).href));
  } finally {
    rmSync(driver, { recursive: true, force: true });
    rmSync(target, { recursive: true, force: true });
  }
});

test("a strict run fails with a named error when the test target drops a required function", async () => {
  const driver = await driverTree();
  const reference = readFileSync(join(root, MODULE), "utf8");
  const without = reference.replace(
    "export function inspectPeriodGeometryBounds(",
    "function inspectPeriodGeometryBounds(",
  );
  assert.notEqual(without, reference);
  const target = targetTree(without);
  try {
    const { run, final } = strictRun(driver, target);
    assert.notEqual(run.status, 0, run.stdout);
    assert.match(run.stdout, /^# fail [1-9]\d*$/m);
    assert.match(
      run.stdout,
      /strict bridge run: core-shared\/geometryBounds\.js#inspectPeriodGeometryBounds is not claimed by the test target/,
    );
    // The stand-in fails the call; the stub's function never runs.
    assert.doesNotMatch(run.stdout, new RegExp(STUB_CALLED));
    assert.equal(final.externalCalls, 0);
  } finally {
    rmSync(driver, { recursive: true, force: true });
    rmSync(target, { recursive: true, force: true });
  }
});
