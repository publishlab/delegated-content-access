import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const loopbackBridge = join(root, "test-bridges/js-loopback/bridge.mjs");
const runner = join(root, "test-bridges/_shared/run.mjs");
const LISTED = "core-shared/binaryStrings.js";
const OTHER = "core-shared/codec.js";

/** @param {string} path */
const moduleUrl = (path) => JSON.stringify(pathToFileURL(join(root, path)).href);

// One call into each of two implementation modules. binaryStringBytes calls
// codec.js inside itself, which never crosses in any run.
const BOTH_MODULES = `import test from "node:test";
import assert from "node:assert/strict";
import { binaryStringBytes } from ${moduleUrl(LISTED)};
import { base64urlEncode } from ${moduleUrl(OTHER)};
test("probe", () => {
  assert.deepEqual(binaryStringBytes("AAE"), new Uint8Array([0, 1]));
  assert.equal(base64urlEncode(new Uint8Array([0, 1])), "AAE");
});
`;

// The same calls, but the binaryStrings.js argument list holds a function,
// which no bridge value carries.
const UNCARRIED_INPUT = `import test from "node:test";
import assert from "node:assert/strict";
import { binaryStringBytes } from ${moduleUrl(LISTED)};
import { base64urlEncode } from ${moduleUrl(OTHER)};
test("probe", () => {
  assert.deepEqual(binaryStringBytes("AAE", () => {}), new Uint8Array([0, 1]));
  assert.equal(base64urlEncode(new Uint8Array([0, 1])), "AAE");
});
`;

/**
 * Runs one probe test file through js-loopback with the given settings and a
 * transcript, and returns the run and every transcript record.
 *
 * @param {string} source @param {Record<string, string>} settings
 */
function runProbe(source, settings) {
  const directory = mkdtempSync(join(tmpdir(), "dca-module-set-"));
  const logs = join(directory, "logs");
  const probe = join(directory, "probe.test.js");
  writeFileSync(probe, source);
  try {
    const environment = { ...process.env, DCA_LOG_DIR: logs, ...settings };
    delete environment.NODE_TEST_CONTEXT;
    delete environment.DCA_TARGET_ROOT;
    delete environment.DCA_TEST_SELECTION;
    const run = spawnSync(
      process.execPath,
      ["--import", loopbackBridge, "--test", "--test-reporter=tap", probe],
      {
        cwd: root,
        env: environment,
        encoding: "utf8",
      },
    );
    const shards = readdirSync(logs, { recursive: true, encoding: "utf8" }).filter((file) =>
      file.endsWith(".transcript.jsonl"),
    );
    const records = shards.flatMap((file) =>
      readFileSync(join(logs, file), "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line)),
    );
    return { run, records };
  } catch (error) {
    return { run: undefined, records: [], error };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

/** @param {any[]} records @param {string} sourceModule */
function operationsOf(records, sourceModule) {
  const described = records.find(
    (record) => record.event === "module" && record.sourceModule === sourceModule,
  );
  return new Set((described?.members ?? []).map((/** @type {any} */ member) => member.id));
}

test("a strict run over a named module set sends only the listed module's calls to the test target", () => {
  const { run, records } = runProbe(BOTH_MODULES, {
    DCA_BRIDGE_MODE: "strict",
    DCA_BRIDGE_MODULES: LISTED,
  });
  assert.ok(run);
  assert.equal(run.status, 0, run.stdout + run.stderr);
  const listed = operationsOf(records, LISTED);
  const calls = records.filter((record) => record.event === "call");
  assert.equal(calls.length, 1);
  assert.ok(listed.has(calls[0].operation));
  const [final] = records.filter((record) => record.event === "final");
  assert.deepEqual(final.modules, [LISTED]);
  assert.deepEqual(final.unroutedModules, [OTHER]);
  assert.equal(final.externalCalls, 1);
  assert.equal(final.referenceFallbacks, 0);
});

test("a listed module never falls back, and the set decides which module that is", () => {
  const listed = runProbe(UNCARRIED_INPUT, {
    DCA_BRIDGE_MODE: "strict",
    DCA_BRIDGE_MODULES: LISTED,
  });
  assert.ok(listed.run);
  assert.notEqual(listed.run.status, 0, listed.run.stdout);
  assert.match(listed.run.stdout, /^# fail 1$/m);
  assert.deepEqual(
    listed.records.filter((record) => record.event === "route" || record.event === "call"),
    [],
  );

  // With only codec.js listed, the same binaryStrings.js call runs on the
  // reference, and only the codec.js call crosses.
  const other = runProbe(UNCARRIED_INPUT, {
    DCA_BRIDGE_MODE: "strict",
    DCA_BRIDGE_MODULES: OTHER,
  });
  assert.ok(other.run);
  assert.equal(other.run.status, 0, other.run.stdout + other.run.stderr);
  const codec = operationsOf(other.records, OTHER);
  const calls = other.records.filter((record) => record.event === "call");
  assert.equal(calls.length, 1);
  assert.ok(codec.has(calls[0].operation));
  const [final] = other.records.filter((record) => record.event === "final");
  assert.deepEqual(final.unroutedModules, [LISTED]);
  assert.equal(final.referenceFallbacks, 0);
});

test("a named module set is refused outside strict mode and when it names no reference module", () => {
  const refusals = [
    [{ DCA_BRIDGE_MODE: "overlay", DCA_BRIDGE_MODULES: LISTED }, /set DCA_BRIDGE_MODE=strict/],
    [
      { DCA_BRIDGE_MODE: "strict", DCA_BRIDGE_MODULES: "core-shared/absent.js" },
      /DCA_BRIDGE_MODULES names core-shared\/absent\.js, which is no reference module/,
    ],
    [
      { DCA_BRIDGE_MODE: "strict", DCA_BRIDGE_MODULES: "test-reference/support/keys.js" },
      /which is no implementation module path/,
    ],
    [
      { DCA_BRIDGE_MODE: "strict", DCA_BRIDGE_MODULES: `${LISTED},${LISTED}` },
      /DCA_BRIDGE_MODULES names each module once/,
    ],
    [
      { DCA_BRIDGE_MODE: "strict", DCA_BRIDGE_MODULES: `${LISTED},` },
      /DCA_BRIDGE_MODULES lists reference module paths, comma-separated/,
    ],
  ];
  for (const [settings, message] of refusals) {
    const environment = { ...process.env, ...settings };
    delete environment.NODE_TEST_CONTEXT;
    delete environment.DCA_TARGET_ROOT;
    delete environment.DCA_LOG_DIR;
    const refused = spawnSync(
      process.execPath,
      [
        "--import",
        loopbackBridge,
        "--test",
        "--test-reporter=tap",
        "test-reference/core-shared/binary-strings.test.js",
      ],
      { cwd: root, env: environment, encoding: "utf8" },
    );
    assert.notEqual(refused.status, 0);
    assert.match(`${refused.stdout}${refused.stderr}`, message);
    assert.doesNotMatch(refused.stdout, /^# pass [1-9]/m);
  }
});

test("the runner names the modules a named module set left on the reference and refuses one for a selection", () => {
  const environment = {
    ...process.env,
    DCA_BRIDGE: "js-loopback",
    DCA_BRIDGE_MODE: "strict",
    DCA_BRIDGE_MODULES: LISTED,
  };
  delete environment.NODE_TEST_CONTEXT;
  delete environment.DCA_TARGET_ROOT;
  delete environment.DCA_LOG_DIR;
  const passed = spawnSync(
    process.execPath,
    [runner, "test-reference/core-shared/binary-strings.test.js"],
    { cwd: root, env: environment, encoding: "utf8" },
  );
  assert.equal(passed.status, 0, passed.stderr);
  assert.match(
    passed.stderr,
    /strict over named modules core-shared\/binaryStrings\.js: [1-9]\d* external calls; 0 uncarried results; left on the reference: core-shared\/codec\.js/,
  );

  const refused = spawnSync(process.execPath, [runner, "portable-core"], {
    cwd: root,
    env: environment,
    encoding: "utf8",
  });
  assert.notEqual(refused.status, 0);
  assert.match(
    refused.stderr,
    /a portable selection routes every module it imports; DCA_BRIDGE_MODULES is for a direct strict run/,
  );
});
