import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const loopbackBridge = join(root, "test-bridges/js-loopback/bridge.mjs");

/** @param {string} path */
const moduleUrl = (path) => JSON.stringify(pathToFileURL(join(root, path)).href);

/**
 * Runs one probe test file through js-loopback in overlay mode with a
 * transcript, and returns the run and every transcript record.
 *
 * @param {string} source
 */
function runProbe(source) {
  const directory = mkdtempSync(join(tmpdir(), "dca-fallback-"));
  const logs = join(directory, "logs");
  const probe = join(directory, "probe.test.js");
  writeFileSync(probe, source);
  try {
    const environment = { ...process.env, DCA_BRIDGE_MODE: "overlay", DCA_LOG_DIR: logs };
    delete environment.NODE_TEST_CONTEXT;
    delete environment.DCA_TARGET_ROOT;
    const run = spawnSync(process.execPath, ["--import", loopbackBridge, "--test", probe], {
      cwd: root,
      env: environment,
      encoding: "utf8",
    });
    const records = readdirSync(logs, { recursive: true, encoding: "utf8" })
      .filter((file) => file.endsWith(".transcript.jsonl"))
      .flatMap((file) =>
        readFileSync(join(logs, file), "utf8")
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line)),
      );
    return { run, records };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("a call that falls back runs its internal calls on the reference too", () => {
  // The second argument is a function, so the call cannot cross and falls
  // back. binaryStringBytes then calls base64urlDecode and base64urlEncode
  // from codec.js; those calls must not cross either.
  const { run, records } = runProbe(`import test from "node:test";
import assert from "node:assert/strict";
import { binaryStringBytes } from ${moduleUrl("core-shared/binaryStrings.js")};
test("probe", () => {
  assert.deepEqual(binaryStringBytes("AAE", () => {}), new Uint8Array([0, 1]));
});
`);
  assert.equal(run.status, 0, run.stdout);
  assert.deepEqual(
    records.filter((record) => record.event === "call"),
    [],
  );
  assert.equal(records.filter((record) => record.event === "route").length, 1);
});

test("a module with nothing to claim exists once, for the test and for the fallback", () => {
  const { run } = runProbe(`import test from "node:test";
import assert from "node:assert/strict";
import { DcaData } from ${moduleUrl("core-client/DcaData.js")};
import { DcaData as FallbackDcaData } from ${JSON.stringify(
    `${pathToFileURL(join(root, "core-client/DcaData.js")).href}?dca-bridge-reference-fallback`,
  )};
test("probe", () => {
  assert.equal(DcaData, FallbackDcaData);
});
`);
  assert.equal(run.status, 0, run.stdout);
});

test("an error class that only the fallback graph loads still maps back", () => {
  // The probe imports periodLabels.js alone. Its DcaError comes from
  // errors.js, which only the reference fallback of periodLabels.js imports.
  const { run, records } = runProbe(`import test from "node:test";
import assert from "node:assert/strict";
import { formatT } from ${moduleUrl("core-shared/periodLabels.js")};
test("probe", () => {
  assert.throws(
    () => formatT(new Date("2026-09-23T12:00:00.000Z"), 0),
    (error) =>
      error.constructor.name === "DcaError" &&
      error.name === "DcaError" &&
      error.code === "bad_config",
  );
});
`);
  assert.equal(run.status, 0, run.stdout);
  assert.equal(records.filter((record) => record.event === "call").length, 1);
});
