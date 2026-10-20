import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { portableSelectionArguments, verifySelectionEvidence } from "../run-support.mjs";

/**
 * Runs Node's test runner over the given files, as a named selection does,
 * with the run reporter writing its case report into the same directory.
 *
 * @param {Record<string, string>} files test file name to source
 */
function runSelection(files) {
  const directory = mkdtempSync(join(tmpdir(), "dca-run-reporter-"));
  try {
    for (const [name, source] of Object.entries(files))
      writeFileSync(join(directory, name), source);
    const reportPath = join(directory, "case-counts.json");
    const selection = { tests: Object.keys(files).map((file) => ({ file })) };
    const arguments_ = portableSelectionArguments(selection, {
      reportPath,
      environment: {},
      interactive: false,
    });
    const environment = { ...process.env };
    delete environment.NODE_TEST_CONTEXT;
    const run = spawnSync(process.execPath, arguments_, {
      cwd: directory,
      env: environment,
      encoding: "utf8",
    });
    return {
      status: run.status,
      stdout: run.stdout,
      report: existsSync(reportPath) ? readFileSync(reportPath, "utf8") : undefined,
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

/** Transcript shards in which every file made the one required call. @param {string[]} files */
function calledShards(files) {
  return files.map((entry) => [
    {
      event: "module",
      sourceModule: "core/math.js",
      members: [{ id: "op-1", sourceExport: "twice" }],
    },
    { event: "call", operation: "op-1" },
    { event: "final", entry, externalCalls: 1, referenceFallbacks: 0 },
  ]);
}

/** @param {string[]} files @param {number} testCount */
function selectionOf(files, testCount) {
  return {
    testCount,
    tests: files.map((file) => ({ file })),
    required: [{ module: "core/math.js", exports: ["twice"] }],
  };
}

const header = 'import test, { describe } from "node:test";\n';

test("the reporter counts each file's cases by how they ended, as Node's summary does", () => {
  const run = runSelection({
    "a.test.js": `${header}
test("passes", () => {});
test("skipped", { skip: true }, () => {});
test("todo that fails", { todo: true }, () => { throw new Error("later"); });
test("fails", () => { throw new Error("boom"); });
test("times out", { timeout: 20 }, () => new Promise((resolve) => setTimeout(resolve, 500)));
describe("a suite is not a case", () => {
  test("nested", async (t) => { await t.test("subtest", () => {}); });
});
`,
    "b.test.js": `${header}
test("never ends", () => new Promise((resolve) => setTimeout(resolve, 500)));
setTimeout(() => process.exit(3), 20);
`,
  });
  assert.equal(run.status, 1);
  assert.match(run.stdout, /^# tests 8$/m, "the human stream stays on stdout");
  assert.deepEqual(JSON.parse(run.report ?? "null"), {
    version: 1,
    files: {
      "a.test.js": { tests: 7, passed: 3, failed: 1, cancelled: 1, skipped: 1, todo: 1 },
      // the crashed file reports itself as one failed case
      "b.test.js": { tests: 1, passed: 0, failed: 1, cancelled: 0, skipped: 0, todo: 0 },
    },
    node: { tests: 8, passed: 3, failed: 2, cancelled: 1, skipped: 1, todo: 1 },
  });
});

test("Node exits 0 with a TODO case, and the named selection still fails", () => {
  const run = runSelection({
    "a.test.js": `${header}test("passes", () => {});\ntest("later", { todo: "not yet" }, () => {});\n`,
  });
  assert.equal(run.status, 0, "Node treats a TODO case as success");
  assert.throws(
    () =>
      verifySelectionEvidence(
        selectionOf(["a.test.js"], 2),
        calledShards(["a.test.js"]),
        run.report,
      ),
    /passed 1\/2; failed 0, cancelled 0, skipped 0, todo 1; a\.test\.js: todo 1$/,
  );
});

test("Node exits 0 with a skipped case, and the named selection still fails", () => {
  const run = runSelection({
    "a.test.js": `${header}test("passes", () => {});\ntest("skipped", { skip: true }, () => {});\n`,
  });
  assert.equal(run.status, 0);
  assert.throws(
    () =>
      verifySelectionEvidence(
        selectionOf(["a.test.js"], 2),
        calledShards(["a.test.js"]),
        run.report,
      ),
    /passed 1\/2; .*skipped 1.*; a\.test\.js: skipped 1$/,
  );
});

test("a timed-out case counts as cancelled and fails the named selection", () => {
  const run = runSelection({
    "a.test.js": `${header}test("times out", { timeout: 20 }, () => new Promise((resolve) => setTimeout(resolve, 500)));\n`,
  });
  assert.notEqual(run.status, 0);
  assert.throws(
    () =>
      verifySelectionEvidence(
        selectionOf(["a.test.js"], 1),
        calledShards(["a.test.js"]),
        run.report,
      ),
    /passed 0\/1; failed 0, cancelled 1, .*a\.test\.js: cancelled 1$/,
  );
});

test("a failed case fails the named selection and names its file", () => {
  const run = runSelection({
    "a.test.js": `${header}test("passes", () => {});\n`,
    "b.test.js": `${header}test("fails", () => { throw new Error("boom"); });\n`,
  });
  assert.equal(run.status, 1);
  assert.throws(
    () =>
      verifySelectionEvidence(
        selectionOf(["a.test.js", "b.test.js"], 2),
        calledShards(["a.test.js", "b.test.js"]),
        run.report,
      ),
    /passed 1\/2; failed 1, .*; b\.test\.js: failed 1$/,
  );
});

test("a selection whose every case passes verifies from the report", () => {
  const run = runSelection({
    "a.test.js": `${header}test("one", () => {});\ndescribe("group", () => { test("two", () => {}); });\n`,
    "b.test.js": `${header}test("three", async (t) => { await t.test("four", () => {}); });\n`,
  });
  assert.equal(run.status, 0);
  assert.equal(
    verifySelectionEvidence(
      selectionOf(["a.test.js", "b.test.js"], 4),
      calledShards(["a.test.js", "b.test.js"]),
      run.report,
    ).passed,
    4,
  );
});
