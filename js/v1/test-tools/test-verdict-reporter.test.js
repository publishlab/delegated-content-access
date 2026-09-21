// @ts-check

// The gate's house rule and its slowest-file list, proved through real `node --test` runs.
// Each row spawns node over fixture files in a temporary directory and reads the exit code
// the reporter set. `NODE_TEST_CONTEXT` is deleted from the child environment: this file runs
// inside a test process, which sets that variable, and a child that inherits it switches its
// own reporter.

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPORTER = pathToFileURL(
  fileURLToPath(new URL("./test-verdict-reporter.mjs", import.meta.url)),
).href;

const PASSING = `const test = require('node:test'); test('green', () => {});`;
const FAILING = `const test = require('node:test'); test('red', () => { throw new Error('red'); });`;
const TODO = `const test = require('node:test'); test.todo('unfinished', () => {});`;
const SLOW = `const test = require('node:test');
test('slow', async () => { await new Promise((resolve) => setTimeout(resolve, 200)); });`;

/**
 * @param {Record<string, string>} files - fixture file name to source
 * @param {{ pattern?: string, isolation?: string }} [options]
 */
function run(files, options = {}) {
  const root = mkdtempSync(join(tmpdir(), "dca-verdict-"));
  try {
    for (const [name, source] of Object.entries(files)) writeFileSync(join(root, name), source);
    const childEnv = { ...process.env };
    delete childEnv.NODE_TEST_CONTEXT;
    return spawnSync(
      process.execPath,
      [
        `--experimental-test-isolation=${options.isolation ?? "process"}`,
        "--test",
        "--test-reporter=spec",
        "--test-reporter-destination=stdout",
        `--test-reporter=${REPORTER}`,
        "--test-reporter-destination=stderr",
        options.pattern ?? "*.test.js",
      ],
      { cwd: root, encoding: "utf8", env: childEnv },
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("a green run keeps node's own success", () => {
  const result = run({ "a.test.js": PASSING, "b.test.js": PASSING });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /2 tests, 2 passed, 0 failed, 0 skipped, 0 todo/);
});

test("a failing test keeps exit 1", () => {
  const result = run({ "a.test.js": PASSING, "b.test.js": FAILING });
  assert.equal(result.status, 1);
});

test("a todo on an otherwise green run is partial", () => {
  const result = run({ "a.test.js": PASSING, "b.test.js": TODO });
  assert.equal(result.status, 2, result.stderr);
});

test("a failure beside a todo keeps exit 1", () => {
  const result = run({ "a.test.js": FAILING, "b.test.js": TODO });
  assert.equal(result.status, 1, result.stderr);
});

test("a run that matched no file is partial", () => {
  const result = run({ "a.test.js": PASSING }, { pattern: "nothing-here/*.test.js" });
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stderr, /0 tests, 0 passed/);
});

test("a todo is partial under single-process isolation too", () => {
  const result = run({ "a.test.js": PASSING, "b.test.js": TODO }, { isolation: "none" });
  assert.equal(result.status, 2, result.stderr);
});

test("the slowest-file list names the fixture files in duration order", () => {
  const result = run({ "fast.test.js": PASSING, "slow.test.js": SLOW });
  assert.equal(result.status, 0, result.stderr);
  const listed = [...result.stderr.matchAll(/^ +[0-9]+ ms {2}(.+)$/gm)].map((match) => match[1]);
  assert.equal(listed.length, 2, result.stderr);
  assert.match(listed[0], /slow\.test\.js$/);
  assert.match(listed[1], /fast\.test\.js$/);
});

test("single-process isolation reports no slowest-file list", () => {
  const result = run({ "a.test.js": PASSING, "b.test.js": PASSING }, { isolation: "none" });
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stderr, /SLOWEST FILES/);
});
