// @ts-check
//
// Where the gate's test files may live. `pnpm test` hands node one glob over the whole
// package and node runs every `*.test.js` it finds outside `experiments/` and
// `test-contract/`, so a directory nobody meant as a test directory joins the gate the
// moment a `*.test.js` file lands in it. A generated tree, a scratch copy or a vendored
// package would then run on every gate, or stop it, without anyone choosing that.
//
// The rule below names no directory list. It names the two shapes a test file lives in
// here: a top-level `test*/` directory, and `extensions/<name>/test/`. A new
// `test-something/` directory joins the gate automatically. A file outside these
// shapes fails this check and must either move into an admitted test directory or make
// the boundary change explicit here.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { globSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const V1_PATH = fileURLToPath(new URL("../", import.meta.url));

const PACKAGE_JSON = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

function gateGlob() {
  const command = PACKAGE_JSON.scripts?.["test:unit"];
  assert.equal(typeof command, "string", "package.json declares test:unit");
  const patterns = [...command.matchAll(/"([^"]+\.test\.js)"/g)].map((match) => match[1]);
  assert.equal(patterns.length, 1, "test:unit carries one quoted discovery glob");
  return patterns[0];
}

const TOP_LEVEL_TEST_DIRECTORY = /^test[^/]*\//;
const EXTENSION_TEST_DIRECTORY = /^extensions\/[^/]+\/test\//;

/** @returns {string[]} */
function discoveredFiles() {
  return globSync(gateGlob(), { cwd: V1_PATH })
    .map((file) => file.split("\\").join("/"))
    .sort();
}

describe("The discovery boundary of the test gate", () => {
  test("the gate glob reaches the test directories", () => {
    const files = discoveredFiles();
    assert.ok(files.length > 100, `the gate glob found ${files.length} test files`);
    for (const shape of [TOP_LEVEL_TEST_DIRECTORY, EXTENSION_TEST_DIRECTORY]) {
      assert.ok(
        files.some((file) => shape.test(file)),
        `no discovered file matches ${shape}`,
      );
    }
  });

  test("every file the gate discovers sits in a test directory", () => {
    const strays = discoveredFiles().filter(
      (file) => !TOP_LEVEL_TEST_DIRECTORY.test(file) && !EXTENSION_TEST_DIRECTORY.test(file),
    );
    assert.deepEqual(
      strays,
      [],
      "the gate runs these files from outside a test directory; move them under a top-level " +
        "test*/ directory or extensions/<name>/test/, or state here why they belong",
    );
  });

  test("the excluded tiers stay out of the gate", () => {
    const files = discoveredFiles();
    for (const excluded of ["experiments/", "test-contract/issuer-core/"]) {
      assert.deepEqual(
        files.filter((file) => file.startsWith(excluded)),
        [],
        `${excluded}: this tier runs from its own command, not from the gate glob`,
      );
    }
  });
});
