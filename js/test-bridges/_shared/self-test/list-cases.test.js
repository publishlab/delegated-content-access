import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { listCases } from "../list-cases.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const portableTest = JSON.stringify(
  pathToFileURL(join(root, "test-reference/support/portable-test.js")).href,
);

// Cases declared through `test`, a renamed import, a portableTest binding and
// a suite. Each case fails, and the list names it all the same.
const CASES = `import full, { describe } from "node:test";
import { portableTest } from ${portableTest};
const selected = portableTest("some-selection");
full("a plain case", () => { throw new Error("a case that fails"); });
selected("a selected case", () => { throw new Error("a case that fails"); });
describe("a suite", () => {
  full("a nested case", () => { throw new Error("a case that fails"); });
});
`;

test("the case list names every case a test file registers, whatever the case does, and no suite", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-list-cases-"));
  const file = join(directory, "cases.test.js");
  writeFileSync(file, CASES);
  try {
    assert.deepEqual(listCases(file), ["a plain case", "a selected case", "a nested case"]);
    // A selection in the caller's environment would make other cases no-ops;
    // the list is still the whole file.
    assert.deepEqual(listCases(file, { ...process.env, DCA_TEST_SELECTION: "another" }), [
      "a plain case",
      "a selected case",
      "a nested case",
    ]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the case list refuses a test file that fails to load", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-list-cases-"));
  const file = join(directory, "broken.test.js");
  writeFileSync(file, `throw new Error("the file does not load");\n`);
  try {
    assert.throws(() => listCases(file), /cannot list the cases of .*broken\.test\.js/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
