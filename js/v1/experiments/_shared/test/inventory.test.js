// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

const EXPERIMENTS = new URL("../../", import.meta.url);
const packageJson = JSON.parse(readFileSync(new URL("../package.json", EXPERIMENTS), "utf8"));

/**
 * Every entry point the runner glob selects, as a path relative to
 * `experiments/`. One directory per experiment means one `test/` per
 * directory, `_shared/test/` included, so the walk covers what the glob
 * selects.
 *
 * @returns {string[]}
 */
function entryPoints() {
  /** @type {string[]} */
  const found = [];
  for (const experiment of readdirSync(EXPERIMENTS, { withFileTypes: true })) {
    if (!experiment.isDirectory()) continue;
    const dir = `${experiment.name}/test/`;
    let entries;
    try {
      entries = readdirSync(new URL(dir, EXPERIMENTS), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isFile() && entry.name.endsWith(".test.js")) found.push(`${dir}${entry.name}`);
    }
  }
  return found.sort();
}

const EXPECTED = [
  "_shared/test/bind-version-migration.test.js",
  "_shared/test/inventory.test.js",
  "bind-on-accessGroup/test/characterization.test.js",
  "bind-on-accessGroup/test/comparison.test.js",
  "bind-on-authority/test/comparison.test.js",
  "bind-on-authority/test/control.test.js",
  "bind-on-renderId-and-slot/test/bind-self-test.test.js",
  "bind-on-renderId-and-slot/test/comparison.test.js",
  "derived-content-aad/test/comparison.test.js",
  "retained-render/test/authority-by-kind.test.js",
  "retained-render/test/render-coordinate.test.js",
  "retained-render/test/scope-coordinate.test.js",
];

test("the experiment entrypoint baseline and explicit runner are unchanged", () => {
  assert.deepEqual(
    entryPoints(),
    EXPECTED,
    "experiment entrypoints changed; update this baseline with the intended suite change",
  );
  assert.equal(
    packageJson.scripts["test:experiments"],
    'node --test "experiments/*/test/*.test.js"',
  );
});
