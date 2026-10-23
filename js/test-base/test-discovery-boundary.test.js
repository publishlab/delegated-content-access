// @ts-check
//
// Where the gate's test files may live. `pnpm test` hands node one glob over the whole
// package and node runs every `*.test.js` it finds outside `experiments/` and
// `test-contract/`, so a directory nobody meant as a test directory joins the gate the
// moment a `*.test.js` file lands in it. A generated tree, a scratch copy or a vendored
// package would then run on every gate, or stop it, without anyone choosing that.
//
// The rule below names the three shapes a test file lives in
// here: a top-level `test*/` directory, `extensions/<name>/test/`, and
// `evidence-benchmarks/<name>/test/`. Benchmark runner tests form a separate
// tier; measurement scripts remain opt-in. A new
// `test-something/` directory joins the unit gate automatically, but does not
// silently join the public reference gate: that choice needs an explicit tier
// classification below. A file outside these shapes fails this check and must
// either move into an admitted test directory or make the boundary explicit here.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import {
  assertNoExecutableTestReentry,
  allImportEdgesOf,
  developmentImportEdgesOf,
  sideEffectImportSpecifiers,
} from "./sourceGraph.js";
import { developmentEdgesOf } from "./developmentGraph.js";
import { globSync, readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
const BENCHMARK_TEST_DIRECTORY = /^evidence-benchmarks\/[^/]+\/test\//;
const REFERENCE_TEST_DIRECTORY = /^test(?:\/|-(?:reference|extensions|profiles)\/)/;
const SEPARATE_TEST_TIERS = new Set(["test-base", "test-bridges", "test-tools", "test-vectors"]);

/** @param {string} file */
function isReferenceTest(file) {
  return REFERENCE_TEST_DIRECTORY.test(file) || EXTENSION_TEST_DIRECTORY.test(file);
}

/** @param {string[]} files */
function unclassifiedTestFiles(files) {
  return files.filter(
    (file) =>
      !isReferenceTest(file) &&
      !SEPARATE_TEST_TIERS.has(file.split("/")[0]) &&
      !BENCHMARK_TEST_DIRECTORY.test(file),
  );
}

/** @returns {string[]} */
function publicReferenceFiles() {
  const command = PACKAGE_JSON.scripts?.["test:reference:public"];
  assert.equal(typeof command, "string", "package.json declares test:reference:public");
  const patterns = [...command.matchAll(/"([^"]+\.test\.js)"/g)].map((match) => match[1]);
  assert.ok(patterns.length > 0, "the public reference command selects test files");
  return [...new Set(patterns.flatMap((pattern) => globSync(pattern, { cwd: V1_PATH })))].sort();
}

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
      (file) =>
        !TOP_LEVEL_TEST_DIRECTORY.test(file) &&
        !EXTENSION_TEST_DIRECTORY.test(file) &&
        !BENCHMARK_TEST_DIRECTORY.test(file),
    );
    assert.deepEqual(
      strays,
      [],
      "the gate runs these files from outside a test directory; move them under a top-level " +
        "test*/ directory, extensions/<name>/test/ or evidence-benchmarks/<name>/test/, " +
        "or state here why they belong",
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

  test("the public reference gate selects every admitted reference test and no separate tier", () => {
    const unitFiles = discoveredFiles();
    assert.deepEqual(
      unclassifiedTestFiles(unitFiles),
      [],
      "a new test directory needs an explicit reference or separate-tier classification; " +
        "test-lib/ may not contain test entry points",
    );
    assert.deepEqual(
      publicReferenceFiles(),
      unitFiles.filter(isReferenceTest),
      "public check must select every discovered reference test, with no extra tier",
    );
  });

  test("a new test directory and a test-lib entry point cannot disappear from public check", () => {
    assert.deepEqual(unclassifiedTestFiles(["test-new/case.test.js"]), ["test-new/case.test.js"]);
    assert.deepEqual(
      unclassifiedTestFiles(["evidence-benchmarks/example/test/runner.test.js"]),
      [],
    );
    assert.deepEqual(unclassifiedTestFiles(["evidence-benchmarks/example/src/runner.test.js"]), [
      "evidence-benchmarks/example/src/runner.test.js",
    ]);
    assert.deepEqual(unclassifiedTestFiles(["test-lib/case.test.js"]), ["test-lib/case.test.js"]);
    assert.deepEqual(unclassifiedTestFiles(["extensions/other/test-lib/case.test.js"]), [
      "extensions/other/test-lib/case.test.js",
    ]);
  });
});

describe("Test ownership preserves discovery", () => {
  test("public reference selectors match each file exactly once", () => {
    const patterns = [
      ...PACKAGE_JSON.scripts["test:reference:public"].matchAll(/"([^"]+\.test\.js)"/g),
    ].map((match) => match[1]);
    const selected = patterns.flatMap((pattern) => globSync(pattern, { cwd: V1_PATH }));
    assert.equal(selected.length, new Set(selected).size, "reference globs must not overlap");
  });

  test("side-effect test imports are detected without reading source-text fixtures", () => {
    const source = [
      'import "./second.test.js";',
      "import './third.test.js';",
      'import /* rationale */ "./fourth.test.js";',
      '// import "./comment.test.js";',
      '/* import "./block.test.js"; */',
      "const text = 'import \"./quoted.test.js\";';",
      'const fixture = `import "./fixture.test.js";`;',
      'const nested = `${import("./dynamic.test.js")}`;',
    ].join("\n");
    assert.deepEqual(sideEffectImportSpecifiers(source), [
      "./second.test.js",
      "./third.test.js",
      "./fourth.test.js",
    ]);
  });

  test("helper closures cannot register another executable test", () => {
    const scratch = mkdtempSync(join(tmpdir(), "dca-test-reentry-"));
    const root = pathToFileURL(`${scratch}/`);
    const entry = "extensions/example/test/first.test.js";
    const helper = "extensions/example/test/_lib/helper.js";
    mkdirSync(join(scratch, "extensions/example/test/_lib"), { recursive: true });
    writeFileSync(join(scratch, entry), 'import "./_lib/helper.js";');
    const edges = (rel) => developmentImportEdgesOf(rel, root);
    try {
      for (const source of [
        '  import "../second.test.js";',
        'export { value } from "../second.test.js";',
        'const lazy = () => import /* target */ ("../second.test.js");',
      ]) {
        writeFileSync(join(scratch, helper), source);
        assert.throws(
          () => assertNoExecutableTestReentry(entry, edges),
          /helper.js imports executable test/,
          source,
        );
      }
      for (const suffix of ["?review", "#review"]) {
        for (const source of [
          `export { value } from "../second.test.js${suffix}";`,
          `const lazy = () => import("../second.test.js${suffix}");`,
        ]) {
          writeFileSync(join(scratch, helper), source);
          assert.throws(
            () => assertNoExecutableTestReentry(entry, edges),
            /unsupported query or fragment/,
            source,
          );
        }
      }
      writeFileSync(join(scratch, helper), 'export { value } from "../second.%74est.js";');
      assert.throws(() => assertNoExecutableTestReentry(entry, edges), /imports executable test/);
      writeFileSync(join(scratch, helper), 'const fixture = `import "../second.test.js";`;');
      assertNoExecutableTestReentry(entry, edges);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("browser development mount retains closure only for its known host caller", () => {
    const scratch = mkdtempSync(join(tmpdir(), "dca-browser-dev-mount-"));
    const root = pathToFileURL(`${scratch}/`);
    const entry = "extensions/example/test/entry.test.js";
    const browser = "extensions/html-content-map/test/chromium.js";
    const other = "extensions/html-content-map/test/other.js";
    const production = "extensions/html-content-map/core-client/production.js";
    for (const directory of [
      "extensions/example/test",
      "extensions/html-content-map/test",
      "extensions/html-content-map/core-client",
    ])
      mkdirSync(join(scratch, directory), { recursive: true });
    const edges = (rel) => developmentEdgesOf(rel, root);
    try {
      writeFileSync(join(scratch, entry), 'import "../../html-content-map/test/chromium.js";');
      writeFileSync(join(scratch, production), "export const value = 42;");
      const productionImport = `const lazy = () => import("/__js/${production}");`;
      writeFileSync(join(scratch, browser), productionImport);
      assertNoExecutableTestReentry(entry, edges);
      assert.equal(edges(browser)[0].target, production);
      assert.throws(
        () => allImportEdgesOf(browser, root),
        /unsupported absolute path or URL scheme/,
      );
      writeFileSync(join(scratch, other), productionImport);
      assert.throws(() => edges(other), /unsupported absolute path or URL scheme/);
      writeFileSync(
        join(scratch, browser),
        'const lazy = () => import("/__js/extensions/example/test/second.test.js");',
      );
      assert.throws(() => assertNoExecutableTestReentry(entry, edges), /imports executable test/);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("tests import helpers rather than other executable test files", () => {
    for (const rel of discoveredFiles()) {
      assertNoExecutableTestReentry(rel, developmentEdgesOf);
    }
  });
});
