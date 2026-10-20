// @ts-check
//
// The base/extension source boundary, runnable after `extensions/` has been
// removed. The standard reference suite composes selected extensions and is
// therefore the wrong place to prove that the base distribution stands alone.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  allImportEdgesOf,
  dynamicImportExpressionsOf,
  runtimeImportEdge,
  closureOf,
  extensionOf,
  isDevelopmentModule,
  assertRuntimeClosure,
  extensionDependencyGraph,
  assertAcyclic,
  requiredExtensions,
} from "./sourceGraph.js";

const V1 = new URL("../", import.meta.url);
const V1_PATH = fileURLToPath(V1);

const ROOT_ENTRIES = readdirSync(V1_PATH, { withFileTypes: true });
const BASE_SOURCE_DIRS = ROOT_ENTRIES.filter(
  (entry) =>
    entry.isDirectory() &&
    (entry.name.startsWith("core-") ||
      entry.name.startsWith("adapter-") ||
      entry.name.startsWith("integration-") ||
      entry.name === "ports"),
).map((entry) => entry.name);
const BASE_BARRELS = ROOT_ENTRIES.filter(
  (entry) => entry.isFile() && entry.name.endsWith(".mjs"),
).map((entry) => entry.name);
const BASE_REFERENCE_DIRS = ["test", "test-reference"];

/** @returns {string[]} */
function extensionDirectories() {
  const extensionsPath = join(V1_PATH, "extensions");
  if (!existsSync(extensionsPath)) return [];
  return readdirSync(extensionsPath, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);
}

/** @param {string} extension @returns {string[]} */
function extensionEntries(extension) {
  return readdirSync(join(V1_PATH, "extensions", extension), { withFileTypes: true })
    .filter(
      (entry) => entry.isFile() && (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")),
    )
    .map((entry) => `extensions/${extension}/${entry.name}`);
}

/**
 * @param {string} scratch
 * @param {Set<string>} removedExtensions
 */
function copyTreeWithout(scratch, removedExtensions) {
  for (const entry of readdirSync(V1_PATH, { withFileTypes: true })) {
    if (entry.name === "node_modules") continue;
    if (entry.name !== "extensions") {
      cpSync(join(V1_PATH, entry.name), join(scratch, entry.name), {
        recursive: entry.isDirectory(),
      });
      continue;
    }
    const retained = readdirSync(join(V1_PATH, "extensions"), { withFileTypes: true }).filter(
      (extension) => extension.isDirectory() && !removedExtensions.has(extension.name),
    );
    if (retained.length > 0) mkdirSync(join(scratch, "extensions"));
    for (const extension of retained) {
      cpSync(
        join(V1_PATH, "extensions", extension.name),
        join(scratch, "extensions", extension.name),
        {
          recursive: true,
        },
      );
    }
  }
}

/** @param {string} scratch @param {string[]} modules */
function importFrom(scratch, modules) {
  const imports = modules.map((module) => `import(${JSON.stringify(`./${module}`)})`).join(", ");
  return spawnSync(
    process.execPath,
    ["--input-type=module", "--eval", `await Promise.all([${imports}])`],
    {
      cwd: scratch,
      encoding: "utf8",
    },
  );
}

/**
 * @param {string} dir - relative to `js/`
 * @returns {string[]}
 */
function modulesIn(dir) {
  /** @type {string[]} */
  const files = [];
  /** @param {string} directory */
  const visit = (directory) => {
    for (const entry of readdirSync(join(V1_PATH, directory), { withFileTypes: true })) {
      const child = `${directory}/${entry.name}`;
      if (entry.isDirectory()) visit(child);
      else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) files.push(child);
    }
  };
  visit(dir);
  return files;
}

/**
 * @param {string} rel
 * @param {{ target: string, specifier?: string }[]} edges
 */
// These three imports load entries copied to temporary extraction trees.
// Pin both caller and expression; other computed imports cannot evade base-only closure.
const BASE_EXTRACTION_IMPORTS = new Map([
  [
    "test-reference/integration-issuer/createIssuerCore.test.js",
    ['pathToFileURL(join(root, "integration-issuer/createIssuerCore.js")).href'],
  ],
  [
    "test-reference/integration-publisher/createPublisher.test.js",
    [
      'pathToFileURL(join(root, "integration-publisher/createPublisher.js")).href',
      'pathToFileURL(join(root, "adapter-publisher/writeMarkupDelivery.js")).href',
    ],
  ],
]);

function assertBaseEdges(rel, edges) {
  for (const edge of edges) {
    assert.ok(
      !edge.target.startsWith("<runtime import in ") ||
        (BASE_EXTRACTION_IMPORTS.get(rel) ?? []).some(
          (expression) => edge.specifier === `import(${expression})`,
        ),
      `${rel}: unresolved runtime import`,
    );
    assert.equal(
      extensionOf(edge.target),
      null,
      `${rel} imports ${edge.target}; base source cannot import an extension`,
    );
  }
}

describe("The base extension boundary", () => {
  test("every base core, adapter, port and barrel imports no extension", () => {
    assert.ok(BASE_BARRELS.length > 0, "the base tree exposes at least one root .mjs barrel");
    const modules = [...BASE_SOURCE_DIRS.flatMap(modulesIn), ...BASE_BARRELS];
    for (const rel of modules) assertBaseEdges(rel, allImportEdgesOf(rel));

    for (const barrel of BASE_BARRELS) {
      for (const rel of closureOf([barrel])) {
        assertBaseEdges(rel, allImportEdgesOf(rel));
      }
    }
  });

  test("the base-edge guard rejects core and barrel dependencies on an extension", () => {
    for (const rel of ["core-client/NewClient.js", "reference.mjs"]) {
      assert.throws(
        () => assertBaseEdges(rel, [{ target: "extensions/example/core-client/Example.js" }]),
        /base source cannot import an extension/,
      );
    }
  });

  test("computed base imports are pinned to the known extraction callers and expressions", () => {
    for (const [rel, expressions] of BASE_EXTRACTION_IMPORTS) {
      assert.deepEqual(
        dynamicImportExpressionsOf(rel),
        expressions,
        `${rel}: extraction imports remain exact`,
      );
      for (const expression of expressions) {
        assertBaseEdges(rel, [runtimeImportEdge(rel, expression)]);
        for (const other of [
          "test-reference/other.test.js",
          "test-lib/helper.js",
          "core-client/Client.js",
        ]) {
          assert.throws(
            () => assertBaseEdges(other, [runtimeImportEdge(other, expression)]),
            /unresolved runtime import/,
          );
        }
      }
      assert.throws(
        () => assertBaseEdges(rel, [runtimeImportEdge(rel, "otherPath")]),
        /unresolved runtime import/,
      );
    }
  });

  test("base reference files import no extension", () => {
    const extensionDependencies = [];
    for (const dir of BASE_REFERENCE_DIRS) {
      for (const rel of modulesIn(dir)) {
        assertBaseEdges(rel, allImportEdgesOf(rel));
        for (const reached of closureOf([rel])) {
          assertBaseEdges(reached, allImportEdgesOf(reached));
          if (extensionOf(reached) !== null) extensionDependencies.push(`${rel} -> ${reached}`);
        }
      }
    }
    assert.deepEqual(
      extensionDependencies,
      [],
      "base reference files cannot depend transitively on extensions",
    );
  });

  test("the base barrels load from an extracted tree with no extensions directory", () => {
    const scratch = mkdtempSync(join(tmpdir(), "dca-base-"));
    try {
      copyTreeWithout(scratch, new Set(extensionDirectories()));
      assert.equal(
        existsSync(join(scratch, "extensions")),
        false,
        "the extracted base smoke tree contains no extensions directory",
      );

      const result = importFrom(scratch, BASE_BARRELS);
      assert.equal(
        result.status,
        0,
        `base barrels failed without extensions:\n${result.stderr || result.stdout}`,
      );
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});

describe("Extension runtime dependencies", () => {
  const extensions = extensionDirectories();
  const modules = extensions.flatMap((name) => modulesIn(`extensions/${name}`));
  const runtime = modules.filter((rel) => !isDevelopmentModule(rel));
  const graph = extensionDependencyGraph(runtime);

  test("all extension runtime modules exclude development dependencies", () => {
    assertRuntimeClosure(runtime);
  });

  test("extension runtime dependencies are acyclic", () => {
    assertAcyclic(graph);
  });

  test("each extension loads with its required closure and no unrelated extensions", () => {
    for (const name of extensions) {
      const required = requiredExtensions(name, graph);
      const scratch = mkdtempSync(join(tmpdir(), `dca-closure-${name}-`));
      try {
        copyTreeWithout(scratch, new Set(extensions.filter((other) => !required.has(other))));
        const result = importFrom(scratch, [...BASE_BARRELS, ...extensionEntries(name)]);
        assert.equal(
          result.status,
          0,
          `${name}: required closure failed:\n${result.stderr || result.stdout}`,
        );
      } finally {
        rmSync(scratch, { recursive: true, force: true });
      }
    }
  });

  test("removing a required runtime dependency fails honestly", () => {
    for (const name of extensions) {
      for (const missing of requiredExtensions(name, graph)) {
        if (missing === name) continue;
        const scratch = mkdtempSync(join(tmpdir(), `dca-missing-${missing}-`));
        try {
          copyTreeWithout(scratch, new Set([missing]));
          // Include every runtime module, including private modules outside root entries.
          const result = importFrom(
            scratch,
            runtime.filter((rel) => extensionOf(rel) === name),
          );
          assert.notEqual(
            result.status,
            0,
            `${name}: missing required ${missing} must not silently load`,
          );
        } finally {
          rmSync(scratch, { recursive: true, force: true });
        }
      }
    }
  });

  test("classification defaults unknown helpers to runtime", () => {
    assert.equal(isDevelopmentModule("extensions/one/helper.js"), false);
    for (const directory of [
      "test",
      "test-lib",
      "test-support",
      "testing",
      "bench-scenarios",
      "tools",
    ]) {
      assert.equal(isDevelopmentModule(`extensions/one/${directory}/helper.js`), true);
    }
  });

  test("runtime closure rejects same-extension and transitive development dependencies", () => {
    const root = "extensions/one/helper.js";
    for (const target of [
      "extensions/one/test/helper.js",
      "extensions/two/bench-scenarios/case.js",
    ]) {
      const graph = new Map([
        [root, [{ specifier: "./helper.js", target }]],
        [target, []],
      ]);
      assert.throws(
        () => assertRuntimeClosure([root], (rel) => graph.get(rel) ?? []),
        /development code/,
      );
    }
    const helper = "extensions/two/helper.js";
    const dev = "extensions/two/test/fixture.js";
    const transitive = new Map([
      [root, [{ specifier: "./helper.js", target: helper }]],
      [helper, [{ specifier: "./fixture.js", target: dev }]],
      [dev, []],
    ]);
    assert.throws(
      () => assertRuntimeClosure([root], (rel) => transitive.get(rel) ?? []),
      /development code/,
    );
    assert.throws(
      () =>
        assertRuntimeClosure([root], () => [
          { specifier: "import(path)", target: `<runtime import in ${root}>` },
        ]),
      /unresolved runtime import/,
    );
  });

  test("dependency graph accepts sibling reuse, excludes development and rejects cycles", () => {
    const a = "extensions/one/helper.js";
    const b = "extensions/two/helper.js";
    const dev = "extensions/three/test/case.js";
    const edges = new Map([
      [a, [{ specifier: "./two.js", target: b }]],
      [b, []],
      [dev, [{ specifier: "./one.js", target: a }]],
    ]);
    const graph = extensionDependencyGraph([a, b, dev], (rel) => edges.get(rel) ?? []);
    assert.deepEqual([...requiredExtensions("one", graph)].sort(), ["one", "two"]);
    assert.equal(graph.has("three"), false);
    assertAcyclic(graph);
    graph.get("two").add("one");
    assert.throws(() => assertAcyclic(graph), /dependency cycle/);
  });
});
