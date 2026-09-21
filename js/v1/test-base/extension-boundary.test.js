// @ts-check
//
// The base/extension source boundary, runnable after `extensions/` has been
// removed. The standard reference suite composes selected extensions and is
// therefore the wrong place to prove that the base distribution stands alone.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

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
 * @param {string} dir - relative to `js/v1/`
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
 * Read static imports and re-exports. Every import declaration in this tree
 * uses `from`; refusing a partial read keeps a new statement shape from
 * silently escaping the gate.
 *
 * @param {string} rel
 * @returns {{ specifier: string, target: string }[]}
 */
function staticEdgesOf(rel) {
  const from = new URL(rel, V1);
  const source = readFileSync(from, "utf8");
  const declarations = [
    ...source.matchAll(/^(import|export)\b([^'\"]*?)from\s*(['\"])([^'\"]+)\3/gm),
  ];
  const importStatements = (source.match(/^import\b/gm) ?? []).length;
  const importsRead = declarations.filter((match) => match[1] === "import").length;
  assert.equal(
    importsRead,
    importStatements,
    `${rel}: ${importStatements} import statements, ${importsRead} read - the base gate missed one`,
  );

  return declarations.map((match) => {
    const specifier = match[4];
    return {
      specifier,
      target: specifier.startsWith(".")
        ? new URL(specifier, from).href.slice(V1.href.length)
        : specifier,
    };
  });
}

/** @param {string} rel @returns {string|null} */
function extensionOf(rel) {
  return /^extensions\/([^/]+)\//.exec(rel)?.[1] ?? null;
}

/**
 * @param {string} rel
 * @param {{ target: string }[]} edges
 */
function assertBaseEdges(rel, edges) {
  for (const edge of edges) {
    assert.equal(
      extensionOf(edge.target),
      null,
      `${rel} imports ${edge.target}; base source cannot import an extension`,
    );
  }
}

/**
 * @param {string} rel
 * @param {{ target: string }[]} edges
 */
function assertExtensionEdges(rel, edges) {
  const sourceExtension = extensionOf(rel);
  assert.notEqual(sourceExtension, null, `${rel}: expected an extension source path`);
  for (const edge of edges) {
    const targetExtension = extensionOf(edge.target);
    assert.ok(
      targetExtension === null || targetExtension === sourceExtension,
      `${rel} imports ${edge.target}; extensions cannot import sibling extensions`,
    );
  }
}

/**
 * Complete relative static closure of the named entries.
 *
 * @param {string[]} entries
 * @returns {Set<string>}
 */
function closureOf(entries) {
  const seen = new Set();
  const queue = [...entries];
  while (queue.length > 0) {
    const rel = /** @type {string} */ (queue.shift());
    if (seen.has(rel)) continue;
    seen.add(rel);
    assert.ok(existsSync(new URL(rel, V1)), `${rel}: source closure target exists`);
    for (const edge of staticEdgesOf(rel)) {
      if (edge.specifier.startsWith(".")) queue.push(edge.target);
    }
  }
  return seen;
}

describe("The base extension boundary", () => {
  test("every base core, adapter, port and barrel imports no extension", () => {
    assert.ok(BASE_BARRELS.length > 0, "the base tree exposes at least one root .mjs barrel");
    const modules = [...BASE_SOURCE_DIRS.flatMap(modulesIn), ...BASE_BARRELS];
    for (const rel of modules) assertBaseEdges(rel, staticEdgesOf(rel));

    for (const barrel of BASE_BARRELS) {
      for (const rel of closureOf([barrel])) {
        assertBaseEdges(rel, staticEdgesOf(rel));
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

  test("base reference files import no extension", () => {
    const extensionDependencies = [];
    for (const dir of BASE_REFERENCE_DIRS) {
      for (const rel of modulesIn(dir)) {
        assertBaseEdges(rel, staticEdgesOf(rel));
        for (const reached of closureOf([rel])) {
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

describe("The boundary between extensions", () => {
  test("an extension imports base or itself, never a sibling extension", () => {
    const extensionsPath = join(V1_PATH, "extensions");
    if (!existsSync(extensionsPath)) return;
    const siblingDependencies = [];
    for (const entry of readdirSync(extensionsPath, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      for (const rel of modulesIn(`extensions/${entry.name}`)) {
        assertExtensionEdges(rel, staticEdgesOf(rel));
        for (const reached of closureOf([rel])) {
          const reachedExtension = extensionOf(reached);
          if (reachedExtension !== null && reachedExtension !== entry.name) {
            siblingDependencies.push(`${rel} -> ${reached}`);
          }
        }
      }
    }
    assert.deepEqual(siblingDependencies, [], "extensions cannot depend transitively on siblings");
  });

  test("the extension-edge guard rejects a sibling dependency", () => {
    assert.throws(
      () =>
        assertExtensionEdges("extensions/one/core-client/One.js", [
          { target: "extensions/two/core-shared/Two.js" },
        ]),
      /extensions cannot import sibling extensions/,
    );
  });

  test("each extension can be removed while base and every remaining extension entry still load", () => {
    const extensionsPath = join(V1_PATH, "extensions");
    if (!existsSync(extensionsPath)) return;
    const extensions = extensionDirectories();

    for (const removed of extensions) {
      const scratch = mkdtempSync(join(tmpdir(), `dca-without-${removed}-`));
      try {
        copyTreeWithout(scratch, new Set([removed]));
        assert.equal(
          existsSync(join(scratch, "extensions", removed)),
          false,
          `${removed}: removed extension is absent from its smoke tree`,
        );
        const remainingEntries = extensions
          .filter((extension) => extension !== removed)
          .flatMap(extensionEntries);
        const result = importFrom(scratch, [...BASE_BARRELS, ...remainingEntries]);
        assert.equal(
          result.status,
          0,
          `${removed}: base or remaining extension entries failed after removal:\n${result.stderr || result.stdout}`,
        );
      } finally {
        rmSync(scratch, { recursive: true, force: true });
      }
    }
  });
});
