// @ts-check
//
// Who inside the core may import whom. The rules come from the layout design
// § "The core split by role", stated there as the assertions this file runs.
// The split has landed: the flat `core/` is now four sibling directories -
// `core-shared/`, `core-publisher/`, `core-issuer/`, `core-client/` - and
// a module takes its role from the directory it sits in.
//
// The role map below walks the four directory trees recursively, so membership
// follows a file's path and cannot drift from disk, and no table has to be kept
// in step with the tree. The set of role directories itself still has to be
// pinned - a new `core-*` dir the rules do not iterate would carry modules no
// rule here examines - and the last test holds that.
//
// The filesystem makes the rules exhaustive. A `.js` file anywhere below a
// core role directory has that role whether or not anyone thought about it, so
// a new core module gets a role the moment it lands and every rule below
// reaches it. This is the strength the flat version bought with a table held
// against `readdir`; the directories give it for free.
//
// Every rule reads source text and parses import statements on purpose; nothing
// in the core is executed here. A role's implementer has to carry an import
// edge along whether or not today's run reaches it, so a role's slice is exactly
// its import closure - which is why splitting the client-bound
// transport out of `keySealing.js` keeps `bind.js` and the seal side out of the
// client's closure entirely.
//
// Role guards follow static imports, re-exports and runtime import() edges.
// Unsupported or unresolved runtime forms fail rather than disappearing from
// the graph. JSDoc type imports are erased at runtime; extracted-contract
// checks account for them separately where the public type surface needs them.
//
// Scope: rules 1-5 bind the four core directories only. `adapter-*/`, `ports/`,
// `demo/`, `tools/`, `experiments/`, `test-lib/` and `test/`
// and `test-reference/` cross roles by design, and
// `demo/browser/` simulates every role in one tab - which is why the
// shipped-to-the-browser rule is pointed at `demo/actors/Browser.js` and
// `demo/actors/PageLoad.js`, the client walk, and never at `demo/browser/`.
//
// Reading source needs the filesystem, which core, ports and actors never
// touch. This is a test file, so `node:fs` is at hand here the way `node:test`
// is.

import {
  importsOf,
  closureOf,
  reexportAwareTargets,
  dynamicImportExpressionsOf,
  runtimeDynamicImportExpressions,
  allImportEdgesOf,
  assertRuntimeClosure,
} from "./sourceGraph.js";
import { developmentEdgesOf } from "./developmentGraph.js";
import { copyManifestFiles } from "../tools/copyManifest.js";
import test, { describe } from "node:test";
import assert from "node:assert/strict";
import {
  readdirSync,
  readFileSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
} from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

const V1 = new URL("../", import.meta.url);
const EXPERIMENTS_PRESENT = existsSync(fileURLToPath(new URL("experiments/_implementation/", V1)));

/**
 * The base core, three role cores and the non-empty pairwise slices. The base
 * is the bottom of every role extraction; a pairwise slice belongs only to its
 * named consumers. The disk check below prevents a new core directory from
 * escaping this map.
 */
const CORE_ROLES = [
  "core-shared",
  "core-publisher",
  "core-issuer",
  "core-client",
  "core-shared--client-issuer",
  "core-shared--client-publisher",
  "core-shared--publisher-issuer",
];

/** The application roles: everything but shared. Rule 2 iterates these. */
const APP_ROLES = ["core-publisher", "core-issuer", "core-client"];

/** Every pairwise slice, including the deliberately absent empty candidate. */
const PAIRWISE_CONSUMERS = new Map([
  ["core-shared--client-issuer", ["core-client", "core-issuer"]],
  ["core-shared--client-publisher", ["core-client", "core-publisher"]],
  ["core-shared--publisher-issuer", ["core-publisher", "core-issuer"]],
]);

/**
 * The optional source trees reuse the base role vocabulary below one named
 * extension. Discovering them here keeps a nested `core-*` directory from
 * falling outside the role checks that protect the base tree.
 */
const EXTENSION_CORE_SLICES = (() => {
  const root = fileURLToPath(new URL("extensions/", V1));
  if (!existsSync(root)) return [];
  /** @type {{ extension: string, slice: string, dir: string }[]} */
  const found = [];
  for (const extension of readdirSync(root, { withFileTypes: true })) {
    if (!extension.isDirectory()) continue;
    const extensionDir = `extensions/${extension.name}/`;
    for (const entry of readdirSync(fileURLToPath(new URL(extensionDir, V1)), {
      withFileTypes: true,
    })) {
      assert.ok(
        !entry.isDirectory() || !["client", "issuer", "publisher", "shared"].includes(entry.name),
        `${extensionDir}${entry.name}: extension role slices use the core-* names and cannot evade role checks`,
      );
      if (!entry.isDirectory() || !entry.name.startsWith("core-")) continue;
      assert.ok(
        CORE_ROLES.includes(entry.name),
        `${extensionDir}${entry.name}: extension role slices use the base core vocabulary`,
      );
      found.push({
        extension: extension.name,
        slice: entry.name,
        dir: `${extensionDir}${entry.name}`,
      });
    }
  }
  return found;
})();

/** Extension adapters and integrations have the same inward rules as base tiers. */
const EXTENSION_OUTER_SLICES = (() => {
  const root = fileURLToPath(new URL("extensions/", V1));
  if (!existsSync(root)) return [];
  const found = [];
  for (const extension of readdirSync(root, { withFileTypes: true })) {
    if (!extension.isDirectory()) continue;
    const extensionDir = `extensions/${extension.name}/`;
    for (const entry of readdirSync(fileURLToPath(new URL(extensionDir, V1)), {
      withFileTypes: true,
    })) {
      if (!entry.isDirectory() || !/^(adapter|integration)-/.test(entry.name)) continue;
      assert.ok(
        /^(adapter|integration)-(client|issuer|publisher)$/.test(entry.name),
        `${extensionDir}${entry.name}: unknown extension role tier`,
      );
      found.push({
        extension: extension.name,
        slice: entry.name,
        dir: `${extensionDir}${entry.name}`,
      });
    }
  }
  return found;
})();

/** @param {string} role @returns {Set<string>} */
function allowedCoreSlicesFor(role) {
  return new Set([
    "core-shared",
    role,
    ...[...PAIRWISE_CONSUMERS]
      .filter(([, consumers]) => consumers.includes(role))
      .map(([slice]) => slice),
  ]);
}

/**
 * Every role directory in the layout. The four core dirs plus the tiers around
 * them: the delivery adapters, the default port, the three composition entries a
 * consumer copies, and the demo composition. The
 * core rules bind only the core dirs; the adapter, integration and demo tiers are here so the
 * client-walk rule can name exactly what a page loads, across every tier it
 * reaches. `demo/browser/` is left out on purpose - it is the composition root
 * that runs every role in one tab and sits outside these rules by design.
 */
const ROLE_DIRS = [
  ...CORE_ROLES,
  "adapter-publisher",
  "adapter-client",
  "adapter-issuer",
  "integration-client",
  "integration-publisher",
  "integration-issuer",
  "ports",
  "demo",
  "demo/actors",
  "demo/actors/issuer",
  "demo/support",
  "demo/scenarios",
  ...EXTENSION_CORE_SLICES.map(({ dir }) => dir),
  ...EXTENSION_OUTER_SLICES.map(({ dir }) => dir),
];

/** The publisher- and issuer-side tiers: no client walk may reach one. */
const PUBLISHER_ISSUER_TIERS = [
  "core-publisher",
  "core-issuer",
  "adapter-publisher",
  "adapter-issuer",
  "integration-publisher",
  "integration-issuer",
];

/**
 * The inward dependencies each reusable outer boundary may carry.
 * `integration-client/` composes what a browser client keeps, so it reaches the
 * client adapters as well as the client core slices, and reaches no port.
 * `integration-publisher/` composes the Sealer and reaches no adapter: a host
 * writes markup with `adapter-publisher/` itself. `integration-issuer/`
 * composes the issuer core under the unlock endpoint port and the browser
 * admission adapter. Hosts still provide transport, registration and policy.
 */
const OUTER_ALLOWED = new Map([
  ["adapter-publisher", new Set(["adapter-publisher", ...allowedCoreSlicesFor("core-publisher")])],
  ["adapter-client", new Set(["adapter-client", ...allowedCoreSlicesFor("core-client")])],
  ["adapter-issuer", new Set(["adapter-issuer", ...allowedCoreSlicesFor("core-issuer")])],
  [
    "integration-client",
    new Set(["integration-client", "adapter-client", ...allowedCoreSlicesFor("core-client")]),
  ],
  [
    "integration-publisher",
    new Set(["integration-publisher", ...allowedCoreSlicesFor("core-publisher")]),
  ],
  [
    "integration-issuer",
    new Set([
      "integration-issuer",
      "ports",
      "adapter-issuer",
      ...allowedCoreSlicesFor("core-issuer"),
    ]),
  ],
  ["ports", new Set(["ports", ...allowedCoreSlicesFor("core-issuer")])],
]);

/**
 * @param {string} dir - a directory relative to `js/`
 * @returns {string[]} its `.js` and `.mjs` files, including nested directories, as paths
 *   relative to `js/`
 */
function jsFilesIn(dir) {
  /** @type {string[]} */
  const files = [];
  /** @param {string} directory - relative to `js/`, with a trailing slash */
  const visit = (directory) => {
    for (const entry of readdirSync(fileURLToPath(new URL(directory, V1)), {
      withFileTypes: true,
    })) {
      const child = `${directory}${entry.name}`;
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules") visit(`${child}/`);
      } else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) files.push(child);
    }
  };
  visit(dir === "" ? "" : `${dir}/`);
  return files;
}

/**
 * Module path (relative to `js/`) to the role directory that owns it, built
 * by walking role directories. Core role trees are siblings, so a core module
 * has exactly one role; nested demo directories follow their more-specific
 * entry in `ROLE_DIRS`.
 *
 * @type {Map<string, string>}
 */
const ROLE_OF = new Map(
  ROLE_DIRS.flatMap((role) =>
    jsFilesIn(role).map((rel) => {
      const extensionSlice = [...EXTENSION_CORE_SLICES, ...EXTENSION_OUTER_SLICES].find(
        ({ dir }) => dir === role,
      );
      return /** @type {[string, string]} */ ([rel, extensionSlice?.slice ?? role]);
    }),
  ),
);

/**
 * @param {string} role
 * @returns {string[]} that role's modules, including nested directories, as
 *   paths relative to `js/`
 */
function modulesOf(role) {
  return jsFilesIn(role);
}

/**
 * @param {string} rel
 * @returns {string} the role owning that module, or a phrase naming what it is
 *   instead - an import out of the core into a sibling tier lands here and fails
 *   every rule
 */
function roleOf(rel) {
  return ROLE_OF.get(rel) ?? "outside the role map";
}

describe("Real source declaration positions", () => {
  test("local graphs reject absolute and URL imports while retaining relative, node and package edges", () => {
    const scratch = mkdtempSync(join(tmpdir(), "dca-module-specifiers-"));
    const root = pathToFileURL(`${scratch}/`);
    const entry = "extensions/example/probe.js";
    const production = "extensions/example/production.js";
    const dev = "extensions/example/test/secret.js";
    const write = (rel, source) => {
      mkdirSync(dirname(join(scratch, rel)), { recursive: true });
      writeFileSync(join(scratch, rel), source);
    };
    const edges = (rel) => allImportEdgesOf(rel, root);
    const sources = (specifier) => [
      `import { value } from ${JSON.stringify(specifier)};`,
      `export { value } from ${JSON.stringify(specifier)};`,
      `const lazy = () => import(${JSON.stringify(specifier)});`,
    ];
    try {
      write(dev, "export const value = 42;");
      write(production, "export const value = 42;");
      for (const specifier of [
        join(scratch, dev),
        pathToFileURL(join(scratch, dev)).href,
        "data:text/javascript,export const value=42",
        "https://example.test/module.js",
        "C:/fixtures/secret.js",
        "\\fixtures\\secret.js",
      ]) {
        for (const source of sources(specifier)) {
          write(entry, source);
          assert.throws(
            () => assertRuntimeClosure([entry], edges),
            /unsupported absolute path or URL scheme/,
            source,
          );
        }
      }
      for (const specifier of ["./production.js", "node:fs", "parse5"]) {
        for (const source of sources(specifier)) {
          write(entry, source);
          assert.equal(edges(entry)[0].specifier, specifier);
          assertRuntimeClosure([entry], edges);
        }
      }
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("indented, inline, commented and dynamic edges reach runtime and role guards", () => {
    const scratch = mkdtempSync(join(tmpdir(), "dca-static-source-"));
    const root = pathToFileURL(`${scratch}/`);
    const entry = "extensions/content-groups/core-client/review-probe.js";
    const helper = "extensions/content-groups/helper.js";
    const dev = "extensions/content-groups/test/_lib/chainPort.js";
    const write = (rel, source) => {
      mkdirSync(dirname(join(scratch, rel)), { recursive: true });
      writeFileSync(join(scratch, rel), source);
    };
    const edges = (rel) => allImportEdgesOf(rel, root);
    try {
      write(dev, "export const CHAIN = 1;");
      for (const source of [
        '  import { CHAIN } from "../test/_lib/chainPort.js";',
        '/* eslint extraction/imports:off */ import { CHAIN } from "../test/_lib/chainPort.js";',

        'const marker = 1; import { CHAIN } from "../test/_lib/chainPort.js";',
        '/* lead */ import /* binding */ { CHAIN } from /* target */ "../test/_lib/chainPort.js";',
        '  export { CHAIN } from "../test/_lib/chainPort.js";',
        'const marker = 1; export { /* } misleading */ CHAIN } from /* target */ "../test/_lib/chainPort.js";',
        'export * from "../test/_lib/chainPort.js";',
        'const lazy = () => import /* target */ ("../test/_lib/chainPort.js");',
        'let x=1; x++ / 2; import { CHAIN } from "../test/_lib/chainPort.js";',
        'const of=1; of / 2; import { CHAIN } from "../test/_lib/chainPort.js";',
        'const lazy = () => import("\\u002e\\u002e/test/_lib/chainPort.js");',
      ]) {
        write(entry, source);
        assert.equal(edges(entry).length, 1, source);
        assert.throws(() => assertRuntimeClosure([entry], edges), /development code/, source);
      }
      write(entry, '  import { CHAIN } from "../helper.js";');
      write(helper, '  export { CHAIN } from "./test/_lib/chainPort.js";');
      assert.throws(() => assertRuntimeClosure([entry], edges), /development code/);
      write(
        entry,
        '  export { periodFamilyGeneration } from "../../chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";',
      );
      assert.throws(
        () => assertExtensionCoreRoleTarget(entry, "core-client", edges(entry)[0].target),
        /forbidden/,
      );
      write(entry, 'import { CHAIN } from "../test/_lib/\\u0063hainPort.js";');
      assert.throws(() => assertRuntimeClosure([entry], edges), /development code/);
      write(entry, 'import { CHAIN from "../test/_lib/chainPort.js";');
      assert.throws(() => edges(entry), /source graph parse failed/);
      write(entry, 'const fixture = `  import { CHAIN } from "../test/_lib/chainPort.js";`;');
      assert.deepEqual(edges(entry), []);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});

describe("The import parser reads either quote style", () => {
  // `test-base/fixtures/quote-styles.fixture.js` holds one single-quoted and
  // one double-quoted `from` specifier, importing two sibling fixtures. The
  // fixture exists on disk because both parsers below build a `file://` URL
  // from a path relative to `V1` and read real source text; a source string
  // held only in this test would exercise a different code path.
  const FIXTURE = "test-base/fixtures/quote-styles.fixture.js";

  test("importsOf reads a single-quoted and a double-quoted import", () => {
    const edges = importsOf(FIXTURE);
    assert.deepEqual(
      edges.map((edge) => edge.target),
      ["test-base/fixtures/sibling-a.fixture.js", "test-base/fixtures/sibling-b.fixture.js"],
    );
  });

  test("reexportAwareTargets reads a single-quoted and a double-quoted import", () => {
    assert.deepEqual(reexportAwareTargets(FIXTURE), [
      "test-base/fixtures/sibling-a.fixture.js",
      "test-base/fixtures/sibling-b.fixture.js",
    ]);
  });
});

describe("The boundary between the roles inside the core", () => {
  test("a shared module imports nothing that is not shared", () => {
    // Rule 1. Shared is the bottom of the tree: both ends of the wire hold
    // these bytes, so a shared module reaching a role's module would make
    // that role's code part of every other role's slice.
    for (const rel of modulesOf("core-shared")) {
      for (const edge of allImportEdgesOf(rel)) {
        assert.equal(
          roleOf(edge.target),
          "core-shared",
          `${rel} imports ${edge.target}, which is ${roleOf(edge.target)}`,
        );
      }
    }
  });

  test("a role module imports only its base and named pairwise slices", () => {
    // Rule 2. A role extraction is its base, its own core, and exactly the
    // pairwise slices whose names include that role.
    for (const role of APP_ROLES) {
      for (const rel of modulesOf(role)) {
        for (const edge of allImportEdgesOf(rel)) {
          const target = roleOf(edge.target);
          assert.ok(
            allowedCoreSlicesFor(role).has(target),
            `${rel} (${role}) imports ${edge.target}, which is ${target}`,
          );
        }
      }
    }
  });

  test("a pairwise slice imports only itself and the universal base", () => {
    for (const [slice] of PAIRWISE_CONSUMERS) {
      if (!CORE_ROLES.includes(slice)) continue;
      for (const rel of modulesOf(slice)) {
        for (const edge of allImportEdgesOf(rel)) {
          const target = roleOf(edge.target);
          assert.ok(
            target === slice || target === "core-shared",
            `${rel} (${slice}) imports ${edge.target}, which is ${target}`,
          );
        }
      }
    }
  });

  test("the client imports no periodKeys.js", () => {
    // Rule 3. True today and after the derivation cut with no carve-out:
    // the cache sorts `t` as an opaque string and needs no label
    // arithmetic, so neither half of that file has a client caller.
    for (const rel of modulesOf("core-client")) {
      for (const edge of allImportEdgesOf(rel)) {
        assert.notEqual(
          edge.target,
          "core-shared--publisher-issuer/periodKeys.js",
          `${rel} imports periodKeys.js`,
        );
      }
    }
  });

  test("the client imports no jwt.js", () => {
    // Rule 4. `jwt.js` is publisher (sign) and issuer (verify) material and
    // stays shared on that basis; this is the assertion carrying the claim
    // that the client never joins them.
    for (const rel of modulesOf("core-client")) {
      for (const edge of allImportEdgesOf(rel)) {
        assert.notEqual(
          edge.target,
          "core-shared--publisher-issuer/jwt.js",
          `${rel} imports jwt.js`,
        );
      }
    }
  });

  test("core-client imports no client-bound extension", () => {
    // Rule 5. Client-bound transport is an optional extension, so the base
    // core-client slice must not carry it at all. The generic AES-GCM unwrap-to-handle
    // primitive the cached trial needs lives in `aead.js` (`decryptToKey`, the
    // twin of `decrypt`), so the resolver opens a cached handle with a shared
    // primitive and reaches no profile module. The client-bound transport
    // itself is injected as a capability, never hardcoded into core-client.
    for (const rel of modulesOf("core-client")) {
      for (const edge of allImportEdgesOf(rel)) {
        assert.ok(
          !edge.target.startsWith("extensions/client-bound-transport/"),
          `${rel} imports the optional client-bound transport extension`,
        );
      }
    }
  });

  test("the label half of periodKeys.js references no crypto", () => {
    // `periodKeys.js` is label arithmetic alone. Base carries opaque keys
    // and names no construction for their bytes.
    const source = readFileSync(
      fileURLToPath(new URL("core-shared--publisher-issuer/periodKeys.js", V1)),
      "utf8",
    );
    for (const token of ["subtle", "HKDF", "deriveBits", "importKey", "crypto"]) {
      assert.ok(
        !source.includes(token),
        `periodKeys.js names "${token}" - base labels must stay independent of key construction`,
      );
    }
  });

  test("the retired JavaScript derivation profile cannot return", () => {
    assert.equal(
      existsSync(fileURLToPath(new URL("core-shared/periodKeyDerivation.js", V1))),
      false,
      "optional key derivation must not live inside a base core directory",
    );

    const transcriptTokens = [
      ["dca", "day", "chain", "v1"].join("-"),
      ["dca", "day", "chain", "step", "v1"].join("-"),
      ["dca", "day", "chain", "leaf", "v1"].join("-"),
    ];
    for (const rel of jsFilesIn("")) {
      const source = readFileSync(fileURLToPath(new URL(rel, V1)), "utf8");
      for (const token of transcriptTokens) {
        assert.ok(!source.includes(token), `${rel} restores retired transcript ${token}`);
      }
    }
  });

  test("base role cores do not reach extensions", () => {
    // Optional code is selected by composition. Base role cores only know
    // the narrow operations they receive and cannot pull a named extension
    // into an otherwise base-only distribution.
    for (const entry of [
      "core-publisher/Sealer.js",
      "core-issuer/IssuerEngine.js",
      "core-client/ContentKeyResolver.js",
    ]) {
      assert.ok(
        ![...closureOf([entry])].some((rel) => rel.startsWith("extensions/")),
        `${entry} reaches an extension - base cores must stay base-only`,
      );
    }
  });
});

function assertExtensionCoreRoleTarget(rel, slice, target) {
  const allowed = slice === "core-shared" ? new Set(["core-shared"]) : allowedCoreSlicesFor(slice);
  assert.ok(allowed.has(roleOf(target)), `${rel} (${slice}) imports forbidden ${target}`);
}

describe("The boundary inside extensions", () => {
  test("sibling reuse preserves role and pairwise consumer boundaries", () => {
    const client = "extensions/example/core-client/Client.js";
    const pairwise = "extensions/example/core-shared--client-issuer/Request.js";
    assertExtensionCoreRoleTarget(
      client,
      "core-client",
      "extensions/chain-keys/core-client/ChainKeyCache.js",
    );
    assertExtensionCoreRoleTarget(
      pairwise,
      "core-shared--client-issuer",
      "extensions/chain-keys/core-shared--client-issuer/ChainKeyRequest.js",
    );
    assert.throws(
      () =>
        assertExtensionCoreRoleTarget(
          client,
          "core-client",
          "extensions/chain-keys/core-issuer/chainKeyIssuerEngine.js",
        ),
      /forbidden/,
    );
    assert.throws(
      () =>
        assertExtensionCoreRoleTarget(
          pairwise,
          "core-shared--client-issuer",
          "extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js",
        ),
      /forbidden/,
    );
  });

  test("extension adapters and integrations obey their inward role rules", () => {
    for (const { extension, slice, dir } of EXTENSION_OUTER_SLICES) {
      const allowed = OUTER_ALLOWED.get(slice);
      assert.ok(allowed, `${dir}: a role tier needs an inward rule`);
      for (const rel of modulesOf(dir)) {
        for (const edge of allImportEdgesOf(rel)) {
          // The server HTML adapter uses the declared stock parser; it is not
          // another DCA role or an unresolved runtime import.
          if (
            extension === "html-content-map" &&
            ["adapter-client", "adapter-publisher"].includes(slice) &&
            edge.target === "parse5"
          )
            continue;
          assert.ok(allowed.has(roleOf(edge.target)), `${rel} reaches forbidden ${edge.target}`);
        }
      }
    }
  });
  test("nested extension role slices obey the base role import rules", () => {
    for (const { slice, dir } of EXTENSION_CORE_SLICES) {
      for (const rel of modulesOf(dir)) {
        for (const edge of allImportEdgesOf(rel)) {
          assertExtensionCoreRoleTarget(rel, slice, edge.target);
        }
      }
    }
  });
});

describe("The reusable boundaries around role core", () => {
  test("adapters and ports point inward, never into demo or another role", () => {
    for (const [role, allowed] of OUTER_ALLOWED) {
      for (const rel of modulesOf(role)) {
        for (const edge of allImportEdgesOf(rel)) {
          const target = roleOf(edge.target);
          assert.ok(
            allowed.has(target),
            `${rel} (${role}) imports ${edge.target}, which is ${target}`,
          );
        }
      }
    }
  });

  test("Page is a delivery value: it imports only shared code and its local wire check", () => {
    // `Page` crosses no actor boundary. Its one local helper is the
    // JSON-only check shared with Network; that helper itself points only at
    // core-shared errors.
    for (const edge of importsOf("demo/support/Page.js")) {
      const allowed =
        roleOf(edge.target) === "core-shared" || edge.target === "demo/support/wireSafe.js";
      assert.ok(
        allowed,
        `demo/support/Page.js imports ${edge.target}, which is ${roleOf(edge.target)}`,
      );
    }
    for (const edge of importsOf("demo/support/wireSafe.js")) {
      assert.equal(
        roleOf(edge.target),
        "core-shared",
        `demo/support/wireSafe.js imports ${edge.target}, which is ${roleOf(edge.target)}`,
      );
    }
  });
});

/**
 * Every directory directly under `experiments/`: one per experiment, plus the
 * underscore directories that belong to no single experiment.
 *
 * @returns {string[]}
 */
function experimentDirectories() {
  return readdirSync(fileURLToPath(new URL("experiments/", V1)), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
}

/**
 * @param {string} directory - relative to `js/`, with a trailing slash
 * @returns {string[]} every `.js` module below it, or nothing when it is absent
 */
function modulesUnder(directory) {
  if (!existsSync(fileURLToPath(new URL(directory, V1)))) return [];
  /** @type {string[]} */
  const files = [];
  /** @param {string} at */
  const visit = (at) => {
    for (const entry of readdirSync(fileURLToPath(new URL(at, V1)), { withFileTypes: true })) {
      const child = `${at}${entry.name}`;
      if (entry.isDirectory()) visit(`${child}/`);
      else if (entry.name.endsWith(".js")) files.push(child);
    }
  };
  visit(directory);
  return files;
}

/**
 * Every alternate implementation module, relative to `js/`. An alternate implementation sits in one of
 * two places: `experiments/_implementation/<name>/` when two or more
 * experiments use it, and `experiments/<experiment>/implementation/` when one
 * experiment owns it. Both are walked here, so a module in either place
 * carries the rule below whether or not anyone thought about it.
 *
 * @returns {string[]}
 */
function variantImplementationModules() {
  /** @type {string[]} */
  const files = [...modulesUnder("experiments/_implementation/")];
  for (const experiment of experimentDirectories()) {
    if (experiment.startsWith("_")) continue;
    files.push(...modulesUnder(`experiments/${experiment}/implementation/`));
  }
  return files;
}

/**
 * Which alternate implementation owns a module, or null when the path is not one at
 * all. Its family name is the named directory under `_implementation/` or
 * the experiment name. Moving shared modules into the underscore directory
 * does not create another family; different names remain separate. A module
 * sitting directly under `_implementation/` has no named directory and
 * answers null, which the rule below refuses.
 *
 * @param {string} rel - path relative to `js/`
 * @returns {string|null}
 */
function lookAlikeOf(rel) {
  const segments = rel.split("/");
  if (segments[0] !== "experiments" || segments.length < 4) return null;
  if (segments[1] === "_implementation") return segments[2];
  if (segments[2] === "implementation") return segments[1];
  return null;
}

describe("The boundary between variants", () => {
  test("implementation family identity survives relocation without merging siblings", () => {
    const local = lookAlikeOf(
      "experiments/resource-group-chains/implementation/group-set-boundary.js",
    );
    const shared = lookAlikeOf("experiments/_implementation/resource-group-chains/construction.js");
    assert.equal(local, "resource-group-chains");
    assert.equal(shared, local);
    assert.notEqual(
      lookAlikeOf("experiments/another-construction/implementation/construction.js"),
      local,
    );
    assert.notEqual(
      lookAlikeOf("experiments/_implementation/another-construction/construction.js"),
      local,
    );
    assert.equal(lookAlikeOf("experiments/_implementation/unowned.js"), null);
    assert.equal(lookAlikeOf("core-client/ContentKeyResolver.js"), null);
  });

  test(
    "an alternate implementation does not import a sibling",
    { skip: !EXPERIMENTS_PRESENT },
    () => {
      for (const rel of variantImplementationModules()) {
        const source = lookAlikeOf(rel);
        assert.ok(
          source !== null && !source.endsWith("/"),
          `${rel} sits at an implementation root; every alternate implementation owns a named directory`,
        );
        for (const edge of importsOf(rel)) {
          const target = lookAlikeOf(edge.target);
          if (target === null) continue;
          assert.equal(
            target,
            source,
            `${rel} imports ${edge.target}; alternate implementations do not compose one another`,
          );
        }
      }
    },
  );
});

describe("The boundary between experiments", () => {
  test(
    "an experiment's tests reach its own files, the underscore directories and the standard tree",
    { skip: !EXPERIMENTS_PRESENT },
    () => {
      for (const experiment of experimentDirectories()) {
        const owned = [
          ...modulesUnder(`experiments/${experiment}/test/`),
          ...modulesUnder(`experiments/${experiment}/test-lib/`),
        ];
        for (const rel of owned) {
          for (const edge of importsOf(rel)) {
            if (!edge.target.startsWith("experiments/")) continue;
            const reached = edge.target.split("/")[1];
            assert.ok(
              reached === experiment || reached.startsWith("_"),
              `${rel} imports ${edge.target}; an experiment reaches its own files, ` +
                "experiments/_implementation/ and experiments/_shared/, never another experiment",
            );
          }
        }
      }
    },
  );
});

describe("The accessGroup showcase boundary", () => {
  test(
    "the comparison entry imports only its variant and shared suite",
    { skip: !EXPERIMENTS_PRESENT },
    () => {
      const rel = "experiments/bind-on-accessGroup/test/comparison.test.js";
      assert.ok(existsSync(fileURLToPath(new URL(rel, V1))), `${rel} exists outside test/`);
      for (const edge of importsOf(rel)) {
        const allowed =
          edge.specifier.startsWith("node:") ||
          edge.target.startsWith("experiments/_implementation/bind-on-accessGroup/") ||
          edge.target === "test-lib/suites/binding-relabel.js";
        assert.ok(
          allowed,
          `${rel} imports ${edge.target}; the comparison reaches only its variant and shared suite`,
        );
      }
    },
  );

  test(
    "target-local characterization imports no shared requirement",
    { skip: !EXPERIMENTS_PRESENT },
    () => {
      const rel = "experiments/bind-on-accessGroup/test/characterization.test.js";
      assert.ok(
        existsSync(fileURLToPath(new URL(rel, V1))),
        `${rel} exists in the experiments lane`,
      );
      for (const edge of importsOf(rel)) {
        const allowed =
          edge.specifier.startsWith("node:") ||
          edge.target.startsWith("experiments/_implementation/bind-on-accessGroup/") ||
          edge.target.startsWith("core-shared/");
        assert.ok(
          allowed,
          `${rel} imports ${edge.target}; characterization reaches only its target and core`,
        );
      }
    },
  );
});

describe("The reference test boundary", () => {
  test("the reference test tree runs without the optional experiments rack", () => {
    const entries = [...jsFilesIn("test"), ...jsFilesIn("test-lib"), ...jsFilesIn("test-profiles")];
    const crossed = [...closureOf(entries, developmentEdgesOf)].filter((rel) =>
      rel.startsWith("experiments/"),
    );
    assert.deepEqual(
      crossed,
      [],
      "reference test or test-lib code reaches the optional experiments rack",
    );
  });
});

describe("What the browser is handed", () => {
  test("the pre-import capability probe reaches only core-shared errors", () => {
    assert.deepEqual(
      [...closureOf(["integration-client/browserCapabilities.js"])].sort(),
      ["core-shared/errors.js", "integration-client/browserCapabilities.js"],
      "a host can probe browser capabilities before the composition imports another module",
    );
  });

  test("nothing the client walk loads reaches a publisher or issuer module", () => {
    // Rule 7, and the assertion that carries the shipped-to-the-browser
    // claim. `demo/browser/` could never be the entry point here: it is the
    // composition root that runs every role in one tab. The two actors below
    // are the client walk that a page loads.
    const closure = closureOf(["demo/actors/Browser.js", "demo/actors/PageLoad.js"]);
    const crossed = [...closure].filter((rel) => PUBLISHER_ISSUER_TIERS.includes(roleOf(rel)));
    assert.deepEqual(crossed, [], "publisher or issuer code reachable from the client walk");

    // The closure, pinned. Without it a walk that resolved nothing would
    // report the same green as a walk that resolved everything. The pin is
    // everything the client walk reaches that carries a role: its own
    // `core-client/` modules and the `core-shared/` ones under them, the two
    // client actors themselves, and the demo-tier modules it loads them
    // through - the base period-key cache, its eviction policy and
    // the markup reader and the issuer-route circuit breaker in
    // `adapter-client/`. The optional client-bound
    // capability is injected, so it is absent from this base walk.
    // `demo/actors/` mixes the
    // client actors with `Publisher` and `IssuerServer`, which the by-tier
    // cross-role check above cannot tell apart from Browser and PageLoad; this
    // pin is what catches one of them appearing in the walk.
    //
    // `PageLoad` builds its resolver, request builder and content opener
    // through `integration-client/composeClient.js`, so that module is in the
    // walk. The other two files of that tier are not: a page that loads
    // `Browser` calls `Browser.load`, while a host copying this source calls
    // `createBrowserClient.js`, which reaches `browserCapabilities.js` and
    // `composeClient.js` from there.
    const reached = [...closure].filter((rel) => ROLE_OF.has(rel)).sort();
    assert.deepEqual(
      reached,
      [
        "adapter-client/IssuerRouteCircuitBreaker.js",
        "adapter-client/MarkupDeliveryReader.js",
        "adapter-client/PeriodKeyCache.js",
        "adapter-client/periodKeyEviction.js",
        "adapter-client/routeAttempts.js",
        "core-client/ContentKeyResolver.js",
        "core-client/ContentRepresentationOpener.js",
        "core-client/DcaData.js",
        "core-client/DcaRequestBuilder.js",
        "core-client/ReaderContext.js",
        "core-client/ResponseAssociation.js",
        "core-client/contentEncodings.js",
        "core-client/contentKeyWrapAttempt.js",
        "core-client/openContent.js",
        "core-client/periodKeyCandidateSource.js",
        "core-client/responseSectionEntries.js",
        "core-shared--client-issuer/DcaRequest.js",
        "core-shared--client-issuer/responseKeys.js",
        "core-shared--client-publisher/contentAad.js",
        "core-shared--client-publisher/contentHandling.js",
        "core-shared/aead.js",
        "core-shared/binaryStrings.js",
        "core-shared/codec.js",
        "core-shared/compactJwt.js",
        "core-shared/cryptoProvider.js",
        "core-shared/errors.js",
        "core-shared/markupPlacement.js",
        "core-shared/names.js",
        "core-shared/periodLabels.js",
        "core-shared/publisherOrigin.js",
        "core-shared/wire.js",
        "demo/actors/Browser.js",
        "demo/actors/PageLoad.js",
        "integration-client/composeClient.js",
      ],
      "the client closure: its core modules, the two client actors, and the demo-tier modules under them",
    );
  });
});

/**
 * Every source file under `js/` that is not itself under the test tree, as
 * paths relative to `js/`. The walk descends every directory except the
 * `test-lib/`, `test/`, `test-vectors/`, each experiment's own `test/` and `test-lib/`,
 * the three named `experiments/_shared/` tiers, `test-reference/` and
 * `test-contract/` and `test-profiles/` trees, which reach fixtures by design, and takes
 * both `.js` and `.mjs` so `reference.mjs` - the public testing surface, which re-exports rather than
 * imports - is walked like any other source file. `node_modules/` is skipped so
 * a tree with dependencies installed still reads only our own sources.
 *
 * @returns {string[]}
 */
function nonTestSources() {
  /** @type {string[]} */
  const out = [];
  /** @param {string} dir - relative to `js/`, with a trailing slash or empty */
  const walk = (dir) => {
    for (const entry of readdirSync(fileURLToPath(new URL(dir, V1)), { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (
          dir === "" &&
          (entry.name === "test-lib" ||
            entry.name === "test" ||
            entry.name === "test-vectors" ||
            entry.name === "test-extensions" ||
            entry.name === "test-profiles" ||
            entry.name === "test-reference" ||
            entry.name === "test-fixtures" ||
            entry.name === "test-contract" ||
            entry.name === "node_modules")
        )
          continue;
        if (
          /^experiments\/[^/]+\/$/.test(dir) &&
          (entry.name === "test" || entry.name === "test-lib")
        )
          continue;
        if (
          dir === "experiments/_shared/" &&
          (entry.name === "harnesses" || entry.name === "suites")
        )
          continue;
        if (dir.startsWith("extensions/") && entry.name === "test") continue;
        walk(`${dir}${entry.name}/`);
      } else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) {
        out.push(`${dir}${entry.name}`);
      }
    }
  };
  walk("");
  return out;
}

/**
 * The edges from non-test source into the test tree that the reference keeps on
 * purpose, each as `${importer} -> ${target}`. `reference.mjs` re-exports the
 * portable issuer seam and the reference `Client` so a consumer drives this
 * implementation through one file. The accessGroup row is an optional
 * test-rack adapter over the shared sealed-section fixture; it has no runtime
 * consumer outside that rack. The fixture generator builds the Sealer factory
 * records from the same setups and known test keys as the bridged Sealer
 * cases. Everything else that reaches a test tree is drift.
 */
const SOURCE_INTO_TEST_ALLOWED = [
  "reference.mjs -> test-contract/issuer-endpoint/support/issuer-endpoint-contract.js",
  "reference.mjs -> test-contract/issuer-endpoint/bindings/reference-issuer-endpoint-binding.js",
  "reference.mjs -> test-lib/harnesses/client.js",
  "experiments/_implementation/bind-on-accessGroup/sealedSection.js -> test-lib/harnesses/sealedSection.js",
  "tools/sealerFactoryRecords.js -> test-reference/support/keys.js",
  "tools/sealerFactoryRecords.js -> test-reference/support/sealerCases.js",
];

/**
 * Whether a path relative to `js/` sits in a test-only tier inside the
 * experiments directory: an experiment's own `test/` or `test-lib/`, or the
 * three named tiers under `experiments/_shared/`, which drop the `test-lib`
 * segment and are named here instead of inferred.
 *
 * @param {string} rel - path relative to `js/`
 * @returns {boolean}
 */
function isExperimentTestTier(rel) {
  const segments = rel.split("/");
  if (segments[0] !== "experiments" || segments.length < 3) return false;
  if (segments[1] === "_shared")
    return segments[2] === "test" || segments[2] === "harnesses" || segments[2] === "suites";
  return segments[2] === "test" || segments[2] === "test-lib";
}

describe("The boundary between source and the test tree", () => {
  test("every static source import and re-export resolves to a path on disk", () => {
    for (const importer of nonTestSources()) {
      for (const target of reexportAwareTargets(importer)) {
        assert.ok(
          existsSync(fileURLToPath(new URL(target, V1))),
          `${importer} -> ${target}: relative source edge target is missing`,
        );
      }
    }
  });

  test("test-only library code has no generic support directory", () => {
    // Test-only reuse is named by responsibility under `test-lib/`; a
    // catch-all `test/support/` would hide whether a module is a fixture,
    // helper, adapter, harness, or behavioral suite.
    assert.equal(
      existsSync(fileURLToPath(new URL("test/support/", V1))),
      false,
      "generic test/support/ must not return; place test-only code under a named test-lib/ category",
    );
  });

  test("no non-test source reaches into a test tree but the deliberate reference edges", () => {
    // The dependency runs one way: tests and fixtures reach into source, and
    // source does not reach back. A demo, adapter, core, port, tool or variant
    // module importing a fixture would drag the test tree into the shipped
    // slice and let a fixture stand in for real code. The public testing
    // surface is the one exception, pinned by exact edge, so a new
    // source->test import goes red and a deliberate edge that
    // disappears stops being allowed rather than lingering as a stale grant.
    /** @type {string[]} */
    const found = [];
    for (const rel of nonTestSources()) {
      for (const target of reexportAwareTargets(rel)) {
        if (
          target === "test-lib" ||
          target.startsWith("test-lib/") ||
          target === "test" ||
          target.startsWith("test/") ||
          target === "test-profiles" ||
          target.startsWith("test-profiles/") ||
          isExperimentTestTier(target) ||
          target === "test-reference" ||
          target.startsWith("test-reference/") ||
          target === "test-fixtures" ||
          target.startsWith("test-fixtures/") ||
          target === "test-contract" ||
          target.startsWith("test-contract/")
        )
          found.push(`${rel} -> ${target}`);
      }
    }

    const allowed = new Set(SOURCE_INTO_TEST_ALLOWED);
    for (const edge of found) {
      assert.ok(allowed.has(edge), `${edge}: non-test source must not import from the test tree`);
    }
    assert.deepEqual(
      [...found].sort(),
      [...SOURCE_INTO_TEST_ALLOWED].sort(),
      "the source->test-tree edges are exactly the deliberate ones the reference keeps",
    );
  });

  test("no production module under core-*, adapter-*, integration-* or ports imports from a testing/ directory", () => {
    // A `testing/` directory holds test-only source, such as the Sealer
    // factory whose setup can fix the clock, the random bytes and the period
    // keys. Production composes its own collaborators. A module inside a
    // `testing/` directory may import its siblings; nothing outside one may.
    const inTesting = (/** @type {string} */ rel) => rel.split("/").includes("testing");
    const production = readdirSync(fileURLToPath(V1), { withFileTypes: true })
      .filter(
        (entry) =>
          entry.isDirectory() &&
          (entry.name.startsWith("core-") ||
            entry.name.startsWith("adapter-") ||
            entry.name.startsWith("integration-") ||
            entry.name === "ports"),
      )
      .flatMap((entry) => jsFilesIn(entry.name))
      .filter((rel) => !inTesting(rel));
    assert.ok(production.includes("core-publisher/Sealer.js"), "the walk reaches the core");
    /** @type {string[]} */
    const found = [];
    for (const rel of production) {
      for (const target of reexportAwareTargets(rel)) {
        if (inTesting(target)) found.push(`${rel} -> ${target}`);
      }
    }
    assert.deepEqual(found, [], "production modules must not import test-only source");
  });
});

/**
 * @returns {string[]} every JavaScript module below `test-contract/`
 */
function contractModules() {
  /** @type {string[]} */
  const files = [];
  /** @param {string} directory */
  const visit = (directory) => {
    for (const entry of readdirSync(fileURLToPath(new URL(directory, V1)), {
      withFileTypes: true,
    })) {
      const child = `${directory}${entry.name}`;
      if (entry.isDirectory()) visit(`${child}/`);
      else if (entry.name.endsWith(".js")) files.push(child);
    }
  };
  visit("test-contract/");
  return files;
}

/**
 * Contract fixtures exercise an endpoint from its public seam. These trees are
 * demo composition, presentation, or reference-test helpers rather than
 * contract dependencies, so none is an approved shared-support exception.
 *
 * @param {string} target
 * @returns {boolean}
 */
function isContractForbiddenTarget(target) {
  return (
    target.startsWith("demo/") ||
    target.startsWith("test-lib/") ||
    target.startsWith("test-reference/")
  );
}

/**
 * The trees a binding selects an implementation from: the issuer core and the
 * public ports beside it. `ports/` is here because the endpoint port carries
 * the reference status table, and a contract that reads that table would agree
 * with the reference by construction instead of holding it to an expectation
 * the contract wrote down.
 *
 * @param {string} target
 * @returns {boolean}
 */
function isContractImplementationTarget(target) {
  return target.startsWith("core-issuer/") || target.startsWith("ports/");
}

/**
 * Contract bindings may adapt a selected implementation, including its issuer
 * core. The portable contract and runner must remain implementation-neutral.
 *
 * @param {string} rel
 * @returns {boolean}
 */
function isContractBinding(rel) {
  return /^test-contract\/[^/]+\/bindings\//.test(rel);
}

/**
 * @param {string} rel
 * @param {{ target: string }[]} edges
 */
function assertContractImportBoundary(rel, edges) {
  for (const edge of edges) {
    assert.equal(
      isContractForbiddenTarget(edge.target),
      false,
      `${rel} imports ${edge.target}; contract tests cannot depend on demo or reference-test support`,
    );
    if (rel.startsWith("test-contract/") && isContractImplementationTarget(edge.target)) {
      assert.ok(
        isContractBinding(rel),
        `${rel} imports ${edge.target}; only a contract binding may select an implementation`,
      );
    }
  }
}

/**
 * @param {string} rel
 * @param {string[]} expressions
 */
function assertKnownContractDynamicImports(rel, expressions) {
  const allowed =
    new Map([
      ["test-contract/run-contract-target.js", ["bindingUrl"]],
      ["test-contract/issuer-endpoint/issuer-endpoint.contract.test.js", ["bindingPath"]],
    ]).get(rel) ?? [];
  assert.deepEqual(
    expressions,
    allowed,
    `${rel}: contract modules may dynamically import only the manifest-selected binding`,
  );
}

describe("The contract-test import boundary", () => {
  test("contract tests do not reach demo composition or flat reference-test support", () => {
    // `test-contract/` may provision its own plain data and use the core or
    // public port a binding selects. It must not reuse demo actors,
    // scenarios, browser/presentation modules, demo support, or the flat
    // `test-lib/` helpers, which would make the supposedly portable
    // contract depend on reference composition.
    // Check the relative-import closure rather than only direct contract
    // edges: an otherwise allowed helper must not conceal a later import
    // of reference composition. `closureOf` deduplicates cycles and does
    // not wander into unrelated roots.
    for (const rel of closureOf(contractModules())) {
      assertContractImportBoundary(rel, importsOf(rel));
      assertKnownContractDynamicImports(rel, dynamicImportExpressionsOf(rel));
    }
  });

  test("the boundary rejects a newly added demo module, portable implementation import, and dynamic reference import", () => {
    assert.throws(
      () =>
        assertContractImportBoundary("test-contract/new-target/support/portable.js", [
          { target: "demo/new-composition.js" },
        ]),
      /contract tests cannot depend on demo/,
    );
    assert.throws(
      () =>
        assertContractImportBoundary("test-contract/new-target/support/portable.js", [
          { target: "core-issuer/IssuerEngine.js" },
        ]),
      /only a contract binding may select an implementation/,
    );
    // The endpoint port owns the reference status table, so a contract
    // module reaching it would source the expectation it is meant to hold.
    assert.throws(
      () =>
        assertContractImportBoundary("test-contract/new-target/support/portable.js", [
          { target: "ports/UnlockEndpoint.js" },
        ]),
      /only a contract binding may select an implementation/,
    );
    assert.doesNotThrow(() =>
      assertContractImportBoundary("test-contract/new-target/bindings/reference.js", [
        { target: "ports/UnlockEndpoint.js" },
      ]),
    );
    assert.throws(
      () =>
        assertContractImportBoundary("test-contract/new-target/support/portable.js", [
          { target: "test-reference/core-shared/codec.test.js" },
        ]),
      /contract tests cannot depend on demo or reference-test support/,
    );
    assert.throws(
      () =>
        assertKnownContractDynamicImports("test-contract/new-target/support/portable.js", [
          "../../demo/new-composition.js",
        ]),
      /may dynamically import only the manifest-selected binding/,
    );
  });

  test("the dynamic-import scanner ignores strings, comments, and regex literals but finds runtime imports", () => {
    const source = [
      "const quoted = \"import('ignored-string') // still a string\";",
      "// import('ignored-line-comment')",
      "/* import('ignored-block-comment') */",
      "const endpoint = 'https://example.test/path//not-a-comment';",
      "/import(forbidden)/;",
      "/import\\(also-forbidden\\)[/]/;",
      "const binding = await import(bindingPath);",
    ].join("\n");
    assert.deepEqual(runtimeDynamicImportExpressions(source), ["bindingPath"]);
  });
});

/**
 * @returns {string[]} every direct test file in the extracted core-shared target
 */
function extractedCoreSharedTests() {
  return jsFilesIn("test-reference/core-shared").filter((rel) => rel.endsWith(".test.js"));
}

/**
 * An extracted core test may use reference support when that support is
 * itself confined to reusable core source. The support directory is deliberately
 * reference-only; it is not a new implementation role.
 *
 * @param {string} rel
 * @param {{ specifier: string, target: string }[]} edges
 */
function assertExtractedCoreSharedTestImports(rel, edges) {
  for (const edge of edges) {
    const isSharedSupport = edge.target.startsWith("test-reference/support/");
    assert.ok(
      edge.specifier.startsWith("node:") ||
        CORE_ROLES.includes(roleOf(edge.target)) ||
        isSharedSupport,
      `${rel} imports ${edge.target}, which is ${roleOf(edge.target)}; extracted core tests and their shared support reach only reusable core source`,
    );
  }
}

/**
 * Follow every relative edge from an extracted test, including shared
 * reference support. Checking only the test's direct imports would let a
 * support helper hide a demo actor behind an otherwise-legal edge.
 *
 * @param {string} rel
 */
function assertExtractedCoreSharedTestClosure(rel) {
  for (const reached of closureOf([rel], allImportEdgesOf)) {
    assertExtractedCoreSharedTestImports(reached, allImportEdgesOf(reached));
  }
}

/**
 * The same closure assertion with an injected graph. It keeps the negative
 * controls deterministic and lets them exercise more than one hop without
 * creating files solely to make a deliberately bad import.
 *
 * @param {string[]} entries
 * @param {Map<string, { specifier: string, target: string }[]>} graph
 */
function assertExtractedCoreSharedTestGraph(entries, graph) {
  const edgesOf = (rel) => graph.get(rel) ?? [];
  for (const reached of closureOf(entries, edgesOf)) {
    assertExtractedCoreSharedTestImports(reached, edgesOf(reached));
  }
}

/** The two native issuer entries selected by the portable core binding. */
const ISSUER_CORE_NATIVE_ENTRIES = [
  "core-issuer/IssuerProcessor.js",
  "core-issuer/IssuerEngine.js",
];

/** The application-side header read selects the per-request registration. */
const ISSUER_CORE_BINDING_IMPORTS = [...ISSUER_CORE_NATIVE_ENTRIES, "core-shared/compactJwt.js"];

/** The directory-rule closure for one extracted issuer role. */
const ISSUER_CORE_NATIVE_SLICE = [
  "core-shared",
  "core-issuer",
  "core-shared--client-issuer",
  "core-shared--publisher-issuer",
];

/** @param {string} target */
function isIssuerCoreNativeSliceTarget(target) {
  return ISSUER_CORE_NATIVE_SLICE.some((directory) => target.startsWith(`${directory}/`));
}

/**
 * Check the source closure the native issuer-core binding must carry. A
 * relative edge is source that extraction must include; a bare or `node:`
 * specifier is not a source path. An unresolved runtime import is neither and
 * therefore fails rather than silently falling out of `closureOf`.
 *
 * @param {string[]} entries
 * @param {(rel: string) => {{ specifier: string, target: string }[]} [edgesOf]
 */
function assertIssuerCoreNativeSliceClosure(entries, edgesOf = allImportEdgesOf) {
  /** @type {Set<string>} */
  const seen = new Set();
  const queue = [...entries];
  while (queue.length > 0) {
    const reached = /** @type {string} */ (queue.shift());
    if (seen.has(reached)) continue;
    seen.add(reached);
    for (const edge of edgesOf(reached)) {
      assert.ok(
        !edge.target.startsWith("<runtime import in "),
        `${reached} has unresolved ${edge.specifier}; an extracted source closure cannot omit a runtime target`,
      );
      if (edge.specifier.startsWith(".")) {
        assert.ok(
          isIssuerCoreNativeSliceTarget(edge.target),
          `${reached} imports ${edge.target}; extracted issuer core reaches only ${ISSUER_CORE_NATIVE_SLICE.join(", ")}`,
        );
        queue.push(edge.target);
      }
    }
  }
}

describe("The extracted core-shared reference-test slice", () => {
  test("every test in its directory and its shared support closure reaches only reusable core source", () => {
    for (const rel of extractedCoreSharedTests()) {
      assertExtractedCoreSharedTestClosure(rel);
    }
  });

  test("the guard rejects a new test that reaches demo composition", () => {
    assert.throws(
      () =>
        assertExtractedCoreSharedTestImports("test-reference/core-shared/new.test.js", [
          { specifier: "../../demo/actors/Browser.js", target: "demo/actors/Browser.js" },
        ]),
      /extracted core tests and their shared support reach only reusable core source/,
    );
  });

  test("the guard rejects shared support that reaches demo composition", () => {
    assert.throws(
      () =>
        assertExtractedCoreSharedTestImports("test-reference/support/new-helper.js", [
          { specifier: "../../demo/actors/Random.js", target: "demo/actors/Random.js" },
        ]),
      /extracted core tests and their shared support reach only reusable core source/,
    );
  });

  test("the closure guard allows test-to-support but rejects support-to-demo or another target", () => {
    const entry = "test-reference/core-shared/new.test.js";
    const support = "test-reference/support/new-helper.js";
    const shared = "core-shared/codec.js";
    const testToSupport = { specifier: "../support/new-helper.js", target: support };
    const supportToShared = { specifier: "../../core-shared/codec.js", target: shared };
    const allowed = new Map([
      [entry, [testToSupport]],
      [support, [supportToShared]],
      [shared, []],
    ]);

    // A direct-only check would stop at the allowed first edge. The actual
    // closure must also inspect the support node's second-hop edge.
    assert.doesNotThrow(() => assertExtractedCoreSharedTestImports(entry, [testToSupport]));
    assert.doesNotThrow(() => assertExtractedCoreSharedTestGraph([entry], allowed));

    for (const target of ["demo/actors/Random.js", "ports/UnlockEndpoint.js"]) {
      const forbidden = new Map(allowed);
      forbidden.set(support, [{ specifier: "../../" + target, target }]);
      assert.throws(
        () => assertExtractedCoreSharedTestGraph([entry], forbidden),
        /extracted core tests and their shared support reach only reusable core source/,
        `support must not conceal a second-hop ${target} edge`,
      );
    }
  });

  test("the all-edge scanner includes export-from and runtime import edges", () => {
    assert.ok(
      allImportEdgesOf("reference.mjs").some((edge) => edge.target === "core-shared/aead.js"),
      "export-from edges are part of a closure",
    );
    const runtimeEdges = allImportEdgesOf(
      "test-contract/issuer-endpoint/issuer-endpoint.contract.test.js",
    );
    assert.ok(
      runtimeEdges.some((edge) => edge.target.startsWith("<runtime import in ")),
      "runtime import() edges are part of a closure even when their target is dynamic",
    );
  });
});

describe("The native issuer-core source slice behind the portable contract", () => {
  test("the selected reference binding imports exactly the checked issuer entries", () => {
    const binding = "test-contract/issuer-core/bindings/reference-issuer-core-binding.js";
    const edges = allImportEdgesOf(binding);
    for (const edge of edges) {
      assert.ok(
        !edge.target.startsWith("<runtime import in "),
        `${binding} has unresolved ${edge.specifier}; binding-to-entry selection cannot omit a runtime target`,
      );
    }
    const selected = edges
      .filter((edge) => edge.specifier.startsWith("."))
      .map((edge) => edge.target)
      .sort();
    assert.deepEqual(
      selected,
      [...ISSUER_CORE_BINDING_IMPORTS].sort(),
      `${binding} selects exactly the issuer entries and shared registration locator whose source closure this test checks`,
    );
  });

  test("all selected binding imports close only over the documented issuer role slice", () => {
    assertIssuerCoreNativeSliceClosure(ISSUER_CORE_BINDING_IMPORTS);
  });

  test("the closure guard rejects a reached shared dependency reaching a port", () => {
    // IssuerEngine reaches codec.js, so this proves the walk enqueues an
    // allowed first hop before it rejects the injected second-hop port edge.
    const injectedEdges = (rel) =>
      rel === "core-shared/codec.js"
        ? [
            ...allImportEdgesOf(rel),
            {
              specifier: "../ports/UnlockEndpoint.js",
              target: "ports/UnlockEndpoint.js",
            },
          ]
        : allImportEdgesOf(rel);
    assert.throws(
      () => assertIssuerCoreNativeSliceClosure(ISSUER_CORE_BINDING_IMPORTS, injectedEdges),
      /extracted issuer core reaches only/,
      "a second-hop port dependency must not be accepted into the issuer source slice",
    );
  });
});

describe("The role map against the tree", () => {
  test("the core-* directories on disk are exactly the roles the rules cover", () => {
    // This test is what makes the directory version as strong as the table it
    // replaced. A module takes its role from the directory holding it, so a
    // module absent from every rule is impossible. A new `core-*` directory the
    // rules never iterate can still slip through; its modules would be examined
    // by nothing. So the set of role dirs is held against disk.
    const coreDirs = readdirSync(fileURLToPath(V1))
      .filter((name) => name.startsWith("core-"))
      .sort();
    assert.deepEqual(
      coreDirs,
      [...CORE_ROLES].sort(),
      "a core-* directory on disk is not covered by the boundary rules (or vice versa)",
    );

    // The map was built by reading those directories, so every mapped module
    // is on disk; pinning it says the read found real files and not stale
    // paths.
    for (const rel of ROLE_OF.keys()) {
      assert.ok(existsSync(fileURLToPath(new URL(rel, V1))), `${rel} is mapped but not on disk`);
    }
  });
});

// The slices a consumer copies, each held against the tree it is copied from
// and against the import rule its entry composes under.
//
// Each `copy-manifest--<role>.json` names the directories a consumer copies and
// takes every `.js` file directly in each. A consumer reads that file at a
// pinned revision, copies those paths, and proves the copy with its own check;
// a path the manifest does not name is public reference source rather than part
// of the copied slice. A subdirectory, such as `core-publisher/testing/`, stays
// out of the copy, so no copied module may import from one.
//
// A manifest and `OUTER_ALLOWED` above state the same thing from two sides:
// what the entry directory may import, and what a consumer has to copy for
// those imports to resolve. Reading the row off that map here is what keeps the
// two from drifting: a directory added to the import rule and forgotten in the
// manifest leaves a consumer with an unresolved import, and one added to the
// manifest alone copies source the entry never reaches. The one exception is
// an adapter directory the host calls beside the entry rather than through it:
// the publisher writes delivery carriers with `adapter-publisher/`. The issuer
// entry now composes its browser adapter directly. A manifest
// names that directory as well, and its imports must resolve in the same copy.
// The publisher and issuer rows are exact: the entry reaches every directory
// its row admits. The client row admits `core-shared--client-publisher/`,
// which the browser entry does not reach today, so its closure is held inside
// the row rather than equal to it.
// These cases live in this file rather than beside the manifests because a
// second test file importing the map would evaluate this one again and run
// every test above twice.
const COPY_SLICES = [
  {
    role: "client",
    manifest: "copy-manifest--client.json",
    entry: "integration-client/createBrowserClient.js",
    beside: [],
    exact: false,
  },
  {
    role: "publisher",
    manifest: "copy-manifest--publisher.json",
    entry: "integration-publisher/createPublisher.js",
    beside: ["adapter-publisher"],
    exact: true,
  },
  {
    role: "issuer",
    manifest: "copy-manifest--issuer.json",
    entry: "integration-issuer/createIssuerCore.js",
    beside: [],
    exact: true,
  },
];

/** @param {string} rel @returns {string} the directory a module sits directly in */
function directoryOf(rel) {
  return rel.slice(0, rel.lastIndexOf("/"));
}

for (const { role, manifest: manifestName, entry, beside, exact } of COPY_SLICES) {
  const manifest = JSON.parse(readFileSync(fileURLToPath(new URL(manifestName, V1)), "utf8"));
  const paths = Object.values(manifest.layers).flatMap((layer) => layer.paths);
  const copiedFiles = copyManifestFiles(manifest, V1);
  const directories = [...new Set(copiedFiles.map(directoryOf))];
  const entryDirectory = directoryOf(entry);

  describe(`The ${role} copy slice`, () => {
    test("the manifest names the tree it is copied from", () => {
      assert.deepEqual(Object.keys(manifest.layers), ["core", "adapters", "integration"]);
      assert.equal(
        Object.hasOwn(manifest, "directories"),
        false,
        "layer membership has one authority",
      );
      assert.equal(
        new Set(directories).size,
        directories.length,
        "directories belong to one layer",
      );
      for (const layer of Object.values(manifest.layers)) {
        assert.deepEqual(Object.keys(layer), ["paths"]);
        assert.ok(Array.isArray(layer.paths) && layer.paths.length > 0);
      }
      assert.equal(manifest.root, "js");
      assert.equal(manifest.role, role);
      assert.equal(Object.hasOwn(manifest, "filePattern"), false);
      assert.equal(new Set(paths).size, paths.length);
    });

    test("every named directory is on disk and holds only .js files at its top level", () => {
      for (const directory of directories) {
        const entries = readdirSync(fileURLToPath(new URL(`${directory}/`, V1)), {
          withFileTypes: true,
        });
        assert.ok(
          entries.some((found) => found.isFile()),
          `${directory}: named by the manifest and empty on disk`,
        );
        for (const found of entries) {
          assert.ok(
            found.isDirectory() || (found.isFile() && found.name.endsWith(".js")),
            `${directory}/${found.name}: the manifest copies the .js files directly in a directory, and this is not one`,
          );
        }
      }
    });

    test("the slice is exactly what the entry may import, plus the adapter the host calls beside it", () => {
      const allowed = OUTER_ALLOWED.get(entryDirectory);
      assert.ok(allowed !== undefined, `the import rule carries a row for ${entryDirectory}`);
      assert.deepEqual(
        [...directories].sort(),
        [...new Set([...allowed, ...beside])].sort(),
        `the copied ${role} slice and the entry's import rule name the same directories`,
      );
    });

    test("the entry's import closure stays inside its import rule", () => {
      const allowed = OUTER_ALLOWED.get(entryDirectory) ?? new Set();
      // Entries may expose companion compositions through re-exports; those
      // modules are runtime dependencies of the copied entry too.
      const reached = [
        ...new Set([...closureOf([entry], allImportEdgesOf)].map(directoryOf)),
      ].sort();
      for (const directory of reached) {
        assert.ok(allowed.has(directory), `${entry} reaches ${directory}, outside its rule`);
      }
      if (exact) {
        assert.deepEqual(
          reached,
          [...allowed].sort(),
          `${entry} reaches every directory its rule admits, so the manifest copies no spare one`,
        );
      }
    });

    test("literal files and direct patterns form a deduplicated union", () => {
      const selected = copyManifestFiles(
        { layers: { core: { paths: [entry, `${entryDirectory}/*.js`] } } },
        V1,
      );
      assert.ok(selected.includes(entry));
      assert.equal(selected.filter((path) => path === entry).length, 1);
      assert.ok(selected.every((path) => directoryOf(path) === entryDirectory));
      assert.throws(
        () => copyManifestFiles({ layers: { core: { paths: ["**/*.js"] } } }, V1),
        /unsupported copy path/,
      );
    });

    test("every copied module imports only copied modules", () => {
      const copied = new Set(copiedFiles);
      for (const rel of copied) {
        for (const edge of allImportEdgesOf(rel)) {
          assert.ok(
            edge.specifier.startsWith("."),
            `${rel} imports ${edge.specifier}, which a copy of the ${role} slice cannot resolve`,
          );
          assert.ok(
            copied.has(edge.target),
            `${rel} imports ${edge.target}, which the ${role} manifest does not copy`,
          );
        }
      }
    });
  });
}
