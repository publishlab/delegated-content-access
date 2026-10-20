// @ts-check
// Development-only source graph checks. Parsing uses the package's existing
// pinned ESLint public API; no runtime distribution imports this helper.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Linter } from "eslint";

const V1 = new URL("../", import.meta.url);
const linter = new Linter();
// Repeated closure walks revisit identical text. Cache only extracted records,
// never ASTs or path-only results: rewritten temporary fixtures must be reparsed.
const parsedSources = new Map();

function parseModule(source) {
  if (parsedSources.has(source)) return parsedSources.get(source);
  const declarations = [];
  const dynamic = [];
  const extraction = {
    rules: {
      imports: {
        create(context) {
          const sourceCode = context.sourceCode;
          const reexport = (node) => {
            if (node.source) declarations.push({ kind: "export", specifier: node.source.value });
          };
          return {
            ImportDeclaration(node) {
              declarations.push({
                kind: "import",
                clause: source.slice(node.range[0] + "import".length, node.source.range[0]),
                sideEffect: node.specifiers.length === 0,
                specifier: node.source.value,
              });
            },
            ExportNamedDeclaration: reexport,
            ExportAllDeclaration: reexport,
            ImportExpression(node) {
              const expression = sourceCode.getText(node.source);
              let specifier;
              if (!node.options) {
                if (node.source.type === "Literal" && typeof node.source.value === "string")
                  specifier = node.source.value;
                else if (
                  node.source.type === "TemplateLiteral" &&
                  node.source.expressions.length === 0
                )
                  specifier = node.source.quasis[0].value.cooked;
              }
              dynamic.push({
                expression: node.options
                  ? `${expression}, ${sourceCode.getText(node.options)}`
                  : expression,
                specifier,
              });
            },
          };
        },
      },
    },
  };
  const diagnostics = linter.verify(
    source,
    [
      {
        languageOptions: { ecmaVersion: "latest", sourceType: "module" },
        plugins: { extraction },
        rules: { "extraction/imports": "error" },
      },
    ],
    { allowInlineConfig: false, reportUnusedDisableDirectives: false },
  );
  assert.equal(
    diagnostics.length,
    0,
    `source graph parse failed: ${diagnostics.map((item) => `${item.line}:${item.column} ${item.message}`).join("; ")}`,
  );
  const parsed = { declarations, dynamic };
  parsedSources.set(source, parsed);
  return parsed;
}

function resolvedEdge(rel, specifier, root) {
  const scheme = /^[A-Za-z][A-Za-z0-9+.-]*:/.exec(specifier)?.[0];
  assert.ok(
    !specifier.startsWith("/") && !specifier.startsWith("\\") && (!scheme || scheme === "node:"),
    `${rel}: unsupported absolute path or URL scheme in module specifier ${specifier}`,
  );
  assert.ok(
    !/[?#]/.test(specifier),
    `${rel}: unsupported query or fragment in module specifier ${specifier}`,
  );
  return {
    specifier,
    // Decode file URL pathname identity, so encoded names cannot hide a test
    // or role directory. Queries/fragments are rejected, never silently stripped.
    target: specifier.startsWith(".")
      ? fileURLToPath(new URL(specifier, new URL(rel, root))).slice(fileURLToPath(root).length)
      : specifier,
  };
}

function dynamicEdge(rel, record, root) {
  return typeof record.specifier === "string"
    ? resolvedEdge(rel, record.specifier, root)
    : { specifier: `import(${record.expression})`, target: `<runtime import in ${rel}>` };
}

export function importsOf(rel, root = V1) {
  return parseModule(readFileSync(new URL(rel, root), "utf8"))
    .declarations.filter((record) => record.kind === "import")
    .map((record) => {
      assert.ok(!record.sideEffect, `${rel}: unsupported side-effect runtime import declaration`);
      return { clause: record.clause, ...resolvedEdge(rel, record.specifier, root) };
    });
}

export function reexportAwareTargets(rel, root = V1) {
  return parseModule(readFileSync(new URL(rel, root), "utf8"))
    .declarations.filter(({ specifier }) => specifier.startsWith("."))
    .map(({ specifier }) => resolvedEdge(rel, specifier, root).target);
}

export function runtimeDynamicImportExpressions(source) {
  return parseModule(source).dynamic.map(({ expression }) => expression);
}

export function dynamicImportExpressionsOf(rel, root = V1) {
  return runtimeDynamicImportExpressions(readFileSync(new URL(rel, root), "utf8"));
}

export function runtimeImportEdge(rel, expression, root = V1) {
  const parsed = parseModule(`import(${expression});`).dynamic;
  assert.equal(parsed.length, 1, "unsupported nested dynamic-import expression");
  return dynamicEdge(rel, parsed[0], root);
}

export function allImportEdgesOf(rel, root = V1) {
  const parsed = parseModule(readFileSync(new URL(rel, root), "utf8"));
  // Preserve the runtime declaration restriction while collecting real AST edges.
  const imports = importsOf(rel, root);
  const reexports = parsed.declarations
    .filter((record) => record.kind === "export")
    .map(({ specifier }) => resolvedEdge(rel, specifier, root));
  return [
    ...imports,
    ...reexports,
    ...parsed.dynamic.map((record) => dynamicEdge(rel, record, root)),
  ];
}

export function developmentImportEdgesOf(
  rel,
  root = V1,
  mapSpecifier = (_rel, specifier) => specifier,
) {
  const parsed = parseModule(readFileSync(new URL(rel, root), "utf8"));
  return [
    ...parsed.declarations.map(({ specifier }) =>
      resolvedEdge(rel, mapSpecifier(rel, specifier), root),
    ),
    ...parsed.dynamic.map((record) =>
      dynamicEdge(
        rel,
        typeof record.specifier === "string"
          ? { ...record, specifier: mapSpecifier(rel, record.specifier) }
          : record,
        root,
      ),
    ),
  ];
}

export function sideEffectImportSpecifiers(source) {
  return parseModule(source)
    .declarations.filter((record) => record.kind === "import" && record.sideEffect)
    .map(({ specifier }) => specifier);
}

export function closureOf(entries, edgesOf = allImportEdgesOf) {
  const seen = new Set();
  const queue = [...entries];
  while (queue.length) {
    const rel = queue.shift();
    if (seen.has(rel)) continue;
    seen.add(rel);
    for (const edge of edgesOf(rel)) {
      if (edge.specifier.startsWith(".")) queue.push(edge.target);
    }
  }
  return seen;
}

export function assertNoExecutableTestReentry(entry, edgesOf = developmentImportEdgesOf) {
  const seen = new Set();
  const queue = [entry];
  while (queue.length) {
    const rel = queue.shift();
    if (seen.has(rel)) continue;
    seen.add(rel);
    for (const edge of edgesOf(rel)) {
      assert.ok(
        !edge.target.endsWith(".test.js"),
        `${entry}: ${rel} imports executable test ${edge.target}; extract its fixture instead`,
      );
      if (edge.specifier.startsWith(".")) queue.push(edge.target);
    }
  }
}

/** Explicit development locations; every other extension module is runtime. */
export function isDevelopmentModule(rel) {
  const parts = rel.split("/");
  if (parts[0] === "extensions") {
    return parts
      .slice(2, -1)
      .some((part) =>
        ["test", "test-lib", "test-support", "testing", "bench-scenarios", "tools"].includes(part),
      );
  }
  return (
    /^(?:test[^/]*|tools|bench-scenarios|experiments|evidence-[^/]+)\//.test(rel) ||
    parts.slice(0, -1).includes("testing")
  );
}

export function extensionOf(rel) {
  return /^extensions\/([^/]+)\//.exec(rel)?.[1] ?? null;
}

/** Walk every runtime root, including modules not reachable from public entries. */
export function assertRuntimeClosure(entries, edgesOf = allImportEdgesOf) {
  for (const rel of closureOf(entries, edgesOf)) {
    assert.ok(!isDevelopmentModule(rel), `${rel}: runtime closure reaches development code`);
    for (const edge of edgesOf(rel)) {
      assert.ok(
        !edge.target.startsWith("<runtime import in "),
        `${rel}: unresolved runtime import`,
      );
      if (edge.specifier.startsWith(".")) {
        assert.ok(
          !isDevelopmentModule(edge.target),
          `${rel} -> ${edge.target}: runtime reaches development code`,
        );
      }
    }
  }
}

/** Aggregate actual runtime import edges by extension; development is excluded. */
export function extensionDependencyGraph(modules, edgesOf = allImportEdgesOf) {
  const graph = new Map();
  for (const rel of modules.filter((file) => !isDevelopmentModule(file))) {
    const owner = extensionOf(rel);
    if (owner === null) continue;
    if (!graph.has(owner)) graph.set(owner, new Set());
    for (const reached of closureOf([rel], edgesOf)) {
      const dependency = extensionOf(reached);
      if (dependency !== null && dependency !== owner) graph.get(owner).add(dependency);
    }
  }
  return graph;
}

export function assertAcyclic(graph) {
  const complete = new Set();
  const active = [];
  const visit = (name) => {
    assert.ok(
      !active.includes(name),
      `extension dependency cycle: ${[...active, name].join(" -> ")}`,
    );
    if (complete.has(name)) return;
    active.push(name);
    for (const dependency of graph.get(name) ?? []) visit(dependency);
    active.pop();
    complete.add(name);
  };
  for (const name of graph.keys()) visit(name);
}

export function requiredExtensions(name, graph) {
  const required = new Set();
  const visit = (next) => {
    if (required.has(next)) return;
    required.add(next);
    for (const dependency of graph.get(next) ?? []) visit(dependency);
  };
  visit(name);
  return required;
}
