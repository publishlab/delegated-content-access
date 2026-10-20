// Writes reference-shapes.json: for each function export of each reference
// implementation module, the parts of its JSDoc return type the driver needs
// to read a test target's answer. Run from js/:
//
//   node test-bridges/_shared/reference-shapes-write.mjs
//
// The TypeScript checker reads the types; nothing here matches text. The
// shapes self-test fails when the committed file differs from what this
// writes. The Shape typedef below is the file's grammar; reference-shapes.mjs
// reads answers by it.

import { writeFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import * as prettier from "prettier";
import {
  API,
  ElementFlags,
  ObjectFlags,
  SignatureKind,
  SymbolFlags,
  TypeFlags,
} from "typescript/unstable/sync";
import { SyntaxKind } from "typescript/unstable/ast";

import { isDriverOwnedModule, isSafeModulePath } from "./routing.mjs";

/**
 * The part of a reference export's JSDoc return type the driver needs to read
 * a test target's answer, as `reference-shapes.json` records it:
 *
 * - `"string"`, `"Uint8Array"`, `"null"`, `"undefined"`: that value;
 * - `"value"`: any other definite type, such as a number, boolean or instant;
 * - `"any"`: the type leaves the value open;
 * - `{ list: Shape }` and `{ tuple: Shape[] }`: a list;
 * - `{ record: { name: Shape }, values?: Shape }`: a record; a member left out
 *   is open, and `values` is the shape of a member the record does not name;
 * - `{ discriminant: name, cases: { literal: record } }`: a union of records
 *   told apart by the member `name`, keyed by its value in JSON;
 * - `{ anyOf: Shape[] }`: a union.
 *
 * @typedef {"string" | "Uint8Array" | "null" | "undefined" | "value" | "any" | "never"
 *   | { list: Shape } | { tuple: Shape[] }
 *   | { record: Record<string, Shape>, values?: Shape }
 *   | { discriminant: string, cases: Record<string, Shape> }
 *   | { anyOf: Shape[] }} Shape
 */

/** @typedef {{ version: 1, modules: Record<string, Record<string, Shape>> }} ReferenceShapes */
/** @typedef {import("typescript/unstable/sync").Type} Type */
/** @typedef {import("typescript/unstable/sync").Checker} Checker */
/** @typedef {import("typescript/unstable/sync").Project} Project */
/** @typedef {import("typescript/unstable/sync").Symbol} TypeSymbol */

export const SHAPES_FILE = fileURLToPath(new URL("./reference-shapes.json", import.meta.url));
const REFERENCE_CONFIG = fileURLToPath(new URL("../../jsconfig.json", import.meta.url));

/**
 * Admits every value. An export or record member with this shape is left out
 * of the file; a list element, tuple entry or index signature writes it.
 */
const ANY = "any";
/** Admits no value; dropped from a union. */
const NEVER = "never";

/**
 * Reads the shapes of every implementation module in the program `config`
 * names. The config is read as is, with one change: `strictNullChecks`, so
 * the checker keeps `null` and `undefined` apart as the JSDoc writes them.
 *
 * @param {string} [config] a tsconfig or jsconfig; defaults to js/jsconfig.json
 * @returns {ReferenceShapes}
 */
export function referenceShapes(config = REFERENCE_CONFIG) {
  const root = dirname(resolve(config));
  // A config beside the real one, so `extends` and `include` resolve as they
  // do for it. It exists only in the checker's view of the file system.
  const derived = join(root, `.reference-shapes.${basename(config)}`);
  const text = JSON.stringify({
    extends: `./${basename(config)}`,
    compilerOptions: { strictNullChecks: true },
  });
  const api = new API({
    cwd: root,
    fs: {
      readFile: (file) => (file === derived ? text : undefined),
      fileExists: (file) => (file === derived ? true : undefined),
    },
  });
  try {
    const project = api.updateSnapshot({ openProjects: [derived] }).getProject(derived);
    if (!project) throw new Error(`the TypeScript checker did not load ${config}`);
    /** @type {Record<string, Record<string, Shape>>} */
    const modules = {};
    const files = project.program
      .getSourceFileNames()
      .map((file) => [relative(root, file).split("\\").join("/"), file])
      .filter(
        ([path]) =>
          isSafeModulePath(path) && !isDriverOwnedModule(path) && !path.startsWith("experiments/"),
      )
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
    for (const [path, file] of files) {
      const exports = moduleShapes(project, file);
      if (Object.keys(exports).length) modules[path] = exports;
    }
    return { version: 1, modules };
  } finally {
    api.close();
  }
}

/**
 * @param {Project} project @param {string} file
 * @returns {Record<string, Shape>}
 */
function moduleShapes(project, file) {
  const checker = project.checker;
  const source = project.program.getSourceFile(file);
  const moduleSymbol = source && checker.getSymbolAtLocation(source);
  if (!moduleSymbol) return {};
  /** @type {Record<string, Shape>} */
  const shapes = {};
  const exports = [...checker.getExportsOfModule(moduleSymbol)].sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
  );
  for (const exported of exports) {
    const symbol =
      exported.flags & SymbolFlags.Alias ? checker.getAliasedSymbol(exported) : exported;
    if (!(symbol.flags & (SymbolFlags.Function | SymbolFlags.Variable))) continue;
    if (symbol.flags & SymbolFlags.Class) continue;
    const type = checker.getTypeOfSymbol(symbol);
    if (!type) continue;
    const signatures = checker.getSignaturesOfType(type, SignatureKind.Call);
    if (signatures.length !== 1) continue;
    const [signature] = signatures;
    if (!declaresReturn(project, symbol, signature)) continue;
    const returned = checker.getReturnTypeOfSignature(signature);
    if (!returned) continue;
    const shape = reduce(checker, returned, new Set());
    if (shape !== ANY && shape !== NEVER && shape !== "value") shapes[exported.name] = shape;
  }
  return shapes;
}

const TYPE_NODES = new Set([
  SyntaxKind.FunctionType,
  SyntaxKind.JSDocSignature,
  SyntaxKind.CallSignature,
  SyntaxKind.MethodSignature,
]);

/**
 * Whether the JSDoc states the return type: a `@returns` or `@type` tag, or a
 * signature that itself comes from a type annotation. An inferred return
 * type stays unmarked.
 *
 * @param {Project} project @param {TypeSymbol} symbol
 * @param {import("typescript/unstable/sync").Signature} signature
 */
function declaresReturn(project, symbol, signature) {
  if (
    project.checker
      .getJsDocTagsOfSymbol(symbol)
      .some((tag) => tag.name === "returns" || tag.name === "return" || tag.name === "type")
  )
    return true;
  const declaration = /** @type {any} */ (signature.declaration?.resolve(project));
  if (!declaration) return false;
  if (TYPE_NODES.has(declaration.kind)) return true;
  return (declaration.jsDoc ?? []).some((/** @type {any} */ doc) =>
    (doc.tags ?? []).some(
      (/** @type {any} */ tag) =>
        tag.kind === SyntaxKind.JSDocReturnTag || tag.kind === SyntaxKind.JSDocTypeTag,
    ),
  );
}

/** @param {Shape} shape */
function key(shape) {
  return JSON.stringify(shape);
}

/**
 * @param {Checker} checker @param {Type} type @param {Set<number>} stack
 *   the object types being reduced, so a recursive type ends as unmarked
 * @returns {Shape}
 */
function reduce(checker, type, stack) {
  const flags = type.flags;
  if (flags & TypeFlags.AnyOrUnknown) return ANY;
  if (flags & TypeFlags.Never) return NEVER;
  // A type parameter, such as a generic that returns its input, and the
  // types computed from one say nothing the driver could rely on.
  if (flags & (TypeFlags.Instantiable & ~TypeFlags.InstantiablePrimitive)) return ANY;
  if (flags & TypeFlags.Null) return "null";
  if (flags & (TypeFlags.Undefined | TypeFlags.Void)) return "undefined";
  if (flags & TypeFlags.StringLike) return "string";
  if (
    flags &
    (TypeFlags.NumberLike |
      TypeFlags.BooleanLike |
      TypeFlags.BigIntLike |
      TypeFlags.ESSymbolLike |
      TypeFlags.EnumLike)
  )
    return "value";
  if (type.isUnionType()) return union(checker, type.getTypes() ?? [], stack);
  if (type.isIntersectionType()) return intersection(checker, type, stack);
  if (!(flags & TypeFlags.Object)) return ANY;
  if (stack.has(type.id)) return ANY;
  stack.add(type.id);
  try {
    return object(checker, type, stack);
  } finally {
    stack.delete(type.id);
  }
}

/**
 * @param {Checker} checker @param {readonly Type[]} types @param {Set<number>} stack
 * @returns {Shape}
 */
function union(checker, types, stack) {
  /** @type {Map<string, Shape>} */
  const members = new Map();
  for (const member of types) {
    const shape = reduce(checker, member, stack);
    if (shape === ANY) return ANY;
    if (shape !== NEVER) members.set(key(shape), shape);
  }
  const records = [...members.values()].filter(
    (shape) => typeof shape === "object" && "record" in shape,
  );
  const discriminated = records.length > 1 ? discriminate(checker, types, stack) : undefined;
  if (discriminated) {
    for (const record of records) members.delete(key(record));
    members.set(key(discriminated), discriminated);
  }
  if (members.size === 0) return NEVER;
  if (members.size === 1) return [...members.values()][0];
  return {
    anyOf: [...members.keys()].sort().map((name) => /** @type {Shape} */ (members.get(name))),
  };
}

/**
 * The record members of a union keyed by a member every one of them has as
 * a distinct string, number or boolean literal, such as `kind`. The first
 * such member name in sorted order wins.
 *
 * @param {Checker} checker @param {readonly Type[]} types @param {Set<number>} stack
 * @returns {Shape | undefined}
 */
function discriminate(checker, types, stack) {
  // Boolean literals arrive as separate members; so do record members.
  const records = types.filter((member) => {
    const shape = reduce(checker, member, stack);
    return typeof shape === "object" && "record" in shape;
  });
  /** @type {Map<string, Map<Type, string>>} */
  const candidates = new Map();
  for (const record of records) {
    for (const property of checker.getPropertiesOfType(record)) {
      if (property.flags & SymbolFlags.Optional) continue;
      const propertyType = checker.getTypeOfSymbol(property);
      if (!propertyType || !(propertyType.flags & TypeFlags.Unit)) continue;
      if (propertyType.flags & TypeFlags.Nullable) continue;
      const value = /** @type {import("typescript/unstable/sync").LiteralType} */ (propertyType)
        .value;
      if (!["string", "number", "boolean"].includes(typeof value)) continue;
      const seen = candidates.get(property.name) ?? new Map();
      seen.set(record, JSON.stringify(value));
      candidates.set(property.name, seen);
    }
  }
  const names = [...candidates.keys()].sort();
  for (const name of names) {
    const seen = /** @type {Map<Type, string>} */ (candidates.get(name));
    const literals = new Set(seen.values());
    if (seen.size !== records.length || literals.size !== records.length) continue;
    /** @type {Record<string, Shape>} */
    const cases = {};
    for (const [record, literal] of [...seen].sort(([, left], [, right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    )) {
      const shape = /** @type {{ record: Record<string, Shape>, values?: Shape }} */ (
        reduce(checker, record, stack)
      );
      const members = Object.fromEntries(
        Object.entries(shape.record).filter(([member]) => member !== name),
      );
      cases[literal] = { ...shape, record: members };
    }
    return { discriminant: name, cases };
  }
  return undefined;
}

/**
 * An intersection of records is one record. An intersection that brands a
 * string or bytes, such as `string & { brand: "name" }`, is that string or
 * those bytes. Anything else stays unmarked.
 *
 * @param {Checker} checker @param {import("typescript/unstable/sync").IntersectionType} type
 * @param {Set<number>} stack
 * @returns {Shape}
 */
function intersection(checker, type, stack) {
  const shapes = (type.getTypes() ?? []).map((member) => reduce(checker, member, stack));
  if (shapes.some((shape) => shape === NEVER)) return NEVER;
  const leaves = shapes.filter((shape) => typeof shape === "string" && shape !== ANY);
  if (leaves.length === 1) return leaves[0];
  if (leaves.length > 1) return ANY;
  if (shapes.every((shape) => typeof shape === "object" && "record" in shape))
    return record(checker, type, stack);
  return ANY;
}

/**
 * @param {Checker} checker @param {Type} type @param {Set<number>} stack
 * @returns {Shape}
 */
function object(checker, type, stack) {
  const symbol = type.getSymbol();
  const name = symbol?.name;
  if (name === "Promise" && type.isTypeReference()) {
    const [settled] = checker.getTypeArguments(type);
    return settled ? reduce(checker, settled, stack) : ANY;
  }
  if (name === "Uint8Array" || name === "Buffer") return "Uint8Array";
  if (checker.isTupleType(type) && type.isTypeReference()) {
    const elements = checker.getTypeArguments(type);
    const flags =
      /** @type {import("typescript/unstable/sync").TupleType} */ (type.getTarget()).elementFlags ??
      [];
    if (flags.some((flag) => flag & ElementFlags.Variable))
      return { list: union(checker, elements, stack) };
    return { tuple: elements.map((element) => admitAny(reduce(checker, element, stack))) };
  }
  if (checker.isArrayType(type) && type.isTypeReference()) {
    const [element] = checker.getTypeArguments(type);
    return { list: element ? admitAny(reduce(checker, element, stack)) : ANY };
  }
  if (
    checker.getSignaturesOfType(type, SignatureKind.Call).length ||
    checker.getSignaturesOfType(type, SignatureKind.Construct).length
  )
    return "value";
  // A class instance or a library interface, such as Date, Map or CryptoKey,
  // is not a record. JSDoc declares records as type literals.
  if (symbol && symbol.flags & (SymbolFlags.Class | SymbolFlags.Interface)) return "value";
  if (
    /** @type {import("typescript/unstable/sync").ObjectType} */ (type).objectFlags &
    ObjectFlags.ClassOrInterface
  )
    return "value";
  return record(checker, type, stack);
}

/**
 * A record lists the members whose shape can matter: a member that is only a
 * number, a boolean, an instant or unmarked is left out. `values` is the
 * shape of every other member, from a string index signature.
 *
 * @param {Checker} checker @param {Type} type @param {Set<number>} stack
 * @returns {Shape}
 */
function record(checker, type, stack) {
  /** @type {Record<string, Shape>} */
  const members = {};
  const properties = [...checker.getPropertiesOfType(type)].sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
  );
  for (const property of properties) {
    const propertyType = checker.getTypeOfSymbol(property);
    if (!propertyType) continue;
    let shape = reduce(checker, propertyType, stack);
    if (property.flags & SymbolFlags.Optional && shape !== ANY) shape = withUndefined(shape);
    if (shape !== ANY && shape !== NEVER && shape !== "value") members[property.name] = shape;
  }
  const index = checker
    .getIndexInfosOfType(type)
    .find((info) => info.keyType.flags & TypeFlags.String);
  if (!index) return { record: members };
  return { record: members, values: admitAny(reduce(checker, index.valueType, stack)) };
}

/** @param {Shape} shape @returns {Shape} */
function withUndefined(shape) {
  if (shape === "undefined") return shape;
  /** @type {Shape[]} */
  const members = typeof shape === "object" && "anyOf" in shape ? [...shape.anyOf] : [shape];
  if (!members.includes("undefined")) members.push("undefined");
  return { anyOf: members.sort((left, right) => (key(left) < key(right) ? -1 : 1)) };
}

/** @param {Shape} shape @returns {Shape} */
function admitAny(shape) {
  return shape === NEVER ? ANY : shape;
}

/** @param {ReferenceShapes} shapes */
export async function formatShapes(shapes) {
  const options = (await prettier.resolveConfig(SHAPES_FILE)) ?? {};
  return prettier.format(JSON.stringify(shapes), { ...options, filepath: SHAPES_FILE });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  writeFileSync(SHAPES_FILE, await formatShapes(referenceShapes()));
  process.stdout.write(`wrote ${relative(process.cwd(), SHAPES_FILE)}\n`);
}
