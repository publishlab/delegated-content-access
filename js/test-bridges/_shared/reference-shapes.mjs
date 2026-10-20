import { readFileSync } from "node:fs";

/** @typedef {import("./reference-shapes-write.mjs").Shape} Shape */
/** @typedef {import("./reference-shapes-write.mjs").ReferenceShapes} ReferenceShapes */
/** @typedef {"record" | "list" | "Uint8Array"} DeclaredType */
/** @typedef {{ at: (string | number)[], type: DeclaredType }} Declaration */
/**
 * Where the test target stated the JS type itself: a list of positions, or
 * `"all"` when every value in the answer carries its own JS type.
 *
 * @typedef {"all" | readonly Declaration[]} Declared
 */

const SHAPES_URL = new URL("./reference-shapes.json", import.meta.url);

/** @type {ReferenceShapes | undefined} */
let loaded;

/** @returns {ReferenceShapes} */
export function loadReferenceShapes() {
  loaded ??= JSON.parse(readFileSync(SHAPES_URL, "utf8"));
  return /** @type {ReferenceShapes} */ (loaded);
}

/**
 * @param {ReferenceShapes} shapes @param {string} sourceModule @param {string} sourceExport
 * @returns {Shape | undefined}
 */
export function returnShape(shapes, sourceModule, sourceExport) {
  const exports = Object.hasOwn(shapes.modules, sourceModule)
    ? shapes.modules[sourceModule]
    : undefined;
  return exports && Object.hasOwn(exports, sourceExport) ? exports[sourceExport] : undefined;
}

/** @param {unknown} value */
function isPlainRecord(value) {
  return (
    value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype
  );
}

/**
 * The bridge value type a driver-side value has.
 *
 * @param {unknown} value
 */
function kindOf(value) {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  if (typeof value === "string") return "string";
  if (value instanceof Uint8Array) return "Uint8Array";
  if (Array.isArray(value)) return "list";
  if (isPlainRecord(value)) return "record";
  return "value";
}

/**
 * The name of a value's type for a diagnostic: its bridge value type, or for
 * any other value its `typeof` or `Date`.
 *
 * @param {unknown} value
 */
function typeName(value) {
  const kind = kindOf(value);
  if (kind !== "value") return kind;
  return value instanceof Date ? "Date" : typeof value;
}

/** @param {Shape} shape @returns {Shape[]} */
function branches(shape) {
  return typeof shape === "object" && "anyOf" in shape ? shape.anyOf : [shape];
}

/** @param {Shape} shape @returns {string} the bridge value type the shape is, or "any" */
function shapeKind(shape) {
  if (typeof shape === "string") return shape;
  if ("list" in shape || "tuple" in shape) return "list";
  if ("record" in shape || "discriminant" in shape) return "record";
  return "union";
}

/** @param {Shape} shape @param {string} kind */
function admits(shape, kind) {
  return branches(shape).some((branch) => {
    const own = shapeKind(branch);
    return own === "any" || own === kind;
  });
}

/** @param {Shape} shape */
function admittedKinds(shape) {
  return [...new Set(branches(shape).map(shapeKind))].sort().join(" or ");
}

/** @param {(string | number)[]} at */
function positionName(at) {
  if (at.length === 0) return "the result";
  return at
    .map((step, index) =>
      typeof step === "number"
        ? `[${step}]`
        : /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(step)
          ? `${index === 0 ? "" : "."}${step}`
          : `[${JSON.stringify(step)}]`,
    )
    .join("");
}

/** @param {(string | number)[]} at */
function positionKey(at) {
  return JSON.stringify(at);
}

/**
 * The value at `at`, or undefined when the path leaves the answer.
 *
 * @param {unknown} value @param {(string | number)[]} at
 */
function valueAt(value, at) {
  let current = value;
  for (const step of at) {
    if (current === null || typeof current !== "object" || !Object.hasOwn(current, step))
      return undefined;
    current = /** @type {Record<string | number, unknown>} */ (current)[step];
  }
  return current;
}

/**
 * Reads a test target's answer by the reference export's return shape. Only
 * a value with exactly one reading changes: an empty list where the type is a
 * record becomes `{}`, a string where it is `Uint8Array` becomes its UTF-8
 * bytes, and `null` where it admits `undefined` but not `null` becomes
 * `undefined`. A value a union admits, and a value that contradicts the type,
 * pass unchanged. A position in `declared` carries the test target's own type:
 * it is never converted, and a type the reference does not admit there is
 * refused.
 *
 * @param {Shape | undefined} shape @param {unknown} value
 * @param {Declared} [declared]
 */
export function convertAnswer(shape, value, declared = []) {
  if (declared === "all") return convert(shape, value, [], "all");
  /** @type {Map<string, DeclaredType>} */
  const declarations = new Map();
  for (const { at, type } of declared) {
    const holds = kindOf(valueAt(value, at));
    if (holds !== type)
      throw new TypeError(
        `bridge response declares ${type} at ${positionName(at)}, where the answer holds ${holds}`,
      );
    declarations.set(positionKey(at), type);
  }
  return convert(shape, value, [], declarations);
}

/**
 * @param {Shape | undefined} shape @param {unknown} value
 * @param {(string | number)[]} at @param {Map<string, DeclaredType> | "all"} declarations
 * @returns {unknown}
 */
function convert(shape, value, at, declarations) {
  if (shape === undefined || shape === "any") return value;
  const declaredType = declarations === "all" ? kindOf(value) : declarations.get(positionKey(at));
  if (declaredType !== undefined && !admits(shape, declaredType))
    throw new TypeError(
      `the test target declares ${declarations === "all" ? typeName(value) : declaredType} at ${positionName(at)}, where the reference type admits ${admittedKinds(shape)}`,
    );
  if (declaredType === undefined) {
    if (Array.isArray(value) && value.length === 0 && !admits(shape, "list"))
      return admits(shape, "record") ? {} : value;
    if (typeof value === "string" && !admits(shape, "string"))
      return admits(shape, "Uint8Array") ? new TextEncoder().encode(value) : value;
    if (value === null && !admits(shape, "null"))
      return admits(shape, "undefined") ? undefined : value;
  }
  if (Array.isArray(value)) {
    const lists = branches(shape).filter((branch) => shapeKind(branch) === "list");
    if (lists.length !== 1) return value;
    const list = /** @type {{ list: Shape } | { tuple: Shape[] }} */ (lists[0]);
    return value.map((entry, index) =>
      convert("tuple" in list ? list.tuple[index] : list.list, entry, [...at, index], declarations),
    );
  }
  if (isPlainRecord(value)) {
    const records = branches(shape).filter((branch) => shapeKind(branch) === "record");
    if (records.length !== 1) return value;
    let record =
      /** @type {{ record: Record<string, Shape>, values?: Shape } | { discriminant: string, cases: Record<string, Shape> }} */ (
        records[0]
      );
    const members = /** @type {Record<string, unknown>} */ (value);
    if ("discriminant" in record) {
      const literal = JSON.stringify(members[record.discriminant]);
      if (literal === undefined || !Object.hasOwn(record.cases, literal)) return value;
      record = /** @type {{ record: Record<string, Shape>, values?: Shape }} */ (
        record.cases[literal]
      );
    }
    const { record: named, values } = record;
    return Object.fromEntries(
      Object.entries(members).map(([name, member]) => [
        name,
        convert(
          Object.hasOwn(named, name) ? named[name] : values,
          member,
          [...at, name],
          declarations,
        ),
      ]),
    );
  }
  return value;
}
