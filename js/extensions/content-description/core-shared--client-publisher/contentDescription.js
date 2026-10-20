// @ts-check
import { isUnicodeScalarString } from "../../../core-shared/names.js";

/** @typedef {{version: '1', schema?: string, description?: string}} ContentDescription */
/** @typedef {{state: 'absent'|'available'|'unsupported'|'invalid', description: ContentDescription|null}} DescriptionAdmission */
/** @typedef {{maxDescriptionCodePoints?: number, maxSchemaCodePoints?: number, maxSerializedBytes?: number, maxNodes?: number, maxDepth?: number}} DescriptionOptions */
/** @type {Readonly<Required<DescriptionOptions>>} */
export const DEFAULT_DESCRIPTION_LIMITS = Object.freeze({
  maxDescriptionCodePoints: 4096,
  maxSchemaCodePoints: 2048,
  maxSerializedBytes: 32768,
  maxNodes: 128,
  maxDepth: 8,
});

/** @param {DescriptionOptions} options @returns {Required<DescriptionOptions>} */
function limitsFor(options) {
  const limits = { ...DEFAULT_DESCRIPTION_LIMITS };
  for (const rawKey of Object.keys(options)) {
    const key = /** @type {keyof DescriptionOptions} */ (rawKey);
    const value = options[key];
    if (
      !Object.hasOwn(limits, key) ||
      typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      value <= 0
    )
      throw new TypeError("Description limits must be known positive safe integers");
    limits[key] = value;
  }
  return limits;
}
/** @param {unknown} value @returns {value is Record<string, any>} */
export function isDescriptionRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Measure a JSON-compatible native envelope before copying. Accessors, cycles,
// non-JSON values, excessive traversal and malformed scalar strings are refused.
/** @param {unknown} value @param {Required<DescriptionOptions>} limits @returns {boolean} */
function boundedEnvelope(value, limits) {
  let nodes = 0;
  let bytes = 0;
  const ancestors = new Set();
  /** @param {string} text @returns {boolean} */
  function string(text) {
    bytes += 2;
    for (const char of text) {
      const point = char.codePointAt(0);
      if (point === undefined) return false;
      if (point >= 0xd800 && point <= 0xdfff) return false;
      bytes +=
        point < 32
          ? ["\b", "\t", "\n", "\f", "\r"].includes(char)
            ? 2
            : 6
          : char === '"' || char === "\\"
            ? 2
            : point < 128
              ? 1
              : point < 2048
                ? 2
                : point < 65536
                  ? 3
                  : 4;
      if (bytes > limits.maxSerializedBytes) return false;
    }
    return bytes <= limits.maxSerializedBytes;
  }
  /** @param {any} node @param {number} depth @returns {boolean} */
  function visit(node, depth) {
    if (++nodes > limits.maxNodes || depth > limits.maxDepth) return false;
    if (typeof node === "string") return string(node);
    if (
      node === null ||
      typeof node === "boolean" ||
      (typeof node === "number" && Number.isFinite(node))
    ) {
      bytes += JSON.stringify(node).length;
    } else if (typeof node === "object") {
      if (ancestors.has(node)) return false;
      if (
        !Array.isArray(node) &&
        Object.getPrototypeOf(node) !== Object.prototype &&
        Object.getPrototypeOf(node) !== null
      )
        return false;
      const keys = Object.keys(node);
      if (
        Object.getOwnPropertySymbols(node).length ||
        Object.getOwnPropertyNames(node).length !== keys.length + (Array.isArray(node) ? 1 : 0)
      )
        return false;
      ancestors.add(node);
      bytes += 2;
      let count = 0;
      for (const key of keys) {
        if (++count > limits.maxNodes) return false;
        if (count > 1) bytes++;
        if (!Array.isArray(node)) {
          if (!string(key)) return false;
          bytes++;
        }
        const field = Object.getOwnPropertyDescriptor(node, key);
        if (!field || !Object.hasOwn(field, "value") || !visit(field.value, depth + 1))
          return false;
      }
      if (Array.isArray(node) && count !== node.length) return false;
      ancestors.delete(node);
    } else return false;
    return bytes <= limits.maxSerializedBytes;
  }
  return visit(value, 1);
}

/** Admit only the selected item's optional public metadata. No content validation.
 * @param {Record<string, any>} item @param {DescriptionOptions} [options]
 * @returns {DescriptionAdmission}
 */
export function admitContentDescription(item, options = {}) {
  const limits = limitsFor(options);
  if (!isDescriptionRecord(item)) throw new TypeError("Expected an item record");
  if (!Object.hasOwn(item, "contentDescription")) return { state: "absent", description: null };
  const field = Object.getOwnPropertyDescriptor(item, "contentDescription");
  const value = field && Object.hasOwn(field, "value") ? field.value : null;
  const invalid = /** @type {DescriptionAdmission} */ ({ state: "invalid", description: null });
  if (
    !isDescriptionRecord(value) ||
    !boundedEnvelope(value, limits) ||
    !Object.hasOwn(value, "version") ||
    typeof value.version !== "string"
  )
    return invalid;
  if (value.version !== "1") return { state: "unsupported", description: null };
  if (Object.keys(value).some((key) => !["version", "schema", "description"].includes(key)))
    return invalid;
  const schema = Object.hasOwn(value, "schema");
  const description = Object.hasOwn(value, "description");
  if (!schema && !description) return invalid;
  if (
    schema &&
    (!isUnicodeScalarString(value.schema) ||
      !value.schema.length ||
      [...value.schema].length > limits.maxSchemaCodePoints)
  )
    return invalid;
  if (
    description &&
    (!isUnicodeScalarString(value.description) ||
      !value.description.length ||
      [...value.description].length > limits.maxDescriptionCodePoints)
  )
    return invalid;
  /** @type {ContentDescription} */
  const admitted = { version: "1" };
  if (schema) admitted.schema = value.schema;
  if (description) admitted.description = value.description;
  return { state: "available", description: admitted };
}
