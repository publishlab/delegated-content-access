import { decodeCryptoKey, encodeCryptoKey, isRuntimeCryptoKey } from "./serializer-crypto-key.mjs";

const text = new TextEncoder();
const decoder = new TextDecoder();

export const runtimeValueTypes = Object.freeze([
  "null",
  "boolean",
  "string",
  "number",
  "record",
  "list",
  "undefined",
  "Uint8Array",
  "Date",
  "CryptoKey",
]);

/** @param {BridgeValue} value @param {Set<string>} [types] */
export function bridgeValueTypes(value, types = new Set()) {
  if (value === null) types.add("null");
  else if (Array.isArray(value)) {
    types.add("list");
    value.forEach((entry) => bridgeValueTypes(entry, types));
  } else if (typeof value === "object") {
    const type = value.$type;
    // A handle names an object the adapter issued in this session. It is not
    // a value type, so it needs no `valueTypes` entry.
    if (type === "Handle") return types;
    if (typeof type === "string") {
      types.add(type === "Record" ? "record" : type);
      if (type === "Record" && value.value && typeof value.value === "object")
        Object.values(value.value).forEach((entry) => bridgeValueTypes(entry, types));
    } else {
      types.add("record");
      Object.values(value).forEach((entry) => bridgeValueTypes(entry, types));
    }
  } else types.add(typeof value);
  return types;
}

/** @typedef {null | boolean | string | number | BridgeValue[] | { [key: string]: BridgeValue }} BridgeValue */
/** @typedef {{ $type: "Handle", class: string, handle: string }} HandleTag */
/**
 * A session's handle table, which the codec asks about objects it cannot
 * otherwise encode and about every handle it decodes. `encode` returns the
 * tag of an object the session carries by handle, or undefined for any other
 * value, and throws for a handle it refuses. `decode` returns the object a tag
 * names, or throws.
 *
 * @typedef {{ encode: (value: object) => HandleTag | undefined, decode: (tag: HandleTag) => unknown }} HandleCodec
 */

/**
 * Whether `value` has the exact handle layout. An ordinary record with the
 * same members arrives escaped as a `Record`, so it never matches.
 *
 * @param {Record<string, unknown>} value @returns {boolean}
 */
function isHandleLayout(value) {
  return (
    hasExactKeys(value, ["$type", "class", "handle"]) &&
    typeof value.class === "string" &&
    value.class.length > 0 &&
    typeof value.handle === "string" &&
    value.handle.length > 0
  );
}

/**
 * The object a handle names in `handles`' session.
 *
 * @param {Record<string, unknown>} value @param {HandleCodec | undefined} handles
 */
function decodeHandle(value, handles) {
  if (!isHandleLayout(value)) throw new TypeError("bridge tagged value has an exact known shape");
  if (handles === undefined) throw new TypeError("bridge handle needs its session");
  return handles.decode(/** @type {HandleTag} */ (/** @type {unknown} */ (value)));
}

/**
 * The tag `handles` gives `value`, or undefined when `value` is no object the
 * session carries by handle.
 *
 * @param {unknown} value @param {HandleCodec | undefined} handles
 */
function handleTag(value, handles) {
  if (handles === undefined) return undefined;
  if (value === null || typeof value !== "object") return undefined;
  return handles.encode(value);
}

/** @param {Uint8Array} bytes */
function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

/** @param {unknown} value @returns {value is Record<string, any>} */
function isPlainRecord(value) {
  return (
    value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype
  );
}

/**
 * A bridge list is a plain array. An Array subclass is a runtime object whose
 * class the receiver would lose.
 *
 * @param {unknown[]} value
 */
function assertPlainArray(value) {
  if (Object.getPrototypeOf(value) !== Array.prototype)
    throw new TypeError("bridge lists are plain arrays");
}

/** @param {Record<string, unknown>} record @param {string[]} keys */
function hasExactKeys(record, keys) {
  const actual = Object.keys(record).sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

/** @param {Record<string, BridgeValue>} record @param {HandleCodec | undefined} handles */
function decodeOrdinaryRecord(record, handles) {
  return Object.fromEntries(
    Object.entries(record).map(([key, entry]) => [key, decodeValue(entry, handles)]),
  );
}

/** @param {Record<string, BridgeValue>} record @param {HandleCodec | undefined} handles */
async function decodeOrdinaryRecordAsync(record, handles) {
  return Object.fromEntries(
    await Promise.all(
      Object.entries(record).map(async ([key, entry]) => [
        key,
        await decodeValueAsync(entry, handles),
      ]),
    ),
  );
}

/**
 * Encodes a bridge JS value. With `handles`, an object the session carries by
 * handle, at any depth, becomes its tag.
 *
 * @param {unknown} value @param {HandleCodec} [handles] @returns {BridgeValue}
 */
export function encodeValue(value, handles) {
  return encodeWith(value, new WeakSet(), handles);
}

/**
 * @param {unknown} value @param {WeakSet<object>} seen @param {HandleCodec | undefined} handles
 * @returns {BridgeValue}
 */
function encodeWith(value, seen, handles) {
  if (value === undefined) return { $type: "undefined" };
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("bridge numbers are finite");
    return value;
  }
  const tag = handleTag(value, handles);
  if (tag !== undefined) return tag;
  if (isRuntimeCryptoKey(value))
    throw new TypeError("bridge CryptoKey serialization requires an async semantic call");
  if (value instanceof Uint8Array) return { $type: "Uint8Array", base64url: base64url(value) };
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new TypeError("bridge instants are valid");
    return { $type: "Date", iso: value.toISOString() };
  }
  if (Array.isArray(value)) {
    assertPlainArray(value);
    if (seen.has(value)) throw new TypeError("bridge values are acyclic");
    seen.add(value);
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) throw new TypeError("bridge lists are dense");
      result.push(encodeWith(value[index], seen, handles));
    }
    seen.delete(value);
    return result;
  }
  if (isPlainRecord(value)) {
    if (seen.has(value)) throw new TypeError("bridge values are acyclic");
    seen.add(value);
    const result = Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, encodeWith(entry, seen, handles)]),
    );
    seen.delete(value);
    return Object.hasOwn(value, "$type") ? { $type: "Record", value: result } : result;
  }
  throw new TypeError("bridge values are JSON data, bytes, undefined, or instants");
}

/**
 * Encodes a bridge JS value, `CryptoKey` included. With `handles`, an object
 * the session carries by handle, at any depth, becomes its tag.
 *
 * @param {unknown} value @param {HandleCodec} [handles] @returns {Promise<BridgeValue>}
 */
export async function encodeValueAsync(value, handles) {
  return encodeAsyncWith(value, new WeakSet(), handles);
}

/**
 * @param {unknown} value @param {WeakSet<object>} seen @param {HandleCodec | undefined} handles
 * @returns {Promise<BridgeValue>}
 */
async function encodeAsyncWith(value, seen, handles) {
  const tag = handleTag(value, handles);
  if (tag !== undefined) return tag;
  if (isRuntimeCryptoKey(value)) return /** @type {BridgeValue} */ (await encodeCryptoKey(value));
  if (value === undefined || value === null || typeof value !== "object")
    return encodeWith(value, seen, handles);
  if (value instanceof Uint8Array || value instanceof Date) return encodeWith(value, seen, handles);
  if (Array.isArray(value)) {
    assertPlainArray(value);
    if (seen.has(value)) throw new TypeError("bridge values are acyclic");
    seen.add(value);
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) throw new TypeError("bridge lists are dense");
      result.push(await encodeAsyncWith(value[index], seen, handles));
    }
    seen.delete(value);
    return result;
  }
  if (isPlainRecord(value)) {
    if (seen.has(value)) throw new TypeError("bridge values are acyclic");
    seen.add(value);
    /** @type {Record<string, BridgeValue>} */
    const result = {};
    for (const [key, entry] of Object.entries(value))
      result[key] = await encodeAsyncWith(entry, seen, handles);
    seen.delete(value);
    return Object.hasOwn(value, "$type") ? { $type: "Record", value: result } : result;
  }
  return encodeWith(value, seen, handles);
}

/**
 * Decodes a bridge value. A handle, at any depth, becomes the object it names
 * in the session of `handles`; without `handles` it is refused.
 *
 * @param {BridgeValue} value @param {HandleCodec} [handles] @returns {unknown}
 */
export function decodeValue(value, handles) {
  if (Array.isArray(value)) return value.map((entry) => decodeValue(entry, handles));
  if (!isPlainRecord(value)) return value;
  if (value.$type === "Handle") return decodeHandle(value, handles);
  if (value.$type === "undefined" && hasExactKeys(value, ["$type"])) return undefined;
  if (
    value.$type === "Uint8Array" &&
    hasExactKeys(value, ["$type", "base64url"]) &&
    typeof value.base64url === "string" &&
    /^[A-Za-z0-9_-]*$/.test(value.base64url) &&
    value.base64url.length % 4 !== 1
  ) {
    const bytes = new Uint8Array(Buffer.from(value.base64url, "base64url"));
    if (base64url(bytes) !== value.base64url)
      throw new TypeError("bridge bytes are canonical base64url");
    return bytes;
  }
  if (
    value.$type === "Date" &&
    hasExactKeys(value, ["$type", "iso"]) &&
    typeof value.iso === "string"
  ) {
    const instant = new Date(value.iso);
    if (Number.isNaN(instant.getTime()) || instant.toISOString() !== value.iso)
      throw new TypeError("bridge instant is canonical ISO time");
    return instant;
  }
  if (
    value.$type === "Record" &&
    hasExactKeys(value, ["$type", "value"]) &&
    isPlainRecord(value.value)
  )
    return decodeOrdinaryRecord(/** @type {Record<string, BridgeValue>} */ (value.value), handles);
  if (value.$type === "CryptoKey")
    throw new TypeError("bridge CryptoKey materialization requires an async semantic call");
  if (Object.hasOwn(value, "$type"))
    throw new TypeError("bridge tagged value has an exact known shape");
  return decodeOrdinaryRecord(value, handles);
}

/**
 * Decodes a bridge value, `CryptoKey` included. A handle, at any depth,
 * becomes the object it names in the session of `handles`.
 *
 * @param {BridgeValue} value @param {HandleCodec} [handles] @returns {Promise<unknown>}
 */
export async function decodeValueAsync(value, handles) {
  if (Array.isArray(value))
    return Promise.all(value.map((entry) => decodeValueAsync(entry, handles)));
  if (!isPlainRecord(value)) return value;
  if (value.$type === "Handle") return decodeHandle(value, handles);
  if (
    value.$type === "CryptoKey" &&
    hasExactKeys(value, [
      "$type",
      "algorithm",
      "extractable",
      "format",
      "keyType",
      "usages",
      "value",
    ]) &&
    (value.keyType === "private" || value.keyType === "public" || value.keyType === "secret") &&
    isPlainRecord(value.algorithm) &&
    typeof value.extractable === "boolean" &&
    Array.isArray(value.usages) &&
    value.usages.every((usage) => typeof usage === "string") &&
    value.format === "jwk" &&
    isPlainRecord(value.value)
  ) {
    return decodeCryptoKey(value);
  }
  if (value.$type === "CryptoKey")
    throw new TypeError("bridge tagged value has an exact known shape");
  if (
    value.$type === "Record" &&
    hasExactKeys(value, ["$type", "value"]) &&
    isPlainRecord(value.value)
  )
    return decodeOrdinaryRecordAsync(
      /** @type {Record<string, BridgeValue>} */ (value.value),
      handles,
    );
  if (
    Object.hasOwn(value, "$type") &&
    !["undefined", "Uint8Array", "Date"].includes(/** @type {string} */ (value.$type))
  )
    throw new TypeError("bridge tagged value has an exact known shape");
  if (Object.hasOwn(value, "$type")) return decodeValue(value, handles);
  return decodeOrdinaryRecordAsync(value, handles);
}

export const utf8 =
  /** @type {{ encode: (value: string) => Uint8Array, decode: (value: AllowSharedBufferSource) => string }} */ ({
    encode: (value) => text.encode(value),
    decode: (value) => decoder.decode(value),
  });
