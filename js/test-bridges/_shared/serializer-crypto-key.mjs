const sourceJwks = new WeakMap();

/** @param {unknown} value */
function jsonCopy(value) {
  return JSON.parse(JSON.stringify(value));
}

/** @param {unknown} value */
function isCryptoKey(value) {
  return typeof CryptoKey !== "undefined" && value instanceof CryptoKey;
}

/** @param {unknown} left @param {unknown} right @returns {boolean} */
function sameJson(left, right) {
  if (left === right) return true;
  if (!left || !right || typeof left !== "object" || typeof right !== "object") return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((entry, index) => sameJson(entry, right[index]))
    );
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  const leftRecord = /** @type {Record<string, unknown>} */ (left);
  const rightRecord = /** @type {Record<string, unknown>} */ (right);
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) => key === rightKeys[index] && sameJson(leftRecord[key], rightRecord[key]),
    )
  );
}

/** Retains the supplied JWK only for a key created by this bridge boundary. */
export function registerCryptoKeySource(
  /** @type {CryptoKey} */ key,
  /** @type {JsonWebKey} */ jwk,
) {
  sourceJwks.set(key, jsonCopy(jwk));
  return key;
}

/** @param {unknown} value @returns {value is CryptoKey} */
export function isRuntimeCryptoKey(value) {
  return isCryptoKey(value);
}

/** @param {CryptoKey} key */
export async function encodeCryptoKey(key) {
  const jwk = key.extractable ? await crypto.subtle.exportKey("jwk", key) : sourceJwks.get(key);
  if (!jwk) throw new TypeError("bridge cannot serialize an unknown nonextractable CryptoKey");
  const value = { ...jwk, ext: key.extractable, key_ops: [...key.usages] };
  return {
    $type: "CryptoKey",
    keyType: key.type,
    algorithm: jsonCopy(key.algorithm),
    extractable: key.extractable,
    usages: [...key.usages],
    format: "jwk",
    value: jsonCopy(value),
  };
}

/** @param {any} record */
export async function decodeCryptoKey(record) {
  const key = await crypto.subtle.importKey(
    "jwk",
    record.value,
    record.algorithm,
    record.extractable,
    record.usages,
  );
  if (
    key.type !== record.keyType ||
    key.extractable !== record.extractable ||
    !sameJson(key.algorithm, record.algorithm) ||
    !sameJson([...key.usages], record.usages)
  ) {
    throw new TypeError("bridge CryptoKey metadata did not survive import");
  }
  return registerCryptoKeySource(key, record.value);
}
