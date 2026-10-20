// The native fixture for the bridge-values suite. The suite and its expected
// values are in ../../../_shared/bridge-values/; suite.mjs there defines what
// each function returns. The functions are async so a key crosses as the bridge
// proxy would carry it.

/** @param {Uint8Array} octets */
function hex(octets) {
  return Buffer.from(octets).toString("hex");
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return (
    value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype
  );
}

/** @param {unknown} value */
export async function identity(value) {
  return value;
}

/** @param {unknown} value @param {...unknown} operands @returns {Promise<unknown>} */
export async function inspect(value, ...operands) {
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (value === undefined) return { undefined: true };
  if (typeof value === "string") return { octets: hex(new TextEncoder().encode(value)) };
  if (value instanceof Uint8Array) return { octets: hex(value) };
  if (value instanceof Date) return { epochMilliseconds: value.getTime() };
  if (value instanceof CryptoKey) {
    const [message, signature] = /** @type {[BufferSource, BufferSource]} */ (operands);
    const algorithm = { name: "ECDSA", hash: "SHA-256" };
    return { verifies: await crypto.subtle.verify(algorithm, value, signature, message) };
  }
  if (Array.isArray(value)) return Promise.all(value.map((entry) => inspect(entry)));
  if (isRecord(value)) {
    const entries = Object.entries(value);
    return Object.fromEntries(
      await Promise.all(entries.map(async ([name, entry]) => [name, await inspect(entry)])),
    );
  }
  throw new TypeError("fixture value has no bridge value type");
}

/** @param {unknown} value @returns {Promise<unknown>} */
export async function transform(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === "boolean") return !value;
  if (typeof value === "number") return -value;
  if (typeof value === "string") return `${value}é`;
  if (value instanceof Uint8Array) return new Uint8Array([...value, 0xff]);
  if (value instanceof Date) return new Date(value.getTime() + 1);
  if (value instanceof CryptoKey) {
    const jwk = await crypto.subtle.exportKey("jwk", value);
    return crypto.subtle.importKey("jwk", jwk, value.algorithm, value.extractable, value.usages);
  }
  if (Array.isArray(value)) return (await Promise.all(value.map(transform))).reverse();
  if (isRecord(value)) {
    const entries = Object.entries(value);
    return Object.fromEntries(
      await Promise.all(entries.map(async ([name, entry]) => [name, await transform(entry)])),
    );
  }
  throw new TypeError("fixture value has no bridge value type");
}
