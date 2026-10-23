// @ts-check
//
// Reference-test key-material scanner shared by base and optional-extension
// placement tests. It asks the same opaque period-key supply used to compose the
// render rather than trusting an unlock response.

import { decrypt } from "../../core-shared/aead.js";
import { base64urlDecode, base64urlEncode } from "../../core-shared/codec.js";
import { dcaError } from "../../core-shared/errors.js";
import { decodeCompactJwt } from "../../core-shared/compactJwt.js";
import { contentKeyWrapNonce } from "../../core-shared/contentKeyWrapNonce.js";

/**
 * Recompute every key a render is made of from the publisher's own
 * supply: each periodKey named by the render and each contentKey those
 * periodKeys unwrap. Reading the render rather than a response gives a
 * client-bound run known bytes to compare against even when delivery uses
 * opaque handles.
 *
 * @param {any} wire
 * @param {{ derive: (accessGroup: string, t: string) => Promise<Uint8Array> }} periodKeySupply
 * @param {{ additionalDataFor?: (entry: { contentName: string, accessGroup: string, value: any }) => Uint8Array|undefined }} [options]
 * @returns {Promise<{ label: string, bytes: Uint8Array }[]>}
 */
export async function keyMaterialInPlay(wire, periodKeySupply, options = {}) {
  if (typeof periodKeySupply?.derive !== "function") {
    throw dcaError(
      "bad_config",
      "keyMaterialInPlay needs a periodKeySupply with derive(accessGroup, t)",
    );
  }
  if (options.additionalDataFor !== undefined && typeof options.additionalDataFor !== "function") {
    throw dcaError("bad_config", "keyMaterialInPlay additionalDataFor is a function when supplied");
  }
  /** @type {{ label: string, bytes: Uint8Array }[]} */
  const material = [];
  /** @type {Set<string>} */
  const seenContentKeys = new Set();
  // Each wrap's nonce derives from the render and its coordinate; no entry carries one.
  const renderId = decodeCompactJwt(wire.resourceJWT).payload.renderId;

  // The scan has to see every wrap, so a page it cannot walk throws rather
  // than reporting no material.
  if (!Array.isArray(wire.contentData))
    throw dcaError("bad_page", "keyMaterialInPlay needs contentData as an array of item records");
  for (const record of wire.contentData) {
    const contentName = record?.contentName;
    const keys = record?.keys ?? [];
    if (typeof contentName !== "string" || !Array.isArray(keys))
      throw dcaError("bad_page", "keyMaterialInPlay needs named item records with keys arrays");
    for (const entry of keys) {
      const { accessGroup, period } = entry ?? {};
      if (typeof accessGroup !== "string" || typeof period !== "string")
        throw dcaError("bad_page", `a wrap of ${contentName} names no accessGroup and period`);
      const periodKey = await periodKeySupply.derive(accessGroup, period);
      material.push({ label: `the periodKey for ${accessGroup}/${period}`, bytes: periodKey });

      // `value` is the wire record, so a caller reads `value.period`.
      const aad = options.additionalDataFor?.({ contentName, accessGroup, value: entry });
      const nonce = await contentKeyWrapNonce({
        renderId,
        contentName,
        accessGroup,
        t: period,
        aad,
      });
      if (nonce === null) throw dcaError("bad_page", `no wrap nonce for ${contentName}/${period}`);
      const contentKey = await decrypt(periodKey, nonce, base64urlDecode(entry.key), aad);
      const spelling = base64urlEncode(contentKey);
      if (seenContentKeys.has(spelling)) continue;
      seenContentKeys.add(spelling);
      material.push({ label: `the contentKey for ${contentName}`, bytes: contentKey });
    }
  }

  return material;
}

/**
 * The wire spelling, standard base64, and both hex cases catch the common ways
 * raw key bytes can escape through a string.
 *
 * @param {Uint8Array} bytes
 * @returns {string[]}
 */
function spellingsOf(bytes) {
  let binary = "";
  let hex = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
    hex += byte.toString(16).padStart(2, "0");
  }
  return [base64urlEncode(bytes), btoa(binary), hex, hex.toUpperCase()];
}

/** @param {Uint8Array} haystack @param {Uint8Array} needle */
function containsBytes(haystack, needle) {
  if (needle.length === 0 || haystack.length < needle.length) return false;
  for (let start = 0; start <= haystack.length - needle.length; start++) {
    let hit = true;
    for (let i = 0; i < needle.length; i++) {
      if (haystack[start + i] !== needle[i]) {
        hit = false;
        break;
      }
    }
    if (hit) return true;
  }
  return false;
}

/**
 * Search strings, byte containers and live CryptoKey handles recursively.
 * Object member names are searched too, so a map keyed by material cannot
 * hide behind otherwise clean values.
 *
 * @param {any} root
 * @param {{ label: string, bytes: Uint8Array }[]} material
 * @returns {string[]}
 */
export function leaks(root, material) {
  const secrets = material.map(({ label, bytes }) => ({
    label,
    bytes,
    spellings: spellingsOf(bytes),
  }));
  /** @type {string[]} */
  const found = [];
  /** @type {Set<object>} */
  const seen = new Set();

  /** @param {any} value @param {string} path */
  const visit = (value, path) => {
    if (value === null || value === undefined) return;
    if (typeof value === "string") {
      for (const secret of secrets) {
        for (const spelling of secret.spellings) {
          if (value.includes(spelling)) found.push(`${path}: ${secret.label}, as text`);
        }
      }
      return;
    }
    if (typeof value !== "object" || seen.has(value)) return;
    seen.add(value);

    if (globalThis.CryptoKey && value instanceof globalThis.CryptoKey) {
      found.push(`${path}: a CryptoKey handle (${value.algorithm?.name})`);
      return;
    }
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
      const bytes =
        value instanceof ArrayBuffer
          ? new Uint8Array(value)
          : new Uint8Array(
              /** @type {any} */ (value).buffer,
              /** @type {any} */ (value).byteOffset,
              /** @type {any} */ (value).byteLength,
            );
      for (const secret of secrets) {
        if (containsBytes(bytes, secret.bytes)) found.push(`${path}: ${secret.label}, as bytes`);
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((entry, index) => visit(entry, `${path}[${index}]`));
      return;
    }
    if (value instanceof Map) {
      for (const [key, entry] of value) {
        visit(key, `${path}<key>`);
        visit(entry, `${path}.get(${String(key)})`);
      }
      return;
    }
    if (value instanceof Set) {
      let index = 0;
      for (const entry of value) visit(entry, `${path}<${index++}>`);
      return;
    }
    for (const key of Object.keys(value)) {
      visit(key, `${path}<key>`);
      visit(value[key], `${path}.${key}`);
    }
  };

  visit(root, "$");
  return found;
}
