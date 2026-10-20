// @ts-check
//
// How `run.js` turns one crossing into numbers: byte counts, compression,
// the normalization that makes compressed counts repeat, and the operation
// counters that stand for local derivation work.
//
// Three sizes describe one crossing, all in bytes:
//
//   raw     the UTF-8 length of the string that crossed
//   gzip    `zlib.gzipSync` at level 9, the setting the sibling
//           `compression-before-sealing` benchmark uses
//   br      `zlib.brotliCompressSync` at Node's defaults: quality 11, window
//           22, generic mode
//
// Raw counts repeat exactly on a rerun. Every sealed value has a fixed width
// (a 109-octet ECDH-P256 carrier, a 256-octet RSA-OAEP carrier at 2048 bits, a
// 64-octet ES256 signature), so the random bytes inside change nothing about
// the length. Compressed counts do move: an ECDH ephemeral key, an RSA-OAEP
// seal and an ES256 signature are fresh random bytes on every render, and a
// compressor finds a different handful of chance matches in each.
//
// `normalized()` removes that noise. It replaces each of those random values
// with the same number of bytes drawn from SHA-256 in counter mode over the
// value's position in the render, and re-encodes them as base64url of the same
// length. Everything else the render seeds from `demo/actors/Random.js`, so
// the normalized string repeats byte for byte and so do its compressed sizes.
// The replacement keeps each value's length and its uniform byte
// distribution, so it compresses as a fresh render does; `run.js` prints the
// spread over genuine renders beside the normalized figure to show that.

import { createHash } from "node:crypto";
import { brotliCompressSync, gzipSync } from "node:zlib";

import { base64urlDecode, base64urlEncode, utf8Encode } from "../../core-shared/codec.js";

/** gzip level, as the sibling benchmark and a static-asset CDN setting use. */
export const GZIP_LEVEL = 9;

/**
 * @param {string} text
 * @returns {{ raw: number, gzip: number, br: number }}
 */
export function sizes(text) {
  const bytes = utf8Encode(text);
  return {
    raw: bytes.length,
    gzip: gzipSync(bytes, { level: GZIP_LEVEL }).length,
    br: brotliCompressSync(bytes).length,
  };
}

/**
 * `length` bytes that depend on `label` alone.
 *
 * @param {string} label
 * @param {number} length
 * @returns {Uint8Array}
 */
function stream(label, length) {
  const out = new Uint8Array(length);
  for (let block = 0, filled = 0; filled < length; block++) {
    const digest = createHash("sha256").update(`${label}#${block}`).digest();
    out.set(digest.subarray(0, Math.min(digest.length, length - filled)), filled);
    filled += digest.length;
  }
  return out;
}

/**
 * The replacement for one random base64url value at one position.
 *
 * @param {string} label
 * @param {string} value
 */
function replacement(label, value) {
  const width = base64urlDecode(value).length;
  const replaced = base64urlEncode(stream(label, width));
  if (replaced.length !== value.length) {
    throw new Error(`normalization changed the width of ${label}`);
  }
  return replaced;
}

/**
 * A function that rewrites any string carrying this render's random values
 * into its normalized twin: the markup, and the request that copies the same
 * values. The values are the ES256 signature in `resourceJWT` and every
 * issuer-sealed carrier under `issuerData[*].sealed`. Each is long and random,
 * so a plain substring replacement cannot hit anything else.
 *
 * @param {any} dcaData - the parsed dca-data of one render
 * @returns {(text: string) => string}
 */
export function normalizer(dcaData) {
  /** @type {Map<string, string>} */
  const replaced = new Map();
  const signature = String(dcaData.resourceJWT).split(".")[2];
  replaced.set(signature, replacement("resourceJWT.signature", signature));
  for (const [issuerName, block] of Object.entries(dcaData.issuerData)) {
    for (const [section, members] of Object.entries(/** @type {any} */ (block).sealed)) {
      for (const [outer, inner] of Object.entries(/** @type {any} */ (members))) {
        if (typeof inner === "string") {
          replaced.set(inner, replacement(`${issuerName}/${section}/${outer}`, inner));
          continue;
        }
        for (const [t, value] of Object.entries(/** @type {any} */ (inner))) {
          replaced.set(
            /** @type {string} */ (value),
            replacement(`${issuerName}/${section}/${outer}/${t}`, /** @type {string} */ (value)),
          );
        }
      }
    }
  }
  return (text) => {
    let out = text;
    for (const [from, to] of replaced) out = out.split(from).join(to);
    if (out.length !== text.length) throw new Error("normalization changed a string's length");
    return out;
  };
}

/**
 * @typedef {object} Work
 * @property {number} hkdf - `deriveBits` calls under HKDF: chain-construction steps
 * @property {number} ecdh - `deriveBits` calls under ECDH: one per ECDH-P256 seal or opening
 * @property {number} rsa - `encrypt` or `decrypt` calls under RSA-OAEP: one per seal or opening
 */

/**
 * Counts WebCrypto operations spent while `run` runs, filed under the phase
 * that is current when each call starts. `run` receives a function that sets
 * the phase. The originals are restored in a `finally`, the way
 * `chain-keys-bounds/measure.js` counts HKDF.
 *
 * @template T
 * @param {(phase: (name: string) => void) => Promise<T>} run
 * @returns {Promise<{ value: T, work: Record<string, Work> }>}
 */
export async function counted(run) {
  const subtle = globalThis.crypto.subtle;
  const { deriveBits, encrypt, decrypt } = subtle;
  /** @type {Record<string, Work>} */
  const work = {};
  let phase = "unphased";
  const tally = () => (work[phase] ??= { hkdf: 0, ecdh: 0, rsa: 0 });
  /** @param {any} algorithm */
  const nameOf = (algorithm) => (typeof algorithm === "string" ? algorithm : algorithm?.name);

  subtle.deriveBits = async function (/** @type {any[]} */ ...args) {
    const name = nameOf(args[0]);
    if (name === "HKDF") tally().hkdf++;
    if (name === "ECDH") tally().ecdh++;
    return deriveBits.apply(this, /** @type {any} */ (args));
  };
  subtle.encrypt = async function (/** @type {any[]} */ ...args) {
    if (nameOf(args[0]) === "RSA-OAEP") tally().rsa++;
    return encrypt.apply(this, /** @type {any} */ (args));
  };
  subtle.decrypt = async function (/** @type {any[]} */ ...args) {
    if (nameOf(args[0]) === "RSA-OAEP") tally().rsa++;
    return decrypt.apply(this, /** @type {any} */ (args));
  };
  try {
    const value = await run((name) => {
      phase = name;
    });
    return { value, work };
  } finally {
    subtle.deriveBits = deriveBits;
    subtle.encrypt = encrypt;
    subtle.decrypt = decrypt;
  }
}

/**
 * @param {number} count
 * @returns {string} digits grouped in threes, `30 786`
 */
export function grouped(count) {
  return String(count).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
}
