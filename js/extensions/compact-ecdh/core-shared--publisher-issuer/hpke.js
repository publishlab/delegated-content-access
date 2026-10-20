// @ts-check
//
// RFC 9180 HPKE in Base mode for the one suite the compact-ECDH profile fixes
// (docs/spec-profile--compact-ecdh.md Section 4.1):
//
//   KEM   DHKEM(P-256, HKDF-SHA256)   0x0010
//   KDF   HKDF-SHA256                 0x0001
//   AEAD  AES-256-GCM                 0x0002
//
// One sender context seals exactly one message at sequence number zero, and
// one receiver context opens it. At sequence zero the AEAD nonce is the
// base_nonce itself (RFC 9180 Section 5.2, ComputeNonce), so no sequence
// state exists here. The exporter secret is not computed; Section 4.1 of the
// profile allows that because the profile uses no exported value.
//
// The construction is the RFC's, byte for byte: the full DHKEM
// ExtractAndExpand over the raw ECDH x-coordinate (RFC 9180 Section 4.1), with
// `enc || pkRm` as kem_context in uncompressed form, and the full key schedule
// (Section 5.1) with the "HPKE-v1" labels, empty psk and psk_id, and mode 0.
// The raw x-coordinate never serves as a key by itself.
//
// It runs on WebCrypto ECDH, HMAC-SHA256 and AES-GCM, with no HPKE library.
// HKDF is written here as HMAC calls because RFC 9180 needs Extract and Expand
// as separate steps, and WebCrypto's HKDF only offers the two fused.
//
// Decap needs the recipient's own public key for kem_context. WebCrypto cannot
// derive it from a non-extractable private key, so `open` takes the
// recipient's key pair rather than the private key alone.
//
// `seal` generates its ephemeral key pair itself, so a caller cannot reuse
// one. `sealTranscript` and `openTranscript` are the steps under `seal` and
// `open`; they take the ephemeral pair and return the RFC 9180 intermediates.
// Only `seal`, `open` and the test facility in `testing/` call them;
// ../test/export-surface.test.js fails when any other module names them.

import { generateEcdhKeyPair, exportRawKey } from "../../../core-shared/cryptoProvider.js";
import { encrypt, decrypt } from "../../../core-shared/aead.js";
import { utf8Encode } from "../../../core-shared/codec.js";

const { subtle } = globalThis.crypto;

/** RFC 9180 Section 7.1: DHKEM(P-256, HKDF-SHA256). */
export const KEM_ID = 0x0010;

/** RFC 9180 Section 7.2: HKDF-SHA256. */
export const KDF_ID = 0x0001;

/** RFC 9180 Section 7.3: AES-256-GCM. */
export const AEAD_ID = 0x0002;

/** Nenc: the uncompressed P-256 point `04 || X || Y`. */
export const ENC_BYTES = 65;

/** Nsecret, Nh: the DHKEM shared secret and the HKDF-SHA256 output width. */
const HASH_BYTES = 32;

/** Nk for AES-256-GCM. */
const KEY_BYTES = 32;

/** Nn for AES-256-GCM. */
const NONCE_BYTES = 12;

/** The ECDH x-coordinate in bits, fixed width so leading zero octets stay. */
const DH_BITS = 256;

/** Base mode, RFC 9180 Section 5. */
const MODE_BASE = 0x00;

const VERSION_LABEL = utf8Encode("HPKE-v1");

/** "KEM" || I2OSP(kem_id, 2), RFC 9180 Section 4.1. */
export const KEM_SUITE_ID = concat(utf8Encode("KEM"), i2osp(KEM_ID, 2));

/** "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2), Section 5.1. */
export const HPKE_SUITE_ID = concat(
  utf8Encode("HPKE"),
  i2osp(KEM_ID, 2),
  i2osp(KDF_ID, 2),
  i2osp(AEAD_ID, 2),
);

/**
 * The values one sender or receiver context derives. Production callers never
 * see these; `testing/` returns them so tests can pin each step.
 *
 * @typedef {object} HpkeIntermediates
 * @property {Uint8Array} dh - the raw ECDH x-coordinate, 32 octets
 * @property {Uint8Array} sharedSecret - the DHKEM shared_secret, 32 octets
 * @property {Uint8Array} key - the AEAD key, 32 octets
 * @property {Uint8Array} baseNonce - the AEAD base_nonce, 12 octets
 */

/**
 * @param {number} value
 * @param {number} width
 * @returns {Uint8Array}
 */
function i2osp(value, width) {
  const out = new Uint8Array(width);
  let rest = value;
  for (let i = width - 1; i >= 0; i--) {
    out[i] = rest & 0xff;
    rest = Math.floor(rest / 256);
  }
  return out;
}

/**
 * @param {...Uint8Array} parts
 * @returns {Uint8Array}
 */
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * WebCrypto receives an ArrayBuffer-backed copy. Copied from the private
 * `webCryptoBytes` in ../../../core-shared/cryptoProvider.js, which has no HMAC or raw
 * ECDH output to offer this module.
 *
 * @param {Uint8Array} bytes
 * @returns {Uint8Array<ArrayBuffer>}
 */
function webCryptoBytes(bytes) {
  return Uint8Array.from(bytes);
}

/**
 * @param {Uint8Array} key
 * @param {Uint8Array} message
 * @returns {Promise<Uint8Array>}
 */
async function hmacSha256(key, message) {
  const handle = await subtle.importKey(
    "raw",
    webCryptoBytes(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await subtle.sign("HMAC", handle, webCryptoBytes(message)));
}

/**
 * RFC 9180 Section 4: LabeledExtract. An empty salt is HashLen zero octets
 * (RFC 5869 Section 2.2); it is spelled out because some WebCrypto runtimes
 * refuse a zero-length HMAC key.
 *
 * @param {Uint8Array} suiteId
 * @param {Uint8Array} salt
 * @param {string} label
 * @param {Uint8Array} ikm
 * @returns {Promise<Uint8Array>}
 */
export function labeledExtract(suiteId, salt, label, ikm) {
  const labeledIkm = concat(VERSION_LABEL, suiteId, utf8Encode(label), ikm);
  return hmacSha256(salt.length === 0 ? new Uint8Array(HASH_BYTES) : salt, labeledIkm);
}

/**
 * RFC 9180 Section 4: LabeledExpand, over HKDF-Expand (RFC 5869 Section 2.3).
 *
 * @param {Uint8Array} suiteId
 * @param {Uint8Array} prk
 * @param {string} label
 * @param {Uint8Array} info
 * @param {number} length
 * @returns {Promise<Uint8Array>}
 */
export async function labeledExpand(suiteId, prk, label, info, length) {
  const labeledInfo = concat(i2osp(length, 2), VERSION_LABEL, suiteId, utf8Encode(label), info);
  const out = new Uint8Array(length);
  /** @type {Uint8Array} */
  let previous = new Uint8Array(0);
  for (let block = 1, offset = 0; offset < length; block++) {
    previous = await hmacSha256(prk, concat(previous, labeledInfo, Uint8Array.of(block)));
    out.set(previous.subarray(0, Math.min(HASH_BYTES, length - offset)), offset);
    offset += HASH_BYTES;
  }
  return out;
}

/**
 * RFC 9180 Section 4.1: ExtractAndExpand.
 *
 * @param {Uint8Array} dh
 * @param {Uint8Array} kemContext - enc || pkRm, both uncompressed
 */
async function extractAndExpand(dh, kemContext) {
  const eaePrk = await labeledExtract(KEM_SUITE_ID, new Uint8Array(0), "eae_prk", dh);
  return labeledExpand(KEM_SUITE_ID, eaePrk, "shared_secret", kemContext, HASH_BYTES);
}

/**
 * RFC 9180 Section 5.1: KeySchedule for mode_base, empty psk and psk_id. The
 * exporter secret is left out.
 *
 * @param {Uint8Array} sharedSecret
 * @param {Uint8Array} info
 */
async function keySchedule(sharedSecret, info) {
  const empty = new Uint8Array(0);
  const pskIdHash = await labeledExtract(HPKE_SUITE_ID, empty, "psk_id_hash", empty);
  const infoHash = await labeledExtract(HPKE_SUITE_ID, empty, "info_hash", info);
  const context = concat(Uint8Array.of(MODE_BASE), pskIdHash, infoHash);
  const secret = await labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", empty);
  const key = await labeledExpand(HPKE_SUITE_ID, secret, "key", context, KEY_BYTES);
  const baseNonce = await labeledExpand(HPKE_SUITE_ID, secret, "base_nonce", context, NONCE_BYTES);
  return { key, baseNonce };
}

/**
 * @param {CryptoKey} privateKey
 * @param {CryptoKey} publicKey
 * @returns {Promise<Uint8Array>}
 */
async function ecdhX(privateKey, publicKey) {
  return new Uint8Array(
    await subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, DH_BITS),
  );
}

/**
 * @param {Uint8Array} raw - 65 octets
 * @returns {Promise<CryptoKey>}
 */
function importP256Public(raw) {
  return subtle.importKey(
    "raw",
    webCryptoBytes(raw),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
}

/**
 * SetupBaseS (RFC 9180 Section 5.1.1) with the given ephemeral pair, then one
 * Seal at sequence zero (Section 5.2).
 *
 * @param {CryptoKeyPair} ephemeral - generated for this one message
 * @param {CryptoKey} recipientPublicKey - ECDH P-256
 * @param {Uint8Array} info
 * @param {Uint8Array} aad
 * @param {Uint8Array} plaintext
 * @returns {Promise<{ enc: Uint8Array, ciphertext: Uint8Array } & HpkeIntermediates>}
 */
export async function sealTranscript(ephemeral, recipientPublicKey, info, aad, plaintext) {
  const enc = new Uint8Array(await exportRawKey(ephemeral.publicKey));
  const pkRm = new Uint8Array(await exportRawKey(recipientPublicKey));
  const dh = await ecdhX(ephemeral.privateKey, recipientPublicKey);
  const sharedSecret = await extractAndExpand(dh, concat(enc, pkRm));
  const { key, baseNonce } = await keySchedule(sharedSecret, info);
  const ciphertext = await encrypt(key, baseNonce, plaintext, aad, KEY_BYTES);
  return { enc, ciphertext, dh, sharedSecret, key, baseNonce };
}

/**
 * SetupBaseR (RFC 9180 Section 5.1.1), then one Open at sequence zero. Throws
 * on an `enc` WebCrypto refuses and on a failed AEAD tag; the caller maps both.
 *
 * @param {Uint8Array} enc - the 65-octet uncompressed ephemeral point
 * @param {CryptoKeyPair} recipient - the private key and its own public key
 * @param {Uint8Array} info
 * @param {Uint8Array} aad
 * @param {Uint8Array} ciphertext
 * @returns {Promise<{ plaintext: Uint8Array } & HpkeIntermediates>}
 */
export async function openTranscript(enc, recipient, info, aad, ciphertext) {
  const ephemeralPublic = await importP256Public(enc);
  const pkRm = new Uint8Array(await exportRawKey(recipient.publicKey));
  const dh = await ecdhX(recipient.privateKey, ephemeralPublic);
  const sharedSecret = await extractAndExpand(dh, concat(enc, pkRm));
  const { key, baseNonce } = await keySchedule(sharedSecret, info);
  const plaintext = await decrypt(key, baseNonce, ciphertext, aad, KEY_BYTES);
  return { plaintext, dh, sharedSecret, key, baseNonce };
}

/**
 * Single-shot Base-mode seal under a fresh ephemeral P-256 key pair.
 *
 * @param {CryptoKey} recipientPublicKey - ECDH P-256
 * @param {Uint8Array} info
 * @param {Uint8Array} aad
 * @param {Uint8Array} plaintext
 * @returns {Promise<{ enc: Uint8Array, ciphertext: Uint8Array }>}
 */
export async function seal(recipientPublicKey, info, aad, plaintext) {
  // RFC 9180 Section 9.7.1 and the profile's freshness duty: one ephemeral
  // per message. Reusing one repeats the key and nonce.
  const ephemeral = await generateEcdhKeyPair();
  const { enc, ciphertext } = await sealTranscript(
    ephemeral,
    recipientPublicKey,
    info,
    aad,
    plaintext,
  );
  return { enc, ciphertext };
}

/**
 * Single-shot Base-mode open.
 *
 * @param {Uint8Array} enc - the 65-octet uncompressed ephemeral point
 * @param {CryptoKeyPair} recipient
 * @param {Uint8Array} info
 * @param {Uint8Array} aad
 * @param {Uint8Array} ciphertext
 * @returns {Promise<Uint8Array>}
 */
export async function open(enc, recipient, info, aad, ciphertext) {
  return (await openTranscript(enc, recipient, info, aad, ciphertext)).plaintext;
}
