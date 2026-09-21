// @ts-check
//
// AES-GCM. The same call seals content and wraps keys.
//
// The caller passes the 12-byte nonce as an argument. Generating it here would
// put entropy inside a pure core; the nonce comes from the `Random` that the
// sealing caller holds.
//
// The caller states the key width, and this module never sniffs it. Canonical
// DCA data keys are 16 bytes; callers state the 32-byte width of ECDH transport
// keys explicitly. A key whose length disagrees with the stated width is refused
// rather than imported at whatever width arrived.

import { dcaError } from "./errors.js";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesGcmUnwrapKey,
  importAesGcmKey,
} from "./cryptoProvider.js";

/** AES-GCM nonce length in bytes, fixed by the data format. */
export const NONCE_BYTES = 12;

/** AES-GCM auth tag length in bytes. */
export const TAG_BYTES = 16;

/** The AES key width used when a caller does not state one. */
const DEFAULT_KEY_BYTES = 16;

/** The AES widths used by canonical data keys and transport keys. */
const KEY_WIDTHS = [16, 32];

/**
 * Key material, either as raw bytes or as a handle whose bytes are not
 * readable from JS. Client-bound transport hands over the second kind, and
 * nothing here has to know which it got.
 *
 * @typedef {Uint8Array|CryptoKey} AesKey
 */

/**
 * @param {AesKey} key
 * @param {KeyUsage} usage
 * @param {number} keyBytes - the width the caller stated
 * @returns {Promise<CryptoKey>}
 */
async function asCryptoKey(key, usage, keyBytes = DEFAULT_KEY_BYTES) {
  // When the caller omits keyBytes, this uses the one canonical delivered-key
  // width. It must not infer AES-256 from an opaque handle: callers of the
  // retained internal transport key pass 32 explicitly at their call site.
  if (!KEY_WIDTHS.includes(keyBytes)) {
    throw dcaError(
      "bad_config",
      `an AES-GCM key is 16 or 32 bytes wide, and this call states ${JSON.stringify(keyBytes)}`,
    );
  }
  if (key instanceof Uint8Array) {
    if (key.length !== keyBytes) {
      throw dcaError(
        "bad_key",
        `AES-${keyBytes * 8}-GCM needs a ${keyBytes}-byte key, got ${key.length}`,
      );
    }
    return importAesGcmKey(key, [usage]);
  }
  // A handle with unreadable bytes still reports its algorithm. Where the
  // runtime also exposes the handle's AES width, this code checks that width
  // against the stated one. Inside the call below, WebCrypto refuses a value
  // that states no algorithm.
  const algorithm = /** @type {any} */ (key).algorithm;
  if (
    typeof algorithm?.name === "string" &&
    (algorithm.name !== "AES-GCM" ||
      (typeof algorithm.length === "number" && algorithm.length !== keyBytes * 8))
  ) {
    throw dcaError("bad_key", `this call needs an AES-${keyBytes * 8}-GCM CryptoKey`);
  }
  return key;
}

/**
 * @param {Uint8Array} nonce
 * @returns {void}
 */
function validateNonce(nonce) {
  if (nonce.length !== NONCE_BYTES) {
    throw dcaError("bad_config", `AES-GCM needs a ${NONCE_BYTES}-byte nonce, got ${nonce.length}`);
  }
}

/**
 * @param {AesKey} key
 * @param {Uint8Array} nonce - 12 bytes, from `Random`
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} [aad] - opaque to everyone but the sealer
 * @param {number} [keyBytes] - the key width the caller states. The default
 *   is the canonical 16-byte data-key width.
 * @returns {Promise<Uint8Array>} ciphertext with the 16-byte tag appended
 */
export async function encrypt(key, nonce, plaintext, aad, keyBytes) {
  const cryptoKey = await asCryptoKey(key, "encrypt", keyBytes);
  validateNonce(nonce);
  const sealed = await aesGcmEncrypt(cryptoKey, nonce, plaintext, aad);
  return new Uint8Array(sealed);
}

/**
 * Throws when the tag does not verify. A wrong key, a changed nonce, a changed
 * aad and a flipped ciphertext byte all fail the same way. For anything a
 * signature does not cover, this tag is the only integrity check.
 *
 * @param {AesKey} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} ciphertext - with the tag appended
 * @param {Uint8Array} [aad]
 * @param {number} [keyBytes] - the key width the caller states, as for
 *   `encrypt`
 * @returns {Promise<Uint8Array>}
 */
export async function decrypt(key, nonce, ciphertext, aad, keyBytes) {
  const cryptoKey = await asCryptoKey(key, "decrypt", keyBytes);
  validateNonce(nonce);
  const opened = await aesGcmDecrypt(cryptoKey, nonce, ciphertext, aad);
  return new Uint8Array(opened);
}

/**
 * Performs the same AES-GCM open as `decrypt`, but returns a non-extractable
 * `CryptoKey` instead of bytes. `subtle.unwrapKey` produces a key whose material
 * never reaches JavaScript, so callers can continue the chain without the key
 * ever becoming readable: a periodKey handle opens a contentKey handle, and the
 * contentKey handle decrypts the article. Client-bound transport needs this;
 * direct delivery opens to bytes with `decrypt`.
 *
 * Same argument order and byte-taking convention as `decrypt`: the ciphertext is
 * bytes, so any base64url decode stays with the caller.
 *
 * @param {AesKey} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} ciphertext - with the tag appended
 * @param {Uint8Array} [aad]
 * @param {KeyUsage[]} [usages] - what the opened handle is allowed to do, and
 *   nothing more. A delivered contentKey decrypts (`['decrypt']`); a periodKey
 *   only unwraps the next hop and keeps `['unwrapKey']`. The default covers the
 *   leaf case, but every caller in this codebase passes its intended set:
 *   granting a handle both would give it more than it needs.
 * @param {number} [keyBytes] - the wrapping key's width, stated as for
 *   `encrypt`
 * @param {number} [unwrappedKeyBytes] - the width of the key being recovered
 * @returns {Promise<CryptoKey>} non-extractable AES-GCM key
 */
export async function decryptToKey(
  key,
  nonce,
  ciphertext,
  aad,
  usages = ["decrypt"],
  keyBytes,
  unwrappedKeyBytes = DEFAULT_KEY_BYTES,
) {
  const cryptoKey = await asCryptoKey(key, "unwrapKey", keyBytes);
  validateNonce(nonce);
  if (!KEY_WIDTHS.includes(unwrappedKeyBytes)) {
    throw dcaError(
      "bad_config",
      `an unwrapped AES-GCM key is 16 or 32 bytes wide, and this call states ${JSON.stringify(unwrappedKeyBytes)}`,
    );
  }
  // AES-GCM appends its fixed tag to the raw key bytes. This code checks the
  // wrapped length before unwrapKey because a runtime may recover raw AES
  // material at its own width even when the caller requested another import
  // algorithm length.
  const expectedCarrierBytes = unwrappedKeyBytes + TAG_BYTES;
  if (ciphertext.length !== expectedCarrierBytes) {
    throw dcaError(
      "bad_key",
      `an AES-${unwrappedKeyBytes * 8}-GCM wrapped key is ${expectedCarrierBytes} bytes with its tag, got ${ciphertext.length}`,
    );
  }
  const opened = await aesGcmUnwrapKey(
    cryptoKey,
    nonce,
    ciphertext,
    aad,
    usages,
    unwrappedKeyBytes,
  );
  const algorithm = /** @type {any} */ (opened).algorithm;
  if (algorithm?.name !== "AES-GCM" || algorithm.length !== unwrappedKeyBytes * 8) {
    throw dcaError(
      "bad_key",
      `this call recovered a non-canonical AES-${unwrappedKeyBytes * 8}-GCM CryptoKey`,
    );
  }
  return opened;
}
