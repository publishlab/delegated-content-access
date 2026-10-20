// @ts-check
//
// One attempt to open one content-key wrap with one already-selected
// period-key capability. This file does not select or order candidates; the
// resolver does. Entry interpretation supplies the one AAD reading selected
// for this attempt.

import { decrypt, decryptToKey, NONCE_BYTES, TAG_BYTES } from "../core-shared/aead.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";

/** Canonical v1 content keys and period-key handles are AES-128. */
const CONTENT_KEY_BYTES = 16;

/** A raw 16-byte key wrapped by AES-GCM carries its 16-byte tag too. */
const WRAPPED_CONTENT_KEY_BYTES = CONTENT_KEY_BYTES + TAG_BYTES;

/** @param {unknown} cause */
function isAuthenticationFailure(cause) {
  return cause instanceof DOMException && cause.name === "OperationError";
}

/**
 * Decode and try one validated content-key wrap. Returns null when the entry
 * is unreadable or the GCM tag fails. Throws on configuration and capability
 * faults.
 *
 * Canonical wraps use a 16-byte period key and recover a 16-byte content key.
 *
 * @param {any} entry
 * @param {Uint8Array|CryptoKey} periodKey
 * @param {Uint8Array} [aad]
 * @returns {Promise<Uint8Array|CryptoKey|null>}
 */
export async function attemptContentKeyWrap(entry, periodKey, aad) {
  if (!(periodKey instanceof Uint8Array) && !(periodKey instanceof globalThis.CryptoKey)) {
    throw dcaError(
      "bad_config",
      "a content-key wrap attempt needs period-key bytes or a CryptoKey handle",
    );
  }
  if (aad !== undefined && !(aad instanceof Uint8Array)) {
    throw dcaError("bad_config", "content-key wrap AAD is bytes when present");
  }
  if (periodKey instanceof Uint8Array && periodKey.length !== 16) {
    throw dcaError(
      "bad_key",
      `a canonical wrap takes a 16-byte period key, and this candidate is ` + `${periodKey.length}`,
    );
  }
  if (periodKey instanceof globalThis.CryptoKey) {
    const algorithm = /** @type {any} */ (periodKey).algorithm;
    if (algorithm?.name !== "AES-GCM" || algorithm.length !== CONTENT_KEY_BYTES * 8) {
      throw dcaError("bad_key", "a canonical wrap takes an AES-128-GCM period-key handle");
    }
  }
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return null;

  const nonce = own(entry, "nonce");
  const wrapped = own(entry, "key");
  if (typeof nonce !== "string" || typeof wrapped !== "string") return null;

  // The decoder returns null for a spelling that section 2.2 refuses, so the
  // entry is unreadable and this candidate misses. The decoder does not throw
  // here, because a throw would propagate out of this function rather than
  // drop one candidate.
  const nonceBytes = binaryStringBytes(nonce);
  const wrappedBytes = binaryStringBytes(wrapped);
  if (nonceBytes === null || wrappedBytes === null) return null;
  if (nonceBytes.length !== NONCE_BYTES || wrappedBytes.length !== WRAPPED_CONTENT_KEY_BYTES)
    return null;

  try {
    const opened =
      periodKey instanceof Uint8Array
        ? await decrypt(periodKey, nonceBytes, wrappedBytes, aad)
        : await decryptToKey(periodKey, nonceBytes, wrappedBytes, aad, ["decrypt"]);
    if (opened instanceof Uint8Array) {
      return opened.length === CONTENT_KEY_BYTES ? opened : null;
    }
    const algorithm = /** @type {any} */ (opened).algorithm;
    return algorithm?.name === "AES-GCM" && algorithm.length === CONTENT_KEY_BYTES * 8
      ? opened
      : null;
  } catch (cause) {
    if (isAuthenticationFailure(cause)) return null;
    throw cause;
  }
}
