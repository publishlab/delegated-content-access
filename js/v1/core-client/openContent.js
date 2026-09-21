// @ts-check

// This function runs the decode and open steps at the end of one content
// decrypt. It lives in its own module, outside any client class, because the
// variants that build their own aad need every guard in it, and a variant can
// choose only the aad in a content decrypt. A nonce the page did not carry, an
// aad that is not a string, base64url that does not decode and a tag that does
// not verify are the same four failures however the aad was built, and copies
// of these checks drift.

import { utf8Encode } from "../core-shared/codec.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { decrypt } from "../core-shared/aead.js";
import { DcaError, dcaError } from "../core-shared/errors.js";

/**
 * Runs the decode and open steps at the end of a content decrypt.
 *
 * Only a DcaError may leave this function. `PageLoad` shows a DcaError as a
 * locked item and rethrows anything else, so a raw OperationError out of
 * WebCrypto or an InvalidCharacterError out of `atob` would take the whole load
 * down over one mangled item.
 *
 * This function gives a tag failure its own code instead of one of the miss
 * codes. To GCM, a wrong key, a record moved into another slot, a changed aad
 * and a flipped byte are one event, and that event means something different
 * from "nothing here opens this name".
 *
 * @param {Uint8Array|CryptoKey} contentKey
 * @param {string} contentName - for the messages
 * @param {unknown} nonce - base64url, off the page
 * @param {string} ciphertext - base64url, from `extract`
 * @param {unknown} aad - what the caller built or read off the record
 * @returns {Promise<Uint8Array>}
 */
export async function openContent(contentKey, contentName, nonce, ciphertext, aad) {
  if (typeof nonce !== "string") {
    throw dcaError("bad_page", `the contentData record for "${contentName}" carries no nonce`);
  }

  // This function throws the same page fault for a record with no string aad
  // and for a variant whose own build produced no string. If it passed them
  // on, both would reach GCM as a changed aad, and the caller would be told the
  // tag failed when the key was never wrong.
  if (typeof aad !== "string") {
    throw dcaError("bad_page", `the contentData record for "${contentName}" carries no aad`);
  }

  // Only the canonical unpadded base64url of spec--data-format.md section 2.2
  // decodes to bytes here. A padded value, a standard-base64 character and a
  // last character with unused bits set all decode through the generic codec,
  // and a page may not spell an item that way.
  const nonceBytes = binaryStringBytes(nonce);
  const ciphertextBytes = binaryStringBytes(ciphertext);
  if (nonceBytes === null || ciphertextBytes === null) {
    throw dcaError("bad_page", `the nonce or ciphertext for "${contentName}" is not base64url`);
  }

  try {
    return await decrypt(contentKey, nonceBytes, ciphertextBytes, utf8Encode(aad));
  } catch (cause) {
    // `aead` already reports a nonce of the wrong length, and reporting it
    // again as a tag failure would lose the more precise answer.
    if (cause instanceof DcaError) throw cause;
    throw dcaError(
      "decrypt_failed",
      `AES-GCM decrypt failed for "${contentName}": auth tag mismatch`,
    );
  }
}
