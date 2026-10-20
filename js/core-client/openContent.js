// @ts-check

// Final content opening uses the fixed twelve-zero-octet nonce. The caller
// supplies privately captured AAD bytes and ciphertext; carried item nonce
// or AAD members never participate in this procedure.

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
 * codes. To GCM, a wrong key, a record moved into another slot, a changed
 * render or item name and a flipped byte are one event. That event means
 * something different from "nothing here opens this name".
 *
 * @param {Uint8Array|CryptoKey} contentKey
 * @param {string} contentName - for the messages
 * @param {string} ciphertext - base64url, from `extract`
 * @param {Uint8Array} contentAad - the item's transcript, from its captured view
 * @returns {Promise<Uint8Array>}
 */
export async function openContent(contentKey, contentName, ciphertext, contentAad) {
  // A caller holding no transcript bytes, such as one that still reads a
  // carried string off the record, is a composition fault. Passed on, it would
  // reach GCM as a changed AAD and read as a wrong key.
  if (!(contentAad instanceof Uint8Array)) {
    throw dcaError("bad_config", `the content AAD for "${contentName}" is not bytes`);
  }

  // Only the canonical unpadded base64url of spec--data-format.md section 2.2
  // decodes to bytes here. A padded value, a standard-base64 character and a
  // last character with unused bits set all decode through the generic codec,
  // and a page may not spell an item that way.
  const ciphertextBytes = binaryStringBytes(ciphertext);
  if (ciphertextBytes === null) {
    throw dcaError("bad_page", `the ciphertext for "${contentName}" is not base64url`);
  }

  if (ciphertextBytes.length < 16) {
    throw dcaError("bad_page", `the ciphertext for "${contentName}" has an invalid AES-GCM length`);
  }

  try {
    return await decrypt(
      contentKey,
      new Uint8Array(12),
      ciphertextBytes,
      Uint8Array.from(contentAad),
    );
  } catch (cause) {
    // Trusted crypto/key configuration faults remain distinct from an
    // authentication failure. Malformed page lengths were refused above.
    if (cause instanceof DcaError) throw cause;
    throw dcaError(
      "decrypt_failed",
      `AES-GCM decrypt failed for "${contentName}": auth tag mismatch`,
    );
  }
}
