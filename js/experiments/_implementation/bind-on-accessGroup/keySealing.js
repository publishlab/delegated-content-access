// @ts-check
// Sibling to base source: js/core-shared--publisher-issuer/keySealing.js
//
// This rejected implementation changes only the value that the variant-only
// carrier fixture commits to. The production core keeps its fixed dca-bind-key-envelope
// grammar and exports no alternate-binding seam.

import { dcaError } from "../../../core-shared/errors.js";
import { sealingWith } from "../../../tools/vector-fixtures/keySealingWith.js";
import { bindValue } from "./bind.js";

const sealing = sealingWith(bindValue);

/**
 * Preserve this row's refusal surface while the fixture supplies both carrier
 * bodies. In particular, a `bind` option cannot carry a different value grammar
 * past the accessGroup-only builder.
 *
 * @param {any} options
 * @returns {any}
 */
function checkedOptions(options) {
  const checked = options ?? {};
  if (checked.bind !== undefined) {
    throw dcaError(
      "unsupported_option",
      "the binding is built from an accessGroup here, not passed as a string",
    );
  }
  if (checked.binding === undefined) {
    throw dcaError("binding_failed", "this variant requires a binding coordinate");
  }
  return checked;
}

/**
 * @param {Uint8Array} keyBytes
 * @param {CryptoKey} issuerPublicKey
 * @param {string} algorithm
 * @param {any} [options]
 * @returns {Promise<string>}
 */
export async function seal(keyBytes, issuerPublicKey, algorithm, options) {
  return sealing.seal(keyBytes, issuerPublicKey, algorithm, checkedOptions(options));
}

/**
 * @param {string} blob
 * @param {CryptoKey} issuerPrivateKey
 * @param {string} algorithm
 * @param {any} [options]
 * @returns {Promise<Uint8Array>}
 */
export async function unseal(blob, issuerPrivateKey, algorithm, options) {
  try {
    return await sealing.unseal(blob, issuerPrivateKey, algorithm, checkedOptions(options));
  } catch (error) {
    // This row has always named its one bound field in the RSA mismatch.
    // The fixture's generic message says "coordinate" because other rows
    // may bind a larger value.
    if (
      algorithm === "rsa-oaep" &&
      error instanceof Error &&
      error.message === "RSA-OAEP unseal failed: the plaintext is not bound to this coordinate"
    ) {
      throw dcaError(
        "unseal_failed",
        "RSA-OAEP unseal failed: the plaintext is not bound to this access tier",
      );
    }
    throw error;
  }
}
