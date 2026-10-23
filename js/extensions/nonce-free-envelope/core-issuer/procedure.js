// @ts-check
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { dcaError } from "../../../core-shared/errors.js";
import { NONCE_FREE_ENVELOPE, open } from "../core-shared--publisher-issuer/envelope.js";

/**
 * @param {string} sealed
 * @param {{privateKey: CryptoKey}} key
 * @param {Uint8Array} aad - supplied by the engine's existing BIND reconstruction
 * @returns {Promise<Uint8Array>}
 */
export async function openNonceFreeEnvelope(sealed, key, aad) {
  const bytes = binaryStringBytes(sealed);
  if (bytes === null) throw dcaError("unseal_failed", "the experimental envelope does not open");
  return open(bytes, key.privateKey, aad);
}

/** @returns {{name: string, envelopeProcedures: Record<string, {open: typeof openNonceFreeEnvelope, keyAlgorithms: string[]}>}} */
export function nonceFreeEnvelopeIssuerContribution() {
  return Object.freeze({
    name: NONCE_FREE_ENVELOPE,
    envelopeProcedures: Object.freeze({
      [NONCE_FREE_ENVELOPE]: Object.freeze({
        open: openNonceFreeEnvelope,
        keyAlgorithms: ["ecdh-p256"],
      }),
    }),
  });
}
