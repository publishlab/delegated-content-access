// @ts-check
import { seal as coreSeal } from "../../../core-shared--publisher-issuer/keySealing.js";
import { bindValue } from "../../../core-shared--publisher-issuer/bind.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { dcaError } from "../../../core-shared/errors.js";
import {
  NONCE_FREE_ENVELOPE,
  seal as sealEnvelope,
} from "../core-shared--publisher-issuer/envelope.js";

/**
 * @param {Uint8Array} payload
 * @param {CryptoKey} publicKey
 * @param {string} algorithm
 * @param {any} [options]
 * @returns {Promise<string>}
 */
async function seal(payload, publicKey, algorithm, options = {}) {
  if (options.envelope === undefined) return coreSeal(payload, publicKey, algorithm, options);
  if (options.envelope !== NONCE_FREE_ENVELOPE || algorithm !== "ecdh-p256") {
    throw dcaError("bad_config", "nonce-free envelope requires explicit matching ECDH selection");
  }
  if (
    options.ephemeralKeyPair !== undefined ||
    options.kdf !== undefined ||
    options.payloadBytes !== undefined
  ) {
    throw dcaError(
      "unsupported_option",
      "nonce-free envelope generates its own pair and fixes its construction",
    );
  }
  return base64urlEncode(
    await sealEnvelope(payload, publicKey, utf8Encode(bindValue(options.binding))),
  );
}

/** @type {import('../../../core-publisher/Sealer.js').KeySealing} */
export const nonceFreeEnvelopeKeySealing = Object.freeze({ seal });

/** @returns {import('../../../core-publisher/publisherComposition.js').PublisherContribution} */
export function nonceFreeEnvelopePublisherContribution() {
  return Object.freeze({ name: NONCE_FREE_ENVELOPE, keySealing: nonceFreeEnvelopeKeySealing });
}
