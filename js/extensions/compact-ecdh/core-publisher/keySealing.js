// @ts-check
//
// The publisher side of the compact-ECDH extension: a key sealing that seals
// to an issuer whose configuration selects `envelope: "compact-ecdh"` with the
// profile's construction, and hands every other seal to the core key sealing
// unchanged (docs/spec-profile--compact-ecdh.md Sections 2 and 4).
//
// The Sealer passes the issuer's selection as `options.envelope` and writes the
// same value into the issuer block, so the client relays it and the issuer opens
// with the same procedure. The BIND octets are the core ones, as AAD.

import { seal as coreSeal } from "../../../core-shared--publisher-issuer/keySealing.js";
import { bindValue } from "../../../core-shared--publisher-issuer/bind.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { dcaError } from "../../../core-shared/errors.js";
import { seal as sealEnvelope } from "../core-shared--publisher-issuer/envelope.js";
import { COMPACT_ECDH } from "../core-shared--publisher-issuer/selector.js";

/** Every key this seam seals is a 16-byte AES key (Section 4.2). */
const SEALED_KEY_BYTES = 16;

/**
 * @param {Uint8Array} keyBytes
 * @param {CryptoKey} publicKey
 * @param {string} algorithm - the issuer key's ordinary procedure
 * @param {any} [options] - the Sealer's carrier options
 * @returns {Promise<string>}
 */
async function seal(keyBytes, publicKey, algorithm, options = {}) {
  const envelope = options?.envelope;
  if (envelope === undefined) return coreSeal(keyBytes, publicKey, algorithm, options);
  if (envelope !== COMPACT_ECDH) {
    throw dcaError("bad_config", `this key sealing has no envelope procedure ${String(envelope)}`);
  }
  // The compact procedure uses the issuer's P-256 key pair, the same one the
  // ordinary ECDH envelope uses; an RSA key has no compact form.
  if (algorithm !== "ecdh-p256") {
    throw dcaError("bad_config", "compact-ecdh seals only to an issuer registered for ecdh-p256");
  }
  // A caller-chosen ephemeral key would let one context seal twice, which
  // repeats the AES key and nonce (Section 6).
  if (options.ephemeralKeyPair !== undefined) {
    throw dcaError("unsupported_option", "compact-ecdh draws its ephemeral key itself");
  }
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== SEALED_KEY_BYTES) {
    throw dcaError("bad_key", "a sealed key is 16 bytes");
  }
  const aad = utf8Encode(bindValue(options.binding));
  return base64urlEncode(await sealEnvelope(keyBytes, publicKey, aad));
}

/** @type {import('../../../core-publisher/Sealer.js').KeySealing} */
export const compactEcdhKeySealing = Object.freeze({ seal });

/**
 * The publisher contribution: it owns the key sealing seam. An issuer then
 * selects the procedure with `envelope: "compact-ecdh"` in its configuration.
 *
 * @returns {import('../../../core-publisher/publisherComposition.js').PublisherContribution}
 */
export function compactEcdhPublisherContribution() {
  return Object.freeze({ name: "compact-ecdh", keySealing: compactEcdhKeySealing });
}
