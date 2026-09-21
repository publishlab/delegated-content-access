// @ts-check
//
// Issuer to client, under client-bound transport, the RSA-OAEP method. The
// sibling of the ECDH-P256 method: the same last hop, wrapping each
// delivered key so its bytes never appear in the client's JavaScript, but
// against the client's RSA public key instead of an agreed ECDH transport.
//
// One key wrapped straight under RSA-OAEP: no ephemeral pair, no agreed
// transport key, no nonce. OAEP randomises its own padding, so an RSA response
// carries no entropy the issuer supplies and cannot be made to repeat; a vector
// pins an open, never a re-seal, the same statement keySealing.js's RSA carrier
// makes. The data format fixes RSA-OAEP to SHA-256.
//
// This module differs from keySealing.js's RSA in what comes out. That module
// opens to bytes through subtle.decrypt, because the issuer unseals a blob a
// publisher handed it. Here the client opens to a non-extractable CryptoKey
// handle through subtle.unwrapKey, because the whole point of client-bound
// transport is that the key never lands in JavaScript. This is therefore its
// own profile rather than a branch of that module.

import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { dcaError } from "../../../core-shared/errors.js";

const { subtle } = globalThis.crypto;

/**
 * This profile's method name. The tag a client-bound response carries so the
 * client can tell an answer meant for it from one meant for another method.
 */
export const METHOD = "RSA-OAEP";

/**
 * The client key requirements this profile owns. The capability validates only
 * key-safety facts common to every profile, then invokes this synchronous hook
 * so an injected profile does not need a capability-side method allowlist.
 *
 * @param {{ privateKey: CryptoKey, publicKey: JsonWebKey }} keyPair
 */
export function validateClientKeyPair({ privateKey, publicKey }) {
  const algorithm = /** @type {any} */ (privateKey).algorithm;
  if (
    algorithm?.name !== "RSA-OAEP" ||
    algorithm.hash?.name !== OAEP_HASH ||
    publicKey.kty !== "RSA"
  ) {
    throw dcaError(
      "bad_config",
      "an RSA-OAEP client needs an RSA-OAEP SHA-256 private key and public JWK",
    );
  }
  if (!Array.isArray(privateKey.usages) || !privateKey.usages.includes("unwrapKey")) {
    throw dcaError("bad_config", "an RSA-OAEP client private key needs unwrapKey usage");
  }
}

/** The data format fixes RSA-OAEP to SHA-256. */
export const OAEP_HASH = "SHA-256";

/**
 * The client's response-scoped opener. RSA carries no agreed transport, so
 * nothing is read off the transport object here; each delivered value opens
 * directly against the client's private half.
 *
 * @param {any} transport - the transport member the response carried, unused
 * @param {CryptoKey} clientPrivateKey
 * @returns {Promise<{ open: (value: any, usages: KeyUsage[]) => Promise<CryptoKey|null> }>}
 */
export async function open(transport, clientPrivateKey) {
  return {
    /**
     * @param {any} value - one delivered value, `{ key }`
     * @param {KeyUsage[]} usages - what the opened handle may do; a periodKey
     *   opens with `['unwrapKey']`, a delivered contentKey with `['decrypt']`.
     * @returns {Promise<CryptoKey|null>} the non-extractable handle
     */
    async open(value, usages) {
      const wrapped = binaryStringBytes(/** @type {any} */ (value).key);
      if (wrapped === null) {
        throw dcaError(
          "unwrap_failed",
          "a client-bound wrapped key is canonical unpadded base64url",
        );
      }

      try {
        const opened = await subtle.unwrapKey(
          "raw",
          wrapped,
          clientPrivateKey,
          { name: "RSA-OAEP" },
          { name: "AES-GCM", length: 128 },
          false,
          usages,
        );
        const algorithm = /** @type {any} */ (opened).algorithm;
        if (algorithm?.name !== "AES-GCM" || algorithm.length !== 128) {
          throw dcaError("bad_key", "client-bound delivery recovered a non-AES-128-GCM key");
        }
        return opened;
      } catch {
        // From here, a wrong private key, a blob one modulus too wide or
        // too narrow, and a flipped byte all surface as the same OAEP
        // padding failure, the way the ECDH side sees one tag failure.
        throw dcaError("unwrap_failed", "RSA-OAEP unwrap failed: OAEP padding check");
      }
    },
  };
}
