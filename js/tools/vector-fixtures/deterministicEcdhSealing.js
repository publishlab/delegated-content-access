// @ts-check
//
// An adapter for a recorded ECDH transcript, nonconforming on purpose and used
// by tests and vector builds only. A caller substitutes it for `keySealing`
// explicitly, and it supplies a recorded ephemeral pair; production publishers
// use the core default, which generates a fresh pair per envelope.

import { seal } from "../../core-shared--publisher-issuer/keySealing.js";

/**
 * @param {(issuerPublicKey: CryptoKey, binding: object) => CryptoKeyPair|undefined} ephemeralFor
 */
export function deterministicEcdhFixtureSealing(ephemeralFor) {
  return Object.freeze({
    /**
     * @param {Uint8Array} keyBytes
     * @param {CryptoKey} issuerPublicKey
     * @param {string} algorithm
     * @param {any} options
     */
    seal(keyBytes, issuerPublicKey, algorithm, options) {
      if (algorithm !== "ecdh-p256") return seal(keyBytes, issuerPublicKey, algorithm, options);
      const ephemeralKeyPair = ephemeralFor(issuerPublicKey, options.binding);
      if (ephemeralKeyPair === undefined) {
        throw new Error("no recorded ephemeral keypair for this ECDH fixture coordinate");
      }
      return seal(keyBytes, issuerPublicKey, algorithm, {
        ...options,
        ephemeralKeyPair,
      });
    },
  });
}
