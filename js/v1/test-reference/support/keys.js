// @ts-check
//
// Key material a test makes up: a keypair for whichever algorithm is under test,
// a periodKey that is nothing but a label, and a seeded byte stream.
//
// `seededRandom` is a factory and not a shared instance. Three files each held
// one stream at module scope, so every draw in every test of those files
// depended on how many draws the tests before it had made: a test moved,
// renamed or skipped changed the bytes of its neighbours. A stream per test,
// from that test's own seed, makes a failing run replayable on its own.

import { dcaError } from "../../core-shared/errors.js";
import { base64urlEncode } from "../../core-shared/codec.js";
import {
  generateEcdsaP256KeyPair,
  generateEcdhKeyPair,
  generateRsaOaepKeyPair,
} from "../../core-shared/cryptoProvider.js";

/**
 * The issuer opening keypair for one algorithm. Both algorithms carry the same
 * 16-byte envelope payload, and which keypair an issuer holds is a deployment
 * choice rather than a wire one.
 *
 * @param {string} [algorithm] - 'ECDH-P256' or 'RSA-OAEP'
 * @param {{ modulusLength?: number, hash?: string }} [rsa] - for the cases where
 *   the modulus or the hash is the subject
 * @returns {Promise<CryptoKeyPair>}
 */
export function issuerKeypair(algorithm = "ECDH-P256", rsa = {}) {
  if (algorithm === "RSA-OAEP") {
    return /** @type {Promise<CryptoKeyPair>} */ (generateRsaOaepKeyPair(rsa));
  }
  return /** @type {Promise<CryptoKeyPair>} */ (generateEcdhKeyPair());
}

/**
 * The publisher's signing keypair.
 *
 * @returns {Promise<CryptoKeyPair>}
 */
export function signingKeypair() {
  return /** @type {Promise<CryptoKeyPair>} */ (generateEcdsaP256KeyPair());
}

/**
 * A key that is nothing but a label: the byte it is filled with is how a test
 * says which key it is looking at.
 *
 * @param {number} fill
 * @returns {Uint8Array}
 */
export function periodKey(fill) {
  return new Uint8Array(16).fill(fill);
}

/**
 * A plain seeded byte stream of a test's own, so its bytes depend on its own
 * seed and on nothing that ran before it. This is the seeded branch of the
 * demo Random actor kept local so reference tests do not reach demo code.
 *
 * @param {number} seed
 * @returns {{ seeded: true, bytes: (n: number) => Uint8Array }}
 */
export function seededRandom(seed) {
  let state = seed | 0;
  const next = () => {
    state = (state + 0x9e3779b9) | 0;
    let word = state ^ (state >>> 16);
    word = Math.imul(word, 0x21f0aaad);
    word ^= word >>> 15;
    word = Math.imul(word, 0x735a2d97);
    return (word ^ (word >>> 15)) >>> 0;
  };

  return {
    seeded: true,
    bytes(n) {
      if (!Number.isInteger(n) || n < 0) {
        throw dcaError("bad_config", `Random.bytes needs a non-negative integer, got ${n}`);
      }

      const out = new Uint8Array(n);
      for (let i = 0; i < n; i += 4) {
        const word = next();
        out[i] = word & 0xff;
        if (i + 1 < n) out[i + 1] = (word >>> 8) & 0xff;
        if (i + 2 < n) out[i + 2] = (word >>> 16) & 0xff;
        if (i + 3 < n) out[i + 3] = (word >>> 24) & 0xff;
      }
      return out;
    },
  };
}

/**
 * Key bytes as they cross a wire.
 *
 * @param {Uint8Array} keyBytes
 * @returns {string}
 */
export function asWire(keyBytes) {
  return base64urlEncode(keyBytes);
}
