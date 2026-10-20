// @ts-check
//
// Key material a test makes up: a keypair for whichever algorithm is under test,
// a periodKey that is nothing but a label, and seeded, offset and labelled byte
// streams.
//
// `seededRandom` is a factory and not a shared instance. Three files each held
// one stream at module scope, so every draw in every test of those files
// depended on how many draws the tests before it had made: a test moved,
// renamed or skipped changed the bytes of its neighbours. A stream per test,
// from that test's own seed, makes a failing run replayable on its own.

import { createHash } from "node:crypto";

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
 * @param {string} [algorithm] - 'ecdh-p256' or 'rsa-oaep'
 * @param {{ modulusLength?: number, hash?: string }} [rsa] - for the cases where
 *   the modulus or the hash is the subject
 * @returns {Promise<CryptoKeyPair>}
 */
export function issuerKeypair(algorithm = "ecdh-p256", rsa = {}) {
  if (algorithm === "rsa-oaep") {
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

/**
 * Known test key documents, made up once for tests that need the same key
 * material in the reference and in a port. A test that generates its keys
 * cannot hand a port the private half, since the reference keeps it
 * non-extractable. These keys sign and seal test renders and nothing else.
 *
 * The publisher's ECDSA P-256 signing key as a PKCS#8 PEM, and its public
 * half as an SPKI PEM to verify with.
 */
export const TEST_SIGNING_KEY_PKCS8 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7O8VtGxSny/jVf0D
TjDtzhrSwJJXy6MFOcFHjeyM0oihRANCAASG7kcwEmbWL8OZzn5Op+cM+XIGEddc
zLTv8Ed6ieAFYxSThUQ5PCT3TOOlPrnNt+NfuYJdOKomOLim2XmPfmBY
-----END PRIVATE KEY-----
`;

export const TEST_SIGNING_PUBLIC_KEY_SPKI = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhu5HMBJm1i/Dmc5+TqfnDPlyBhHX
XMy07/BHeongBWMUk4VEOTwk90zjpT65zbfjX7mCXTiqJji4ptl5j35gWA==
-----END PUBLIC KEY-----
`;

/**
 * An issuer's ECDH P-256 key pair: the public half as an SPKI PEM for the
 * Sealer setup, and the private half as a PKCS#8 PEM. Only the test opens
 * envelopes with the private half; no Sealer setup ever holds it.
 */
export const TEST_ISSUER_PUBLIC_KEY_SPKI = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuXUf+qgjGmMkv5rRX+wv2KR7RrP5
l7+s8I/QbvWZyrO3bignf8lM4cxuA612rVe0v+TqU2N+C1MeK3e1EfqNNw==
-----END PUBLIC KEY-----
`;

export const TEST_ISSUER_PRIVATE_KEY_PKCS8 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1PNq26z0tUPvH7EZ
FJ8Syb80JxJznmXqtSLnIdlk2m+hRANCAAS5dR/6qCMaYyS/mtFf7C/YpHtGs/mX
v6zwj9Bu9ZnKs7duKCd/yUzhzG4DrXatV7S/5OpTY34LUx4rd7UR+o03
-----END PRIVATE KEY-----
`;

/**
 * A second issuer's RSA-OAEP 2048-bit key pair, in the same two forms: the
 * SPKI PEM for the Sealer setup, and the PKCS#8 PEM only for the test that
 * opens its envelopes.
 */
export const TEST_RSA_ISSUER_PUBLIC_KEY_SPKI = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlCNWfOwpL+mdkVB7YgtC
qoTdyIqdY+knKx+s5rcRBAi1DoSTJM5/Ff2OqJMfsbor5JnsSSnAGHfKx/aV58MS
d98nYPbHurzViKi+CvBJ9ITJUet+uq6A5v6yNeVoY9xXHLldIRHQ2cevfzuyz+HR
iet4Cj6+dnra/+yD7i1sQ0qjw43H9w5QVvTagdV9MHHEWtWCHV1/wF+kPSpUke3X
LfFawIDQN6hCk4JD1rQEMgXwVhmP72CoXDmsEEZoQ8Xs3m9SuNPGwz7XiFHjRpki
yOGV1KAecY5Xqg6WELQanbKrlWtqcnVKeaxm2AiPXR8HmWUBpB6AyEDIWQdqszj+
QQIDAQAB
-----END PUBLIC KEY-----
`;

export const TEST_RSA_ISSUER_PRIVATE_KEY_PKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCUI1Z87Ckv6Z2R
UHtiC0KqhN3Iip1j6ScrH6zmtxEECLUOhJMkzn8V/Y6okx+xuivkmexJKcAYd8rH
9pXnwxJ33ydg9se6vNWIqL4K8En0hMlR6366roDm/rI15Whj3FccuV0hEdDZx69/
O7LP4dGJ63gKPr52etr/7IPuLWxDSqPDjcf3DlBW9NqB1X0wccRa1YIdXX/AX6Q9
KlSR7dct8VrAgNA3qEKTgkPWtAQyBfBWGY/vYKhcOawQRmhDxezeb1K408bDPteI
UeNGmSLI4ZXUoB5xjleqDpYQtBqdsquVa2pydUp5rGbYCI9dHweZZQGkHoDIQMhZ
B2qzOP5BAgMBAAECggEAO1oLMWLnP5iQdmOyA36yd6JjP5F17M1B0a/PtOJc8WpR
rF7mm2UWmudrjFPh63HFW0JmXovZOJRqTQKZXfGUyS1B2EIXlNRKk4XUGorafprj
FCzPqhj3cVVTbm+bCwOBbXNBAlpifJbaVBZFlq+JpgIPJr+rzMl9S/Nlinxtd2no
e4q5vta9+gTvWvvZdJrc72bClLHH8vYH6yWvGThre1GuYyv4IhLRxUaJys96Yf2R
RsKoJ5CoYtgSMgMXP7FJcaML2Usyyu8b9ojd8YyfAN79J2rkYFv1IFqZyT3gACor
pBqXZSx37NQB/GsYqBC1ETrAP8XTN9EQJyNrsAT9BwKBgQDNjo4i3HBBqZ6fUvS1
f9djgecquUCSevxg0PCqws7mzBRwMsmi/VDWJctmY1Al93MIaWPwHCnN6P6LyAU3
UlGPbaOoMIR/hvAv42J6d50P53t5Hoc0oPL/SrVVKmZ/bO1Th9/AGu0bjiQrFFhj
H+FNHzSuHN6J9GmAIKlXacV0/wKBgQC4faGNvQp5gXgqdp5SkEPxYK/2sK2Lys+n
2gJy7zTjY3wTjBQ5TWcFAQIY3cKr19wUNYAnSyQYd5+iYUnwW+31647FMvxSr2g0
ZdUk6wTczK5Z/kmpz6rn2+1AQfefRnPKXT8J2KvrYbeoRLQqHzpzhnXdkBeOm5o/
/BSELtVMvwKBgFzMteiRInDSddUx614hSAkZdVZ5aeh3c4b17SD6b9QMYFHC6/sU
Z7E2QNyJi36Idztd8QtOe6UFQh2zAH/YPxAEjHT66mZ0cez8t9HYPGUYuUqV+K5O
10Vf4ft/9+QhNgeW+PHOdisRgcydE8Y0d0+M/gh46hLX7+UzWaAoFUfbAoGADuW2
Iefd7KnTtjoV1rznf5o7G0Rw/xTFZ9xmzjkaoDHsVve8ulPRucm3DaL6kT3A+7DG
RGYA6CjgrxAEFHCX6n+2652OWm7njzOZ3n1LyziL66Bo+llWh5pusf2hrS7XMsQM
zxK77ynY1rGVisEyyxlUcyure0x9TCVi0rmlZ6kCgYEAm0lGO3rvO82jyDOzoKri
DIzJEOx3ENoCYqn7KukTCYl1cMzu5E1HJ0zxLtWxZ6XWu0Z/V/ks4paV0A+vcQ4a
d/GmE8m0sjhues3aaVzsPLy/LneKqKsmsVD0KrwERL3m0so+O1auvAguJ1M1OibM
CThtmTQ8tXP+ArGgsuENowQ=
-----END PRIVATE KEY-----
`;

/**
 * The random bytes of one render, as one stream the Sealer reads from front to
 * back. Byte `i` is `(fill + i) mod 256`, so every offset of a stream up to 256
 * bytes is distinct and a read that starts at another offset changes every
 * value after it. A test asserts each value the render draws as the slice at
 * the reference's offset, and the stream does not care how a port splits its
 * reads.
 *
 * @param {number} fill
 * @param {number} length
 * @returns {Uint8Array}
 */
export function randomStream(fill, length) {
  return Uint8Array.from({ length }, (_, index) => (fill + index) & 0xff);
}

/**
 * The random bytes of one render, named by a label instead of a first byte.
 * Block `i` is SHA-256 over the label's UTF-8 bytes followed by `i` as a 4-byte
 * big-endian counter, and the stream is the blocks in order, cut to `length`.
 * Distinct labels give unrelated streams, so a case names its stream after
 * itself. A port never sees the label: the test hands it the bytes, as it does
 * those of `randomStream`.
 *
 * @param {string} label
 * @param {number} length
 * @returns {Uint8Array}
 */
export function labelStream(label, length) {
  const stream = new Uint8Array(length);
  for (let block = 0; block * 32 < length; block += 1) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(block);
    const digest = createHash("sha256").update(label, "utf8").update(counter).digest();
    stream.set(digest.subarray(0, Math.min(32, length - block * 32)), block * 32);
  }
  return stream;
}
