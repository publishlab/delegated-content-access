// @ts-check
//
// Deterministic HPKE for tests and vector recording, nonconforming on purpose.
// A compact-ECDH publisher generates a fresh ephemeral key pair for every
// envelope (docs/spec-profile--compact-ecdh.md Section 4.1), and the
// production `seal` in `../hpke.js` and `../envelope.js` takes none from its
// caller. Published HPKE vectors and DCA vectors fix the ephemeral key, so
// this module lets a test supply it and read back the intermediates
// (dh, shared_secret, key, base_nonce). No production module imports from
// `testing/`.
//
// `deriveKeyPair` is RFC 9180 Section 7.1.3 DeriveKeyPair for P-256. WebCrypto
// cannot multiply a scalar by the base point directly, so the key pair comes
// from a PKCS#8 import of the bare scalar, which the runtime completes with
// its public point. Node accepts that import; a runtime that does not cannot
// run these vectors.

import { exportRawKey } from "../../../../core-shared/cryptoProvider.js";
import {
  KEM_SUITE_ID,
  labeledExpand,
  labeledExtract,
  openTranscript,
  sealTranscript,
} from "../hpke.js";
import { sealEnvelopeTranscript } from "../envelope.js";

const { subtle } = globalThis.crypto;

/** The P-256 group order n, SEC 2 v2.0 Section 2.4.2. */
const ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** Nsk for P-256. */
const SCALAR_BYTES = 32;

/**
 * PKCS#8 PrivateKeyInfo for id-ecPublicKey on prime256v1, wrapping an RFC 5915
 * ECPrivateKey that holds only the 32-octet scalar. The scalar follows the
 * prefix.
 */
const PKCS8_P256_PREFIX = Uint8Array.from([
  0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
  0x01, 0x04, 0x20,
]);

/**
 * @typedef {object} DerivedKeyPair
 * @property {CryptoKey} privateKey - ECDH P-256, `deriveBits`
 * @property {CryptoKey} publicKey
 * @property {Uint8Array} skBytes - SerializePrivateKey, 32 octets
 * @property {Uint8Array} pkBytes - SerializePublicKey, 65 octets uncompressed
 */

/**
 * @param {Uint8Array} bytes
 * @returns {bigint}
 */
function os2ip(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/**
 * The key pair for a known P-256 scalar.
 *
 * @param {Uint8Array} skBytes - 32 octets, 0 < sk < n
 * @returns {Promise<DerivedKeyPair>}
 */
export async function keyPairFromScalar(skBytes) {
  if (skBytes.length !== SCALAR_BYTES) throw new Error("a P-256 scalar is 32 octets");
  const pkcs8 = new Uint8Array(PKCS8_P256_PREFIX.length + SCALAR_BYTES);
  pkcs8.set(PKCS8_P256_PREFIX, 0);
  pkcs8.set(skBytes, PKCS8_P256_PREFIX.length);
  const algorithm = { name: "ECDH", namedCurve: "P-256" };
  const extractable = await subtle.importKey("pkcs8", pkcs8, algorithm, true, ["deriveBits"]);
  const jwk = await subtle.exportKey("jwk", extractable);
  const privateKey = await subtle.importKey("jwk", jwk, algorithm, false, ["deriveBits"]);
  const publicKey = await subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    algorithm,
    true,
    [],
  );
  const pkBytes = new Uint8Array(await exportRawKey(publicKey));
  return { privateKey, publicKey, skBytes: Uint8Array.from(skBytes), pkBytes };
}

/**
 * RFC 9180 Section 7.1.3: DeriveKeyPair for DHKEM(P-256, HKDF-SHA256).
 *
 * @param {Uint8Array} ikm
 * @returns {Promise<DerivedKeyPair>}
 */
export async function deriveKeyPair(ikm) {
  const dkpPrk = await labeledExtract(KEM_SUITE_ID, new Uint8Array(0), "dkp_prk", ikm);
  for (let counter = 0; counter < 256; counter++) {
    const candidate = await labeledExpand(
      KEM_SUITE_ID,
      dkpPrk,
      "candidate",
      Uint8Array.of(counter),
      SCALAR_BYTES,
    );
    // The bitmask for P-256 is 0xff, so no bit of the candidate is cleared.
    const sk = os2ip(candidate);
    if (sk !== 0n && sk < ORDER) return keyPairFromScalar(candidate);
  }
  throw new Error("DeriveKeyPairError");
}

/**
 * One HPKE seal at sequence zero under the given ephemeral pair, with every
 * intermediate.
 *
 * @param {CryptoKeyPair} ephemeral
 * @param {CryptoKey} recipientPublicKey
 * @param {Uint8Array} info
 * @param {Uint8Array} aad
 * @param {Uint8Array} plaintext
 */
export function sealWithEphemeral(ephemeral, recipientPublicKey, info, aad, plaintext) {
  return sealTranscript(ephemeral, recipientPublicKey, info, aad, plaintext);
}

/**
 * One HPKE open at sequence zero, with every intermediate.
 *
 * @param {Uint8Array} enc - 65 octets
 * @param {CryptoKeyPair} recipient
 * @param {Uint8Array} info
 * @param {Uint8Array} aad
 * @param {Uint8Array} ciphertext
 */
export function openWithIntermediates(enc, recipient, info, aad, ciphertext) {
  return openTranscript(enc, recipient, info, aad, ciphertext);
}

/**
 * One compact-ECDH envelope under the given ephemeral pair: the bytes
 * `../envelope.js` `seal` produces when it draws this pair, with every
 * intermediate.
 *
 * @param {CryptoKeyPair} ephemeral
 * @param {Uint8Array} payload - 16 or 32 octets
 * @param {CryptoKey} issuerPublicKey
 * @param {Uint8Array} aad - the BIND octets
 */
export function sealEnvelopeWithEphemeral(ephemeral, payload, issuerPublicKey, aad) {
  return sealEnvelopeTranscript(ephemeral, payload, issuerPublicKey, aad);
}
