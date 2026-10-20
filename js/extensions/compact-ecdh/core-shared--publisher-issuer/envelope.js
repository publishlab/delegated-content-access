// @ts-check
//
// The compact-ECDH publisher-to-issuer envelope of
// docs/spec-profile--compact-ecdh.md Sections 4 and 5:
//
//     0    33 octets   compressed ephemeral point, 02 or 03 || X
//     33   remaining   HPKE ciphertext: the payload and a 16-octet GCM tag
//
// A 16-octet key gives 65 octets and a 32-octet payload 81. The HPKE `info` is
// fixed, the caller's BIND octets are the AAD with nothing added, and the
// caller states the payload width from its own mechanism, never from the blob.
//
// HPKE itself sees only the standard 65-octet `enc`. The publisher compresses
// it after sealing; the issuer recovers it before opening (Section 4.3).
//
// Every failure to open throws `unseal_failed` with one fixed message, the
// code ../../../core-shared--publisher-issuer/keySealing.js uses for a failed
// open. A wrong length, a bad prefix, an invalid point, a changed BIND and a
// failed tag all look the same to the caller, and none leads to another
// procedure (Section 5). Three mistakes outside the blob are reported as such
// instead, before the blob is read: a stated width other than 16 or 32 and an
// issuer key pair off ECDH P-256 (`bad_config`), and an AAD that is not bytes
// (`binding_failed`).

import { generateEcdhKeyPair } from "../../../core-shared/cryptoProvider.js";
import { TAG_BYTES } from "../../../core-shared/aead.js";
import { utf8Encode } from "../../../core-shared/codec.js";
import { dcaError } from "../../../core-shared/errors.js";
import { open as hpkeOpen, sealTranscript } from "./hpke.js";
import { COMPRESSED_BYTES, compressP256, decompressP256 } from "./p256Point.js";

/** Section 4.1: the exact HPKE `info` octets. */
export const INFO = utf8Encode("dca-derivation-compact-ecdh");

/** Section 4.2: the payload widths this profile permits. */
export const PAYLOAD_WIDTHS = Object.freeze([16, 32]);

const OPEN_FAILED = "compact ECDH envelope did not open";

/**
 * @param {number} width - 16 or 32
 * @returns {number} 65 or 81
 */
export function envelopeBytes(width) {
  return COMPRESSED_BYTES + width + TAG_BYTES;
}

/**
 * @param {unknown} aad
 * @returns {asserts aad is Uint8Array}
 */
function checkAad(aad) {
  if (!(aad instanceof Uint8Array)) {
    throw dcaError("binding_failed", "a compact ECDH envelope binds BIND octets, and none came");
  }
}

/**
 * @param {unknown} payload
 * @returns {asserts payload is Uint8Array}
 */
function checkPayload(payload) {
  if (!(payload instanceof Uint8Array) || !PAYLOAD_WIDTHS.includes(payload.length)) {
    throw dcaError("bad_key", "a compact ECDH envelope carries a 16- or 32-octet payload");
  }
}

/** @param {CryptoKey} key */
function checkIssuerPublicKey(key) {
  const algorithm = /** @type {EcKeyAlgorithm|undefined} */ (key?.algorithm);
  if (algorithm?.name !== "ECDH" || algorithm.namedCurve !== "P-256") {
    throw dcaError("bad_config", "compact ECDH seals to an ECDH P-256 issuer public key");
  }
}

/**
 * The key pair is the issuer's trusted configuration. A pair off ECDH P-256 is
 * its fault, reported before the blob is read, so the client never sees it as
 * a refused blob.
 *
 * @param {CryptoKeyPair} pair
 */
function checkIssuerKeyPair(pair) {
  const algorithm = /** @type {EcKeyAlgorithm|undefined} */ (pair?.privateKey?.algorithm);
  if (algorithm?.name !== "ECDH" || algorithm.namedCurve !== "P-256") {
    throw dcaError("bad_config", "compact ECDH opens with an ECDH P-256 issuer key pair");
  }
  checkIssuerPublicKey(pair.publicKey);
}

/**
 * The envelope under a given ephemeral pair, with the HPKE intermediates.
 * `seal` calls it with a pair it has just generated; the test facility in
 * `testing/` calls it with a recorded pair. No other caller supplies one;
 * ../test/export-surface.test.js fails when another module names it.
 *
 * @param {CryptoKeyPair} ephemeral
 * @param {Uint8Array} payload - 16 or 32 octets
 * @param {CryptoKey} issuerPublicKey - ECDH P-256
 * @param {Uint8Array} aad - the BIND octets
 */
export async function sealEnvelopeTranscript(ephemeral, payload, issuerPublicKey, aad) {
  checkPayload(payload);
  checkAad(aad);
  checkIssuerPublicKey(issuerPublicKey);
  const transcript = await sealTranscript(ephemeral, issuerPublicKey, INFO, aad, payload);
  const compressedEnc = compressP256(transcript.enc);
  const blob = new Uint8Array(compressedEnc.length + transcript.ciphertext.length);
  blob.set(compressedEnc, 0);
  blob.set(transcript.ciphertext, compressedEnc.length);
  return { blob, ...transcript };
}

/**
 * Seals one payload under a fresh ephemeral key pair.
 *
 * @param {Uint8Array} payload - 16 or 32 octets
 * @param {CryptoKey} issuerPublicKey - ECDH P-256
 * @param {Uint8Array} aad - the BIND octets
 * @returns {Promise<Uint8Array>} 65 or 81 octets
 */
export async function seal(payload, issuerPublicKey, aad) {
  // Section 4.1: a fresh ephemeral pair for every envelope. Reusing one
  // repeats the AES key and nonce.
  const ephemeral = await generateEcdhKeyPair();
  return (await sealEnvelopeTranscript(ephemeral, payload, issuerPublicKey, aad)).blob;
}

/**
 * Opens one envelope. The issuer's key pair is needed whole: HPKE's KEM
 * context holds the recipient's public key, and WebCrypto cannot derive it
 * from a non-extractable private key.
 *
 * @param {Uint8Array} blob
 * @param {CryptoKeyPair} issuerKeyPair - the ECDH P-256 private key and its public key
 * @param {Uint8Array} aad - the BIND octets the issuer rebuilt
 * @param {number} width - the payload width the caller's mechanism expects
 * @returns {Promise<Uint8Array>}
 */
export async function open(blob, issuerKeyPair, aad, width) {
  if (!PAYLOAD_WIDTHS.includes(width)) {
    throw dcaError("bad_config", "a compact ECDH payload is 16 or 32 octets wide");
  }
  checkAad(aad);
  checkIssuerKeyPair(issuerKeyPair);

  let plaintext;
  try {
    // Section 4.3: width and prefix are checked here, and the point
    // recovered, before the issuer's private key takes part in anything.
    if (!(blob instanceof Uint8Array) || blob.length !== envelopeBytes(width)) {
      throw new Error("width");
    }
    const enc = decompressP256(blob.subarray(0, COMPRESSED_BYTES));
    if (enc === null) throw new Error("point");
    plaintext = await hpkeOpen(enc, issuerKeyPair, INFO, aad, blob.subarray(COMPRESSED_BYTES));
  } catch {
    // Section 5: one failure, whatever refused the blob.
    throw dcaError("unseal_failed", OPEN_FAILED);
  }
  // The length check above fixes the ciphertext width, so this cannot fail
  // today; the profile states the plaintext width as its own requirement.
  if (plaintext.length !== width) throw dcaError("unseal_failed", OPEN_FAILED);
  return plaintext;
}
