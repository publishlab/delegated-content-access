// @ts-check
// Experimental replacement for the ordinary ECDH carrier, not an adopted suite.
// Copies the ECDH flow and validation from core-shared--publisher-issuer/keySealing.js:
// that module has no carrier-layout seam. The shared crypto operations stay reused.
import { encrypt, decrypt } from "../../../core-shared/aead.js";
import { dcaError } from "../../../core-shared/errors.js";
import {
  generateEcdhKeyPair,
  deriveAesGcmKey,
  exportRawKey,
  importRawEcdhPublicKey,
} from "../../../core-shared/cryptoProvider.js";

/** Local experiment selector only; no profile catalogue registration. */
export const NONCE_FREE_ENVELOPE = "experimental-nonce-free-envelope";

/** @param {CryptoKey} key */
function checkKey(key) {
  const algorithm = /** @type {EcKeyAlgorithm} */ (key?.algorithm);
  if (algorithm?.name !== "ECDH" || algorithm.namedCurve !== "P-256") {
    throw dcaError("bad_config", "nonce-free envelope needs an ECDH P-256 key");
  }
}

/**
 * Generates a fresh independent ephemeral pair internally for every seal.
 * One agreement seals one payload; replaying its bytes does not seal again.
 * @param {Uint8Array} payload - exactly 16 bytes
 * @param {CryptoKey} recipientPublicKey
 * @param {Uint8Array} aad - existing BIND octets, never omitted
 * @returns {Promise<Uint8Array>} uncompressed point (65) + ciphertext/tag (32)
 */
export async function seal(payload, recipientPublicKey, aad) {
  if (!(payload instanceof Uint8Array) || payload.length !== 16) {
    throw dcaError("bad_key", "this envelope carries exactly 16 bytes");
  }
  if (!(aad instanceof Uint8Array) || aad.length === 0) {
    throw dcaError("binding_failed", "existing BIND octets are required");
  }
  checkKey(recipientPublicKey);
  const capturedPayload = Uint8Array.from(payload);
  const capturedAad = Uint8Array.from(aad);
  const ephemeral = await generateEcdhKeyPair();
  const point = new Uint8Array(await exportRawKey(ephemeral.publicKey));
  const key = await deriveAesGcmKey(recipientPublicKey, ephemeral.privateKey);
  const ciphertext = await encrypt(key, new Uint8Array(12), capturedPayload, capturedAad, 32);
  const blob = new Uint8Array(97);
  blob.set(point);
  blob.set(ciphertext, 65);
  return blob;
}

/**
 * @param {Uint8Array} blob
 * @param {CryptoKey} recipientPrivateKey
 * @param {Uint8Array} aad - reconstructed original BIND octets
 * @returns {Promise<Uint8Array>}
 */
export async function open(blob, recipientPrivateKey, aad) {
  checkKey(recipientPrivateKey);
  if (!(aad instanceof Uint8Array) || aad.length === 0) {
    throw dcaError("binding_failed", "existing BIND octets are required");
  }
  if (!(blob instanceof Uint8Array) || blob.length !== 97 || blob[0] !== 4) {
    throw dcaError("unseal_failed", "the experimental envelope does not open");
  }
  const captured = Uint8Array.from(blob);
  const capturedAad = Uint8Array.from(aad);
  try {
    const ephemeral = await importRawEcdhPublicKey(captured.subarray(0, 65));
    const key = await deriveAesGcmKey(ephemeral, recipientPrivateKey);
    return await decrypt(key, new Uint8Array(12), captured.subarray(65), capturedAad, 32);
  } catch (cause) {
    throw Object.assign(dcaError("unseal_failed", "the experimental envelope does not open"), {
      cause,
    });
  }
}
