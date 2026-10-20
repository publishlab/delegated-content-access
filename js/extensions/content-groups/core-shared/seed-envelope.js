// The 32-byte seed envelope; stock sealed-key width remains 16 bytes. Seal and
// open take the AAD bytes from the caller's binding builder, so one encryption
// and one decryption serve every binding.
import { base64urlEncode } from "../../../core-shared/codec.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { encrypt, decrypt } from "../../../core-shared/aead.js";
import {
  deriveAesGcmKey,
  generateEcdhKeyPair,
  importRawEcdhPublicKey,
} from "../../../core-shared/cryptoProvider.js";
import { CONTRACT, keyBytes } from "./construction.js";

export const ENVELOPE_ALGORITHM = CONTRACT.envelopeAlgorithm;
/** Ephemeral P-256 point (65), nonce (12), ciphertext (32) and tag (16). */
export const ENVELOPE_BYTES = 125;

/** @param {unknown} aad @returns {Uint8Array} */
function checkedAad(aad) {
  if (!(aad instanceof Uint8Array) || aad.length === 0)
    throw new Error("seed envelope AAD is nonempty bytes");
  return Uint8Array.from(aad);
}

/**
 * Seal a 32-byte seed to an issuer's P-256 key: a fresh ephemeral key pair, the
 * raw ECDH x-coordinate as the AES-256-GCM key and a random 12-byte nonce.
 * @param {Uint8Array} seed
 * @param {CryptoKey} issuerPublicKey
 * @param {Uint8Array} aad
 * @returns {Promise<string>} canonical unpadded base64url of the 125-byte envelope
 */
export async function sealSeed(seed, issuerPublicKey, aad) {
  const plaintext = keyBytes(seed, 32, "seed");
  const bound = checkedAad(aad);
  const ephemeral = await generateEcdhKeyPair("P-256");
  const point = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("raw", ephemeral.publicKey),
  );
  if (point.length !== 65 || point[0] !== 4) throw new Error("unexpected P-256 public point");
  const key = await deriveAesGcmKey(issuerPublicKey, ephemeral.privateKey);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const envelope = new Uint8Array(ENVELOPE_BYTES);
  envelope.set(point);
  envelope.set(nonce, 65);
  envelope.set(await encrypt(key, nonce, plaintext, bound, 32), 77);
  return base64urlEncode(envelope);
}

/**
 * Open a seed envelope. A wrong AAD, key or byte fails the GCM tag and rejects
 * with WebCrypto's OperationError.
 * @param {unknown} sealed
 * @param {CryptoKey} issuerPrivateKey
 * @param {Uint8Array} aad
 * @returns {Promise<Uint8Array>} the 32-byte seed
 */
export async function openSeed(sealed, issuerPrivateKey, aad) {
  const envelope = binaryStringBytes(sealed);
  if (!envelope || envelope.length !== ENVELOPE_BYTES || envelope[0] !== 4)
    throw new Error("invalid seed envelope width");
  const bound = checkedAad(aad);
  const point = await importRawEcdhPublicKey(envelope.subarray(0, 65), "P-256");
  const key = await deriveAesGcmKey(point, issuerPrivateKey);
  const seed = await decrypt(key, envelope.subarray(65, 77), envelope.subarray(77), bound, 32);
  return keyBytes(seed, 32, "opened seed");
}
