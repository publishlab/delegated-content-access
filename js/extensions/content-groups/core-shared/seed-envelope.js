// The 32-byte seed envelope; stock sealed-key width remains 16 bytes. Seal and
// open take the AAD bytes from the caller's binding builder, so one encryption
// and one decryption serve every binding.
//
// The AES-GCM nonce is twelve implicit zero bytes and is never carried. That is
// safe only because every seal draws a fresh ephemeral pair, so each agreement,
// and with it each AES key, encrypts exactly one seed. Resending saved bytes is
// not a new encryption; sealing a second seed under one pair would be.
import { base64urlEncode } from "../../../core-shared/codec.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { encrypt, decrypt, NONCE_BYTES } from "../../../core-shared/aead.js";
import {
  deriveAesGcmKey,
  generateEcdhKeyPair,
  importRawEcdhPublicKey,
} from "../../../core-shared/cryptoProvider.js";
import { dcaError } from "../../../core-shared/errors.js";
import { CONTRACT, keyBytes } from "./construction.js";

export const ENVELOPE_ALGORITHM = CONTRACT.envelopeAlgorithm;
/** Ephemeral P-256 point (65), ciphertext (32) and tag (16); no carried nonce. */
export const ENVELOPE_BYTES = 113;

/** @param {unknown} aad @returns {Uint8Array} */
function checkedAad(aad) {
  if (!(aad instanceof Uint8Array) || aad.length === 0)
    throw new Error("seed envelope AAD is nonempty bytes");
  return Uint8Array.from(aad);
}

/** @param {CryptoKey} key @param {"public"|"private"} type */
function checkConfiguredKey(key, type) {
  const algorithm = /** @type {EcKeyAlgorithm|undefined} */ (key?.algorithm);
  if (
    key?.type !== type ||
    algorithm?.name !== "ECDH" ||
    algorithm.namedCurve !== "P-256" ||
    (type === "private" && !key.usages.includes("deriveBits"))
  ) {
    throw dcaError("bad_config", `a seed envelope requires a configured ECDH P-256 ${type} key`);
  }
}

/**
 * Seal a 32-byte seed to an issuer's P-256 key: a fresh ephemeral key pair, the
 * raw ECDH x-coordinate as the AES-256-GCM key and the implicit zero nonce.
 * @param {Uint8Array} seed
 * @param {CryptoKey} issuerPublicKey
 * @param {Uint8Array} aad
 * @returns {Promise<string>} canonical unpadded base64url of the 113-byte envelope
 */
export async function sealSeed(seed, issuerPublicKey, aad) {
  checkConfiguredKey(issuerPublicKey, "public");
  const plaintext = keyBytes(seed, 32, "seed");
  const bound = checkedAad(aad);
  const ephemeral = await generateEcdhKeyPair("P-256");
  const point = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("raw", ephemeral.publicKey),
  );
  if (point.length !== 65 || point[0] !== 4) throw new Error("unexpected P-256 public point");
  const key = await deriveAesGcmKey(issuerPublicKey, ephemeral.privateKey);
  const envelope = new Uint8Array(ENVELOPE_BYTES);
  envelope.set(point);
  envelope.set(await encrypt(key, new Uint8Array(NONCE_BYTES), plaintext, bound, 32), 65);
  return base64urlEncode(envelope);
}

/**
 * Open a seed envelope. Any width but 113 bytes is refused before key work,
 * the former 125-byte carrier with its nonce included: the width selects no
 * layout. A wrong AAD, key or byte fails the GCM tag and rejects with
 * WebCrypto's OperationError.
 * @param {unknown} sealed
 * @param {CryptoKey} issuerPrivateKey
 * @param {Uint8Array} aad
 * @returns {Promise<Uint8Array>} the 32-byte seed
 */
export async function openSeed(sealed, issuerPrivateKey, aad) {
  checkConfiguredKey(issuerPrivateKey, "private");
  const envelope = binaryStringBytes(sealed);
  if (!envelope || envelope.length !== ENVELOPE_BYTES || envelope[0] !== 4)
    throw new Error("invalid seed envelope width");
  const bound = checkedAad(aad);
  const point = await importRawEcdhPublicKey(envelope.subarray(0, 65), "P-256");
  const key = await deriveAesGcmKey(point, issuerPrivateKey);
  const seed = await decrypt(key, new Uint8Array(NONCE_BYTES), envelope.subarray(65), bound, 32);
  return keyBytes(seed, 32, "opened seed");
}
