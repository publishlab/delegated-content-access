// @ts-check
//
// This module wraps the cryptographic operations that DCA asks its runtime to
// perform. The calling modules handle protocol validation and DCA refusal
// mapping; this module only passes those already-validated operations to
// WebCrypto.

const { subtle } = globalThis.crypto;

/** @typedef {Uint8Array|ArrayBuffer} CryptoBytes */

/**
 * WebCrypto receives an ArrayBuffer-backed snapshot, never a view backed by
 * shared memory. `Uint8Array` admits either backing type, while the DOM
 * `BufferSource` contract deliberately does not admit `SharedArrayBuffer`.
 *
 * @param {CryptoBytes} bytes
 * @returns {Uint8Array<ArrayBuffer>}
 */
function webCryptoBytes(bytes) {
  return bytes instanceof Uint8Array ? Uint8Array.from(bytes) : new Uint8Array(bytes.slice(0));
}

/** @param {CryptoBytes} raw @param {KeyUsage[]} usages */
export function importAesGcmKey(raw, usages) {
  return subtle.importKey("raw", webCryptoBytes(raw), { name: "AES-GCM" }, false, usages);
}

/**
 * @param {CryptoBytes} nonce
 * @param {CryptoBytes} [aad]
 * @returns {AesGcmParams}
 */
function aesGcmParams(nonce, aad) {
  /** @type {AesGcmParams} */
  const params = {
    name: "AES-GCM",
    iv: webCryptoBytes(nonce),
    tagLength: 128,
  };
  if (aad !== undefined) {
    params.additionalData = webCryptoBytes(aad);
  }
  return params;
}

/**
 * @param {CryptoKey} key
 * @param {CryptoBytes} nonce
 * @param {CryptoBytes} plaintext
 * @param {CryptoBytes} [aad]
 */
export function aesGcmEncrypt(key, nonce, plaintext, aad) {
  return subtle.encrypt(aesGcmParams(nonce, aad), key, webCryptoBytes(plaintext));
}

/**
 * @param {CryptoKey} key
 * @param {CryptoBytes} nonce
 * @param {CryptoBytes} ciphertext
 * @param {CryptoBytes} [aad]
 */
export function aesGcmDecrypt(key, nonce, ciphertext, aad) {
  return subtle.decrypt(aesGcmParams(nonce, aad), key, webCryptoBytes(ciphertext));
}

/**
 * @param {CryptoKey} wrappingKey
 * @param {CryptoBytes} nonce
 * @param {CryptoBytes} ciphertext
 * @param {CryptoBytes|undefined} aad
 * @param {KeyUsage[]} usages
 * @param {number} unwrappedKeyBytes
 */
export function aesGcmUnwrapKey(wrappingKey, nonce, ciphertext, aad, usages, unwrappedKeyBytes) {
  return subtle.unwrapKey(
    "raw",
    webCryptoBytes(ciphertext),
    wrappingKey,
    aesGcmParams(nonce, aad),
    { name: "AES-GCM", length: unwrappedKeyBytes * 8 },
    false,
    usages,
  );
}

/** @param {CryptoKey} key */
export function exportRawKey(key) {
  return subtle.exportKey("raw", key);
}

/** @param {string} namedCurve */
export function generateEcdhKeyPair(namedCurve = "P-256") {
  return subtle.generateKey({ name: "ECDH", namedCurve }, false, ["deriveBits"]);
}

/** @param {CryptoBytes} raw @param {string} namedCurve */
export function importRawEcdhPublicKey(raw, namedCurve = "P-256") {
  return subtle.importKey("raw", webCryptoBytes(raw), { name: "ECDH", namedCurve }, false, []);
}

/** @param {CryptoKey} publicKey @param {CryptoKey} privateKey */
export async function deriveAesGcmKey(publicKey, privateKey) {
  const shared = await subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  return importAesGcmKey(new Uint8Array(shared), ["encrypt", "decrypt"]);
}

/** @param {{ modulusLength?: number, hash?: string }} [options] */
export function generateRsaOaepKeyPair(options = {}) {
  return subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: options.modulusLength ?? 2048,
      publicExponent: webCryptoBytes(new Uint8Array([1, 0, 1])),
      hash: options.hash ?? "SHA-256",
    },
    false,
    ["encrypt", "decrypt"],
  );
}

/** @param {CryptoKey} publicKey @param {CryptoBytes} plaintext */
export function rsaOaepEncrypt(publicKey, plaintext) {
  return subtle.encrypt({ name: "RSA-OAEP" }, publicKey, webCryptoBytes(plaintext));
}

/** @param {CryptoKey} privateKey @param {CryptoBytes} ciphertext */
export function rsaOaepDecrypt(privateKey, ciphertext) {
  return subtle.decrypt({ name: "RSA-OAEP" }, privateKey, webCryptoBytes(ciphertext));
}

/** Generate an ES256 (ECDSA over P-256) key pair, the only signing-key type DCA uses. */
export function generateEcdsaP256KeyPair() {
  return subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
}

/** @param {CryptoKey} privateKey @param {CryptoBytes} message */
export function es256Sign(privateKey, message) {
  return subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, webCryptoBytes(message));
}

/** @param {CryptoKey} publicKey @param {CryptoBytes} signature @param {CryptoBytes} message */
export function es256Verify(publicKey, signature, message) {
  return subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    webCryptoBytes(signature),
    webCryptoBytes(message),
  );
}

/** @param {CryptoBytes} input */
export function sha256Digest(input) {
  return subtle.digest("SHA-256", webCryptoBytes(input));
}
