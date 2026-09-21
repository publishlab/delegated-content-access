// @ts-check
// Sibling to base source: js/v1/core-shared--publisher-issuer/keySealing.js
//
// A seal that commits to nothing: the same two carriers, the same blob layouts,
// and no coordinate anywhere in them. It is the shape
// `js/v1/core-shared--publisher-issuer/keySealing.js` had
// before the binding replaced it, kept runnable because every claim this
// variant makes is a comparison against it. A relabel that is refused is only
// interesting beside the same relabel succeeding.
//
// This module serves three controls, and each one needs something different
// from it:
//
//   the relabel     a blob sealed here opens at any coordinate, so the premium
//                   contentKey comes back under a bodytext grant
//   the omission    an issuer that adopted the binding and forgot the carrier
//                   unseals through this, and fails every bound blob it meets
//   the rollover    one keyId taking both shapes is the migration shortcut, and
//                   this is the old shape it keeps taking
//
// It repeats core's bodies rather than reaching into core for them. An empty
// binding value would reproduce the seal side exactly, since AES-GCM over an
// empty additionalData matches AES-GCM over none, and an RSA plaintext with
// nothing ahead of the key holds just the key. The unseal side would still
// differ: core recovers the RSA plaintext and compares its whole head, where
// this recovers whatever OAEP hands back and measures nothing. That difference
// is the point of one of the tests here, so the body has to be the old one
// rather than the new one with its value emptied.
//
// The client-bound transport calls are not repeated. They are the issuer-to-
// client hop, the binding never reached them, and core's are still core's.
//
// This is a frozen pre-spec control kept for the experiments directory, not a
// conforming producer: it is the last `DCA-ECDH-P256` HKDF sealing path in the
// tree, and core refuses a stated `kdf` at every spelling.

import { base64urlEncode, base64urlDecode, utf8Encode } from "../../../core-shared/codec.js";
import { encrypt, decrypt, NONCE_BYTES, TAG_BYTES } from "../../../core-shared/aead.js";
import { dcaError } from "../../../core-shared/errors.js";

const { subtle } = globalThis.crypto;

/** Uncompressed P-256 point: 0x04 and the two 32-byte coordinates. */
const EPHEMERAL_BYTES = 65;

/** The optional HKDF profile's domain-separation string. */
const HKDF_INFO = "DCA-ECDH-P256";

/** The data format fixes RSA-OAEP to SHA-256. */
const OAEP_HASH = "SHA-256";

/** OAEP with SHA-256 costs two hashes and a byte of the modulus. */
const OAEP_OVERHEAD = 2 * 32 + 2;

/**
 * @typedef {'none'|'hkdf'} Kdf
 */

/**
 * @typedef {object} UnboundSealOptions
 * @property {Kdf} [kdf] - ECDH only, refused for RSA-OAEP
 * @property {{ bytes: (n: number) => Uint8Array }} [random] - the ECDH blob nonce
 * @property {CryptoKeyPair} [ephemeralKeyPair] - injectable for a replayed run
 */

/**
 * A `binding` reaches here whenever this module is dropped in behind a seam that
 * supplies one, and it is ignored on purpose: this module stands for code
 * written before the binding existed. Core refuses to ignore an option, and
 * ignoring one here makes the omission a real footgun rather than a
 * configuration error somebody would have caught.
 *
 * @param {string} algorithm
 * @param {UnboundSealOptions} options
 * @returns {Kdf}
 */
function checkSupport(algorithm, options) {
  if (algorithm !== "ECDH-P256" && algorithm !== "RSA-OAEP") {
    throw dcaError("unsupported_algorithm", `keySealing has no ${algorithm} yet`);
  }
  if (algorithm === "RSA-OAEP") {
    if (options.kdf !== undefined) {
      throw dcaError(
        "unsupported_option",
        "kdf is an ECDH question: RSA-OAEP wraps the key and derives nothing",
      );
    }
    if (options.ephemeralKeyPair !== undefined) {
      throw dcaError(
        "unsupported_option",
        "ephemeralKeyPair is ECDH only: OAEP draws its padding inside WebCrypto, " +
          "so an RSA seal cannot be made to repeat",
      );
    }
    return "none";
  }
  const kdf = options.kdf ?? "none";
  if (kdf !== "none" && kdf !== "hkdf") {
    throw dcaError("unsupported_option", `keySealing has no kdf "${kdf}"`);
  }
  return kdf;
}

/**
 * @param {CryptoKey} key
 * @returns {number} the modulus width in bytes, which is the exact blob size
 */
function rsaWidth(key) {
  const algorithm = /** @type {RsaHashedKeyAlgorithm} */ (key.algorithm);

  if (algorithm.name !== "RSA-OAEP") {
    throw dcaError("bad_config", `RSA-OAEP needs an RSA-OAEP key, got ${algorithm.name}`);
  }
  if (algorithm.hash.name !== OAEP_HASH) {
    throw dcaError(
      "bad_config",
      `the data format fixes RSA-OAEP to ${OAEP_HASH}; this key hashes with ${algorithm.hash.name}`,
    );
  }

  return algorithm.modulusLength / 8;
}

/**
 * @param {Uint8Array} keyBytes
 * @param {CryptoKey} issuerPublicKey
 * @returns {Promise<string>}
 */
async function sealRsa(keyBytes, issuerPublicKey) {
  const width = rsaWidth(issuerPublicKey);
  const capacity = width - OAEP_OVERHEAD;

  if (keyBytes.length > capacity) {
    throw dcaError(
      "bad_config",
      `RSA-OAEP over ${width * 8} bits carries ${capacity} bytes at most, got ${keyBytes.length}`,
    );
  }

  return base64urlEncode(await subtle.encrypt({ name: "RSA-OAEP" }, issuerPublicKey, keyBytes));
}

/**
 * Whatever OAEP hands back, with no width asked of it. A bound blob recovers
 * here as the binding value followed by the key, and nothing on this path looks
 * for either. That asymmetry is why a keyId has to be pinned to the shape a
 * blob was sealed under, rather than a reader inspected for it.
 *
 * @param {string} blob
 * @param {CryptoKey} issuerPrivateKey
 * @returns {Promise<Uint8Array>}
 */
async function unsealRsa(blob, issuerPrivateKey) {
  const width = rsaWidth(issuerPrivateKey);
  const bytes = base64urlDecode(blob);

  if (bytes.length !== width) {
    throw dcaError(
      "unseal_failed",
      `sealed blob is ${bytes.length} bytes, not the ${width} this modulus takes`,
    );
  }

  try {
    return new Uint8Array(await subtle.decrypt({ name: "RSA-OAEP" }, issuerPrivateKey, bytes));
  } catch {
    throw dcaError("unseal_failed", "RSA-OAEP unseal failed: OAEP padding check");
  }
}

/**
 * The AES-256 key both sides arrive at from one ECDH agreement. Core's, and
 * repeated here because core does not export it.
 *
 * @param {CryptoKey} publicKey
 * @param {CryptoKey} privateKey
 * @param {Kdf} kdf
 * @returns {Promise<CryptoKey>}
 */
async function agree(publicKey, privateKey, kdf) {
  const shared = await subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);

  if (kdf === "none") {
    return subtle.importKey("raw", shared, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }

  const material = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8Encode(HKDF_INFO) },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * @param {Uint8Array} keyBytes
 * @param {CryptoKey} issuerPublicKey
 * @param {string} algorithm - 'ECDH-P256' or 'RSA-OAEP'
 * @param {UnboundSealOptions} options
 * @returns {Promise<string>} the base64url blob, as it appears on the wire
 */
export async function seal(keyBytes, issuerPublicKey, algorithm, options = {}) {
  const kdf = checkSupport(algorithm, options);

  if (algorithm === "RSA-OAEP") {
    return sealRsa(keyBytes, issuerPublicKey);
  }

  if (!options.random) {
    throw dcaError("missing_random", "an unbound seal needs a Random for the blob nonce");
  }

  const ephemeral =
    options.ephemeralKeyPair ??
    (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]));

  const ephemeralPublic = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
  const nonce = options.random.bytes(NONCE_BYTES);

  const wrappingKey = await agree(issuerPublicKey, ephemeral.privateKey, kdf);
  const ciphertext = await encrypt(wrappingKey, nonce, keyBytes, undefined, 32);

  const blob = new Uint8Array(ephemeralPublic.length + nonce.length + ciphertext.length);
  blob.set(ephemeralPublic, 0);
  blob.set(nonce, ephemeralPublic.length);
  blob.set(ciphertext, ephemeralPublic.length + nonce.length);

  return base64urlEncode(blob);
}

/**
 * @param {string} blob - the base64url string from the wire
 * @param {CryptoKey} issuerPrivateKey
 * @param {string} algorithm - 'ECDH-P256' or 'RSA-OAEP'
 * @param {UnboundSealOptions} options
 * @returns {Promise<Uint8Array>}
 */
export async function unseal(blob, issuerPrivateKey, algorithm, options = {}) {
  const kdf = checkSupport(algorithm, options);

  if (algorithm === "RSA-OAEP") {
    return unsealRsa(blob, issuerPrivateKey);
  }

  const bytes = base64urlDecode(blob);
  if (bytes.length < EPHEMERAL_BYTES + NONCE_BYTES + TAG_BYTES) {
    throw dcaError("unseal_failed", `sealed blob too short: ${bytes.length} bytes`);
  }

  const ephemeralPublic = bytes.subarray(0, EPHEMERAL_BYTES);
  const nonce = bytes.subarray(EPHEMERAL_BYTES, EPHEMERAL_BYTES + NONCE_BYTES);
  const ciphertext = bytes.subarray(EPHEMERAL_BYTES + NONCE_BYTES);

  try {
    const publicKey = await subtle.importKey(
      "raw",
      ephemeralPublic,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const wrappingKey = await agree(publicKey, issuerPrivateKey, kdf);
    return await decrypt(wrappingKey, nonce, ciphertext, undefined, 32);
  } catch {
    // A wrong private key, a bound blob whose AAD this supplies none of,
    // and a flipped byte all land here as one tag failure.
    throw dcaError("unseal_failed", "ECDH unseal failed: AES-GCM auth tag mismatch");
  }
}
