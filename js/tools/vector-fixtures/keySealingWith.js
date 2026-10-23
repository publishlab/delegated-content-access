// @ts-check
//
// Core's bound seal and open, with the value grammar handed in rather than
// fixed. `core-shared--publisher-issuer/keySealing.js` builds the bound value
// directly from `bindFields`, the same string that `bindValue` returns, and
// exposes no seam to swap it. The grammar is a security decision: the shipped
// core uses one grammar, and BIND stays on the protocol path.
//
// This module lets red-team experiments and fixtures inject an alternate
// grammar by passing the value builder as an argument. For admitted inputs,
// `sealingWith(bindValue)` reproduces the carrier bytes core emits.
//
// It repeats core's bodies rather than reaching into core, because the value
// sits deep inside each carrier: the AES-GCM `additionalData` on one, the OAEP
// plaintext prefix compared whole on the other. Core builds that value from
// its own binding fields before it enters either carrier.

import { base64urlEncode, base64urlDecode, utf8Encode } from "../../core-shared/codec.js";
import { encrypt, decrypt, NONCE_BYTES, TAG_BYTES } from "../../core-shared/aead.js";
import { dcaError } from "../../core-shared/errors.js";

const { subtle } = globalThis.crypto;

/** Uncompressed P-256 point: 0x04 and two 32-byte coordinates. */
const EPHEMERAL_BYTES = 65;

/** The data format fixes RSA-OAEP to SHA-256. */
const OAEP_HASH = "SHA-256";

/** OAEP padding takes a hash length each for seed and label, plus 2. */
const OAEP_OVERHEAD = 2 * 32 + 2;

/** The narrowest RSA modulus the sealed-key specification admits, as in core. */
const RSA_MODULUS_BITS_FLOOR = 2048;

/**
 * The sealed key's width, and so where the binding prefix ends in the RSA
 * plaintext, as in core.
 */
const SEALED_KEY_BYTES = 16;

/**
 * @typedef {object} Binding
 */

/**
 * Core's `checkSupport`, with the value built by the injected grammar. It repeats
 * core's algorithm, binding, `kdf` and `ephemeralKeyPair` refusals. Core's
 * `payloadBytes` refusal and its payload-width and blob-spelling checks are not
 * repeated here.
 *
 * @param {(binding: any) => string} buildValue
 * @param {string} algorithm
 * @param {any} options
 * @returns {{ aad: Uint8Array }}
 */
function checkSupport(buildValue, algorithm, options) {
  if (algorithm !== "ecdh-p256" && algorithm !== "rsa-oaep") {
    throw dcaError("unsupported_algorithm", `keySealing has no ${algorithm} yet`);
  }
  if (options.binding === undefined) {
    throw dcaError(
      "binding_failed",
      "a seal names the coordinate it is for, and this call names none",
    );
  }

  if (options.kdf !== undefined) {
    throw dcaError(
      "unsupported_option",
      "keySealing applies no KDF: the ECDH carrier uses the agreed x-coordinate as the AES key, " +
        "and RSA-OAEP wraps the key",
    );
  }

  const aad = utf8Encode(buildValue(options.binding));

  if (algorithm === "rsa-oaep" && options.ephemeralKeyPair !== undefined) {
    throw dcaError(
      "unsupported_option",
      "ephemeralKeyPair is ECDH only: OAEP draws its padding inside WebCrypto, " +
        "so an RSA seal cannot be made to repeat",
    );
  }
  return { aad };
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
  if (algorithm.modulusLength < RSA_MODULUS_BITS_FLOOR) {
    throw dcaError(
      "bad_config",
      `a sealed-key modulus is at least ${RSA_MODULUS_BITS_FLOOR} bits, and this key is ` +
        `${algorithm.modulusLength}`,
    );
  }

  return algorithm.modulusLength / 8;
}

/**
 * @param {CryptoKey} key
 */
function checkEcdhKey(key) {
  const algorithm = key.algorithm;

  if (algorithm.name !== "ECDH") {
    throw dcaError("bad_config", `ECDH-P256 needs an ECDH key, got ${algorithm.name}`);
  }
  const namedCurve = /** @type {EcKeyAlgorithm} */ (algorithm).namedCurve;
  if (namedCurve !== "P-256") {
    throw dcaError(
      "bad_config",
      `the data format fixes ECDH to P-256; this key uses ${namedCurve}`,
    );
  }
}

/**
 * Byte equality that compares the whole array, as in core.
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function sameBytes(a, b) {
  if (a.length !== b.length) return false;

  let differing = 0;
  for (let i = 0; i < a.length; i++) differing |= a[i] ^ b[i];
  return differing === 0;
}

/**
 * @param {Uint8Array} keyBytes
 * @param {CryptoKey} issuerPublicKey
 * @param {Uint8Array} aad - the binding value, UTF-8
 * @returns {Promise<string>}
 */
async function sealRsa(keyBytes, issuerPublicKey, aad) {
  const width = rsaWidth(issuerPublicKey);
  const capacity = width - OAEP_OVERHEAD;

  if (keyBytes.length !== SEALED_KEY_BYTES) {
    throw dcaError(
      "bad_config",
      `the RSA plaintext puts the binding ahead of a ${SEALED_KEY_BYTES}-byte key, and this key is ` +
        `${keyBytes.length}`,
    );
  }

  const plaintext = new Uint8Array(aad.length + keyBytes.length);
  plaintext.set(aad, 0);
  plaintext.set(keyBytes, aad.length);

  if (plaintext.length > capacity) {
    throw dcaError(
      "bad_config",
      `RSA-OAEP over ${width * 8} bits carries ${capacity} bytes at most, and the binding with the key is ` +
        `${plaintext.length}`,
    );
  }

  return base64urlEncode(await subtle.encrypt({ name: "RSA-OAEP" }, issuerPublicKey, plaintext));
}

/**
 * @param {string} blob
 * @param {CryptoKey} issuerPrivateKey
 * @param {Uint8Array} aad
 * @returns {Promise<Uint8Array>}
 */
async function unsealRsa(blob, issuerPrivateKey, aad) {
  const width = rsaWidth(issuerPrivateKey);
  const bytes = base64urlDecode(blob);

  if (bytes.length !== width) {
    throw dcaError(
      "unseal_failed",
      `sealed blob is ${bytes.length} bytes, not the ${width} this modulus takes`,
    );
  }

  let plaintext;
  try {
    plaintext = new Uint8Array(await subtle.decrypt({ name: "RSA-OAEP" }, issuerPrivateKey, bytes));
  } catch {
    throw dcaError("unseal_failed", "RSA-OAEP unseal failed: OAEP padding check");
  }

  if (
    plaintext.length !== aad.length + SEALED_KEY_BYTES ||
    !sameBytes(plaintext.subarray(0, plaintext.length - SEALED_KEY_BYTES), aad)
  ) {
    throw dcaError(
      "unseal_failed",
      "RSA-OAEP unseal failed: the plaintext is not bound to this coordinate",
    );
  }

  return plaintext.subarray(aad.length);
}

/**
 * The AES-256 key both sides arrive at from one ECDH agreement. Copied from
 * core, which does not export it.
 *
 * @param {CryptoKey} publicKey
 * @param {CryptoKey} privateKey
 * @returns {Promise<CryptoKey>}
 */
async function agree(publicKey, privateKey) {
  const shared = await subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);

  return subtle.importKey("raw", shared, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/**
 * A bound seal/unseal pair over one value grammar. `seal` and `unseal` match
 * core's `seal` and `open` signatures, so the pair drops into the `keySealing`
 * seam wherever core's does.
 *
 * @param {(binding: any) => string} buildValue - how the bound value is built
 * @returns {{
 *   seal: (keyBytes: Uint8Array, publicKey: CryptoKey, algorithm: string, options?: any) => Promise<string>,
 *   unseal: (blob: string, privateKey: CryptoKey, algorithm: string, options?: any) => Promise<Uint8Array>,
 * }}
 */
export function sealingWith(buildValue) {
  /**
   * @param {Uint8Array} keyBytes
   * @param {CryptoKey} issuerPublicKey
   * @param {string} algorithm
   * @param {any} [options]
   * @returns {Promise<string>}
   */
  const seal = async (keyBytes, issuerPublicKey, algorithm, options = {}) => {
    const { aad } = checkSupport(buildValue, algorithm, options);

    if (algorithm === "rsa-oaep") {
      return sealRsa(keyBytes, issuerPublicKey, aad);
    }

    checkEcdhKey(issuerPublicKey);

    const ephemeral =
      options.ephemeralKeyPair ??
      (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]));

    const ephemeralPublic = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
    const nonce = new Uint8Array(NONCE_BYTES);

    const wrappingKey = await agree(issuerPublicKey, ephemeral.privateKey);
    const ciphertext = await encrypt(wrappingKey, nonce, keyBytes, aad, 32);

    const blob = new Uint8Array(ephemeralPublic.length + ciphertext.length);
    blob.set(ephemeralPublic, 0);
    blob.set(ciphertext, ephemeralPublic.length);

    return base64urlEncode(blob);
  };

  /**
   * @param {string} blob
   * @param {CryptoKey} issuerPrivateKey
   * @param {string} algorithm
   * @param {any} [options]
   * @returns {Promise<Uint8Array>}
   */
  const unseal = async (blob, issuerPrivateKey, algorithm, options = {}) => {
    const { aad } = checkSupport(buildValue, algorithm, options);

    if (algorithm === "rsa-oaep") {
      return unsealRsa(blob, issuerPrivateKey, aad);
    }

    const bytes = base64urlDecode(blob);
    // A minimum, not an exact width: fixtures seal attack payloads longer than one key.
    if (bytes.length < EPHEMERAL_BYTES + TAG_BYTES) {
      throw dcaError("unseal_failed", `sealed blob too short: ${bytes.length} bytes`);
    }

    const ephemeralPublic = bytes.subarray(0, EPHEMERAL_BYTES);
    const nonce = new Uint8Array(NONCE_BYTES);
    const ciphertext = bytes.subarray(EPHEMERAL_BYTES);

    try {
      const publicKey = await subtle.importKey(
        "raw",
        ephemeralPublic,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        [],
      );
      const wrappingKey = await agree(publicKey, issuerPrivateKey);
      return await decrypt(wrappingKey, nonce, ciphertext, aad, 32);
    } catch {
      throw dcaError("unseal_failed", "ECDH unseal failed: AES-GCM auth tag mismatch");
    }
  };

  return { seal, unseal };
}
