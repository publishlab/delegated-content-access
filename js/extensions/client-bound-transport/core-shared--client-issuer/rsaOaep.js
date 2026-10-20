// @ts-check
//
// Issuer to client, under client-bound transport, the RSA-OAEP method. The
// sibling of the ECDH-P256 method: the same last hop, wrapping each
// delivered key so its bytes never appear in the client's JavaScript, but
// against the client's RSA public key instead of an agreed ECDH transport.
//
// One key wrapped straight under RSA-OAEP: no ephemeral pair, no agreed
// transport key, no nonce. OAEP randomises its own padding, so an RSA response
// carries no entropy the issuer supplies and cannot be made to repeat; a vector
// pins an open, never a re-seal, the same statement keySealing.js's RSA carrier
// makes. The data format fixes RSA-OAEP to SHA-256.
//
// This module differs from keySealing.js's RSA in what comes out. That module
// opens to bytes through subtle.decrypt, because the issuer unseals a blob a
// publisher handed it. Here the client opens to a non-extractable CryptoKey
// handle through subtle.unwrapKey, because the whole point of client-bound
// transport is that the key never lands in JavaScript. This is therefore its
// own profile rather than a branch of that module. The OAEP label is the
// key-kind context from keyKind.js, so a wrapped key opens only as the kind of the
// section it was written into.

import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { dcaError } from "../../../core-shared/errors.js";
import { NO_COMPOSED_KINDS, keyKindContext, kindDescriptor } from "./keyKind.js";

const { subtle } = globalThis.crypto;

/**
 * This profile's method name. The tag a client-bound response carries so the
 * client can tell an answer meant for it from one meant for another method.
 */
export const METHOD = "RSA-OAEP";

/**
 * The client key requirements this profile owns. The capability validates only
 * key-safety facts common to every profile, then invokes this synchronous hook
 * so an injected profile does not need a capability-side method allowlist.
 *
 * @param {{ privateKey: CryptoKey, publicKey: JsonWebKey }} keyPair
 */
export function validateClientKeyPair({ privateKey, publicKey }) {
  const algorithm = /** @type {any} */ (privateKey).algorithm;
  if (
    algorithm?.name !== "RSA-OAEP" ||
    algorithm.hash?.name !== OAEP_HASH ||
    !Number.isSafeInteger(algorithm.modulusLength) ||
    algorithm.modulusLength < 2048 ||
    publicKey.kty !== "RSA"
  ) {
    throw dcaError(
      "bad_config",
      "an RSA-OAEP client needs an RSA-OAEP SHA-256 private key of at least 2048 bits and public JWK",
    );
  }
  if (!Array.isArray(privateKey.usages) || !privateKey.usages.includes("unwrapKey")) {
    throw dcaError("bad_config", "an RSA-OAEP client private key needs unwrapKey usage");
  }
}

/**
 * Keep the public offer in the RSA profile's compatible JWK form. Unlike the
 * ECDH profile, RSA permits its admitted algorithm, use, extractability, and
 * operation metadata on the request offer.
 * @param {JsonWebKey} publicKey
 * @returns {JsonWebKey}
 */
export function publicKeyForOffer(publicKey) {
  const bad = (/** @type {string} */ why) =>
    dcaError("bad_config", `an RSA-OAEP client offer ${why}`);
  if (
    publicKey.kty !== "RSA" ||
    typeof publicKey.n !== "string" ||
    typeof publicKey.e !== "string"
  ) {
    throw bad("has RSA kty, modulus, and exponent members");
  }
  const positiveInteger = (/** @type {string} */ value, /** @type {string} */ name) => {
    const bytes = binaryStringBytes(value);
    if (bytes === null || bytes.length === 0 || bytes[0] === 0) {
      throw bad(`${name} is not a canonical positive Base64urlUInt`);
    }
    return bytes;
  };
  const modulus = positiveInteger(publicKey.n, "n");
  const exponent = positiveInteger(publicKey.e, "e");
  const modulusBits = (modulus.length - 1) * 8 + 32 - Math.clz32(modulus[0]);
  if (modulusBits < 2048) throw bad("modulus is under 2048 bits");
  if (((exponent.at(-1) ?? 0) & 1) === 0 || (exponent.length === 1 && exponent[0] < 3)) {
    throw bad("exponent is not an odd integer of at least 3");
  }
  if (publicKey.alg !== undefined && publicKey.alg !== "RSA-OAEP-256") {
    throw bad("alg is not RSA-OAEP-256");
  }
  if (publicKey.use !== undefined && publicKey.use !== "enc") throw bad("use is not encryption");
  if (publicKey.ext !== undefined && typeof publicKey.ext !== "boolean") {
    throw bad("ext is not boolean");
  }
  const keyOps = publicKey.key_ops;
  if (
    keyOps !== undefined &&
    (!Array.isArray(keyOps) ||
      keyOps.some((operation) => operation !== "encrypt" && operation !== "wrapKey"))
  ) {
    throw bad("key_ops does not name only RSA-OAEP encryption or wrapping");
  }
  return { ...publicKey, ...(Array.isArray(keyOps) ? { key_ops: [...keyOps] } : {}) };
}

/**
 * Chain results must be opened to 16 key octets for Step and Leaf. An RSA
 * key limited to unwrapKey remains valid for period-key-only delivery, but cannot
 * decrypt a chain key. Called during chain-capable client setup.
 * @param {{ privateKey: CryptoKey }} keyPair
 * @returns {void}
 */
export function assertCanOpenChainKeys({ privateKey }) {
  if (!Array.isArray(privateKey.usages) || !privateKey.usages.includes("decrypt")) {
    throw dcaError("bad_config", "an RSA-OAEP client receiving chain keys needs decrypt usage");
  }
}

/**
 * Every kind that opens to raw bytes, chain keys and composed derivation kinds
 * alike, needs OAEP decrypt beside the unwrapKey the handle kinds use. Called
 * at client setup whenever a raw composed kind is selected.
 * @param {{ privateKey: CryptoKey }} keyPair
 * @returns {void}
 */
export function assertCanOpenRawKeys({ privateKey }) {
  if (!Array.isArray(privateKey.usages) || !privateKey.usages.includes("decrypt")) {
    throw dcaError(
      "bad_config",
      "an RSA-OAEP client receiving raw derivation keys needs decrypt usage",
    );
  }
}

/** The data format fixes RSA-OAEP to SHA-256. */
export const OAEP_HASH = "SHA-256";

/**
 * The client's response-scoped opener. RSA carries no agreed transport, so
 * nothing is read off the transport object here; each delivered value opens
 * directly against the client's private half.
 *
 * @param {any} transport - the transport member the response carried, unused
 * @param {CryptoKey} clientPrivateKey
 * @param {Readonly<Record<string, Readonly<import("./keyKind.js").KindDescriptor>>>} [composedKinds] -
 *   the settled kinds trusted composition added beside the base three
 * @returns {Promise<{ open: (value: any, usages: KeyUsage[], keyKind: string) => Promise<CryptoKey|Uint8Array|null> }>}
 */
export async function open(transport, clientPrivateKey, composedKinds = NO_COMPOSED_KINDS) {
  kindDescriptor("contentKey", composedKinds);
  const modulusLength = /** @type {any} */ (clientPrivateKey).algorithm?.modulusLength;
  if (!Number.isSafeInteger(modulusLength) || modulusLength < 2048) {
    throw dcaError(
      "bad_config",
      "an RSA-OAEP client private key has a modulusLength of at least 2048 bits",
    );
  }
  const expectedCiphertextBytes = Math.ceil(modulusLength / 8);
  return {
    /**
     * @param {any} value - one delivered value, `{ key }`
     * @param {KeyUsage[]} usages - what the opened handle may do; a periodKey
     *   opens with `['unwrapKey']`, a delivered contentKey with `['decrypt']`.
     * @param {string} keyKind - the kind of the admitted section this key
     *   entry was read from, bound as the OAEP label. A raw kind (a chain key,
     *   or a composed derivation kind) is recovered as exactly its width in bytes
     * @returns {Promise<CryptoKey|Uint8Array|null>} the non-extractable
     *   handle or the chain-key bytes
     */
    async open(value, usages, keyKind) {
      const descriptor = kindDescriptor(keyKind, composedKinds);
      const label = keyKindContext(keyKind, composedKinds);
      const wrapped = binaryStringBytes(/** @type {any} */ (value).key);
      if (wrapped === null) {
        throw dcaError(
          "unwrap_failed",
          "a client-bound wrapped key is canonical unpadded base64url",
        );
      }

      if (wrapped.length !== expectedCiphertextBytes) {
        throw dcaError("unwrap_failed", "RSA-OAEP ciphertext has the wrong modulus width");
      }

      try {
        if (descriptor.open === "raw") {
          const opened = new Uint8Array(
            await subtle.decrypt(
              { name: "RSA-OAEP", label },
              clientPrivateKey,
              Uint8Array.from(wrapped),
            ),
          );
          if (opened.length !== descriptor.width) {
            throw dcaError(
              "unwrap_failed",
              `a client-bound ${keyKind} is exactly ${descriptor.width} octets`,
            );
          }
          return opened;
        }
        const opened = await subtle.unwrapKey(
          "raw",
          Uint8Array.from(wrapped),
          clientPrivateKey,
          { name: "RSA-OAEP", label },
          { name: "AES-GCM", length: descriptor.width * 8 },
          false,
          usages,
        );
        const algorithm = /** @type {any} */ (opened).algorithm;
        if (algorithm?.name !== "AES-GCM" || algorithm.length !== descriptor.width * 8) {
          throw dcaError("bad_key", "client-bound delivery recovered a non-AES-128-GCM key");
        }
        return opened;
      } catch {
        // From here, a wrong private key, a blob one modulus too wide or
        // too narrow, a key wrapped for another key kind and a flipped byte
        // all surface as the same OAEP padding failure, the way the ECDH
        // side sees one tag failure.
        throw dcaError("unwrap_failed", "RSA-OAEP unwrap failed: OAEP padding check");
      }
    },
  };
}
