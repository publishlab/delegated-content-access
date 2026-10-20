// @ts-check
//
// Issuer to client, under client-bound transport. This is the sealed-blob
// operation pointed the other way: agree a key with a peer's public half and
// wrap under it, on the same AES-GCM primitive, split out of keySealing.js so
// the two directions are separate modules. The directions differ in what comes
// out. A sealed blob is opened to bytes, because the issuer has to hand
// something over. Client-bound content and period wraps open to a `CryptoKey`
// handle; chain wraps open to bytes needed for the specified expansion.
//
// The ECDH-P256 response-binding method fixes the interoperable transcript in
// docs/spec--response-binding.md: P-256 agreement, HKDF-SHA256 with the
// specified info, and AES-256-GCM with each key-kind context as AAD.
// Content and period keys open to CryptoKey handles; chain keys open to bytes.
// rsaOaep.js supplies the other specified method behind the same interface.

import { utf8Encode } from "../../../core-shared/codec.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { decrypt, decryptToKey } from "../../../core-shared/aead.js";
import { DcaError, dcaError } from "../../../core-shared/errors.js";
import { NO_COMPOSED_KINDS, keyKindContext, kindDescriptor } from "./keyKind.js";

const { subtle } = globalThis.crypto;

/**
 * The response-binding method name carried by an ECDH-P256 response.
 */
export const METHOD = "ECDH-P256";

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
    algorithm?.name !== "ECDH" ||
    algorithm.namedCurve !== "P-256" ||
    publicKey.kty !== "EC" ||
    publicKey.crv !== "P-256"
  ) {
    throw dcaError(
      "bad_config",
      "an ECDH-P256 client needs an ECDH P-256 private key and public JWK",
    );
  }
  if (!Array.isArray(privateKey.usages) || !privateKey.usages.includes("deriveKey")) {
    throw dcaError("bad_config", "an ECDH-P256 client private key needs deriveKey usage");
  }
}

/**
 * Prepare the synchronous public request offer. This checks only the wire
 * fields and coordinate encoding; the trusted key-generation/import boundary
 * owns point and pair validity.
 * @param {JsonWebKey} publicKey
 * @returns {JsonWebKey}
 */
export function publicKeyForOffer(publicKey) {
  if (publicKey.kty !== "EC" || publicKey.crv !== "P-256") {
    throw dcaError("bad_config", "an ECDH-P256 client offer uses EC/P-256");
  }
  const jwk = /** @type {any} */ (publicKey);
  for (const member of ["x", "y"]) {
    const coordinate = jwk[member];
    if (typeof coordinate !== "string") {
      throw dcaError("bad_config", `an ECDH-P256 client offer has a string ${member} coordinate`);
    }
    const bytes = binaryStringBytes(coordinate);
    if (bytes === null || bytes.length !== 32) {
      throw dcaError(
        "bad_config",
        `an ECDH-P256 client offer has a canonical 32-byte ${member} coordinate`,
      );
    }
  }
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

/**
 * ECDH chain keys and period keys use the same derived transport key. The
 * ordinary pair validation already requires deriveKey for both forms.
 * @param {{ privateKey: CryptoKey, publicKey: JsonWebKey }} keyPair
 * @returns {void}
 */
export function assertCanOpenChainKeys(keyPair) {
  validateClientKeyPair(keyPair);
}

/**
 * Any kind that opens to raw bytes (chain keys, and composed derivation kinds)
 * uses the same derived transport key, so deriveKey suffices here too.
 * @param {{ privateKey: CryptoKey, publicKey: JsonWebKey }} keyPair
 * @returns {void}
 */
export function assertCanOpenRawKeys(keyPair) {
  validateClientKeyPair(keyPair);
}

/**
 * The info string the client-bound transport binds its HKDF to. A different
 * context from the sealed blob's, so a shared secret agreed for one is not a
 * key for the other even if the same curve and the same pair were somehow used
 * on both.
 *
 * agreeTransport derives with HKDF rather than using the raw x-coordinate. The
 * sealed blob's format applies no KDF because a publisher and an issuer have to
 * agree on it across implementations.
 * The response-binding specification fixes this separate HKDF transcript
 * for issuer-to-client interoperability.
 */
const CLIENT_TRANSPORT_INFO = "dca-derivation-client-bound-transport";

/**
 * A peer's P-256 public key off the wire. Rebuilt from the four members that
 * describe the point rather than imported as it arrived: `ext` and `key_ops`
 * are the exporting runtime's business, and a key that arrives claiming usages
 * is not a key this side has agreed to.
 *
 * @param {any} jwk
 * @param {string} code - what a caller calls a public key it cannot read
 * @returns {Promise<CryptoKey>}
 */
export async function importPeer(jwk, code) {
  const bad = (/** @type {string} */ why) =>
    dcaError(code, `${why}; a P-256 public key as JWK is what crosses here`);

  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) throw bad("that is not a JWK");
  const { kty, crv, x, y, d } = /** @type {any} */ (jwk);
  if (kty !== "EC" || crv !== "P-256")
    throw bad(`kty ${JSON.stringify(kty)} crv ${JSON.stringify(crv)}`);
  if (typeof x !== "string" || typeof y !== "string")
    throw bad("the point is two base64url coordinates");
  // A private key where a public one belongs is a mistake worth naming: it
  // would otherwise import and work, and nobody would learn that a secret had
  // been sent across.
  if (d !== undefined) throw bad("that carries a private key");

  // WebCrypto accepts several forgiving base64 spellings. The wire profile
  // does not: coordinates are exactly 32 bytes, in the one spelling
  // spec--data-format.md section 2.2 admits, which the shared decoder holds.
  const canonicalCoordinate = (/** @type {string} */ coordinate, /** @type {string} */ name) => {
    const bytes = binaryStringBytes(coordinate);
    if (bytes === null) throw bad(`${name} is not canonical unpadded base64url`);
    if (bytes.length !== 32) throw bad(`${name} must decode to exactly 32 bytes`);
    return coordinate;
  };

  const canonicalX = canonicalCoordinate(x, "x");
  const canonicalY = canonicalCoordinate(y, "y");

  try {
    return await subtle.importKey(
      "jwk",
      { kty, crv, x: canonicalX, y: canonicalY },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
  } catch {
    throw bad("the point is not on P-256");
  }
}

/**
 * The AES key both ends of the transport arrive at. Non-extractable, like
 * everything else in this chain: the client cannot read the transport key
 * either, only use it.
 *
 * @param {CryptoKey} publicKey - the peer's
 * @param {CryptoKey} privateKey - ours
 * @returns {Promise<CryptoKey>}
 */
export async function agreeTransport(publicKey, privateKey) {
  const material = await subtle.deriveKey(
    { name: "ECDH", public: publicKey },
    privateKey,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: Uint8Array.from(utf8Encode(CLIENT_TRANSPORT_INFO)),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt", "unwrapKey"],
  );
}

/**
 * The client's response-scoped opener. Agree the transport once against the
 * client's private half, then open each delivered value to a handle. Requires
 * the transport's public key: a client-bound answer carries the key it was
 * wrapped under, and its absence is a `bad_response`.
 *
 * @param {any} transport - the `{ publicKey }` the response carried
 * @param {CryptoKey} clientPrivateKey
 * @param {Readonly<Record<string, Readonly<import("./keyKind.js").KindDescriptor>>>} [composedKinds] -
 *   the settled kinds trusted composition added beside the base three
 * @returns {Promise<{ open: (value: any, usages: KeyUsage[], keyKind: string) => Promise<CryptoKey|Uint8Array|null> }>}
 */
export async function open(transport, clientPrivateKey, composedKinds = NO_COMPOSED_KINDS) {
  // Refuse an unsettled set before any agreement with the private key.
  kindDescriptor("contentKey", composedKinds);
  const transportPublicKey =
    transport === null || typeof transport !== "object"
      ? undefined
      : /** @type {any} */ (transport).publicKey;
  if (transportPublicKey === undefined) {
    throw dcaError(
      "bad_response",
      "a client-bound answer carries the public key it was wrapped under",
    );
  }
  const transportKey = await transportKeyFor(transportPublicKey, clientPrivateKey);

  return {
    /**
     * @param {any} value - one delivered value, `{ key, nonce }`
     * @param {KeyUsage[]} usages - what the opened handle may do; a periodKey
     *   opens with `['unwrapKey']`, a delivered contentKey with `['decrypt']`.
     * @param {string} keyKind - the kind of the admitted section this key
     *   entry was read from, bound as GCM additional data. A raw kind (a chain
     *   key, or a composed derivation kind) opens to exactly its width in
     *   bytes; the other kinds keep their non-extractable AES handles
     * @returns {Promise<CryptoKey|Uint8Array|null>} the handle, the chain-key bytes,
     *   or null for an
     *   undecodable nonce (an unreadable entry, skipped)
     */
    async open(value, usages, keyKind) {
      const descriptor = kindDescriptor(keyKind, composedKinds);
      const context = keyKindContext(keyKind, composedKinds);
      const nonce = binaryStringBytes(/** @type {any} */ (value).nonce);
      if (nonce === null) return null;
      if (descriptor.open === "raw") {
        const bytes = binaryStringBytes(/** @type {any} */ (value).key);
        if (bytes === null) {
          throw dcaError(
            "unwrap_failed",
            "a client-bound wrapped key is canonical unpadded base64url",
          );
        }
        try {
          const opened = await decrypt(transportKey, nonce, bytes, context, 32);
          if (opened.length !== descriptor.width) {
            throw dcaError(
              "unwrap_failed",
              `a client-bound ${keyKind} is exactly ${descriptor.width} octets`,
            );
          }
          return opened;
        } catch (cause) {
          if (cause instanceof DcaError && cause.code === "unwrap_failed") throw cause;
          throw dcaError("unwrap_failed", "AES-GCM unwrap failed: auth tag mismatch");
        }
      }
      return unwrapKey(
        /** @type {any} */ (value).key,
        transportKey,
        nonce,
        context,
        usages,
        descriptor.width,
      );
    },
  };
}

/**
 * The client's end of the same agreement: the issuer's ephemeral public key out
 * of the response, against the private key this client keeps and cannot read.
 *
 * @param {any} transportPublicKey - the JWK the response carried
 * @param {CryptoKey} clientPrivateKey
 * @returns {Promise<CryptoKey>}
 */
async function transportKeyFor(transportPublicKey, clientPrivateKey) {
  const peer = await importPeer(transportPublicKey, "bad_response");
  return agreeTransport(peer, clientPrivateKey);
}

/**
 * The other side. What comes out is a handle rather than bytes. This decodes
 * the transport blob and hands the bytes to `aead.decryptToKey`, the twin of
 * `aead.decrypt` that opens to a non-extractable `CryptoKey`, so the chain can
 * carry on, a periodKey handle unwrapping a contentKey handle, which decrypts
 * the article. The thin delegate
 * here is the client-bound direction's own, the way `wrapKey` delegates to
 * `aead.encrypt`.
 *
 * @param {string} blob - base64url, as the response carried it
 * @param {CryptoKey} wrappingKey - the transport key, or a periodKey handle
 * @param {Uint8Array} nonce
 * @param {Uint8Array} context - the key-kind context, as GCM additional data
 * @param {KeyUsage[]} usages - passed through to `aead.decryptToKey`: what the
 *   opened handle may do. A periodKey opens with `['unwrapKey']`, a delivered
 *   contentKey with `['decrypt']`.
 * @param {number} width - the kind's key width in octets
 * @returns {Promise<CryptoKey>} AES-GCM of that width, non-extractable
 */
async function unwrapKey(blob, wrappingKey, nonce, context, usages, width) {
  const bytes = binaryStringBytes(blob);
  if (bytes === null) {
    throw dcaError("unwrap_failed", "a client-bound wrapped key is canonical unpadded base64url");
  }

  try {
    return await decryptToKey(wrappingKey, nonce, bytes, context, usages, 32, width);
  } catch {
    // One tag failure again: a body wrapped for another client, a nonce
    // that does not belong to this blob, a key wrapped for another key kind
    // and a flipped byte are the same event from here.
    throw dcaError("unwrap_failed", "AES-GCM unwrap failed: auth tag mismatch");
  }
}
