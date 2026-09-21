// @ts-check

// The issuer-only half of the ECDH-P256 client-bound transport method. Shared
// agreement mechanics live beside the client opener; this slice owns the
// response-scoped ephemeral key and every operation that seals key bytes.

import { base64urlEncode } from "../../../core-shared/codec.js";
import { encrypt, NONCE_BYTES } from "../../../core-shared/aead.js";
import { dcaError } from "../../../core-shared/errors.js";
import { METHOD, importPeer, agreeTransport } from "../core-shared--client-issuer/ecdhP256.js";

const { subtle } = globalThis.crypto;

export { METHOD };

/** The one DCA capability width this transport is permitted to carry. */
const DELIVERED_KEY_BYTES = 16;

/**
 * @param {any} clientPublicKey
 * @param {{ ephemeralKeyPair?: CryptoKeyPair }} [options]
 * @returns {Promise<{ transportPublicKey: JsonWebKey, transportKey: CryptoKey }>}
 */
async function clientTransport(clientPublicKey, options = {}) {
  const peer = await importPeer(clientPublicKey, "bad_client_key");
  const ephemeral =
    options.ephemeralKeyPair ??
    (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]));

  const exported = await subtle.exportKey("jwk", ephemeral.publicKey);
  return {
    transportPublicKey: { kty: exported.kty, crv: exported.crv, x: exported.x, y: exported.y },
    transportKey: await agreeTransport(peer, ephemeral.privateKey),
  };
}

/**
 * @param {any} clientPublicKey
 * @param {{ random?: { bytes: (n: number) => Uint8Array }, ephemeralKeyPair?: CryptoKeyPair }} [options]
 * @returns {Promise<{ transport: { publicKey: JsonWebKey }, wrap: (keyBytes: Uint8Array) => Promise<{ key: string, nonce: string }> }>}
 */
export async function seal(clientPublicKey, { random, ephemeralKeyPair } = {}) {
  if (!random || typeof random.bytes !== "function") {
    throw dcaError(
      "bad_config",
      "client-bound transport wraps under a nonce per key, so it needs a Random",
    );
  }
  const { transportPublicKey, transportKey } = await clientTransport(clientPublicKey, {
    ephemeralKeyPair,
  });

  return {
    transport: { publicKey: transportPublicKey },
    async wrap(keyBytes) {
      // This public profile seam is also used without KeyDelivery. Refuse
      // a wrong DCA payload before taking a nonce from its Random or
      // encrypting it under the retained AES-256 transport key.
      if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== DELIVERED_KEY_BYTES) {
        throw dcaError(
          "bad_key",
          `client-bound delivery wraps exactly ${DELIVERED_KEY_BYTES}-byte DCA keys`,
        );
      }
      const nonce = random.bytes(NONCE_BYTES);
      return {
        key: base64urlEncode(await encrypt(transportKey, nonce, keyBytes, undefined, 32)),
        nonce: base64urlEncode(nonce),
      };
    },
  };
}
