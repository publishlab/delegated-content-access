// @ts-check

// The issuer-only half of the ECDH-P256 client-bound transport method. Shared
// agreement mechanics live beside the client opener; this slice owns the
// response-scoped ephemeral key and every operation that seals key bytes.

import { base64urlEncode } from "../../../core-shared/codec.js";
import { encrypt, NONCE_BYTES } from "../../../core-shared/aead.js";
import { dcaError } from "../../../core-shared/errors.js";
import { METHOD, importPeer, agreeTransport } from "../core-shared--client-issuer/ecdhP256.js";
import {
  NO_COMPOSED_KINDS,
  keyKindContext,
  kindDescriptor,
} from "../core-shared--client-issuer/keyKind.js";

const { subtle } = globalThis.crypto;

export { METHOD };

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
 * @param {{ random?: { bytes: (n: number) => Uint8Array }, ephemeralKeyPair?: CryptoKeyPair, composedKinds?: Readonly<Record<string, Readonly<import("../core-shared--client-issuer/keyKind.js").KindDescriptor>>> }} [options] -
 *   `composedKinds` is the settled set trusted composition added beside the base kinds
 * @returns {Promise<{ transport: { publicKey: JsonWebKey }, wrap: (keyBytes: Uint8Array, keyKind: string) => Promise<{ key: string, nonce: string }> }>}
 */
export async function seal(
  clientPublicKey,
  { random, ephemeralKeyPair, composedKinds = NO_COMPOSED_KINDS } = {},
) {
  kindDescriptor("contentKey", composedKinds);
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
    async wrap(keyBytes, keyKind) {
      // This public profile seam is also used without KeyDelivery. Refuse
      // a wrong DCA payload before taking a nonce from its Random or
      // encrypting it under the retained AES-256 transport key.
      const { width } = kindDescriptor(keyKind, composedKinds);
      if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== width) {
        throw dcaError("bad_key", `client-bound delivery wraps exactly ${width}-byte DCA keys`);
      }
      // The kind of the section being written, bound as GCM additional data.
      const context = keyKindContext(keyKind, composedKinds);
      const nonce = random.bytes(NONCE_BYTES);
      return {
        key: base64urlEncode(await encrypt(transportKey, nonce, keyBytes, context, 32)),
        nonce: base64urlEncode(nonce),
      };
    },
  };
}
