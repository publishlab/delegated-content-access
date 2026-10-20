// @ts-check

// The issuer-only half of the RSA-OAEP client-bound transport method.

import { base64urlEncode } from "../../../core-shared/codec.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { dcaError } from "../../../core-shared/errors.js";
import { METHOD, OAEP_HASH } from "../core-shared--client-issuer/rsaOaep.js";
import {
  NO_COMPOSED_KINDS,
  keyKindContext,
  kindDescriptor,
} from "../core-shared--client-issuer/keyKind.js";

const { subtle } = globalThis.crypto;

export { METHOD };

/**
 * @param {any} jwk
 * @param {string} code
 * @returns {Promise<CryptoKey>}
 */
async function importPeer(jwk, code) {
  const bad = (/** @type {string} */ why) =>
    dcaError(code, `${why}; an RSA-OAEP public key as JWK is what crosses here`);

  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) throw bad("that is not a JWK");
  const { kty, n, e, alg, use, ext, key_ops: keyOps } = /** @type {any} */ (jwk);
  if (kty !== "RSA") throw bad(`kty ${JSON.stringify(kty)}`);
  if (typeof n !== "string" || typeof e !== "string")
    throw bad("the key is a modulus and an exponent, both base64url");
  for (const member of ["d", "p", "q", "dp", "dq", "qi", "oth"]) {
    if (/** @type {any} */ (jwk)[member] !== undefined)
      throw bad(`that carries private RSA member ${member}`);
  }

  // RFC 7518 Base64urlUInt is stricter than the forgiving JWK decoder in
  // WebCrypto: one canonical unpadded spelling of the minimum-length
  // unsigned big-endian integer, never empty and never zero-prefixed.
  const integerBytes = (/** @type {string} */ value, /** @type {string} */ name) => {
    const bytes = binaryStringBytes(value);
    if (bytes === null || bytes.length === 0 || bytes[0] === 0) {
      throw bad(`${name} is not a canonical positive Base64urlUInt`);
    }
    return bytes;
  };
  const modulus = integerBytes(n, "n");
  const exponent = integerBytes(e, "e");

  const modulusBits = (modulus.length - 1) * 8 + 32 - Math.clz32(modulus[0]);
  if (modulusBits < 2048) throw bad("the modulus is under 2048 bits");
  if (((exponent.at(-1) ?? 0) & 1) === 0 || (exponent.length === 1 && exponent[0] < 3)) {
    throw bad("the exponent is not an odd integer of at least 3");
  }

  if (alg !== undefined && alg !== "RSA-OAEP-256")
    throw bad(`alg ${JSON.stringify(alg)} is not RSA-OAEP-256`);
  if (use !== undefined && use !== "enc") throw bad(`use ${JSON.stringify(use)} is not encryption`);
  if (ext !== undefined && typeof ext !== "boolean")
    throw bad(`ext ${JSON.stringify(ext)} is not boolean`);
  // An unwrapKey-only pair exports its public half with key_ops: [] in Node.
  // The response-binding contract requires that private capability, but does
  // not require key_ops on the offered public JWK. Nonempty metadata can
  // only advertise the public operations compatible with issuer wrapping.
  if (
    keyOps !== undefined &&
    (!Array.isArray(keyOps) ||
      keyOps.some((operation) => operation !== "encrypt" && operation !== "wrapKey"))
  ) {
    throw bad("key_ops does not name only RSA-OAEP encryption or wrapping");
  }

  let key;
  try {
    // Metadata was admitted above. Import only the public RSA material so
    // runtime-specific JWK policy cannot replace the protocol checks.
    key = await subtle.importKey(
      "jwk",
      { kty, n, e },
      { name: "RSA-OAEP", hash: OAEP_HASH },
      false,
      ["encrypt"],
    );
  } catch {
    throw bad(`the key is not RSA-OAEP over ${OAEP_HASH}`);
  }
  return key;
}

/**
 * @param {any} clientPublicKey
 * @param {{ composedKinds?: Readonly<Record<string, Readonly<import("../core-shared--client-issuer/keyKind.js").KindDescriptor>>> }} [options] -
 *   the settled kinds trusted composition added beside the base kinds
 * @returns {Promise<{ transport: {}, wrap: (keyBytes: Uint8Array, keyKind: string) => Promise<{ key: string }> }>}
 */
export async function seal(clientPublicKey, { composedKinds = NO_COMPOSED_KINDS } = {}) {
  kindDescriptor("contentKey", composedKinds);
  const peer = await importPeer(clientPublicKey, "bad_client_key");

  return {
    transport: {},
    async wrap(keyBytes, keyKind) {
      // KeyDelivery validates its assembled response too, but this is a
      // public profile seam. Do not let a standalone caller produce an
      // OAEP carrier for a retired or AES-192-width DCA capability.
      const { width } = kindDescriptor(keyKind, composedKinds);
      if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== width) {
        throw dcaError("bad_key", `client-bound delivery wraps exactly ${width}-byte DCA keys`);
      }
      // The kind of the section being written, bound as the OAEP label.
      const label = keyKindContext(keyKind, composedKinds);
      const wrapped = await subtle.encrypt(
        { name: "RSA-OAEP", label },
        peer,
        Uint8Array.from(keyBytes),
      );
      return { key: base64urlEncode(new Uint8Array(wrapped)) };
    },
  };
}
