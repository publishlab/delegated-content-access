// @ts-check
// Provisional construction, not a registered response-binding method.
import { importPeer } from "../../client-bound-transport/core-shared--client-issuer/ecdhP256.js";
import {
  NO_COMPOSED_KINDS,
  keyKindContext,
  kindDescriptor,
} from "../../client-bound-transport/core-shared--client-issuer/keyKind.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { decrypt, decryptToKey } from "../../../core-shared/aead.js";

const { subtle } = globalThis.crypto;
const encoder = new TextEncoder();
const zeroNonce = () => new Uint8Array(12);

/** @param {number} value */
function u32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff)
    throw new Error("unrepresentable framing length");
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

/** @param {Uint8Array[]} parts */
function concat(parts) {
  const result = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/** @param {string} value */
function scalarBytes(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)
  ) {
    throw new Error("kind and path members must be nonempty Unicode scalar strings");
  }
  const bytes = encoder.encode(value);
  return concat([u32(bytes.length), bytes]);
}

/** @param {string} kind @param {readonly string[]} path */
export function entryInfo(kind, path) {
  if (!Array.isArray(path) || path.length === 0)
    throw new Error("a full response entry path is required");
  return concat([
    encoder.encode("dca-derivation-client-bound-entry-key"),
    new Uint8Array(1),
    scalarBytes(kind),
    u32(path.length),
    ...path.map(scalarBytes),
  ]);
}

/** @param {JsonWebKey} publicJwk @param {CryptoKey} privateKey */
export async function agreement(publicJwk, privateKey) {
  const peer = await importPeer(publicJwk, "bad_response");
  // Same deriveKey-to-HKDF pattern as client-bound-transport's agreeTransport;
  // that exported seam derives one response AES key and cannot supply material.
  return subtle.deriveKey({ name: "ECDH", public: peer }, privateKey, "HKDF", false, ["deriveKey"]);
}

/** @param {CryptoKey} material @param {Uint8Array<ArrayBuffer>} info @param {KeyUsage[]} usages */
export function deriveEntryKey(material, info, usages) {
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

/**
 * @param {{publicKey: JsonWebKey}} transport
 * @param {CryptoKey} clientPrivateKey
 * @param {Readonly<Record<string, Readonly<import("../../client-bound-transport/core-shared--client-issuer/keyKind.js").KindDescriptor>>>} [composedKinds]
 */
export async function open(transport, clientPrivateKey, composedKinds = NO_COMPOSED_KINDS) {
  kindDescriptor("contentKey", composedKinds);
  // importPeer snapshots the admitted point before its first crypto await.
  const material = await agreement(transport?.publicKey, clientPrivateKey);
  return {
    /** @param {any} value @param {KeyUsage[]} usages @param {string} kind @param {readonly string[]} path */
    async open(value, usages, kind, path) {
      const descriptor = kindDescriptor(kind, composedKinds);
      const info = entryInfo(kind, path);
      const aad = keyKindContext(kind, composedKinds);
      const bytes = binaryStringBytes(value?.key);
      if (
        bytes === null ||
        bytes.length !== descriptor.width + 16 ||
        Object.keys(value).some((name) => name !== "key")
      )
        throw new Error("invalid nonce-free entry");
      const requestedUsages = [...usages];
      const key = await deriveEntryKey(
        material,
        info,
        descriptor.open === "raw" ? ["decrypt"] : ["unwrapKey"],
      );
      if (descriptor.open === "raw") return decrypt(key, zeroNonce(), bytes, aad, 32);
      return decryptToKey(key, zeroNonce(), bytes, aad, requestedUsages, 32, descriptor.width);
    },
  };
}
