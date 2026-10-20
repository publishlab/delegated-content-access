// @ts-check
//
// Opens an ECDH P-256 envelope the way an issuer does, so a test can check
// which key a render sealed at a coordinate. The construction is the one in
// docs/spec--sealed-key-envelopes.md, section 4. The first 65 bytes are the
// ephemeral public point, the next 12 are the nonce, and the rest is the
// sealed key and its tag. The 32-byte ECDH x-coordinate is the AES-256-GCM key
// with no KDF, and the BIND string is the additional data.
//
// This uses only Node's Buffer and WebCrypto, not
// `core-shared--publisher-issuer/keySealing.js`. An assertion helper is test
// code, and a strict bridge run would otherwise route that module to the test
// target.

import assert from "node:assert/strict";

const { subtle } = globalThis.crypto;

const POINT_BYTES = 65;
const NONCE_BYTES = 12;
const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };

/**
 * The key inside `envelope`, opened with the issuer's private key at the
 * coordinate `bind` names. A wrong key, point, nonce, KDF or BIND fails the GCM
 * tag, and the call fails an assertion that names the BIND it tried.
 *
 * @param {string} envelope - base64url, as the wire carries it
 * @param {string} bind - the BIND string, such as `dca-bind-key-envelope|c|<renderId>|bodytext`
 * @param {string} privateKeyPem - the issuer's PKCS#8 PEM
 * @returns {Promise<Uint8Array>}
 */
export async function openEcdhEnvelope(envelope, bind, privateKeyPem) {
  const bytes = new Uint8Array(Buffer.from(envelope, "base64url"));
  const der = Buffer.from(
    privateKeyPem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, ""),
    "base64",
  );
  const privateKey = await subtle.importKey("pkcs8", der, ECDH_P256, false, ["deriveBits"]);
  const point = await subtle.importKey("raw", bytes.subarray(0, POINT_BYTES), ECDH_P256, false, []);
  const shared = await subtle.deriveBits({ name: "ECDH", public: point }, privateKey, 256);
  const key = await subtle.importKey("raw", shared, { name: "AES-GCM" }, false, ["decrypt"]);
  /** @type {ArrayBuffer} */
  let opened;
  try {
    opened = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: bytes.subarray(POINT_BYTES, POINT_BYTES + NONCE_BYTES),
        additionalData: new TextEncoder().encode(bind),
      },
      key,
      bytes.subarray(POINT_BYTES + NONCE_BYTES),
    );
  } catch {
    assert.fail(`the envelope does not open at ${bind} under the issuer's private key`);
  }
  return new Uint8Array(opened);
}
