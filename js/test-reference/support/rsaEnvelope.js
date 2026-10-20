// @ts-check
//
// Opens an RSA-OAEP envelope the way an issuer does, so a test can check which
// key a render sealed at a coordinate. The construction is the one in
// docs/spec--sealed-key-envelopes.md, section 5: OAEP with SHA-256, MGF1 with
// SHA-256 and an empty label, over the plaintext `BIND || key`. The issuer
// splits the plaintext at the fixed 16-byte key width, and the recovered BIND
// must equal the expected one in full.
//
// This uses only Node's Buffer and WebCrypto, for the reason ecdhEnvelope.js
// gives: a strict bridge run would route a reference module to the test target.

import assert from "node:assert/strict";

const { subtle } = globalThis.crypto;

const KEY_BYTES = 16;
const RSA_OAEP_SHA256 = { name: "RSA-OAEP", hash: "SHA-256" };

/**
 * The key inside `envelope`, opened with the issuer's private key at the
 * coordinate `bind` names. A wrong key, hash or padding fails the OAEP
 * decoding, and a wrong BIND or key width fails the comparison. Each failure
 * is an assertion that names the BIND it tried.
 *
 * @param {string} envelope - base64url, as the wire carries it
 * @param {string} bind - the BIND string, such as `dca-bind-key-envelope|c|<renderId>|bodytext`
 * @param {string} privateKeyPem - the issuer's PKCS#8 PEM
 * @returns {Promise<Uint8Array>}
 */
export async function openRsaEnvelope(envelope, bind, privateKeyPem) {
  const der = Buffer.from(
    privateKeyPem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, ""),
    "base64",
  );
  const privateKey = await subtle.importKey("pkcs8", der, RSA_OAEP_SHA256, false, ["decrypt"]);
  /** @type {ArrayBuffer} */
  let opened;
  try {
    opened = await subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      Buffer.from(envelope, "base64url"),
    );
  } catch {
    assert.fail(`the envelope does not open at ${bind} under the issuer's private key`);
  }
  const plaintext = new Uint8Array(opened);
  const expectedBind = new TextEncoder().encode(bind);
  assert.equal(
    plaintext.length,
    expectedBind.length + KEY_BYTES,
    `the plaintext at ${bind} is the BIND and a 16-byte key`,
  );
  assert.equal(
    Buffer.from(plaintext.subarray(0, expectedBind.length)).toString("utf8"),
    bind,
    `the plaintext at ${bind} carries that BIND`,
  );
  return plaintext.subarray(expectedBind.length);
}
