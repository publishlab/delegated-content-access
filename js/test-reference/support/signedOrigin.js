// @ts-check
//
// The delivery origin a render signs, read back from its `resourceJWT`. The
// Sealer origin test asserts it for the reference, and a bridge asserts the
// same thing for a `resourceJWT` another implementation emitted. The expected
// origin always comes from the caller's own fixture, never from the token.
//
// The payload is read here, with Node's own base64url decoder, rather than
// through `core-shared/compactJwt.js`: an assertion helper is test code, and a
// strict bridge run would otherwise route that implementation module to the
// test target as well.

import assert from "node:assert/strict";

/**
 * Asserts that the known test key signed `expectedOrigin` into `resourceJWT`.
 *
 * @param {string} resourceJWT
 * @param {string} expectedOrigin
 * @param {string} publicKeyPem
 */
export async function assertSignedOrigin(resourceJWT, expectedOrigin, publicKeyPem) {
  const segments = resourceJWT.split(".");
  assert.equal(segments.length, 3, "a resourceJWT is a compact JWS of three segments");
  const body = publicKeyPem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
  const key = await crypto.subtle.importKey(
    "spki",
    Buffer.from(body, "base64"),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    Buffer.from(segments[2], "base64url"),
    Buffer.from(`${segments[0]}.${segments[1]}`),
  );
  assert.equal(valid, true, "the resourceJWT has a valid signature from the test key");
  const payloadJson = Buffer.from(segments[1], "base64url").toString("utf8");
  const signedOrigin = JSON.parse(payloadJson).origin;
  assert.equal(signedOrigin, expectedOrigin);
}
