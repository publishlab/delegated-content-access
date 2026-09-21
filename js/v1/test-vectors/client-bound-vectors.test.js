//
// Replays the two versioned issuer-to-client delivery profiles outside the base
// vector set. The ECDH profile seals and opens from injected entropy; RSA-OAEP
// opens its recorded ciphertext only because OAEP's padding seed is internal.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import * as ecdhProfile from "../extensions/client-bound-transport/ecdhP256.js";
import * as rsaProfile from "../extensions/client-bound-transport/rsaOaep.js";
import { encrypt, decrypt } from "../core-shared/aead.js";
import { base64urlDecode } from "../core-shared/codec.js";

const { subtle } = globalThis.crypto;

const ECDH_FILE = fileURLToPath(
  new URL(
    "../../../verification/vectors/v1-profile--client-bound-ecdh-p256/client-bound-ecdh-p256.json",
    import.meta.url,
  ),
);
const RSA_FILE = fileURLToPath(
  new URL(
    "../../../verification/vectors/v1-profile--client-bound-rsa-oaep/client-bound-rsa-oaep.json",
    import.meta.url,
  ),
);

/** @param {string} file */
function vectorAt(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

/** Profile vectors pin the P-256 point, not browser-specific JWK export metadata. */
function p256PublicJwk(jwk) {
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

/** @param {{ publicKeyJwk: JsonWebKey, privateKeyJwk: JsonWebKey }} pair */
async function importEcdhPair(pair) {
  const algorithm = { name: "ECDH", namedCurve: "P-256" };
  return {
    publicKey: await subtle.importKey("jwk", pair.publicKeyJwk, algorithm, true, []),
    privateKey: await subtle.importKey("jwk", pair.privateKeyJwk, algorithm, false, ["deriveKey"]),
  };
}

/** The client handle must carry the raw delivery key and never become exportable. */
async function assertHandleCarries(vector, handle) {
  assert.equal(handle.extractable, false, "the client opens a non-extractable key handle");
  assert.equal(handle.algorithm.name, "AES-GCM");
  assert.deepEqual([...handle.usages], ["decrypt"]);
  const nonce = new Uint8Array([1, 3, 3, 7, 9, 9, 2, 5, 8, 4, 6, 0]);
  const plaintext = new Uint8Array([4, 2, 4, 2]);
  const ciphertext = await encrypt(
    base64urlDecode(vector.input.deliveryKeyBase64url),
    nonce,
    plaintext,
  );
  assert.deepEqual(
    await decrypt(handle, nonce, ciphertext),
    plaintext,
    "the handle is the delivered key",
  );
  assert.equal(
    vector.expected.openedKeyBase64url,
    vector.input.deliveryKeyBase64url,
    "the environment recovery value is fixed",
  );
}

test("client-bound ECDH-P256 profile re-seals the wire and opens it", async () => {
  const vector = vectorAt(ECDH_FILE);
  assert.equal(vector.vectorFormat, "profile");
  assert.equal(vector.profile, "client-bound-ecdh-p256/v1");
  assert.deepEqual(Object.keys(vector.expected.transport).sort(), ["method", "mode", "publicKey"]);
  assert.deepEqual(Object.keys(vector.expected.wrappedKey).sort(), ["key", "nonce"]);

  const nonce = base64urlDecode(vector.input.nonceBase64url);
  const sealer = await ecdhProfile.seal(vector.input.client.publicKeyJwk, {
    ephemeralKeyPair: await importEcdhPair(vector.input.issuerEphemeralKeyPair),
    random: {
      bytes: (n) => {
        assert.equal(n, nonce.length);
        return nonce;
      },
    },
  });
  assert.deepEqual(
    {
      publicKey: p256PublicJwk(sealer.transport.publicKey),
      mode: "client-bound",
      method: ecdhProfile.METHOD,
    },
    vector.expected.transport,
    "the injected ephemeral key is the response public key",
  );
  assert.deepEqual(
    await sealer.wrap(base64urlDecode(vector.input.deliveryKeyBase64url)),
    vector.expected.wrappedKey,
    "the injected nonce makes the issuer seal byte-replayable",
  );

  const opener = await ecdhProfile.open(
    sealer.transport,
    (await importEcdhPair(vector.input.client)).privateKey,
  );
  await assertHandleCarries(vector, await opener.open(vector.expected.wrappedKey, ["decrypt"]));
});

test("client-bound RSA-OAEP profile opens its recorded wire without claiming a repeatable seal", async () => {
  const vector = vectorAt(RSA_FILE);
  assert.equal(vector.vectorFormat, "profile");
  assert.equal(vector.profile, "client-bound-rsa-oaep/v1");
  assert.deepEqual(Object.keys(vector.expected.transport).sort(), ["method", "mode"]);
  assert.deepEqual(Object.keys(vector.expected.wrappedKey), ["key"]);

  const privateKey = await subtle.importKey(
    "jwk",
    vector.input.client.privateKeyJwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["unwrapKey"],
  );
  const opener = await rsaProfile.open(vector.expected.transport, privateKey);
  await assertHandleCarries(vector, await opener.open(vector.expected.wrappedKey, ["decrypt"]));
});
