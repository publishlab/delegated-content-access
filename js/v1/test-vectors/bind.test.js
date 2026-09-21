// Replays the recorded bound-carrier vector. The binding behavior around
// generated values remains in test/bind.test.js; this file owns the recorded
// bytes and is selected only by the vector tier.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import * as boundSealing from "../core-shared--publisher-issuer/keySealing.js";
import { bindValue, RENDER_ID_BYTES } from "../core-shared--publisher-issuer/bind.js";
import { decrypt, NONCE_BYTES } from "../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import { refuses } from "../test-lib/helpers/refuses.js";

const { subtle } = globalThis.crypto;
const VECTOR_FILE = fileURLToPath(
  new URL(
    "../../../verification/vectors/v1-alt--bind-on-renderId-and-slot/bind-blobs.json",
    import.meta.url,
  ),
);
const BIND_VECTOR = JSON.parse(readFileSync(VECTOR_FILE, "utf8"));

/** @param {{ publicKeyJwk: any, privateKeyJwk: any }} pair */
async function importEcdh({ publicKeyJwk, privateKeyJwk }) {
  const algorithm = { name: "ECDH", namedCurve: "P-256" };
  return {
    publicKey: await subtle.importKey("jwk", publicKeyJwk, algorithm, true, []),
    privateKey: await subtle.importKey("jwk", privateKeyJwk, algorithm, false, ["deriveBits"]),
  };
}

/** @param {string} base64url */
function pinnedNonce(base64url) {
  const nonce = base64urlDecode(base64url);
  return { bytes: () => nonce };
}

/** Uncompressed P-256 point, the first field of an ECDH blob. */
const EPHEMERAL_BYTES = 65;

/**
 * Take a recorded ECDH blob apart so the no-additionalData control can be
 * checked at the carrier primitive.
 *
 * @param {string} blob
 * @param {CryptoKey} issuerPrivateKey
 */
async function blobAesKey(blob, issuerPrivateKey) {
  const bytes = base64urlDecode(blob);
  const ephemeralPublic = await subtle.importKey(
    "raw",
    bytes.subarray(0, EPHEMERAL_BYTES),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const shared = await subtle.deriveBits(
    { name: "ECDH", public: ephemeralPublic },
    issuerPrivateKey,
    256,
  );

  return {
    key: await subtle.importKey("raw", shared, { name: "AES-GCM" }, false, ["decrypt"]),
    nonce: bytes.subarray(EPHEMERAL_BYTES, EPHEMERAL_BYTES + NONCE_BYTES),
    ciphertext: bytes.subarray(EPHEMERAL_BYTES + NONCE_BYTES),
  };
}

describe("The bound-carrier vector", () => {
  test("the recorded BIND strings are what the grammar builds", () => {
    const { input, expected } = BIND_VECTOR;

    assert.equal(
      BIND_VECTOR.vectorFormat,
      "4",
      "this bound-carrier fixture is not a render vector",
    );
    assert.equal(input.algorithm, "ECDH-P256");
    assert.equal(
      bindValue({ renderId: input.renderId, contentName: input.contentName }),
      expected.bind.content,
    );
    assert.equal(
      bindValue({ renderId: input.renderId, accessGroup: input.accessGroup, t: input.t }),
      expected.bind.period,
    );
    assert.equal(base64urlDecode(input.renderId).length, RENDER_ID_BYTES);
  });

  test("re-sealing the ECDH input reproduces both blobs byte for byte", async () => {
    const { input, expected } = BIND_VECTOR;
    const issuer = await importEcdh(input.ecdh.issuer);

    const contentBlob = await boundSealing.seal(
      base64urlDecode(input.contentKeyBase64url),
      issuer.publicKey,
      "ECDH-P256",
      {
        random: pinnedNonce(input.ecdh.contentNonceBase64url),
        ephemeralKeyPair: await importEcdh(input.ecdh.contentEphemeral),
        binding: { renderId: input.renderId, contentName: input.contentName },
      },
    );
    assert.equal(contentBlob, expected.ecdh.contentBlob);
    assert.equal(base64urlDecode(contentBlob).length, 109);

    const periodBlob = await boundSealing.seal(
      base64urlDecode(input.periodKeyBase64url),
      issuer.publicKey,
      "ECDH-P256",
      {
        random: pinnedNonce(input.ecdh.periodNonceBase64url),
        ephemeralKeyPair: await importEcdh(input.ecdh.periodEphemeral),
        binding: { renderId: input.renderId, accessGroup: input.accessGroup, t: input.t },
      },
    );
    assert.equal(periodBlob, expected.ecdh.periodBlob);
  });

  test("the recorded blobs open under their own slot and under no other", async () => {
    const { input, expected } = BIND_VECTOR;
    const issuer = await importEcdh(input.ecdh.issuer);

    const opened = await boundSealing.open(
      expected.ecdh.contentBlob,
      issuer.privateKey,
      "ECDH-P256",
      {
        binding: { renderId: input.renderId, contentName: input.contentName },
      },
    );
    assert.equal(base64urlEncode(opened), input.contentKeyBase64url);

    await refuses(
      () =>
        boundSealing.open(expected.ecdh.contentBlob, issuer.privateKey, "ECDH-P256", {
          binding: { renderId: input.renderId, contentName: "bodytext" },
        }),
      "unseal_failed",
      "the same blob, rebuilt for another slot",
    );
  });

  test("the RSA blob pins an unseal, and the plaintext is BIND then the key", async () => {
    const { input, expected } = BIND_VECTOR;
    const privateKey = await subtle.importKey(
      "jwk",
      input.rsa.privateKeyJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"],
    );

    assert.equal(
      base64urlDecode(expected.rsa.contentBlob).length,
      256,
      "one modulus wide, whatever it carries",
    );

    const opened = await boundSealing.open(expected.rsa.contentBlob, privateKey, "RSA-OAEP", {
      binding: { renderId: input.renderId, contentName: input.contentName },
    });
    assert.equal(base64urlEncode(opened), input.contentKeyBase64url);

    const plaintext = base64urlDecode(expected.rsa.plaintextBase64url);
    assert.equal(
      new TextDecoder().decode(plaintext.subarray(0, plaintext.length - 16)),
      expected.bind.content,
    );
    assert.equal(
      base64urlEncode(plaintext.subarray(plaintext.length - 16)),
      input.contentKeyBase64url,
    );

    await refuses(
      () =>
        boundSealing.open(expected.rsa.contentBlob, privateKey, "RSA-OAEP", {
          binding: { renderId: input.renderId, contentName: "bodytext" },
        }),
      "unseal_failed",
      "the prefix is checked after the unseal, and it is the whole defence on this carrier",
    );
  });

  test("an unseal supplying no additionalData fails closed", async () => {
    const { input, expected } = BIND_VECTOR;
    const issuer = await importEcdh(input.ecdh.issuer);

    assert.equal(expected.ecdh.unsealWithoutAad.fails, true, "the vector records the expectation");
    assert.equal(expected.ecdh.unsealWithoutAad.reason, "aes-gcm-tag");

    const { key, nonce, ciphertext } = await blobAesKey(
      expected.ecdh.contentBlob,
      issuer.privateKey,
    );
    await assert.rejects(
      () => decrypt(key, nonce, ciphertext, undefined, 32),
      (error) => {
        assert.equal(
          error.name,
          "OperationError",
          "the tag commits the binding, so an unseal that supplies none fails it as aes-gcm-tag",
        );
        return true;
      },
    );

    const bound = utf8Encode(
      bindValue({ renderId: input.renderId, contentName: input.contentName }),
    );
    assert.equal(
      base64urlEncode(await decrypt(key, nonce, ciphertext, bound, 32)),
      input.contentKeyBase64url,
    );

    const opened = await boundSealing.open(
      expected.ecdh.contentBlob,
      issuer.privateKey,
      "ECDH-P256",
      {
        binding: { renderId: input.renderId, contentName: input.contentName },
      },
    );
    assert.equal(base64urlEncode(opened), input.contentKeyBase64url);
  });
});
