// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesGcmUnwrapKey,
  deriveAesGcmKey,
  es256Sign,
  es256Verify,
  exportRawKey,
  generateEcdhKeyPair,
  generateEcdsaP256KeyPair,
  generateRsaOaepKeyPair,
  importAesGcmKey,
  importRawEcdhPublicKey,
  rsaOaepDecrypt,
  rsaOaepEncrypt,
  sha256Digest,
} from "../../core-shared/cryptoProvider.js";
import { base64urlEncode, utf8Encode } from "../../core-shared/codec.js";

const NONCE = new Uint8Array(12).fill(0x11);

/** @param {CryptoKey} key @param {number} bits @param {KeyUsage[]} usages */
function assertAesGcmKey(key, bits, usages) {
  assert.equal(key.algorithm.name, "AES-GCM");
  assert.equal(key.algorithm.length, bits);
  assert.equal(key.extractable, false);
  assert.deepEqual([...key.usages].sort(), [...usages].sort());
}

test("AES provider operations preserve AAD and create non-extractable handles", async () => {
  const raw = new Uint8Array(16).fill(0x22);
  const key = await importAesGcmKey(raw, ["encrypt", "decrypt"]);
  assertAesGcmKey(key, 128, ["encrypt", "decrypt"]);

  const plaintext = utf8Encode("provider AES");
  const aad = utf8Encode("bound");
  const ciphertext = await aesGcmEncrypt(key, NONCE, plaintext, aad);
  assert.deepEqual(new Uint8Array(await aesGcmDecrypt(key, NONCE, ciphertext, aad)), plaintext);
  await assert.rejects(() => aesGcmDecrypt(key, NONCE, ciphertext, utf8Encode("moved")));
  await assert.rejects(() => exportRawKey(key));
});

test("AES unwrap returns the requested non-extractable key descriptor", async () => {
  const wrapping = await importAesGcmKey(new Uint8Array(16).fill(0x33), ["encrypt", "unwrapKey"]);
  const recoveredRaw = new Uint8Array(16).fill(0x44);
  const carrier = await aesGcmEncrypt(wrapping, NONCE, recoveredRaw);
  const recovered = await aesGcmUnwrapKey(wrapping, NONCE, carrier, undefined, ["decrypt"], 16);

  assertAesGcmKey(recovered, 128, ["decrypt"]);
  await assert.rejects(() => exportRawKey(recovered));
});

test("ECDH P-256 public encoding imports and agrees to usable AES keys", async () => {
  const first = await generateEcdhKeyPair();
  const second = await generateEcdhKeyPair();
  assert.equal(first.privateKey.algorithm.name, "ECDH");
  assert.equal(first.privateKey.algorithm.namedCurve, "P-256");
  assert.equal(first.privateKey.extractable, false);
  assert.deepEqual(first.privateKey.usages, ["deriveBits"]);

  const firstPublicRaw = new Uint8Array(await exportRawKey(first.publicKey));
  const importedFirstPublic = await importRawEcdhPublicKey(firstPublicRaw);
  assert.equal(importedFirstPublic.algorithm.name, "ECDH");
  assert.equal(importedFirstPublic.algorithm.namedCurve, "P-256");
  assert.equal(importedFirstPublic.extractable, false);
  assert.deepEqual(importedFirstPublic.usages, []);

  const firstShared = await deriveAesGcmKey(second.publicKey, first.privateKey);
  const secondShared = await deriveAesGcmKey(importedFirstPublic, second.privateKey);
  assertAesGcmKey(firstShared, 256, ["encrypt", "decrypt"]);
  assertAesGcmKey(secondShared, 256, ["encrypt", "decrypt"]);
  const ciphertext = await aesGcmEncrypt(firstShared, NONCE, utf8Encode("agreed"));
  assert.deepEqual(
    new Uint8Array(await aesGcmDecrypt(secondShared, NONCE, ciphertext)),
    utf8Encode("agreed"),
  );
});

test("RSA-OAEP provider uses 2048-bit SHA-256 keys and preserves native refusal", async () => {
  const pair = await generateRsaOaepKeyPair();
  const other = await generateRsaOaepKeyPair();
  assert.equal(pair.publicKey.algorithm.name, "RSA-OAEP");
  assert.equal(pair.publicKey.algorithm.modulusLength, 2048);
  assert.equal(pair.publicKey.algorithm.hash.name, "SHA-256");
  assert.equal(pair.privateKey.extractable, false);
  assert.deepEqual(pair.publicKey.usages, ["encrypt"]);
  assert.deepEqual(pair.privateKey.usages, ["decrypt"]);

  const plaintext = utf8Encode("RSA provider");
  const ciphertext = await rsaOaepEncrypt(pair.publicKey, plaintext);
  assert.deepEqual(new Uint8Array(await rsaOaepDecrypt(pair.privateKey, ciphertext)), plaintext);
  await assert.rejects(() => rsaOaepDecrypt(other.privateKey, ciphertext));
});

test("ES256 and SHA-256 provider operations use their fixed constructions", async () => {
  const pair = await generateEcdsaP256KeyPair();
  assert.equal(pair.publicKey.algorithm.name, "ECDSA");
  assert.equal(pair.publicKey.algorithm.namedCurve, "P-256");
  assert.equal(pair.privateKey.extractable, false);
  assert.deepEqual(pair.publicKey.usages, ["verify"]);
  assert.deepEqual(pair.privateKey.usages, ["sign"]);

  const message = utf8Encode("signed");
  const signature = new Uint8Array(await es256Sign(pair.privateKey, message));
  assert.equal(await es256Verify(pair.publicKey, signature, message), true);
  assert.equal(await es256Verify(pair.publicKey, signature, utf8Encode("changed")), false);
  assert.equal(
    base64urlEncode(await sha256Digest(utf8Encode("hello"))),
    "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ",
  );
});
