import test from "node:test";
import assert from "node:assert/strict";
import { createDecipheriv, createECDH } from "node:crypto";
import { readFile } from "node:fs/promises";
import { CONTRACT, contentNameSeedAad } from "../core-shared/construction.js";
import {
  ENVELOPE_ALGORITHM,
  ENVELOPE_BYTES,
  openSeed,
  sealSeed,
} from "../core-shared/seed-envelope.js";
import { CHAIN } from "./_lib/chainPort.js";

const subtle = globalThis.crypto.subtle;
const SEED = Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i);
const BINDING = Object.freeze({
  publisher: "https://news.example",
  renderId: "AAECAwQFBgcICQoLDA0ODw",
  issuerName: "issuer",
  contentName: "bodytext",
  windowStartLabel: "261014T1200",
  periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
});

/** @param {string} name */
async function fixture(name) {
  return JSON.parse(await readFile(new URL(`fixtures/${name}`, import.meta.url), "utf8"));
}

const ZERO_NONCE = Buffer.alloc(12);

// Extractable, so the node:crypto opener below can run the agreement itself.
async function issuerKeys() {
  return subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

/**
 * Open `ciphertext || tag` with node:crypto alone: the raw ECDH x-coordinate as
 * the AES-256-GCM key and the nonce the caller names. It shares no code with
 * openSeed, so it checks the layout instead of repeating it.
 * @param {CryptoKey} privateKey @param {Uint8Array} point @param {Uint8Array} nonce
 * @param {Uint8Array} sealed @param {Uint8Array} aad
 */
async function nodeOpen(privateKey, point, nonce, sealed, aad) {
  const { d } = await subtle.exportKey("jwk", privateKey);
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(/** @type {string} */ (d), "base64url"));
  const decipher = createDecipheriv("aes-256-gcm", ecdh.computeSecret(point), nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(sealed.subarray(-16));
  return Buffer.concat([decipher.update(sealed.subarray(0, -16)), decipher.final()]);
}

test("the envelope algorithm and width are the contract's", () => {
  assert.equal(ENVELOPE_ALGORITHM, CONTRACT.envelopeAlgorithm);
  assert.equal(ENVELOPE_ALGORITHM, "ecdh-p256-content-name-seed");
  assert.equal(ENVELOPE_BYTES, 113);
});

test("a seed sealed under a caller AAD opens under the same AAD in the 113-byte layout", async () => {
  const issuer = await issuerKeys();
  const aad = await contentNameSeedAad(BINDING, CHAIN);
  const sealed = await sealSeed(SEED, issuer.publicKey, aad);
  const envelope = Buffer.from(sealed, "base64url");
  assert.equal(envelope.toString("base64url"), sealed);
  assert.equal(sealed.length, 151);
  assert.equal(envelope.length, 113);
  assert.equal(envelope[0], 4);
  // The first 65 bytes are an importable uncompressed P-256 point.
  await subtle.importKey(
    "raw",
    envelope.subarray(0, 65),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  assert.deepEqual(await openSeed(sealed, issuer.privateKey, aad), SEED);
  // The ciphertext starts right after the point and opens under twelve zero nonce bytes.
  const opened = await nodeOpen(
    issuer.privateKey,
    envelope.subarray(0, 65),
    ZERO_NONCE,
    envelope.subarray(65),
    aad,
  );
  assert.deepEqual(Uint8Array.from(opened), SEED);
  const again = Buffer.from(await sealSeed(SEED, issuer.publicKey, aad), "base64url");
  assert.notDeepEqual(again.subarray(0, 65), envelope.subarray(0, 65), "fresh point per seal");
  assert.notDeepEqual(again.subarray(65), envelope.subarray(65), "fresh agreement per seal");
});

test("rival seeds at one coordinate seal under distinct points and each opens to its own seed", async () => {
  const issuer = await issuerKeys();
  const aad = await contentNameSeedAad(BINDING, CHAIN);
  const rival = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);
  const first = await sealSeed(SEED, issuer.publicKey, aad);
  const second = await sealSeed(rival, issuer.publicKey, aad);
  const point = (/** @type {string} */ s) => Buffer.from(s, "base64url").subarray(0, 65);
  assert.notDeepEqual(point(first), point(second));
  assert.deepEqual(await openSeed(first, issuer.privateKey, aad), SEED);
  assert.deepEqual(await openSeed(second, issuer.privateKey, aad), rival);
});

test("opening refuses another AAD, another key and a changed byte with OperationError", async () => {
  const issuer = await issuerKeys();
  const aad = await contentNameSeedAad(BINDING, CHAIN);
  const sealed = await sealSeed(SEED, issuer.publicKey, aad);
  const otherAad = await contentNameSeedAad({ ...BINDING, contentName: "headline" }, CHAIN);
  await assert.rejects(openSeed(sealed, issuer.privateKey, otherAad), { name: "OperationError" });
  await assert.rejects(openSeed(sealed, (await issuerKeys()).privateKey, aad), {
    name: "OperationError",
  });
  // First and last ciphertext byte, first and last tag byte.
  for (const at of [65, 96, 97, 112]) {
    const changed = Buffer.from(sealed, "base64url");
    changed[at] ^= 1;
    await assert.rejects(openSeed(changed.toString("base64url"), issuer.privateKey, aad), {
      name: "OperationError",
    });
  }
});

test("width, prefix, seed and AAD shape are refused before any key work", async () => {
  const issuer = await issuerKeys();
  const aad = await contentNameSeedAad(BINDING, CHAIN);
  const envelope = Buffer.from(await sealSeed(SEED, issuer.publicKey, aad), "base64url");
  for (const bad of [
    envelope.subarray(0, 112).toString("base64url"),
    Buffer.concat([envelope, Buffer.of(0)]).toString("base64url"),
    Buffer.concat([Buffer.of(2), envelope.subarray(1)]).toString("base64url"),
    `${envelope.toString("base64url")}=`,
    42,
  ])
    await assert.rejects(openSeed(bad, issuer.privateKey, aad), /seed envelope/);
  await assert.rejects(sealSeed(SEED.subarray(1), issuer.publicKey, aad), /32 bytes/);
  for (const badAad of [undefined, "aad", new Uint8Array(0)]) {
    await assert.rejects(
      sealSeed(SEED, issuer.publicKey, /** @type {any} */ (badAad)),
      /AAD is nonempty bytes/,
    );
    await assert.rejects(
      openSeed(envelope.toString("base64url"), issuer.privateKey, /** @type {any} */ (badAad)),
      /AAD is nonempty bytes/,
    );
  }
});

test("the former 125-byte carrier is refused for its width, even when its nonce field would open", async () => {
  const issuer = await issuerKeys();
  const aad = await contentNameSeedAad(BINDING, CHAIN);
  const envelope = Buffer.from(await sealSeed(SEED, issuer.publicKey, aad), "base64url");
  // point || nonce || ciphertext || tag, with the zero nonce written out.
  const legacy = Buffer.concat([envelope.subarray(0, 65), ZERO_NONCE, envelope.subarray(65)]);
  assert.equal(legacy.length, 125);
  // Control: a reader of the former layout would recover the seed from these bytes.
  const opened = await nodeOpen(
    issuer.privateKey,
    legacy.subarray(0, 65),
    legacy.subarray(65, 77),
    legacy.subarray(77),
    aad,
  );
  assert.deepEqual(Uint8Array.from(opened), SEED);
  await assert.rejects(
    openSeed(legacy.toString("base64url"), issuer.privateKey, aad),
    /invalid seed envelope width/,
  );
});

test("a fixed-scalar envelope from node:crypto with a literal zero nonce opens to its seed", async () => {
  // Written by _lib/generate-vectors.mjs with node:crypto ECDH and AES-256-GCM.
  const vector = await fixture("seed-envelope.json");
  const aadVector = await fixture("seed-aad.json");
  const aad = await contentNameSeedAad(aadVector.binding, CHAIN);
  assert.equal(new TextDecoder().decode(aad), vector.aadUtf8);
  const envelope = Buffer.from(vector.envelope, "base64url");
  assert.equal(envelope.length, 113);
  assert.equal(vector.envelope.length, 151);
  assert.equal(vector.implicitNonceHex, ZERO_NONCE.toString("hex"));
  assert.equal(envelope.subarray(0, 65).toString("hex"), vector.ephemeralPublicHex);
  assert.equal(envelope.subarray(65).toString("hex"), vector.ciphertextAndTagHex);
  const privateKey = await subtle.importKey(
    "jwk",
    vector.issuerPrivateJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const seed = await openSeed(vector.envelope, privateKey, aad);
  assert.equal(Buffer.from(seed).toString("hex"), vector.seedHex);
  const otherAad = await contentNameSeedAad({ ...aadVector.binding, issuerName: "other" }, CHAIN);
  await assert.rejects(openSeed(vector.envelope, privateKey, otherAad), {
    name: "OperationError",
  });
});

test("configured seed keys fail as host configuration while a different valid key is an opening failure", async () => {
  const good = await issuerKeys();
  const wrongCurve = await subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, false, [
    "deriveBits",
  ]);
  const rsa = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false,
    ["encrypt", "decrypt"],
  );
  const aad = await contentNameSeedAad(BINDING, CHAIN);
  const sealed = await sealSeed(SEED, good.publicKey, aad);
  for (const key of [wrongCurve.publicKey, rsa.publicKey, good.privateKey]) {
    await assert.rejects(sealSeed(SEED, key, aad), { code: "bad_config" });
  }
  for (const key of [wrongCurve.privateKey, rsa.privateKey, good.publicKey]) {
    await assert.rejects(openSeed(sealed, key, aad), { code: "bad_config" });
  }
  const other = await issuerKeys();
  await assert.rejects(openSeed(sealed, other.privateKey, aad), { name: "OperationError" });
  assert.deepEqual(await openSeed(sealed, good.privateKey, aad), SEED);
});

test("a matching seed key without deriveBits usage is a provisioning fault", async () => {
  const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveKey",
  ]);
  const aad = await contentNameSeedAad(BINDING, CHAIN);
  const sealed = await sealSeed(SEED, pair.publicKey, aad);
  await assert.rejects(openSeed(sealed, pair.privateKey, aad), { code: "bad_config" });
});
