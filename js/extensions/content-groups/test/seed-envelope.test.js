import test from "node:test";
import assert from "node:assert/strict";
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

async function issuerKeys() {
  return subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

test("the envelope algorithm and width are the contract's", () => {
  assert.equal(ENVELOPE_ALGORITHM, CONTRACT.envelopeAlgorithm);
  assert.equal(ENVELOPE_ALGORITHM, "ecdh-p256-content-name-seed");
  assert.equal(ENVELOPE_BYTES, 125);
});

test("a seed sealed under a caller AAD opens under the same AAD in the 125-byte layout", async () => {
  const issuer = await issuerKeys();
  const aad = await contentNameSeedAad(BINDING, CHAIN);
  const sealed = await sealSeed(SEED, issuer.publicKey, aad);
  const envelope = Buffer.from(sealed, "base64url");
  assert.equal(envelope.toString("base64url"), sealed);
  assert.equal(envelope.length, 125);
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
  const again = Buffer.from(await sealSeed(SEED, issuer.publicKey, aad), "base64url");
  assert.notDeepEqual(again.subarray(0, 77), envelope.subarray(0, 77), "fresh point and nonce");
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
  for (const at of [70, 100, 124]) {
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
    envelope.subarray(0, 124).toString("base64url"),
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

test("a fixed-scalar, fixed-nonce envelope from node:crypto opens to its seed", async () => {
  // Written by _lib/generate-vectors.mjs with node:crypto ECDH and AES-256-GCM.
  const vector = await fixture("seed-envelope.json");
  const aadVector = await fixture("seed-aad.json");
  const aad = await contentNameSeedAad(aadVector.binding, CHAIN);
  assert.equal(new TextDecoder().decode(aad), vector.aadUtf8);
  const envelope = Buffer.from(vector.envelope, "base64url");
  assert.equal(envelope.length, 125);
  assert.equal(envelope.subarray(0, 65).toString("hex"), vector.ephemeralPublicHex);
  assert.equal(envelope.subarray(65, 77).toString("hex"), vector.nonceHex);
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
