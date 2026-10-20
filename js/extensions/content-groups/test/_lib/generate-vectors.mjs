// Writes the extension's independent fixtures from node:crypto and literal
// transcript text. It imports nothing from the implementation, so a fixture
// checks the implementation instead of repeating it. Run from js/:
//   node extensions/content-groups/test/_lib/generate-vectors.mjs
import { createCipheriv, createECDH, createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";

const fixtures = new URL("../fixtures/", import.meta.url);

/** @param {string} text */
const sha256Hex = (text) => createHash("sha256").update(text, "utf8").digest("hex");

/** @param {URL} url @param {unknown} value */
async function write(url, value) {
  await writeFile(url, `${JSON.stringify(value, null, 2)}\n`);
}

// Seed-envelope AAD: F(["dca-bind-content-name-seed", publisherNamespace, renderId,
// issuerName, contentName, windowStartLabel, chainsPerDay, periodMinutes]).
const binding = {
  publisher: "https://news.example",
  renderId: "AAECAwQFBgcICQoLDA0ODw",
  issuerName: "issuer",
  contentName: "bodytext",
  windowStartLabel: "261014T1200",
  periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
};
const aad =
  `["dca-bind-content-name-seed","${sha256Hex(binding.publisher)}","${binding.renderId}",` +
  `"${binding.issuerName}","${binding.contentName}","${binding.windowStartLabel}",` +
  `${binding.periodGeometry.chainsPerDay},${binding.periodGeometry.periodMinutes}]`;
await write(new URL("seed-aad.json", fixtures), {
  binding,
  expectedAadUtf8: aad,
  expectedAadHex: Buffer.from(aad, "utf8").toString("hex"),
});

// Seed envelope: fixed issuer and ephemeral P-256 scalars and a fixed nonce. The
// AES-256-GCM key is the raw 32-byte ECDH x-coordinate; the envelope is the
// 65-byte ephemeral point, the 12-byte nonce and the 48-byte ciphertext and tag.
const fromHex = (/** @type {string} */ h) => Buffer.from(h, "hex");
const issuer = createECDH("prime256v1");
issuer.setPrivateKey(fromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"));
const ephemeral = createECDH("prime256v1");
ephemeral.setPrivateKey(
  fromHex("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"),
);
const nonce = fromHex("c0c1c2c3c4c5c6c7c8c9cacb");
const seedHex = "d9b1274900e75c2ddcf90b8015ffc87d4bd60eb8b84298d5ec9d57e26223a8f3";
const cipher = createCipheriv("aes-256-gcm", ephemeral.computeSecret(issuer.getPublicKey()), nonce);
cipher.setAAD(Buffer.from(aad, "utf8"));
const sealed = Buffer.concat([
  cipher.update(fromHex(seedHex)),
  cipher.final(),
  cipher.getAuthTag(),
]);
const issuerPoint = issuer.getPublicKey();
await write(new URL("seed-envelope.json", fixtures), {
  issuerPrivateJwk: {
    kty: "EC",
    crv: "P-256",
    d: issuer.getPrivateKey().toString("base64url"),
    x: issuerPoint.subarray(1, 33).toString("base64url"),
    y: issuerPoint.subarray(33, 65).toString("base64url"),
  },
  ephemeralPublicHex: ephemeral.getPublicKey().toString("hex"),
  nonceHex: nonce.toString("hex"),
  aadUtf8: aad,
  seedHex,
  envelope: Buffer.concat([ephemeral.getPublicKey(), nonce, sealed]).toString("base64url"),
});
