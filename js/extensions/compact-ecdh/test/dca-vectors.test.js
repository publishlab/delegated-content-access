// @ts-check
//
// The recorded DCA compact-ECDH vectors, `vectors/dca-compact-ecdh.json`:
// fixed `info`, BIND octets as AAD, both Y parities for 16- and 32-octet
// payloads, an ECDH x-coordinate with a leading zero octet, and every HPKE
// intermediate. `tools/record-dca-vectors.mjs` recorded them; its provenance
// member says which fields another implementation checked (`goChecked`) and
// which envelopes it sealed (`goSealed`).
//
// Expected bytes come from the file. This test re-derives each key pair from
// its ikm, seals under the recorded ephemeral, compares every field, and
// opens the recorded blob through the production `open`.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { utf8Encode } from "../../../core-shared/codec.js";
import { INFO, open } from "../core-shared--publisher-issuer/envelope.js";
import { decompressP256 } from "../core-shared--publisher-issuer/p256Point.js";
import {
  deriveKeyPair,
  sealEnvelopeWithEphemeral,
} from "../core-shared--publisher-issuer/testing/deterministicHpke.js";

const document = JSON.parse(
  readFileSync(new URL("vectors/dca-compact-ecdh.json", import.meta.url), "utf8"),
);

/** @param {string} value */
const bytes = (value) => Uint8Array.from(Buffer.from(value, "hex"));
/** @param {Uint8Array} value */
const hex = (value) => Buffer.from(value).toString("hex");

const FIELDS = /** @type {const} */ ([
  "enc",
  "dh",
  "sharedSecret",
  "key",
  "baseNonce",
  "ciphertext",
  "blob",
]);

// One name per check Go made on its own: a name that restates another check
// would read as extra independent evidence.
const GO_CASE_CHECKS = [
  "skEm",
  "enc",
  "blob[0:33]",
  "blob[33:]",
  "decompressed-enc",
  "dh",
  "ciphertext-opens",
  "key-and-nonce-reproduce",
  "flipped-prefix-refused",
];

test("Go's checks are named once each, and the file says what each one did", () => {
  const meaning = document.provenance.goCheckedMeaning;
  assert.deepEqual(document.issuer.goChecked, ["skRm", "pkRm"]);
  for (const c of document.cases) assert.deepEqual(c.goChecked, GO_CASE_CHECKS, c.id);
  for (const name of ["skRm", "pkRm", ...GO_CASE_CHECKS]) {
    assert.equal(typeof meaning[name], "string", name);
  }
  assert.equal(Object.hasOwn(meaning, "sharedSecret"), false, "Go cannot check it");
});

test("the file pins the profile's info octets", () => {
  assert.equal(document.info, hex(INFO));
  assert.deepEqual(bytes(document.info), utf8Encode(document.infoText));
});

test("the cases cover both parities per width and a leading-zero ECDH x", () => {
  const seen = new Set(
    document.cases.map((/** @type {any} */ c) => `${c.payload.length / 2}:${c.blob.slice(0, 2)}`),
  );
  for (const want of ["16:02", "16:03", "32:02", "32:03"]) assert.ok(seen.has(want), want);
  assert.ok(document.cases.some((/** @type {any} */ c) => c.dh.startsWith("00")));
  for (const c of document.cases) {
    assert.equal(c.blob.length / 2, c.payload.length / 2 === 16 ? 65 : 81, c.id);
    assert.deepEqual(bytes(c.aad), utf8Encode(c.aadText), c.id);
  }
});

describe("Node reproduces and opens every recorded case", async () => {
  const issuer = await deriveKeyPair(bytes(document.issuer.ikmR));

  test("the issuer key pair comes from its ikm", () => {
    assert.equal(hex(issuer.skBytes), document.issuer.skRm);
    assert.equal(hex(issuer.pkBytes), document.issuer.pkRm);
  });

  for (const c of document.cases) {
    test(c.id, async () => {
      const ephemeral = await deriveKeyPair(bytes(c.ikmE));
      assert.equal(hex(ephemeral.skBytes), c.skEm);
      const sealed = await sealEnvelopeWithEphemeral(
        ephemeral,
        bytes(c.payload),
        issuer.publicKey,
        bytes(c.aad),
      );
      for (const field of FIELDS) assert.equal(hex(sealed[field]), c[field], field);
      assert.equal(Buffer.from(sealed.blob).toString("base64url"), c.blobBase64url);
      assert.deepEqual(decompressP256(bytes(c.blob).subarray(0, 33)), bytes(c.enc));

      const opened = await open(bytes(c.blob), issuer, bytes(c.aad), c.payload.length / 2);
      assert.equal(hex(opened), c.payload);
    });
  }

  for (const g of document.goSealed) {
    test(`opens the envelope Go sealed: ${g.id}`, async () => {
      assert.deepEqual(
        decompressP256(bytes(g.blob).subarray(0, 33)),
        bytes(g.enc),
        "decompression matches Go's enc",
      );
      const opened = await open(bytes(g.blob), issuer, bytes(g.aad), g.payload.length / 2);
      assert.equal(hex(opened), g.payload);
    });
  }
});
