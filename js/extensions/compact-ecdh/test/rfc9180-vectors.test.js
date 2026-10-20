// @ts-check
//
// The fixed suite against the published RFC 9180 vector for exactly
// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM in Base mode.
// `vectors/rfc9180-suite-0010-0001-0002.json` says where the vector comes
// from and how its accumulated value is computed.
//
// The source carries no per-message ciphertext, shared_secret, key or
// base_nonce for this suite. It pins them through enc and through
// `encryptions_accumulated`: 1000 seals on one context, whose ciphertexts
// depend on the key and base_nonce at every sequence number. This test
// derives both keys from their ikm, seals the first message with this
// module, then continues the context's sequence with the key and base_nonce
// the module derived. One wrong octet in either changes the hash.

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { encrypt } from "../../../core-shared/aead.js";
import {
  deriveKeyPair,
  openWithIntermediates,
  sealWithEphemeral,
} from "../core-shared--publisher-issuer/testing/deterministicHpke.js";
import { open } from "../core-shared--publisher-issuer/hpke.js";

const document = JSON.parse(
  readFileSync(new URL("vectors/rfc9180-suite-0010-0001-0002.json", import.meta.url), "utf8"),
);

/** @param {string} hex */
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
/** @param {Uint8Array} value */
const hex = (value) => Buffer.from(value).toString("hex");

/** Go draws aad and plaintext from SHAKE128 over empty input, read as a stream. */
function shakeSource() {
  // 1000 messages, two draws each, at most 256 octets per draw.
  const stream = createHash("shake128", { outputLength: 1000 * 2 * 256 }).digest();
  let offset = 0;
  return () => {
    const n = stream[offset];
    const out = Uint8Array.from(stream.subarray(offset + 1, offset + 1 + n));
    offset += 1 + n;
    return out;
  };
}

/** ComputeNonce, RFC 9180 Section 5.2. */
function nonceAt(/** @type {Uint8Array} */ baseNonce, /** @type {number} */ seq) {
  const nonce = Uint8Array.from(baseNonce);
  for (let i = 0, rest = seq; rest > 0; i++, rest = Math.floor(rest / 256)) {
    nonce[nonce.length - 1 - i] ^= rest & 0xff;
  }
  return nonce;
}

test("the vector file holds exactly the fixed suite in Base mode", () => {
  assert.equal(document.vectors.length, 1);
  const [vector] = document.vectors;
  assert.deepEqual(
    [vector.mode, vector.kem_id, vector.kdf_id, vector.aead_id],
    [0, 0x0010, 0x0001, 0x0002],
  );
});

for (const vector of document.vectors) {
  test("DeriveKeyPair reproduces skRm and pkRm from ikmR", async () => {
    const recipient = await deriveKeyPair(bytes(vector.ikmR));
    assert.equal(hex(recipient.skBytes), vector.skRm);
    assert.equal(hex(recipient.pkBytes), vector.pkRm);
  });

  test("seal reproduces enc and the accumulated ciphertexts; open recovers the plaintext", async () => {
    const recipient = await deriveKeyPair(bytes(vector.ikmR));
    const ephemeral = await deriveKeyPair(bytes(vector.ikmE));
    const info = bytes(vector.info);
    const draw = shakeSource();
    const sink = createHash("shake128", { outputLength: 16 });

    const aad0 = draw();
    const pt0 = draw();
    const sealed = await sealWithEphemeral(ephemeral, recipient.publicKey, info, aad0, pt0);
    assert.equal(hex(sealed.enc), vector.enc);
    assert.equal(sealed.key.length, 32);
    assert.equal(sealed.baseNonce.length, 12);
    sink.update(sealed.ciphertext);

    const opened = await openWithIntermediates(
      sealed.enc,
      recipient,
      info,
      aad0,
      sealed.ciphertext,
    );
    assert.deepEqual(opened.plaintext, pt0);
    for (const name of /** @type {const} */ (["dh", "sharedSecret", "key", "baseNonce"])) {
      assert.deepEqual(opened[name], sealed[name], `the receiver derives the same ${name}`);
    }
    assert.deepEqual(await open(sealed.enc, recipient, info, aad0, sealed.ciphertext), pt0);

    for (let seq = 1; seq < 1000; seq++) {
      const aad = draw();
      const pt = draw();
      sink.update(await encrypt(sealed.key, nonceAt(sealed.baseNonce, seq), pt, aad, 32));
    }
    assert.equal(sink.digest("hex"), vector.encryptions_accumulated);
  });
}
