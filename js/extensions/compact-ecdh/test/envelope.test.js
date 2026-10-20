// @ts-check
//
// The compact carrier of docs/spec-profile--compact-ecdh.md Sections 4.2, 4.3
// and 5: `compressedEnc (33) || ciphertext`, 65 octets for a 16-octet payload
// and 81 for a 32-octet one, `info` fixed, BIND as AAD. Every failed open
// throws the single `unseal_failed` code with one message, so a caller learns
// nothing about which check refused the blob.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { utf8Encode } from "../../../core-shared/codec.js";
import { DcaError } from "../../../core-shared/errors.js";
import { INFO, open, seal } from "../core-shared--publisher-issuer/envelope.js";
import { compressP256, decompressP256 } from "../core-shared--publisher-issuer/p256Point.js";
import {
  deriveKeyPair,
  openWithIntermediates,
  sealEnvelopeWithEphemeral,
} from "../core-shared--publisher-issuer/testing/deterministicHpke.js";

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

const BIND = utf8Encode("dca-bind-key-envelope|c|AAECAwQFBgcICQoLDA0ODw|bodytext");
const KEY16 = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const SEED32 = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);

/** @returns {Promise<CryptoKeyPair>} */
function issuerKeys() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

/** One failure shape for every refusal. */
let failureMessage = /** @type {string|undefined} */ (undefined);

/**
 * @param {Promise<unknown>} promise
 * @param {string} why
 */
async function refused(promise, why) {
  await assert.rejects(
    promise,
    (error) => {
      assert.ok(error instanceof DcaError, why);
      assert.equal(error.code, "unseal_failed", why);
      failureMessage ??= error.message;
      assert.equal(error.message, failureMessage, `${why}: one message for every refusal`);
      return true;
    },
    why,
  );
}

/**
 * Refused, and before the issuer's private key took part. Section 4.3 checks
 * width and prefix before opening; the refusal alone cannot show the order,
 * because a later tag or width check refuses the same blob.
 *
 * @param {() => Promise<unknown>} run
 * @param {string} why
 */
async function refusedBeforeAgreement(run, why) {
  const { subtle } = globalThis.crypto;
  const held = Object.getOwnPropertyDescriptor(subtle, "deriveBits");
  const real = subtle.deriveBits;
  let count = 0;
  subtle.deriveBits = function (/** @type {any[]} */ ...args) {
    count++;
    return real.apply(this, /** @type {any} */ (args));
  };
  try {
    await refused(run(), why);
  } finally {
    if (held) Object.defineProperty(subtle, "deriveBits", held);
    else delete (/** @type {any} */ (subtle).deriveBits);
  }
  assert.equal(count, 0, `${why}: no key agreement`);
}

/** @param {bigint} x @param {number} prefix */
function compressedX(prefix, x) {
  const out = new Uint8Array(33);
  out[0] = prefix;
  out.set(Buffer.from(x.toString(16).padStart(64, "0"), "hex"), 1);
  return out;
}

/** @param {Uint8Array} blob @param {Uint8Array} head */
function withHead(blob, head) {
  const out = Uint8Array.from(blob);
  out.set(head, 0);
  return out;
}

test("info is exactly the UTF-8 octets of dca-derivation-compact-ecdh", () => {
  assert.deepEqual(INFO, utf8Encode("dca-derivation-compact-ecdh"));
  assert.equal(INFO.length, 27);
});

describe("seal and open", () => {
  for (const [payload, width] of /** @type {const} */ ([
    [KEY16, 65],
    [SEED32, 81],
  ])) {
    test(`a ${payload.length}-octet payload is a ${width}-octet blob that opens`, async () => {
      const issuer = await issuerKeys();
      const blob = await seal(payload, issuer.publicKey, BIND);
      assert.equal(blob.length, width);
      assert.ok(blob[0] === 0x02 || blob[0] === 0x03);
      assert.ok(decompressP256(blob.subarray(0, 33)), "the head is a valid compressed point");
      assert.deepEqual(await open(blob, issuer, BIND, payload.length), payload);
    });
  }

  test("the seal side refuses a payload width other than 16 or 32", async () => {
    const issuer = await issuerKeys();
    for (const width of [0, 15, 17, 24, 31, 33]) {
      await assert.rejects(seal(new Uint8Array(width), issuer.publicKey, BIND), {
        code: "bad_key",
      });
    }
  });

  test("the open side refuses a stated width other than 16 or 32 as configuration", async () => {
    const issuer = await issuerKeys();
    const blob = await seal(KEY16, issuer.publicKey, BIND);
    await assert.rejects(open(blob, issuer, BIND, 24), { code: "bad_config" });
  });

  test("an AAD that is not bytes is a binding fault on either side", async () => {
    const issuer = await issuerKeys();
    const blob = await seal(KEY16, issuer.publicKey, BIND);
    await assert.rejects(seal(KEY16, issuer.publicKey, /** @type {any} */ (undefined)), {
      code: "binding_failed",
    });
    await assert.rejects(open(blob, issuer, /** @type {any} */ ([...BIND]), 16), {
      code: "binding_failed",
    });
  });

  test("the seal side refuses a key that is not ECDH P-256", async () => {
    const p384 = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, false, [
      "deriveBits",
    ]);
    await assert.rejects(seal(KEY16, p384.publicKey, BIND), { code: "bad_config" });
  });
});

describe("every refusal is the one unseal failure", () => {
  test("refusals", async (t) => {
    const issuer = await issuerKeys();
    const other = await issuerKeys();
    const blob16 = await seal(KEY16, issuer.publicKey, BIND);
    const blob32 = await seal(SEED32, issuer.publicKey, BIND);

    // Both points with this x share the ECDH x-coordinate, so only the KEM
    // context (enc || pkRm) tells them apart.
    const flipped = Uint8Array.from(blob16);
    flipped[0] ^= 0x01;
    await refused(open(flipped, issuer, BIND, 16), "prefix flipped between 02 and 03");

    for (const prefix of [0x00, 0x01, 0x04, 0x05, 0xff]) {
      const bad = Uint8Array.from(blob16);
      bad[0] = prefix;
      await refused(open(bad, issuer, BIND, 16), `prefix ${prefix}`);
    }
    await refused(
      open(withHead(blob16, compressedX(0x02, P)), issuer, BIND, 16),
      "x equal to the field prime",
    );
    await refused(
      open(withHead(blob16, compressedX(0x03, (1n << 256n) - 1n)), issuer, BIND, 16),
      "x above the field prime",
    );
    await refused(
      open(withHead(blob16, compressedX(0x02, 1n)), issuer, BIND, 16),
      "x with no square root",
    );
    await refusedBeforeAgreement(
      () => open(blob16.subarray(0, 64), issuer, BIND, 16),
      "one octet short",
    );
    await refusedBeforeAgreement(
      () => open(Uint8Array.from([...blob16, 0]), issuer, BIND, 16),
      "one octet long",
    );
    await refused(open(new Uint8Array(0), issuer, BIND, 16), "empty");
    await refusedBeforeAgreement(
      () => open(blob32, issuer, BIND, 16),
      "a 32-octet payload where 16 is expected",
    );
    await refusedBeforeAgreement(
      () => open(blob16, issuer, BIND, 32),
      "a 16-octet payload where 32 is expected",
    );

    const changedAad = Uint8Array.from(BIND);
    changedAad[changedAad.length - 1] ^= 0x01;
    await refused(open(blob16, issuer, changedAad, 16), "changed AAD");
    await refused(open(blob16, issuer, new Uint8Array(0), 16), "empty AAD");

    for (const index of [33, 48, 64]) {
      const bad = Uint8Array.from(blob16);
      bad[index] ^= 0x80;
      await refused(open(bad, issuer, BIND, 16), `ciphertext bit flipped at ${index}`);
    }
    const xBit = Uint8Array.from(blob16);
    xBit[32] ^= 0x01;
    await refused(open(xBit, issuer, BIND, 16), "x changed");

    await refused(open(blob16, other, BIND, 16), "wrong private key");
    await refused(
      open(blob16, { privateKey: issuer.privateKey, publicKey: other.publicKey }, BIND, 16),
      "the issuer's private key with another public key",
    );
    await refused(
      open(/** @type {any} */ ("not bytes"), issuer, BIND, 16),
      "a blob that is not bytes",
    );
    t.diagnostic(`one message: ${failureMessage}`);
  });
});

test("an issuer key pair off ECDH P-256 is a configuration fault, not a refused blob", async () => {
  const issuer = await deriveKeyPair(utf8Encode("dca compact-ecdh key-type issuer"));
  const blob = await seal(new Uint8Array(16), issuer.publicKey, BIND);
  const p384 = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, false, [
    "deriveBits",
  ]);
  const rsa = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false,
    ["decrypt", "encrypt"],
  );
  const ecdsa = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  for (const [label, pair] of [
    ["P-384 pair", p384],
    ["RSA pair", rsa],
    ["P-384 private key", { privateKey: p384.privateKey, publicKey: issuer.publicKey }],
    ["ECDSA P-256 private key", { privateKey: ecdsa.privateKey, publicKey: issuer.publicKey }],
    ["P-384 public key", { privateKey: issuer.privateKey, publicKey: p384.publicKey }],
    ["no public key", { privateKey: issuer.privateKey }],
  ]) {
    await assert.rejects(
      open(blob, /** @type {any} */ (pair), BIND, 16),
      { code: "bad_config" },
      String(label),
    );
  }
});

test("a flipped prefix keeps the ECDH x and fails through the KEM context", async () => {
  const issuer = await deriveKeyPair(utf8Encode("dca compact-ecdh parity issuer"));
  const ephemeral = await deriveKeyPair(utf8Encode("dca compact-ecdh parity ephemeral"));
  const sealed = await sealEnvelopeWithEphemeral(ephemeral, KEY16, issuer.publicKey, BIND);
  const flippedHead = Uint8Array.from(sealed.blob.subarray(0, 33));
  flippedHead[0] ^= 0x01;
  const otherEnc = decompressP256(flippedHead);
  assert.ok(otherEnc);
  assert.notDeepEqual(otherEnc, sealed.enc);

  await assert.rejects(
    openWithIntermediates(otherEnc, issuer, INFO, BIND, sealed.ciphertext),
    "the tag fails under the other point",
  );
  // The same agreement reached without the tag: equal dh, different
  // shared_secret, because kem_context holds the full enc.
  const ownDh = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "ECDH",
        public: await crypto.subtle.importKey(
          "raw",
          otherEnc,
          { name: "ECDH", namedCurve: "P-256" },
          false,
          [],
        ),
      },
      issuer.privateKey,
      256,
    ),
  );
  assert.deepEqual(ownDh, sealed.dh, "both points give the same ECDH x-coordinate");
});

describe("freshness", () => {
  test("two seals of one payload use different ephemeral points", async () => {
    const issuer = await issuerKeys();
    const one = await seal(KEY16, issuer.publicKey, BIND);
    const two = await seal(KEY16, issuer.publicKey, BIND);
    assert.notDeepEqual(one.subarray(0, 33), two.subarray(0, 33));
    assert.notDeepEqual(one.subarray(33), two.subarray(33));
  });

  // docs/spec-profile--compact-ecdh.md Section 6: a repeated ephemeral key
  // repeats the AES key and nonce. This is the failure condition the
  // publisher's freshness duty prevents, asserted here, not a mode.
  test("a forced reused ephemeral repeats the key and nonce", async () => {
    const issuer = await deriveKeyPair(utf8Encode("dca compact-ecdh freshness issuer"));
    const ephemeral = await deriveKeyPair(utf8Encode("dca compact-ecdh freshness reused"));
    const first = await sealEnvelopeWithEphemeral(ephemeral, KEY16, issuer.publicKey, BIND);
    const second = await sealEnvelopeWithEphemeral(
      ephemeral,
      SEED32.subarray(0, 16),
      issuer.publicKey,
      BIND,
    );
    assert.deepEqual(second.key, first.key);
    assert.deepEqual(second.baseNonce, first.baseNonce);
    assert.deepEqual(second.blob.subarray(0, 33), first.blob.subarray(0, 33));

    // Same key, same nonce: XOR of the two ciphertext bodies is the XOR of the
    // two payloads, which is what GCM nonce reuse exposes.
    const xorCt = first.ciphertext.subarray(0, 16).map((b, i) => b ^ second.ciphertext[i]);
    const xorPt = KEY16.map((b, i) => b ^ SEED32[i]);
    assert.deepEqual(xorCt, xorPt);
  });

  test("the deterministic path and the production path frame the same bytes", async () => {
    const issuer = await deriveKeyPair(utf8Encode("dca compact-ecdh framing issuer"));
    const ephemeral = await deriveKeyPair(utf8Encode("dca compact-ecdh framing ephemeral"));
    const sealed = await sealEnvelopeWithEphemeral(ephemeral, KEY16, issuer.publicKey, BIND);
    assert.deepEqual(sealed.blob.subarray(0, 33), compressP256(ephemeral.pkBytes));
    assert.deepEqual(sealed.blob.subarray(33), sealed.ciphertext);
    assert.deepEqual(await open(sealed.blob, issuer, BIND, 16), KEY16);
  });
});
