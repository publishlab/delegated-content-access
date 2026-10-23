// @ts-check
//
// The period-key wrap nonce is first12(SHA-256(context)), where context is the
// label, a zero octet, the 16 render ID octets and four length-prefixed fields.
// Every expected value here comes from this file's own framing and node:crypto,
// or from a literal, and never from the helper under test: a producer and a
// reader that share one framing bug would otherwise agree with each other and
// with this test.

import { test } from "../support/portable-test.js";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { contentKeyWrapNonce } from "../../core-shared/contentKeyWrapNonce.js";

const RENDER_ID = "AAECAwQFBgcICQoLDA0ODw";

/** @param {Uint8Array} bytes */
function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

/** @param {Uint8Array|Buffer} bytes */
function lp(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

/**
 * @param {{ renderId: string, contentName: string, accessGroup: string, t: string, aad?: Uint8Array }} fields
 * @returns {string}
 */
function expectedNonce({ renderId, contentName, accessGroup, t, aad }) {
  const context = Buffer.concat([
    Buffer.from("dca-derivation-content-key-wrap-nonce", "utf8"),
    Buffer.from([0]),
    Buffer.from(renderId, "base64url"),
    lp(Buffer.from(contentName, "utf8")),
    lp(Buffer.from(accessGroup, "utf8")),
    lp(Buffer.from(t, "utf8")),
    lp(Buffer.from(aad ?? new Uint8Array(0))),
  ]);
  return createHash("sha256").update(context).digest().subarray(0, 12).toString("hex");
}

const SEED = Object.freeze({
  renderId: RENDER_ID,
  contentName: "bodytext",
  accessGroup: "premium",
  t: "251023T1400",
});

test("the seed coordinate derives the recorded nonce", async () => {
  // The literal was computed separately in Python and PHP before this helper existed.
  assert.equal(expectedNonce(SEED), "5bc590cb902de4d359b2c28b", "this file's own framing");
  const nonce = await contentKeyWrapNonce(SEED);
  assert.ok(nonce instanceof Uint8Array);
  assert.equal(hex(nonce), "5bc590cb902de4d359b2c28b");
  assert.equal(
    hex(/** @type {Uint8Array} */ (await contentKeyWrapNonce({ ...SEED, aad: new Uint8Array(0) }))),
    "5bc590cb902de4d359b2c28b",
    "empty selected AAD is the ordinary transcript",
  );
});

test("the selected wrap AAD enters the transcript as its exact bytes", async () => {
  const aad = new TextEncoder().encode(
    `dca-bind-seal-omission|${RENDER_ID}|bodytext|premium|251023T1400`,
  );
  assert.equal(
    expectedNonce({ ...SEED, aad }),
    "67a5505ba3fb204538663480",
    "this file's own framing",
  );
  assert.equal(
    hex(/** @type {Uint8Array} */ (await contentKeyWrapNonce({ ...SEED, aad }))),
    "67a5505ba3fb204538663480",
  );
  const flipped = Uint8Array.from(aad);
  flipped[flipped.length - 1] ^= 1;
  assert.equal(
    hex(/** @type {Uint8Array} */ (await contentKeyWrapNonce({ ...SEED, aad: flipped }))),
    expectedNonce({ ...SEED, aad: flipped }),
  );
  assert.notEqual(expectedNonce({ ...SEED, aad: flipped }), "67a5505ba3fb204538663480");
});

test("each coordinate changes the nonce and length prefixes keep fields apart", async () => {
  const cases = [
    { ...SEED, renderId: "AAECAwQFBgcICQoLDA0OEA" },
    { ...SEED, contentName: "teaser" },
    { ...SEED, accessGroup: "basic" },
    { ...SEED, t: "251023T1500" },
    // Without length prefixes these two would hash the same octets.
    { ...SEED, contentName: "ab", accessGroup: "cd" },
    { ...SEED, contentName: "abc", accessGroup: "d" },
  ];
  const seen = new Set([expectedNonce(SEED)]);
  for (const fields of cases) {
    const nonce = /** @type {Uint8Array} */ (await contentKeyWrapNonce(fields));
    assert.equal(hex(nonce), expectedNonce(fields), JSON.stringify(fields));
    assert.ok(
      !seen.has(hex(nonce)),
      `${JSON.stringify(fields)} repeats another coordinate's nonce`,
    );
    seen.add(hex(nonce));
  }
});

test("names at the 64-character boundary derive; one more character refuses", async () => {
  const contentName = `a${"b".repeat(63)}`;
  const accessGroup = `g${"-".repeat(63)}`;
  const nonce = await contentKeyWrapNonce({ ...SEED, contentName, accessGroup });
  assert.equal(
    hex(/** @type {Uint8Array} */ (nonce)),
    expectedNonce({ ...SEED, contentName, accessGroup }),
  );
  assert.equal(await contentKeyWrapNonce({ ...SEED, contentName: `${contentName}c` }), null);
  assert.equal(await contentKeyWrapNonce({ ...SEED, accessGroup: `${accessGroup}h` }), null);
});

test("non-ASCII names and labels are refused, not framed or normalized", async () => {
  // The name grammar admits ASCII only. A helper that framed these as UTF-8
  // would hash a coordinate no producer can write.
  for (const contentName of ["bodytéxt", "bodytéxt", "ｂodytext", "body​text"]) {
    assert.equal(await contentKeyWrapNonce({ ...SEED, contentName }), null, contentName);
  }
  assert.equal(await contentKeyWrapNonce({ ...SEED, accessGroup: "prémium" }), null);
  assert.equal(await contentKeyWrapNonce({ ...SEED, t: "２51023T1400" }), null);
});

test("malformed names, labels and AAD are refused", async () => {
  for (const value of [undefined, null, 1, {}, [], "", "1bodytext", "body|text", "body text"]) {
    assert.equal(
      await contentKeyWrapNonce(/** @type {any} */ ({ ...SEED, contentName: value })),
      null,
    );
    assert.equal(
      await contentKeyWrapNonce(/** @type {any} */ ({ ...SEED, accessGroup: value })),
      null,
    );
  }
  for (const t of [
    undefined,
    251023,
    "251023T140",
    "251023T14000",
    "251023t1400",
    "251023T1400Z",
  ]) {
    assert.equal(await contentKeyWrapNonce(/** @type {any} */ ({ ...SEED, t })), null, String(t));
  }
  for (const aad of [null, "aad", [1, 2], new ArrayBuffer(2), new Uint16Array(1)]) {
    assert.equal(
      await contentKeyWrapNonce(/** @type {any} */ ({ ...SEED, aad })),
      null,
      String(aad),
    );
  }
  for (const fields of [undefined, null, "fields", []]) {
    assert.equal(await contentKeyWrapNonce(/** @type {any} */ (fields)), null);
  }
});

test("a render ID that is not canonical base64url of 16 octets is refused", async () => {
  for (const renderId of [
    undefined,
    16,
    "",
    "AAECAwQFBgcICQoLDA0ODw==", // padded
    "AAECAwQFBgcICQoLDA0OD+", // standard alphabet
    "AAECAwQFBgcICQoLDA0ODx", // nonzero unused trailing bits
    "AAECAwQFBgcICQoLDA0O", // 15 octets
    "AAECAwQFBgcICQoLDA0ODxA", // 17 octets
    " AAECAwQFBgcICQoLDA0ODw",
  ]) {
    assert.equal(
      await contentKeyWrapNonce(/** @type {any} */ ({ ...SEED, renderId })),
      null,
      JSON.stringify(renderId),
    );
  }
});

test("inputs are captured when the call starts", async () => {
  const aad = new TextEncoder().encode("selected");
  const fields = { ...SEED, aad };
  const pending = contentKeyWrapNonce(fields);
  aad.fill(0);
  fields.contentName = "teaser";
  assert.equal(
    hex(/** @type {Uint8Array} */ (await pending)),
    expectedNonce({ ...SEED, aad: new TextEncoder().encode("selected") }),
  );
});
