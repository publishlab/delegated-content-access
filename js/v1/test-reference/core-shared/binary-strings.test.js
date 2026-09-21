//
// core-shared/binaryStrings - the named strict decoder every wire receive
// boundary reads a binary member through.
//
// Section 2.2 of the data format admits one spelling for a binary field and
// refuses padding, standard-base64 characters, undecodable input and a spelling
// with nonzero unused trailing bits. `base64urlDecode` admits three of those on
// purpose, because PEM key material goes through the same call, so the strict
// rule is a second named function rather than a change to the first. Both are
// asserted here: the strict answers, and the leniency the generic pair keeps.

import test from "node:test";
import assert from "node:assert/strict";

import { binaryStringBytes } from "../../core-shared/binaryStrings.js";
import { base64urlDecode, base64urlEncode } from "../../core-shared/codec.js";

const DEADBEEF = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

test("a canonical spelling supplies its bytes", () => {
  assert.deepEqual(binaryStringBytes("3q2-7w"), DEADBEEF);
  assert.deepEqual(binaryStringBytes("QQ"), new Uint8Array([0x41]));
  assert.deepEqual(binaryStringBytes("AAA"), new Uint8Array([0, 0]));
  assert.deepEqual(
    binaryStringBytes(""),
    new Uint8Array(0),
    "the empty spelling carries zero bytes",
  );

  const every = new Uint8Array(256);
  for (let i = 0; i < 256; i++) every[i] = i;
  assert.deepEqual(binaryStringBytes(base64urlEncode(every)), every, "every byte round-trips");
});

test("a value that is not a string is refused rather than coerced", () => {
  for (const value of [undefined, null, 42, {}, ["3q2-7w"], new Uint8Array(4)]) {
    const shown = JSON.stringify(value) ?? "undefined";
    assert.equal(binaryStringBytes(/** @type {any} */ (value)), null, `value ${shown}`);
  }
});

test("a character outside the alphabet is refused, padding and standard base64 with it", () => {
  // Padding is this rule applied to `=`, which is why a padded spelling has no
  // separate branch. `+` and `/` are the standard alphabet, and both decode to
  // bytes through the generic pair below.
  for (const value of [
    "3q2-7w==",
    "3q2-7w=",
    "3q2+7w",
    "3q2/7w",
    "3q2-7w*",
    "3q2-7 w",
    "3q2-\n7w",
  ]) {
    assert.equal(binaryStringBytes(value), null, `spelling ${JSON.stringify(value)}`);
  }
});

test("a length of 1 modulo 4 is refused, because it encodes no whole byte count", () => {
  assert.equal(binaryStringBytes("A"), null);
  assert.equal(binaryStringBytes("AAAAA"), null);
});

test("a spelling the decoder itself refuses comes back as a refusal, not as a throw", () => {
  // The screens above catch this one first, so the decoder's own throw is the
  // branch under it rather than the one that fires. The pair has to agree that
  // no caller of the strict decoder ever sees the throw.
  assert.throws(() => base64urlDecode("QUJDQ"), { name: "InvalidCharacterError" });
  assert.equal(binaryStringBytes("QUJDQ"), null);
});

test("nonzero unused trailing bits are refused, and the canonical neighbour is not", () => {
  // Re-encoding is what catches these: every mainstream decoder reads them and
  // discards the bits, so `3q2-7x` and `3q2-7w` decode to the same four bytes.
  assert.deepEqual(
    base64urlDecode("3q2-7x"),
    DEADBEEF,
    "the generic decoder reads the noncanonical twin",
  );
  assert.equal(binaryStringBytes("3q2-7x"), null);
  assert.equal(binaryStringBytes("QR"), null);
  assert.equal(binaryStringBytes("AAB"), null);
  assert.deepEqual(binaryStringBytes("QQ"), new Uint8Array([0x41]), "the control for QR");
  assert.deepEqual(binaryStringBytes("AAA"), new Uint8Array([0, 0]), "the control for AAB");
});

test("the generic decoder keeps the leniency PEM material depends on", () => {
  // The pinned half of the carve-out: every spelling the strict rule refuses
  // above still supplies bytes here, so a PEM body reaches the same call it
  // always did. codec.test.js covers the rest of that behavior.
  assert.deepEqual(base64urlDecode("AAAA"), new Uint8Array([0, 0, 0]));
  assert.deepEqual(base64urlDecode("/w=="), new Uint8Array([0xff]));
  for (const value of ["3q2-7w==", "3q2+7w", "3q2-7x"]) {
    assert.equal(
      base64urlDecode(value).length,
      4,
      `the generic decoder still reads ${JSON.stringify(value)}`,
    );
    assert.equal(
      binaryStringBytes(value),
      null,
      `the strict decoder refuses ${JSON.stringify(value)}`,
    );
  }
});
