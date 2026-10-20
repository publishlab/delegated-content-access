//
// core-shared/codec - the published base64url pair, and the UTF-8 pair.

import { test, portableTest } from "../support/portable-test.js";
import assert from "node:assert/strict";

import {
  base64urlEncode,
  base64urlDecode,
  utf8Encode,
  utf8Decode,
} from "../../core-shared/codec.js";
const portableCoreTest = portableTest("portable-core");

/**
 * Spellings the padding step settles, each beside the bytes it decodes to.
 *
 * @type {[string, Uint8Array][]}
 */
const PADDING_SETTLED = [
  ["QUJDQU", new Uint8Array([0x41, 0x42, 0x43, 0x41])],
  ["QQ=", new Uint8Array([0x41])],
];

portableCoreTest("base64urlEncode emits the URL alphabet", () => {
  // 0xFB 0xFF 0xBE is "+/++" in standard base64, "-_--" in base64url.
  assert.equal(base64urlEncode(new Uint8Array([0xfb, 0xff, 0xbe])), "-_--");
});

portableCoreTest("base64urlEncode strips padding", () => {
  assert.equal(base64urlEncode(new Uint8Array([0x00])), "AA");
  assert.equal(base64urlEncode(new Uint8Array([0x00, 0x00])), "AAA");
  assert.equal(base64urlEncode(new Uint8Array([0x00, 0x00, 0x00])), "AAAA");
});

test("base64urlEncode accepts an ArrayBuffer as well as a view", () => {
  const bytes = new Uint8Array([1, 2, 3, 4, 5]);
  assert.equal(base64urlEncode(bytes.buffer), base64urlEncode(bytes));
});

portableCoreTest("base64urlDecode reverses base64urlEncode", () => {
  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) bytes[i] = i;
  assert.deepEqual(base64urlDecode(base64urlEncode(bytes)), bytes);
});

portableCoreTest("base64urlDecode also reads standard base64 with padding", () => {
  // The replacements are no-ops when no - or _ are present; PEM key import needs this.
  assert.deepEqual(base64urlDecode("AAAA"), new Uint8Array([0, 0, 0]));
  assert.deepEqual(base64urlDecode("/w=="), new Uint8Array([0xff]));
});

test("base64urlDecode refuses a spelling it cannot read", () => {
  // `atob` runs the WHATWG forgiving-base64 parser, so every refusal arrives
  // as one InvalidCharacterError whatever went wrong: a character outside the
  // alphabet, a length no encoder can produce, or layout. openContent is
  // where that becomes bad_page.
  assert.throws(() => base64urlDecode("not base64url!!"), { name: "InvalidCharacterError" });
  assert.throws(() => base64urlDecode("QUJDQ"), { name: "InvalidCharacterError" });
  assert.throws(() => base64urlDecode("QUJD QUJD"), { name: "InvalidCharacterError" });
  assert.throws(() => base64urlDecode("QUJD\nQUJD"), { name: "InvalidCharacterError" });
});

test("the padding step settles a half-padded string and a wrapped one", () => {
  // Both verdicts belong to the padding computation rather than to `atob`,
  // which on its own reads 'QUJDQU' and every other unpadded length here
  // and would answer the opposite way on these two. Padding is counted from
  // the string as it arrives: it completes 'QQ=', which `atob` alone calls a
  // stray '=', and it counts the space in 'QUJD QUJD' that forgiving-base64
  // would have stripped, so the padding no longer reconciles. The alphabet
  // tolerance this module documents is about `+`, `/` and `=` for PEM
  // material; a wrapped PEM body arrives with its line breaks removed.
  for (const [spelling, bytes] of PADDING_SETTLED) {
    assert.deepEqual(base64urlDecode(spelling), bytes);
  }
  assert.throws(() => base64urlDecode("QUJD QUJD"), { name: "InvalidCharacterError" });
});

// The portable twin of the case above. Its refusal asserts the WHATWG error
// name that `atob` throws, which another language has no reason to emit, so
// that half runs only in the direct case.
portableCoreTest(
  "the padding step settles a half-padded string and a wrapped one, decodes only",
  () => {
    for (const [spelling, bytes] of PADDING_SETTLED) {
      assert.deepEqual(base64urlDecode(spelling), bytes, spelling);
    }
  },
);

portableCoreTest("base64urlEncode survives an input larger than the spread limit", () => {
  // The spread form in the public encoding reference RangeErrors somewhere
  // around 125k bytes. A 200KB article has to encode.
  const big = new Uint8Array(200_000);
  for (let i = 0; i < big.length; i++) big[i] = i % 256;

  const encoded = base64urlEncode(big);

  assert.equal(encoded.length, Math.ceil((big.length * 4) / 3));
  assert.ok(!/[+/=]/.test(encoded), "no standard-base64 characters survive");
  assert.deepEqual(base64urlDecode(encoded), big);
});

portableCoreTest("utf8 round-trip carries non-ASCII", () => {
  const text = 'Bodø – "æøå" – 🐕';
  assert.equal(utf8Decode(utf8Encode(text)), text);
});
