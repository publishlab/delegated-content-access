// @ts-check
//
// SEC 1 compressed P-256 points (SEC 1 v2.0 Sections 2.3.3 and 2.3.4), as the
// compact carrier of docs/spec-profile--compact-ecdh.md Section 4.3 uses them.
//
// OpenSSL, through `node:crypto` `ECDH.convertKey`, is the second opinion
// here: it decompresses and compresses with its own code, so a test that
// agrees with it does not only agree with the module under test.

import test from "node:test";
import assert from "node:assert/strict";
import { ECDH } from "node:crypto";

import { compressP256, decompressP256 } from "../core-shared--publisher-issuer/p256Point.js";

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

/** The P-256 base point, SEC 2 Section 2.4.2, uncompressed. */
const G = Uint8Array.from(
  Buffer.from(
    "04" +
      "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "hex",
  ),
);

/** @param {number} prefix @param {bigint} x */
function encoded(prefix, x) {
  const out = new Uint8Array(33);
  out[0] = prefix;
  out.set(Buffer.from(x.toString(16).padStart(64, "0"), "hex"), 1);
  return out;
}

/** @param {Uint8Array} bytes */
function opensslUncompressed(bytes) {
  return Uint8Array.from(
    /** @type {Buffer} */ (
      ECDH.convertKey(bytes, "prime256v1", undefined, undefined, "uncompressed")
    ),
  );
}

/** @returns {Promise<Uint8Array>} */
async function freshPoint() {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  return new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
}

test("the base point compresses to 03 || x, because its y is odd", () => {
  const compressed = compressP256(G);
  assert.equal(compressed.length, 33);
  assert.equal(compressed[0], 0x03);
  assert.deepEqual(compressed.subarray(1), G.subarray(1, 33));
  assert.deepEqual(decompressP256(compressed), G);
});

test("fresh points of both parities round-trip and match OpenSSL", async () => {
  const seen = new Set();
  for (let i = 0; i < 64 && seen.size < 2; i++) {
    const point = await freshPoint();
    const compressed = compressP256(point);
    seen.add(compressed[0]);
    assert.equal(compressed[0], point[64] & 1 ? 0x03 : 0x02);
    assert.deepEqual(
      compressed,
      Uint8Array.from(ECDH.convertKey(point, "prime256v1", undefined, undefined, "compressed")),
    );
    assert.deepEqual(decompressP256(compressed), point);
    assert.deepEqual(decompressP256(compressed), opensslUncompressed(compressed));
  }
  assert.deepEqual([...seen].sort(), [0x02, 0x03], "both parities were exercised");
});

test("x = 0 is on the curve; both parities decode with leading zero octets kept", () => {
  for (const prefix of [0x02, 0x03]) {
    const point = decompressP256(encoded(prefix, 0n));
    assert.ok(point, `prefix ${prefix}`);
    assert.equal(point.length, 65);
    assert.deepEqual(point.subarray(1, 33), new Uint8Array(32));
    assert.equal(point[64] & 1, prefix & 1);
    assert.deepEqual(point, opensslUncompressed(encoded(prefix, 0n)));
  }
});

test("a flipped prefix gives the other point with the same x", () => {
  const compressed = compressP256(G);
  const flipped = Uint8Array.from(compressed);
  flipped[0] ^= 0x01;
  const other = decompressP256(flipped);
  assert.ok(other);
  assert.deepEqual(other.subarray(1, 33), G.subarray(1, 33));
  assert.notDeepEqual(other.subarray(33), G.subarray(33));
  const y = BigInt("0x" + Buffer.from(G.subarray(33)).toString("hex"));
  const yOther = BigInt("0x" + Buffer.from(other.subarray(33)).toString("hex"));
  assert.equal(y + yOther, P, "the two roots are y and p - y");
});

test("decompression refuses a wrong length", () => {
  const good = compressP256(G);
  // Read past the length check, these two would decode x = 5, which is on the curve.
  const x5 = encoded(0x02, 5n);
  const long34 = Uint8Array.from([0x02, 0x00, ...x5.subarray(1)]);
  const short32 = Uint8Array.from([0x02, ...x5.subarray(2)]);
  for (const bytes of [
    new Uint8Array(0),
    good.subarray(0, 32),
    Uint8Array.from([...good, 0]),
    G,
    long34,
    short32,
  ]) {
    assert.equal(decompressP256(bytes), null, `length ${bytes.length}`);
  }
  assert.equal(decompressP256(/** @type {any} */ ([...good])), null, "33 numbers, not bytes");
});

test("decompression refuses a prefix other than 02 or 03", () => {
  for (const prefix of [0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff]) {
    assert.equal(decompressP256(encoded(prefix, 0n)), null, `prefix ${prefix}`);
  }
});

test("decompression refuses x at or above the field prime", () => {
  for (const x of [P, P + 1n, P + 5n, (1n << 256n) - 1n]) {
    for (const prefix of [0x02, 0x03]) {
      assert.equal(decompressP256(encoded(prefix, x)), null, `x = ${x.toString(16)}`);
    }
  }
  // x = 5 is on the curve, and P + 5 would reduce to it: the refusal above is
  // the range check, not a missing root.
  assert.ok(decompressP256(encoded(0x02, 5n)));
});

test("an x whose curve equation goes negative before reduction decodes as OpenSSL does", () => {
  // x is the square root of 2 above b: x^3 - 3x + b = 2x - 3x + b = b - x < 0
  // before the 3p term lifts it, and this x is on the curve.
  const x = 0xaf8bbdfe8cdd5577acbf345b543d28cf402f4e94d3865b97ea0787f2d3aa5d22n;
  for (const prefix of [0x02, 0x03]) {
    const point = decompressP256(encoded(prefix, x));
    assert.ok(point, `prefix ${prefix}`);
    assert.deepEqual(point, opensslUncompressed(encoded(prefix, x)));
  }
});

test("decompression refuses an x whose curve equation has no square root", () => {
  for (const x of [1n, 2n, 3n, 4n, 7n]) {
    assert.throws(() => opensslUncompressed(encoded(0x02, x)), "OpenSSL agrees x is off the curve");
    assert.equal(decompressP256(encoded(0x02, x)), null, `x = ${x}`);
    assert.equal(decompressP256(encoded(0x03, x)), null, `x = ${x}`);
  }
});

test("compression refuses anything but a 65-octet uncompressed point", () => {
  assert.throws(() => compressP256(G.subarray(0, 64)), { code: "bad_key" });
  const hybrid = Uint8Array.from(G);
  hybrid[0] = 0x07;
  assert.throws(() => compressP256(hybrid), { code: "bad_key" });
});
