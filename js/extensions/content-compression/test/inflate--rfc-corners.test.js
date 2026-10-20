// @ts-check
//
// The refusals the two specifications call for, each reached by a stream built
// for it. Hand-written bit streams where the case cannot be reached from a
// compressor's output, byte patches of a valid member where it can.
//
// The bit order is RFC 1951 section 3.1.1: fields go in starting with their
// least significant bit, Huffman codes starting with their most significant.

import test from "node:test";
import assert from "node:assert/strict";
import { crc32, gunzipSync, gzipSync } from "node:zlib";

import { utf8Encode } from "../../../core-shared/codec.js";
import { inflateGzip } from "../core-shared--client-publisher/inflate/inflate.js";

const BODY = utf8Encode("<p>The council voted 7-2 to rezone the harbour.</p>".repeat(40));

/** A deflate bit stream, written the way the format packs it. */
class Bits {
  /** @type {number[]} */
  #bytes = [];
  #held = 0;
  #count = 0;

  /** @param {number} bit */
  #bit(bit) {
    this.#held |= (bit & 1) << this.#count;
    this.#count += 1;
    if (this.#count === 8) {
      this.#bytes.push(this.#held);
      this.#held = 0;
      this.#count = 0;
    }
  }

  /** A plain field: least significant bit first. @param {number} value @param {number} width */
  field(value, width) {
    for (let at = 0; at < width; at += 1) this.#bit(value >>> at);
    return this;
  }

  /** A Huffman code: most significant bit first. @param {number} code @param {number} width */
  code(code, width) {
    for (let at = width - 1; at >= 0; at -= 1) this.#bit(code >>> at);
    return this;
  }

  /** @returns {Uint8Array} */
  bytes() {
    if (this.#count > 0) {
      this.#bytes.push(this.#held);
      this.#held = 0;
      this.#count = 0;
    }
    return Uint8Array.from(this.#bytes);
  }
}

/**
 * RFC 1951 section 3.2.6: a fixed literal/length code, as that section lays the
 * four ranges out.
 *
 * @param {Bits} bits
 * @param {number} symbol
 */
function fixedLiteral(bits, symbol) {
  if (symbol < 144) return bits.code(0x30 + symbol, 8);
  if (symbol < 256) return bits.code(0x190 + symbol - 144, 9);
  if (symbol < 280) return bits.code(symbol - 256, 7);
  return bits.code(0xc0 + symbol - 280, 8);
}

/** @param {Bits} bits @param {number} symbol */
function fixedDistance(bits, symbol) {
  return bits.code(symbol, 5);
}

/**
 * A gzip member around already-written deflate bytes. The trailer is whatever
 * the caller names, since most cases here are refused before it is read.
 *
 * @param {Uint8Array} deflated
 * @param {{ crc?: number, size?: number, trailing?: number[] }} [trailer]
 * @returns {Uint8Array}
 */
function member(deflated, trailer = {}) {
  const crc = trailer.crc ?? 0;
  const size = trailer.size ?? 0;
  return Uint8Array.from([
    0x1f,
    0x8b,
    8,
    0,
    0,
    0,
    0,
    0,
    0,
    3,
    ...deflated,
    crc & 0xff,
    (crc >>> 8) & 0xff,
    (crc >>> 16) & 0xff,
    (crc >>> 24) & 0xff,
    size & 0xff,
    (size >>> 8) & 0xff,
    (size >>> 16) & 0xff,
    (size >>> 24) & 0xff,
    ...(trailer.trailing ?? []),
  ]);
}

/** @param {Uint8Array} bytes @param {RegExp} message */
async function refused(bytes, message) {
  await assert.rejects(
    () => inflateGzip.decode(bytes),
    (cause) => {
      assert.equal(/** @type {any} */ (cause).code, "bad_encoding");
      assert.match(/** @type {any} */ (cause).message, message);
      return true;
    },
  );
}

/**
 * A dynamic-block header carrying the code-length code set this file reuses:
 * symbol 16 at one bit, 17 at two, 18 and 0 at three. HCLEN is 4, so the four
 * entries arrive in the section 3.2.7 order 16, 17, 18, 0.
 *
 * @param {Bits} bits
 * @param {number} literalCount
 * @param {number} distanceCount
 */
function dynamicHeader(bits, literalCount = 257, distanceCount = 1) {
  bits.field(1, 1).field(2, 2);
  bits
    .field(literalCount - 257, 5)
    .field(distanceCount - 1, 5)
    .field(0, 4);
  return bits.field(1, 3).field(2, 3).field(3, 3).field(3, 3);
}

// The canonical codes that header gives out. Codes of one length go in symbol
// order, RFC 1951 section 3.2.2, so among the two three-bit codes symbol 0 comes
// before symbol 18.
const CODE_16 = /** @param {Bits} bits */ (bits) => bits.code(0b0, 1);
const CODE_18 = /** @param {Bits} bits */ (bits) => bits.code(0b111, 3);

test("reserved length codes 286 and 287 are refused", async () => {
  for (const symbol of [286, 287]) {
    const bits = new Bits().field(1, 1).field(1, 2);
    fixedLiteral(bits, 65);
    fixedLiteral(bits, symbol);
    await refused(member(bits.bytes()), new RegExp(`length code ${symbol} is reserved`));
  }
});

test("reserved distance codes 30 and 31 are refused", async () => {
  for (const symbol of [30, 31]) {
    const bits = new Bits().field(1, 1).field(1, 2);
    for (let at = 0; at < 4; at += 1) fixedLiteral(bits, 65);
    fixedLiteral(bits, 257);
    fixedDistance(bits, symbol);
    await refused(member(bits.bytes()), new RegExp(`distance code ${symbol} is reserved`));
  }
});

test("a code-length repeat as the first entry is refused", async () => {
  const bits = new Bits();
  dynamicHeader(bits);
  CODE_16(bits);
  bits.field(0, 2);
  await refused(member(bits.bytes()), /first entry, with nothing to repeat/);
});

test("an over-subscribed code set is refused", async () => {
  // Four code-length codes, all one bit long. One bit holds two codes.
  const bits = new Bits().field(1, 1).field(2, 2).field(0, 5).field(0, 5).field(0, 4);
  bits.field(1, 3).field(1, 3).field(1, 3).field(1, 3);
  await refused(member(bits.bytes()), /over-subscribed/);
});

test("an incomplete code set is refused", async () => {
  // Two code-length codes of two bits: four patterns exist and two are unused.
  const bits = new Bits().field(1, 1).field(2, 2).field(0, 5).field(0, 5).field(0, 4);
  bits.field(2, 3).field(2, 3).field(0, 3).field(0, 3);
  await refused(member(bits.bytes()), /incomplete/);
});

test("one code in a set is the exception the format needs", async () => {
  // The same set with a single code is accepted: a block with no
  // back-references still declares a distance code set.
  const body = utf8Encode("abcdefghijklmnopqrstuvwxyz");
  const valid = new Uint8Array(gzipSync(body, { level: 9 }));
  assert.deepEqual(await inflateGzip.decode(valid), body);
});

/**
 * One dynamic block that writes "A": the literal set holds 'A' and
 * end-of-block at one bit each, and the distance set holds one code, symbol 0,
 * at the given length. HCLEN is 18 so the code-length code can give symbols
 * 0, 1, 2 and 18 two bits each: 0 is 00, 1 is 01, 2 is 10 and 18 is 11.
 *
 * @param {number} distanceLength - 1 or 2
 */
function singleDistanceCodeMember(distanceLength) {
  const bits = new Bits().field(1, 1).field(2, 2);
  bits.field(0, 5).field(0, 5).field(14, 4);
  const order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1];
  /** @type {Record<number, number>} */
  const codeLengthLengths = { 0: 2, 1: 2, 2: 2, 18: 2 };
  for (const symbol of order) bits.field(codeLengthLengths[symbol] ?? 0, 3);
  /** @type {Record<number, number>} */
  const code = { 0: 0b00, 1: 0b01, 2: 0b10, 18: 0b11 };
  bits.code(code[18], 2).field(65 - 11, 7); // literals 0..64 unused
  bits.code(code[1], 2); // 'A'
  bits.code(code[18], 2).field(138 - 11, 7); // 66..203 unused
  bits.code(code[18], 2).field(52 - 11, 7); // 204..255 unused
  bits.code(code[1], 2); // end-of-block
  bits.code(code[distanceLength], 2); // distance code 0
  bits.code(0, 1).code(1, 1); // 'A', end-of-block
  const body = utf8Encode("A");
  return { gzip: member(bits.bytes(), { crc: crc32(body), size: body.length }), body };
}

test("a single distance code is accepted only at one bit, as RFC 1951 section 3.2.7 has it", async () => {
  // "If only one distance code is used, it is encoded using one bit": the
  // one-bit form opens, and zlib opens it too.
  const permitted = singleDistanceCodeMember(1);
  assert.deepEqual(new Uint8Array(gunzipSync(permitted.gzip)), permitted.body);
  assert.deepEqual(await inflateGzip.decode(permitted.gzip), permitted.body);

  // The same set with its one code at two bits leaves three patterns unused.
  // zlib refuses it, so a client on the platform decoder would fail the item.
  const twoBits = singleDistanceCodeMember(2);
  assert.throws(() => gunzipSync(twoBits.gzip), /invalid distances set/);
  await refused(twoBits.gzip, /distance code set is incomplete/);
});

test("LEN and NLEN disagreeing in a stored block is refused", async () => {
  const bits = new Bits().field(1, 1).field(0, 2);
  const stored = [...bits.bytes(), 4, 0, 0, 0, 65, 66, 67, 68];
  await refused(member(Uint8Array.from(stored)), /LEN and NLEN disagree/);
});

test("a distance reaching before the start of the output is refused", async () => {
  const bits = new Bits().field(1, 1).field(1, 2);
  fixedLiteral(bits, 257);
  fixedDistance(bits, 0);
  await refused(member(bits.bytes()), /reaches before the start of the output/);
});

test("the reserved block type 3 is refused", async () => {
  const bits = new Bits().field(1, 1).field(3, 2).field(0, 8).field(0, 8);
  await refused(member(bits.bytes()), /reserved type 3/);
});

test("a header declaring more codes than the format has is refused", async () => {
  const tooManyLiterals = new Bits();
  dynamicHeader(tooManyLiterals, 288, 1);
  await refused(member(tooManyLiterals.bytes()), /more than 286 literal\/length codes/);

  const tooManyDistances = new Bits();
  dynamicHeader(tooManyDistances, 257, 32);
  await refused(member(tooManyDistances.bytes()), /more than 30 distance codes/);
});

test("a code-length repeat running past the declared codes is refused", async () => {
  const bits = new Bits();
  dynamicHeader(bits, 257, 1);
  // 258 lengths are declared and each of these fills 138 of them.
  for (let at = 0; at < 2; at += 1) {
    CODE_18(bits);
    bits.field(127, 7);
  }
  await refused(member(bits.bytes()), /runs past the declared codes/);
});

test("a truncated stream is refused at every cut", async () => {
  const valid = new Uint8Array(gzipSync(BODY, { level: 9 }));
  for (let keep = 18; keep < valid.length; keep += 1) {
    await refused(valid.subarray(0, keep), /gzip decode failed/);
  }
  for (let keep = 0; keep < 18; keep += 1) {
    await refused(valid.subarray(0, keep), /too short to be a gzip member/);
  }
});

test("a wrong CRC32 and a wrong ISIZE are each refused", async () => {
  const valid = new Uint8Array(gzipSync(BODY, { level: 9 }));

  const badCrc = Uint8Array.from(valid);
  badCrc[badCrc.length - 8] ^= 0xff;
  await refused(badCrc, /CRC32 trailer does not match/);

  const badSize = Uint8Array.from(valid);
  badSize[badSize.length - 4] ^= 0xff;
  await refused(badSize, /ISIZE trailer does not match/);
});

test("bytes after the member are refused", async () => {
  const valid = new Uint8Array(gzipSync(BODY, { level: 9 }));
  const withTail = Uint8Array.from([...valid, 0, 1, 2]);
  await refused(withTail, /bytes follow the end of the gzip member/);

  // Two members back to back draw the same refusal: this reads one member.
  await refused(Uint8Array.from([...valid, ...valid]), /bytes follow the end of the gzip member/);
});

test("the gzip header itself is held to RFC 1952 section 2.3", async () => {
  const valid = new Uint8Array(gzipSync(BODY, { level: 9 }));

  const badMagic = Uint8Array.from(valid);
  badMagic[1] = 0x8c;
  await refused(badMagic, /does not start with the gzip magic/);

  const badMethod = Uint8Array.from(valid);
  badMethod[2] = 9;
  await refused(badMethod, /is not deflate/);

  const reservedFlag = Uint8Array.from(valid);
  reservedFlag[3] |= 0x20;
  await refused(reservedFlag, /reserved FLG bit/);

  // FNAME set on a header that carries no name: the scan for the terminating
  // zero runs into the deflate data and off the end.
  const unterminated = Uint8Array.from([
    0x1f,
    0x8b,
    8,
    8,
    0,
    0,
    0,
    0,
    0,
    3,
    ...new Array(20).fill(1),
  ]);
  await refused(unterminated, /never terminated/);

  // FEXTRA with a length longer than what follows it.
  const runaway = Uint8Array.from([
    0x1f,
    0x8b,
    8,
    4,
    0,
    0,
    0,
    0,
    0,
    3,
    0xff,
    0xff,
    ...new Array(20).fill(0),
  ]);
  await refused(runaway, /FEXTRA runs past the end/);

  // FHCRC that does not match the header it covers.
  const badHeaderCrc = Uint8Array.from([
    0x1f,
    0x8b,
    8,
    2,
    0,
    0,
    0,
    0,
    0,
    3,
    0,
    0,
    ...new Array(20).fill(0),
  ]);
  await refused(badHeaderCrc, /FHCRC does not match/);
});
