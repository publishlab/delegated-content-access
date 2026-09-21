// @ts-check
//
// A decode-only gzip, written from the two specifications and from nothing
// else. It exists for a runtime with no `DecompressionStream`, which is the
// only reason a client would select it.
//
//   DEFLATE   https://www.rfc-editor.org/rfc/rfc1951
//   gzip      https://www.rfc-editor.org/rfc/rfc1952
//
// Every part below names the section it implements. The two code tables of
// RFC 1951 section 3.2.5 are transcribed from the specification's own text and
// stand beside it, so a reader can check the transcription against the source
// rather than against another implementation.
//
// Decode only. There is no compressor here, and a client that selects this
// pairs it with whatever can compress on its side, or with nothing at all when
// it only ever reads.
//
// Refusals are `bad_encoding`, the code the extension's other gzip path throws,
// so a client shows one locked item either way. Every loop is bounded by the
// input: a read past the end throws, so no input makes this run on.

import { dcaError } from "../../../../core-shared/errors.js";

/** RFC 1951 section 3.2.7: no Huffman code in a deflate stream is longer than this. */
const MAX_CODE_BITS = 15;

/** RFC 1951 section 3.2.5: the largest back-reference distance. */
const WINDOW = 32768;

/**
 * RFC 1951 section 3.2.5, the length table, as the specification prints it:
 *
 *        Extra               Extra               Extra
 *   Code Bits Length(s) Code Bits Lengths   Code Bits Length(s)
 *   ---- ---- ------     ---- ---- -------   ---- ---- -------
 *    257   0     3       267   1   15,16     277   4   67-82
 *    258   0     4       268   1   17,18     278   4   83-98
 *    259   0     5       269   2   19-22     279   4   99-114
 *    260   0     6       270   2   23-26     280   4  115-130
 *    261   0     7       271   2   27-30     281   5  131-162
 *    262   0     8       272   2   31-34     282   5  163-194
 *    263   0     9       273   3   35-42     283   5  195-226
 *    264   0    10       274   3   43-50     284   5  227-257
 *    265   1  11,12      275   3   51-58     285   0    258
 *    266   1  13,14      276   3   59-66
 *
 * Read down each column: code 257 first, code 285 last. The two arrays below
 * are that table with the codes dropped, since code 257 is index 0.
 */
const LENGTH_BASE = Uint16Array.from([
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
  163, 195, 227, 258,
]);
const LENGTH_EXTRA = Uint8Array.from([
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
]);

/**
 * RFC 1951 section 3.2.5, the distance table, as the specification prints it:
 *
 *         Extra           Extra               Extra
 *    Code Bits Dist  Code Bits   Dist     Code Bits Distance
 *    ---- ---- ----  ---- ----  ------    ---- ---- --------
 *      0   0    1     10   4     33-48    20    9   1025-1536
 *      1   0    2     11   4     49-64    21    9   1537-2048
 *      2   0    3     12   5     65-96    22   10   2049-3072
 *      3   0    4     13   5     97-128   23   10   3073-4096
 *      4   1   5,6    14   6    129-192   24   11   4097-6144
 *      5   1   7,8    15   6    193-256   25   11   6145-8192
 *      6   2   9-12   16   7    257-384   26   12   8193-12288
 *      7   2  13-16   17   7    385-512   27   12  12289-16384
 *      8   3  17-24   18   8    513-768   28   13  16385-24576
 *      9   3  25-32   19   8   769-1024   29   13  24577-32768
 *
 * Codes 30 and 31 are absent from the table on purpose: the specification calls
 * them reserved, and `distanceFrom` below refuses them.
 */
const DISTANCE_BASE = Uint16Array.from([
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
  3073, 4097, 6145, 8193, 12289, 16385, 24577,
]);
const DISTANCE_EXTRA = Uint8Array.from([
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
]);

/**
 * RFC 1951 section 3.2.7: the order the code-length code lengths arrive in.
 * The order puts the lengths most likely to be zero last, so a short HCLEN
 * drops them.
 */
const CODE_LENGTH_ORDER = Uint8Array.from([
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
]);

/** RFC 1952 section 2.3.1: the FLG bits. */
const FTEXT = 1;
const FHCRC = 2;
const FEXTRA = 4;
const FNAME = 8;
const FCOMMENT = 16;
const FRESERVED = 0xe0;

/**
 * RFC 1952 section 8: CRC-32 as gzip specifies it, the reflected polynomial
 * with a pre-inverted and post-inverted register. The table is the usual
 * byte-at-a-time form of the bit loop the specification gives.
 */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let value = n;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value >>> 1) ^ (0xedb88320 & -(value & 1));
    }
    table[n] = value >>> 0;
  }
  return table;
})();

/**
 * @param {Uint8Array} bytes
 * @returns {number} the gzip CRC-32 of those bytes, unsigned
 */
function crc32(bytes) {
  let crc = 0xffffffff;
  for (let at = 0; at < bytes.length; at += 1) {
    crc = CRC_TABLE[(crc ^ bytes[at]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** @param {string} why @returns {Error} */
function refuse(why) {
  return dcaError("bad_encoding", `gzip decode failed: ${why}`);
}

/**
 * The bit-at-a-time reader RFC 1951 section 3.1.1 describes: Huffman codes are
 * packed starting with the most significant bit of the code, everything else
 * starting with the least significant bit of the byte, and a value spanning
 * bytes takes the earlier byte's bits as the lower ones.
 */
class BitReader {
  /** @type {Uint8Array} */
  #bytes;
  #at;
  /** Bits already read out of `#bytes` and not yet handed out. */
  #held = 0;
  #count = 0;

  /** @param {Uint8Array} bytes @param {number} at */
  constructor(bytes, at) {
    this.#bytes = bytes;
    this.#at = at;
  }

  /**
   * @param {number} width - at most 13, which is the widest field in the format
   * @returns {number}
   */
  bits(width) {
    let held = this.#held;
    let count = this.#count;
    while (count < width) {
      if (this.#at >= this.#bytes.length) throw refuse("the stream ends inside a block");
      held |= this.#bytes[this.#at] << count;
      this.#at += 1;
      count += 8;
    }
    this.#held = held >>> width;
    this.#count = count - width;
    return held & ((1 << width) - 1);
  }

  /**
   * RFC 1951 section 3.2.4: a stored block skips the rest of the current byte.
   *
   * @returns {void}
   */
  align() {
    this.#held = 0;
    this.#count = 0;
  }

  /** @returns {number} the next whole byte, which the caller has aligned to */
  byte() {
    if (this.#at >= this.#bytes.length) throw refuse("the stream ends inside a stored block");
    const value = this.#bytes[this.#at];
    this.#at += 1;
    return value;
  }

  /** @param {number} length @returns {Uint8Array} */
  take(length) {
    if (this.#at + length > this.#bytes.length)
      throw refuse("a stored block runs past the end of the stream");
    const slice = this.#bytes.subarray(this.#at, this.#at + length);
    this.#at += length;
    return slice;
  }

  /** @returns {number} how far into the input the reader has consumed, in whole bytes */
  get position() {
    return this.#at;
  }
}

/** The output of one member, grown as it is written. */
class Output {
  #bytes = new Uint8Array(1 << 16);
  #length = 0;

  /** @param {number} needed */
  #room(needed) {
    if (this.#length + needed <= this.#bytes.length) return;
    let size = this.#bytes.length;
    while (size < this.#length + needed) size *= 2;
    const grown = new Uint8Array(size);
    grown.set(this.#bytes.subarray(0, this.#length));
    this.#bytes = grown;
  }

  /** @param {number} value */
  push(value) {
    this.#room(1);
    this.#bytes[this.#length] = value;
    this.#length += 1;
  }

  /** @param {Uint8Array} slice */
  append(slice) {
    this.#room(slice.length);
    this.#bytes.set(slice, this.#length);
    this.#length += slice.length;
  }

  /**
   * RFC 1951 section 3.2.3: the copy reads from what has already been output,
   * one byte at a time, so a distance shorter than the length repeats.
   *
   * @param {number} distance
   * @param {number} length
   */
  copy(distance, length) {
    if (distance > this.#length)
      throw refuse("a back-reference reaches before the start of the output");
    this.#room(length);
    let from = this.#length - distance;
    for (let written = 0; written < length; written += 1) {
      this.#bytes[this.#length] = this.#bytes[from];
      this.#length += 1;
      from += 1;
    }
  }

  /** @returns {Uint8Array} */
  bytes() {
    return this.#bytes.slice(0, this.#length);
  }

  /** @returns {number} */
  get length() {
    return this.#length;
  }
}

/**
 * RFC 1951 section 3.2.2, the two rules that make a code set canonical: codes
 * of one length are consecutive and in symbol order, and the first code of a
 * length is the last code of the previous length, incremented and shifted left.
 *
 * A table built from those rules needs no code values stored. Keeping the count
 * of codes per length, and the symbols sorted by (length, symbol), is enough
 * for `symbolFrom` to walk one bit at a time.
 *
 * The same section says a code set is a complete prefix code, which is the
 * Kraft sum below: doubling the room at each length and subtracting the codes
 * taken must land on zero. A negative means more codes than that length allows,
 * a positive leaves some bit patterns undecodable. The format needs one
 * exception in practice, a set with a single used symbol: a block with no
 * back-references still declares a distance code set, and the one code in it is
 * short of complete.
 *
 * @param {Uint8Array} lengths - code length per symbol, zero where unused
 * @param {string} what - for the message
 * @returns {{ counts: Uint16Array, symbols: Uint16Array, used: number }}
 */
function codeSet(lengths, what) {
  const counts = new Uint16Array(MAX_CODE_BITS + 1);
  for (let symbol = 0; symbol < lengths.length; symbol += 1) {
    if (lengths[symbol] > MAX_CODE_BITS)
      throw refuse(`a ${what} code is longer than ${MAX_CODE_BITS} bits`);
    counts[lengths[symbol]] += 1;
  }

  const used = lengths.length - counts[0];
  if (used === 0) return { counts, symbols: new Uint16Array(0), used };

  let room = 1;
  for (let length = 1; length <= MAX_CODE_BITS; length += 1) {
    room = (room << 1) - counts[length];
    if (room < 0) throw refuse(`the ${what} code set is over-subscribed`);
  }
  if (room > 0 && used > 1) throw refuse(`the ${what} code set is incomplete`);

  const offsets = new Uint16Array(MAX_CODE_BITS + 2);
  for (let length = 1; length <= MAX_CODE_BITS; length += 1) {
    offsets[length + 1] = offsets[length] + counts[length];
  }
  const symbols = new Uint16Array(used);
  for (let symbol = 0; symbol < lengths.length; symbol += 1) {
    const length = lengths[symbol];
    if (length !== 0) {
      symbols[offsets[length]] = symbol;
      offsets[length] += 1;
    }
  }

  return { counts, symbols, used };
}

/**
 * One symbol, read bit by bit against a canonical set. At each length the
 * accumulated code is compared against the first code of that length: inside
 * the run of codes that length holds, the symbol is that many places into the
 * length's block of symbols. RFC 1951 section 3.2.2.
 *
 * @param {BitReader} reader
 * @param {{ counts: Uint16Array, symbols: Uint16Array }} set
 * @param {string} what - for the message
 * @returns {number}
 */
function symbolFrom(reader, set, what) {
  let code = 0;
  let first = 0;
  let index = 0;

  for (let length = 1; length <= MAX_CODE_BITS; length += 1) {
    code |= reader.bits(1);
    const count = set.counts[length];
    if (code - first < count) return set.symbols[index + (code - first)];
    index += count;
    first = (first + count) << 1;
    code <<= 1;
  }

  throw refuse(`no ${what} code matches the next ${MAX_CODE_BITS} bits`);
}

/**
 * RFC 1951 section 3.2.6: the code lengths a fixed block uses. Literals 0-143
 * take 8 bits, 144-255 take 9, 256-279 take 7 and 280-287 take 8; every
 * distance code takes 5. The two sets are built once, since they never change.
 */
const FIXED = (() => {
  const literals = new Uint8Array(288);
  for (let symbol = 0; symbol < 288; symbol += 1) {
    if (symbol < 144) literals[symbol] = 8;
    else if (symbol < 256) literals[symbol] = 9;
    else if (symbol < 280) literals[symbol] = 7;
    else literals[symbol] = 8;
  }
  const distances = new Uint8Array(32).fill(5);
  return { literals: codeSet(literals, "literal"), distances: codeSet(distances, "distance") };
})();

/**
 * RFC 1951 section 3.2.7: the two code sets a dynamic block carries, read from
 * the header that precedes them.
 *
 * @param {BitReader} reader
 * @returns {{ literals: any, distances: any }}
 */
function dynamicCodeSets(reader) {
  const literalCount = reader.bits(5) + 257;
  const distanceCount = reader.bits(5) + 1;
  const codeLengthCount = reader.bits(4) + 4;

  // The section states the ranges: HLIT is 257 through 286 and HDIST is 1
  // through 30, because 286, 287, 30 and 31 are reserved and no code set may
  // give them a length.
  if (literalCount > 286) throw refuse("the header declares more than 286 literal/length codes");
  if (distanceCount > 30) throw refuse("the header declares more than 30 distance codes");

  const codeLengthLengths = new Uint8Array(CODE_LENGTH_ORDER.length);
  for (let index = 0; index < codeLengthCount; index += 1) {
    codeLengthLengths[CODE_LENGTH_ORDER[index]] = reader.bits(3);
  }
  const codeLengths = codeSet(codeLengthLengths, "code length");

  const lengths = new Uint8Array(literalCount + distanceCount);
  let filled = 0;
  while (filled < lengths.length) {
    const symbol = symbolFrom(reader, codeLengths, "code length");

    if (symbol < 16) {
      lengths[filled] = symbol;
      filled += 1;
      continue;
    }

    let repeat;
    let value;
    if (symbol === 16) {
      // "Copy the previous code length", which is why it cannot be first:
      // there is no previous length to copy.
      if (filled === 0)
        throw refuse("a code length repeat is the first entry, with nothing to repeat");
      value = lengths[filled - 1];
      repeat = 3 + reader.bits(2);
    } else if (symbol === 17) {
      value = 0;
      repeat = 3 + reader.bits(3);
    } else {
      value = 0;
      repeat = 11 + reader.bits(7);
    }

    if (filled + repeat > lengths.length)
      throw refuse("a code length repeat runs past the declared codes");
    lengths.fill(value, filled, filled + repeat);
    filled += repeat;
  }

  return {
    literals: codeSet(lengths.subarray(0, literalCount), "literal"),
    distances: codeSet(lengths.subarray(literalCount), "distance"),
  };
}

/**
 * RFC 1951 section 3.2.5: one length, from its code and the extra bits after
 * it. Codes 286 and 287 are reserved, and a fixed block can name them because
 * the fixed set gives all 288 symbols a length.
 *
 * @param {BitReader} reader
 * @param {number} symbol - 257 through 287
 * @returns {number}
 */
function lengthFrom(reader, symbol) {
  const index = symbol - 257;
  if (index >= LENGTH_BASE.length) throw refuse(`length code ${symbol} is reserved`);
  return LENGTH_BASE[index] + reader.bits(LENGTH_EXTRA[index]);
}

/**
 * RFC 1951 section 3.2.5: one distance, from its code and the extra bits after
 * it. Codes 30 and 31 are reserved, and the fixed distance set names them for
 * the same reason.
 *
 * @param {BitReader} reader
 * @param {number} symbol - 0 through 31
 * @returns {number}
 */
function distanceFrom(reader, symbol) {
  if (symbol >= DISTANCE_BASE.length) throw refuse(`distance code ${symbol} is reserved`);
  const distance = DISTANCE_BASE[symbol] + reader.bits(DISTANCE_EXTRA[symbol]);
  if (distance > WINDOW) throw refuse("a distance is longer than the 32 KB window");
  return distance;
}

/**
 * RFC 1951 section 3.2.4: a stored block, byte-aligned, with its length written
 * twice, the second time inverted.
 *
 * @param {BitReader} reader
 * @param {Output} output
 */
function storedBlock(reader, output) {
  reader.align();
  const length = reader.byte() | (reader.byte() << 8);
  const inverted = reader.byte() | (reader.byte() << 8);
  if (length !== (~inverted & 0xffff)) throw refuse("a stored block's LEN and NLEN disagree");
  output.append(reader.take(length));
}

/**
 * RFC 1951 section 3.2.3: one block of codes, literals written out as they come
 * and lengths followed by a distance and a copy, until the end-of-block symbol.
 *
 * @param {BitReader} reader
 * @param {Output} output
 * @param {{ literals: any, distances: any }} sets
 */
function codedBlock(reader, output, sets) {
  for (;;) {
    const symbol = symbolFrom(reader, sets.literals, "literal");
    if (symbol < 256) {
      output.push(symbol);
      continue;
    }
    if (symbol === 256) return;

    const length = lengthFrom(reader, symbol);
    const distance = distanceFrom(reader, symbolFrom(reader, sets.distances, "distance"));
    output.copy(distance, length);
  }
}

/**
 * RFC 1951 section 3.2.3: the block sequence, each one carrying whether it is
 * the last and which of the three kinds it is. Back-references reach across
 * block boundaries, which is why one `Output` runs through all of them.
 *
 * @param {BitReader} reader
 * @returns {Output}
 */
function inflate(reader) {
  const output = new Output();
  for (;;) {
    const last = reader.bits(1);
    const kind = reader.bits(2);

    if (kind === 0) storedBlock(reader, output);
    else if (kind === 1) codedBlock(reader, output, FIXED);
    else if (kind === 2) codedBlock(reader, output, dynamicCodeSets(reader));
    else throw refuse("a block declares the reserved type 3");

    if (last) return output;
  }
}

/**
 * RFC 1952 section 2.3: the member header, and section 2.3.1 the flags whose
 * optional fields follow it.
 *
 * @param {Uint8Array} bytes
 * @returns {number} where the deflate data begins
 */
function headerEnd(bytes) {
  if (bytes.length < 18) throw refuse("the input is too short to be a gzip member");
  if (bytes[0] !== 0x1f || bytes[1] !== 0x8b)
    throw refuse("the input does not start with the gzip magic 1f 8b");
  if (bytes[2] !== 8) throw refuse(`compression method ${bytes[2]} is not deflate`);

  const flags = bytes[3];
  if (flags & FRESERVED) throw refuse("the header sets a reserved FLG bit");
  void FTEXT;

  let at = 10;
  if (flags & FEXTRA) {
    if (at + 2 > bytes.length) throw refuse("the header ends inside FEXTRA");
    const extraLength = bytes[at] | (bytes[at + 1] << 8);
    at += 2 + extraLength;
    if (at > bytes.length) throw refuse("FEXTRA runs past the end of the input");
  }
  for (const flag of [FNAME, FCOMMENT]) {
    if (!(flags & flag)) continue;
    while (at < bytes.length && bytes[at] !== 0) at += 1;
    if (at >= bytes.length) throw refuse("a zero-terminated header field is never terminated");
    at += 1;
  }
  if (flags & FHCRC) {
    if (at + 2 > bytes.length) throw refuse("the header ends inside FHCRC");
    const stored = bytes[at] | (bytes[at + 1] << 8);
    if (stored !== (crc32(bytes.subarray(0, at)) & 0xffff))
      throw refuse("FHCRC does not match the header");
    at += 2;
  }

  return at;
}

/**
 * One gzip member, decoded. RFC 1952 section 2.3.1 puts the CRC-32 of the
 * uncompressed bytes and their length modulo 2^32 after the deflate data, and
 * both are checked here. Anything after that trailer is refused: this decoder
 * reads one member, and a second member would deliver bytes the caller did not
 * ask for.
 *
 * @param {Uint8Array} bytes - a gzip member
 * @returns {Uint8Array} the bytes it carries
 */
export function gunzip(bytes) {
  const reader = new BitReader(bytes, headerEnd(bytes));
  const output = inflate(reader);
  reader.align();

  const at = reader.position;
  if (at + 8 > bytes.length) throw refuse("the stream ends before its CRC32 and ISIZE trailer");
  const stored =
    (bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16) | (bytes[at + 3] << 24)) >>> 0;
  const size =
    (bytes[at + 4] | (bytes[at + 5] << 8) | (bytes[at + 6] << 16) | (bytes[at + 7] << 24)) >>> 0;

  const decoded = output.bytes();
  if (crc32(decoded) !== stored) throw refuse("the CRC32 trailer does not match the decoded bytes");
  if (decoded.length >>> 0 !== size)
    throw refuse("the ISIZE trailer does not match the decoded length");
  if (at + 8 !== bytes.length) throw refuse("bytes follow the end of the gzip member");

  return decoded;
}

/**
 * The decode half of the extension's `Gzip` shape, so a client selects this by
 * injection: `gzip: { encode, decode }` with this `decode`.
 *
 * @param {Uint8Array} bytes
 * @returns {Promise<Uint8Array>}
 */
export async function decode(bytes) {
  return gunzip(bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes));
}

/**
 * This decoder as one value, shaped like the decode half of
 * `core-shared--client-publisher/gzipCodec.js`'s `Gzip`.
 *
 * @type {{ decode: (bytes: Uint8Array) => Promise<Uint8Array> }}
 */
export const inflateGzip = { decode };
