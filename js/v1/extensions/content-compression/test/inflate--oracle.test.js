// @ts-check
//
// The polyfill against the reference compressor. Node's zlib produces the
// streams, this decoder reads them back, and the bytes have to match what went
// in. Every level from 0 to 9 is covered because the level picks the block
// type: 0 emits stored blocks, the low levels emit fixed codes on small inputs,
// and the high levels emit dynamic ones.

import test from "node:test";
import assert from "node:assert/strict";
import { deflateRawSync, gzipSync } from "node:zlib";

import { utf8Decode, utf8Encode } from "../../../core-shared/codec.js";
import { syntheticArticle } from "../../../tools/synthetic-html.js";
import { inflateGzip } from "../core-client/inflate/inflate.js";

const LEVELS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
const SIZES = [3000, 10_000, 30_000];
const FORMS = /** @type {const} */ (["html", "txt", "json"]);
const SEEDS = [1, 7, 23];

/** @param {Uint8Array} bytes */
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * A gzip member built by hand, so the optional header fields this decoder has
 * to skip can be set. Node's `gzipSync` exposes none of them.
 *
 * @param {Uint8Array} data
 * @param {{ extra?: Uint8Array, name?: string, comment?: string, headerCrc?: boolean }} options
 * @returns {Uint8Array}
 */
function memberWith(data, options = {}) {
  const FEXTRA = 4;
  const FNAME = 8;
  const FCOMMENT = 16;
  const FHCRC = 2;

  let flags = 0;
  /** @type {number[]} */
  const optional = [];
  if (options.extra) {
    flags |= FEXTRA;
    optional.push(
      options.extra.length & 0xff,
      (options.extra.length >>> 8) & 0xff,
      ...options.extra,
    );
  }
  if (options.name !== undefined) {
    flags |= FNAME;
    optional.push(...utf8Encode(options.name), 0);
  }
  if (options.comment !== undefined) {
    flags |= FCOMMENT;
    optional.push(...utf8Encode(options.comment), 0);
  }
  if (options.headerCrc) flags |= FHCRC;

  const head = [0x1f, 0x8b, 8, flags, 0, 0, 0, 0, 0, 3, ...optional];
  if (options.headerCrc) {
    const through = crc32(Uint8Array.from(head)) & 0xffff;
    head.push(through & 0xff, (through >>> 8) & 0xff);
  }

  const deflated = new Uint8Array(deflateRawSync(data));
  const checksum = crc32(data);
  const size = data.length >>> 0;
  return Uint8Array.from([
    ...head,
    ...deflated,
    checksum & 0xff,
    (checksum >>> 8) & 0xff,
    (checksum >>> 16) & 0xff,
    (checksum >>> 24) & 0xff,
    size & 0xff,
    (size >>> 8) & 0xff,
    (size >>> 16) & 0xff,
    (size >>> 24) & 0xff,
  ]);
}

test("every zlib level over every synthetic body round trips", async () => {
  for (const form of FORMS) {
    for (const bytes of SIZES) {
      for (const seed of SEEDS) {
        const body = utf8Encode(syntheticArticle({ bytes, form, seed }));
        for (const level of LEVELS) {
          const member = new Uint8Array(gzipSync(body, { level }));
          const back = await inflateGzip.decode(member);
          assert.deepEqual(back, body, `${form} ${bytes} seed ${seed} level ${level}`);
        }
      }
    }
  }
});

test("the empty input round trips at every level", async () => {
  for (const level of LEVELS) {
    const member = new Uint8Array(gzipSync(new Uint8Array(0), { level }));
    assert.deepEqual(await inflateGzip.decode(member), new Uint8Array(0));
  }
});

test("a body past the 32 KB window round trips, so back-references cross blocks", async () => {
  const body = utf8Encode(syntheticArticle({ bytes: 200_000, seed: 4 }));
  assert.ok(body.length > 32 * 1024 * 4, `the generator produced ${body.length} bytes`);

  const member = new Uint8Array(gzipSync(body, { level: 9 }));
  assert.deepEqual(await inflateGzip.decode(member), body);
});

test("a stored-only stream reads back", async () => {
  const body = utf8Encode(syntheticArticle({ bytes: 90_000, seed: 6 }));
  const member = new Uint8Array(gzipSync(body, { level: 0 }));

  // Level 0 stores, so the member is longer than what went in.
  assert.ok(member.length > body.length, `${member.length} against ${body.length}`);
  assert.deepEqual(await inflateGzip.decode(member), body);
});

test("the optional header fields are skipped, one at a time and all at once", async () => {
  const body = utf8Encode(syntheticArticle({ bytes: 3000, seed: 9 }));

  const cases = [
    { extra: Uint8Array.from([1, 2, 3, 4]) },
    { name: "article.html" },
    { comment: "rendered by the reference publisher" },
    { headerCrc: true },
    {
      extra: Uint8Array.from([9, 9]),
      name: "a.html",
      comment: "both",
      headerCrc: true,
    },
  ];

  for (const options of cases) {
    const member = memberWith(body, options);
    assert.deepEqual(await inflateGzip.decode(member), body, JSON.stringify(Object.keys(options)));
  }
});

test("the decoded bytes are the article a reader would show", async () => {
  const body = syntheticArticle({ bytes: 10_000, seed: 2 });
  const member = new Uint8Array(gzipSync(utf8Encode(body), { level: 6 }));

  assert.equal(utf8Decode(await inflateGzip.decode(member)), body);
});
