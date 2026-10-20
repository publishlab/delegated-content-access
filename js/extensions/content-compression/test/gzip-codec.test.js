// @ts-check
//
// The gzip pair on its own: what it hands back, and that it copies the bytes it
// is given instead of keeping a reference to them.

import test from "node:test";
import assert from "node:assert/strict";

import { utf8Decode, utf8Encode } from "../../../core-shared/codec.js";
import { gunzip } from "../core-shared--client-publisher/inflate/inflate.js";
import {
  ENCODING,
  IDENTITY,
  decode,
  decodeWebStreams,
  decoders,
  encode,
  webStreamsGzip,
} from "../core-shared--client-publisher/gzipCodec.js";

test("the client registry uses the strict decoder", () => {
  assert.equal(ENCODING, "gzip");
  assert.equal(IDENTITY, "identity");
  assert.equal(webStreamsGzip.encode, encode);
  assert.equal(webStreamsGzip.decode, decodeWebStreams);
  assert.equal(decoders.gzip, decode);
});

test("two complete members, padding, and a damaged trailer fail the default decoder", async () => {
  const first = await encode(utf8Encode("article"));
  const second = await encode(utf8Encode("appended"));
  const joined = new Uint8Array(first.length + second.length);
  joined.set(first);
  joined.set(second, first.length);
  // Native DecompressionStream behavior for concatenated members varies by
  // runtime; the published default must reject them in either case.
  const padded = new Uint8Array(first.length + 1);
  padded.set(first);
  const damaged = Uint8Array.from(first);
  damaged[damaged.length - 8] ^= 1;
  for (const bytes of [joined, padded, damaged, first.subarray(0, first.length - 1)]) {
    await assert.rejects(() => decoders.gzip(bytes), { code: "bad_encoding" });
  }
});

test("the default decoder also works without DecompressionStream", async () => {
  const member = await encode(utf8Encode("article"));
  const native = globalThis.DecompressionStream;
  try {
    /** @type {any} */ (globalThis).DecompressionStream = undefined;
    assert.deepEqual(await decoders.gzip(member), utf8Encode("article"));
  } finally {
    globalThis.DecompressionStream = native;
  }
});

test("the strict decoder bounds input and expanded output before accepting a member", async () => {
  const compressed = await encode(new Uint8Array(4096).fill(65));
  assert.throws(() => gunzip(compressed, { maxInputBytes: compressed.length - 1 }), {
    code: "bad_encoding",
  });
  assert.throws(() => gunzip(compressed, { maxOutputBytes: 1024 }), {
    code: "bad_encoding",
  });
  assert.deepEqual(gunzip(compressed, { maxOutputBytes: 4096 }), new Uint8Array(4096).fill(65));
});

test("encode then decode returns the input bytes", async () => {
  const bytes = utf8Encode("<p>The council voted 7-2 to rezone the harbour.</p>");
  const compressed = await encode(bytes);

  assert.ok(compressed instanceof Uint8Array);
  // The gzip member header: magic 1f 8b, deflate method 08.
  assert.deepEqual([...compressed.slice(0, 3)], [0x1f, 0x8b, 0x08]);
  assert.deepEqual(await decode(compressed), bytes);
});

test("a repetitive body compresses to a fraction of its length", async () => {
  const bytes = utf8Encode("<p>The council voted to rezone the harbour.</p>".repeat(400));
  const compressed = await encode(bytes);

  assert.ok(compressed.length * 20 < bytes.length, `${compressed.length} against ${bytes.length}`);
  assert.equal(utf8Decode(await decode(compressed)), utf8Decode(bytes));
});

test("the empty input round trips", async () => {
  assert.deepEqual(await decode(await encode(new Uint8Array(0))), new Uint8Array(0));
});

test("bytes changed after the call do not change what was encoded", async () => {
  const bytes = utf8Encode("the harbour plan");
  const first = await encode(bytes);
  bytes.fill(0x41);

  assert.deepEqual(await decode(first), utf8Encode("the harbour plan"));
});

test("bytes handed to decode are not written to", async () => {
  const compressed = await encode(utf8Encode("the harbour plan"));
  const before = Uint8Array.from(compressed);
  await decode(compressed);

  assert.deepEqual(compressed, before);
});

test("input that is not gzip is refused as a typed error", async () => {
  await assert.rejects(() => decode(utf8Encode("not gzip at all")), { code: "bad_encoding" });
});

test("the exported strict decoder honors the caller's output allowance including zero", async () => {
  const bytes = utf8Encode("article");
  const member = await encode(bytes);
  assert.deepEqual(await decode(member, { maxOutputBytes: bytes.length }), bytes);
  await assert.rejects(() => decode(member, { maxOutputBytes: bytes.length - 1 }), {
    code: "bad_encoding",
  });
  await assert.rejects(() => decode(member, { maxOutputBytes: 0 }), { code: "bad_encoding" });
  const empty = await encode(new Uint8Array());
  assert.deepEqual(await decode(empty, { maxOutputBytes: 0 }), new Uint8Array());
  const corrupt = Uint8Array.from(empty);
  corrupt[corrupt.length - 8] ^= 1;
  await assert.rejects(() => decode(corrupt, { maxOutputBytes: 0 }), { code: "bad_encoding" });
});
