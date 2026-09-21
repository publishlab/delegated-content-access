// @ts-check
//
// The gzip pair on its own: what it hands back, and that it copies the bytes it
// is given instead of keeping a reference to them.

import test from "node:test";
import assert from "node:assert/strict";

import { utf8Decode, utf8Encode } from "../../../core-shared/codec.js";
import {
  ENCODING,
  IDENTITY,
  decode,
  encode,
  webStreamsGzip,
} from "../core-shared--client-publisher/gzipCodec.js";

test("the extension writes one encoding, and the Web Streams pair is the default", () => {
  assert.equal(ENCODING, "gzip");
  assert.equal(IDENTITY, "identity");
  assert.equal(webStreamsGzip.encode, encode);
  assert.equal(webStreamsGzip.decode, decode);
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
