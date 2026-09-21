// @ts-check
//
// The polyfill as a client selects it: injected as the decode half of the
// extension's `Gzip`, over a render this extension's publisher produced. Nothing
// in the extension imports the polyfill, so this test covers the whole path by
// which it reaches a client.

import test from "node:test";
import assert from "node:assert/strict";

import { utf8Decode } from "../../../core-shared/codec.js";
import { syntheticArticle } from "../../../tools/synthetic-html.js";
import { webStreamsGzip } from "../core-shared--client-publisher/gzipCodec.js";
import { inflateGzip } from "../core-client/inflate/inflate.js";
import { CompressingSealer } from "../core-publisher/CompressingSealer.js";
import { openEncodedContent } from "../core-client/openEncodedContent.js";
import { ARTICLE, contentKeyOf, render, world } from "./world.js";

/** The publisher's Web Streams gzip, the client's polyfill. */
const SELECTED = { encode: webStreamsGzip.encode, decode: inflateGzip.decode };

test("a client injecting the polyfill opens what the publisher gzipped", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const body = syntheticArticle({ bytes: 30_000, seed: 8 });
  const wire = await render(new CompressingSealer(sealerConfig()), [
    { name: "bodytext", value: body },
    { name: "sidebar", value: ARTICLE },
  ]);

  for (const [contentName, expected] of [
    ["bodytext", body],
    ["sidebar", ARTICLE],
  ]) {
    const bytes = await openEncodedContent({
      record: wire.contentData[contentName],
      contentName,
      ciphertext: wire.sealedContent[contentName],
      resolveKey: () => contentKeyOf(wire, contentName, periodKeySupply),
      gzip: SELECTED,
    });
    assert.equal(utf8Decode(bytes), expected);
  }
});

test("a ciphertext the polyfill cannot read is a typed refusal, not a throw out of the loop", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const wire = await render(new CompressingSealer(sealerConfig()), [
    { name: "bodytext", value: ARTICLE },
  ]);

  // The item opens, and the bytes under it are not a gzip member: the decode
  // step refuses with the same code the extension's other path throws.
  const identity = await render(new CompressingSealer(sealerConfig({ seed: 2 })), [
    { name: "bodytext", value: ARTICLE, options: { contentEncoding: "identity" } },
  ]);

  await assert.rejects(
    () =>
      openEncodedContent({
        record: { ...identity.contentData.bodytext, contentEncodings: ["gzip"] },
        contentName: "bodytext",
        ciphertext: identity.sealedContent.bodytext,
        resolveKey: () => contentKeyOf(identity, "bodytext", periodKeySupply),
        gzip: SELECTED,
      }),
    { code: "bad_encoding" },
  );

  assert.deepEqual(wire.contentData.bodytext.contentEncodings, ["gzip"]);
});
