// @ts-check
//
// The polyfill as a client selects it: injected as the decode half of the
// extension's `Gzip`, over a render this extension's publisher produced. Nothing
// in the extension imports the polyfill, so this test covers the whole path by
// which it reaches a client.

import test from "node:test";
import assert from "node:assert/strict";

import { utf8Decode, utf8Encode } from "../../../core-shared/codec.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { syntheticArticle } from "../../../tools/synthetic-html.js";
import { webStreamsGzip } from "../core-shared--client-publisher/gzipCodec.js";
import { inflateGzip } from "../core-shared--client-publisher/inflate/inflate.js";
import { CompressingSealer } from "../core-publisher/CompressingSealer.js";
import { openEncodedContent } from "../core-client/openEncodedContent.js";
import { ARTICLE, contentKeyOf, itemOf, render, world } from "./world.js";

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
      item: itemOf(wire, contentName),
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

  // A publisher declared gzip over bytes that are not a gzip member. The item
  // opens, and the polyfill's decode step refuses with the same code the
  // extension's other path throws.
  const mislabeled = await render(new Sealer(sealerConfig({ seed: 2 })), [
    {
      name: "bodytext",
      value: { bytes: utf8Encode(ARTICLE), contentType: "text/html", contentEncodings: ["gzip"] },
    },
  ]);
  await assert.rejects(
    () =>
      openEncodedContent({
        item: itemOf(mislabeled, "bodytext"),
        ciphertext: mislabeled.sealedContent.bodytext,
        resolveKey: () => contentKeyOf(mislabeled, "bodytext", periodKeySupply),
        gzip: SELECTED,
      }),
    { code: "bad_encoding" },
  );

  // A gzip label added to an identity item on the way to the client changes
  // the content AAD, so the tag refuses it before the polyfill sees a byte.
  const identity = await render(new CompressingSealer(sealerConfig({ seed: 3 })), [
    { name: "bodytext", value: ARTICLE, options: { contentEncoding: "identity" } },
  ]);
  const relabeled = structuredClone(identity);
  relabeled.contentData.bodytext.contentEncodings = ["gzip"];
  await assert.rejects(
    () =>
      openEncodedContent({
        item: itemOf(relabeled, "bodytext"),
        ciphertext: relabeled.sealedContent.bodytext,
        resolveKey: () => contentKeyOf(relabeled, "bodytext", periodKeySupply),
        gzip: SELECTED,
      }),
    { code: "bad_encoding" },
  );

  assert.deepEqual(wire.contentData.bodytext.contentEncodings, ["gzip"]);
});
