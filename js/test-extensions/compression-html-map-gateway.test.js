// @ts-check
//
// A gzip-represented item placed by the HTML content map, through the real
// publisher (`createPublisher` with a pre-encoded descriptor), the admitting
// map writer, the real issuer core and the server-side `createHtmlGateway`.
//
// The map selects no decoder. A host that serves compressed items passes the
// compression extension's registry through `clientOptions.contentDecoders`,
// the same option `createBrowserClient` takes. Without it the compressed item
// fails on its own: the identity item still opens, and the report names the
// failed item rather than calling it locked, because the issuer did not refuse
// anything (docs/spec-proposal--html-content-map.md Section 9, `item_failed`).

import test from "node:test";
import assert from "node:assert/strict";

import { utf8Encode } from "../core-shared/codec.js";
import {
  ENCODING,
  decoders,
  encode,
} from "../extensions/content-compression/core-shared--client-publisher/gzipCodec.js";
import { writeMappedDelivery } from "../extensions/html-content-map/adapter-publisher/writeMappedDelivery.js";
import { createHtmlGateway } from "../extensions/html-content-map/integration-client/createHtmlGateway.js";
import {
  ARTICLE_MAP,
  BODYTEXT,
  FACTBOX,
  ISSUER_NAME,
  UNLOCK_URL,
  articlePage,
  mapWorld,
} from "../extensions/html-content-map/test/world.js";

const URL = "https://pub.example/articles/harbour";

/** One admitted page whose bodytext is gzip and whose factbox is identity. */
async function compressedArticle() {
  const world = await mapWorld();
  const render = await world.publish({
    items: [
      {
        name: "bodytext",
        value: /** @type {any} */ ({
          bytes: await encode(utf8Encode(BODYTEXT)),
          contentType: "text/html",
          contentEncodings: [ENCODING],
        }),
      },
      { name: "factbox", value: FACTBOX, contentType: "text/html" },
    ],
    page: articlePage,
  });
  assert.deepEqual(render.dcaData.contentData.bodytext.contentEncodings, [ENCODING]);
  const html = writeMappedDelivery({
    dcaData: render.dcaData,
    sealedContent: render.sealedContent,
    contentMap: ARTICLE_MAP,
    page: articlePage,
    items: { bodytext: BODYTEXT, factbox: FACTBOX },
  });
  return { world, html };
}

/**
 * @param {any} world
 * @param {string} html
 * @param {object} [clientOptions]
 */
function gatewayOver(world, html, clientOptions) {
  return createHtmlGateway({
    sources: [{ origin: world.origin }],
    registrations: [{ id: "pub", keys: { [world.signingKid]: world.signingPublicKey } }],
    fetch: async (url) => ({
      status: url === URL ? 200 : 404,
      headers: {
        get: (/** @type {string} */ name) =>
          name === "content-type" && url === URL ? "text/html; charset=utf-8" : null,
      },
      body: new Response(url === URL ? html : "").body,
    }),
    issuerName: ISSUER_NAME,
    issuerEndpoint: UNLOCK_URL,
    admitCaller: () => true,
    transport: world.transport,
    ...(clientOptions === undefined ? {} : { clientOptions }),
  });
}

test("a gateway with the gzip registry in clientOptions places the compressed item", async () => {
  const { world, html } = await compressedArticle();
  const result = await gatewayOver(world, html, { contentDecoders: decoders }).reconstruct({
    url: URL,
    callerContext: "caller",
  });
  assert.deepEqual(result.report, {
    outcome: "complete",
    items: { bodytext: "opened", factbox: "opened" },
  });
  assert.ok(result.html?.includes("<p>The council voted 7-2 to rezone the harbour.</p>"));
  assert.ok(result.html?.includes("<li>Area: <b>north quay</b></li>"));
  assert.equal(world.unlocks.length, 1);
  assert.deepEqual(Object.keys(world.unlocks[0].request.sealed.contentKeys).sort(), [
    "bodytext",
    "factbox",
  ]);
});

test("a gateway without a gzip decoder fails only the compressed item and opens the other", async () => {
  const { world, html } = await compressedArticle();
  const result = await gatewayOver(world, html).reconstruct({ url: URL, callerContext: "caller" });
  assert.deepEqual(result.report, {
    outcome: "failed",
    failure: "item_failed",
    items: { bodytext: "failed", factbox: "opened" },
  });
  assert.equal(result.html, null);
  assert.equal(result.reconstructed, false);
});
