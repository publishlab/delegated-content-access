// @ts-check
//
// One selected gzip representation whose content key arrives through a
// reusable period key instead of an item content key. The publisher
// compresses before sealing, the issuer handles only key routes, and the client
// opens the item under the key from the returned period key before it reverses
// gzip. A second compressed article in the same period opens from that
// retained period key without another issuer call.
//
// Requested: dca-profile-content-compression for the single-layer sequence
// ["gzip"], dca-profile-period-keys for the key route, and dca-profile-html-carrier for
// the carrier. Resolved: dca-profile-baseline, dca-profile-content-compression,
// dca-profile-html-carrier and dca-profile-period-keys. The publisher omits the item
// content-key route, so plaintext cannot make this test green without the
// period-key capability returned by the issuer.
// Carrier as run: the demo browser reads each delivery with
// `MarkupDeliveryReader` over a root of fabricated carrier elements
// (`rootFromPage`), so the client side runs HTML-carrier extraction. No markup
// string is written or parsed here, and no test in this file crosses the
// serialized JSON document.
// The tags name the representation, compression and period-key duties only.
//
// Focused suites own the other cases: a client without gzip refusing only the
// marked item (extensions/content-compression/test/base-client-cost.test.js),
// authentication failing before any decoder runs
// (test-reference/core-client/wire-lookup-client.test.js), and unselected
// period-key relay or issuer input (dca-profile-period-keys.test.js).

import test from "node:test";
import assert from "node:assert/strict";

import { base64urlDecode, base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import { actorWorld, readArticle } from "../demo/scenarios/world.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  CONTENT_NAME,
  CONTENT_TYPE,
  DOMAIN,
  ISSUER_NAME,
  SIGNING_KID,
  T_NEXT,
  T_NOW,
  UNLOCK_URL,
} from "../demo/scenarios/fixtures.js";
import { Page } from "../demo/support/Page.js";
import {
  contentRecordOf,
  issuerBlockOf,
  sealedContentOf,
  wrapsOf,
} from "../test-lib/helpers/inspect.js";
import { originForHost } from "../demo/support/provisioning.js";
import { CompressingSealer } from "../extensions/content-compression/core-publisher/CompressingSealer.js";
import {
  ENCODING,
  decoders,
  encode,
  decode,
} from "../extensions/content-compression/core-shared--client-publisher/gzipCodec.js";

// AES-GCM appends a 16-octet tag to the sealed plaintext.
const TAG_LENGTH = 16;

/** A period-only issuer: every group of the render and no item content key. */
const periodOnly = (
  /** @type {unknown} */ _issuer,
  /** @type {{ accessGroups: string[] }} */ render,
) => ({
  contentKeyNames: [],
  suppliedAccessGroups: [...render.accessGroups],
});

/**
 * Where each key resolution of one page load found the content key.
 *
 * @param {any} load
 * @returns {[string, string][]} operation and origin kind, in order
 */
function keyRoute(load) {
  return load
    .stats()
    .keyResolutions.flatMap((/** @type {any} */ entry) =>
      entry.origins.map((/** @type {any} */ origin) => [entry.operation, origin.kind]),
    );
}

test(
  "gzip opens through a returned period key and reuses it for the next article",
  {
    tags: [
      "dca-profile-baseline/publisher/representation-declaration",
      "dca-profile-content-compression/publisher/gzip-compression",
      "dca-profile-content-compression/client/gzip-decompression",
      "dca-profile-period-keys/publisher/period-key-supply",
      "dca-profile-period-keys/issuer/period-key-result",
      "dca-profile-period-keys/client/period-key-admission",
    ],
  },
  async () => {
    const world = await actorWorld({
      relayPeriodKeys: true,
      periodKeyInput: true,
      issuerSupplyPlanFor: periodOnly,
    });
    const origin = originForHost(DOMAIN);

    // The publisher's gzip records what it compressed and what it produced.
    /** @type {{ input: Uint8Array, output: Uint8Array }[]} */
    const encoded = [];
    const gzip = {
      encode: async (/** @type {Uint8Array} */ bytes) => {
        const output = await encode(bytes);
        encoded.push({ input: Uint8Array.from(bytes), output: Uint8Array.from(output) });
        return output;
      },
      decode,
    };

    /** @param {'A'|'B'} label */
    const compressedRender = async (label) => {
      const sealer = new CompressingSealer(
        {
          origin,
          clock: world.clock,
          random: world.random,
          signingKeys: { [SIGNING_KID]: world.signingKeys.privateKey },
          signingKid: SIGNING_KID,
          periodKeySupply: world.periodKeySupply,
          issuerSupplyPlanFor: periodOnly,
          issuers: world.issuers,
        },
        { gzip },
      );
      sealer.resource(`12345${label.charCodeAt(0)}`, { section: "politics" });
      sealer.content(CONTENT_NAME, ARTICLES[label], CONTENT_TYPE, { accessGroups: [ACCESS_GROUP] });
      const { dcaData, sealedContent } = await sealer.seal();
      return new Page({ publisherOrigin: origin, dcaData, sealedContent });
    };

    // The client's gzip entry records the bytes the opener hands it.
    /** @type {Uint8Array[]} */
    const decoderInputs = [];
    const exchanges = [];
    const browser = world.makeBrowser({
      relayPeriodKeys: true,
      contentDecoders: {
        [ENCODING]: async (/** @type {Uint8Array} */ bytes) => {
          decoderInputs.push(Uint8Array.from(bytes));
          return decoders[ENCODING](bytes);
        },
      },
      network: {
        async post(url, request, options) {
          const answer = await world.network.post(url, request, options);
          exchanges.push({
            url,
            request: JSON.parse(JSON.stringify(request)),
            response: JSON.parse(JSON.stringify(answer.body)),
          });
          return answer;
        },
      },
    });

    // Publisher: gzip runs on the article bytes before sealing, the item names
    // the selected layer, and only the period-key route reaches the issuer.
    const pageA = await compressedRender("A");
    const deliveryA = pageA.asJson();
    const recordA = contentRecordOf(deliveryA, CONTENT_NAME);
    assert.deepEqual(recordA.contentEncodings, [ENCODING]);
    assert.equal(recordA.contentType, CONTENT_TYPE);
    assert.equal(encoded.length, 1);
    assert.deepEqual(encoded[0].input, utf8Encode(ARTICLES.A));
    assert.equal(
      base64urlDecode(sealedContentOf(deliveryA, CONTENT_NAME) ?? "").length,
      encoded[0].output.length + TAG_LENGTH,
      "the sealed plaintext is the gzip output",
    );
    const issuerA = issuerBlockOf(deliveryA, ISSUER_NAME);
    assert.equal(Object.hasOwn(issuerA.sealed, "contentKeys"), false);
    assert.ok(issuerA.sealed.periodKeys.some(({ accessGroup }) => accessGroup === ACCESS_GROUP));
    assert.ok(wrapsOf(deliveryA, CONTENT_NAME, ACCESS_GROUP).length > 0);

    // Issuer: one exchange returns the period keys for the render's two periods
    // and no content key. The representation list never reaches the request.
    const first = await readArticle(browser, pageA, [CONTENT_NAME]);
    assert.equal(first.unlock.ok, true);
    assert.equal(exchanges.length, 1);
    const [{ url, request, response }] = exchanges;
    assert.equal(url, UNLOCK_URL);
    assert.deepEqual(request.sealed.contentKeys, []);
    assert.ok(request.sealed.periodKeys.some(({ accessGroup }) => accessGroup === ACCESS_GROUP));
    assert.equal(JSON.stringify(request).includes("contentEncodings"), false);
    assert.deepEqual(response.keys.contentKeys, []);
    assert.deepEqual(response.keys.periodKeys, [
      {
        accessGroup: ACCESS_GROUP,
        period: T_NOW,
        key: base64urlEncode(await world.periodKeySupply.derive(ACCESS_GROUP, T_NOW)),
      },
      {
        accessGroup: ACCESS_GROUP,
        period: T_NEXT,
        key: base64urlEncode(await world.periodKeySupply.derive(ACCESS_GROUP, T_NEXT)),
      },
    ]);

    // Client: after the unlock the resolver unwraps the item key with the
    // cached period key and holds it for this render, and the open uses that
    // held key. The authenticated plaintext reaching gzip is the publisher's gzip
    // output, and the reversed bytes are the article.
    assert.deepEqual(keyRoute(first.load), [
      ["resolve", "missing"],
      ["re-resolve-after-unlock", "cached-period-key"],
      ["open", "held-content-key"],
    ]);
    assert.equal(decoderInputs.length, 1);
    assert.deepEqual(decoderInputs[0], encoded[0].output);
    assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);

    // Second article, same client and period: the cached period key resolves
    // its key with no unlock, and gzip again receives the decrypted gzip output.
    const pageB = await compressedRender("B");
    assert.deepEqual(contentRecordOf(pageB.asJson(), CONTENT_NAME).contentEncodings, [ENCODING]);
    const second = await readArticle(browser, pageB, [CONTENT_NAME]);
    assert.equal(second.unlock, null, "the retained period key avoids another issuer call");
    assert.equal(exchanges.length, 1);
    assert.equal(browser.stats().unlocks, 1);
    assert.deepEqual(keyRoute(second.load), [
      ["resolve", "cached-period-key"],
      ["open", "held-content-key"],
    ]);
    assert.equal(decoderInputs.length, 2);
    assert.deepEqual(decoderInputs[1], encoded[1].output);
    assert.equal(second.texts[CONTENT_NAME], ARTICLES.B);
  },
);
