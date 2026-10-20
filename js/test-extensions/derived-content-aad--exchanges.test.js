// @ts-check
//
// Derived content AAD across real exchanges: every cell renders with a stock
// publisher, unlocks at a real issuer and opens through a public client, with no
// AAD carried on the wire (docs/spec--content-protection.md Sections 3.2, 3.3 and
// 5.4). The matrix is built from what this repository composes, not from the
// full product of the axes.
//
// Covered (14 cells):
// - carrier {JSON delivery, HTML carrier} x key route {item content key from the
//   issuer, period key opening the cached wrap, chain key from which the client
//   derives the ordinary period key (chain-keys extension)} x response transport
//   {direct, client-bound ECDH-P256}: 12 cells through `createDeliveryClient`
//   (JSON) and `createBrowserClient` (HTML) against a demo `IssuerServer`.
// - content-groups extension x {JSON, HTML} x direct: 2 cells. The page
//   crosses the stock JSON and markup writers, and `createDeliveryClient` with
//   the extension's client bundle reads it through the stock JSON or markup
//   reader and opens it.
//
// Not exercised here, though composed elsewhere: content-groups over
// client-bound transport (js/test-extensions/content-groups-composition.test.js),
// the RSA-OAEP client-bound method
// (js/test-extensions/client-bound-chain-keys-admission.test.js), fallback and
// multi-issuer routes, and the html-content-map gateway.

import test from "node:test";
import assert from "node:assert/strict";
import { decrypt } from "../core-shared/aead.js";
import { base64urlDecode } from "../core-shared/codec.js";
import { writeJsonDelivery } from "../adapter-publisher/writeJsonDelivery.js";
import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { JsonDeliveryReader } from "../adapter-client/JsonDeliveryReader.js";
import { MarkupDeliveryReader } from "../adapter-client/MarkupDeliveryReader.js";
import { domOver } from "../test-lib/helpers/domOver.js";
import { contentAadOctets } from "../test-reference/support/contentAadOctets.js";
import {
  item as groupItem,
  world as groupsWorld,
} from "../extensions/content-groups/test/_lib/world.js";
import { BODY, GROUP, LOCKED, exchangeWorld } from "./support/derivedContentAadExchanges.js";

/** @param {Uint8Array} bytes */
const text = (bytes) => new TextDecoder().decode(bytes);

const ROUTES = /** @type {const} */ (["item", "period", "chain"]);
const TRANSPORTS = /** @type {const} */ (["direct", "client-bound"]);
const CARRIERS = /** @type {const} */ (["json", "html"]);

/**
 * The key family the issuer's answer used for the route under test, and only
 * that one.
 *
 * @param {"item"|"period"|"chain"} route
 * @param {any} body
 */
function assertRoute(route, body) {
  const keys = body.keys;
  const count = (/** @type {any} */ section) =>
    Object.values(section ?? {}).reduce(
      (/** @type {number} */ n, /** @type {any} */ v) => n + Object.keys(v).length,
      0,
    );
  if (route === "item") {
    assert.ok(Object.keys(keys.contentKeys ?? {}).length > 0, "item keys delivered");
    assert.equal(count(keys.periodKeys) + count(keys.chainKeys), 0);
  } else if (route === "period") {
    assert.deepEqual(keys.contentKeys ?? {}, {});
    assert.ok(count(keys.periodKeys) > 0, "period keys delivered");
    assert.equal(count(keys.chainKeys), 0);
  } else {
    assert.deepEqual(keys.contentKeys ?? {}, {});
    assert.ok(Object.keys(keys.chainKeys?.[GROUP] ?? {}).length > 0, "a chain key delivered");
    assert.equal(count(keys.periodKeys), 0);
  }
}

test("exchange matrix: every supported cell opens each item to its plaintext under the derived AAD", async (t) => {
  for (const route of ROUTES) {
    for (const transport of TRANSPORTS) {
      for (const carrier of CARRIERS) {
        await t.test(`${carrier} x ${route} x ${transport}`, async () => {
          const w = await exchangeWorld({ route, transport });
          const rendered = await w.render();
          for (const item of [BODY, LOCKED]) {
            assert.equal(Object.hasOwn(rendered.dcaData.contentData[item.name], "aad"), false);
          }
          const state = await w.readerState();
          const client = w.clientFor(rendered, carrier, state);
          for (const item of [BODY, LOCKED]) {
            const opened = await client.open(item.name);
            assert.equal(text(opened.bytes), item.value);
            assert.equal(opened.contentType, item.contentType);
          }
          const answer = w.answers[0];
          assert.equal(answer.status, 200);
          assertRoute(route, answer.body);
          assert.equal(
            answer.body.transport === undefined ? "direct" : "client-bound",
            transport,
            "the answer used the transport under test",
          );

          if (route === "item" && transport === "direct") {
            // The raw item key against octets spelled by hand: the publisher
            // sealed under the written transcript, not only under the module.
            const key = base64urlDecode(answer.body.keys.contentKeys[BODY.name]);
            const plain = await decrypt(
              key,
              new Uint8Array(12),
              base64urlDecode(rendered.sealedContent[BODY.name]),
              contentAadOctets(rendered.dcaData, BODY.name),
            );
            assert.equal(text(plain), BODY.value);
          }

          if (route !== "item") {
            // The grant is reusable: a later render of the same resource in the
            // same period opens from the retained keys with no request.
            const sent = w.answers.length;
            const later = await w.render();
            const again = w.clientFor(later, carrier, state);
            assert.equal(text((await again.openLocal(LOCKED.name)).bytes), LOCKED.value);
            assert.equal(w.answers.length, sent);
          }
        });
      }
    }
  }

  for (const carrier of CARRIERS) {
    await t.test(`${carrier} x content-groups x direct`, async () => {
      const w = await groupsWorld();
      const items = ["sportsArticle", "sportsBrief"];
      const published = await w.publish({
        items: items.map((name) => groupItem(name, ["sports"], `plaintext:${name}`)),
      });
      const deliveryReader = overCarrier(published, carrier);
      for (const name of items) {
        assert.equal(Object.hasOwn(deliveryReader.dcaData.contentData[name], "aad"), false);
      }
      const client = w.reader().client(published, w.issuer(), { deliveryReader });
      assert.deepEqual((await client.unlock(items)).missing, []);
      for (const name of items) {
        assert.equal(await client.open(name), `plaintext:${name}`, name);
      }
    });
  }
});

/**
 * One content-groups page across a stock carrier, as the stock reader of that
 * carrier reads it.
 *
 * @param {{ page: any, sealedContent: Record<string, string>, origin: string }} published
 * @param {"json"|"html"} carrier
 */
function overCarrier({ page, sealedContent, origin }, carrier) {
  const render = { dcaData: page, sealedContent };
  return carrier === "json"
    ? new JsonDeliveryReader(writeJsonDelivery(render), { publisherOrigin: origin })
    : new MarkupDeliveryReader(domOver(writeMarkupDelivery(render), { publisherOrigin: origin }));
}

test("chain-derived grant: a record moved to another slot fails, and a carried old AAD does not help", async () => {
  const w = await exchangeWorld({ route: "chain", transport: "direct" });
  const rendered = JSON.parse(JSON.stringify(await w.render()));
  const state = await w.readerState();
  const grantee = w.clientFor(rendered, "json", state);
  assert.equal(text((await grantee.open(BODY.name)).bytes), BODY.value);
  assertRoute("chain", w.answers[0].body);

  const moved = structuredClone(rendered);
  moved.dcaData.contentData[BODY.name] = rendered.dcaData.contentData[LOCKED.name];
  moved.sealedContent[BODY.name] = rendered.sealedContent[LOCKED.name];
  for (const carried of [undefined, "article-42|1|locked-data"]) {
    const copy = structuredClone(moved);
    if (carried !== undefined) copy.dcaData.contentData[BODY.name].aad = carried;
    const reader = w.clientFor(copy, "json", state);
    assert.ok(
      (await reader.resolver.contentKeyFor(reader.dcaData, BODY.name)) instanceof Uint8Array,
      "the chain-derived period key still recovers the moved record's key",
    );
    await assert.rejects(reader.openLocal(BODY.name), { code: "decrypt_failed" });
  }
  assert.equal(w.answers.length, 1, "nothing was retried at the issuer");
});
