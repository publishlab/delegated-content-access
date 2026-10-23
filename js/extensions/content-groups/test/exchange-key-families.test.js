// @ts-check
//
// The generic `keyFamilies` seam of a selected request builder. A request
// carrying only extension coordinates is an eligible route, and the same
// coordinates stay under the strict-endpoint and raw-custody guards: a client
// that selected client-bound transport never silently takes derivation keys
// direct.

import test from "node:test";
import assert from "node:assert/strict";

import { A, URL_OF, WidgetRequestBuilder, world } from "./_lib/widgetRequests.js";

const OFFER = { kty: "EC", crv: "P-256", x: "x", y: "y" };
const capability = { publicKey: OFFER, openDeliveredKeys: async () => null };

test("a request with only extension coordinates is an eligible route", async () => {
  const { client, posted } = world({});
  const result = await client.unlock(["bodytext"]);
  assert.equal(result.skipped, undefined);
  assert.equal(posted.length, 1);
  assert.deepEqual(posted[0].request.requestedWidgets, { bodytext: ["w1", "w2"] });
  assert.deepEqual(posted[0].request.sealed.contentKeys, []);
});

test("without keyFamilies, extension-only coordinates are no eligible route", async () => {
  const builder = new WidgetRequestBuilder();
  Object.defineProperty(builder, "keyFamilies", { value: undefined });
  const { client, posted } = world({ builder });
  assert.deepEqual(await client.unlock(["bodytext"]), {
    skipped: "no-eligible-route",
    application: null,
  });
  assert.equal(posted.length, 0);
});

test("a strict endpoint refuses extension coordinates without a client-bound offer", async () => {
  const { client, posted } = world({ acceptDirectResponse: false });
  await assert.rejects(client.unlock(["bodytext"]), {
    code: "bad_config",
    message: /strict endpoint needs a client-bound offer/,
  });
  assert.equal(posted.length, 0);
});

test("a client-bound client never takes extension derivation keys direct", async () => {
  const builder = new WidgetRequestBuilder({ clientPublicKey: OFFER });
  const { client, posted } = world({
    builder,
    acceptDirectResponse: true,
    options: { clientBoundKeyCapability: capability, acceptDirectFallback: true },
  });
  await assert.rejects(client.unlock(["bodytext"]), {
    code: "bad_config",
    message: /raw key custody/,
  });
  assert.equal(posted.length, 0);
});

test("the custody guard admits extension derivation keys only with raw custody", async () => {
  const builder = new WidgetRequestBuilder({ clientPublicKey: OFFER });
  const { client, posted } = world({
    builder,
    acceptDirectResponse: true,
    options: {
      clientBoundKeyCapability: capability,
      acceptDirectFallback: true,
      persistRawPeriodKeys: true,
    },
  });
  await client.unlock(["bodytext"]);
  assert.equal(posted.length, 1);
});

test("extension item content keys need no raw custody", async () => {
  const builder = new WidgetRequestBuilder({ clientPublicKey: OFFER });
  builder.returns = { contentKeys: true, familyKeys: false };
  const { client, posted } = world({
    builder,
    acceptDirectResponse: true,
    options: { clientBoundKeyCapability: capability, acceptDirectFallback: true },
  });
  await client.unlock(["bodytext"]);
  assert.equal(posted.length, 1);
  assert.equal(posted[0].issuer, A);
  assert.equal(URL_OF[A], "https://a.example/unlock");
});
