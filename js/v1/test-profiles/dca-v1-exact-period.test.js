// @ts-check
//
// One complete selected exact-period composition. Focused suites own the
// detailed publisher, request, issuer and cache rules; this scenario proves
// those pieces meet through their real role seams. The publisher deliberately
// omits direct content-key delivery, so plaintext cannot make this test green
// without the exact capability returned by the issuer.
//
// Requested: dca-v1-exact-period.
// Resolved: dca-v1-direct-https and dca-v1-exact-period.

import test from "node:test";
import assert from "node:assert/strict";

import { actorWorld, readArticle } from "../demo/scenarios/world.js";
import { ARTICLES, CONTENT_NAME, ISSUER_NAME, UNLOCK_URL } from "../demo/scenarios/fixtures.js";

/** @param {any} value */
function hasChainMaterial(value) {
  return JSON.stringify(value).includes("periodChain");
}

test("selected exact-period delivery opens once and reuses the retained leaf", async () => {
  const world = await actorWorld({
    relayExactPeriod: true,
    exactPeriodInput: true,
    issuerSupplyPlanFor: () => ({ directContentKeys: false }),
  });

  const exchanges = [];
  const browser = world.makeBrowser({
    relayExactPeriod: true,
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

  const pageA = await world.render("A");
  const deliveryA = pageA.asJson();
  const issuerA = deliveryA.issuerData[ISSUER_NAME];
  assert.equal(Object.hasOwn(issuerA.sealed, "contentKeys"), false);
  assert.ok(issuerA.sealed.periodKeys.premium);
  assert.ok(deliveryA.contentData[CONTENT_NAME].keys.premium.length > 0);
  assert.equal(hasChainMaterial(deliveryA), false);

  const first = await readArticle(browser, pageA, [CONTENT_NAME]);
  assert.equal(first.unlock.ok, true);
  assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);
  assert.equal(exchanges.length, 1);

  const [{ url, request, response }] = exchanges;
  assert.equal(url, UNLOCK_URL);
  assert.deepEqual(request.sealed.contentKeys, {});
  assert.ok(request.sealed.periodKeys.premium);
  assert.deepEqual(response.keys.contentKeys, {});
  assert.ok(response.keys.periodKeys.premium);
  assert.equal(hasChainMaterial(request), false);
  assert.equal(hasChainMaterial(response), false);

  const retained = await browser.cache.entries();
  assert.ok(retained.length > 0);

  const pageB = await world.render("B");
  const second = await readArticle(browser, pageB, [CONTENT_NAME]);
  assert.equal(second.unlock, null, "the retained exact leaf avoids another issuer call");
  assert.equal(second.texts[CONTENT_NAME], ARTICLES.B);
  assert.equal(exchanges.length, 1);
  assert.equal(browser.stats().unlocks, 1);
});

test("publisher material and client relay do not activate an unselected issuer", async () => {
  const world = await actorWorld({
    relayExactPeriod: true,
    exactPeriodInput: false,
    issuerSupplyPlanFor: () => ({ directContentKeys: false }),
  });
  const page = await world.render("A");
  const delivery = page.asJson();
  assert.ok(delivery.issuerData[ISSUER_NAME].sealed.periodKeys.premium);

  const read = await readArticle(world.browser, page, [CONTENT_NAME]);
  assert.equal(read.unlock.ok, false);
  assert.equal(read.unlock.status, 400);
  assert.equal(read.texts[CONTENT_NAME], null);
  assert.equal(world.servers.primary.stats().grants, 0);
});

test("exact-period route selection does not decide entitlement", async () => {
  const world = await actorWorld({
    relayExactPeriod: true,
    exactPeriodInput: true,
    issuerSupplyPlanFor: () => ({ directContentKeys: false }),
    accessPolicy: {
      decide: () => ({ contentNames: [], periodGrants: [] }),
    },
  });

  const read = await readArticle(world.browser, await world.render("A"), [CONTENT_NAME]);
  assert.equal(read.unlock.ok, false);
  assert.equal(read.unlock.status, 401);
  assert.equal(read.texts[CONTENT_NAME], null);
  assert.equal(world.servers.primary.stats().grants, 0);
});
