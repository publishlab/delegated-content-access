// @ts-check
//
// One complete selected period-key composition. Focused suites own the
// detailed publisher, request, issuer and cache rules; this scenario proves
// those pieces meet through their real role seams. The publisher deliberately
// omits item content-key delivery, so plaintext cannot make this test green
// without the period-key capability returned by the issuer.
//
// Requested: dca-profile-period-keys, with dca-profile-html-carrier for the carrier.
// Resolved: dca-profile-baseline, dca-profile-html-carrier and dca-profile-period-keys.
// Carrier as run: the demo browser reads each delivery with
// `MarkupDeliveryReader` over a root of fabricated carrier elements
// (`rootFromPage`), so the client side runs HTML-carrier extraction. No markup
// string is written or parsed here, and no test in this file crosses the
// serialized JSON document.
// The tags name the period-key duties only.

import test from "node:test";
import assert from "node:assert/strict";

import { actorWorld, readArticle } from "../demo/scenarios/world.js";
import {
  ARTICLES,
  CONTENT_NAME,
  ISSUER_NAME,
  UNLOCK_URL,
  T_NOW,
  T_NEXT,
} from "../demo/scenarios/fixtures.js";
import { issuerBlockOf, wrapsOf } from "../test-lib/helpers/inspect.js";

/** A period-only issuer: every group of the render and no item content key. */
const periodOnly = (
  /** @type {unknown} */ _issuer,
  /** @type {{ accessGroups: string[] }} */ render,
) => ({
  contentKeyNames: [],
  suppliedAccessGroups: [...render.accessGroups],
});

/**
 * The periods of a `{accessGroup, period, key}` record array under premium, in
 * array order.
 *
 * @param {any[]} records
 */
const periodsOf = (records) =>
  records.filter(({ accessGroup }) => accessGroup === "premium").map(({ period }) => period);

/** @param {any} value */
function hasChainMaterial(value) {
  const json = JSON.stringify(value);
  return json.includes('"chainKeys"');
}

test(
  "selected period-key delivery opens once and reuses the retained period key",
  {
    tags: [
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

    const exchanges = [];
    const browser = world.makeBrowser({
      relayPeriodKeys: true,
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
    const issuerA = issuerBlockOf(deliveryA, ISSUER_NAME);
    assert.equal(Object.hasOwn(issuerA.sealed, "contentKeys"), false);
    assert.ok(issuerA.sealed.periodKeys.some(({ accessGroup }) => accessGroup === "premium"));
    assert.ok(wrapsOf(deliveryA, CONTENT_NAME, "premium").length > 0);
    assert.equal(hasChainMaterial(deliveryA), false);

    const first = await readArticle(browser, pageA, [CONTENT_NAME]);
    assert.equal(first.unlock.ok, true);
    assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(exchanges.length, 1);

    const [{ url, request, response }] = exchanges;
    assert.equal(url, UNLOCK_URL);
    assert.deepEqual(request.sealed.contentKeys, []);
    assert.ok(request.sealed.periodKeys.some(({ accessGroup }) => accessGroup === "premium"));
    assert.deepEqual(response.keys.contentKeys, []);
    assert.ok(response.keys.periodKeys.some(({ accessGroup }) => accessGroup === "premium"));
    assert.equal(hasChainMaterial(request), false);
    assert.equal(hasChainMaterial(response), false);

    const retained = await browser.cache.entries();
    assert.ok(retained.length > 0);

    const pageB = await world.render("B");
    const second = await readArticle(browser, pageB, [CONTENT_NAME]);
    assert.equal(second.unlock, null, "the retained period key avoids another issuer call");
    assert.equal(second.texts[CONTENT_NAME], ARTICLES.B);
    assert.equal(exchanges.length, 1);
    assert.equal(browser.stats().unlocks, 1);
  },
);

test("publisher material and client relay do not activate an unselected issuer", async () => {
  const world = await actorWorld({
    relayPeriodKeys: true,
    periodKeyInput: false,
    issuerSupplyPlanFor: periodOnly,
  });
  const page = await world.render("A");
  const delivery = page.asJson();
  assert.ok(
    issuerBlockOf(delivery, ISSUER_NAME).sealed.periodKeys.some(
      ({ accessGroup }) => accessGroup === "premium",
    ),
  );

  const read = await readArticle(world.browser, page, [CONTENT_NAME]);
  assert.equal(read.unlock.ok, false);
  assert.equal(read.unlock.status, 400);
  assert.equal(read.texts[CONTENT_NAME], null);
  assert.equal(world.servers.primary.stats().grants, 0);
});

test("period-key route selection does not decide entitlement", async () => {
  const world = await actorWorld({
    relayPeriodKeys: true,
    periodKeyInput: true,
    issuerSupplyPlanFor: periodOnly,
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

test(
  "a partial period-key grant retains only the authorized period and cannot open the next one",
  {
    tags: [
      "dca-profile-period-keys/publisher/period-key-supply",
      "dca-profile-period-keys/issuer/period-key-result",
      "dca-profile-period-keys/client/period-key-admission",
    ],
  },
  async () => {
    let decisions = 0;
    const world = await actorWorld({
      relayPeriodKeys: true,
      periodKeyInput: true,
      issuerSupplyPlanFor: periodOnly,
      accessPolicy: {
        decide(_claims, presented) {
          decisions += 1;
          assert.deepEqual(presented.contentNames, []);
          assert.deepEqual(presented.accessGroups, ["premium"]);
          return {
            contentNames: [],
            periodGrants:
              decisions === 1
                ? [
                    {
                      accessGroup: "premium",
                      periods: presented.periodCoordinates.premium.slice(0, 1),
                    },
                  ]
                : [],
          };
        },
      },
    });
    const exchanges = [];
    const browser = world.makeBrowser({
      relayPeriodKeys: true,
      network: {
        async post(url, request, options) {
          const answer = await world.network.post(url, request, options);
          exchanges.push({
            request: JSON.parse(JSON.stringify(request)),
            response: JSON.parse(JSON.stringify(answer.body)),
          });
          return answer;
        },
      },
    });
    const pageA = await world.render("A");
    assert.equal(issuerBlockOf(pageA.asJson(), ISSUER_NAME).sealed.contentKeys, undefined);
    assert.deepEqual(periodsOf(issuerBlockOf(pageA.asJson(), ISSUER_NAME).sealed.periodKeys), [
      T_NOW,
      T_NEXT,
    ]);
    const first = await readArticle(browser, pageA, [CONTENT_NAME]);
    assert.equal(first.unlock.ok, true);
    assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);
    assert.deepEqual(periodsOf(exchanges[0].request.sealed.periodKeys), [T_NOW, T_NEXT]);
    assert.deepEqual(periodsOf(exchanges[0].response.keys.periodKeys), [T_NOW]);
    assert.deepEqual(exchanges[0].response.keys.contentKeys, []);
    assert.deepEqual(
      (await browser.cache.entries()).map(({ t }) => t),
      [T_NOW],
    );

    world.clock.advance(60 * 60 * 1000);
    const pageB = await world.render("B");
    assert.equal(
      wrapsOf(pageB.asJson(), CONTENT_NAME, "premium").some(({ period }) => period === T_NOW),
      false,
    );
    const second = await readArticle(browser, pageB, [CONTENT_NAME]);
    assert.equal(second.unlock.ok, false);
    assert.equal(second.unlock.status, 401);
    assert.equal(second.texts[CONTENT_NAME], null);
    assert.equal(exchanges.length, 2, "the ungranted next period needs a new issuer decision");
    assert.equal(decisions, 2);
    assert.equal(exchanges[1].response.keys, undefined);
    assert.equal(
      (await browser.cache.entries()).some(({ t }) => t === T_NEXT),
      false,
    );
  },
);
