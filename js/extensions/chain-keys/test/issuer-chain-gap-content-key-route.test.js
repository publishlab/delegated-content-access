// @ts-check
//
// Chain-only issuer supply at a read coordinate: article coordinates remain
// independent of the optional current-forward horizon and its supply gaps.
//
// The publisher supplies the item's old window and a later window, while the
// issuer's current coordinate falls in the intervening gap. An explicit old
// target can still use its independently rooted source; without a selector,
// only the future horizon is considered and it stops at the gap.

import test from "node:test";
import assert from "node:assert/strict";

import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { referenceChainKeyProfile } from "../referenceProfile.js";
import { actorWorld } from "../../../demo/scenarios/world.js";
import { rootFromPage } from "../../../demo/support/queryableRoot.js";
import { ACCESS_GROUP, AT, CONTENT_NAME, ISSUER_NAME } from "../../../demo/scenarios/fixtures.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import {
  chainBrowser,
  chainGeneration,
  chainPartition,
  chainSupply,
  coordinatesOf,
  deliveryPlan,
  exchangesPosted,
} from "./world.js";

/**
 * Terminal labels of the render's window and of the window after next. The
 * window between them, [251024T0000, 251024T1145], has no member.
 */
const RENDER_WINDOW_TERMINAL = "251023T2345";
const NEXT_WINDOW_TERMINAL = "251024T1145";
const LATER_WINDOW_TERMINAL = "251024T2345";

/** Five minutes into the missing window: the issuer's current coordinate is 251024T0000. */
const ISSUER_AT = "2025-10-24T00:05:00Z";

/**
 * Sixty-four periods from 251024T0000 run past the missing window's 48 and
 * into the later window. A grant this wide gives a gap-skipping selection
 * something to find.
 */
const FUTURE_PERIOD_COUNT = 64;

/**
 * The publisher's supply over two windows that do not touch: the render's own
 * and the one after next. A family carries at most two chain members, and the
 * publisher decides which windows they are. The period keys and the geometry
 * stay as the frozen supply planned them; only the supplied labels change, and
 * each capability comes from the same generation.
 *
 * @param {any} generation
 * @param {string[]} suppliedTs
 */
function supplyAt(generation, suppliedTs) {
  const supply = chainSupply(generation);
  return {
    derive: (/** @type {string} */ accessGroup, /** @type {string} */ t) =>
      supply.derive(accessGroup, t),
    familyPlan(
      /** @type {string} */ accessGroup,
      /** @type {Date} */ now,
      /** @type {object} */ period,
    ) {
      const plan = supply.familyPlan(accessGroup, now, period);
      return {
        ...plan,
        chain: {
          geometry: plan.chain.geometry,
          suppliedTs,
          capabilityAt: async (/** @type {string} */ t) =>
            (await generation.chainCapability(accessGroup, t)).key,
        },
      };
    },
  };
}

/** Grants requested coordinates and a separately bounded forward horizon. */
const accessPolicy = {
  decide(/** @type {any} */ _claims, /** @type {any} */ requested) {
    return {
      contentNames: requested.contentNames,
      periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
        accessGroup,
        futurePeriodCount: FUTURE_PERIOD_COUNT,
        authorizePeriod: () => true,
      })),
    };
  },
};

/** A focused control suppressing the optional unsigned article selector. */
function chainBrowserWithoutArticleTargets(world) {
  return world.makeBrowser({
    chainKeyStrategy: "retain",
    requestBuilderFactory: (/** @type {object} */ options) => new ChainKeyRequestBuilder(options),
    network: {
      post: (/** @type {string} */ url, /** @type {any} */ request, /** @type {any} */ options) => {
        const transported = JSON.parse(JSON.stringify(request));
        delete transported.requestedPeriodKeys;
        return world.network.post(url, transported, options);
      },
    },
  });
}

test("without article targets, a future chain horizon stops at the current supply gap", async () => {
  const generation = chainGeneration(7);
  const chainCache = new ChainKeyCache({ strategy: "retain" });
  const world = await actorWorld({
    at: AT,
    periodKeySupply: supplyAt(generation, [RENDER_WINDOW_TERMINAL, LATER_WINDOW_TERMINAL]),
    issuerSupplyPlanFor: deliveryPlan(() => ["chain-keys"]),
    accessPolicy,
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => chainCache,
    primary: { periodGrantKind: "chain-keys" },
  });
  const browser = chainBrowserWithoutArticleTargets(world);

  const page = await world.render("A");
  const sealed = page.asJson().issuerData[ISSUER_NAME].sealed;
  assert.deepEqual(
    Object.keys(sealed.chainKeys[ACCESS_GROUP]).sort(),
    [RENDER_WINDOW_TERMINAL, LATER_WINDOW_TERMINAL],
    "the publisher supplies the render's window and the later one, with a gap between",
  );
  assert.equal(sealed.periodKeys, undefined, "and no period-key supply beside the chain");
  assert.equal(
    typeof sealed.contentKeys[CONTENT_NAME],
    "string",
    "and a content-key route for the item",
  );
  assert.deepEqual(
    coordinatesOf(page),
    ["251023T1415", "251023T1430"],
    "the item's wraps sit in the render's window, the older one",
  );

  world.clock.set(ISSUER_AT);
  const load = browser.load(rootFromPage(page));
  assert.deepEqual(await load.resolve([CONTENT_NAME]), { covered: [], missing: [CONTENT_NAME] });

  const { result: unlock, exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.equal(unlock.ok, true);
  assert.equal(unlock.issuerName, ISSUER_NAME);
  assert.equal(exchanges.length, 1, "one issuer was asked once");
  const [exchange] = exchanges;
  assert.deepEqual(
    Object.keys(exchange.request.sealed.chainKeys[ACCESS_GROUP]).sort(),
    [RENDER_WINDOW_TERMINAL, LATER_WINDOW_TERMINAL],
    "the client relayed both members, so the issuer held both windows to choose from",
  );
  assert.equal(Object.hasOwn(exchange.request, "requestedPeriodKeys"), false);
  assert.equal(exchange.status, 200);
  assert.deepEqual(
    Object.keys(exchange.body.keys),
    ["contentKeys"],
    "the answer carries the item key and no period key or chain capability from either window",
  );
  assert.deepEqual(Object.keys(exchange.body.keys.contentKeys), [CONTENT_NAME]);
  assert.equal(exchange.body.errors, undefined, "a gap clamps the selection and is no error");
  assert.equal(world.servers.primary.stats().grants, 1);

  assert.deepEqual(await browser.cache.entries(), [], "the client filed no period key");
  assert.deepEqual(chainCache.entries(), [], "and no chain capability");
  assert.deepEqual(
    await chainPartition(chainCache, world, coordinatesOf(page)[0]),
    [],
    "so nothing reaches back into the older window where the item's wraps sit",
  );

  const [, afterUnlock] = load.stats().keyResolutions;
  assert.deepEqual(afterUnlock, {
    operation: "re-resolve-after-unlock",
    origins: [{ contentName: CONTENT_NAME, kind: "held-content-key" }],
  });
  const opened = await load.open(CONTENT_NAME);
  assert.equal(opened.error, null);
  assert.match(
    utf8Decode(/** @type {Uint8Array} */ (opened.bytes)),
    /rezone the harbour/,
    "the content-key route opens the item",
  );
});

test("an explicit old article target is served from its own window alongside current-forward access", async () => {
  const generation = chainGeneration(7);
  const world = await actorWorld({
    at: AT,
    periodKeySupply: supplyAt(generation, [RENDER_WINDOW_TERMINAL, NEXT_WINDOW_TERMINAL]),
    issuerSupplyPlanFor: deliveryPlan(() => ["chain-keys"]),
    accessPolicy: {
      decide(_claims, requested) {
        return {
          contentNames: [],
          periodGrants: requested.accessGroups.map((accessGroup) => ({
            accessGroup,
            futurePeriodCount: 2,
            authorizePeriod: () => true,
          })),
        };
      },
    },
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => new ChainKeyCache({ strategy: "retain" }),
    primary: { periodGrantKind: "chain-keys" },
  });
  const browser = chainBrowser(world);
  const page = await world.render("A");
  assert.deepEqual(coordinatesOf(page), ["251023T1415", "251023T1430"]);

  world.clock.set(ISSUER_AT);
  const load = browser.load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.equal(exchanges.length, 1);
  assert.deepEqual(
    Object.keys(exchanges[0].body.keys.chainKeys[ACCESS_GROUP]).sort(),
    ["251023T1430", "251024T0015"],
    "article and future targets use their independently rooted windows",
  );
  const opened = await load.open(CONTENT_NAME);
  assert.equal(opened.error, null);
});

test("an explicit old article target stays unavailable when its old-window source is absent", async () => {
  const generation = chainGeneration(7);
  const world = await actorWorld({
    at: AT,
    periodKeySupply: supplyAt(generation, [NEXT_WINDOW_TERMINAL]),
    issuerSupplyPlanFor: deliveryPlan(() => ["chain-keys"]),
    accessPolicy: {
      decide(_claims, requested) {
        return {
          contentNames: [],
          periodGrants: requested.accessGroups.map((accessGroup) => ({
            accessGroup,
            futurePeriodCount: 2,
            authorizePeriod: () => true,
          })),
        };
      },
    },
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => new ChainKeyCache({ strategy: "retain" }),
    primary: { periodGrantKind: "chain-keys" },
  });
  const browser = chainBrowser(world);
  const page = await world.render("A");
  world.clock.set(ISSUER_AT);
  const load = browser.load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.equal(exchanges.length, 1);
  assert.deepEqual(Object.keys(exchanges[0].body.keys.chainKeys[ACCESS_GROUP]), ["251024T0015"]);
  assert.equal(await load.open(CONTENT_NAME).then(({ error }) => error), "no_key");
});

test("a same-window returned chain key reaches an earlier item wrap", async () => {
  const generation = chainGeneration(7);
  const world = await actorWorld({
    at: AT,
    periodKeySupply: supplyAt(generation, [RENDER_WINDOW_TERMINAL]),
    issuerSupplyPlanFor: deliveryPlan(() => ["chain-keys"]),
    accessPolicy: {
      decide(_claims, requested) {
        return {
          contentNames: [],
          periodGrants: requested.accessGroups.map((accessGroup) => ({
            accessGroup,
            futurePeriodCount: 2,
            authorizePeriod: () => true,
          })),
        };
      },
    },
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => new ChainKeyCache({ strategy: "retain" }),
    primary: { periodGrantKind: "chain-keys" },
  });
  const browser = chainBrowser(world);
  const page = await world.render("A");
  assert.deepEqual(coordinatesOf(page), ["251023T1415", "251023T1430"]);

  world.clock.set("2025-10-23T14:50:00Z");
  const load = browser.load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.equal(exchanges.length, 1);
  const keys = exchanges[0].body.keys;
  assert.deepEqual(Object.keys(keys.chainKeys[ACCESS_GROUP]), ["251023T1500"]);
  const opened = await load.open(CONTENT_NAME);
  assert.equal(opened.error, null);
});
