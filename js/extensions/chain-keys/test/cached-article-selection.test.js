// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { actorWorld, readArticle } from "../../../demo/scenarios/world.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import {
  ACCESS_GROUP,
  CONTENT_NAME,
  ISSUER_NAME,
  keyDerivationSecret,
} from "../../../demo/scenarios/fixtures.js";
import { ARTICLES } from "../../../demo/scenarios/fixtures.js";
import { rootFromPage } from "../../../demo/support/queryableRoot.js";
import { referenceChainKeyProfile } from "../referenceProfile.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { chainKeyCapabilitySource } from "../core-issuer/chainKeyCapabilitySource.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { basePeriodOnlyPolicy, chainBrowser, deliveryPlan, exchangesPosted } from "./world.js";

const P10 = "251023T1000";
const P13 = "251023T1300";
const P18 = "251023T1800";
const C11 = "251023T1145";
const C23 = "251023T2345";
const ACTOR_C11 = "251023T1100";
const ACTOR_C23 = "251023T2300";
const READ_AT = "2025-10-23T13:00:00Z";
const GEOMETRY = { chainsPerDay: 2, periodMinutes: 15 };

test("the existing base period-key route still returns an old supplied article key", async () => {
  const world = await actorWorld({
    at: "2025-10-23T10:00:00Z",
    period: { length: 60, slots: 1 },
    periodKeySupply: periodFamilySupply({
      families: {
        [ACCESS_GROUP]: periodFamilyGeneration({
          keyDerivationSecret: keyDerivationSecret(7),
          geometry: { chainsPerDay: 2, periodMinutes: 60 },
        }),
      },
      chainWindows: 2,
    }),
    issuerSupplyPlanFor: deliveryPlan(() => ["period-keys"]),
    accessPolicy: basePeriodOnlyPolicy(1),
  });
  const page = await world.render("A");
  assert.deepEqual(
    Object.keys(page.asJson().issuerData[ISSUER_NAME].sealed.periodKeys[ACCESS_GROUP]),
    [P10],
  );
  world.clock.set(READ_AT);
  const read = await readArticle(world.makeBrowser(), page, [CONTENT_NAME]);
  assert.equal(read.unlock.ok, true);
  assert.equal(read.texts[CONTENT_NAME], ARTICLES.A);
});

/** @param {Record<string, Record<string, string>>} chainKeys @param {Record<string, string[]>} requestedPeriodKeys */
function sourceRequest(chainKeys, requestedPeriodKeys) {
  return new DcaRequest({
    sealed: { contentKeys: {}, chainKeys },
    periodGeometry: GEOMETRY,
    requestedPeriodKeys,
  });
}

/** @param {string} accessGroup @param {number} futurePeriodCount @param {(t: string) => boolean} authorizePeriod */
function grant(accessGroup, futurePeriodCount, authorizePeriod) {
  return { accessGroup, futurePeriodCount, authorizePeriod };
}

/** @param {DcaRequest} request @param {any[]} grants @param {'period-keys'|'chain-keys'} [representation] */
function sourceSelection(request, grants, representation = "period-keys") {
  return chainKeyCapabilitySource({ representation }).selection(
    request,
    { capturedAtMs: Date.parse(READ_AT) },
    grants,
  );
}

/** @param {(t: string) => boolean} permits @param {number} futurePeriodCount @param {string[]} itemGrantNames @param {() => void} onDecision */
function policy(permits, futurePeriodCount, itemGrantNames = [], onDecision = () => {}) {
  return {
    decide(_claims, requested) {
      onDecision();
      return {
        contentNames: requested.contentNames.filter((name) => itemGrantNames.includes(name)),
        periodGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          futurePeriodCount,
          authorizePeriod: permits,
        })),
      };
    },
  };
}

/**
 * Chain-only publisher supply, without an item content-key envelope. The
 * article must therefore open through the returned reusable capability.
 *
 * @param {{ permits: (t: string) => boolean, futurePeriodCount: number, representation?: 'period-keys'|'chain-keys', chainsPerDay?: number, itemGrantNames?: string[], items?: { name: string, value: string, accessGroups?: string[] }[] }} options
 */
async function cachedArticleWorld({
  permits,
  futurePeriodCount,
  representation = "period-keys",
  chainsPerDay = 2,
  itemGrantNames = [],
  items = [],
}) {
  const counters = { policyCalls: 0, openingKeyReads: 0 };
  const profile =
    representation === "period-keys"
      ? {
          ...referenceChainKeyProfile,
          issuerEngineFor: referenceChainKeyProfile.explicitIssuerEngineFor,
        }
      : referenceChainKeyProfile;
  const world = await actorWorld({
    at: "2025-10-23T10:00:00Z",
    period: { length: 60, slots: 1 },
    periodKeySupply: periodFamilySupply({
      families: {
        [ACCESS_GROUP]: periodFamilyGeneration({
          keyDerivationSecret: keyDerivationSecret(7),
          geometry: { chainsPerDay, periodMinutes: 60 },
        }),
      },
      chainWindows: 2,
    }),
    issuerSupplyPlanFor: (_issuer, render) => ({
      contentKeyNames: itemGrantNames,
      suppliedAccessGroups: render.accessGroups,
      reachableContentNames: render.contentNames,
      periodKeyDelivery: Object.fromEntries(
        render.accessGroups.map((accessGroup) => [accessGroup, ["chain-keys"]]),
      ),
    }),
    accessPolicy: policy(permits, futurePeriodCount, itemGrantNames, () => counters.policyCalls++),
    chainKeyProfile: profile,
    chainKeyCacheFactory: (options) => new ChainKeyCache(options),
    primary: { periodGrantKind: "chain-keys" },
  });
  const keyStore = world.keyStores.primary;
  const originalGet = keyStore.get.bind(keyStore);
  Object.defineProperty(keyStore, "get", {
    configurable: true,
    value: (...args) => {
      counters.openingKeyReads++;
      return originalGet(...args);
    },
  });
  const page = await world.render("A", { items });
  assert.deepEqual(
    page.asJson().contentData[CONTENT_NAME].keys[ACCESS_GROUP].map((entry) => entry.t),
    [P10],
  );
  const supply = page.asJson().issuerData[ISSUER_NAME].sealed;
  assert.deepEqual(
    Object.keys(supply.chainKeys[ACCESS_GROUP]).sort(),
    chainsPerDay === 1 ? [ACTOR_C23, "251024T2300"] : [ACTOR_C11, ACTOR_C23],
  );
  assert.deepEqual(Object.keys(supply.contentKeys ?? {}).sort(), [...itemGrantNames].sort());
  world.clock.set(READ_AT);
  return { world, page, counters };
}

test("an old article target is projected before optional future period keys", async () => {
  const { world, page } = await cachedArticleWorld({
    permits: () => true,
    futurePeriodCount: 6,
  });
  const load = chainBrowser(world).load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.equal(exchanges.length, 1);
  assert.deepEqual(exchanges[0].request.requestedPeriodKeys, { [ACCESS_GROUP]: [P10] });
  assert.equal(exchanges[0].status, 200);
  const returned = exchanges[0].body.keys.periodKeys[ACCESS_GROUP];
  assert.deepEqual(Object.keys(returned).sort(), [
    P10,
    P13,
    "251023T1400",
    "251023T1500",
    "251023T1600",
    "251023T1700",
    P18,
  ]);
  assert.equal((await load.open(CONTENT_NAME)).error, null);
});

test("narrow period policy projects only the old article target and its permitted future horizon", async () => {
  const permitted = new Set([
    P10,
    P13,
    "251023T1400",
    "251023T1500",
    "251023T1600",
    "251023T1700",
    P18,
  ]);
  const { world, page } = await cachedArticleWorld({
    permits: (t) => permitted.has(t),
    futurePeriodCount: 6,
  });
  const load = chainBrowser(world).load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.equal(exchanges[0].status, 200);
  assert.deepEqual(
    Object.keys(exchanges[0].body.keys.periodKeys[ACCESS_GROUP]).sort(),
    [...permitted].sort(),
  );
  assert.equal((await load.open(CONTENT_NAME)).error, null);
});

test("zero future count does not deny an independently authorized old article target", async () => {
  const { world, page } = await cachedArticleWorld({
    permits: (t) => t === P10,
    futurePeriodCount: 0,
  });
  const load = chainBrowser(world).load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.equal(exchanges[0].status, 200);
  assert.deepEqual(Object.keys(exchanges[0].body.keys.periodKeys[ACCESS_GROUP]), [P10]);
  assert.equal(exchanges[0].body.notDelivered, undefined);
  assert.equal((await load.open(CONTENT_NAME)).error, null);
});

test("a broad chain agreement selects old and current windows independently", async () => {
  const { world, page } = await cachedArticleWorld({
    permits: () => true,
    futurePeriodCount: 6,
    representation: "chain-keys",
  });
  const load = chainBrowser(world).load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.equal(exchanges[0].status, 200);
  const cutoffs = Object.keys(exchanges[0].body.keys.chainKeys[ACCESS_GROUP]).sort();
  assert.deepEqual(cutoffs, [P10, P18]);
  assert.equal((await load.open(CONTENT_NAME)).error, null);
});

test("a daily broad chain agreement carries the authorized old prefix through the future cutoff", async () => {
  const { world, page } = await cachedArticleWorld({
    permits: () => true,
    futurePeriodCount: 6,
    representation: "chain-keys",
    chainsPerDay: 1,
  });
  const load = chainBrowser(world).load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.equal(exchanges[0].status, 200);
  assert.deepEqual(Object.keys(exchanges[0].body.keys.chainKeys[ACCESS_GROUP]), [P18]);
  assert.equal((await load.open(CONTENT_NAME)).error, null);
});

test("a chain-only answer does not widen narrow period authorization to a window prefix", async () => {
  const { world, page } = await cachedArticleWorld({
    permits: (t) => t === P10,
    futurePeriodCount: 0,
    representation: "chain-keys",
  });
  const load = chainBrowser(world).load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.equal(exchanges.length, 1);
  assert.equal(exchanges[0].body?.keys?.chainKeys?.[ACCESS_GROUP], undefined);
  assert.equal(exchanges[0].body?.keys?.periodKeys?.[ACCESS_GROUP], undefined);
  assert.equal((await load.open(CONTENT_NAME)).error, "no_key");
});

test("an old source survives a missing current window, while missing old supply and denial stay distinct", () => {
  const oldOnly = sourceRequest({ premium: { [C11]: "AQ" } }, { premium: [P10] });
  const selected = sourceSelection(oldOnly, [grant("premium", 1, () => true)])("premium");
  assert.deepEqual(
    selected.selected.map(({ t, targetTs }) => [t, targetTs]),
    [[C11, [P10]]],
  );

  const missingOld = sourceRequest({ premium: { [C23]: "Ag" } }, { premium: [P10] });
  assert.deepEqual(sourceSelection(missingOld, [grant("premium", 0, () => true)])("premium"), {
    unavailable: "unavailable",
  });
  assert.deepEqual(sourceSelection(oldOnly, [grant("premium", 0, () => false)])("premium"), {
    unavailable: "denied",
  });
});

test("a selected source requires an actual boolean trusted policy decision", () => {
  const request = sourceRequest({ premium: { [C11]: "AQ" } }, { premium: [P10] });
  assert.throws(
    () => sourceSelection(request, [grant("premium", 0, () => /** @type {any} */ ("yes"))]),
    { code: "bad_policy" },
  );
});

test("a denied current coordinate is not reported as an unreachable authorized current period", () => {
  const request = sourceRequest(
    { premium: { [C11]: "AQ", "251024T2345": "Ag" } },
    { premium: [P10] },
  );
  const answer = sourceSelection(
    request,
    [grant("premium", 1, (t) => t === P10)],
    "chain-keys",
  )("premium");
  assert.deepEqual(answer, { unavailable: true });
});

test("a reachable tampered hint is denied while the legitimate article target and future keys remain usable", async () => {
  const { world, page } = await cachedArticleWorld({
    permits: (t) => t === P10 || (t >= P13 && t <= P18),
    futurePeriodCount: 6,
  });
  const browser = world.makeBrowser({
    chainKeyStrategy: "retain",
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
    network: {
      post(url, request, options) {
        const tampered = JSON.parse(JSON.stringify(request));
        tampered.requestedPeriodKeys[ACCESS_GROUP].push("251023T0900");
        return world.network.post(url, tampered, options);
      },
    },
  });
  const load = browser.load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.deepEqual(exchanges[0].request.requestedPeriodKeys, {
    [ACCESS_GROUP]: [P10, "251023T0900"],
  });
  const returned = exchanges[0].body.keys.periodKeys[ACCESS_GROUP];
  assert.equal(Object.hasOwn(returned, "251023T0900"), false);
  assert.equal(Object.hasOwn(returned, P10), true);
  assert.equal(
    Object.keys(returned).some((t) => t >= P13 && t <= P18),
    true,
  );
  assert.equal((await load.open(CONTENT_NAME)).error, null);
});

test("an item grant stays item-scoped and cannot turn its period hint into a reusable key", async () => {
  const second = "premium-second-item";
  const { world, page } = await cachedArticleWorld({
    permits: () => false,
    futurePeriodCount: 6,
    itemGrantNames: [CONTENT_NAME],
    items: [{ name: second, value: "A separately wrapped item.", accessGroups: [ACCESS_GROUP] }],
  });
  const load = chainBrowser(world).load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, () => load.unlock());
  assert.deepEqual(exchanges[0].request.requestedPeriodKeys, { [ACCESS_GROUP]: [P10] });
  assert.deepEqual(Object.keys(exchanges[0].body.keys.contentKeys), [CONTENT_NAME]);
  assert.equal(exchanges[0].body.keys.periodKeys?.[ACCESS_GROUP], undefined);
  assert.equal((await load.open(CONTENT_NAME)).error, null);
  assert.equal((await load.open(second)).error, "no_key");
});

test("malformed, off-grid and excess selectors are refused before policy or envelope opening", async () => {
  const { world, page, counters } = await cachedArticleWorld({
    permits: () => true,
    futurePeriodCount: 6,
  });
  const alterations = [
    (selector) => {
      selector[ACCESS_GROUP] = "not-an-array";
    },
    (selector) => {
      selector[ACCESS_GROUP] = ["251023T1001"];
    },
    (selector) => {
      selector[ACCESS_GROUP] = Array(289).fill(P10);
    },
  ];
  let alteration = alterations[0];
  const browser = world.makeBrowser({
    chainKeyStrategy: "retain",
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
    network: {
      post(url, request, options) {
        const tampered = JSON.parse(JSON.stringify(request));
        alteration(tampered.requestedPeriodKeys);
        return world.network.post(url, tampered, options);
      },
    },
  });
  const load = browser.load(rootFromPage(page));
  const { exchanges } = await exchangesPosted(world.network, async () => {
    for (const current of alterations) {
      alteration = current;
      const result = await load.unlock();
      assert.equal(result.ok, false);
    }
  });
  assert.deepEqual(
    exchanges.map(({ status }) => status),
    [400, 400, 400],
  );
  assert.equal(counters.policyCalls, 0);
  assert.equal(counters.openingKeyReads, 0);
});

test("an old-window projection opens its actual supplied coordinate", async () => {
  const request = sourceRequest({ premium: { [C11]: "AQ" } }, { premium: [P10] });
  const source = chainKeyCapabilitySource();
  const selected = source.selection(request, { capturedAtMs: Date.parse(READ_AT) }, [
    grant("premium", 0, () => true),
  ])("premium");
  /** @type {any[]} */
  const openedAt = [];
  const produce = source.capabilities({
    request,
    open: async (_sealed, bind) => {
      openedAt.push(bind);
      return { bytes: new Uint8Array(16).fill(7) };
    },
  });
  const answer = await produce("premium", selected.selected);
  assert.deepEqual(
    openedAt.map(({ suppliedT }) => suppliedT),
    [C11],
  );
  assert.deepEqual(
    answer.periods.map(({ t }) => t),
    [P10],
  );
});

test("article targets across groups fill the 512-key response before optional future reach", () => {
  const day = Array.from({ length: 96 }, (_, index) => {
    const hour = Math.floor(index / 4)
      .toString()
      .padStart(2, "0");
    const minute = ((index % 4) * 15).toString().padStart(2, "0");
    return `251023T${hour}${minute}`;
  });
  const groups = Array.from({ length: 7 }, (_, index) => `group${index}`);
  const hints = Object.fromEntries([
    [groups[0], [day[0]]],
    ...groups.slice(1, 6).map((group) => [group, day]),
    [groups[6], day.slice(0, 31)],
  ]);
  const chainKeys = Object.fromEntries(
    groups.map((group) => [group, { [C11]: "AQ", [C23]: "Ag" }]),
  );
  delete chainKeys[groups[6]][C23];
  const grants = groups.map((group, index) => grant(group, index === 0 ? 288 : 0, () => true));
  const select = sourceSelection(sourceRequest(chainKeys, hints), grants);
  const selectedTargets = groups.map((group) =>
    select(group).selected.flatMap(({ targetTs }) => targetTs),
  );
  assert.deepEqual(
    selectedTargets.map((targets) => targets.length),
    [1, 96, 96, 96, 96, 96, 31],
  );
  assert.deepEqual(selectedTargets[0], [day[0]]);
});

test("period authorization for one group does not transfer to another group with the same requested label", () => {
  const request = sourceRequest(
    {
      premium: { [C11]: "AQ" },
      archive: { [C11]: "Ag" },
    },
    { premium: [P10], archive: [P10] },
  );
  const premiumGrant = grant("premium", 0, (t) => t === P10);
  const archiveGrant = grant("archive", 0, () => false);
  const select = sourceSelection(request, [premiumGrant, archiveGrant]);
  assert.deepEqual(
    select("premium", 0, premiumGrant).selected.map(({ targetTs }) => targetTs),
    [[P10]],
  );
  assert.deepEqual(select("archive", 0, archiveGrant), { unavailable: "denied" });
});

test("a retained article period key opens after the future horizon without another unlock", async () => {
  let entitled = true;
  const { world, page } = await cachedArticleWorld({
    permits: () => entitled,
    futurePeriodCount: 6,
  });
  const original = JSON.stringify(page.asJson());
  const cache = new PeriodKeyCache();
  const browser = world.makeBrowser({
    cacheFactory: () => cache,
    chainKeyStrategy: "retain",
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
  });
  const { exchanges } = await exchangesPosted(world.network, async () => {
    assert.equal(
      (await readArticle(browser, page, [CONTENT_NAME])).texts[CONTENT_NAME],
      ARTICLES.A,
    );
    entitled = false;
    world.clock.set("2025-10-23T20:00:00Z");
    const retained = await readArticle(browser, page, [CONTENT_NAME]);
    assert.equal(retained.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(retained.unlock, null, "retained capability requires no fresh grant");
  });
  assert.equal(exchanges.length, 1);
  assert.equal(
    JSON.stringify(page.asJson()),
    original,
    "cache age changes no publisher coordinate",
  );
});

test("host eviction after the horizon causes a fresh denied unlock rather than key expiry", async () => {
  let entitled = true;
  const { world, page } = await cachedArticleWorld({
    permits: () => entitled,
    futurePeriodCount: 6,
  });
  const browser = chainBrowser(world);
  const { exchanges } = await exchangesPosted(world.network, async () => {
    assert.equal(
      (await readArticle(browser, page, [CONTENT_NAME])).texts[CONTENT_NAME],
      ARTICLES.A,
    );
    entitled = false;
    world.clock.set("2025-10-23T20:00:00Z");
    const evicted = await readArticle(browser, page, [CONTENT_NAME]);
    assert.equal(evicted.errors[CONTENT_NAME], "no_key");
    assert.notEqual(evicted.unlock, null, "a host-evicted key must be requested again");
  });
  assert.deepEqual(
    exchanges.map(({ status }) => status),
    [200, 401],
  );
});

test("chain response capacity uses member bounds rather than the projected-key total", () => {
  const groups = ["a", "b", "c"];
  const request = new DcaRequest({
    sealed: {
      contentKeys: {},
      chainKeys: Object.fromEntries(groups.map((group) => [group, { "251023T2355": "Aw" }])),
    },
    periodGeometry: { chainsPerDay: 1, periodMinutes: 5 },
  });
  const grants = groups.map((group) => grant(group, 288, () => true));
  const lookup = chainKeyCapabilitySource({ representation: "chain-keys" }).selection(
    request,
    { capturedAtMs: Date.parse("2025-10-23T00:00:00Z") },
    grants,
  );
  for (const group of groups) {
    const result = lookup(
      group,
      288,
      grants.find((entry) => entry.accessGroup === group),
    );
    assert.equal(result.selected.length, 1);
    assert.equal(result.selected[0].targetTs.at(-1), "251023T2355");
  }
});
