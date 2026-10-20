// @ts-check
//
// One client carries its retained capability across a chain-window edge and a
// family-generation rollover, and meets one fresh issuer denial on the way.
//
// Three renders share one access group:
//
// - P, generation one, wrapped at 251023T2345, the last position of the
//   window [251023T1200, 251023T2345]. A chain issuer grants a cutoff there.
// - O, generation one, wrapped at 251024T0000, the first position of the next
//   window. A period-key issuer grants that one period key.
// - N, generation two, wrapped at the same 251024T0000 after the publisher
//   replaces its key-derivation secret and keeps the geometry.
//
// Opening authority is the intersection of what the retained bytes can reach
// and which wrap they authenticate. The window-one cutoff reaches back inside
// its own window only, so it derives nothing at 251024T0000. The old period
// key sits at N's label, but a label grants nothing: its bytes fail N's wrap
// and the client asks an issuer. That issuer's current policy denies, which
// withholds a new key and takes back no key already held. A later permitted
// request grants generation two's chain key, which opens N while P and O keep
// opening through the capability each one was opened with
// (`docs/spec-profile--chain-keys.md` §7.2 and §19-20;
// `docs/spec-profile--period-keys.md` §10-11; `docs/spec--content-protection.md` §5.3).
//
// Both issuers grant periods only, and every answer is recorded, so a content
// key cannot open an item behind the cache's back.

import test from "node:test";
import assert from "node:assert/strict";

import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { referenceChainKeyProfile } from "../referenceProfile.js";
import { actorWorld } from "../../../demo/scenarios/world.js";
import { rootFromPage } from "../../../demo/support/queryableRoot.js";
import { ACCESS_GROUP, CONTENT_NAME, ISSUER_NAME } from "../../../demo/scenarios/fixtures.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import {
  candidatesOffered,
  chainBrowser,
  chainGeneration,
  chainPartition,
  chainSupply,
  coordinatesOf,
  deliveryPlan,
  exchangesPosted,
  basePeriodOnlyPolicy,
  periodOnlyPolicy,
  sameBytes,
} from "./world.js";

const CHAIN_ISSUER_NAME = "paywall_chain_service";
const CHAIN_UNLOCK_URL = "https://chain.example.com/unlock";

/** The last position of the first window and the first position of the next. */
const OLD_WINDOW_T = "251023T2345";
const EDGE_T = "251024T0000";

/**
 * One period a grant, so a chain grant's cutoff is the issuer's current
 * coordinate and a period-key grant is one period key.
 */
const PERIOD = Object.freeze({ length: 15, slots: 1 });

test("retained old capability survives a window edge, a generation rollover and a denial, and opens only its own items", async () => {
  const oldGeneration = chainGeneration(7);
  const newGeneration = chainGeneration(9);

  // The chain issuer's current policy. A denied request is refused whole, the
  // way an issuer refuses a reader it no longer entitles.
  let chainIssuerAllows = true;
  const periodGrant = periodOnlyPolicy(1);
  const chainPolicy = {
    decide(/** @type {any} */ claims, /** @type {any} */ requested) {
      return chainIssuerAllows
        ? periodGrant.decide(claims, requested)
        : { contentNames: [], periodGrants: [] };
    },
  };

  const chainCache = new ChainKeyCache({ strategy: "retain" });
  const world = await actorWorld({
    at: "2025-10-23T23:50:00Z",
    period: PERIOD,
    periodKeySupply: chainSupply(oldGeneration),
    issuerSupplyPlanFor: deliveryPlan((issuer) =>
      issuer.issuerName === CHAIN_ISSUER_NAME ? ["chain-keys"] : ["period-keys"],
    ),
    accessPolicy: basePeriodOnlyPolicy(1),
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => chainCache,
  });
  const { server: chainServer, keyStore: chainKeyStore } = await world.standUp(
    CHAIN_ISSUER_NAME,
    CHAIN_UNLOCK_URL,
    {
      periodGrantKind: "chain-keys",
      accessPolicy: chainPolicy,
    },
  );
  const periodKeyServer = world.servers.primary;
  const browser = chainBrowser(world);

  /**
   * One page load: a resolve, an unlock when an issuer is named, and an open.
   * It records what both caches offered during the resolve and every exchange
   * the unlock carried.
   *
   * @param {any} page
   * @param {string} [issuerName]
   */
  const step = async (page, issuerName) => {
    const load = browser.load(rootFromPage(page));
    const {
      result: { result: resolved, offered: periodKeysOffered },
      offered: chainOffered,
    } = await candidatesOffered(
      chainCache,
      () => candidatesOffered(browser.cache, () => load.resolve([CONTENT_NAME])),
      "candidates",
    );
    const { result: unlock, exchanges } =
      issuerName === undefined
        ? { result: null, exchanges: [] }
        : await exchangesPosted(world.network, () => load.unlock({ issuerName }));
    const opened = await load.open(CONTENT_NAME);
    const [first, afterUnlock] = load.stats().keyResolutions;
    return {
      resolved,
      // One array per cache consultation, so an empty answer still shows
      // the cache was asked.
      periodKeysOffered,
      chainOffered,
      unlock,
      exchanges,
      // The origin that opened the item: the resolve's own when the cache
      // covered it, the re-resolve's after an unlock.
      origin: (issuerName === undefined ? first : afterUnlock)?.origins[0],
      text: opened.bytes === null ? null : utf8Decode(opened.bytes),
      error: opened.error,
    };
  };

  /** @param {any} exchange */
  const grantedIn = (exchange) => ({
    status: exchange.status,
    contentKeys: Object.keys(exchange.body.keys?.contentKeys ?? {}),
    periodKeys: Object.keys(exchange.body.keys?.periodKeys?.[ACCESS_GROUP] ?? {}),
    chainCutoffs: Object.keys(exchange.body.keys?.chainKeys?.[ACCESS_GROUP] ?? {}),
  });

  const oldEdgePeriodKey = await oldGeneration.periodKey(ACCESS_GROUP, EDGE_T);
  const newEdgePeriodKey = await newGeneration.periodKey(ACCESS_GROUP, EDGE_T);
  assert.equal(
    sameBytes(oldEdgePeriodKey, newEdgePeriodKey),
    false,
    "the two generations put rival bytes at one label",
  );

  // 1. P at 23:50. The chain issuer grants one period, so the cutoff is P's
  //    own coordinate, the last position of the first window.
  const pageP = await world.render("A");
  assert.deepEqual(coordinatesOf(pageP), [OLD_WINDOW_T]);
  const p1 = await step(pageP, CHAIN_ISSUER_NAME);
  assert.deepEqual(p1.resolved, { covered: [], missing: [CONTENT_NAME] });
  assert.deepEqual(p1.exchanges.map(grantedIn), [
    { status: 200, contentKeys: [], periodKeys: [], chainCutoffs: [OLD_WINDOW_T] },
  ]);
  assert.deepEqual(p1.origin, {
    contentName: CONTENT_NAME,
    kind: "cached-chain-key",
    accessGroup: ACCESS_GROUP,
    t: OLD_WINDOW_T,
  });
  assert.match(String(p1.text), /rezone the harbour/);

  // 2. O at 00:05, one position into the next window. The first window's
  //    cutoff is asked about the edge and derives nothing there, so the
  //    period-key issuer grants the one old period key.
  world.clock.set("2025-10-24T00:05:00Z");
  const pageO = await world.render("B");
  assert.deepEqual(coordinatesOf(pageO), [EDGE_T]);
  const o1 = await step(pageO, ISSUER_NAME);
  assert.deepEqual(o1.resolved, { covered: [], missing: [CONTENT_NAME] });
  assert.deepEqual(o1.periodKeysOffered, [[]], "the base cache holds nothing at the edge yet");
  assert.deepEqual(
    o1.chainOffered,
    [[]],
    "the first window's cutoff reaches back inside its window and not across the edge",
  );
  assert.deepEqual(o1.exchanges.map(grantedIn), [
    { status: 200, contentKeys: [], periodKeys: [EDGE_T], chainCutoffs: [] },
  ]);
  assert.deepEqual(o1.origin, {
    contentName: CONTENT_NAME,
    kind: "cached-period-key",
    accessGroup: ACCESS_GROUP,
    t: EDGE_T,
  });
  assert.match(String(o1.text), /second reading/);

  // 3. The publisher replaces its key-derivation secret and keeps the
  //    geometry. N wraps at the label O already holds a period key for.
  world.publisher.rotatePeriodKeySupply(chainSupply(newGeneration));
  const pageN = await world.render("C");
  assert.deepEqual(coordinatesOf(pageN), [EDGE_T]);

  // 4. The chain issuer's current policy denies N. The old period key at the same
  //    label is offered, fails N's wrap, and nothing else is on hand.
  chainIssuerAllows = false;
  const openingKeyLookupsBeforeDenial = chainKeyStore.reachCount;
  assert.ok(openingKeyLookupsBeforeDenial > 0, "the earlier live chain grant reached its key");
  const n1 = await step(pageN, CHAIN_ISSUER_NAME);
  assert.deepEqual(n1.resolved, { covered: [], missing: [CONTENT_NAME] });
  assert.ok(
    n1.periodKeysOffered.flat().some((candidate) => sameBytes(candidate, oldEdgePeriodKey)),
    "the old period key was tried against N's wrap",
  );
  assert.deepEqual(n1.chainOffered, [[]], "the chain partition still reaches nothing at the edge");
  assert.equal(n1.unlock.ok, false);
  assert.deepEqual(n1.exchanges.map(grantedIn), [
    { status: 401, contentKeys: [], periodKeys: [], chainCutoffs: [] },
  ]);
  assert.equal(n1.text, null, "N stays locked");
  assert.equal(n1.error, "no_key");
  assert.equal(
    chainKeyStore.reachCount,
    openingKeyLookupsBeforeDenial,
    "the current denial after a live grant reaches no opening key",
  );
  assert.equal(chainServer.stats().denials, 1);
  assert.equal(
    periodKeyServer.stats().requests,
    1,
    "the period-key issuer was never asked about N",
  );

  // The denial took back nothing: P and O reopen from the cache alone.
  const p2 = await step(pageP);
  assert.deepEqual(p2.resolved, { covered: [CONTENT_NAME], missing: [] });
  assert.equal(p2.origin.kind, "cached-chain-key");
  assert.equal(p2.origin.t, OLD_WINDOW_T);
  assert.match(String(p2.text), /rezone the harbour/);
  const o2 = await step(pageO);
  assert.deepEqual(o2.resolved, { covered: [CONTENT_NAME], missing: [] });
  assert.equal(o2.origin.kind, "cached-period-key");
  assert.match(String(o2.text), /second reading/);

  // 5. The policy permits again. One chain grant from the second generation
  //    opens N; the old period key was tried first and missed again.
  chainIssuerAllows = true;
  const n2 = await step(pageN, CHAIN_ISSUER_NAME);
  assert.deepEqual(n2.resolved, { covered: [], missing: [CONTENT_NAME] });
  assert.ok(
    n2.periodKeysOffered.flat().some((candidate) => sameBytes(candidate, oldEdgePeriodKey)),
  );
  assert.deepEqual(n2.exchanges.map(grantedIn), [
    { status: 200, contentKeys: [], periodKeys: [], chainCutoffs: [EDGE_T] },
  ]);
  assert.deepEqual(n2.origin, {
    contentName: CONTENT_NAME,
    kind: "cached-chain-key",
    accessGroup: ACCESS_GROUP,
    t: EDGE_T,
  });
  assert.match(String(n2.text), /close on Friday/);
  const atEdge = await chainPartition(chainCache, world, EDGE_T);
  assert.ok(atEdge.some((candidate) => sameBytes(candidate, newEdgePeriodKey)));
  assert.equal(
    atEdge.some((candidate) => sameBytes(candidate, oldEdgePeriodKey)),
    false,
    "the chain partition reaches the second generation's period key at the edge, not the first's",
  );

  // Every item now opens from the cache, each through its own capability.
  const opens = [
    [await step(pageP), "cached-chain-key", OLD_WINDOW_T, /rezone the harbour/],
    [await step(pageO), "cached-period-key", EDGE_T, /second reading/],
    [await step(pageN), "cached-chain-key", EDGE_T, /close on Friday/],
  ];
  for (const [opened, kind, t, text] of opens) {
    assert.deepEqual(opened.resolved, { covered: [CONTENT_NAME], missing: [] });
    assert.deepEqual(opened.origin, {
      contentName: CONTENT_NAME,
      kind,
      accessGroup: ACCESS_GROUP,
      t,
    });
    assert.match(String(opened.text), text);
  }

  assert.equal(browser.stats().unlocks, 4, "P, O, the denied N and the granted N");
  assert.equal(chainServer.stats().grants, 2);
  assert.equal(periodKeyServer.stats().grants, 1);
});
