// @ts-check
//
// One access-group family leaving independently generated period keys for a
// later canonical chain-key generation, with a retained old render on the far side
// of the move.
//
// The neighbouring rival-generation cases start where this one ends: they roll
// one chain generation onto another, so both sides of the move derive from the
// frozen construction and both live in the chain partition. Here the first
// generation is opaque bytes the publisher was handed, filed by the client in
// the ordinary base cache, and the second is the canonical construction reached
// through a chain-capable issuer. Nothing labels either one on the wire, which
// is what the first case's four observations are about.
//
// The two renders land on one coordinate on purpose. A fifteen-minute base
// period spells its label the way this profile always spells one, so the second
// render wraps at the same `t` as the first. The old candidate is therefore
// tried and fails an AES-GCM tag rather than being passed over for a coordinate
// nobody asked about, which is the trial the specification's rollover section
// describes: rival bytes at one coordinate, no generation tag to route by.
//
// Two issuers serve one publisher. `periodGrantKind` is fixed when a server is
// constructed and a chain issuer closes its period route to a request carrying
// no chain key, so the period-key generation and the chain-key generation are
// answered by two servers. One publisher stands behind both: the same origin, the same
// signing key and the same access group across the move, reconfigured between
// renders by rotating its supply and its per-issuer delivery plan.
//
// Watch the grant counters in the last two steps. One unlock files the chain
// capability, and the retained old render costs no third one.
//
// The second case makes the same move and names no issuer for the new render.
// The browser walks the two issuers in a given order and asks only the first.
// The period-key issuer answers with the new generation's period keys, the chain
// issuer with a chain key that derives the same period keys. Either answer
// opens the new render, and the old render still reopens from the cache.

import test from "node:test";
import assert from "node:assert/strict";

import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { referenceChainKeyProfile } from "../referenceProfile.js";
import { Random } from "../../../demo/actors/Random.js";
import { actorWorld } from "../../../demo/scenarios/world.js";
import { randomPeriodKeySupply } from "../../../demo/support/randomPeriodKeySupply.js";
import { rootFromPage } from "../../../demo/support/queryableRoot.js";
import {
  ACCESS_GROUP,
  AT,
  CONTENT_NAME,
  ISSUER_NAME,
  UNLOCK_URL,
} from "../../../demo/scenarios/fixtures.js";
import { base64urlEncode, utf8Decode } from "../../../core-shared/codec.js";
import { periodKeyMap } from "../../../test-reference/support/namedRecords.js";
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

/**
 * The base period the independently generated period keys are labelled with. Fifteen
 * minutes is the one that puts a base label and this profile's fixed
 * `YYMMDDTHHMM` on the same string, so the two generations meet at one
 * coordinate instead of at two that never compare.
 */
const PERIOD = Object.freeze({ length: 15, slots: 2 });

/** The chain-capable issuer, beside the period-key issuer the world already stands up. */
const CHAIN_ISSUER_NAME = "paywall_chain_service";
const CHAIN_UNLOCK_URL = "https://chain.example.com/unlock";

/**
 * Period material and nothing else, over the grant this case's period runs to.
 * A content-key grant opens the render it was asked for without any
 * period key at all, so an issuer handing one over would settle every open
 * below before the cached path was reached.
 */
const accessPolicy = periodOnlyPolicy(PERIOD.slots);
const baseAccessPolicy = basePeriodOnlyPolicy(PERIOD.slots);

test("a family of independently generated period keys moves to a chain-key generation without losing the old render", async () => {
  // The chain generation the family arrives at, and the publisher supply that
  // plans it. Both are made here so the test can name the canonical period key the
  // client is expected to end up with.
  const generation = chainGeneration(9);
  const rotatedSupply = chainSupply(generation, 2, PERIOD.slots);

  // What the publisher supplies each issuer, asked once per issuer per render.
  // The publisher is reconfigured by moving this and its key supply together:
  // before the move every issuer is offered the ordinary period-key route, after it
  // the chain issuer is offered the family's positioned capability.
  let familyDelivery = "period-keys";
  const supplyPlan = deliveryPlan((issuer) =>
    familyDelivery === "chain-keys" && issuer.issuerName === CHAIN_ISSUER_NAME
      ? ["chain-keys"]
      : ["period-keys"],
  );

  // Held rather than made by the browser's factory, so the test can read the
  // partition the chain grant is filed in.
  const chainCache = new ChainKeyCache({ strategy: "retain" });

  const world = await actorWorld({
    at: AT,
    period: PERIOD,
    periodKeySupply: randomPeriodKeySupply({ random: new Random({ seed: 4242 }) }),
    issuerSupplyPlanFor: supplyPlan,
    accessPolicy: baseAccessPolicy,
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => chainCache,
  });
  const { server: chainServer } = await world.standUp(CHAIN_ISSUER_NAME, CHAIN_UNLOCK_URL, {
    periodGrantKind: "chain-keys",
    accessPolicy,
  });
  // Built after both issuers stand, since a browser walks the ones it was
  // made with. One browser across every step puts the cache on trial.
  const browser = chainBrowser(world);

  // 1. The period-key generation: one render, one unlock, one retained candidate.
  const independentPage = await world.render("A");
  const independentLoad = browser.load(rootFromPage(independentPage));
  assert.deepEqual(await independentLoad.resolve([CONTENT_NAME]), {
    covered: [],
    missing: [CONTENT_NAME],
  });
  const firstUnlock = await independentLoad.unlock();
  assert.equal(firstUnlock.ok, true);
  assert.equal(firstUnlock.issuerName, ISSUER_NAME);
  const openedIndependent = await independentLoad.open(CONTENT_NAME);
  assert.equal(openedIndependent.error, null);
  assert.match(
    utf8Decode(/** @type {Uint8Array} */ (openedIndependent.bytes)),
    /rezone the harbour/,
  );
  assert.equal(world.servers.primary.stats().grants, 1);
  assert.equal(chainServer.stats().requests, 0, "the chain issuer has not been asked anything yet");

  const coordinates = coordinatesOf(independentPage);
  const held = await browser.cache.entries();
  assert.deepEqual(
    [...held.map(({ t }) => t)].sort(),
    [...coordinates].sort(),
    "the base cache holds the periods that render shipped and nothing else",
  );
  const overlap = coordinates[0];
  const retained = held.filter((entry) => entry.t === overlap);
  assert.equal(
    retained.length,
    1,
    "one independently generated period-key candidate stands at the coordinate",
  );

  // 2. The same publisher and access group, now on the canonical construction.
  familyDelivery = "chain-keys";
  world.publisher.rotatePeriodKeySupply(rotatedSupply);
  const chainPage = await world.render("B");
  assert.deepEqual(
    coordinatesOf(chainPage),
    coordinates,
    "the later render wraps at the coordinates already cached",
  );
  const canonical = /** @type {Uint8Array} */ (await generation.periodKey(ACCESS_GROUP, overlap));
  assert.equal(
    sameBytes(/** @type {Uint8Array} */ (retained[0].key), canonical),
    false,
    "the two generations are rival bytes at one coordinate, which is what makes the miss a trial",
  );

  // 3. The retained candidate is offered and misses; one unlock files the
  //    chain capability; the new render opens.
  const chainLoad = browser.load(rootFromPage(chainPage));
  const { result: chainResolve, offered } = await candidatesOffered(browser.cache, () =>
    chainLoad.resolve([CONTENT_NAME]),
  );
  assert.deepEqual(
    chainResolve,
    { covered: [], missing: [CONTENT_NAME] },
    "nothing the client already holds opens the new render",
  );
  assert.equal(
    offered.length,
    coordinates.length,
    "the base cache was consulted once per authored coordinate",
  );
  assert.ok(
    offered[0].some((candidate) =>
      sameBytes(candidate, /** @type {Uint8Array} */ (retained[0].key)),
    ),
    "the retained period-key candidate was among the bytes it offered, so the new wrap was tried against it",
  );
  assert.deepEqual(
    await chainPartition(chainCache, world, overlap),
    [],
    "and the chain partition held nothing at the coordinate to try instead",
  );
  assert.deepEqual(chainLoad.stats().keyResolutions, [
    { operation: "resolve", origins: [{ contentName: CONTENT_NAME, kind: "missing" }] },
  ]);
  assert.equal(
    world.servers.primary.stats().grants,
    1,
    "a trial miss costs the period-key issuer nothing",
  );

  const secondUnlock = await chainLoad.unlock({ issuerName: CHAIN_ISSUER_NAME });
  assert.equal(secondUnlock.ok, true);
  assert.equal(secondUnlock.issuerName, CHAIN_ISSUER_NAME);
  assert.equal(chainServer.stats().grants, 1, "the chain issuer granted once");
  assert.equal(world.servers.primary.stats().grants, 1);
  const openedChain = await chainLoad.open(CONTENT_NAME);
  assert.equal(openedChain.error, null);
  assert.match(utf8Decode(/** @type {Uint8Array} */ (openedChain.bytes)), /second reading/);

  assert.ok(
    (await chainPartition(chainCache, world, overlap)).some((candidate) =>
      sameBytes(candidate, canonical),
    ),
    "the one new unlock filed the chain capability that reaches the canonical period key at this coordinate",
  );

  // 4. The old render, reloaded: still opened by the retained independently
  //    generated period-key candidate, and no issuer is asked a third time.
  const oldAgain = browser.load(rootFromPage(independentPage));
  assert.deepEqual(await oldAgain.resolve([CONTENT_NAME]), {
    covered: [CONTENT_NAME],
    missing: [],
  });
  const [reading] = oldAgain.stats().keyResolutions;
  assert.equal(reading.operation, "resolve");
  assert.equal(reading.origins.length, 1);
  const [opening] = reading.origins;
  assert.equal(
    opening.kind,
    "cached-period-key",
    "the old render is opened by the candidate the ordinary base cache kept",
  );
  assert.equal(opening.accessGroup, ACCESS_GROUP);
  assert.ok(coordinates.includes(opening.t), "and at one of the coordinates that render shipped");
  const reopened = await oldAgain.open(CONTENT_NAME);
  assert.equal(reopened.error, null);
  assert.match(utf8Decode(/** @type {Uint8Array} */ (reopened.bytes)), /rezone the harbour/);
  assert.equal(oldAgain.stats().unlocks, 0);
  assert.equal(browser.stats().unlocks, 2, "the whole move costs two unlocks");
  assert.equal(world.servers.primary.stats().grants, 1);
  assert.equal(chainServer.stats().grants, 1, "the retained old render needs no third grant");
});

/**
 * The same move, but the new render is unlocked with no issuer named, by a
 * browser that walks the two issuers in the order given. The old render's
 * unlock names the period-key issuer, so the walk decides only the unlock under
 * test. It has to: a chain-first walk would ask the chain issuer about the old
 * render first, that issuer closes its period route to a request carrying no
 * chain key and answers 401, and a refusal ends the walk.
 *
 * @param {"period-keys-first"|"chain-keys-first"} order
 */
async function unnamedUnlockAcrossTheMove(order) {
  const generation = chainGeneration(9);
  let familyDelivery = "period-keys";
  const chainCache = new ChainKeyCache({ strategy: "retain" });
  const world = await actorWorld({
    at: AT,
    period: PERIOD,
    periodKeySupply: randomPeriodKeySupply({ random: new Random({ seed: 4242 }) }),
    issuerSupplyPlanFor: deliveryPlan((issuer) =>
      familyDelivery === "chain-keys" && issuer.issuerName === CHAIN_ISSUER_NAME
        ? ["chain-keys"]
        : ["period-keys"],
    ),
    accessPolicy: baseAccessPolicy,
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => chainCache,
  });
  await world.standUp(CHAIN_ISSUER_NAME, CHAIN_UNLOCK_URL, {
    periodGrantKind: "chain-keys",
    accessPolicy,
  });
  const periodKeyIssuer = { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL };
  const chainIssuer = { issuerName: CHAIN_ISSUER_NAME, unlockUrl: CHAIN_UNLOCK_URL };
  const browser = world.makeBrowser({
    chainKeyStrategy: "retain",
    requestBuilderFactory: (/** @type {object} */ options) => new ChainKeyRequestBuilder(options),
    issuers:
      order === "period-keys-first"
        ? [periodKeyIssuer, chainIssuer]
        : [chainIssuer, periodKeyIssuer],
  });
  /** @param {string} t */
  const baseAt = async (t) =>
    (await browser.cache.candidatesAt(ACCESS_GROUP, t, { publisher: world.publisher.origin })).map(
      base64urlEncode,
    );

  const independentPage = await world.render("A");
  const independentLoad = browser.load(rootFromPage(independentPage));
  await independentLoad.resolve([CONTENT_NAME]);
  assert.equal((await independentLoad.unlock({ issuerName: ISSUER_NAME })).ok, true);
  assert.equal((await independentLoad.open(CONTENT_NAME)).error, null);
  const coordinates = coordinatesOf(independentPage);
  const overlap = coordinates[0];
  const retained = await baseAt(overlap);
  assert.equal(retained.length, 1);

  familyDelivery = "chain-keys";
  world.publisher.rotatePeriodKeySupply(chainSupply(generation, 2, PERIOD.slots));
  const chainPage = await world.render("B");
  assert.deepEqual(coordinatesOf(chainPage), coordinates);
  /** @type {Record<string, string>} */
  const newPeriodKeys = {};
  for (const t of coordinates) {
    newPeriodKeys[t] = base64urlEncode(
      /** @type {Uint8Array} */ (await generation.periodKey(ACCESS_GROUP, t)),
    );
  }
  assert.notEqual(newPeriodKeys[overlap], retained[0]);

  const chainLoad = browser.load(rootFromPage(chainPage));
  assert.deepEqual(await chainLoad.resolve([CONTENT_NAME]), {
    covered: [],
    missing: [CONTENT_NAME],
  });
  const heldBeforeUnlock = await browser.cache.entries();
  const { result: unlocked, exchanges } = await exchangesPosted(world.network, () =>
    chainLoad.unlock(),
  );
  const opened = await chainLoad.open(CONTENT_NAME);

  return {
    world,
    browser,
    chainCache,
    independentPage,
    coordinates,
    overlap,
    retained,
    newPeriodKeys,
    baseAt,
    heldBeforeUnlock,
    chainLoad,
    unlocked,
    exchanges,
    opened,
  };
}

/**
 * The old render, reloaded after the move: the retained candidate opens it
 * and nothing crosses the wire.
 *
 * @param {Awaited<ReturnType<typeof unnamedUnlockAcrossTheMove>>} moved
 */
async function assertOldRenderReopensFromCache({ world, browser, independentPage }) {
  const oldAgain = browser.load(rootFromPage(independentPage));
  const { result: reopened, exchanges } = await exchangesPosted(world.network, async () => {
    assert.deepEqual(await oldAgain.resolve([CONTENT_NAME]), {
      covered: [CONTENT_NAME],
      missing: [],
    });
    return oldAgain.open(CONTENT_NAME);
  });
  assert.equal(reopened.error, null);
  assert.match(utf8Decode(/** @type {Uint8Array} */ (reopened.bytes)), /rezone the harbour/);
  assert.equal(oldAgain.stats().keyResolutions[0].origins[0].kind, "cached-period-key");
  assert.deepEqual(exchanges, [], "no issuer is asked about the old render");
  assert.equal(oldAgain.stats().unlocks, 0);
}

/**
 * The resolution the grant produced, as opposed to the later open, which reads
 * the content key that resolution already put in hand.
 *
 * @param {any} load
 */
function afterUnlock(load) {
  return load
    .stats()
    .keyResolutions.find(
      (/** @type {{ operation: string }} */ { operation }) =>
        operation === "re-resolve-after-unlock",
    );
}

test("an unnamed unlock across the move asks the first issuer holding carriers for the new render", async (t) => {
  await t.test("period-key-only issuer first: the new generation's period keys", async () => {
    const moved = await unnamedUnlockAcrossTheMove("period-keys-first");
    const { exchanges, unlocked, opened, newPeriodKeys, overlap, retained } = moved;

    assert.deepEqual(
      exchanges.map(({ url, status }) => ({ url, status })),
      [{ url: UNLOCK_URL, status: 200 }],
      "one exchange, and the chain issuer behind it is never asked",
    );
    assert.equal(unlocked.issuerName, ISSUER_NAME);
    // A publisher still sealing the old supply for a period-key-only route, or an
    // issuer handing back a key it cached by coordinate, would return the old
    // period key here, and B would stay locked after the grant.
    assert.deepEqual(periodKeyMap(exchanges[0].body.keys.periodKeys), {
      [ACCESS_GROUP]: newPeriodKeys,
    });
    assert.equal(exchanges[0].body.keys.chainKeys, undefined);

    assert.equal(opened.error, null);
    assert.match(utf8Decode(/** @type {Uint8Array} */ (opened.bytes)), /second reading/);
    assert.equal(afterUnlock(moved.chainLoad).origins[0].kind, "cached-period-key");
    assert.deepEqual(
      await moved.baseAt(overlap),
      [newPeriodKeys[overlap], retained[0]],
      "the base cache keeps both generations at the coordinate, newest first",
    );
    assert.deepEqual(await chainPartition(moved.chainCache, moved.world, overlap), []);

    await assertOldRenderReopensFromCache(moved);
  });

  await t.test("chain issuer first: a chain key that reaches the same period keys", async () => {
    const moved = await unnamedUnlockAcrossTheMove("chain-keys-first");
    const { exchanges, unlocked, opened, newPeriodKeys, coordinates } = moved;

    assert.deepEqual(
      exchanges.map(({ url, status }) => ({ url, status })),
      [{ url: CHAIN_UNLOCK_URL, status: 200 }],
      "one exchange, and the period-key issuer behind it is never asked",
    );
    assert.equal(unlocked.issuerName, CHAIN_ISSUER_NAME);
    assert.equal(exchanges[0].body.keys.periodKeys, undefined);
    assert.deepEqual(
      Object.keys(periodKeyMap(exchanges[0].body.keys.chainKeys, "cutoff")[ACCESS_GROUP]),
      [coordinates.at(-1)],
      "one chain key, at the last coordinate the grant runs to",
    );

    assert.equal(opened.error, null);
    assert.match(utf8Decode(/** @type {Uint8Array} */ (opened.bytes)), /second reading/);
    assert.equal(afterUnlock(moved.chainLoad).origins[0].kind, "cached-chain-key");
    for (const t of coordinates) {
      assert.deepEqual(
        (await chainPartition(moved.chainCache, moved.world, t)).map(base64urlEncode),
        [newPeriodKeys[t]],
        `the chain key derives the period key a period-key route would have granted at ${t}`,
      );
    }
    // The whole base cache, not the overlap alone: a client that also filed
    // the chain key as a period key would file it at the chain key's own
    // coordinate, the last one.
    assert.deepEqual(
      await moved.browser.cache.entries(),
      moved.heldBeforeUnlock,
      "the chain grant files nothing in the base cache",
    );

    await assertOldRenderReopensFromCache(moved);
  });
});
