// @ts-check
//
// One access-group family leaving independently supplied exact key material for
// a later canonical chain generation, with a retained old render on the far side
// of the move.
//
// The neighbouring rival-generation cases start where this one ends: they roll
// one chain generation onto another, so both sides of the move derive from the
// frozen construction and both live in the chain partition. Here the first
// generation is opaque bytes the publisher was handed, filed by the client in
// the ordinary base cache, and the second is the canonical construction reached
// through a chain-capable issuer. Nothing labels either one on the wire, which
// is what the four observations below are about.
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
// no chain state, so the exact generation and the chain generation are answered
// by two servers. One publisher stands behind both: the same origin, the same
// signing key and the same access group across the move, reconfigured between
// renders by rotating its supply and its per-issuer delivery plan.
//
// Watch the grant counters in the last two steps. One unlock files the chain
// capability, and the retained old render costs no third one.

import test from "node:test";
import assert from "node:assert/strict";

import { PeriodChainCache } from "../core-client/PeriodChainCache.js";
import { referencePeriodChainProfile } from "../referenceProfile.js";
import { Random } from "../../../demo/actors/Random.js";
import { actorWorld } from "../../../demo/scenarios/world.js";
import { exactPeriodKeySupply } from "../../../demo/support/exactPeriodKeySupply.js";
import { rootFromPage } from "../../../demo/support/queryableRoot.js";
import { ACCESS_GROUP, AT, CONTENT_NAME, ISSUER_NAME } from "../../../demo/scenarios/fixtures.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import {
  candidatesOffered,
  chainBrowser,
  chainGeneration,
  chainPartition,
  chainSupply,
  coordinatesOf,
  deliveryPlan,
  periodOnlyPolicy,
  sameBytes,
} from "./world.js";

/**
 * The base period the independent exact generation is labelled with. Fifteen
 * minutes is the one that puts a base label and this profile's fixed
 * `YYMMDDTHHMM` on the same string, so the two generations meet at one
 * coordinate instead of at two that never compare.
 */
const PERIOD = Object.freeze({ length: 15, slots: 2 });

/** The chain-capable issuer, beside the exact one the world already stands up. */
const CHAIN_ISSUER_NAME = "paywall_chain_service";
const CHAIN_UNLOCK_URL = "https://chain.example.com/unlock";

/**
 * Period material and nothing else, over the grant this case's period runs to.
 * A direct content-key grant opens the render it was asked for without any
 * period key at all, so an issuer handing one over would settle every open
 * below before the cached path was reached.
 */
const accessPolicy = periodOnlyPolicy(PERIOD.slots);

test("an independent exact family moves to a chain generation without losing the old render", async () => {
  // The chain generation the family arrives at, and the publisher supply that
  // plans it. Both are made here so the test can name the canonical leaf the
  // client is expected to end up with.
  const generation = chainGeneration(9);
  const rotatedSupply = chainSupply(generation);

  // What the publisher supplies each issuer, asked once per issuer per render.
  // The publisher is reconfigured by moving this and its key supply together:
  // before the move every issuer is offered the ordinary exact route, after it
  // the chain issuer is offered the family's positioned capability.
  let familyDelivery = "exact";
  const supplyPlan = deliveryPlan((issuer) =>
    familyDelivery === "chain" && issuer.issuerName === CHAIN_ISSUER_NAME ? ["chain"] : ["exact"],
  );

  // Held rather than made by the browser's factory, so the test can read the
  // partition the chain grant is filed in.
  const chainCache = new PeriodChainCache({ strategy: "retain" });

  const world = await actorWorld({
    at: AT,
    period: PERIOD,
    periodKeySupply: exactPeriodKeySupply({ random: new Random({ seed: 4242 }) }),
    issuerSupplyPlanFor: supplyPlan,
    accessPolicy,
    periodChainProfile: referencePeriodChainProfile,
    periodChainCacheFactory: () => chainCache,
  });
  const { server: chainServer } = await world.standUp(CHAIN_ISSUER_NAME, CHAIN_UNLOCK_URL, {
    periodGrantKind: "chain",
    accessPolicy,
  });
  // Built after both issuers stand, since a browser walks the ones it was
  // made with. One browser across every step puts the cache on trial.
  const browser = chainBrowser(world);

  // 1. The exact generation: one render, one unlock, one retained candidate.
  const exactPage = await world.render("A");
  const exactLoad = browser.load(rootFromPage(exactPage));
  assert.deepEqual(await exactLoad.resolve([CONTENT_NAME]), {
    covered: [],
    missing: [CONTENT_NAME],
  });
  const firstUnlock = await exactLoad.unlock();
  assert.equal(firstUnlock.ok, true);
  assert.equal(firstUnlock.issuerName, ISSUER_NAME);
  const openedExact = await exactLoad.open(CONTENT_NAME);
  assert.equal(openedExact.error, null);
  assert.match(utf8Decode(/** @type {Uint8Array} */ (openedExact.bytes)), /rezone the harbour/);
  assert.equal(world.servers.primary.stats().grants, 1);
  assert.equal(chainServer.stats().requests, 0, "the chain issuer has not been asked anything yet");

  const coordinates = coordinatesOf(exactPage);
  const held = await browser.cache.entries();
  assert.deepEqual(
    [...held.map(({ t }) => t)].sort(),
    [...coordinates].sort(),
    "the base cache holds the periods that render shipped and nothing else",
  );
  const overlap = coordinates[0];
  const retained = held.filter((entry) => entry.t === overlap);
  assert.equal(retained.length, 1, "one independent exact candidate stands at the coordinate");

  // 2. The same publisher and access group, now on the canonical construction.
  familyDelivery = "chain";
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
    "the retained exact candidate was among the bytes it offered, so the new wrap was tried against it",
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
    "a trial miss costs the exact issuer nothing",
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
    "the one new unlock filed the chain capability that reaches the canonical leaf at this coordinate",
  );

  // 4. The old render, reloaded: still opened by the retained independent
  //    exact candidate, and no issuer is asked a third time.
  const oldAgain = browser.load(rootFromPage(exactPage));
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
