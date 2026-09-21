// @ts-check
//
// The shapes a period-chain system case renders from: one geometry, a
// period-only access policy, the publisher's chain supply and per-issuer
// delivery plan, the chain-capable browser wiring, and the small readers a case
// compares coordinates and bytes with. Test support for this extension alone,
// so base `test-lib/` cannot host it: a chain supply and a chain request
// builder belong with this directory.
//
// This file registers no test. Node runs the `*.test.js` files under this
// directory and nothing else, so shared shapes live in a plain module; another
// case importing a `.test.js` file would re-run it.

import { PeriodChainRequestBuilder } from "../core-client/PeriodChainRequestBuilder.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import {
  ACCESS_GROUP,
  CONTENT_NAME,
  keyDerivationSecret,
} from "../../../demo/scenarios/fixtures.js";

/** Two chains a day over fifteen-minute periods, the geometry these cases run on. */
export const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

/**
 * Period material and nothing else. A direct content-key grant opens the render
 * it was asked for without any period key at all, so an issuer handing one over
 * would settle an open before the cached path was reached.
 *
 * @param {number} periodCount - how many periods one grant covers
 * @returns {{ decide: (claims: any, requested: { contentNames: string[], accessGroups: string[] }) => object }}
 */
export function periodOnlyPolicy(periodCount) {
  return {
    decide(_claims, requested) {
      return {
        contentNames: [],
        periodGrants: requested.accessGroups.map((accessGroup) => ({ accessGroup, periodCount })),
      };
    },
  };
}

/**
 * One immutable generation of the canonical construction, over the geometry
 * above. A different fill gives a different family root, the root a rotation
 * moves the publisher onto.
 *
 * @param {number} fill
 * @returns {any}
 */
export function chainGeneration(fill) {
  return periodFamilyGeneration({
    keyDerivationSecret: keyDerivationSecret(fill),
    geometry: GEOMETRY,
  });
}

/**
 * The publisher supply that plans one generation for this access group.
 *
 * @param {any} generation
 * @param {number} [chainWindows]
 * @returns {any}
 */
export function chainSupply(generation, chainWindows = 2) {
  return periodFamilySupply({ families: { [ACCESS_GROUP]: generation }, chainWindows });
}

/**
 * A per-issuer delivery plan over one decision: what modes this issuer is
 * offered for this access group. The publisher is asked once per issuer per
 * render, so a plan that reads mutable state changes what the next render
 * delivers.
 *
 * @param {(issuer: { issuerName: string }, accessGroup: string) => string[]} modesFor
 * @returns {(issuer: { issuerName: string }, render: { accessGroups: string[] }) => object}
 */
export function deliveryPlan(modesFor) {
  return (issuer, { accessGroups }) => ({
    periodKeyDelivery: Object.fromEntries(
      accessGroups.map((accessGroup) => [accessGroup, modesFor(issuer, accessGroup)]),
    ),
  });
}

/**
 * A browser that relays chain state and retains rival generations.
 *
 * @param {any} world
 * @returns {any}
 */
export function chainBrowser(world) {
  return world.makeBrowser({
    periodChainStrategy: "retain",
    requestBuilderFactory: (/** @type {object} */ options) =>
      new PeriodChainRequestBuilder(options),
  });
}

/**
 * What a chain cache holds for one coordinate of this publisher's family.
 *
 * @param {any} chainCache
 * @param {any} world
 * @param {string} t
 * @returns {Promise<Uint8Array[]>}
 */
export function chainPartition(chainCache, world, t) {
  return chainCache.candidates(ACCESS_GROUP, t, {
    publisher: world.publisher.origin,
    chainsPerDay: GEOMETRY.chainsPerDay,
    periodMinutes: GEOMETRY.periodMinutes,
  });
}

/**
 * The coordinates one render wrapped its bodytext under, in the order the page
 * lists them. Read off the page the client is handed, so an assertion about
 * overlap is about what crossed.
 *
 * @param {any} page
 * @returns {string[]}
 */
export function coordinatesOf(page) {
  return page
    .asJson()
    .contentData[CONTENT_NAME].keys[ACCESS_GROUP].map(
      (/** @type {{ t: string }} */ entry) => entry.t,
    );
}

/** @param {Uint8Array} a @param {Uint8Array} b */
export function sameBytes(a, b) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

/**
 * The answers a cache gave while `run` ran, one entry per consultation. A step
 * could only work with the candidates it was offered, and the client reaches
 * the cache through its own path, so an assertion about them says what the
 * client saw, not what the cache holds.
 *
 * An instance property shadows the class method and is removed afterwards, so
 * the recording covers one step and nothing after it.
 *
 * @template T
 * @param {any} cache
 * @param {() => Promise<T>} run
 * @returns {Promise<{ result: T, offered: Uint8Array[][] }>}
 */
export async function candidatesOffered(cache, run) {
  const answer = cache.candidatesAt.bind(cache);
  /** @type {Uint8Array[][]} */
  const offered = [];
  Object.defineProperty(cache, "candidatesAt", {
    configurable: true,
    writable: true,
    value: async (/** @type {any[]} */ ...args) => {
      const held = await answer(...args);
      offered.push(held);
      return held;
    },
  });

  try {
    return { result: await run(), offered };
  } finally {
    delete cache.candidatesAt;
  }
}
