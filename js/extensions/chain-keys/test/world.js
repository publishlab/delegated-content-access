// @ts-check
//
// The shapes a chain-key system case renders from: one geometry, a
// chain-key access policy, the publisher's chain supply and per-issuer
// delivery plan, the chain-capable browser wiring, and the small readers a case
// compares coordinates and bytes with. Test support for this extension alone,
// so base `test-lib/` cannot host it: a chain supply and a chain request
// builder belong with this directory.
//
// This file registers no test. Node runs the `*.test.js` files under this
// directory and nothing else, so shared shapes live in a plain module; another
// case importing a `.test.js` file would re-run it.

import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import {
  ACCESS_GROUP,
  CONTENT_NAME,
  keyDerivationSecret,
} from "../../../demo/scenarios/fixtures.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";

/** Two chains a day over fifteen-minute periods, the geometry these cases run on. */
export const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

/**
 * The chain route's future horizon and independent period authorization. A
 * content-key grant opens the render it was asked for without a period key.
 *
 * @param {number} futurePeriodCount - optional current-forward horizon
 * @param {(t: string) => boolean} [authorizePeriod] - trusted coordinate policy
 * @returns {{ decide: (claims: any, requested: { contentNames: string[], accessGroups: string[] }) => object }}
 */
export function periodOnlyPolicy(futurePeriodCount, authorizePeriod = () => true) {
  return {
    decide(_claims, requested) {
      return {
        contentNames: [],
        periodGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          futurePeriodCount,
          authorizePeriod,
        })),
      };
    },
  };
}

/**
 * A base-route fixture that explicitly selects up to maxGrantedLabels from
 * each group's admitted coordinates.
 *
 * @param {number} maxGrantedLabels
 */
export function basePeriodOnlyPolicy(maxGrantedLabels) {
  return {
    decide(_claims, requested) {
      return {
        contentNames: [],
        periodGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          periods: [...(requested.periodCoordinates[accessGroup] ?? [])].slice(0, maxGrantedLabels),
        })),
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
 * @param {number} [chainItemSlots]
 * @returns {any}
 */
export function chainSupply(generation, chainWindows = 2, chainItemSlots) {
  return periodFamilySupply({
    families: { [ACCESS_GROUP]: generation },
    chainWindows,
    ...(chainItemSlots === undefined ? {} : { chainItemSlots }),
  });
}

/**
 * A per-issuer delivery plan over one decision: what modes this issuer is
 * offered for this access group. The issuer is entrusted with the whole
 * render; only the representation of each group varies. The publisher is asked
 * once per issuer per render, so a plan that reads mutable state changes what
 * the next render delivers.
 *
 * @param {(issuer: { issuerName: string }, accessGroup: string) => string[]} modesFor
 * @returns {(issuer: { issuerName: string }, render: { accessGroups: string[], contentNames: string[] }) => object}
 */
export function deliveryPlan(modesFor) {
  return (issuer, render) => ({
    ...wholeRenderIssuerSupplyPlan(issuer, render),
    periodKeyDelivery: Object.fromEntries(
      render.accessGroups.map((accessGroup) => [accessGroup, modesFor(issuer, accessGroup)]),
    ),
  });
}

/**
 * A browser that relays chain keys and retains rival generations.
 *
 * @param {any} world
 * @returns {any}
 */
export function chainBrowser(world) {
  return world.makeBrowser({
    chainKeyStrategy: "retain",
    requestBuilderFactory: (/** @type {object} */ options) => new ChainKeyRequestBuilder(options),
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
 * the recording covers one step and nothing after it. The base cache answers
 * through `candidatesAt` and a chain cache through `candidates`.
 *
 * @template T
 * @param {any} cache
 * @param {() => Promise<T>} run
 * @param {"candidatesAt"|"candidates"} [method]
 * @returns {Promise<{ result: T, offered: Uint8Array[][] }>}
 */
export async function candidatesOffered(cache, run, method = "candidatesAt") {
  const answer = cache[method].bind(cache);
  /** @type {Uint8Array[][]} */
  const offered = [];
  Object.defineProperty(cache, method, {
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
    delete cache[method];
  }
}

/**
 * The unlock exchanges a network carried while `run` ran: each request a
 * client posted and the answer it got back. The issuer's stats count grants,
 * but only the answer says what a grant held, so a case asserting that an
 * issuer manufactured nothing reads it here.
 *
 * An instance property shadows the class method and is removed afterwards, as
 * in `candidatesOffered`.
 *
 * @template T
 * @param {any} network
 * @param {() => Promise<T>} run
 * @returns {Promise<{ result: T, exchanges: { url: string, request: any, status: number, body: any }[] }>}
 */
export async function exchangesPosted(network, run) {
  const post = network.post.bind(network);
  /** @type {{ url: string, request: any, status: number, body: any }[]} */
  const exchanges = [];
  Object.defineProperty(network, "post", {
    configurable: true,
    writable: true,
    value: async (
      /** @type {string} */ url,
      /** @type {any} */ request,
      /** @type {any} */ options,
    ) => {
      const answer = await post(url, request, options);
      exchanges.push({ url, request, status: answer.status, body: answer.body });
      return answer;
    },
  });

  try {
    return { result: await run(), exchanges };
  } finally {
    delete network.post;
  }
}
