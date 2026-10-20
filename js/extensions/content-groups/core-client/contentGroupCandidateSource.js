// @ts-check
//
// Content-group connector recovery as one recovery source of the shared
// `ContentKeyResolver`. For one item it reads the named connector routes and
// the render coordinate once, before any await, then asks the dedicated
// period-key cache and after it the dedicated chain-key cache for keys at the
// render period, each under the item's own content-name partition. Each key
// pads with the page's render ID and the content name, and the pad XOR the
// route's connector is one candidate content key. The resolver authenticates
// every candidate against the item's sealed bytes, bounds the trials and holds
// the first that opens; a candidate proves nothing until then.
//
// The source calls `check()` after every await, so a reader reset during a
// cache read or a pad derivation ends the walk before it reads another cache
// or yields. The caches fence their own filings and reads as well.

import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import {
  CONTRACT,
  chainKeyPartition,
  checkedConnectors,
  checkedScope,
  itemPad,
  periodKeyPartition,
  xor16,
} from "../core-shared/construction.js";

/**
 * The period-key cache reads this source makes. A dedicated instance with the
 * content-group period-key entry kind answers them.
 *
 * @typedef {object} ContentGroupPeriodKeyCache
 * @property {(group: string, t: string, context: { partition: object, lease?: object }) => Promise<(Uint8Array|CryptoKey)[]>} candidatesAt
 * @property {(context: { lease: object }) => Promise<void>} attempted
 * @property {() => Promise<void>} clearReaderContext
 */

/**
 * The chain-key cache reads this source makes: period keys derived at `t` from
 * the chain keys of one partition. A dedicated instance with the content-group
 * chain-key entry kind and no ordinary period view answers them.
 *
 * @typedef {object} ContentGroupChainKeyCache
 * @property {(group: string, t: string, context: { partition: object, lease?: object, chainsPerDay: number, periodMinutes: number, chainCandidateBudget: { remaining: number } }) => Promise<Uint8Array[]>} candidates
 * @property {(context: { lease: object }) => Promise<void>} [promote]
 * @property {(context: { lease: object }) => Promise<void>} attempted
 * @property {() => Promise<void>} clearReaderContext
 */

/**
 * The item's routes and render coordinate, read in one synchronous pass. An
 * item without an admitted connector map, or a page without an admitted
 * geometry and render period, has no connector route here; the request side
 * refuses such an item before any issuer sees it.
 *
 * @param {import("../../../core-client/DcaData.js").DcaData} dcaData
 * @param {string} contentName
 * @param {any} chain
 * @param {{ maxGroups: number }} limits
 * @returns {{ routes: { group: string, connector: Uint8Array }[], geometry: { chainsPerDay: number, periodMinutes: number }, t: string }|null}
 */
function itemRoutes(dcaData, contentName, chain, limits) {
  const record = dcaData.contentDataFor(contentName);
  if (record === undefined) return null;
  const connectors = own(record, CONTRACT.wire.connectors);
  if (connectors === undefined) return null;
  let routes;
  let scope;
  try {
    routes = checkedConnectors(connectors, limits);
    scope = checkedScope(dcaData.toObject(), chain);
  } catch {
    return null;
  }
  return {
    routes: routes.map(({ group, connector }) => ({
      group,
      connector: /** @type {Uint8Array} */ (binaryStringBytes(connector)),
    })),
    geometry: scope.geometry,
    t: scope.period.t,
  };
}

/**
 * @param {{ chain: any, periodKeyCache: ContentGroupPeriodKeyCache, chainKeyCache: ContentGroupChainKeyCache, limits: import("../core-shared/construction.js").ContentGroupLimits }} config
 *   `chain` is the host's chain port (`settleGeometry`, `coordinate`);
 *   `limits` are settled content-group limits
 * @returns {Readonly<import("../../../core-client/ContentKeyResolver.js").RecoverySource>}
 */
export function contentGroupCandidateSource({ chain, periodKeyCache, chainKeyCache, limits }) {
  if (typeof chain?.coordinate !== "function" || typeof chain?.settleGeometry !== "function")
    throw dcaError("bad_config", "a content-group candidate source needs the host's chain port");
  if (
    typeof periodKeyCache?.candidatesAt !== "function" ||
    typeof chainKeyCache?.candidates !== "function"
  )
    throw dcaError(
      "bad_config",
      "a content-group candidate source reads a period-key cache and a chain-key cache",
    );
  // Completion and reset run only after an answer or at logout; a cache missing
  // either would fault an entitled open or latch the reset, so refuse it here.
  if (
    [periodKeyCache, chainKeyCache].some(
      (cache) =>
        typeof cache.attempted !== "function" || typeof cache.clearReaderContext !== "function",
    ) ||
    (chainKeyCache.promote !== undefined && typeof chainKeyCache.promote !== "function")
  )
    throw dcaError(
      "bad_config",
      "a content-group candidate source completes and resets both caches: attempted, clearReaderContext",
    );
  if (!Number.isSafeInteger(limits?.maxTrialsPerItem) || !Number.isSafeInteger(limits?.maxGroups))
    throw dcaError("bad_config", "a content-group candidate source takes settled limits");

  return Object.freeze({
    maxTrialsPerItem: limits.maxTrialsPerItem,

    /** @param {import("../../../core-client/ContentKeyResolver.js").RecoveryContext} context */
    async *candidates({ dcaData, contentName, publisher, renderId, lease, check }) {
      if (publisher === undefined) return;
      const item = itemRoutes(dcaData, contentName, chain, limits);
      if (item === null || item.routes.length === 0) return;
      const { routes, geometry, t } = item;
      // One allowance for this item, across every ordinary-period and chain
      // route. The chain cache spends it before derivation, not after dedup.
      /** @type {{ remaining: number }} */
      const chainCandidateBudget = { remaining: limits.maxTrialsPerItem };

      /**
       * @param {Uint8Array|CryptoKey} periodKey
       * @param {Uint8Array} connector
       */
      const padded = async (periodKey, connector) => {
        if (!(periodKey instanceof Uint8Array) || periodKey.length !== 16) return null;
        const pad = await itemPad(periodKey, { renderId, contentName });
        check();
        return xor16(connector, pad);
      };

      for (const { group, connector } of routes) {
        if (chainCandidateBudget.remaining === 0) return;
        const partition = periodKeyPartition(publisher, geometry, contentName, group);
        const keys = await periodKeyCache.candidatesAt(group, t, { partition, lease });
        check();
        for (const periodKey of keys) {
          if (chainCandidateBudget.remaining === 0) return;
          chainCandidateBudget.remaining--;
          const contentKey = await padded(periodKey, connector);
          if (contentKey) yield { contentKey, origin: { route: "period-key", group, t } };
        }
      }
      for (const { group, connector } of routes) {
        if (chainCandidateBudget.remaining === 0) return;
        const partition = chainKeyPartition(publisher, geometry, contentName, group);
        const keys = await chainKeyCache.candidates(group, t, {
          partition,
          lease,
          chainsPerDay: geometry.chainsPerDay,
          periodMinutes: geometry.periodMinutes,
          chainCandidateBudget,
        });
        check();
        for (const periodKey of keys) {
          const contentKey = await padded(periodKey, connector);
          if (contentKey) yield { contentKey, origin: { route: "chain-key", group, t } };
        }
      }
    },

    /** @param {{ lease: object }} context */
    async promote(context) {
      await chainKeyCache.promote?.(context);
    },

    /** @param {{ lease: object }} context */
    async attempted(context) {
      const results = await Promise.allSettled([
        periodKeyCache.attempted(context),
        chainKeyCache.attempted(context),
      ]);
      const failed = results.find((result) => result.status === "rejected");
      if (failed?.status === "rejected") throw failed.reason;
    },

    /** Retire both dedicated caches; the first failure stays visible. */
    async clearReaderContext() {
      const results = await Promise.allSettled([
        periodKeyCache.clearReaderContext(),
        chainKeyCache.clearReaderContext(),
      ]);
      const failed = results.find((result) => result.status === "rejected");
      if (failed?.status === "rejected") throw failed.reason;
    },
  });
}
