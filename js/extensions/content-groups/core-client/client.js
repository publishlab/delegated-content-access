import {
  chainKeyCoordinate,
  settleChainGeometry,
} from "../../chain-keys/core-shared/chainKeyConstruction.js";

import { dcaError } from "../../../core-shared/errors.js";
import {
  CONTRACT,
  chainKeyPartition,
  periodKeyPartition,
  settleLimits,
} from "../core-shared/construction.js";
import { KIND_DESCRIPTORS } from "../core-shared--client-issuer/request.js";
import { contentGroupCandidateSource } from "./contentGroupCandidateSource.js";
import { contentGroupResponseInput } from "./contentGroupResponseInput.js";
import { ContentGroupRequestBuilder } from "./ContentGroupRequestBuilder.js";

const STOCK_CHAIN_GEOMETRY = Object.freeze({
  coordinate: chainKeyCoordinate,
  settleGeometry: settleChainGeometry,
});

/**
 * @typedef {object} ContentGroupClient
 * @property {import("../core-shared/construction.js").ContentGroupLimits} limits
 * @property {any} periodKeyCache - the dedicated content-group period-key cache
 * @property {any} chainKeyCache - the dedicated content-group chain-key cache
 * @property {Readonly<import("../../../core-client/ContentKeyResolver.js").RecoverySource>} recoverySource
 * @property {import("../../../core-client/ContentKeyResolver.js").ResponseSectionConsumer} responseInput
 * @property {typeof KIND_DESCRIPTORS} keyKinds - the two derivation kinds, for
 *   the host to settle with its selected client-bound transport
 * @property {(options: object) => ContentGroupRequestBuilder} requestBuilderFactory
 * @property {Readonly<{ requestBuilderFactory: (options: object) => ContentGroupRequestBuilder, recoverySources: object[], responseSections: object[] }>} composeOptions -
 *   the three `composeClient` members, ready to spread into its options or
 *   `createDeliveryClient`'s
 */

/**
 * The content-group client bundle over the shared client owners. It builds
 * one dedicated period-key cache and one dedicated chain-key cache, each
 * filing only its own entry kind under content-name partitions, the recovery
 * source the shared resolver runs over them, the response consumer that files
 * an admitted `contentGroups` answer into them, and the request builder. The
 * host supplies the two cache factories, preserving control over clocks and
 * durable storage. Geometry defaults to the required chain-key construction;
 * an explicit chain port can instrument or replace it. The period-key factory builds `adapter-client/PeriodKeyCache.js`,
 * the chain-key factory the chain-keys extension's `ChainKeyCache`. Neither
 * instance is ever the resolver's ordinary `cache` or `chainCache`.
 *
 * @param {object} config
 * @param {any} [config.chain] - optional trusted geometry/coordinate override
 * @param {Record<string, number>} [config.limits] - content-group limits; the
 *   caches take `maxCachedWindows`, `maxWindowsPerGroup`, `maxRivalsPerWindow`
 *   and `maxResponseMembers`, the source `maxTrialsPerItem`, the builder and the
 *   response consumer the request and response bounds
 * @param {Record<string, unknown>} [config.narrowing] - trusted local request
 *   selection; see `ContentGroupRequestBuilder`
 * @param {(config: object) => any} config.createPeriodKeyCache
 * @param {(config: object) => any} config.createChainKeyCache
 * @param {object} [config.storage] - durable storage for both caches
 * @param {string} [config.namespace] - the logical client in that storage
 * @returns {Readonly<ContentGroupClient>}
 */
export function createContentGroupClient({
  chain = STOCK_CHAIN_GEOMETRY,
  limits: inputLimits,
  narrowing,
  createPeriodKeyCache,
  createChainKeyCache,
  storage,
  namespace,
}) {
  if (typeof createPeriodKeyCache !== "function" || typeof createChainKeyCache !== "function")
    throw dcaError(
      "bad_config",
      "a content-group client takes period-key and chain-key cache factories",
    );
  if (namespace !== undefined && storage === undefined)
    throw dcaError("bad_config", "a content-group client namespace names a client in its storage");
  let limits;
  try {
    limits = settleLimits(inputLimits);
  } catch (cause) {
    throw Object.assign(dcaError("bad_config", /** @type {Error} */ (cause).message), { cause });
  }
  const durable = {
    ...(storage === undefined ? {} : { storage }),
    ...(namespace === undefined ? {} : { namespace }),
  };
  const periodKeyCache = createPeriodKeyCache({
    entryKind: CONTRACT.keyKinds.periodKey,
    maxEntries: limits.maxCachedWindows,
    ...durable,
  });
  const chainKeyCache = createChainKeyCache({
    entryKind: CONTRACT.keyKinds.chainKey,
    periodView: "none",
    maxRivalsPerWindow: limits.maxRivalsPerWindow,
    // One content-group answer carries up to maxResponseMembers chain keys,
    // more than the chain-keys message bound,
    maxMembersPerMessage: limits.maxResponseMembers,
    // and up to maxWindowsPerGroup windows of one content name and group.
    maxMembersPerFamily: limits.maxWindowsPerGroup,
    maxWindowsPerFamily: limits.maxWindowsPerGroup,
    maxWindows: limits.maxCachedWindows,
    ...durable,
  });
  if (typeof chainKeyCache?.put !== "function" || typeof periodKeyCache?.put !== "function")
    throw dcaError("bad_config", "a content-group client files into caches that answer put");
  const recoverySource = contentGroupCandidateSource({
    chain,
    periodKeyCache,
    chainKeyCache,
    limits,
  });

  /**
   * File one admitted answer: chain keys under the response lease until the
   * resolver completes the attempt, period keys under their partition. The
   * partitions name the trusted page origin, never an issuer, so a key one
   * entrusted issuer returned serves a page another issuer also covers.
   * @param {import("./contentGroupResponseInput.js").AdmittedContentGroupResponse} admitted
   */
  async function retain({ publisher, periodGeometry, chains, periods, lease }) {
    // Item keys are held in the current render, without a reusable-cache partition.
    if (chains.length === 0 && periods.length === 0) return;
    if (publisher === undefined)
      throw dcaError("bad_page", "the page has no publisher context origin to file keys under");
    const { chainsPerDay, periodMinutes } = periodGeometry;
    for (const { contentName, group, cutoffT, key } of chains)
      await chainKeyCache.put(group, cutoffT, key, {
        partition: chainKeyPartition(publisher, periodGeometry, contentName, group),
        lease,
        chainsPerDay,
        periodMinutes,
      });
    for (const { contentName, group, t, key } of periods)
      await periodKeyCache.put(group, t, key, {
        partition: periodKeyPartition(publisher, periodGeometry, contentName, group),
        lease,
      });
  }

  // The recovery source owns both caches' completion and reset; the consumer
  // holds nothing of its own between calls.
  const responseInput = contentGroupResponseInput({
    chain,
    limits,
    retain,
    clearReaderContext: async () => {},
  });
  /** @param {object} options - the base request options composeClient passes */
  const requestBuilderFactory = (options) =>
    new ContentGroupRequestBuilder({
      ...options,
      limits,
      ...(narrowing === undefined ? {} : { narrowing }),
    });
  return Object.freeze({
    limits,
    periodKeyCache,
    chainKeyCache,
    recoverySource,
    responseInput,
    keyKinds: KIND_DESCRIPTORS,
    requestBuilderFactory,
    composeOptions: Object.freeze({
      requestBuilderFactory,
      recoverySources: [recoverySource],
      responseSections: [responseInput],
    }),
  });
}
