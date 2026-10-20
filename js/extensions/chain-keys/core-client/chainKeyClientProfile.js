// @ts-check
// Client-role composition for the optional chain-key profile. This entry owns
// response admission and candidate-source wiring without publisher or issuer
// generation, supply or engine dependencies.

import { chainKeyCandidateSource } from "./chainKeyCandidateSource.js";
import { chainKeyResponseInput } from "./chainKeyResponseInput.js";
import {
  requestCarrierOf,
  cutoffWithinPresentedReach,
  acceptsPeriodKeyResponseCoordinate,
} from "./periodKeyResponseCoordinate.js";
import {
  CHAIN_KEY_CONSTRUCTION,
  chainKeyConstructionProfile,
  chainKeyCoordinate,
} from "../core-shared/chainKeyConstruction.js";
import { chainMemberLimit } from "../../../core-shared/chainMemberLimit.js";
import { MAX_CHAIN_MEMBERS_PER_MESSAGE } from "../../../core-shared/geometryBounds.js";

// One carrier view per response and immutable associated request. Responses can
// be reused by a host, so response identity alone cannot select the request pair.
/** @type {WeakMap<object, Map<number, WeakMap<object, any>>>} */
const resolvedResponses = new WeakMap();

/** @param {unknown} response @param {unknown} request @param {number} maximum */
function responseCarrierOf(response, request, maximum) {
  if (
    response === null ||
    typeof response !== "object" ||
    request === null ||
    typeof request !== "object"
  )
    return chainKeyResponseInput(response, request, { maxChainMembersPerMessage: maximum });
  let capacities = resolvedResponses.get(request);
  if (capacities === undefined) {
    capacities = new Map();
    resolvedResponses.set(request, capacities);
  }
  let responses = capacities.get(maximum);
  if (responses === undefined) {
    responses = new WeakMap();
    capacities.set(maximum, responses);
  }
  let view = responses.get(response);
  if (view === undefined) {
    view = chainKeyResponseInput(response, request, { maxChainMembersPerMessage: maximum });
    responses.set(response, view);
  }
  return view;
}

/** @param {unknown} t @param {object} geometry */
function acceptsExplicitResponseCoordinate(t, geometry) {
  try {
    chainKeyCoordinate(t, /** @type {any} */ (geometry));
    return true;
  } catch {
    return false;
  }
}

/**
 * A chain opening error names the exact valid source member the request presented.
 *
 * @param {string} accessGroup
 * @param {string} t
 * @param {unknown} request
 * @param {number} maximum
 */
function acceptsPresentedErrorCoordinate(accessGroup, t, request, maximum) {
  const asked = requestCarrierOf(request, maximum).family(accessGroup);
  return (
    asked.kind === "valid" &&
    asked.members.some((/** @type {{ t: string }} */ member) => member.t === t)
  );
}

/**
 * The client-side bundle of one named construction profile, for explicit
 * response and article geometry. The bundle names its construction so the
 * resolver it is injected into reads one profile everywhere: the cache
 * partition, the chain-key width it files, and the period keys that
 * construction derives. Response and article geometry are the same questions under either
 * profile, so only the identity and the cache the candidate source reads
 * differ.
 *
 * @param {string} [construction] - absent is `dca-construction-chain-keys`
 * @param {{ maxChainMembersPerMessage?: number }} [config] - trusted capacity, default 16
 * @returns {Readonly<ReturnType<typeof explicitClientProfileFor>>}
 */
export function chainKeyClientProfileFor(
  construction = CHAIN_KEY_CONSTRUCTION,
  { maxChainMembersPerMessage } = {},
) {
  const maximum = chainMemberLimit(maxChainMembersPerMessage);
  return Object.freeze({
    ...explicitClientProfileFor(maximum),
    constructionProfile: chainKeyConstructionProfile(construction),
  });
}

/** Client-side profile of the construction a composition naming none is on. */
/** @param {number} maximum */
function explicitClientProfileFor(maximum) {
  return Object.freeze({
    constructionProfile: chainKeyConstructionProfile(CHAIN_KEY_CONSTRUCTION),
    /**
     * The geometry a returned family may be filed under, or nothing. A cutoff
     * is admitted only for a family the request presented and only under the
     * pair that request resolved for it: a differing or missing request-side
     * pair leaves the family with no geometry, and that outcome admits no cutoff
     * and retains nothing. A projected period key never reaches here.
     *
     * @param {unknown} response
     * @param {unknown} _dcaData
     * @param {string} accessGroup
     * @param {unknown} [request] - the request document this response answers
     * @param {string} [cutoffT] - the returned cutoff being admitted
     */
    parametersForResponse(response, _dcaData, accessGroup, request, cutoffT) {
      const returned = responseCarrierOf(response, request, maximum).family(accessGroup);
      if (returned.kind !== "valid") return null;
      const asked = requestCarrierOf(request, maximum).family(accessGroup);
      if (asked.kind !== "valid") return null;
      if (typeof cutoffT !== "string" || !cutoffWithinPresentedReach(cutoffT, asked)) return null;
      return asked.geometry;
    },
    /** @param {string} accessGroup @param {string} t @param {unknown} request */
    acceptsPeriodKeyResponseCoordinate: (accessGroup, t, request) =>
      acceptsPeriodKeyResponseCoordinate(accessGroup, t, request, maximum),
    acceptsResponseCoordinate: acceptsExplicitResponseCoordinate,
    /** @param {string} accessGroup @param {string} t @param {unknown} request */
    acceptsPresentedErrorCoordinate: (accessGroup, t, request) =>
      acceptsPresentedErrorCoordinate(accessGroup, t, request, maximum),
    /** The optional ordinary view composes with the base cache under one rival
     * ceiling and shared filing order. Legacy injected chain caches may omit it.
     * @param {{ cache: any }} input
     * @returns {{ candidatesAt: Function, candidateEntriesAt?: Function, attempted: () => Promise<void> }|null}
     */
    periodCacheFor({ cache }) {
      if (typeof cache?.periodCandidates !== "function") return null;
      return {
        candidatesAt: cache.periodCandidates.bind(cache),
        candidateEntriesAt:
          typeof cache.periodCandidateEntries === "function"
            ? cache.periodCandidateEntries.bind(cache)
            : undefined,
        attempted: () => Promise.resolve(),
      };
    },
    // Ordinary derived periods remain usable without render geometry; the source
    // consults geometry only when it needs actual chain derivation.
    candidateSourceFor: (/** @type {{ cache: any }} */ { cache }) => chainKeyCandidateSource(cache),
  });
}

export const explicitChainKeyClientProfile = explicitClientProfileFor(
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
);
