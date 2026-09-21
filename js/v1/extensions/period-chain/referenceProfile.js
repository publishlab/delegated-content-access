// @ts-check

// The reference period-chain capability is composed outside the base role
// cores. It supplies one geometry to publisher, issuer and client without
// making a normal exact-period deployment depend on chains.
//
// The publisher half generates the family. `familyGenerationFor` makes one
// immutable generation of the frozen `dca-period-chain-v1` construction over a
// family root and a complete geometry, and `exactSupplyFor` narrows it to the
// `derive(accessGroup, t)` the base `Sealer` takes. The composition keeps the
// generation itself, which is what a later issuer-supply plan asks for a
// positioned capability; base receives the narrow supply and no way back to it.
// The client response/cache half consumes only explicit frozen-v1 geometry.

import {
  exactPeriodKeySupplyFor,
  periodFamilyGeneration,
} from "./core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "./core-publisher/periodFamilySupply.js";
import { periodChainIssuerEngine } from "./core-issuer/periodChainIssuerEngine.js";
import { periodChainCandidateSource } from "./core-client/periodChainCandidateSource.js";
import { periodChainResponseInput } from "./core-client/periodChainResponseInput.js";
import { periodChainCarrierReader } from "./core-shared--client-issuer/periodChainCarrierReader.js";
import {
  PERIOD_CHAIN_CONSTRUCTION,
  periodChainConstructionProfile,
  periodChainCoordinate,
} from "./core-shared/periodChainConstruction.js";
import { own } from "../../core-shared/wire.js";

// A resolver asks for the parameters of each access group it files. Keep the
// decided carrier view by response identity so every answer comes from one
// reading of the ordinary production path.
/** @type {WeakMap<object, any>} */
const resolvedResponses = new WeakMap();

/** @param {unknown} response */
function responseCarrierOf(response) {
  if (response === null || typeof response !== "object") return periodChainResponseInput(response);
  const held = resolvedResponses.get(response);
  if (held !== undefined) return held;
  const view = periodChainResponseInput(response);
  resolvedResponses.set(response, view);
  return view;
}

// The request this answer came back to, read through the same carrier reader
// the issuer reads it with, and kept by request identity so one response
// association costs one reading whatever the number of access groups. The
// client profile reads the request itself rather than importing the issuer's
// request module, which stays on the issuer side of the extension.
/** @type {WeakMap<object, any>} */
const resolvedRequests = new WeakMap();

/** @param {unknown} request */
function requestCarrierOf(request) {
  const read = () =>
    periodChainCarrierReader({
      container: own(request, "sealed"),
      context: own(request, "periodChain"),
      valueName: "sealed",
    });
  if (request === null || typeof request !== "object") return read();
  const held = resolvedRequests.get(request);
  if (held !== undefined) return held;
  const view = read();
  resolvedRequests.set(request, view);
  return view;
}

/**
 * The pair a family is settled on. Two resolutions of one pair are separate
 * frozen objects, and a document-wide pair and an equal family override settle
 * the same way, so the comparison is over the two wire values and not over
 * placement or identity.
 *
 * @param {{ chainsPerDay: number, periodMinutes: number }} asked
 * @param {{ chainsPerDay: number, periodMinutes: number }} returned
 */
function samePair(asked, returned) {
  return (
    asked.chainsPerDay === returned.chainsPerDay && asked.periodMinutes === returned.periodMinutes
  );
}

/**
 * A response cutoff is reachable from at least one source member the associated
 * request presented: same stationary window, at or below its supplied
 * position.
 *
 * @param {string} cutoffT
 * @param {{ geometry: object, members: readonly { coordinate: { windowStart: number, position: number } }[] }} asked
 */
function cutoffWithinPresentedReach(cutoffT, asked) {
  let cutoff;
  try {
    cutoff = periodChainCoordinate(cutoffT, /** @type {any} */ (asked.geometry));
  } catch {
    return false;
  }
  return asked.members.some(
    ({ coordinate }) =>
      coordinate.windowStart === cutoff.windowStart && cutoff.position <= coordinate.position,
  );
}

/** @param {unknown} value */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * An exact leaf may be an exact coordinate the request relayed unchanged or a
 * projection reachable from one of its chain members. Projected leaves use
 * request geometry; the response needs none.
 *
 * @param {string} accessGroup
 * @param {string} t
 * @param {unknown} request
 */
function acceptsExactResponseCoordinate(accessGroup, t, request) {
  const sealed = own(request, "sealed");
  const exactFamily = own(own(sealed, "periodKeys"), accessGroup);
  if (record(exactFamily) && typeof own(exactFamily, t) === "string") return true;

  const asked = requestCarrierOf(request).family(accessGroup);
  return asked.kind === "valid" && cutoffWithinPresentedReach(t, asked);
}

/** @param {unknown} t @param {object} geometry */
function acceptsExplicitResponseCoordinate(t, geometry) {
  try {
    periodChainCoordinate(t, /** @type {any} */ (geometry));
    return true;
  } catch {
    return false;
  }
}

/** A chain opening error names the exact valid source member the request presented. */
function acceptsPresentedErrorCoordinate(accessGroup, t, request) {
  const asked = requestCarrierOf(request).family(accessGroup);
  return asked.kind === "valid" && asked.members.some((member) => member.t === t);
}

/**
 * The client-side bundle of one named construction profile, for explicit
 * response and article geometry. The bundle names its construction so the
 * resolver it is injected into reads one profile everywhere: the cache
 * partition, the state width it files, and the exact leaves that construction
 * derives. Response and article geometry are the same questions under either
 * profile, so only the identity and the cache the candidate source reads
 * differ.
 *
 * @param {string} [construction] - absent is `dca-period-chain-v1`
 */
export function periodChainClientProfileFor(construction = PERIOD_CHAIN_CONSTRUCTION) {
  return Object.freeze({
    ...explicitPeriodChainClientProfile,
    constructionProfile: periodChainConstructionProfile(construction),
  });
}

/** Client-side profile of the construction a composition naming none is on. */
export const explicitPeriodChainClientProfile = Object.freeze({
  constructionProfile: periodChainConstructionProfile(PERIOD_CHAIN_CONSTRUCTION),
  /**
   * The geometry a returned family may be filed under, or nothing. A cutoff
   * is admitted only for a family the request presented and only under the
   * pair that request resolved for it: a differing or missing request-side
   * pair leaves the family with no geometry, and that outcome admits no cutoff
   * and retains nothing. A projected exact leaf never reaches here.
   *
   * @param {unknown} response
   * @param {unknown} _dcaData
   * @param {string} accessGroup
   * @param {unknown} [request] - the request document this response answers
   * @param {string} [cutoffT] - the returned cutoff being admitted
   */
  parametersForResponse(response, _dcaData, accessGroup, request, cutoffT) {
    const returned = responseCarrierOf(response).family(accessGroup);
    if (returned.kind !== "valid") return null;
    const asked = requestCarrierOf(request).family(accessGroup);
    if (asked.kind !== "valid") return null;
    if (!samePair(asked.geometry, returned.geometry)) return null;
    if (typeof cutoffT !== "string" || !cutoffWithinPresentedReach(cutoffT, asked)) return null;
    return returned.geometry;
  },
  acceptsExactResponseCoordinate,
  acceptsResponseCoordinate: acceptsExplicitResponseCoordinate,
  acceptsPresentedErrorCoordinate,
  candidateSourceFor: (/** @type {{ cache: any }} */ { cache }) =>
    periodChainCandidateSource(cache),
});

/**
 * The whole reference composition of one named construction profile: the
 * publisher generation, the issuer route and the client bundle, all on that one
 * profile. A composition naming none is on `dca-period-chain-v1`, so every
 * existing caller composes what it always composed.
 *
 * @param {string} [construction]
 */
export function referencePeriodChainProfileFor(construction = PERIOD_CHAIN_CONSTRUCTION) {
  const { constructionId } = periodChainConstructionProfile(construction);
  return Object.freeze({
    // The publisher half: one generation, and the exact-only view of it that
    // base is handed.
    /** @param {object} config */
    familyGenerationFor: (config) =>
      periodFamilyGeneration({
        .../** @type {any} */ (config),
        construction: constructionId,
      }),
    exactSupplyFor: exactPeriodKeySupplyFor,
    familySupplyFor: periodFamilySupply,
    ...periodChainClientProfileFor(constructionId),
    // A deployment selects chain output only for chain-capable clients and
    // thereby authorizes stationary-window-start through cutoff reach.
    /** @param {object} config */
    issuerEngineFor: (config) =>
      periodChainIssuerEngine({
        .../** @type {any} */ (config),
        representation: "chain",
        construction: constructionId,
      }),

    // Relay-capable, exact-only issuer projection.
    /** @param {object} config */
    explicitIssuerEngineFor: (config) =>
      periodChainIssuerEngine({
        .../** @type {any} */ (config),
        construction: constructionId,
      }),
  });
}

/** The reference composition of the construction a caller naming none is on. */
export const referencePeriodChainProfile =
  referencePeriodChainProfileFor(PERIOD_CHAIN_CONSTRUCTION);
