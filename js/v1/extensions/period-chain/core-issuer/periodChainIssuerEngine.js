// @ts-check
//
// The frozen period-chain issuer composition. Base verifies and authorizes the
// request; the extension resolves explicit geometry, opens positioned state
// under the seven-field chain BIND, and projects authorized exact leaves into
// ordinary `periodKeys`. Chain response delivery is a separate client-facing
// capability and is not inferred from request relay. Choosing the `chain`
// representation counts as deployment policy: the choice assumes a
// chain-capable client and
// authorizes the stationary-window reach from window start through each
// selected cutoff.

import { dcaError } from "../../../core-shared/errors.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import {
  PERIOD_CHAIN_CONSTRUCTION,
  periodChainConstructionProfile,
} from "../core-shared/periodChainConstruction.js";
import { periodChainCapabilityEncoderFor } from "./periodChainCapabilityEncoder.js";
import { periodChainCapabilitySource } from "./periodChainCapabilitySource.js";

const MAX_DATE_EPOCH_MS = 8_640_000_000_000_000;

/**
 * This composition installs the period route for a chain-presented
 * family. A miss therefore closes the route instead of silently selecting the
 * base exact prefix, whose sorted-label meaning is different from a clock-started reach.
 *
 * @param {import('../../../core-issuer/IssuerEngine.js').PeriodCapabilitySource} source
 */
export function requireChainRepresentation(source) {
  return {
    ...(source.presented
      ? { presented: (request, invocation) => source.presented(request, invocation) }
      : {}),
    selection(request, invocation) {
      const select = source.selection(request, invocation);
      return (accessGroup, periodCount) => {
        const answer = select(accessGroup, periodCount);
        const cleanMiss =
          answer !== null &&
          typeof answer === "object" &&
          /** @type {any} */ (answer).miss === true &&
          !Object.hasOwn(answer, "selected") &&
          !Object.hasOwn(answer, "unavailable");
        return cleanMiss ? { unavailable: /** @type {true} */ (true) } : answer;
      };
    },
    capabilities: (unlock, invocation) => source.capabilities(unlock, invocation),
  };
}

/** @param {any} invocation @param {{ now: () => Date }|undefined} clock */
function sourceInvocation(invocation, clock) {
  if (
    invocation === undefined ||
    invocation === null ||
    invocation instanceof Date ||
    typeof invocation !== "object" ||
    Array.isArray(invocation)
  ) {
    const instant = invocation ?? clock?.now() ?? null;
    if (instant === null) {
      throw dcaError(
        "bad_config",
        "a chain issuer needs a clock or an application request instant",
      );
    }
    if (!(instant instanceof Date) || !Number.isFinite(instant.getTime())) {
      throw dcaError("bad_config", "an issuer request instant is a valid Date");
    }
    return { capturedAtMs: instant.getTime() };
  }
  if (
    !Object.hasOwn(invocation, "capturedAtMs") ||
    typeof invocation.capturedAtMs !== "number" ||
    !Number.isFinite(invocation.capturedAtMs) ||
    Math.abs(invocation.capturedAtMs) > MAX_DATE_EPOCH_MS
  ) {
    throw dcaError(
      "bad_config",
      "a chain issuer needs finite host-captured epoch milliseconds within Date range",
    );
  }
  return { capturedAtMs: invocation.capturedAtMs };
}

/**
 * @param {object} config
 * @param {string[]} [config.supportedVersions]
 * @param {{ decide: Function }} config.accessPolicy
 * @param {{ now: () => Date }} [config.clock]
 * @param {boolean} [config.developmentHttpOrigin]
 * @param {'exact'|'chain'} [config.representation]
 * @param {string} [config.construction] - the construction profile this route
 *   is on. An absent value means `dca-period-chain-v1`. One profile covers the
 *   whole route: the source opens states of its width, the encoder answers
 *   entries of that width, and base projects exact leaves of the profile's exact width.
 */
export function periodChainIssuerEngine({
  supportedVersions,
  accessPolicy,
  clock,
  developmentHttpOrigin = false,
  representation = "exact",
  construction = PERIOD_CHAIN_CONSTRUCTION,
}) {
  if (clock !== undefined && typeof clock?.now !== "function") {
    throw dcaError("bad_config", "a chain issuer clock is an object with a now()");
  }
  const profile = periodChainConstructionProfile(construction);
  const engine = new IssuerEngine({
    supportedVersions,
    accessPolicy,
    developmentHttpOrigin,
    periodCapabilitySource: requireChainRepresentation(
      periodChainCapabilitySource({
        representation,
        construction: profile.constructionId,
      }),
    ),
  });

  return {
    // This composition installs the selection route, so it declares that route
    // under either representation. The encoder map below states more narrowly
    // what this issuer sends back.
    selectedExtensions: Object.freeze(["period-chain"]),
    capabilityEncoders:
      representation === "chain"
        ? { "period-chain": periodChainCapabilityEncoderFor(profile.constructionId) }
        : {},
    async unlock(request, registration, policyInput = {}, invocation) {
      return engine.unlock(request, registration, policyInput, sourceInvocation(invocation, clock));
    },
  };
}
