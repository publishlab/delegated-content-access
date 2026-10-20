// @ts-check
//
// The frozen chain-key issuer composition. Base verifies and authorizes the
// request; the extension resolves explicit geometry, opens positioned chain keys
// under the seven-field chain BIND, and projects authorized period keys into
// ordinary `periodKeys`. Chain-key response delivery is a separate client-facing
// capability and is not inferred from request relay. Choosing the `chain-keys`
// representation assumes a chain-capable client; the trusted period authorizer
// must still permit the whole stationary-window prefix through each cutoff.

import { dcaError } from "../../../core-shared/errors.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import {
  CHAIN_KEY_CONSTRUCTION,
  chainKeyConstructionProfile,
} from "../core-shared/chainKeyConstruction.js";
import { chainKeyCapabilityEncoderFor } from "./chainKeyCapabilityEncoder.js";
import { chainKeyCapabilitySource } from "./chainKeyCapabilitySource.js";

const MAX_DATE_EPOCH_MS = 8_640_000_000_000_000;

/**
 * An independent chain-horizon grant must never fall through to the base
 * sorted-label prefix: those grants have different reach. An ordinary
 * explicit-label grant is already bounded to trusted named coordinates and
 * may use the base period-key route when the chain source has a clean miss.
 *
 * @param {import('../../../core-issuer/IssuerEngine.js').PeriodCapabilitySource} source
 * @returns {import('../../../core-issuer/IssuerEngine.js').PeriodCapabilitySource}
 */
export function requireChainRepresentation(source) {
  const presented = source.presented;
  /** @type {import('../../../core-issuer/IssuerEngine.js').PeriodCapabilitySource} */
  const required = {
    ...(presented ? { presented: (request, invocation) => presented(request, invocation) } : {}),
    selection(request, invocation, trustedGrants) {
      const select = source.selection(request, invocation, trustedGrants);
      return (accessGroup, periodCount, grant) => {
        const answer = select(accessGroup, periodCount, grant);
        const cleanMiss =
          answer !== null &&
          typeof answer === "object" &&
          /** @type {any} */ (answer).miss === true &&
          !Object.hasOwn(answer, "selected") &&
          !Object.hasOwn(answer, "unavailable");
        return cleanMiss && grant?.authorizePeriod !== undefined
          ? { unavailable: /** @type {true} */ (true) }
          : answer;
      };
    },
    capabilities: (unlock, invocation) => source.capabilities(unlock, invocation),
  };
  return required;
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
 * @param {string[]} config.operatingIssuerNames
 * @param {import('../../../core-issuer/IssuerEngine.js').AccessPolicy} config.accessPolicy
 * @param {{ now: () => Date }} [config.clock]
 * @param {boolean} [config.developmentHttpOrigin]
 * @param {'period-keys'|'chain-keys'} [config.representation]
 * @param {number} [config.maxChainMembersPerMessage] - trusted ingress/output capacity, default 16
 * @param {string} [config.construction] - the construction profile this route
 *   is on. An absent value means `dca-construction-chain-keys`. One profile covers the
 *   whole route: the source opens chain keys of its width, the encoder answers
 *   entries of that width, and base projects period keys of the profile's period-key width.
 * @param {'none'|'partial'|'complete'} [config.notDeliveredReport] - which
 *   `notDelivered` family reports the base engine discloses, as
 *   `IssuerEngine` takes it; "none" when left out.
 */
export function chainKeyIssuerEngine({
  supportedVersions,
  operatingIssuerNames,
  accessPolicy,
  clock,
  developmentHttpOrigin = false,
  representation = "period-keys",
  construction = CHAIN_KEY_CONSTRUCTION,
  maxChainMembersPerMessage,
  notDeliveredReport,
}) {
  if (clock !== undefined && typeof clock?.now !== "function") {
    throw dcaError("bad_config", "a chain issuer clock is an object with a now()");
  }
  const profile = chainKeyConstructionProfile(construction);
  const engine = new IssuerEngine({
    supportedVersions,
    operatingIssuerNames,
    accessPolicy,
    developmentHttpOrigin,
    ...(notDeliveredReport === undefined ? {} : { notDeliveredReport }),
    periodCapabilitySource: requireChainRepresentation(
      chainKeyCapabilitySource({
        representation,
        construction: profile.name,
        maxChainMembersPerMessage,
      }),
    ),
  });

  return {
    /**
     * @param {import('../../../core-shared--client-issuer/DcaRequest.js').DcaRequest} request
     * @returns {void}
     */
    checkVersion(request) {
      engine.checkVersion(request);
    },
    /** @param {import('../../../core-shared--client-issuer/DcaRequest.js').DcaRequest} request */
    checkOperatingIssuerName(request) {
      engine.checkOperatingIssuerName(request);
    },
    // This composition installs the selection route, so it declares that route
    // under either representation. The encoder map below states more narrowly
    // what this issuer sends back.
    selectedExtensions: Object.freeze(["chain-keys"]),
    capabilityEncoders:
      representation === "chain-keys"
        ? { "chain-keys": chainKeyCapabilityEncoderFor(profile.name) }
        : {},
    /**
     * @param {import('../../../core-shared--client-issuer/DcaRequest.js').DcaRequest} request
     * @param {import('../../../core-issuer/IssuerEngine.js').PublisherRegistration} registration
     * @param {import('../../../core-issuer/IssuerEngine.js').IssuerHostPolicyInput} [policyInput]
     * @param {any} [invocation]
     */
    async unlock(request, registration, policyInput = {}, invocation) {
      const context = sourceInvocation(invocation, clock);
      return engine.unlock(request, registration, policyInput, {
        ...context,
        ...(invocation?.verification === undefined
          ? {}
          : { verification: invocation.verification }),
      });
    },
  };
}
