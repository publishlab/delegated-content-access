// @ts-check

// Explicit grant-all wiring for scenarios and tests that exercise crypto or
// transport rather than entitlement. Production-facing constructors require a
// policy; importing this class makes the deliberate absence of access control
// visible at the call site.
//
// `demo/support/AccessPolicy.NaiveAccessPolicy` grants the same way, and it stays
// separate because it shows an issuer that treats the request as its own entitlement.
// This class only wires fixtures and takes no entitlement stance. Changes to how
// either reads presented coordinates must be checked against the other.

import { own } from "../../core-shared/wire.js";

/**
 * @param {{ periodCoordinates: Record<string, string[]> }} requested
 * @param {string} accessGroup
 * @returns {string[]}
 */
function requestedPeriodCoordinates(requested, accessGroup) {
  const coordinates = own(own(requested, "periodCoordinates"), accessGroup);
  return Array.isArray(coordinates) ? [...coordinates] : [];
}

export class AllowAllPolicy {
  /**
   * @param {any} claims - verified by the engine, intentionally irrelevant here
   * @param {{ contentNames: string[], accessGroups: string[], periodCoordinates: Record<string, string[]> }} requested
   * @returns {{ contentNames: string[], periodGrants: { accessGroup: string, periods: string[] }[], policyData: object[] }}
   */
  decide(claims, requested) {
    void claims;
    return {
      contentNames: [...requested.contentNames],
      // Grant each admitted label explicitly; the policy response names the
      // exact coordinates the engine is authorized to open.
      periodGrants: requested.accessGroups.map((accessGroup) => ({
        accessGroup,
        periods: requestedPeriodCoordinates(requested, accessGroup),
      })),
      policyData: [],
    };
  }
}
