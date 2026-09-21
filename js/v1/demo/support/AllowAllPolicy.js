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

import { ALL_PERIODS } from "./AccessPolicy.js";

export class AllowAllPolicy {
  /**
   * @param {any} claims - verified by the engine, intentionally irrelevant here
   * @param {{ contentNames: string[], accessGroups: string[] }} requested
   * @returns {{ contentNames: string[], periodGrants: { accessGroup: string, periodCount: number }[], policyData: object[] }}
   */
  decide(claims, requested) {
    void claims;
    return {
      contentNames: [...requested.contentNames],
      // Grant every presented family in full. `ALL_PERIODS` is the whole-group
      // prefix, and the engine clamps it to what the request carried.
      periodGrants: requested.accessGroups.map((accessGroup) => ({
        accessGroup,
        periodCount: ALL_PERIODS,
      })),
      policyData: [],
    };
  }
}
