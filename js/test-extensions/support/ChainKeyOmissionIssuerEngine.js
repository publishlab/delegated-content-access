// @ts-check
//
// One issuer answering both optional extensions at once, composed in neutral
// territory.
//
// There is no third engine here. Base runs the unlock it always ran and asks
// two questions of its own: one composed source produces a granted content key
// its content-key seal did not answer, and one composed source represents a granted
// period capability. The two extensions supply one answer each, neither
// references the other, and this file is the only place both are named.
//
// The two seams do not meet. A content-key source answers a contentName; a
// period-capability source answers an accessGroup. They share one surface:
// what each says the request presents, which base unions into the coordinate
// set the policy decides over, so composing them in either order presents the
// same coordinates and grants the same thing. Nothing here reconciles them.
//
// Beside those two lines this composition owns what neither extension nor
// base can decide alone: the issuer instant a chain grant starts at, and
// which representation of the period family goes back. It is composition
// support for the tests beside it, not a third implementation anything ships.

import { dcaError } from "../../core-shared/errors.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { requireChainRepresentation } from "../../extensions/chain-keys/core-issuer/chainKeyIssuerEngine.js";
import { chainKeyCapabilitySource } from "../../extensions/chain-keys/core-issuer/chainKeyCapabilitySource.js";
import { chainKeyCapabilityEncoder } from "../../extensions/chain-keys/core-issuer/chainKeyCapabilityEncoder.js";
import { omissionContentKeySource } from "../../extensions/content-key-seal-omission/core-issuer/omissionContentKeySource.js";

export class ChainKeyOmissionIssuerEngine {
  #clock;
  #engine;
  capabilityEncoders = Object.freeze({ "chain-keys": chainKeyCapabilityEncoder });
  selectedExtensions = Object.freeze(["chain-keys"]);

  /**
   * @param {object} config
   * @param {string[]} config.operatingIssuerNames
   * @param {{ decide: Function }} config.accessPolicy
   * @param {{ now: () => Date }} config.clock
   * @param {{ get: (registration: object) => (((accessGroup: string, t: string) => Promise<Uint8Array|readonly Uint8Array[]|null>)|undefined) }} [config.periodKeyLookup] -
   *   application state answering `get(registration)` with the period-key
   *   lookup held for that authenticated publisher registration
   */
  constructor({ accessPolicy, operatingIssuerNames, clock, periodKeyLookup }) {
    if (typeof accessPolicy?.decide !== "function") {
      throw dcaError(
        "bad_config",
        "an accessPolicy is an object with a decide(claims, requested, input)",
      );
    }
    this.#clock = clock;
    this.#engine = new IssuerEngine({
      operatingIssuerNames,
      accessPolicy,
      contentKeyScope: (registration) => periodKeyLookup?.get(registration),
      contentKeySource: omissionContentKeySource(),
      periodCapabilitySource: requireChainRepresentation(
        chainKeyCapabilitySource({ representation: "chain-keys" }),
      ),
    });
  }

  /**
   * @param {any} request
   * @param {any} registration
   * @param {{ principal?: object|null, context?: any }} [policyInput]
   * @param {import('../../core-issuer/IssuerEngine.js').IssuerInvocationContext|Date} [invocation] -
   *   canonical host context, or the retained direct-library Date form
   */
  async unlock(request, registration, policyInput = {}, invocation) {
    const instant = invocation === undefined ? this.#clock.now() : invocation;
    const context = instant instanceof Date ? { capturedAtMs: instant.getTime() } : instant;
    return this.#engine.unlock(request, registration, policyInput, context);
  }
}
