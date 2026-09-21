// @ts-check
//
// Resolve the period-chain extension's untrusted request carrier before an
// issuer opens any envelope. Geometry is explicit and whole-pair: an own
// access-group override replaces the document pair, including when malformed.
// Labels never supply missing geometry. This module reads the carrier with the
// reader both sides share, names the request's own vocabulary, and holds the
// one admission that belongs to the request alone.
//
// No width is read here. A carrier member stays a sealed value until the
// route's opener opens it, and the route's construction profile states the
// width that opening expects, so screening a length at admission would read a
// profile off untrusted bytes.

import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import {
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
} from "../../../core-shared/geometryBounds.js";
import { validatePeriodChainAccessGroup } from "../core-shared/periodChainConstruction.js";
import { periodChainRequestView } from "../core-shared--client-issuer/PeriodChainRequest.js";
import {
  PERIOD_CHAIN_COLLECTION,
  periodChainCarrierReader,
} from "../core-shared--client-issuer/periodChainCarrierReader.js";

export { MAX_CHAIN_MEMBERS_PER_FAMILY, MAX_CHAIN_MEMBERS_PER_MESSAGE };

/**
 * The carrier reader's own container test, repeated here so this admission
 * tests the collection the way the reader tests it.
 *
 * @param {unknown} value
 */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Admit the request's chain collection as a map before anything reads inside
 * it. A selecting issuer refuses the whole request here, the way base refuses a
 * request whose base coordinate cannot be spelled. The refusal comes before
 * policy, opening-key lookup and envelope opening, and it names no coordinate.
 * The narrower scopes, geometry, labels, bounds and leaves, stay inside the
 * reader and answer for one family. An issuer that never installed this source
 * never reaches this function and ignores both members.
 *
 * `validatePeriodChainAccessGroup` refuses a name with `bad_name`, which the
 * unlock endpoint's status map does not carry. The whole-request refusal is
 * spelled `binding_failed`, which the code base already uses for a structural
 * refusal of a request it can make no coordinate out of.
 *
 * @param {unknown} sealed - the request's `sealed` container as it arrived
 */
function admitRequestChainCollection(sealed) {
  if (!record(sealed) || !Object.hasOwn(/** @type {object} */ (sealed), PERIOD_CHAIN_COLLECTION))
    return;
  const collection = own(sealed, PERIOD_CHAIN_COLLECTION);
  if (!record(collection)) {
    throw dcaError("binding_failed", "a request sealed.periodChainKeys is a non-array object");
  }
  for (const accessGroup of Object.keys(/** @type {object} */ (collection))) {
    try {
      validatePeriodChainAccessGroup(accessGroup);
    } catch {
      throw dcaError(
        "binding_failed",
        "a request sealed.periodChainKeys name follows the base name grammar",
      );
    }
  }
}

/**
 * Resolve every own chain family once. Invalid input stays distinguishable
 * from absent input, but carries no parser detail into the issuer response.
 *
 * @param {import('../../../core-shared--client-issuer/DcaRequest.js').DcaRequest} request
 * @returns {{ presented: readonly string[], family: (accessGroup: string) => any }}
 */
export function periodChainRequestInput(request) {
  const view = periodChainRequestView(request);
  admitRequestChainCollection(view.sealed);
  return periodChainCarrierReader({
    container: view.sealed,
    context: view.periodChain,
    valueName: "sealed",
  });
}
