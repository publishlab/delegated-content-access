// @ts-check
//
// Resolve the chain-key extension's untrusted request carrier before an
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
import { validateChainKeyAccessGroup } from "../core-shared/chainKeyConstruction.js";
import { chainKeyRequestView } from "../core-shared--client-issuer/ChainKeyRequest.js";
import { normalizeRequestedPeriodKeys } from "../core-shared--client-issuer/requestedPeriodKeys.js";
import {
  CHAIN_KEYS_MEMBER,
  chainKeyCarrierReader,
} from "../core-shared--client-issuer/chainKeyCarrierReader.js";

export { MAX_CHAIN_MEMBERS_PER_FAMILY, MAX_CHAIN_MEMBERS_PER_MESSAGE };

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Admit the request's chain collection as a record array before anything
 * reads inside it. A selecting issuer refuses the whole request here, the way
 * base refuses a request whose base coordinate cannot be spelled: a collection
 * that is not an array, or a record whose `accessGroup` is missing or outside
 * the name grammar. An element that is not a record names no family and is
 * skipped; its siblings keep their scope. The refusal comes before policy,
 * opening-key lookup and envelope opening, and it names no coordinate. The
 * narrower scopes, geometry, labels and bounds, stay inside the reader and
 * answer for one family; a malformed sealed entry answers for its own member
 * coordinate, once that coordinate is authorized. An issuer that never
 * installed this source never reaches this function and ignores both members.
 *
 * `validateChainKeyAccessGroup` refuses a name with `bad_name`, which the
 * unlock endpoint's status map does not carry. The whole-request refusal is
 * spelled `binding_failed`, which the code base already uses for a structural
 * refusal of a request it can make no coordinate out of.
 *
 * @param {unknown} sealed - the request's `sealed` container as it arrived
 */
function admitRequestChainCollection(sealed) {
  if (!record(sealed) || !Object.hasOwn(sealed, CHAIN_KEYS_MEMBER)) return;
  const collection = own(sealed, CHAIN_KEYS_MEMBER);
  if (!Array.isArray(collection)) {
    throw dcaError("binding_failed", "a request sealed.chainKeys is an array of records");
  }
  for (const element of collection) {
    if (!record(element)) continue;
    try {
      validateChainKeyAccessGroup(/** @type {any} */ (own(element, "accessGroup")));
    } catch {
      throw dcaError(
        "binding_failed",
        "a request sealed.chainKeys record names an access group in the base name grammar",
      );
    }
  }
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function geometryRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Removed per-family overrides are a whole-request failure before policy or
 * key acquisition; a selected family cannot hide an unknown legacy override.
 * @param {unknown} context
 */
function rejectLegacyGeometryOverrides(context) {
  if (!geometryRecord(context)) return;
  if (Object.hasOwn(context, "accessGroups"))
    throw dcaError("binding_failed", "periodGeometry has no accessGroups overrides");
}

/**
 * Resolve every own chain family once. Invalid input stays distinguishable
 * from absent input, but carries no parser detail into the issuer response.
 *
 * @param {import('../../../core-shared--client-issuer/DcaRequest.js').DcaRequest} request
 * @param {{ maxChainMembersPerMessage?: number }} [config] - trusted capacity, default 16
 * @returns {{ presented: readonly string[], family: (accessGroup: string) => any }}
 */
export function chainKeyRequestInput(request, { maxChainMembersPerMessage } = {}) {
  const view = chainKeyRequestView(request);
  const sealed = view.sealed;
  const periodGeometry = view.periodGeometry;
  admitRequestChainCollection(sealed);
  rejectLegacyGeometryOverrides(periodGeometry);
  const carrier = chainKeyCarrierReader({
    container: sealed,
    context: periodGeometry,
    valueName: "sealed",
    maxChainMembersPerMessage,
  });
  const requestedPeriodKeys = normalizeRequestedPeriodKeys(
    view.requestedPeriodKeys,
    carrier.family,
  );
  return Object.freeze({ ...carrier, requestedPeriodKeys });
}
