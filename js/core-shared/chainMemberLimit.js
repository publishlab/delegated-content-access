// @ts-check
import { dcaError } from "./errors.js";
import { MAX_CHAIN_MEMBERS_PER_MESSAGE } from "./geometryBounds.js";

/** A trusted finite implementation capacity; values above 16 exceed the
 * current chain-key specification's message bound and require matching peers.
 * @param {unknown} [value]
 * @returns {number}
 */
export function chainMemberLimit(value = MAX_CHAIN_MEMBERS_PER_MESSAGE) {
  if (!Number.isSafeInteger(value) || /** @type {number} */ (value) < 1)
    throw dcaError("bad_config", "maxChainMembersPerMessage must be a positive safe integer");
  return /** @type {number} */ (value);
}
