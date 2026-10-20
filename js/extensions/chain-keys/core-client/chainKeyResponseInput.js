// @ts-check

// Resolve returned chain members using only the immutable associated request's
// geometry. Neither response metadata nor the current delivery supplies context.

import { own } from "../../../core-shared/wire.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { chainKeyCarrierReader } from "../core-shared--client-issuer/chainKeyCarrierReader.js";

/**
 * @param {unknown} response
 * @param {unknown} request - the immutable request associated with this response
 * @param {{ maxChainMembersPerMessage?: number }} [config] - trusted capacity, default 16
 * @returns {{ presented: readonly string[], family: (accessGroup: string) => any }}
 */
export function chainKeyResponseInput(response, request, { maxChainMembersPerMessage } = {}) {
  return chainKeyCarrierReader({
    container: own(response, "keys"),
    context: own(request, "periodGeometry"),
    valueName: "value",
    maxChainMembersPerMessage,
    // Transport classification happens after geometry and request-associated
    // coordinate admission. A client-bound key entry is therefore structurally
    // present here when it has the common ciphertext member; the selected
    // method opener still decides whether its complete shape and bytes open.
    valueIsValid: (value) =>
      binaryStringBytes(value) !== null ||
      (value !== null && typeof value === "object" && typeof own(value, "key") === "string"),
  });
}
