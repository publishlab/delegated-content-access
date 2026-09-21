// @ts-check

// Resolve a direct period-chain response before any family is filed. Response
// geometry forms a separate context: it never inherits from the request or
// article. The carrier reader that both sides share does the reading; this
// module names the response's own vocabulary.

import { own } from "../../../core-shared/wire.js";
import { periodChainCarrierReader } from "../core-shared--client-issuer/periodChainCarrierReader.js";

/**
 * @param {unknown} response
 * @returns {{ presented: readonly string[], family: (accessGroup: string) => any }}
 */
export function periodChainResponseInput(response) {
  return periodChainCarrierReader({
    container: own(response, "keys"),
    context: own(response, "periodChain"),
    valueName: "value",
  });
}
