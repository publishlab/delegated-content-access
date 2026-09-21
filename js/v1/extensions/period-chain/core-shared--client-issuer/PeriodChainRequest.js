// @ts-check
//
// The request representation for a client that selected period-chain relay.
// It adds the extension's explicit geometry and selected sealed chain members
// to a request another composition already built. The client neither validates
// the publisher's geometry nor derives from the chain state while relaying it.

import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";

export class PeriodChainRequest extends DcaRequest {
  /**
   * @param {DcaRequest} request
   * @param {object} added
   * @param {unknown} [added.periodChain]
   * @param {Record<string, Record<string, string>>} [added.periodChainKeys]
   * @returns {PeriodChainRequest}
   */
  static fromRequest(request, { periodChain, periodChainKeys = {} } = {}) {
    if (!(request instanceof DcaRequest)) {
      throw dcaError(
        "bad_config",
        "a period-chain request is added to a DcaRequest; build one first",
      );
    }

    const { sealed, clientPublicKey, ...head } = request.toObject();
    if (Object.hasOwn(head, "periodChain") || Object.hasOwn(sealed ?? {}, "periodChainKeys")) {
      throw dcaError("bad_config", "a period-chain request refuses a second chain contribution");
    }
    /** @type {any} */
    const document = {
      ...head,
      ...(periodChain === undefined ? {} : { periodChain }),
      sealed: {
        ...sealed,
        ...(Object.keys(periodChainKeys).length === 0 ? {} : { periodChainKeys }),
      },
    };
    if (clientPublicKey !== undefined) document.clientPublicKey = clientPublicKey;
    return new PeriodChainRequest(document);
  }

  /** The explicit geometry representation this relay carried, untrusted. */
  get periodChain() {
    return own(this.toObject(), "periodChain");
  }
}

/**
 * Give issuer-side extension code a checked view over a parsed base request
 * without rebuilding or normalizing its document.
 *
 * @param {DcaRequest} request
 * @returns {PeriodChainRequest}
 */
export function periodChainRequestView(request) {
  if (!(request instanceof DcaRequest)) {
    throw dcaError("bad_config", "a period-chain request view needs a DcaRequest");
  }
  return request instanceof PeriodChainRequest
    ? request
    : new PeriodChainRequest(request.toObject());
}
