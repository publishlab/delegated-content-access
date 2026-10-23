// @ts-check
//
// The request representation for a client that selected chain-key relay.
// It adds the extension's explicit geometry and selected sealed chain members
// to a request another composition already built. The client neither validates
// the publisher's geometry nor derives from the chain key while relaying it.

import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";

export class ChainKeyRequest extends DcaRequest {
  /**
   * @param {DcaRequest} request
   * @param {object} added
   * @param {unknown} [added.periodGeometry]
   * @param {Record<string, unknown>[]} [added.chainKeys] - `{accessGroup, cutoff, key}` records
   * @param {{ accessGroup: string, periods: string[] }[]} [added.requestedPeriodKeys]
   * @returns {ChainKeyRequest}
   */
  static fromRequest(request, { periodGeometry, chainKeys = [], requestedPeriodKeys } = {}) {
    if (!(request instanceof DcaRequest)) {
      throw dcaError("bad_config", "a chain-key request is added to a DcaRequest; build one first");
    }

    const { sealed, clientPublicKey, ...head } = request.toObject();
    if (Object.hasOwn(head, "periodGeometry") || Object.hasOwn(sealed ?? {}, "chainKeys")) {
      throw dcaError("bad_config", "a chain-key request refuses a second chain contribution");
    }
    /** @type {any} */
    const document = {
      ...head,
      ...(periodGeometry === undefined ? {} : { periodGeometry }),
      ...(requestedPeriodKeys === undefined ? {} : { requestedPeriodKeys }),
      sealed: {
        ...sealed,
        ...(chainKeys.length === 0 ? {} : { chainKeys }),
      },
    };
    if (clientPublicKey !== undefined) document.clientPublicKey = clientPublicKey;
    return new ChainKeyRequest(document);
  }

  /** The explicit geometry representation this relay carried, untrusted. */
  get periodGeometry() {
    return own(this.toObject(), "periodGeometry");
  }

  /** The unsigned article-coordinate hints carried by this selected mechanism. */
  get requestedPeriodKeys() {
    return own(this.toObject(), "requestedPeriodKeys");
  }
}

/**
 * Give issuer-side extension code a checked view over a parsed base request
 * without rebuilding or normalizing its document.
 *
 * @param {DcaRequest} request
 * @returns {ChainKeyRequest}
 */
export function chainKeyRequestView(request) {
  if (!(request instanceof DcaRequest)) {
    throw dcaError("bad_config", "a chain-key request view needs a DcaRequest");
  }
  return request instanceof ChainKeyRequest ? request : new ChainKeyRequest(request.toObject());
}
