// @ts-check
//
// One unlock request carrying this extension's two added members: the support
// signal and the forwarded bound candidates.
//
// It adds them to a request base already built, rather than rebuilding the
// document. `DcaRequest.fromParts` names a fixed parts list and drops anything
// beside it (`js/core-shared--client-issuer/DcaRequest.js`), so the two
// members cannot travel through it; they join the finished document instead,
// which is what `fromRequest` below does.
//
// Everything else is base's. This is a `DcaRequest`, so the base engine's
// `instanceof` gate, its accessors and `toObject()` all read it unchanged, and
// an issuer composed without this extension sees the two added members as the
// unknown members they are.

import { own } from "../../../core-shared/wire.js";
import { dcaError } from "../../../core-shared/errors.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";

export class OmissionRequest extends DcaRequest {
  /**
   * The same document base built, with `extensions` before the sealed
   * sections and `boundCandidates` after them. Base's omission rule holds for
   * both: a member the client cannot fill sends no member in its place.
   *
   * The document is rebuilt rather than written into, because `toObject()`
   * hands back the request's own object and a request base still holds must
   * not change under it.
   *
   * @param {DcaRequest} request - what `DcaRequestBuilder` built
   * @param {object} added
   * @param {string[]} [added.extensions] - what this client supports, offered
   *   rather than demanded
   * @param {Record<string, unknown>[]} [added.boundCandidates] - bound
   *   `contentData` wrap entries, each record carrying the contentName,
   *   accessGroup and period it was read at. Labels only; they select which
   *   blob the issuer tries.
   * @returns {OmissionRequest}
   */
  static fromRequest(request, { extensions = [], boundCandidates = [] } = {}) {
    if (!(request instanceof DcaRequest)) {
      throw dcaError("bad_config", "an omission request is added to a DcaRequest; build one first");
    }

    const { sealed, clientPublicKey, ...head } = request.toObject();

    /** @type {any} */
    const document = {
      ...head,
      ...(extensions.length > 0 ? { extensions: [...extensions] } : {}),
      sealed,
    };
    if (boundCandidates.length > 0) document.boundCandidates = boundCandidates;
    if (clientPublicKey !== undefined) document.clientPublicKey = clientPublicKey;

    return new OmissionRequest(document);
  }

  /**
   * What the client says it supports. It grants nothing and changes nothing
   * the issuer verifies or decides; an issuer that does not read it answers
   * as it always did.
   *
   * @returns {string[]}
   */
  get extensions() {
    const value = own(this.toObject(), "extensions");
    return Array.isArray(value) ? value.filter((name) => typeof name === "string") : [];
  }

  /**
   * The forwarded candidate records, or undefined when the request carries
   * none. Container-checked the way base checks its sealed collections: a
   * value that is not an array is not a collection of candidates.
   *
   * @returns {unknown[]|undefined}
   */
  get boundCandidates() {
    const value = own(this.toObject(), "boundCandidates");
    return Array.isArray(value) ? value : undefined;
  }
}
