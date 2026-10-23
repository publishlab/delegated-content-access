// @ts-check
//
// What the client asks one issuer for when the extension is composed. Base's
// selection, plus the support signal and the bound candidates the issuer needs
// to answer an item whose contentKey was never sealed to it.
//
// Base decides that selection: `core-client/DcaRequestBuilder.js` builds the
// request, and this class adds the two members to it. What the page carries for
// this issuer, how a needed item's groups are walked, and what an incomplete
// page sends are all decided there and not repeated here.
//
// The candidate carries the accessGroup and period it was read at. Those are labels
// and nothing else: they select which blob the issuer tries, and a wrong one
// fails authentication rather than moving the coordinate. The client submits no
// authoritative binding string.

import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import { OmissionRequest } from "../core-shared--client-issuer/OmissionRequest.js";
import { omissionBoundCandidates } from "../core-shared--client-publisher/omissionCandidates.js";

const OPTIONS = ["clientPublicKey", "relayPeriodKeys", "innerBuilder"];

/**
 * @typedef {{ build: Function, acceptsPeriodKeyResponseCoordinate?:
 *   (accessGroup: string, t: string, request: unknown) => boolean,
 *   keyFamilies?: (request: any) => import("../../../core-client/requestBuilderContracts.js").ExtensionKeyFamilies }} InnerRequestBuilder
 */

export class OmissionRequestBuilder {
  /** @type {InnerRequestBuilder} */
  #builder;

  /**
   * @param {object} [config]
   * @param {unknown} [config.clientPublicKey]
   * @param {boolean} [config.relayPeriodKeys]
   * @param {InnerRequestBuilder} [config.innerBuilder] - an already selected
   *   request composition to add omission members to
   */
  constructor(config = {}) {
    for (const name of Object.keys(config ?? {})) {
      if (!OPTIONS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `OmissionRequestBuilder has no ${name} yet, and will not pretend to`,
        );
      }
    }
    if (
      config?.innerBuilder !== undefined &&
      (config?.clientPublicKey !== undefined || config?.relayPeriodKeys !== undefined)
    ) {
      throw dcaError(
        "bad_config",
        "an omission request takes an innerBuilder or base request options, not both",
      );
    }
    /** @type {InnerRequestBuilder} */
    const builder =
      config?.innerBuilder ??
      new DcaRequestBuilder({
        ...(config?.clientPublicKey === undefined
          ? {}
          : { clientPublicKey: config.clientPublicKey }),
        ...(config?.relayPeriodKeys === undefined
          ? {}
          : { relayPeriodKeys: config.relayPeriodKeys }),
      });
    if (typeof builder?.build !== "function") {
      throw dcaError("bad_config", "an omission request innerBuilder needs build");
    }
    this.#builder = builder;
    if (typeof builder.acceptsPeriodKeyResponseCoordinate === "function") {
      /** The selected inner composition's coordinate admission, when it supplies one.
       * @type {InnerRequestBuilder["acceptsPeriodKeyResponseCoordinate"]}
       */
      this.acceptsPeriodKeyResponseCoordinate =
        builder.acceptsPeriodKeyResponseCoordinate.bind(builder);
    }
  }

  /**
   * Bound candidates ask for item keys, never derivation keys. Keep any
   * additional key kinds the selected inner builder reports.
   * @param {any} request
   * @returns {import("../../../core-client/requestBuilderContracts.js").ExtensionKeyFamilies}
   */
  keyFamilies(request) {
    const document = typeof request?.toObject === "function" ? request.toObject() : request;
    const inner = this.#builder.keyFamilies?.(request);
    return {
      contentKeys:
        inner?.contentKeys === true || omissionPresentedContentNames(document).length > 0,
      familyKeys: inner?.familyKeys === true,
    };
  }

  /**
   * @param {import('../../../core-client/DcaData.js').DcaData} page
   * @param {string} issuerName
   * @param {string[]} needed - contentNames the client could not resolve
   * @returns {OmissionRequest}
   */
  build(page, issuerName, needed) {
    const request = this.#builder.build(page, issuerName, needed);

    const boundCandidates = omissionBoundCandidates(needed, (name) =>
      page.accessGroupsFor(name).map((group) => [group, page.sealedEntriesFor(name, group)]),
    );

    return OmissionRequest.fromRequest(request, { extensions: [EXTENSION_NAME], boundCandidates });
  }
}

/**
 * The items an omission request presented through its bound candidates. The
 * resolver counts a returned key or error for one of them as solicited, as the
 * issuer counts the same candidates as presented.
 *
 * @param {unknown} request - the request document associated with one response
 * @returns {string[]}
 */
export function omissionPresentedContentNames(request) {
  const candidates = own(request, "boundCandidates");
  if (!Array.isArray(candidates)) return [];
  /** @type {Set<string>} */
  const names = new Set();
  for (const candidate of candidates) {
    const contentName = own(candidate, "contentName");
    if (typeof contentName === "string") names.add(contentName);
  }
  return [...names];
}
