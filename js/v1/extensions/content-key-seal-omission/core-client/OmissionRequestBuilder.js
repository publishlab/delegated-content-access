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
// The candidate carries the accessGroup and t it was read at. Those are labels
// and nothing else: they select which blob the issuer tries, and a wrong one
// fails authentication rather than moving the coordinate. The client submits no
// authoritative binding string.

import { dcaError } from "../../../core-shared/errors.js";
import { setOwn, own } from "../../../core-shared/wire.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { EXTENSION_NAME, isBoundEntry } from "../core-shared/omissionBind.js";
import { OmissionRequest } from "../core-shared--client-issuer/OmissionRequest.js";

const OPTIONS = ["clientPublicKey", "relayExactPeriod", "innerBuilder"];

export class OmissionRequestBuilder {
  /** @type {{ build: Function }} */
  #builder;

  /**
   * @param {object} [config]
   * @param {unknown} [config.clientPublicKey]
   * @param {boolean} [config.relayExactPeriod]
   * @param {{ build: Function }} [config.innerBuilder] - an already selected
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
      (config?.clientPublicKey !== undefined || config?.relayExactPeriod !== undefined)
    ) {
      throw dcaError(
        "bad_config",
        "an omission request takes an innerBuilder or base request options, not both",
      );
    }
    const builder =
      config?.innerBuilder ??
      new DcaRequestBuilder({
        ...(config?.clientPublicKey === undefined
          ? {}
          : { clientPublicKey: config.clientPublicKey }),
        ...(config?.relayExactPeriod === undefined
          ? {}
          : { relayExactPeriod: config.relayExactPeriod }),
      });
    if (typeof builder?.build !== "function") {
      throw dcaError("bad_config", "an omission request innerBuilder needs build");
    }
    this.#builder = builder;
  }

  /**
   * @param {DcaData} page
   * @param {string} issuerName
   * @param {string[]} needed - contentNames the client could not resolve
   * @returns {OmissionRequest}
   */
  build(page, issuerName, needed) {
    const request = this.#builder.build(page, issuerName, needed);

    /** @type {Record<string, any[]>} */
    const boundCandidates = {};
    for (const contentName of needed) {
      /** @type {any[]} */
      const candidates = [];
      for (const accessGroup of page.accessGroupsFor(contentName)) {
        // Every bound entry of the group goes, for the same reason the
        // whole period family goes: the client cannot tell which period
        // this issuer will decide to open under.
        for (const entry of page.sealedEntriesFor(contentName, accessGroup)) {
          if (!isBoundEntry(entry)) continue;
          candidates.push({
            accessGroup,
            t: own(entry, "t"),
            nonce: own(entry, "nonce"),
            key: own(entry, "key"),
            bind: own(entry, "bind"),
          });
        }
      }
      if (candidates.length > 0) setOwn(boundCandidates, contentName, candidates);
    }

    return OmissionRequest.fromRequest(request, { extensions: [EXTENSION_NAME], boundCandidates });
  }
}
