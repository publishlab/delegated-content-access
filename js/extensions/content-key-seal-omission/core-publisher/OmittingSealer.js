// @ts-check
//
// The publisher side with content-key seal omission selected. It renders what
// `core-publisher/Sealer.js` renders, except that an issuer listing this
// extension gets no `sealed.contentKeys` map at all, carries the marker
// that says so, and the render's `contentData` wraps are bound.
//
// It holds a base `Sealer` built from `composePublisherConfig(config,
// omissionContribution(config))`: the composed path a host can also take
// through `createPublisher`. Nothing of the publisher engine is repeated here:
// coordinate enumeration, validation order, randomness, fresh content keys,
// content encryption, sealing, signing and assembly are base's, and a render no
// issuer activated comes out byte for byte as base's.
//
// The class is a convenience over that composition. An `issuers` entry
// carries this extension's `extensions`, `grantable` and `accessGroups` beside
// the base members; the contribution reads them, and the base Sealer receives
// the entry without them.

import { Sealer } from "../../../core-publisher/Sealer.js";
import { composePublisherConfig } from "../../../core-publisher/publisherComposition.js";
import { omissionContribution } from "./omissionSealing.js";

export class OmittingSealer {
  /** @type {Sealer} */
  #sealer;

  /**
   * The base constructor's config, with this extension's per-issuer members
   * allowed inside each `issuers` entry.
   *
   * @param {any} config
   */
  constructor(config) {
    this.#sealer = new Sealer(
      /** @type {any} */ (composePublisherConfig(config, omissionContribution(config)).config),
    );
  }

  /**
   * @param {string} resourceId
   * @param {object} data
   * @returns {this}
   */
  resource(resourceId, data) {
    this.#sealer.resource(resourceId, data);
    return this;
  }

  /**
   * Base's calling forms, forwarded as given: base tells a descriptor from a
   * legacy value by the arguments it receives, so a default filled in here
   * would turn a descriptor call into a refused one.
   *
   * @param {string} name
   * @param {string|Uint8Array|{ bytes: Uint8Array, contentType: string, contentEncodings: string[] }} value
   * @param {string|{ accessGroups?: string[] }} [contentTypeOrOptions]
   * @param {{ accessGroups?: string[] }} [legacyOptions]
   * @returns {this}
   */
  content(name, value, contentTypeOrOptions, legacyOptions) {
    this.#sealer.content(name, value, contentTypeOrOptions, legacyOptions);
    return this;
  }

  /**
   * One render, sealed by base under the composed roles.
   *
   * @returns {Promise<{ dcaData: any, sealedContent: Record<string, string> }>}
   */
  seal() {
    return this.#sealer.seal();
  }
}
