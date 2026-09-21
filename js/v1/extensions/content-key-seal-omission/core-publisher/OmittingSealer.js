// @ts-check
//
// The publisher side with content-key seal omission selected. It renders what
// `core-publisher/Sealer.js` renders, except that an issuer listing this
// extension gets no direct `sealed.contentKeys` map at all, carries the marker
// that says so, and the render's `contentData` wraps are bound.
//
// It holds a base `Sealer` and composes it with the two roles base takes: the
// render's content-key wrap strategy and the per-issuer supply plan, both from
// `omissionSealing.js`. Nothing of the publisher engine is repeated here:
// coordinate enumeration, validation order, randomness, fresh content keys,
// content encryption, sealing, signing and assembly are base's, and a render no
// issuer activated comes out byte for byte as base's.
//
// The class stays because the deployment configuration is per issuer: an
// `issuers` entry carries this extension's `extensions`, `grantable` and
// `accessGroups` beside the base members, and those are read off here before
// the base Sealer ever sees the entry.

import { Sealer } from "../../../core-publisher/Sealer.js";
import { omissionSealing } from "./omissionSealing.js";

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
    this.#sealer = new Sealer(/** @type {any} */ ({ ...config, ...omissionSealing(config) }));
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
   * @param {string} name
   * @param {string} value
   * @param {string} contentType
   * @param {{ accessGroups?: string[] }} [options]
   * @returns {this}
   */
  content(name, value, contentType, options = {}) {
    this.#sealer.content(name, value, contentType, options);
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
