// @ts-check
//
// A `Page` holds one render: the dca-data a publisher emitted and the sealed
// ciphertext beside it. Nothing in it changes after construction. The two
// stateful ends pass a `Page` between them, so everything that acts lives on a
// `Browser` or an `IssuerServer` and never in here.
//
// A JSON API ships the delivery form `asJson()` returns, and
// `ObjectDeliveryReader` reads that form directly. `asJson()` hands back a JSON
// round trip rather than the objects the render was built from: a client
// receives what survived `JSON.stringify`, and a page that handed over live
// `Uint8Array`s would let a test pass on bytes no browser would ever have seen.
//
// A `Page` emits no markup and keeps no markup emitter; it is an immutable
// value. `adapter-publisher/writeMarkupDelivery` writes the two inert elements
// of spec--data-format.md Section 3, markup delivery, when a scenario delivers
// the markup form. The current cross-role scenarios hand `Browser` an
// already-parsed root instead. Both delivery forms carry the same dca-data and
// differ only in where the ciphertext sits, so `asJson()` and the writer's
// markup describe one render either side of that one member.

import { dcaError } from "../../core-shared/errors.js";
import { normalizePublisherOrigin } from "../../core-shared/publisherOrigin.js";
import { assertWireSafe } from "./wireSafe.js";

export class Page {
  /** @type {string} */
  #wire;

  /** @type {string} */
  #publisherOrigin;

  /**
   * @param {object} config
   * @param {string} config.publisherOrigin - delivery context, not wire data
   * @param {object} config.dcaData - what the publisher signed and shipped
   * @param {object} config.sealedContent - contentName to base64url ciphertext
   */
  constructor(config) {
    for (const name of Object.keys(config ?? {})) {
      if (name !== "publisherOrigin" && name !== "dcaData" && name !== "sealedContent") {
        throw dcaError("unsupported_option", `Page has no ${name} yet, and will not pretend to`);
      }
    }
    if (!config?.dcaData)
      throw dcaError("bad_config", "a Page is dca-data and the sealed content beside it");
    if (!config?.sealedContent)
      throw dcaError("bad_config", "a Page needs its sealedContent, even if it is empty");
    const publisherOrigin = normalizePublisherOrigin(config?.publisherOrigin);
    if (publisherOrigin === null) {
      throw dcaError(
        "bad_config",
        "a Page needs its canonical publisherOrigin as delivery context",
      );
    }
    this.#publisherOrigin = publisherOrigin;

    // The constructor serialises the render once. Anything in a render that
    // cannot cross a wire fails here rather than at a client that reads a
    // mangled field three layers on. It has to be a check of its own, because
    // JSON.stringify does not refuse: it turns a CryptoKey into {} and drops an
    // undefined member silently.
    const wire = { ...config.dcaData, sealedContent: config.sealedContent };
    assertWireSafe(wire);
    this.#wire = JSON.stringify(wire);
  }

  /**
   * The JSON delivery form. A fresh object each read, so a client cannot
   * reach back through the page into another client's copy.
   *
   * @returns {any}
   */
  asJson() {
    return JSON.parse(this.#wire);
  }

  /** The origin this render is delivered from; never serialized into dca-data. */
  get publisherOrigin() {
    return this.#publisherOrigin;
  }
}
