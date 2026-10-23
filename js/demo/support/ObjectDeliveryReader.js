// @ts-check

// Reads one render's DCA material out of the object delivery form - what
// `Page.asJson()` hands over, or the string it was serialised to. Its counterpart
// `adapter-client/MarkupDeliveryReader.js` reads the same render out of markup;
// both answer `dcaData` and `extract(contentName)`, so a caller drives the
// identical client walk over either delivery form.
//
// A client reading an object has no page, so this is named for the read and the
// form it reads. It is not a JSON API adapter and does not stand in for one:
// what a content API ships, and what a public adapter for it would look like,
// is out of this round.
//
// It sits here because it adapts a delivery representation. It needs no DOM,
// which keeps it out of `browser/` and is no argument for core: the protocol
// core stays free of delivery forms.
//
// The constructor reads the delivery once, and both answers come off that one
// reading, so a client builds its request from the same reading it decrypts
// from. A caller handing over an object it goes on to mutate is describing a
// delivery that changed mid-read, and nothing here pretends otherwise.
//
// `sealedContent` is stripped from `dcaData` because the markup form does not
// carry it there: the blobs live in a template beside the data block, so a
// client reading either form sees the same `dcaData` members. It is read as an
// own member, so an inherited one is absent, and a present value that is not an
// array of ciphertext records means the delivery announced a carrier it did not
// supply. An enclosing array is turned away as a delivery, and a carrier with a
// record named outside the contentName grammar is rejected whole, like every
// identifier-carrying collection.

import { dcaError } from "../../core-shared/errors.js";
import { isContentName } from "../../core-shared/names.js";
import { normalizePublisherOrigin } from "../../core-shared/publisherOrigin.js";
import { own } from "../../core-shared/wire.js";
import { recordsByName } from "../../core-shared--client-publisher/deliveryRecords.js";

export class ObjectDeliveryReader {
  /** @type {any} */
  #dcaData;

  /** @type {Map<string, any>|null} */
  #sealedContent;

  /** @type {string} */
  #publisherOrigin;

  /**
   * @param {object|string} delivery - the object, or the string it arrived as
   * @param {{ publisherOrigin: string }} context - the object/edge delivery
   *   boundary supplies what a browser markup root would expose
   */
  constructor(delivery, context) {
    const publisherOrigin = normalizePublisherOrigin(context?.publisherOrigin);
    if (publisherOrigin === null) {
      throw dcaError("bad_config", "an ObjectDeliveryReader needs a canonical publisherOrigin");
    }
    const parsed = typeof delivery === "string" ? JSON.parse(delivery) : delivery;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw dcaError("bad_page", "page is not an object");
    }

    // `sealedContent` is read as an own member, like every other name off
    // the wire: an inherited value comes from whoever built the object, not
    // from this delivery. The spread below copies own
    // enumerable members, so the two halves of the split read alike.
    const sealedContent = own(parsed, "sealedContent");
    if (sealedContent !== undefined && !Array.isArray(sealedContent)) {
      throw dcaError("bad_page", "the sealedContent carrier is not an array");
    }
    // The carrier's records are named by contentName, and the format rejects
    // such a collection on one name outside the grammar instead of passing
    // over that record, so a carrier the publisher composed wrong costs every
    // blob on the delivery rather than the one it named badly.
    const records =
      sealedContent === undefined
        ? null
        : recordsByName(sealedContent, "contentName", isContentName);
    if (sealedContent !== undefined && records === null) {
      throw dcaError("bad_page", "the sealedContent carrier carries a name outside the grammar");
    }
    const dcaData = { .../** @type {any} */ (parsed) };
    delete dcaData.sealedContent;
    this.#dcaData = dcaData;
    this.#sealedContent = records;
    this.#publisherOrigin = publisherOrigin;
  }

  /**
   * What the publisher signed and shipped, without the sealed ciphertext
   * beside it.
   *
   * @returns {any}
   */
  get dcaData() {
    return this.#dcaData;
  }

  get publisherOrigin() {
    return this.#publisherOrigin;
  }

  /**
   * The sealed ciphertext for one item, or null when this page does not carry
   * it. A client fetches deferred content by URL, and an unknown name returns
   * null.
   *
   * @param {string} contentName
   * @returns {string|null} base64url ciphertext
   */
  extract(contentName) {
    if (!isContentName(contentName)) return null;

    const value = own(this.#sealedContent?.get(contentName), "content");
    return typeof value === "string" ? value : null;
  }
}
