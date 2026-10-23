// @ts-check
//
// This module reads the markup delivery form back off the DOM. It collects
// every element carrying a reserved class token in the parsed body, holds them to the format's
// carrier rules, parses the one `.dca-data` block and the optional
// `.dca-sealed-content` beside it, then returns each blob by its record's
// `contentName` in the sealed-content block. It mirrors
// `demo/support/ObjectDeliveryReader.js`, which reads the same render out of the
// object form and answers `extract` the same way off the same records.
//
// The caller passes the root in as an argument. Nothing here reads `document`,
// so the same module runs in a browser over the real document and under
// `node --test` over any object that answers `querySelectorAll`. The markup path
// can therefore be asserted in a runtime with no DOM.
//
// The parsed body holds one delivery. A Document root scopes its query to its
// parsed body; a caller may also hand over a body or deliberately scoped
// fragment root. Reserved elements in the head have no delivery meaning. The
// format puts exactly one `dca-data` carrier and at most one sealed-content
// carrier in that scope, so the
// reader refuses the page when it finds a second carrier instead of skipping
// it. Every reserved carrier is an inert `script` whose type is exactly
// `application/json`, and no element serves as both carriers.
//
// The reader returns exactly what the client takes. Every unlock and
// decrypt call is built from `dcaData` and `extract(contentName)`, so a caller
// drives the identical client over either delivery form. Nothing in this
// module decrypts or holds a key.
//
// The constructor collects the carriers once, parses them once, and snapshots
// both results. What a client builds a request from and what it decrypts both
// come from that one reading, and edits to the page after the read change
// neither answer.
//
// The reader accepts a missing sealed block. Every item's ciphertext may be
// deferred; its location and retrieval are outside this reader's contract.
// `extract` then returns the same miss for each item as for an unknown name. The reader
// refuses a present block that holds anything other than a JSON array, because
// the publisher announced a carrier and shipped something else. The carrier's
// records are named by contentName, so the reader admits it whole under the
// format's identifier section: one record name outside the grammar makes the
// reader refuse the whole page instead of only that blob.

import { dcaError } from "../core-shared/errors.js";
import { isContentName } from "../core-shared/names.js";
import { normalizePublisherOrigin } from "../core-shared/publisherOrigin.js";
import { own } from "../core-shared/wire.js";
import { DATA_SELECTOR, SEALED_SELECTOR } from "../core-shared/markupPlacement.js";
import { recordsByName } from "../core-shared--client-publisher/deliveryRecords.js";

/** The one type a reserved carrier carries, per the format's markup delivery. */
const JSON_TYPE = "application/json";

export class MarkupDeliveryReader {
  /** @type {any} */
  #dcaData;

  /**
   * The parsed sealed-content records by contentName, or null when the page
   * ships no block.
   *
   * @type {Map<string, any>|null}
   */
  #sealedContent;

  /** @type {string} */
  #publisherOrigin;

  /**
   * @param {{
   *   querySelectorAll: (selector: string) => any,
   *   nodeType?: number,
   *   body?: { querySelectorAll: (selector: string) => any }|null,
   *   location?: { origin?: string },
   *   ownerDocument?: { location?: { origin?: string } },
   * }} root - the one document the carriers are delivered in. Queried once,
   *   here: a client reads the page as it was when the read began.
   */
  constructor(root) {
    const queries =
      root !== null &&
      typeof root === "object" &&
      typeof (/** @type {any} */ (root).querySelectorAll) === "function";
    if (!queries) {
      throw dcaError(
        "bad_config",
        "a MarkupDeliveryReader reads a root that answers querySelectorAll",
      );
    }

    const publisherOrigin = normalizePublisherOrigin(
      root.location?.origin ?? root.ownerDocument?.location?.origin,
    );
    if (publisherOrigin === null) {
      throw dcaError("bad_page", "the page root carries no canonical publisher origin");
    }
    this.#publisherOrigin = publisherOrigin;

    const scope = root.nodeType === 9 ? root.body : root;
    if (!scope || typeof scope.querySelectorAll !== "function") {
      throw dcaError("bad_page", "the parsed document has no queryable body");
    }
    const dataCarriers = carriers(scope, DATA_SELECTOR);
    const sealedCarriers = carriers(scope, SEALED_SELECTOR);
    if (dataCarriers.length === 0) {
      throw dcaError("bad_page", `the page carries no ${DATA_SELECTOR} block`);
    }
    if (dataCarriers.length > 1) {
      throw dcaError("bad_page", `a page carries exactly one ${DATA_SELECTOR} block`);
    }
    if (sealedCarriers.length > 1) {
      throw dcaError("bad_page", `a page carries at most one ${SEALED_SELECTOR} block`);
    }
    if (sealedCarriers.includes(dataCarriers[0])) {
      throw dcaError(
        "bad_page",
        "one element carries both reserved class tokens, and serves as neither",
      );
    }
    requireInertJsonScript(dataCarriers[0], DATA_SELECTOR);
    for (const element of sealedCarriers) requireInertJsonScript(element, SEALED_SELECTOR);

    const parsed = parseBlock(dataCarriers[0], DATA_SELECTOR);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw dcaError("bad_page", "page is not an object");
    }
    this.#dcaData = parsed;

    if (sealedCarriers.length === 0) {
      this.#sealedContent = null;
      return;
    }
    const carrier = parseBlock(sealedCarriers[0], SEALED_SELECTOR);
    if (!Array.isArray(carrier)) {
      throw dcaError("bad_page", `the ${SEALED_SELECTOR} block is not an array`);
    }
    this.#sealedContent = admittedCarrier(carrier, SEALED_SELECTOR);
  }

  /**
   * The parsed dca-data, as `ObjectDeliveryReader` hands it back from the JSON
   * form. Parsing here does not authenticate it. The markup's dca-data carries
   * no `sealedContent` member to strip.
   *
   * @returns {any}
   */
  get dcaData() {
    return this.#dcaData;
  }

  /** The page origin supplied by the browser delivery boundary. */
  get publisherOrigin() {
    return this.#publisherOrigin;
  }

  /**
   * The sealed ciphertext for one item, or null when this page does not carry
   * it. The lookup is by the record's own `contentName`, so a name that every
   * object answers to finds nothing here. When several records name the item,
   * the last whole record answers.
   *
   * A `content` that is absent or not a string supplies no ciphertext. The
   * decrypt decides what is usable as ciphertext bytes, and that check stays
   * there.
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

/**
 * Returns every element in the root that matches one reserved selector. If the
 * root answers the class query with something that cannot be iterated, no page
 * can be read off that root, and this function raises the same `bad_config` as
 * the constructor's own root check. The argument is at fault, and the caller
 * hears that instead of a TypeError from the collection.
 *
 * @param {{ querySelectorAll: (selector: string) => any }} root
 * @param {string} selector - which carrier, for the message
 * @returns {any[]}
 */
function carriers(root, selector) {
  const answer = root.querySelectorAll(selector);
  if (
    answer === null ||
    typeof answer !== "object" ||
    typeof answer[Symbol.iterator] !== "function"
  ) {
    throw dcaError(
      "bad_config",
      `a MarkupDeliveryReader reads a root whose querySelectorAll answers the ${selector} elements`,
    );
  }
  return [...answer];
}

/**
 * The sealed-content carrier is a collection of records named by contentName,
 * and the format rejects such a collection when one record's name is missing
 * or outside that grammar rather than passing over the record. One bad name
 * therefore costs every blob on the page: the publisher composed a carrier the
 * format does not admit, and a reader that served the siblings would be
 * serving half a page the publisher did not describe. An element that is not
 * a record names nothing and supplies nothing.
 *
 * @param {unknown[]} carrier - already known to be an array
 * @param {string} selector - which carrier, for the message
 * @returns {Map<string, any>} the last whole record per contentName
 */
function admittedCarrier(carrier, selector) {
  const records = recordsByName(carrier, "contentName", isContentName);
  if (records === null) {
    throw dcaError("bad_page", `the ${selector} block carries a name outside the grammar`);
  }
  return records;
}

/**
 * A reserved carrier is an inert `script` element whose type is exactly
 * `application/json`. An element that carries the class token but serves
 * anything else shows the publisher did not compose this page, and it is
 * refused instead of read. Anything a browser would execute or display does not
 * count as a carrier.
 *
 * @param {{ tagName?: any, getAttribute?: any }} element
 * @param {string} selector - which carrier, for the message
 */
function requireInertJsonScript(element, selector) {
  const tagName = element?.tagName;
  if (typeof tagName !== "string" || tagName.toLowerCase() !== "script") {
    throw dcaError("bad_page", `the ${selector} carrier is a script element, and this one is not`);
  }
  const type =
    typeof element.getAttribute === "function" ? element.getAttribute("type") : undefined;
  if (type !== JSON_TYPE) {
    throw dcaError(
      "bad_page",
      `the ${selector} carrier carries type ${JSON_TYPE}, and this one does not`,
    );
  }
}

/**
 * One inert JSON script block, read and parsed once. Invalid or truncated JSON
 * is refused rather than repaired; the delivery boundary is responsible for
 * producing safe script-block text.
 *
 * @param {{ textContent?: any }} block
 * @param {string} selector - which block, for the message
 * @returns {any}
 */
function parseBlock(block, selector) {
  try {
    return JSON.parse(block.textContent);
  } catch {
    throw dcaError("bad_page", `the ${selector} block is not JSON`);
  }
}
