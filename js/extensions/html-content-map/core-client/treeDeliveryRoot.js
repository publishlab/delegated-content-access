// @ts-check
//
// A server-side client has a parse tree, not a DOM, and the base markup reader
// (`adapter-client/MarkupDeliveryReader.js`) reads any root that answers
// `querySelectorAll` for its two class selectors and names the page origin.
// This module answers that seam over the content-map tree port, so the
// server-side path runs the same base structural processing as a browser: the
// reader finds every `dca-data` and `dca-sealed-content` carrier, holds them to
// the format's element rules and parses them.
//
// The root answers only the selectors the Section 5.1 grammar covers, which
// includes the reader's `.dca-data` and `.dca-sealed-content`. Each element it
// returns answers the three members the reader reads: `tagName`,
// `getAttribute` and `textContent`. The root returns one stable view per
// element across queries, as a DOM does, because the reader refuses an element
// carrying both reserved tokens by comparing the results of its two queries by
// identity.
//
// The origin is the fetched final URL's origin. The gateway builds the root
// and runs structural processing before it verifies the `resourceJWT`; it
// holds that origin equal to the verified `origin` claim before any key work.

import { parseSelector, matchesSelector } from "../core-shared--client-publisher/selectors.js";
import { treeEntries } from "../core-shared--client-publisher/treePort.js";

/** The reader queries short class selectors; these limits only bound the parse. */
const ROOT_SELECTOR_LIMITS = { maxLength: 256, maxCompounds: 8 };

/**
 * The element members the base reader reads.
 *
 * @typedef {{ tagName: string, getAttribute: (name: string) => string|null, textContent: string }} ElementView
 */

/**
 * @param {import('../core-shared--client-publisher/treePort.js').TreePort} tree - the locked document
 * @param {string} origin - the delivery origin
 * @returns {{ querySelectorAll: (selector: string) => ElementView[], location: { origin: string } }}
 */
export function treeDeliveryRoot(tree, origin) {
  /** @type {WeakMap<object, ElementView>} */
  const views = new WeakMap();
  /** @param {any} element @returns {ElementView} */
  const viewOf = (element) => {
    let view = views.get(element);
    if (view === undefined) {
      view = {
        tagName: tree.localName(element).toUpperCase(),
        getAttribute: (/** @type {string} */ name) => tree.attribute(element, name),
        textContent: tree.text(element),
      };
      views.set(element, view);
    }
    return view;
  };
  return {
    location: { origin },
    querySelectorAll(selector) {
      const parsed = parseSelector(selector, ROOT_SELECTOR_LIMITS);
      const memo = new Map();
      return treeEntries(tree)
        .filter((entry) => matchesSelector(tree, entry, parsed, memo))
        .map(({ element }) => viewOf(element));
    },
  };
}
