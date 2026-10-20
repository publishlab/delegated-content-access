// @ts-check
//
// The smallest thing that answers `querySelector` and `querySelectorAll` the way
// `adapter-client/MarkupDeliveryReader.js` asks, over a markup STRING: every
// element carrying a reserved class token, `dca-data` or `dca-sealed-content`.
// Each element is matched only up to the first matching close tag, which is the
// tokenizer's own rule and the reason the writer escapes that sequence.
//
// It scans rather than matches one block per class, because the reader inspects
// every element carrying either token: two carriers, an element that is no
// script, a type that is not `application/json` and an element carrying both
// tokens are all pages this fixture has to be able to state.
//
// The scan visits every open tag rather than whole elements outer-first, so a
// carrier inside wrapper elements is found where a browser's class query finds
// it: the format leaves order, depth and siblinghood free.
//
// Promoted out of `test/markup-placement.test.js` so the placement-contract
// tests and the string-to-parse-to-load end-to-end test share the one parser.
// The values-side sibling is `queryableRoot` in `demo/support`: `domOver` starts
// from emitted markup, `queryableRoot` from a render's values.

import {
  DATA_CLASS,
  DATA_SELECTOR,
  SEALED_CLASS,
  SEALED_SELECTOR,
} from "../../core-shared/markupPlacement.js";

/** One open tag with its attributes, wherever it sits. */
const OPEN_TAG = /<([a-zA-Z][a-zA-Z0-9-]*)((?:\s[^>]*)?)>/g;

/** The same element read whole from a known open-tag position, close tag included. */
const ELEMENT_AT = /<([a-zA-Z][a-zA-Z0-9-]*)((?:\s[^>]*)?)>([\s\S]*?)<\/\1\s*>/y;

/** @param {string} attributes @param {string} name */
function attribute(attributes, name) {
  const found = new RegExp(`\\s${name}="([^"]*)"`).exec(attributes);
  return found === null ? null : found[1];
}

/**
 * Every element in the markup carrying a reserved class token, in document
 * order, each answering what the reader reads off an element.
 *
 * @param {string} markup
 * @returns {{ tagName: string, textContent: string, getAttribute: (name: string) => string|null,
 *   classes: string[] }[]}
 */
function reservedElements(markup) {
  const found = [];
  let readTo = 0;
  for (const open of markup.matchAll(OPEN_TAG)) {
    const attributes = open[2];
    const classes = (attribute(attributes, "class") ?? "").split(/\s+/).filter(Boolean);
    if (!classes.includes(DATA_CLASS) && !classes.includes(SEALED_CLASS)) continue;
    // Text already inside a carrier is that carrier's JSON, so markup
    // spelled out in a string value is a value and not a second element.
    if (open.index < readTo) continue;
    ELEMENT_AT.lastIndex = open.index;
    const element = ELEMENT_AT.exec(markup);
    if (element === null) continue;
    readTo = ELEMENT_AT.lastIndex;
    found.push({
      tagName: element[1],
      textContent: element[3],
      classes,
      getAttribute: (/** @type {string} */ name) => attribute(attributes, name),
    });
  }
  return found;
}

/**
 * @param {string} markup
 * @param {{ publisherOrigin?: string }} [context]
 * @returns {{ location: { origin: string }, querySelector: (selector: string) => any,
 *   querySelectorAll: (selector: string) => any[] }}
 */
export function domOver(markup, context = {}) {
  const elements = reservedElements(markup);
  const carrying = (/** @type {string} */ selector) =>
    elements.filter((element) =>
      element.classes.includes(selector === DATA_SELECTOR ? DATA_CLASS : SEALED_CLASS),
    );

  return {
    location: { origin: context.publisherOrigin ?? "https://publisher.example" },
    querySelector: (/** @type {string} */ selector) => {
      if (selector !== DATA_SELECTOR && selector !== SEALED_SELECTOR) return null;
      return carrying(selector)[0] ?? null;
    },
    querySelectorAll: (/** @type {string} */ selector) => {
      if (selector !== DATA_SELECTOR && selector !== SEALED_SELECTOR) return [];
      return carrying(selector);
    },
  };
}
