// @ts-check
//
// This file fabricates a queryable page root straight from one render's values, with no
// markup writer and no DOM. It answers `querySelector` and `querySelectorAll`
// with one carrier each, the way
// `adapter-client/MarkupDeliveryReader.js` reads a delivered page: the `.dca-data`
// block carries the dca-data as JSON, and the `.dca-sealed-content` block
// carries one JSON object keyed by contentName.
//
// Scenarios use this fixture. A cross-role scenario holds a `Page` value
// and hands its render to `Browser.load` as an already-parsed root, without
// running `writeMarkupDelivery`; the writer-to-reader path stays confined to
// the placement-contract tests. `domOver` in `test-lib/helpers` starts from
// emitted markup instead, on the string side.

import { DATA_SELECTOR, SEALED_SELECTOR } from "../../core-shared/markupPlacement.js";

/**
 * @param {{ publisherOrigin: string, dcaData: object, sealedContent?: Record<string, string> }} values -
 *   one render split as the writer takes it: dca-data, and the sealed content
 *   beside it under its own member.
 * @returns {{ querySelector: (selector: string) => any,
 *   querySelectorAll: (selector: string) => any[] }}
 */
function queryableRoot({ publisherOrigin, dcaData, sealedContent }) {
  const dataText = JSON.stringify(dcaData);
  const sealedText = JSON.stringify(sealedContent ?? {});
  const carrier = (/** @type {string} */ textContent) => ({
    tagName: "script",
    textContent,
    getAttribute: (/** @type {string} */ name) => (name === "type" ? "application/json" : null),
  });

  return {
    location: { origin: publisherOrigin },
    querySelector: (/** @type {string} */ selector) => {
      if (selector === DATA_SELECTOR) return carrier(dataText);
      if (selector === SEALED_SELECTOR) return carrier(sealedText);
      return null;
    },
    querySelectorAll: (/** @type {string} */ selector) => {
      if (selector === DATA_SELECTOR) return [carrier(dataText)];
      if (selector === SEALED_SELECTOR) return [carrier(sealedText)];
      return [];
    },
  };
}

/**
 * Builds the same root from a `Page`, splitting its `asJson()` render: the sealed
 * ciphertext sits under its own member beside the dca-data.
 *
 * @param {{ asJson: () => any, publisherOrigin: string }} page
 * @returns {{ location: { origin: string }, querySelector: (selector: string) => any,
 *   querySelectorAll: (selector: string) => any[] }}
 */
export function rootFromPage(page) {
  const { sealedContent, ...dcaData } = page.asJson();
  return queryableRoot({ publisherOrigin: page.publisherOrigin, dcaData, sealedContent });
}
