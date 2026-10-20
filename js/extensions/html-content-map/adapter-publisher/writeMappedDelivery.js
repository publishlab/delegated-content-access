// @ts-check
//
// Publisher admission for the embedded HTML content map. The author supplies
// every mapped item's decoded text so both HTML and plain-text fills can be
// checked for stability after whole-document serialization and reparsing.
// The returned delivery has two base carriers and contentMap inside dca-data.
// Client admission still checks the actual served document independently.

import { dcaError } from "../../../core-shared/errors.js";
import { writeMarkupDelivery } from "../../../adapter-publisher/writeMarkupDelivery.js";
import {
  admitMapItems,
  mapCarrier,
  mapLimits,
  parseContentMap,
} from "../core-shared--client-publisher/contentMap.js";
import { admitLockedDocument, resolveTargets } from "../core-shared--client-publisher/targets.js";
import { treeEntries } from "../core-shared--client-publisher/treePort.js";
import { deliveredFormDiffers, parseRenderedPage } from "./parse5Tree.js";

const MEMBERS = ["dcaData", "sealedContent", "contentMap", "page", "items", "limits"];

/**
 * @typedef {object} MappedDelivery
 * @property {object} dcaData - the render's dca-data, as `writeMarkupDelivery` takes it
 * @property {Record<string, string>} sealedContent - contentName to base64url ciphertext
 * @property {object} contentMap - the map object of Section 4.1
 * @property {(carriers: string) => string} page - the host's template: it puts
 *   the carriers in `body` unchanged and returns the whole page
 * @property {Record<string, string>} [items] - author-time decoded text for every
 *   mapped item, used to check delivered-form stability
 * @property {Partial<import('../core-shared--client-publisher/contentMap.js').MapLimits>} [limits]
 */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Write one mapped delivery and admit it before returning it. Every refusal
 * throws a `DcaError`: a map admission failure, `map_item_delivered_form`
 * for an unstable fill, or `bad_config`/`unsupported_option` for invalid input.
 *
 * @param {MappedDelivery} delivery
 * @returns {string} the rendered page
 */
export function writeMappedDelivery(delivery) {
  if (!isRecord(delivery)) throw dcaError("bad_config", "a mapped delivery is one record");
  for (const name of Object.keys(delivery)) {
    if (!MEMBERS.includes(name)) {
      throw dcaError("unsupported_option", `a mapped delivery takes no ${name} member`);
    }
  }
  const { dcaData, sealedContent, contentMap, page, items, limits } = delivery;
  if (typeof page !== "function") {
    throw dcaError("bad_config", "a mapped delivery needs a page template");
  }
  const admittedLimits = mapLimits(limits);

  const carriers = writeMarkupDelivery({ dcaData: { ...dcaData, contentMap }, sealedContent });
  const html = page(carriers);
  if (typeof html !== "string") throw dcaError("bad_config", "the page template returns a string");
  // Without this a template could rewrite a block, and the item checks below,
  // which read the render's own values, would vouch for a page they never saw.
  if (!html.includes(carriers)) {
    throw dcaError("bad_config", "the page template did not place the carriers unchanged");
  }

  const tree = parseRenderedPage(html);
  admitLockedDocument(tree, admittedLimits);
  const entries = treeEntries(tree);
  const carrier = mapCarrier(tree, entries);
  const map = parseContentMap(
    JSON.stringify(JSON.parse(tree.text(carrier.element)).contentMap),
    admittedLimits,
  );
  const contentData = /** @type {any} */ (dcaData).contentData;
  admitMapItems(map, {
    declares: (name) => isRecord(contentData) && Object.hasOwn(contentData, name),
    contentType: (name) => contentData[name]?.contentType,
    // The base writer already refused any ciphertext outside canonical base64url.
    carriesCiphertext: (name) => Object.hasOwn(sealedContent, name),
  });
  const resolved = resolveTargets(tree, entries, map);

  admitDeliveredForm(html, map, resolved, admittedItems(items, map));
  return html;
}

/**
 * The item text must name exactly the mapped items: a missing item
 * would leave its fills unchecked while the returned markup claims they
 * passed. Every admitted map has at least one fill.
 *
 * @param {unknown} items
 * @param {import('../core-shared--client-publisher/contentMap.js').ContentMap} map
 * @returns {Record<string, string>}
 */
function admittedItems(items, map) {
  const names = Object.keys(map.items);
  if (items === undefined) {
    if (names.length === 0) return {};
    throw dcaError(
      "bad_config",
      `the map declares mapped items ${names.join(", ")}, and the Section 7.1 check needs their author-time text in items`,
    );
  }
  if (!isRecord(items)) throw dcaError("bad_config", "the item text is one record");
  for (const name of Object.keys(items)) {
    if (!names.includes(name)) {
      throw dcaError("bad_config", `the item text names ${name}, which is no mapped item`);
    }
    if (typeof items[name] !== "string") {
      throw dcaError("bad_config", `the item text of ${name} is a string`);
    }
  }
  for (const name of names) {
    if (!Object.hasOwn(items, name)) {
      throw dcaError("bad_config", `the item text leaves out the mapped item ${name}`);
    }
  }
  return /** @type {Record<string, string>} */ (items);
}

/**
 * Section 7.1: each mapped item, placed in its targets, yields the same
 * tree live and in the delivered form. Each item runs alone on the locked
 * page, so a refusal names the item whose fragment broke the duty. Running the
 * items together would add nothing: fill targets are disjoint and never
 * nested, and each fragment serializes as a closed subtree, so one item's
 * delivered form cannot change another's unless it already differs alone.
 *
 * @param {string} html
 * @param {import('../core-shared--client-publisher/contentMap.js').ContentMap} map
 * @param {import('../core-shared--client-publisher/targets.js').ResolvedRule[]} resolved
 * @param {Record<string, string>} items
 * @returns {void}
 */
function admitDeliveredForm(html, map, resolved, items) {
  const fills = resolved.filter(({ rule }) => rule.op === "fill");
  const refuse = (/** @type {typeof fills[number]} */ { rule }) => {
    throw dcaError(
      "map_item_delivered_form",
      `the item ${rule.item} filled by rule ${rule.index} parses differently in the delivered page`,
    );
  };
  const check = (/** @type {typeof fills} */ group) => {
    const differing = deliveredFormDiffers(
      html,
      group.map(({ rule, target }) => ({
        path: target.path,
        html: items[rule.item],
        contentType: map.items[rule.item],
      })),
    );
    if (differing.length > 0) refuse(group[differing[0]]);
  };
  for (const name of Object.keys(items)) check(fills.filter(({ rule }) => rule.item === name));
}
