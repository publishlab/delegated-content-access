// @ts-check
//
// Admission of the embedded contentMap member and its bounded rule grammar.
// Item types come only from the delivery contentData records.

import { dcaError } from "../../../core-shared/errors.js";
import { utf8Encode } from "../../../core-shared/codec.js";
import { isContentName } from "../../../core-shared/names.js";
import { DATA_CLASS, SEALED_CLASS } from "../../../core-shared/markupPlacement.js";
import { parseSelector } from "./selectors.js";
import { HTML_NAMESPACE, isAncestor, orderedTokenSet } from "./treePort.js";

/** The refused separate-carrier token. */
export const MAP_CLASS = "dca-content-map";

/** The one grammar version this client reads. */
const MAP_VERSION = "1";

/** The two item types of Section 4.3, spelled exactly. */
export const ITEM_TYPES = Object.freeze(["text/html", "text/plain"]);

/** The three operations of Section 6.3. */
const OPERATIONS = Object.freeze(["fill", "remove", "removeClass"]);

/**
 * The finite limits Section 5.4 requires. The profile leaves the values to the
 * implementation; these are the reference defaults, and a host may lower or
 * raise each one.
 *
 * @typedef {object} MapLimits
 * @property {number} mapOctets - UTF-8 octets of the serialized contentMap member
 * @property {number} rules - rules in one map
 * @property {number} selectorLength - characters in one target
 * @property {number} selectorCompounds - compounds in one target
 * @property {number} documentOctets - octets of the locked document
 */

/** @type {Readonly<MapLimits>} */
export const DEFAULT_MAP_LIMITS = Object.freeze({
  mapOctets: 64 * 1024,
  rules: 256,
  selectorLength: 256,
  selectorCompounds: 8,
  documentOctets: 4 * 1024 * 1024,
});

/**
 * The limits a host passed, over the defaults. Each supplied value is a
 * positive safe integer; an unknown name is refused, so a misspelled limit
 * does not silently fall back to its default.
 *
 * @param {Partial<MapLimits>} [limits]
 * @returns {Readonly<MapLimits>}
 */
export function mapLimits(limits = {}) {
  if (limits === null || typeof limits !== "object" || Array.isArray(limits)) {
    throw dcaError("bad_config", "map limits are an object");
  }
  for (const name of Object.keys(limits)) {
    if (!Object.hasOwn(DEFAULT_MAP_LIMITS, name)) {
      throw dcaError("unsupported_option", `there is no map limit named ${name}`);
    }
    const value = /** @type {Record<string, unknown>} */ (limits)[name];
    if (!Number.isSafeInteger(value) || /** @type {number} */ (value) < 1) {
      throw dcaError("bad_config", `the map limit ${name} is a positive integer`);
    }
  }
  return Object.freeze({ ...DEFAULT_MAP_LIMITS, ...limits });
}

/**
 * One admitted rule.
 *
 * @typedef {object} MapRule
 * @property {number} index - its position in the `rules` array
 * @property {string} item
 * @property {'fill'|'remove'|'removeClass'} op
 * @property {import('./selectors.js').Selector} target
 * @property {string|null} className - the token a `removeClass` rule removes
 */

/**
 * One admitted map.
 *
 * @typedef {object} ContentMap
 * @property {Record<string, 'text/html'|'text/plain'>} items - contentName to
 *   type, populated by admitMapItems from contentData
 * @property {MapRule[]} rules
 */

/** @param {string} why @returns {never} */
function malformed(why) {
  throw dcaError("map_malformed", `the content map ${why}`);
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Find the one dca-data carrier in `body` under Section 3. Every element in `body`
 * carrying the token counts, whatever its kind, so a publisher that put the
 * token on the wrong element hears `map_malformed` rather than `map_absent`.
 *
 * @param {import('./treePort.js').TreePort} tree
 * @param {import('./treePort.js').TreeEntry[]} entries
 * @returns {import('./treePort.js').TreeEntry}
 */
export function mapCarrier(tree, entries) {
  if (
    entries.some((entry) =>
      orderedTokenSet(tree.attribute(entry.element, "class")).includes(MAP_CLASS),
    )
  ) {
    malformed("uses the unsupported separate dca-content-map carrier");
  }
  const body = entries.find(
    (entry) =>
      entry.parent !== null &&
      entry.parent.parent === null &&
      tree.localName(entry.element) === "body" &&
      tree.namespace(entry.element) === HTML_NAMESPACE,
  );
  const carriers =
    body === undefined
      ? []
      : entries.filter(
          (entry) =>
            isAncestor(body, entry) &&
            orderedTokenSet(tree.attribute(entry.element, "class")).includes(DATA_CLASS),
        );
  if (carriers.length === 0) {
    throw dcaError("map_absent", `the delivery carries no ${DATA_CLASS} element in body`);
  }
  if (carriers.length > 1) malformed(`carrier appears ${carriers.length} times`);
  const [carrier] = carriers;
  const element = carrier.element;
  if (tree.localName(element) !== "script" || tree.namespace(element) !== HTML_NAMESPACE) {
    malformed("carrier is not a script element");
  }
  if (tree.attribute(element, "type") !== "application/json") {
    malformed('carrier does not carry type="application/json"');
  }
  const tokens = orderedTokenSet(tree.attribute(element, "class"));
  if (tokens.includes(SEALED_CLASS)) {
    malformed("carrier also carries a base carrier token");
  }
  return carrier;
}

/**
 * Parse and admit the embedded map text under Section 4.1, the Section 5.1 selector
 * grammar and the Section 5.4 limits on it. Item admission against the
 * delivery, Section 4.2's second paragraph, is `admitMapItems`.
 *
 * @param {string} text - the carrier's text
 * @param {Readonly<MapLimits>} limits
 * @returns {ContentMap}
 */
export function parseContentMap(text, limits) {
  if (utf8Encode(text).length > limits.mapOctets) {
    throw dcaError("map_limit", `the map is longer than ${limits.mapOctets} octets`);
  }
  let map;
  try {
    map = JSON.parse(text);
  } catch {
    malformed("is not valid JSON");
  }
  if (!isObject(map)) malformed("is not a JSON object");

  // A later grammar announces itself here, so the version answers before the
  // member checks that the later grammar would fail.
  const version = map.version;
  if (Object.hasOwn(map, "version") && typeof version === "string" && version !== MAP_VERSION) {
    throw dcaError("map_version_unsupported", `the content map version ${version} is not "1"`);
  }
  for (const name of Object.keys(map)) {
    if (!["version", "rules"].includes(name)) malformed(`has an unknown member ${name}`);
  }
  if (version !== MAP_VERSION) malformed('carries no version string "1"');

  const rules = map.rules;
  if (!Array.isArray(rules) || rules.length === 0) malformed("carries no non-empty rules array");
  if (rules.length > limits.rules) {
    throw dcaError("map_limit", `the map has more than ${limits.rules} rules`);
  }
  const selectorLimits = {
    maxLength: limits.selectorLength,
    maxCompounds: limits.selectorCompounds,
  };
  /** @type {MapRule[]} */
  const admitted = rules.map((rule, index) => {
    if (!isObject(rule)) malformed(`rule ${index} is not an object`);
    for (const name of Object.keys(rule)) {
      if (!["item", "op", "target", "class"].includes(name)) {
        malformed(`rule ${index} has an unknown member ${name}`);
      }
    }
    const { item, op, target } = rule;
    if (typeof item !== "string" || !isContentName(item)) {
      malformed(`rule ${index} names an item outside the contentName grammar`);
    }
    if (typeof op !== "string" || !OPERATIONS.includes(op)) {
      malformed(`rule ${index} has no fill, remove or removeClass op`);
    }
    /** @type {string|null} */
    let className = null;
    if (op === "removeClass") {
      const value = rule.class;
      if (typeof value !== "string" || !/^-?[A-Za-z_][A-Za-z0-9_-]*$/.test(value)) {
        malformed(`rule ${index} names no class ident to remove`);
      }
      className = value;
    } else if (Object.hasOwn(rule, "class")) {
      malformed(`rule ${index} carries a class for the ${op} operation`);
    }
    return {
      index,
      item,
      op: /** @type {'fill'|'remove'|'removeClass'} */ (op),
      target: parseSelector(target, selectorLimits),
      className,
    };
  });

  // An item only a gate reads would open, place nothing and still count
  // toward `complete` (Section 4.2).
  for (const name of new Set(admitted.map((rule) => rule.item))) {
    if (!admitted.some((rule) => rule.item === name && rule.op === "fill")) {
      malformed(`reads the item ${name} by no fill rule`);
    }
  }
  return { items: {}, rules: admitted };
}

/**
 * The delivery facts Section 4.2 checks each map item against.
 *
 * @typedef {object} MapDelivery
 * @property {(contentName: string) => boolean} declares - whether `contentData`
 *   declares the item
 * @property {(contentName: string) => unknown} contentType - authoritative item record type
 * @property {(contentName: string) => boolean} carriesCiphertext - whether
 *   `dca-sealed-content` supplies canonical ciphertext for it
 */

/**
 * Admit every map item against the delivery under Section 4.2: declared by
 * `contentData`, and carried as ciphertext. A map that points at an item the
 * render did not deliver is a defective render, not partial entitlement.
 *
 * @param {ContentMap} map
 * @param {MapDelivery} delivery
 * @returns {void}
 */
export function admitMapItems(map, delivery) {
  for (const name of new Set(map.rules.map((rule) => rule.item))) {
    if (!delivery.declares(name)) {
      throw dcaError("map_item_undeclared", `contentData declares no item ${name}`);
    }
    const type = delivery.contentType(name);
    if (typeof type !== "string") {
      throw dcaError("item_failed", `the item ${name} has no valid contentType`);
    }
    if (!ITEM_TYPES.includes(type)) {
      throw dcaError(
        "map_type_unsupported",
        `the item ${name} has unsupported contentType ${JSON.stringify(type)}`,
      );
    }
    map.items[name] = /** @type {'text/html'|'text/plain'} */ (type);
    if (!delivery.carriesCiphertext(name)) {
      throw dcaError("map_item_no_ciphertext", `the delivery carries no ciphertext for ${name}`);
    }
  }
}
