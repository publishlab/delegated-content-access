// @ts-check
//
// Target resolution and admission on the locked document, per
// docs/spec-proposal--html-content-map.md Sections 5.2 to 5.4. Every rule's selector
// resolves once, before any rule applies and before any unlock request, and
// must match exactly one element. The resolved set must then satisfy four
// structural rules, so the rules commute: tree changes are disjoint, class
// changes touch only surviving elements, carriers stay untouched, and each
// removed class token is present.
//
// The checks read the document through the tree port and hold the resolved
// elements as handles, so placement later changes exactly the elements that
// admission saw. The resolution result also names each target by its path of
// element-child indexes from the document element, the identity Section 7.2
// observes.

import { dcaError } from "../../../core-shared/errors.js";
import { DATA_CLASS, SEALED_CLASS } from "../../../core-shared/markupPlacement.js";
import { MAP_CLASS } from "./contentMap.js";
import { matchesSelector } from "./selectors.js";
import { HTML_NAMESPACE, isAncestor, orderedTokenSet } from "./treePort.js";

/**
 * The HTML void elements, which cannot hold a filled child
 * (https://html.spec.whatwg.org/multipage/syntax.html#void-elements).
 */
const VOID_ELEMENTS = [
  "area",
  "base",
  "br",
  "col",
  "embed",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "source",
  "track",
  "wbr",
];

/**
 * Elements a `fill` may not target beyond the void elements: `template`; the
 * raw text, escapable raw text and other elements whose content the parser
 * reads as text; and the table and select family, whose fragment parsing
 * contexts differ between current engines (Section 5.3).
 */
const UNFILLABLE_ELEMENTS = [
  "template",
  "script",
  "style",
  "textarea",
  "title",
  "xmp",
  "iframe",
  "noembed",
  "noframes",
  "plaintext",
  "noscript",
  "table",
  "thead",
  "tbody",
  "tfoot",
  "tr",
  "colgroup",
  "select",
  "option",
  "optgroup",
  "datalist",
];

/** Elements whose descendants are never a target. */
const EXCLUDING_ANCESTORS = ["select", "datalist", "noscript"];

/** Elements a `fill` or `remove` may not target. */
const DOCUMENT_STRUCTURE = ["html", "head", "body"];

/** The three carrier tokens a `fill` or `remove` may not touch. */
const CARRIER_CLASSES = [DATA_CLASS, SEALED_CLASS, MAP_CLASS];

/**
 * One rule with its resolved target.
 *
 * @typedef {object} ResolvedRule
 * @property {import('./contentMap.js').MapRule} rule
 * @property {import('./treePort.js').TreeEntry} target
 */

/**
 * @param {import('./treePort.js').TreePort} tree
 * @param {any} element
 * @param {string} name
 */
function isHtml(tree, element, name) {
  return tree.namespace(element) === HTML_NAMESPACE && tree.localName(element) === name;
}

/**
 * Refuse a locked document in quirks mode, where class and id selectors match
 * case-insensitively, and one over the document size limit (Sections 5.2 and
 * 5.4). Limited-quirks mode matches as no-quirks mode does.
 *
 * @param {import('./treePort.js').TreePort} tree
 * @param {Readonly<import('./contentMap.js').MapLimits>} limits
 * @returns {void}
 */
export function admitLockedDocument(tree, limits) {
  if (tree.sourceOctets() > limits.documentOctets) {
    throw dcaError(
      "map_limit",
      `the locked document is larger than ${limits.documentOctets} octets`,
    );
  }
  if (tree.mode() === "quirks") {
    throw dcaError("map_document_quirks", "the locked document is in quirks mode");
  }
}

/**
 * Resolve every rule's target on the locked document and admit the resolved
 * set under Section 5.3.
 *
 * @param {import('./treePort.js').TreePort} tree
 * @param {import('./treePort.js').TreeEntry[]} entries - the locked document's tree
 * @param {import('./contentMap.js').ContentMap} map
 * @returns {ResolvedRule[]}
 */
export function resolveTargets(tree, entries, map) {
  /** @type {ResolvedRule[]} */
  const resolved = map.rules.map((rule) => {
    const memo = new Map();
    const matches = entries.filter((entry) => matchesSelector(tree, entry, rule.target, memo));
    if (matches.length !== 1) {
      throw dcaError(
        "map_target_count",
        `rule ${rule.index} target ${JSON.stringify(rule.target.text)} matches ${matches.length} elements`,
      );
    }
    return { rule, target: matches[0] };
  });

  for (const { rule, target } of resolved) admitPlaceable(tree, rule, target);
  admitCarriersUntouched(tree, entries, resolved);
  admitOverlap(resolved);
  for (const { rule, target } of resolved) {
    if (rule.op !== "removeClass") continue;
    const tokens = orderedTokenSet(tree.attribute(target.element, "class"));
    if (!tokens.includes(/** @type {string} */ (rule.className))) {
      throw dcaError(
        "map_class_absent",
        `rule ${rule.index} removes class ${rule.className}, which its target does not carry`,
      );
    }
  }
  return resolved;
}

/**
 * The placeable rule of Section 5.3.
 *
 * @param {import('./treePort.js').TreePort} tree
 * @param {import('./contentMap.js').MapRule} rule
 * @param {import('./treePort.js').TreeEntry} target
 */
function admitPlaceable(tree, rule, target) {
  const refuse = (/** @type {string} */ why) => {
    throw dcaError("map_target_unplaceable", `rule ${rule.index} target ${why}`);
  };
  const element = target.element;
  if (tree.namespace(element) !== HTML_NAMESPACE) refuse("is not in the HTML namespace");
  for (let up = target.parent; up !== null; up = up.parent) {
    for (const name of EXCLUDING_ANCESTORS) {
      if (isHtml(tree, up.element, name)) refuse(`is inside a ${name} element`);
    }
  }
  const name = tree.localName(element);
  if (rule.op !== "removeClass" && DOCUMENT_STRUCTURE.includes(name)) {
    refuse(`is the ${name} element`);
  }
  if (rule.op === "fill" && (VOID_ELEMENTS.includes(name) || UNFILLABLE_ELEMENTS.includes(name))) {
    refuse(`is a ${name} element, which a fill cannot place into`);
  }
}

/**
 * The carrier rule of Section 5.3: no `fill` or `remove` target is or contains
 * an element carrying a base or map carrier token. A `removeClass` target may,
 * and `body` always does.
 *
 * @param {import('./treePort.js').TreePort} tree
 * @param {import('./treePort.js').TreeEntry[]} entries
 * @param {ResolvedRule[]} resolved
 */
function admitCarriersUntouched(tree, entries, resolved) {
  const carriers = entries.filter((entry) => {
    const tokens = orderedTokenSet(tree.attribute(entry.element, "class"));
    return CARRIER_CLASSES.some((token) => tokens.includes(token));
  });
  for (const { rule, target } of resolved) {
    if (rule.op === "removeClass") continue;
    if (carriers.some((carrier) => carrier === target || isAncestor(target, carrier))) {
      throw dcaError(
        "map_target_carrier",
        `rule ${rule.index} would ${rule.op} a DCA carrier or an element that contains one`,
      );
    }
  }
}

/**
 * The two overlap rules of Section 5.3: tree changes are disjoint, and class
 * changes land on elements that survive with their own identity.
 *
 * @param {ResolvedRule[]} resolved
 */
function admitOverlap(resolved) {
  const overlap = (/** @type {string} */ why) => {
    throw dcaError("map_target_overlap", why);
  };
  const treeChanges = resolved.filter(({ rule }) => rule.op !== "removeClass");
  for (let i = 0; i < treeChanges.length; i += 1) {
    for (let j = i + 1; j < treeChanges.length; j += 1) {
      const a = treeChanges[i];
      const b = treeChanges[j];
      if (a.target === b.target) {
        overlap(`rules ${a.rule.index} and ${b.rule.index} change the same element`);
      }
      if (isAncestor(a.target, b.target) || isAncestor(b.target, a.target)) {
        overlap(`rules ${a.rule.index} and ${b.rule.index} change nested elements`);
      }
    }
  }
  /** @type {Map<any, Set<string>>} */
  const classPairs = new Map();
  for (const { rule, target } of resolved) {
    if (rule.op !== "removeClass") continue;
    for (const change of treeChanges) {
      if (change.rule.op === "fill" && isAncestor(change.target, target)) {
        overlap(`rule ${rule.index} changes a class inside the fill of rule ${change.rule.index}`);
      }
      if (
        change.rule.op === "remove" &&
        (change.target === target || isAncestor(change.target, target))
      ) {
        overlap(`rule ${rule.index} changes a class the remove of rule ${change.rule.index} drops`);
      }
    }
    const tokens = classPairs.get(target.element) ?? new Set();
    if (tokens.has(/** @type {string} */ (rule.className))) {
      overlap(`rule ${rule.index} repeats an element and class pair`);
    }
    tokens.add(/** @type {string} */ (rule.className));
    classPairs.set(target.element, tokens);
  }
}
