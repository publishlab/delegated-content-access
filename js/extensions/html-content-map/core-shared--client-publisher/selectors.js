// @ts-check
//
// The target selector grammar of docs/spec-proposal--html-content-map.md Section 5.1
// and a matcher for it over the tree port. The grammar is a small subset of
// Selectors Level 4: type names, `#id`, `.class`, four closed attribute names
// with an optional exact value, and the descendant and child combinators. This
// module parses that subset itself rather than handing the string to a CSS
// engine, because an engine accepts far more than the profile admits and a
// client must refuse the rest as `map_selector_unsupported`.
//
// A parsed selector is plain data, so a port can compare it and a test can
// print it: `#main .bodytext` parses to two compounds joined by a descendant
// combinator, `[{ id: "main" }]` and `[{ class: "bodytext" }]`.
//
// Matching reads the locked document, which target admission has already held
// to no-quirks or limited-quirks mode. In those modes `#id` and `.class` compare
// case-sensitively, and the attribute names the grammar admits are outside the
// set HTML compares case-insensitively, so every comparison here is exact.

import { dcaError } from "../../../core-shared/errors.js";
import { orderedTokenSet } from "./treePort.js";

/**
 * One qualifier of a compound.
 *
 * @typedef {{ kind: 'id', name: string }
 *   | { kind: 'class', name: string }
 *   | { kind: 'attribute', name: string, value: string|null }} Qualifier
 */

/**
 * One compound selector: an optional type name and its qualifiers.
 *
 * @typedef {object} Compound
 * @property {string|null} type
 * @property {Qualifier[]} qualifiers
 */

/**
 * A parsed target: compounds left to right, and the combinator before each
 * compound after the first.
 *
 * @typedef {object} Selector
 * @property {string} text
 * @property {Compound[]} compounds
 * @property {('descendant'|'child')[]} combinators
 */

/** The four attribute names the grammar closes over; `data-*` is checked apart. */
const FIXED_ATTRIBUTE_NAMES = ["slot", "itemprop", "role"];

/** @param {string} text @param {string} why @returns {never} */
function unsupported(text, why) {
  throw dcaError(
    "map_selector_unsupported",
    `the target ${JSON.stringify(text)} is outside the selector grammar: ${why}`,
  );
}

/** @param {number} c */
const isLower = (c) => c >= 0x61 && c <= 0x7a;
/** @param {number} c */
const isDigit = (c) => c >= 0x30 && c <= 0x39;
/** @param {number} c */
const isAlpha = (c) => isLower(c) || (c >= 0x41 && c <= 0x5a);

/**
 * Parse one target selector under Section 5.1, and enforce the two selector
 * limits of Section 5.4 as `map_limit`.
 *
 * @param {unknown} text
 * @param {{ maxLength: number, maxCompounds: number }} limits
 * @returns {Selector}
 */
export function parseSelector(text, limits) {
  if (typeof text !== "string") {
    throw dcaError("map_malformed", "a rule target is a string");
  }
  if (text.length > limits.maxLength) {
    throw dcaError("map_limit", `a target is longer than ${limits.maxLength} characters`);
  }
  let at = 0;

  /** @returns {string} */
  const ident = () => {
    const start = at;
    if (text.charCodeAt(at) === 0x2d) at += 1;
    const first = text.charCodeAt(at);
    if (!(isAlpha(first) || first === 0x5f)) unsupported(text, `no identifier at offset ${start}`);
    at += 1;
    while (at < text.length) {
      const c = text.charCodeAt(at);
      if (isAlpha(c) || isDigit(c) || c === 0x5f || c === 0x2d) at += 1;
      else break;
    }
    return text.slice(start, at);
  };

  /** @returns {string} */
  const attributeName = () => {
    const start = at;
    while (at < text.length) {
      const c = text.charCodeAt(at);
      if (isLower(c) || isDigit(c) || c === 0x2d) at += 1;
      else break;
    }
    const name = text.slice(start, at);
    const dataName = /^data-[a-z0-9-]+$/.test(name);
    if (!FIXED_ATTRIBUTE_NAMES.includes(name) && !dataName) {
      unsupported(text, `the attribute name ${JSON.stringify(name)} is not admitted`);
    }
    return name;
  };

  /** @returns {string} */
  const quoted = () => {
    if (text[at] !== '"') unsupported(text, `a double-quoted value was expected at offset ${at}`);
    at += 1;
    const start = at;
    for (;;) {
      if (at >= text.length) unsupported(text, "an unterminated attribute value");
      const c = text.charCodeAt(at);
      if (c === 0x22) break;
      if (c < 0x20 || c > 0x7e || c === 0x5c) {
        unsupported(text, `a character the value grammar excludes at offset ${at}`);
      }
      at += 1;
    }
    const value = text.slice(start, at);
    at += 1;
    return value;
  };

  /** @returns {Compound} */
  const compound = () => {
    /** @type {string|null} */
    let type = null;
    if (isLower(text.charCodeAt(at))) {
      const start = at;
      at += 1;
      while (at < text.length) {
        const c = text.charCodeAt(at);
        if (isLower(c) || isDigit(c) || c === 0x2d) at += 1;
        else break;
      }
      type = text.slice(start, at);
    }
    /** @type {Qualifier[]} */
    const qualifiers = [];
    for (;;) {
      const c = text[at];
      if (c === "#") {
        at += 1;
        qualifiers.push({ kind: "id", name: ident() });
      } else if (c === ".") {
        at += 1;
        qualifiers.push({ kind: "class", name: ident() });
      } else if (c === "[") {
        at += 1;
        const name = attributeName();
        /** @type {string|null} */
        let value = null;
        if (text[at] === "=") {
          at += 1;
          value = quoted();
        }
        if (text[at] !== "]") unsupported(text, `a closing bracket was expected at offset ${at}`);
        at += 1;
        qualifiers.push({ kind: "attribute", name, value });
      } else {
        break;
      }
    }
    if (type === null && qualifiers.length === 0) {
      unsupported(text, `a compound selector was expected at offset ${at}`);
    }
    return { type, qualifiers };
  };

  /** @type {Compound[]} */
  const compounds = [compound()];
  /** @type {('descendant'|'child')[]} */
  const combinators = [];
  while (at < text.length) {
    const start = at;
    while (text[at] === " ") at += 1;
    if (text[at] === ">") {
      at += 1;
      while (text[at] === " ") at += 1;
      combinators.push("child");
    } else if (at > start) {
      combinators.push("descendant");
    } else {
      unsupported(text, `unexpected character at offset ${at}`);
    }
    // A selector has no trailing space and no dangling combinator.
    if (at >= text.length) unsupported(text, "the selector ends in a combinator or space");
    compounds.push(compound());
    if (compounds.length > limits.maxCompounds) {
      throw dcaError("map_limit", `a target has more than ${limits.maxCompounds} compounds`);
    }
  }
  return { text, compounds, combinators };
}

/**
 * Whether one element satisfies one compound.
 *
 * @param {import('./treePort.js').TreePort} tree
 * @param {any} element
 * @param {Compound} compound
 * @returns {boolean}
 */
function matchesCompound(tree, element, compound) {
  if (compound.type !== null) {
    // Type selectors compare ASCII-case-insensitively for HTML elements in an
    // HTML document, whose local names the parser already lowercased, and
    // case-sensitively for every other namespace. The grammar spells only
    // lowercase names, so an SVG `foreignObject` never matches.
    if (tree.localName(element) !== compound.type) return false;
  }
  for (const qualifier of compound.qualifiers) {
    if (qualifier.kind === "id") {
      if (tree.attribute(element, "id") !== qualifier.name) return false;
    } else if (qualifier.kind === "class") {
      if (!orderedTokenSet(tree.attribute(element, "class")).includes(qualifier.name)) {
        return false;
      }
    } else {
      const value = tree.attribute(element, qualifier.name);
      if (value === null) return false;
      if (qualifier.value !== null && value !== qualifier.value) return false;
    }
  }
  return true;
}

/**
 * Whether the entry's element matches the whole selector: the last compound on
 * the element, then each earlier compound on an ancestor (descendant) or on
 * the parent (child), right to left, with backtracking over ancestors. The
 * memo holds each (ancestor, compound) answer once, so a long chain of
 * descendant combinators costs the depth times the compound count rather than
 * a power of the depth.
 *
 * @param {import('./treePort.js').TreePort} tree
 * @param {import('./treePort.js').TreeEntry} entry
 * @param {Selector} selector
 * @param {Map<import('./treePort.js').TreeEntry, boolean[]>} [memo] - shared
 *   across the entries of one document when a caller matches them all
 * @returns {boolean}
 */
export function matchesSelector(tree, entry, selector, memo = new Map()) {
  /**
   * @param {import('./treePort.js').TreeEntry} at
   * @param {number} index - the compound `at` must satisfy
   * @returns {boolean}
   */
  const from = (at, index) => {
    let answers = memo.get(at);
    if (answers === undefined) {
      answers = [];
      memo.set(at, answers);
    }
    const known = answers[index];
    if (known !== undefined) return known;
    let answer = matchesCompound(tree, at.element, selector.compounds[index]);
    if (answer && index > 0) {
      if (selector.combinators[index - 1] === "child") {
        answer = at.parent !== null && from(at.parent, index - 1);
      } else {
        answer = false;
        for (let up = at.parent; up !== null && !answer; up = up.parent) {
          answer = from(up, index - 1);
        }
      }
    }
    answers[index] = answer;
    return answer;
  };
  return from(entry, selector.compounds.length - 1);
}
