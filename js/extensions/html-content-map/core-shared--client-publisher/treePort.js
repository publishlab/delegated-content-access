// @ts-check
//
// The content-map core reads and changes a document only through a tree port,
// so the same admission and placement code runs over a browser DOM and over a
// server-side parse tree. `../adapter-client/domTree.js` implements the port
// over the native DOM and `../adapter-client/parse5Tree.js` over parse5. An
// element is an opaque handle: the core compares handles with `===` and hands
// them back to the port, and it never reads a member of one.
//
// Target traversal uses the element tree. Carrier text, fills and surrounding
// document snapshots are whole operations; snapshots also retain text, comments
// and doctype data to detect collateral changes. Template contents are not in the
// document tree (docs/spec-proposal--html-content-map.md Section 5.3), so `children`
// never returns them.
//
// This module also holds the two token algorithms both adapters share with the
// core: the ordered set parser a class attribute goes through, and the
// DOMTokenList remove steps a `removeClass` rule applies. The browser adapter
// calls the native `classList.remove`; the parse5 adapter calls
// `classValueWithout` here, so both reach the DOM Standard's result.

/** The HTML namespace, as elements report it. */
export const HTML_NAMESPACE = "http://www.w3.org/1999/xhtml";

/**
 * @typedef {'no-quirks'|'limited-quirks'|'quirks'} DocumentMode
 */

/**
 * A prepared fill holds parsed nodes without changing the live target.
 * @typedef {object} PreparedFill
 * @property {() => boolean} matches - the committed fill still equals its prepared content
 * @property {() => void} commit
 * @property {() => void} rollback - restores the original children if commit was attempted
 */

/**
 * The operations the content-map core needs from one parsed document.
 *
 * @typedef {object} TreePort
 * @property {() => any} documentElement - the root element, or null
 * @property {(element: any) => any[]} children - the element children, in
 *   tree order; a `template` element answers none
 * @property {(element: any) => string} localName
 * @property {(element: any) => string|null} namespace - the namespace URI
 * @property {(element: any, name: string) => string|null} attribute - the
 *   value of the attribute with this local name and no namespace, or null
 * @property {(element: any) => string} text - the concatenated data of every
 *   descendant text node, as `textContent` reads it
 * @property {() => DocumentMode} mode - the document's quirks mode; a DOM that
 *   cannot tell limited-quirks from no-quirks answers `no-quirks`, since the
 *   profile admits both alike
 * @property {() => string} serialize - whole-document HTML for stale checks
 * @property {(mask: {children: any[], removed: any[], classes: any[]}) => string} snapshotWithout - read-only structural snapshot excluding only the named controlled effects
 * @property {(element: any, text: string, contentType: string) => PreparedFill} prepareFill
 * @property {() => number} sourceOctets - the size of the locked document in
 *   octets, for the Section 5.4 limit
 * @property {(element: any) => void} remove - remove the element and its subtree
 * @property {(element: any, token: string) => void} removeClass - apply the
 *   DOMTokenList remove steps to the element's `class` attribute
 * @property {(element: any, text: string) => void} fillText - replace all
 *   children with one text node, or none for an empty string, as the
 *   `textContent` setter does
 * @property {(element: any, html: string) => void} fillHtml - replace all
 *   children with the nodes the HTML fragment parsing algorithm builds from
 *   `html` with the element as context and the scripting flag set, as the
 *   `innerHTML` setter does
 */

/**
 * One element of the document tree with the facts target admission reads.
 *
 * @typedef {object} TreeEntry
 * @property {any} element
 * @property {number[]} path - element-child indexes from the document element
 * @property {TreeEntry|null} parent
 */

/**
 * The ordered set parser of the DOM Standard over ASCII whitespace: split, drop
 * empty strings, keep the first occurrence of each token.
 *
 * @param {string|null} value
 * @returns {string[]}
 */
export function orderedTokenSet(value) {
  if (value === null) return [];
  /** @type {string[]} */
  const tokens = [];
  for (const token of value.split(/[\t\n\f\r ]+/)) {
    if (token.length > 0 && !tokens.includes(token)) tokens.push(token);
  }
  return tokens;
}

/**
 * The `class` value the DOMTokenList `remove` steps leave: the remaining tokens
 * as an ordered set, without duplicates, joined by single spaces. A caller
 * applies it only to an element that carries a `class` attribute, which target
 * admission guarantees for every `removeClass` target.
 *
 * `"bodytext locked  bodytext"` without `locked` is
 * `"bodytext"`.
 *
 * @param {string} value - the current attribute value
 * @param {string} token
 * @returns {string}
 */
export function classValueWithout(value, token) {
  return orderedTokenSet(value)
    .filter((each) => each !== token)
    .join(" ");
}

/**
 * Every element of the document tree in tree order, each with its path and
 * parent entry. Template contents stay out because `children` leaves them out.
 *
 * The walk keeps its own stack, so a deeply nested document costs memory in
 * proportion to its size and never exhausts the call stack.
 *
 * @param {TreePort} tree
 * @returns {TreeEntry[]}
 */
export function treeEntries(tree) {
  const root = tree.documentElement();
  if (root === null || root === undefined) return [];
  /** @type {TreeEntry[]} */
  const entries = [];
  /** @type {TreeEntry[]} */
  const stack = [{ element: root, path: [], parent: null }];
  while (stack.length > 0) {
    const entry = /** @type {TreeEntry} */ (stack.pop());
    entries.push(entry);
    const children = tree.children(entry.element);
    for (let index = children.length - 1; index >= 0; index -= 1) {
      stack.push({ element: children[index], path: [...entry.path, index], parent: entry });
    }
  }
  return entries;
}

/**
 * Whether `ancestor` is a proper ancestor of `entry`.
 *
 * @param {TreeEntry} ancestor
 * @param {TreeEntry} entry
 * @returns {boolean}
 */
export function isAncestor(ancestor, entry) {
  for (let at = entry.parent; at !== null; at = at.parent) {
    if (at === ancestor) return true;
  }
  return false;
}
