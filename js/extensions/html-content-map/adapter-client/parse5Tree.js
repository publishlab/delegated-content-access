// @ts-check
//
// The content-map tree port over parse5, for a server-side client
// (docs/spec-proposal--html-content-map.md Sections 5.2, 6.3 and 7.1). parse5 follows
// the WHATWG HTML parsing algorithm, so the tree it builds is the tree a
// browser builds from the same markup:
//
// - `parseLockedDocument` parses with `scriptingEnabled: true`, parse5's
//   default, spelled out because the profile requires the scripting flag set:
//   `noscript` content is then text, as in a browser with scripting on;
// - `fillHtml` calls `parseFragment(target, html)`, the HTML fragment parsing
//   algorithm with the target as context element, and moves the result under
//   the target, as the `innerHTML` setter does;
// - `serialize` is parse5's serializer, the HTML fragment serialization
//   algorithm applied to the document. It writes a carriage return unescaped,
//   so the receiving parser turns it into a line feed as a browser's own round
//   trip does.
//
// parse5 has one known divergence from a current browser that matters here:
// Chrome 152 parses `select` content with a newer algorithm. The profile keeps
// `select` out of every target and every target's ancestry, so no rule places
// through that algorithm; a publisher fragment containing a `select` still can.
// This module depends on the `parse5` package, which is the reference's one
// runtime dependency.

import { defaultTreeAdapter, parse, parseFragment, serialize } from "parse5";
import { utf8Encode } from "../../../core-shared/codec.js";
import { classValueWithout } from "../core-shared--client-publisher/treePort.js";

/** @typedef {import('parse5').DefaultTreeAdapterMap} Parse5Map */
/** @typedef {Parse5Map['element']} Parse5Element */
/** @typedef {Parse5Map['parentNode']} Parse5Parent */
/** @typedef {Parse5Map['childNode']} Parse5Child */

/**
 * @param {Parse5Child} node
 * @returns {node is Parse5Element}
 */
function isElement(node) {
  return defaultTreeAdapter.isElementNode(node);
}

/**
 * Detach every child of a parent node.
 *
 * @param {Parse5Parent} parent
 */
function clearChildren(parent) {
  for (const child of [...parent.childNodes]) defaultTreeAdapter.detachNode(child);
}

/**
 * The concatenated data of every descendant text node, as `textContent` reads it.
 *
 * @param {Parse5Parent} node
 * @returns {string}
 */
function textOf(node) {
  let out = "";
  for (const child of node.childNodes) {
    if (defaultTreeAdapter.isTextNode(child)) out += child.value;
    else if (isElement(child)) out += textOf(child);
  }
  return out;
}

/**
 * Parse one locked document with the scripting flag set, and wrap it in the
 * tree port.
 *
 * @param {string} html - the decoded delivery
 * @returns {import('../core-shared--client-publisher/treePort.js').TreePort & { serialize: () => string }}
 */
export function parseLockedDocument(html) {
  const document = parse(html, { scriptingEnabled: true });
  const octets = utf8Encode(html).length;

  return {
    documentElement: () => document.childNodes.find(isElement) ?? null,
    children: (element) => /** @type {Parse5Element} */ (element).childNodes.filter(isElement),
    localName: (element) => /** @type {Parse5Element} */ (element).tagName,
    namespace: (element) => /** @type {Parse5Element} */ (element).namespaceURI,
    attribute: (element, name) =>
      /** @type {Parse5Element} */ (element).attrs.find(
        (attribute) => attribute.name === name && !attribute.namespace,
      )?.value ?? null,
    text: (element) => textOf(/** @type {Parse5Element} */ (element)),
    mode: () => document.mode,
    sourceOctets: () => octets,
    snapshotWithout: (mask) => snapshotWithout(document, mask),
    prepareFill: (element, text, contentType) => {
      const target = /** @type {Parse5Element} */ (element);
      const original = [...target.childNodes];
      const fragment =
        contentType === "text/html"
          ? parseFragment(target, text, { scriptingEnabled: true })
          : defaultTreeAdapter.createDocumentFragment();
      if (contentType === "text/plain" && text.length > 0)
        defaultTreeAdapter.insertText(fragment, text);
      const prepared = [...fragment.childNodes];
      const expected = serialize(fragment, { scriptingEnabled: true });
      let attempted = false;
      const replace = (/** @type {Parse5Child[]} */ children) => {
        clearChildren(target);
        for (const child of children) {
          defaultTreeAdapter.detachNode(child);
          defaultTreeAdapter.appendChild(target, child);
        }
      };
      return {
        matches: () => serialize(target, { scriptingEnabled: true }) === expected,
        commit: () => {
          attempted = true;
          replace(prepared);
        },
        rollback: () => {
          if (attempted) replace(original);
        },
      };
    },
    remove: (element) => defaultTreeAdapter.detachNode(/** @type {Parse5Element} */ (element)),
    removeClass: (element, token) => {
      const attribute = /** @type {Parse5Element} */ (element).attrs.find(
        (each) => each.name === "class" && !each.namespace,
      );
      // Target admission proved the token present, so the attribute exists.
      if (attribute !== undefined) attribute.value = classValueWithout(attribute.value, token);
    },
    fillText: (element, text) => {
      const target = /** @type {Parse5Element} */ (element);
      clearChildren(target);
      if (text.length > 0) defaultTreeAdapter.insertText(target, text);
    },
    fillHtml: (element, html) => {
      const target = /** @type {Parse5Element} */ (element);
      const fragment = parseFragment(target, html, { scriptingEnabled: true });
      clearChildren(target);
      for (const child of [...fragment.childNodes]) {
        defaultTreeAdapter.detachNode(child);
        defaultTreeAdapter.appendChild(target, child);
      }
    },
    serialize: () => serialize(document, { scriptingEnabled: true }),
  };
}

/** @param {any} document @param {{children: any[], removed: any[], classes: any[]}} mask @returns {string} */
function snapshotWithout(document, mask) {
  const out = [];
  const stack = [{ node: document, end: false }];
  while (stack.length) {
    const entry = stack.pop();
    if (!entry) break;
    const { node, end } = entry;
    if (mask.removed.includes(node)) continue;
    if (end) {
      out.push("end");
      continue;
    }
    out.push(
      node.tagName
        ? [
            node.tagName,
            node.namespaceURI,
            node.attrs
              .filter(
                (/** @type {any} */ a) =>
                  !(a.name === "class" && !a.namespace && mask.classes.includes(node)),
              )
              .map((/** @type {any} */ a) => [a.namespace ?? null, a.name, a.value]),
          ]
        : [
            node.nodeName,
            node.value ?? node.data ?? null,
            node.name ?? null,
            node.publicId ?? null,
            node.systemId ?? null,
          ],
    );
    stack.push({ node, end: true });
    if (mask.children.includes(node)) continue;
    const children = node.content?.childNodes ?? node.childNodes ?? [];
    for (let i = children.length - 1; i >= 0; i--) stack.push({ node: children[i], end: false });
  }
  return JSON.stringify(out);
}
