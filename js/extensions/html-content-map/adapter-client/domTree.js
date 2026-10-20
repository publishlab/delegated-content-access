// @ts-check
//
// The content-map tree port over a browser's native DOM. A browser client
// resolves targets in the document it runs in (docs/spec-proposal--html-content-map.md
// Section 5.2), and it places items with the platform's own setters, so the
// result is what the spec's oracle harness produces:
//
// - `fillHtml` sets `innerHTML`, which runs the HTML fragment parsing
//   algorithm with the target as context and the scripting flag the document
//   has, and does not run a `script` element in the fragment;
// - `fillText` sets `textContent`;
// - `removeClass` calls `classList.remove`, the DOMTokenList remove steps;
// - `remove` calls `remove()`.
//
// The caller passes the document in, so this module reads no global and runs
// wherever a DOM does. It serializes the document with the HTML fragment
// serialization algorithm the way `innerHTML` does for each child, so a
// browser client's output and a server-side client's output can be compared
// as delivered forms (Section 7.1).

import { utf8Encode } from "../../../core-shared/codec.js";

/**
 * The HTML serialization of one document node: its doctype, the document
 * element's outer HTML and any comments around it, in tree order.
 *
 * @param {Document} document
 * @returns {string}
 */
export function serializeDomDocument(document) {
  let out = "";
  for (const node of Array.from(document.childNodes)) {
    if (node.nodeType === 10) out += `<!DOCTYPE ${/** @type {DocumentType} */ (node).name}>`;
    else if (node.nodeType === 1) out += /** @type {Element} */ (node).outerHTML;
    else if (node.nodeType === 8) out += `<!--${/** @type {Comment} */ (node).data}-->`;
  }
  return out;
}

/**
 * @param {Document} document - the locked document, changed in place
 * @returns {import('../core-shared--client-publisher/treePort.js').TreePort}
 */
export function domTree(document) {
  return {
    documentElement: () => document.documentElement,
    children: (element) => Array.from(/** @type {Element} */ (element).children),
    localName: (element) => /** @type {Element} */ (element).localName,
    namespace: (element) => /** @type {Element} */ (element).namespaceURI,
    attribute: (element, name) => /** @type {Element} */ (element).getAttributeNS(null, name),
    text: (element) => /** @type {Element} */ (element).textContent ?? "",
    // The DOM reports limited-quirks as CSS1Compat, which the profile admits
    // exactly as it admits no-quirks mode.
    mode: () => (document.compatMode === "BackCompat" ? "quirks" : "no-quirks"),
    // The browser parsed the page before this client ran; the size of its
    // serialization bounds the work admission can cause here.
    sourceOctets: () => utf8Encode(serializeDomDocument(document)).length,
    serialize: () => serializeDomDocument(document),
    snapshotWithout: (mask) => snapshotWithout(document, mask),
    prepareFill: (element, text, contentType) => {
      const target = /** @type {Element} */ (element);
      // Parsing on a disconnected clone lets Trusted Types reject a fill
      // before any live fill or lock-removal rule runs.
      const staged = /** @type {Element} */ (target.cloneNode(false));
      if (contentType === "text/html") staged.innerHTML = text;
      else staged.textContent = text;
      const original = Array.from(target.childNodes);
      const prepared = Array.from(staged.childNodes);
      const expected = staged.innerHTML;
      let attempted = false;
      return {
        matches: () => target.innerHTML === expected,
        commit: () => {
          attempted = true;
          target.replaceChildren(...prepared);
        },
        rollback: () => {
          if (attempted) target.replaceChildren(...original);
        },
      };
    },
    remove: (element) => /** @type {Element} */ (element).remove(),
    removeClass: (element, token) => /** @type {Element} */ (element).classList.remove(token),
    fillText: (element, text) => {
      /** @type {Element} */ (element).textContent = text;
    },
    fillHtml: (element, html) => {
      /** @type {Element} */ (element).innerHTML = html;
    },
  };
}

/** Read without cloning nodes or invoking custom-element constructors.
 * @param {Document} document
 * @param {{children: any[], removed: any[], classes: any[]}} mask
 * @returns {string}
 */
function snapshotWithout(document, mask) {
  const out = [];
  const stack = [{ node: /** @type {Node} */ (document), end: false }];
  while (stack.length) {
    const entry = stack.pop();
    if (!entry) break;
    const { node, end } = entry;
    if (mask.removed.includes(node)) continue;
    if (end) {
      out.push("end");
      continue;
    }
    const element = node.nodeType === 1 ? /** @type {Element} */ (node) : null;
    out.push(
      element
        ? [
            node.nodeType,
            element.namespaceURI,
            element.localName,
            Array.from(element.attributes)
              .filter(
                (a) =>
                  !(a.name === "class" && a.namespaceURI === null && mask.classes.includes(node)),
              )
              .map((a) => [a.namespaceURI, a.name, a.value]),
          ]
        : [
            node.nodeType,
            node.nodeName,
            node.nodeValue,
            node.nodeType === 10 ? /** @type {DocumentType} */ (node).publicId : null,
            node.nodeType === 10 ? /** @type {DocumentType} */ (node).systemId : null,
          ],
    );
    stack.push({ node, end: true });
    if (mask.children.includes(node)) continue;
    const children =
      element?.localName === "template"
        ? /** @type {HTMLTemplateElement} */ (element).content.childNodes
        : node.childNodes;
    for (let i = children.length - 1; i >= 0; i--) stack.push({ node: children[i], end: false });
  }
  return JSON.stringify(out);
}
