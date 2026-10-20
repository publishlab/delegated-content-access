// @ts-check
//
// The content-map tree port over parse5, for a publisher that admits its own
// rendered page before it returns the markup
// (docs/spec-proposal--html-content-map.md Sections 3 to 5 and 7.1). The page
// is parsed with the scripting flag set, as a client parses it, so the map,
// target and quirks-mode checks see the tree a client will see.
//
// The read side copies `../adapter-client/parse5Tree.js`. A publisher copy of
// this extension takes no client adapter, and the core holds no parser, so the
// publisher keeps its own reader.
//
// The publisher places nothing on the page it returns. The port's placing
// operations refuse; the placements the publisher needs, HTML or plain-text fills
// for the Section 7.1 check, runs on a private parse in `deliveredFormDiffers`.

import { defaultTreeAdapter, parse, parseFragment, serialize } from "parse5";
import { dcaError } from "../../../core-shared/errors.js";
import { utf8Encode } from "../../../core-shared/codec.js";

/** @typedef {import('parse5').DefaultTreeAdapterMap} Parse5Map */
/** @typedef {Parse5Map['element']} Parse5Element */
/** @typedef {Parse5Map['parentNode']} Parse5Parent */
/** @typedef {Parse5Map['childNode']} Parse5Child */
/** @typedef {Parse5Map['document']} Parse5Document */

/**
 * @param {Parse5Child} node
 * @returns {node is Parse5Element}
 */
function isElement(node) {
  return defaultTreeAdapter.isElementNode(node);
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

/** @param {string} html */
function parsePage(html) {
  return parse(html, { scriptingEnabled: true });
}

/** @returns {never} */
function refusePlacement() {
  throw dcaError("bad_config", "the publisher reader admits a page and places nothing on it");
}

/**
 * Parse one rendered page with the scripting flag set, and wrap it in the
 * read side of the tree port.
 *
 * @param {string} html - the rendered page
 * @returns {import('../core-shared--client-publisher/treePort.js').TreePort}
 */
export function parseRenderedPage(html) {
  const document = parsePage(html);
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
    serialize: () => serialize(document, { scriptingEnabled: true }),
    prepareFill: refusePlacement,
    snapshotWithout: refusePlacement,
    remove: refusePlacement,
    removeClass: refusePlacement,
    fillText: refusePlacement,
    fillHtml: refusePlacement,
  };
}

/**
 * The element at a path of element-child indexes from the document element,
 * or null when the path leads nowhere.
 *
 * @param {Parse5Document} document
 * @param {number[]} path
 * @returns {Parse5Element|null}
 */
function elementAt(document, path) {
  let element = document.childNodes.find(isElement) ?? null;
  for (const index of path) {
    if (element === null) return null;
    element = element.childNodes.filter(isElement)[index] ?? null;
  }
  return element;
}

/**
 * The Section 7.2 observation of a child tree: each node's kind, an element's
 * local name, namespace and attributes as a sorted set, and text and comment
 * data. A template's contents count as its children.
 *
 * @param {Parse5Parent} parent
 * @returns {unknown[]}
 */
function childTree(parent) {
  const nodes =
    isElement(/** @type {Parse5Child} */ (parent)) && /** @type {any} */ (parent).content
      ? /** @type {any} */ (parent).content.childNodes
      : parent.childNodes;
  return nodes.map((/** @type {Parse5Child} */ node) => {
    if (defaultTreeAdapter.isTextNode(node)) return ["text", node.value];
    if (defaultTreeAdapter.isCommentNode(node)) return ["comment", node.data];
    if (!isElement(node)) return ["other"];
    const attributes = node.attrs
      .map((each) => [each.namespace ?? "", each.name, each.value])
      .sort((a, b) => (a.join("\u0000") < b.join("\u0000") ? -1 : 1));
    return ["element", node.namespaceURI, node.tagName, attributes, childTree(node)];
  });
}

/**
 * Fill decoded HTML or plain text into targets on a private parse of `html`,
 * as the `innerHTML` setter does, then serialize that document and parse the
 * serialization as a client's receiver does. The result names every fill
 * whose target's child tree differs between the two: the live tree a browser
 * client builds and the delivered form of Section 7.1.
 *
 * The comparison runs on whole documents because a fragment's own round trip
 * hides the difference: `<div>x</div>` parsed in a `p` context and reparsed in
 * it stays inside, while the serialized page closes the `p` before the `div`.
 *
 * @param {string} html - the rendered page
 * @param {{ path: number[], html: string, contentType?: string }[]} fills - each target by its path
 *   of element-child indexes, and the fragment placed into it
 * @returns {number[]} the indexes into `fills` whose trees differ
 */
export function deliveredFormDiffers(html, fills) {
  const live = parsePage(html);
  const targets = fills.map(({ path }) => elementAt(live, path));
  fills.forEach(({ html: fragmentHtml, contentType = "text/html" }, index) => {
    const target = targets[index];
    if (target === null) throw dcaError("bad_config", "a fill path names no element");
    const fragment =
      contentType === "text/plain"
        ? null
        : parseFragment(target, fragmentHtml, { scriptingEnabled: true });
    for (const child of [...target.childNodes]) defaultTreeAdapter.detachNode(child);
    if (fragment === null) {
      if (fragmentHtml !== "") defaultTreeAdapter.insertText(target, fragmentHtml);
      return;
    }
    for (const child of [...fragment.childNodes]) {
      defaultTreeAdapter.detachNode(child);
      defaultTreeAdapter.appendChild(target, child);
    }
  });
  const delivered = parsePage(serialize(live, { scriptingEnabled: true }));
  /** @type {number[]} */
  const differing = [];
  fills.forEach(({ path }, index) => {
    const target = /** @type {Parse5Element} */ (targets[index]);
    const reparsed = elementAt(delivered, path);
    if (
      reparsed === null ||
      reparsed.tagName !== target.tagName ||
      JSON.stringify(childTree(reparsed)) !== JSON.stringify(childTree(target))
    ) {
      differing.push(index);
    }
  });
  return differing;
}
