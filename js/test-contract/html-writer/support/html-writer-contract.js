// @ts-check
import assert from "node:assert/strict";
import test from "node:test";
import { parse } from "parse5";

/**
 * @typedef {{dcaData: object, sealedContent: {contentName: string, content: string}[]}} WriterInput
 * @typedef {{writeMarkup(input: WriterInput): string | Promise<string>}} HtmlWriterDriver
 */

/** @param {any} node @param {string} name @returns {string | undefined} */
function attribute(node, name) {
  return node.attrs?.find((/** @type {{name: string}} */ attr) => attr.name === name)?.value;
}

/**
 * Body descendants in the document tree, excluding template contents. The
 * optional mode exists only for the owning parser-mode control; the writer
 * contract always requests scripting enabled.
 * @param {string} fragment
 * @param {boolean} scriptingEnabled
 * @returns {any[]}
 */
export function bodyElements(fragment, scriptingEnabled) {
  const document = parse(`<!doctype html><html><head></head><body>${fragment}</body></html>`, {
    scriptingEnabled,
  });
  const html = document.childNodes.find((node) => node.nodeName === "html");
  assert.ok(html && "childNodes" in html, "the document has an html element");
  const body = html.childNodes.find((node) => node.nodeName === "body");
  assert.ok(body && "childNodes" in body, "the document has a body element");
  /** @type {any[]} */
  const elements = [];
  /** @param {any} parent */
  function visit(parent) {
    for (const child of parent.childNodes ?? []) {
      if (child.tagName) elements.push(child);
      visit(child);
    }
  }
  visit(body);
  return elements;
}

/** @param {any} element @returns {string} */
function text(element) {
  return (element.childNodes ?? []).map((/** @type {any} */ node) => node.value ?? "").join("");
}

/** @param {string} markup @param {WriterInput} expected */
export function assertMarkupDelivery(markup, expected) {
  assert.equal(typeof markup, "string", "the writer returns HTML text");
  const elements = bodyElements(`${markup}<p data-dca-contract-sentinel="after">after</p>`, true);
  /** @param {string} token */
  function carrier(token) {
    const matches = elements.filter((element) =>
      (attribute(element, "class") ?? "").split(/[\t\n\f\r ]+/).includes(token),
    );
    assert.equal(matches.length, 1, `exactly one body ${token} carrier survives HTML parsing`);
    const element = matches[0];
    assert.equal(element.tagName, "script", `${token} is a script element`);
    assert.equal(attribute(element, "type"), "application/json", `${token} carries JSON`);
    return element;
  }
  const data = carrier("dca-data");
  const sealed = carrier("dca-sealed-content");
  assert.notEqual(data, sealed, "the two carriers are separate elements");
  const sentinels = elements.filter(
    (element) => attribute(element, "data-dca-contract-sentinel") === "after",
  );
  assert.equal(sentinels.length, 1, "the following page sentinel survives HTML parsing");
  assert.equal(sentinels[0].tagName, "p");
  assert.equal(text(sentinels[0]), "after", "the following page sentinel remains intact");
  assert.deepEqual(JSON.parse(text(data)), expected.dcaData, "data carrier preserves JSON values");
  assert.deepEqual(
    JSON.parse(text(sealed)),
    expected.sealedContent,
    "sealed-content carrier preserves named records",
  );
}

/** @param {any} binding @param {{case: string, input: WriterInput}[]} cases */
export function registerHtmlWriterContract(binding, cases) {
  const driver = /** @type {HtmlWriterDriver} */ (binding.targets["html-writer"].driver);
  assert.equal(typeof driver.writeMarkup, "function", "binding supplies the writer callback");
  for (const fixture of cases) {
    test(`${fixture.case}: writer preserves inert body carriers and page sentinel`, async () => {
      // Keep expected values independent from a callback that mutates its input.
      const expected = structuredClone(fixture.input);
      assertMarkupDelivery(await driver.writeMarkup(structuredClone(fixture.input)), expected);
    });
  }
}
