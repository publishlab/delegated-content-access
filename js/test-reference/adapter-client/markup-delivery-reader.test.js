// @ts-check
//
// The markup reader read against one page: its entry refusals, one code each,
// and what it answers for the sealed-content carrier beside them.
// `MarkupDeliveryReader` reads a render off a root it is handed, and every check
// in its constructor stops a page that cannot be read before a caller builds an
// unlock request off it. The placement-contract and end-to-end tests carry the
// positive path - a real render written, parsed, and read back; this file pins
// the refusals they never reach, on the code the port maps a status from rather
// than the wording, and the carrier answers that are misses rather than
// refusals. One positive case sits here beside them: a carrier inside wrapper
// elements reads, because the format leaves the depth a carrier sits at free.
//
// These tests share the DOM stub. The page-shaped refusals are read through
// `domOver`, the same string-to-root parser the placement and end-to-end tests
// read markup through, so a page with no dca-data block, one whose block is not
// JSON, one whose JSON is not an object, a page carrying two carriers, and one
// whose carrier is no inert JSON script are built as the markup they would
// arrive as. The bad-root refusal takes no page at all: it is about the argument
// itself, so the values that answer no query go in directly.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { MarkupDeliveryReader } from "../../adapter-client/MarkupDeliveryReader.js";
import { DATA_SELECTOR, SEALED_SELECTOR } from "../../core-shared/markupPlacement.js";
import { domOver } from "../../test-lib/helpers/domOver.js";
import { refuses } from "../../test-lib/helpers/refuses.js";
import { INHERITED } from "../../test-lib/fixtures/inherited-names.js";

/**
 * A `.dca-data` script block carrying exactly the given text, with no sealed
 * content beside it - the smallest markup `domOver` reads a dca-data block out
 * of.
 *
 * @param {string} dataText
 * @returns {string}
 */
function pageWithData(dataText) {
  return `<script type="application/json" class="dca-data">${dataText}</script>`;
}

/**
 * A readable page whose sealed-content block carries exactly the given text.
 *
 * @param {string} sealedText
 * @returns {string}
 */
function pageWithSealed(sealedText) {
  return (
    `${pageWithData('{"version":"1"}')}\n` +
    `<script type="application/json" class="dca-sealed-content">${sealedText}</script>`
  );
}

/**
 * The sealed-content block text for ciphertext by name: one
 * `{contentName, content}` record per entry, in the given order.
 *
 * @param {Record<string, unknown>} byName
 * @returns {string}
 */
function carrierText(byName) {
  return JSON.stringify(
    Object.entries(byName).map(([contentName, content]) => ({ contentName, content })),
  );
}

describe("The markup delivery reader, entry refusals", () => {
  test("a parsed Document reads only its body, while a fragment uses its explicit scope", () => {
    const head = domOver(pageWithData('{"version":"head"}'));
    const body = domOver(pageWithData('{"version":"body"}'));
    const document = {
      nodeType: 9,
      location: { origin: "https://publisher.example" },
      body,
      querySelectorAll(selector) {
        return [...head.querySelectorAll(selector), ...body.querySelectorAll(selector)];
      },
    };
    assert.equal(new MarkupDeliveryReader(document).dcaData.version, "body");
    assert.equal(new MarkupDeliveryReader({ ...body, nodeType: 11 }).dcaData.version, "body");
    assert.throws(() => new MarkupDeliveryReader({ ...document, nodeType: 11 }), {
      code: "bad_page",
    });
    assert.throws(() => new MarkupDeliveryReader({ ...document, body: null }), {
      code: "bad_page",
    });
    assert.throws(
      () => new MarkupDeliveryReader({ ...document, body: domOver("<p>no body carrier</p>") }),
      { code: "bad_page" },
    );
  });
  test("a root that does not answer querySelector is a config refusal", async () => {
    for (const root of [null, undefined, 42, "a string", {}, { querySelector: "not a function" }]) {
      await refuses(
        () => new MarkupDeliveryReader(/** @type {any} */ (root)),
        { code: "bad_config", message: /querySelector/ },
        `a ${root === null ? "null" : typeof root} root is not a queryable page`,
      );
    }
  });

  test("a root whose querySelectorAll answers no list of elements is a config refusal", async () => {
    // The caller hands the root in, so an answer nothing iterates raises the
    // same config refusal a root that answers no query at all does, rather
    // than a bare TypeError out of the collection.
    for (const answer of [null, undefined, 42, "a string", {}, { length: 1 }]) {
      await refuses(
        () =>
          new MarkupDeliveryReader(
            /** @type {any} */ ({
              location: { origin: "https://publisher.example" },
              querySelectorAll: () => answer,
            }),
          ),
        { code: "bad_config", message: /querySelectorAll/ },
        `querySelectorAll answering ${answer === null ? "null" : typeof answer}`,
      );
    }
  });

  test("a queryable page without a canonical delivery origin is a page refusal", async () => {
    const page = domOver(pageWithData('{"version":"1"}'));
    for (const [label, root] of [
      ["no location", { querySelectorAll: page.querySelectorAll }],
      ["a null origin", { ...page, location: { origin: null } }],
      ["an opaque origin", { ...page, location: { origin: "null" } }],
      // A DOMParser or createHTMLDocument document has a null location.
      [
        "an owner document without a location",
        { querySelectorAll: page.querySelectorAll, ownerDocument: { location: null } },
      ],
    ]) {
      await refuses(
        () => new MarkupDeliveryReader(/** @type {any} */ (root)),
        { code: "bad_page", message: /canonical publisher origin/ },
        label,
      );
    }
  });

  test("a page carrying no dca-data block is a page refusal", async () => {
    const root = domOver("<p>a page with no dca-data at all</p>");

    await refuses(
      () => new MarkupDeliveryReader(root),
      { code: "bad_page", message: /carries no/ },
      `a page with no ${DATA_SELECTOR} block cannot be read`,
    );
  });

  test("a dca-data block that is not JSON is a page refusal", async () => {
    // A block cut short - the emitter escapes the sequence that would close
    // the script early, so JSON that stops here is markup that was truncated.
    const root = domOver(pageWithData('{"version": "1", "reso'));

    await refuses(
      () => new MarkupDeliveryReader(root),
      { code: "bad_page", message: /not JSON/ },
      "a dca-data block that does not parse cannot be read",
    );
  });

  test("a dca-data block whose JSON is not an object is a page refusal", async () => {
    // Each parses to something that is no dca-data object: a number, a
    // string, a bare null, a boolean, and an enclosing array, which the
    // format makes a structural failure of the delivery like the rest.
    for (const jsonText of ["42", '"a string"', "null", "true", "[]", '[{"version":"1"}]']) {
      const root = domOver(pageWithData(jsonText));

      await refuses(
        () => new MarkupDeliveryReader(root),
        { code: "bad_page", message: /not an object/ },
        `dca-data of \`${jsonText}\` is not a page`,
      );
    }
  });

  test("a duplicate carrier, a wrong tag and a wrong type are page refusals", async () => {
    // The reader inspects every element in the root carrying either
    // reserved class token: exactly one dca-data element, at most one
    // sealed-content element, each a script whose type is exactly
    // application/json, and no element serving as both carriers.
    const data = '{"version":"1"}';
    const sealed = carrierText({ bodytext: "QUJD" });
    const sealedBlock = `<script type="application/json" class="dca-sealed-content">${sealed}</script>`;

    for (const [label, markup, message] of [
      ["two dca-data carriers", `${pageWithData(data)}\n${pageWithData(data)}`, /exactly one/],
      [
        "a dca-data element that is no script",
        `<div type="application/json" class="dca-data">${data}</div>`,
        /script/,
      ],
      [
        "a dca-data element whose type is another",
        `<script type="text/javascript" class="dca-data">${data}</script>`,
        /application\/json/,
      ],
      ["two sealed-content carriers", `${pageWithSealed(sealed)}\n${sealedBlock}`, /at most one/],
      [
        "a sealed-content element that is no script",
        pageWithData(data) +
          `<div type="application/json" class="dca-sealed-content">${sealed}</div>`,
        /script/,
      ],
      [
        "a sealed-content element whose type is another",
        pageWithData(data) +
          `<script type="text/plain" class="dca-sealed-content">${sealed}</script>`,
        /application\/json/,
      ],
      [
        "one element serving as both carriers",
        `<script type="application/json" class="dca-data dca-sealed-content">${data}</script>`,
        /both/,
      ],
    ]) {
      await refuses(
        () => new MarkupDeliveryReader(domOver(/** @type {string} */ (markup))),
        { code: "bad_page", message: /** @type {RegExp} */ (message) },
        /** @type {string} */ (label),
      );
    }
  });

  test("a sealed-content block that is not JSON is a page refusal", async () => {
    const root = domOver(pageWithSealed('[{"contentName": "bodytext", "content": "QUJ'));

    await refuses(
      () => new MarkupDeliveryReader(root),
      { code: "bad_page", message: /not JSON/ },
      `a ${SEALED_SELECTOR} block that does not parse cannot be read`,
    );
  });

  test("a sealed-content carrier that is not an array is a page refusal", async () => {
    // The old name-keyed map is not the collection, and `null` carries
    // nothing: both are a carrier the page said it had and did not, which is
    // not the same page as one that shipped no carrier at all.
    for (const jsonText of ["{}", '{"bodytext":"QUJD"}', "null", "42", '"QUJD"', "true"]) {
      const root = domOver(pageWithSealed(jsonText));

      await refuses(
        () => new MarkupDeliveryReader(root),
        { code: "bad_page", message: /not an array/ },
        `a sealed-content carrier of \`${jsonText}\` is not a collection of ciphertext`,
      );
    }
  });
});

describe("The markup delivery reader, the sealed-content carrier", () => {
  test("a page carrying no sealed-content block reads, and every name is a miss", () => {
    const read = new MarkupDeliveryReader(domOver(pageWithData('{"version":"1"}')));

    assert.deepEqual(read.dcaData, { version: "1" });
    assert.equal(read.extract("bodytext"), null, "every item deferred is a page, not a refusal");
  });

  test("an empty carrier reads the same way", () => {
    const read = new MarkupDeliveryReader(domOver(pageWithSealed("[]")));

    assert.equal(read.extract("bodytext"), null);
  });

  test("a record the carrier does not have is a miss, and one it has comes back exactly", () => {
    const read = new MarkupDeliveryReader(
      domOver(pageWithSealed(carrierText({ bodytext: "QUJD_-", premiumtext: "" }))),
    );

    assert.equal(read.extract("bodytext"), "QUJD_-", "byte for byte, no trim and no decode");
    assert.equal(read.extract("premiumtext"), "", "an empty string is a value the page carried");
    assert.equal(read.extract("sidebar"), null, "a name the carrier never had");
  });

  test("a record whose content is not a string supplies no ciphertext", () => {
    // Decryption stays responsible for rejecting unusable bytes; what the
    // reader answers for a non-string is the same miss an absent record gets.
    const records = [
      ...JSON.parse(carrierText({ a: null, b: 42, c: {}, d: [], e: true })),
      { contentName: "f" },
    ];
    const read = new MarkupDeliveryReader(domOver(pageWithSealed(JSON.stringify(records))));

    for (const contentName of ["a", "b", "c", "d", "e", "f"]) {
      assert.equal(read.extract(contentName), null, `a non-string under ${contentName}`);
    }
  });

  test("the carrier is read by own-property lookup, so an inherited name is a miss", () => {
    const read = new MarkupDeliveryReader(
      domOver(pageWithSealed(carrierText({ bodytext: "QUJD" }))),
    );

    for (const contentName of INHERITED) {
      assert.equal(
        read.extract(contentName),
        null,
        `${contentName} is on every object, not on this page`,
      );
    }
    assert.equal(read.extract("__proto__"), null, "and the one name that is a setter on a literal");
  });

  test("a carrier record name outside the grammar is a page refusal", async () => {
    // The format rejects a collection of records named by contentName when
    // one record's name is missing or violates the grammar: one bad name
    // stops every ciphertext on the page rather than that one record.
    for (const carrier of [
      carrierText({ "bad|name": "QUJD" }),
      carrierText({ bodytext: "QUJD", "2bad": "REVG" }),
      carrierText({ "": "QUJD" }),
      '[{"contentName":"bodytext","content":"QUJD"},{"content":"REVG"}]',
      '[{"contentName":7,"content":"REVG"}]',
    ]) {
      await refuses(
        () => new MarkupDeliveryReader(domOver(pageWithSealed(carrier))),
        { code: "bad_page", message: /name/ },
        carrier,
      );
    }

    // Over an admitted carrier, a lookup argument that is no name is the
    // ordinary miss it always was.
    const read = new MarkupDeliveryReader(
      domOver(pageWithSealed(carrierText({ bodytext: "QUJD" }))),
    );
    assert.equal(read.extract("bad|name"), null);
    assert.equal(read.extract(/** @type {any} */ (null)), null);
    assert.equal(read.extract(/** @type {any} */ (42)), null);
  });

  test("the last of two members of one name is what the carrier answers", () => {
    // The v1 JSON rule: a reader may reject duplicates or expose the
    // lexically last value, and never merges them. `JSON.parse` takes the
    // last, which is what this reader inherits.
    const read = new MarkupDeliveryReader(
      domOver(pageWithSealed('[{"contentName":"bodytext","content":"QUJD","content":"REVG"}]')),
    );

    assert.equal(read.extract("bodytext"), "REVG");
  });

  test("the last whole record for one name is what the carrier answers, in any order of names", () => {
    const replaced = new MarkupDeliveryReader(
      domOver(
        pageWithSealed(
          carrierText({ bodytext: "QUJD" }).replace(
            "]",
            ',{"contentName":"bodytext","content":"REVG"}]',
          ),
        ),
      ),
    );
    assert.equal(replaced.extract("bodytext"), "REVG");

    // Replacement, not merging: a later record without usable content
    // leaves no ciphertext rather than falling back to the earlier one.
    const unusable = new MarkupDeliveryReader(
      domOver(
        pageWithSealed(
          carrierText({ bodytext: "QUJD" }).replace("]", ',{"contentName":"bodytext"}]'),
        ),
      ),
    );
    assert.equal(unusable.extract("bodytext"), null);

    for (const order of [
      { bodytext: "QUJD", premiumtext: "REVG" },
      { premiumtext: "REVG", bodytext: "QUJD" },
    ]) {
      const read = new MarkupDeliveryReader(domOver(pageWithSealed(carrierText(order))));
      assert.equal(read.extract("bodytext"), "QUJD");
      assert.equal(read.extract("premiumtext"), "REVG");
    }
  });

  test("an element that is not a record supplies nothing, and its siblings read", () => {
    const read = new MarkupDeliveryReader(
      domOver(
        pageWithSealed(
          '[null,"QUJD",["bodytext","REVG"],{"contentName":"bodytext","content":"QUJD"},42]',
        ),
      ),
    );
    assert.equal(read.extract("bodytext"), "QUJD");
  });

  test("a carrier nested inside another element is the carrier the reader reads", () => {
    // Page placement leaves order, depth and siblinghood free, so a carrier
    // inside wrapper elements is a carrier a browser hands back from a class
    // query, and the shared markup fixture has to find it there too.
    const read = new MarkupDeliveryReader(
      domOver(
        `<div class="wrap"><section>${pageWithSealed(carrierText({ bodytext: "QUJD" }))}</section></div>`,
      ),
    );

    assert.deepEqual(read.dcaData, { version: "1" });
    assert.equal(read.extract("bodytext"), "QUJD");
  });

  test("each block is queried once and parsed once, and the answers are a snapshot", () => {
    /** @type {string[]} */
    const asked = [];
    let sealedReads = 0;
    const script = { tagName: "script", getAttribute: () => "application/json" };
    const root = {
      location: { origin: "https://publisher.example" },
      querySelectorAll(/** @type {string} */ selector) {
        asked.push(selector);
        if (selector === DATA_SELECTOR) return [{ ...script, textContent: '{"version":"1"}' }];
        if (selector === SEALED_SELECTOR) {
          return [
            {
              ...script,
              get textContent() {
                sealedReads += 1;
                return carrierText({ bodytext: "QUJD" });
              },
            },
          ];
        }
        return [];
      },
    };

    const read = new MarkupDeliveryReader(root);
    assert.deepEqual(
      asked,
      [DATA_SELECTOR, SEALED_SELECTOR],
      "one query per block, in the constructor",
    );
    assert.equal(sealedReads, 1, "and one parse of the carrier");

    // Every later answer comes off that one reading.
    assert.equal(read.extract("bodytext"), "QUJD");
    assert.equal(read.extract("bodytext"), "QUJD");
    assert.deepEqual(asked, [DATA_SELECTOR, SEALED_SELECTOR], "extract queries nothing");
    assert.equal(sealedReads, 1);
  });
});
