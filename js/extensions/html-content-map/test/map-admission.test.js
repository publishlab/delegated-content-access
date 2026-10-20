// @ts-check
//
// Map and target admission, docs/spec-proposal--html-content-map.md Sections 3, 4, 5
// and 9. Each case builds a locked page, parses it with the server-side tree
// port and runs the admission steps of `runContentMap`; the run's key client
// throws, so a case also proves that a map failure asks for no key.
//
// The cases drive the portable core only. The browser port reaches the same
// core, and `browser-oracle.test.js` compares the two ports' placements.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { parseLockedDocument } from "../adapter-client/parse5Tree.js";
import { runContentMap, MAP_FAILURES, mapDeliveryOf } from "../core-client/contentMapRun.js";
import { parseSelector } from "../core-shared--client-publisher/selectors.js";

/** The failure codes the cases in this file reached. */
const reached = new Set();

/** Every item is declared and carried unless a case says otherwise. */
const DELIVERED = {
  declares: () => true,
  carriesCiphertext: () => true,
  contentType: () => "text/html",
};

/**
 * A page with `body` markup and one map carrier holding `mapText`.
 *
 * @param {string} body
 * @param {string} mapText
 * @param {{ doctype?: string, bodyAttributes?: string, carrier?: string, carrierFirst?: boolean }} [shape]
 */
function page(body, mapText, shape = {}) {
  const doctype = shape.doctype ?? "<!DOCTYPE html>";
  const carrier =
    shape.carrier ??
    `<script type="application/json" class="dca-data">{"contentMap":${mapText}}</script>`;
  const content = shape.carrierFirst ? carrier + body : body + carrier;
  return `${doctype}<html><head><title>t</title></head><body${shape.bodyAttributes ?? ""}>${content}</body></html>`;
}

/**
 * The map text for rules over one `text/html` item called `a`.
 *
 * @param {object[]} rules
 */
function mapText(rules) {
  return JSON.stringify({ version: "1", rules });
}

/**
 * Run admission on one page. The key client refuses to be asked.
 *
 * @param {string} html
 * @param {{ delivery?: any, limits?: any }} [options]
 */
async function admit(html, options = {}) {
  let keyRequests = 0;
  const result = await runContentMap({
    tree: parseLockedDocument(html),
    delivery: options.delivery ?? DELIVERED,
    keyClient: () => {
      keyRequests += 1;
      throw new Error("a map failure must not reach key acquisition");
    },
    ...(options.limits === undefined ? {} : { limits: options.limits }),
  });
  return { result, keyRequests };
}

/**
 * Assert that the page fails admission with `code` and asks for no key.
 *
 * @param {string} html
 * @param {string} code
 * @param {string} why
 * @param {{ delivery?: any, limits?: any }} [options]
 */
async function fails(html, code, why, options) {
  let outcome;
  try {
    outcome = await admit(html, options);
  } catch (cause) {
    // Admission passed and the run reached the refusing key client.
    assert.fail(`${why}: admission passed (${/** @type {Error} */ (cause).message})`);
  }
  assert.deepEqual(outcome.result.report, { outcome: "failed", failure: code }, why);
  reached.add(code);
  assert.equal(outcome.result.reconstructed, false, why);
  assert.equal(outcome.keyRequests, 0, `${why}: no key was asked for`);
}

/**
 * Assert that admission passes: the run reaches the key client.
 *
 * @param {string} html
 * @param {string} why
 */
async function passes(html, why) {
  const { result, keyRequests } = await admit(html);
  assert.equal(keyRequests, 1, why);
  assert.equal(result.report.outcome, "failed");
  assert.equal(/** @type {any} */ (result.report).failure, "key_acquisition_failed");
}

const FILL_A = { item: "a", op: "fill", target: "#slot" };
const SLOT = '<div id="slot">teaser</div>';

describe("Section 3: the map carrier", () => {
  test("a page with no carrier in body is map_absent", async () => {
    await fails(page(SLOT, "", { carrier: "" }), "map_absent", "no carrier");
    const inHead = `<!DOCTYPE html><html><head><script type="application/json" class="dca-content-map">${mapText([FILL_A])}</script></head><body>${SLOT}</body></html>`;
    await fails(inHead, "map_malformed", "a separate carrier is refused even outside body");
  });

  test("carrier JSON that is not an object is map_malformed", async () => {
    for (const json of ["[]", "null", '"x"']) {
      const carrier = `<script type="application/json" class="dca-data">${json}</script>`;
      await fails(page(SLOT, "", { carrier }), "map_malformed", `carrier JSON ${json}`);
    }
  });

  test("two carriers, a non-script carrier, a wrong type and a shared token are map_malformed", async () => {
    const text = mapText([FILL_A]);
    const carrier = `<script type="application/json" class="dca-content-map">${text}</script>`;
    await fails(page(SLOT, text, { carrier: carrier + carrier }), "map_malformed", "two carriers");
    await fails(
      page(SLOT, text, { carrier: `<div class="dca-content-map">${text}</div>` }),
      "map_malformed",
      "a div carrier",
    );
    await fails(
      page(SLOT, text, {
        carrier: `<script type="application/json; charset=utf-8" class="dca-content-map">${text}</script>`,
      }),
      "map_malformed",
      "the type is not exactly application/json",
    );
    await fails(
      page(SLOT, text, {
        carrier: `<script type="application/json" class="dca-content-map dca-data">${text}</script>`,
      }),
      "map_malformed",
      "one element carrying the map and dca-data tokens",
    );
    await fails(
      page(SLOT, text, {
        carrier: `<script type="application/json" class="dca-sealed-content dca-content-map">${text}</script>`,
      }),
      "map_malformed",
      "one element carrying the map and dca-sealed-content tokens",
    );
  });

  test("a carrier found among other class tokens is read", async () => {
    await passes(
      page(SLOT, mapText([FILL_A]), {
        carrier: `<script type="application/json" class="x  dca-data y">{"contentMap":${mapText([FILL_A])}}</script>`,
      }),
      "the token set holds the reserved token",
    );
  });
});

describe("Section 4: the map object", () => {
  test("duplicate names follow the common JSON last-member policy", async () => {
    await passes(
      page(
        SLOT,
        '{"version":"2","version":"1","rules":[{"item":"a","op":"fill","target":"#wrong","target":"#slot"}]}',
      ),
      "last occurrence is used consistently",
    );
    await fails(page(SLOT, "{ invalid"), "map_malformed", "invalid JSON");
  });

  test("an unknown member in the map or rule and the removed items table is map_malformed", async () => {
    const cases = [
      JSON.stringify({ version: "1", rules: [FILL_A], extra: 1 }),
      JSON.stringify({ version: "1", items: { a: "text/html" }, rules: [FILL_A] }),
      JSON.stringify({ version: "1", rules: [{ ...FILL_A, x: 1 }] }),
    ];
    for (const text of cases) await fails(page(SLOT, text), "map_malformed", text);
  });

  test("version other than 1 is map_version_unsupported; a missing or mistyped member is map_malformed", async () => {
    await fails(
      page(SLOT, JSON.stringify({ version: "2", rules: [FILL_A] })),
      "map_version_unsupported",
      "version 2",
    );
    await fails(
      page(SLOT, JSON.stringify({ version: "2", future: true })),
      "map_version_unsupported",
      "a later grammar with its own members still answers by version",
    );
    const malformed = [
      { rules: [FILL_A] },
      { version: 1, rules: [FILL_A] },
      { version: "1" },
      { version: "1", rules: [] },
      { version: "1", rules: {} },
      { version: "1", rules: ["#slot"] },
      { version: "1", rules: [{ ...FILL_A, item: "1a" }] },
      { version: "1", rules: [{ op: "fill", target: "#slot" }] },
    ];
    for (const map of malformed) {
      await fails(page(SLOT, JSON.stringify(map)), "map_malformed", JSON.stringify(map));
    }
    await fails(page(SLOT, "[]"), "map_malformed", "an array, not a map object");
  });

  test("item types are admitted from authoritative contentData records", async () => {
    for (const type of [
      "text/html; charset=utf-8",
      "TEXT/HTML",
      "application/json",
      "text/xml",
      null,
      5,
    ]) {
      await fails(
        page(SLOT, mapText([FILL_A])),
        typeof type === "string" ? "map_type_unsupported" : "item_failed",
        `type ${type}`,
        {
          delivery: { ...DELIVERED, contentType: () => type },
        },
      );
    }
  });

  test("a rule's item, op and class are checked", async () => {
    const cases = [
      [{ item: "1b", op: "fill", target: "#slot" }, "an invalid content name"],
      [{ item: "a", op: "append", target: "#slot" }, "an op outside the three"],
      [{ item: "a", op: "fill", target: "#slot", class: "x" }, "a class on a fill"],
      [{ item: "a", op: "remove", target: "#slot", class: "x" }, "a class on a remove"],
      [{ item: "a", op: "removeClass", target: "#slot" }, "a removeClass with no class"],
      [{ item: "a", op: "removeClass", target: "#slot", class: "1x" }, "a class that is no ident"],
      [{ item: "a", op: "removeClass", target: "#slot", class: 7 }, "a class that is no string"],
      [{ item: "a", op: "fill", target: 7 }, "a target that is no string"],
    ];
    for (const [rule, why] of cases) {
      await fails(page(SLOT, mapText([FILL_A, rule])), "map_malformed", String(why));
    }
  });

  test("every item must be read by a fill rule (Section 4.2)", async () => {
    await fails(
      page(
        `${SLOT}<div id="gate" class="locked"></div>`,
        mapText([FILL_A, { item: "g", op: "removeClass", target: "#gate", class: "locked" }]),
      ),
      "map_malformed",
      "an item used only as a gate",
    );
  });

  test("a map item contentData does not declare, or whose ciphertext is missing, fails", async () => {
    const html = page(SLOT, mapText([FILL_A]));
    await fails(html, "map_item_undeclared", "undeclared", {
      delivery: {
        contentType: () => "text/html",
        declares: () => false,
        carriesCiphertext: () => true,
      },
    });
    await fails(html, "map_item_no_ciphertext", "no ciphertext", {
      delivery: {
        contentType: () => "text/html",
        declares: () => true,
        carriesCiphertext: () => false,
      },
    });
    // The delivery view counts only canonical base64url as carried ciphertext.
    for (const ciphertext of [null, "!"]) {
      await fails(html, "map_item_no_ciphertext", `extracted ${ciphertext}`, {
        delivery: mapDeliveryOf({
          dcaData: {
            contentNames: () => ["a"],
            contentDataFor: () => ({ contentType: "text/html" }),
          },
          reader: { extract: () => ciphertext },
        }),
      });
    }
  });
});

describe("Section 5.1: the selector grammar", () => {
  const LIMITS = { maxLength: 256, maxCompounds: 8 };

  test("the grammar's forms parse into compounds and combinators", () => {
    assert.deepEqual(parseSelector("#main .bodytext", LIMITS).compounds, [
      { type: null, qualifiers: [{ kind: "id", name: "main" }] },
      { type: null, qualifiers: [{ kind: "class", name: "bodytext" }] },
    ]);
    const child = parseSelector('section.main>div[data-slot="x y"]', LIMITS);
    assert.deepEqual(child.combinators, ["child"]);
    assert.deepEqual(child.compounds[1], {
      type: "div",
      qualifiers: [{ kind: "attribute", name: "data-slot", value: "x y" }],
    });
    for (const text of [
      "div",
      "h1",
      "x-widget",
      "#-a",
      "._b",
      "[slot]",
      '[itemprop="articleBody"]',
      "[role]",
      "[data-a-1]",
      "a  b",
      "a > b",
      "a >b",
      "a> b",
      "#a#b.c.d",
      '[data-x="<\'>!"]',
    ]) {
      assert.doesNotThrow(() => parseSelector(text, LIMITS), text);
    }
  });

  test("everything outside the grammar is map_selector_unsupported", () => {
    for (const text of [
      "",
      " a",
      "a ",
      "a >",
      "> a",
      "a, b",
      "*",
      "a:first-child",
      "a::before",
      "svg|a",
      "a + b",
      "a ~ b",
      '[data-x^="y"]',
      '[data-x="y" i]',
      "[href]",
      "[class]",
      '[id="x"]',
      "[data-X]",
      "[data-]",
      "Div",
      "#1a",
      "#--a",
      ".a\\:b",
      "#café",
      "[data-x='y']",
      '[data-x="a\\"b"]',
      "a\tb",
      "a\nb",
      "a>>b",
    ]) {
      assert.throws(
        () => parseSelector(text, LIMITS),
        (/** @type {any} */ e) => e.code === "map_selector_unsupported",
        JSON.stringify(text),
      );
    }
  });

  test("a map with an unsupported target fails before any key", async () => {
    await fails(
      page(SLOT, mapText([{ item: "a", op: "fill", target: "#slot, #other" }])),
      "map_selector_unsupported",
      "a selector list",
    );
  });
});

describe("Section 5.2: the locked document", () => {
  test("a document in quirks mode is map_document_quirks; limited-quirks is admitted", async () => {
    await fails(
      page(SLOT, mapText([FILL_A]), { doctype: "" }),
      "map_document_quirks",
      "no doctype",
    );
    await passes(
      page(SLOT, mapText([FILL_A]), {
        doctype:
          '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">',
      }),
      "a limited-quirks doctype",
    );
    assert.equal(
      parseLockedDocument(
        '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "x"><p>',
      ).mode(),
      "limited-quirks",
    );
  });

  test("the parser runs with scripting on: noscript content is text, not a target", async () => {
    await fails(
      page(`<noscript><div id="slot">x</div></noscript>`, mapText([FILL_A])),
      "map_target_count",
      "an element spelled inside noscript is not in the tree",
    );
  });
});

describe("Section 5.3: matching", () => {
  test("zero or several matches are map_target_count; template contents do not count", async () => {
    await fails(page("<div></div>", mapText([FILL_A])), "map_target_count", "zero matches");
    await fails(
      page(`${SLOT}<p id="slot"></p>`, mapText([FILL_A])),
      "map_target_count",
      "two elements with one id",
    );
    await passes(
      page(`${SLOT}<template><div id="slot"></div></template>`, mapText([FILL_A])),
      "a template's contents are not in the document tree",
    );
    await fails(
      page(
        `<section id="main"><div class="bodytext"><div class="bodytext intro"></div><div class="bodytext content-text"></div></div></section>`,
        mapText([{ item: "a", op: "fill", target: "#main .bodytext" }]),
      ),
      "map_target_count",
      "the Section 12.4 nested template",
    );
  });

  test("id and class compare case-sensitively; child and descendant combinators differ", async () => {
    await fails(page('<div id="Slot"></div>', mapText([FILL_A])), "map_target_count", "id case");
    await passes(
      page(
        '<div class="A a"><p class="b"></p></div>',
        mapText([{ item: "a", op: "fill", target: ".a > .b" }]),
      ),
      "a child combinator",
    );
    await fails(
      page(
        '<div class="a"><span><p class="b"></p></span></div>',
        mapText([{ item: "a", op: "fill", target: ".a > .b" }]),
      ),
      "map_target_count",
      "a grandchild is no child",
    );
    await passes(
      page(
        '<div class="a"><span><p class="b"></p></span></div>',
        mapText([{ item: "a", op: "fill", target: ".a .b" }]),
      ),
      "a grandchild is a descendant",
    );
    await passes(
      page(
        '<div data-slot="x"></div><div data-slot="y"></div>',
        mapText([{ item: "a", op: "fill", target: '[data-slot="x"]' }]),
      ),
      "an exact attribute value",
    );
  });

  test("overlapping tree changes are map_target_overlap", async () => {
    const nested = '<div id="outer"><div id="inner"></div></div><div id="slot"></div>';
    const cases = [
      [[FILL_A, { item: "a", op: "fill", target: "#slot" }], "the same element filled twice"],
      [[FILL_A, { item: "a", op: "remove", target: "#slot" }], "one element filled and removed"],
      [
        [
          { item: "a", op: "fill", target: "#outer" },
          { item: "a", op: "fill", target: "#inner" },
        ],
        "a fill target is an ancestor of another",
      ],
      [
        [
          { item: "a", op: "fill", target: "#inner" },
          { item: "a", op: "remove", target: "#outer" },
        ],
        "a remove target is an ancestor of a fill target",
      ],
    ];
    for (const [rules, why] of cases) {
      await fails(
        page(nested, mapText(/** @type {object[]} */ (rules))),
        "map_target_overlap",
        String(why),
      );
    }
  });

  test("class changes land on surviving elements only, once per element and token", async () => {
    const body =
      '<div id="outer" class="k"><div id="inner" class="k"></div></div><div id="slot" class="k"></div>';
    const cases = [
      [
        [
          { item: "a", op: "fill", target: "#outer" },
          { item: "a", op: "removeClass", target: "#inner", class: "k" },
        ],
        "inside a fill",
      ],
      [
        [
          FILL_A,
          { item: "a", op: "remove", target: "#outer" },
          { item: "a", op: "removeClass", target: "#outer", class: "k" },
        ],
        "on a removed element",
      ],
      [
        [
          FILL_A,
          { item: "a", op: "remove", target: "#outer" },
          { item: "a", op: "removeClass", target: "#inner", class: "k" },
        ],
        "inside a removed element",
      ],
      [
        [
          FILL_A,
          { item: "a", op: "removeClass", target: "#slot", class: "k" },
          { item: "a", op: "removeClass", target: "div#slot", class: "k" },
        ],
        "one element and token twice",
      ],
    ];
    for (const [rules, why] of cases) {
      await fails(
        page(body, mapText(/** @type {object[]} */ (rules))),
        "map_target_overlap",
        String(why),
      );
    }
    await passes(
      page(
        body,
        mapText([
          { item: "a", op: "fill", target: "#inner" },
          { item: "a", op: "removeClass", target: "#inner", class: "k" },
          { item: "a", op: "removeClass", target: "#outer", class: "k" },
        ]),
      ),
      "a removeClass on a fill target and on its ancestor",
    );
  });

  test("targets outside the placeable set are map_target_unplaceable", async () => {
    /** @type {[string, object, string][]} */
    const cases = [
      ['<svg><g id="slot"></g></svg>', FILL_A, "an SVG element"],
      [
        '<select><option id="slot"></option></select>',
        { item: "a", op: "remove", target: "#slot" },
        "inside select",
      ],
      [
        '<datalist><option id="slot"></option></datalist>',
        { item: "a", op: "remove", target: "#slot" },
        "inside datalist",
      ],
      ["", { item: "a", op: "fill", target: "body" }, "fill body"],
      ["", { item: "a", op: "fill", target: "html" }, "fill html"],
      ["", { item: "a", op: "fill", target: "head" }, "fill head"],
      ['<img id="slot">', FILL_A, "a void element"],
      ['<br id="slot">', FILL_A, "br"],
      ['<template id="slot"></template>', FILL_A, "template"],
      ['<textarea id="slot"></textarea>', FILL_A, "textarea"],
      ['<xmp id="slot"></xmp>', FILL_A, "xmp"],
      ['<iframe id="slot"></iframe>', FILL_A, "iframe"],
      ['<noembed id="slot"></noembed>', FILL_A, "noembed"],
      ['<noframes id="slot"></noframes>', FILL_A, "noframes"],
      ['<noscript id="slot"></noscript>', FILL_A, "noscript"],
      ['<style id="slot"></style>', FILL_A, "style"],
      ['<table id="slot"><tbody><tr><td></td></tr></tbody></table>', FILL_A, "table"],
      ['<table><tbody id="slot"><tr><td></td></tr></tbody></table>', FILL_A, "tbody"],
      ['<table><tbody><tr id="slot"><td></td></tr></tbody></table>', FILL_A, "tr"],
      ['<table><colgroup id="slot"></colgroup></table>', FILL_A, "colgroup"],
      ['<select id="slot"></select>', FILL_A, "select"],
      ['<datalist id="slot"></datalist>', FILL_A, "datalist"],
      ['<plaintext id="slot">', FILL_A, "plaintext"],
    ];
    for (const [body, rule, why] of cases) {
      // A remove needs some fill rule for its item, placed on a plain slot.
      const rules =
        /** @type {any} */ (rule).op === "fill" ? [rule] : [{ ...FILL_A, target: "#fillme" }, rule];
      await fails(
        // Everything after a plaintext start tag is text, so its carrier goes first.
        page(`<div id="fillme"></div>${body}`, mapText(rules), {
          carrierFirst: why === "plaintext",
        }),
        "map_target_unplaceable",
        why,
      );
    }
    await passes(
      page(
        `${SLOT}<table><tbody><tr><td id="cell"></td></tr></tbody></table>`,
        mapText([{ item: "a", op: "fill", target: "#cell" }]),
      ),
      "a table cell is placeable",
    );
    await passes(
      page(
        SLOT,
        mapText([FILL_A, { item: "a", op: "removeClass", target: "html", class: "k" }]),
      ).replace("<html>", '<html class="k">'),
      "a removeClass on html",
    );
  });

  test("a fill or remove that is or contains a carrier is map_target_carrier", async () => {
    const wrapped = `<div id="wrap">${SLOT}<script type="application/json" class="dca-sealed-content">{}</script></div>`;
    await fails(
      page(wrapped, mapText([FILL_A, { item: "a", op: "remove", target: "#wrap" }])),
      "map_target_carrier",
      "a remove that contains dca-data",
    );
    await fails(
      page(
        `${SLOT}<div id="c" class="dca-sealed-content"></div>`,
        mapText([FILL_A, { item: "a", op: "remove", target: "#c" }]),
      ),
      "map_target_carrier",
      "a remove of an element carrying a carrier token",
    );
    await fails(
      page(SLOT, mapText([FILL_A, { item: "a", op: "remove", target: ".dca-data" }])),
      "map_target_carrier",
      "a remove of the map carrier itself",
    );
    await passes(
      page(SLOT, mapText([FILL_A, { item: "a", op: "removeClass", target: "body", class: "k" }]), {
        bodyAttributes: ' class="k"',
      }),
      "a removeClass on body, which contains the carriers",
    );
  });

  test("a removeClass token absent from its target is map_class_absent", async () => {
    await fails(
      page(SLOT, mapText([FILL_A, { item: "a", op: "removeClass", target: "#slot", class: "k" }])),
      "map_class_absent",
      "no class attribute",
    );
    await fails(
      page(
        '<div id="slot" class="K kk"></div>',
        mapText([FILL_A, { item: "a", op: "removeClass", target: "#slot", class: "k" }]),
      ),
      "map_class_absent",
      "tokens compare exactly",
    );
  });
});

describe("Section 5.4: limits", () => {
  test("each limit is enforced as map_limit before any key", async () => {
    const html = page(
      `${SLOT}<div id="b" class="x"></div>`,
      mapText([FILL_A, { item: "a", op: "removeClass", target: "div#b.x", class: "x" }]),
    );
    await fails(html, "map_limit", "map octets", { limits: { mapOctets: 20 } });
    await fails(html, "map_limit", "rule count", { limits: { rules: 1 } });
    await fails(html, "map_limit", "selector length", { limits: { selectorLength: 4 } });
    await fails(
      page(SLOT, mapText([{ item: "a", op: "fill", target: "html body #slot" }])),
      "map_limit",
      "selector compounds",
      { limits: { selectorCompounds: 2 } },
    );
    await fails(html, "map_limit", "document octets", { limits: { documentOctets: 100 } });
    await passes(html, "the default limits admit an ordinary page");
  });

  test("every Section 9 code this core owns was reached by a case above", () => {
    // source_refused and delivery_refused come from the entries that run
    // Section 6.1 steps 1 and 2 before this core; gateway.test.js reaches both.
    assert.deepEqual(
      [...reached].sort(),
      MAP_FAILURES.filter(
        (code) =>
          ![
            "source_refused",
            "delivery_refused",
            "map_target_stale",
            "map_placement_refused",
            "map_output_unstable",
            "key_acquisition_failed",
          ].includes(code),
      ).sort(),
    );
    assert.ok(MAP_FAILURES.includes("delivery_refused"), "Section 9 names delivery_refused");
  });
});
