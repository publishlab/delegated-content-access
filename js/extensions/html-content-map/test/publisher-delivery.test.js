// @ts-check
//
// Publisher admission for the proposed HTML content map,
// docs/spec-proposal--html-content-map.md Sections 3 to 5 and 7.1, through
// `writeMappedDelivery` with the real publisher. A valid page comes back as
// markup that the server-side client (`createHtmlGateway`) and, where Chromium
// is installed, the browser client (`reconstructBrowserPage`) admit and
// reconstruct. Each invalid case breaks one rule, and the helper refuses it
// with that rule's code before any markup comes back.
//
// Publisher admission does not replace client admission: a client still admits
// the page it is served, with its own limits.

import test, { after, before, describe } from "node:test";
import assert from "node:assert/strict";

import { writeMappedDelivery } from "../adapter-publisher/writeMappedDelivery.js";
import { createHtmlGateway } from "../integration-client/createHtmlGateway.js";
import { writeMarkupDelivery } from "../../../adapter-publisher/writeMarkupDelivery.js";
import { openOracle, oracleBrowserPath } from "./chromium.js";
import {
  ARTICLE_MAP,
  BODYTEXT,
  FACTBOX,
  ISSUER_NAME,
  ORIGIN,
  articlePage,
  mapWorld,
  nestedTemplatePage,
} from "./world.js";

const ARTICLE_ITEMS = [
  { name: "bodytext", value: BODYTEXT, contentType: "text/html" },
  { name: "factbox", value: FACTBOX, contentType: "text/html" },
];

/** The author-time text of each Section 12.3 item. */
const ARTICLE_TEXT = { bodytext: BODYTEXT, factbox: FACTBOX };

/**
 * One render of the Section 12.3 items from a world's publisher, without a
 * page: the values a host hands to `writeMappedDelivery`.
 *
 * @param {any} world
 * @param {{ name: string, value: string, contentType: string }[]} [items]
 */
async function render(world, items = ARTICLE_ITEMS) {
  const { dcaData, sealedContent } = await world.publish({ items, page: () => "" });
  return { dcaData, sealedContent };
}

/**
 * The server-side client's result for a page served at `ORIGIN/page`.
 *
 * @param {any} world
 * @param {string} html
 */
async function serverRun(world, html) {
  const gateway = createHtmlGateway({
    issuerEndpoint: "https://issuer.example/unlock",
    admitCaller: () => true,
    sources: [{ origin: ORIGIN }],
    registrations: [{ id: "pub", keys: { [world.signingKid]: world.signingPublicKey } }],
    fetch: async () => ({
      status: 200,
      headers: { get: (name) => (name === "content-type" ? "text/html; charset=utf-8" : null) },
      body: new globalThis.Response(html).body,
    }),
    issuerName: ISSUER_NAME,
    transport: world.transport,
  });
  return gateway.reconstruct({ url: `${ORIGIN}/page`, callerContext: "reader" });
}

/**
 * Assert that the helper refuses with `code` and returns no markup.
 *
 * @param {() => string} write
 * @param {string} code
 */
function assertRefused(write, code) {
  /** @type {string|null} */
  let markup = null;
  assert.throws(
    () => {
      markup = write();
    },
    (/** @type {any} */ e) => {
      assert.equal(e.code, code, e.message);
      return true;
    },
  );
  assert.equal(markup, null, "no markup came back");
}

const COMPLETE = { outcome: "complete", items: { bodytext: "opened", factbox: "opened" } };

describe("a valid authored page", () => {
  /** @type {any} */
  let world;
  /** @type {string} */
  let html;
  /** @type {{ dcaData: any, sealedContent: Record<string, string> }} */
  let values;

  before(async () => {
    world = await mapWorld();
    values = await render(world);
    html = writeMappedDelivery({
      ...values,
      contentMap: ARTICLE_MAP,
      page: articlePage,
      items: ARTICLE_TEXT,
    });
  });

  test("comes back in the carrier shape the clients read: contentMap inside dca-data", () => {
    const carriers = writeMarkupDelivery({
      ...values,
      dcaData: { ...values.dcaData, contentMap: ARTICLE_MAP },
    });
    assert.equal(html, articlePage(carriers));
  });

  test("passes the server-side client's admission and reconstructs complete", async () => {
    const before = world.unlocks.length;
    const result = await serverRun(world, html);
    assert.deepEqual(result.report, COMPLETE);
    assert.ok(result.html?.includes(FACTBOX), "the factbox is placed");
    assert.equal(world.unlocks.length, before + 1, "one unlock request for the map items");
  });

  describe("in Chromium", { skip: oracleBrowserPath() === null ? "no Chromium" : false }, () => {
    /** @type {Awaited<ReturnType<typeof openOracle>>} */
    let oracle;
    before(async () => {
      oracle = await openOracle({
        transport: {
          /** @param {string} url @param {object} request */
          post: (url, request) => world.transport.post(url, request),
        },
      });
    });
    after(async () => {
      await oracle?.close();
    });

    test("passes the browser client's admission and reconstructs complete", async () => {
      const browser = await oracle.runBrowserClient(html);
      assert.equal(browser.error, null);
      assert.deepEqual(browser.report, COMPLETE);
      assert.equal(browser.reconstructed, true);
    });
  });
});

describe("a page the helper refuses before markup returns", () => {
  /** @type {any} */
  let world;
  /** @type {{ dcaData: any, sealedContent: Record<string, string> }} */
  let values;

  before(async () => {
    world = await mapWorld();
    values = await render(world);
  });

  test("Section 4.1: a map with a member the grammar does not define is map_malformed", () => {
    assertRefused(
      () =>
        writeMappedDelivery({
          ...values,
          contentMap: { ...ARTICLE_MAP, priority: "high" },
          page: articlePage,
        }),
      "map_malformed",
    );
  });

  test("Section 4.2: a map item contentData does not declare is map_item_undeclared", () => {
    assertRefused(
      () =>
        writeMappedDelivery({
          ...values,
          contentMap: {
            version: "1",
            rules: [{ item: "sidebar", op: "fill", target: "#factbox-aside" }],
          },
          page: articlePage,
        }),
      "map_item_undeclared",
    );
  });

  test("Section 4.2: a declared map item the delivery carries no ciphertext for is map_item_no_ciphertext", () => {
    const { bodytext: _left, ...factboxOnly } = values.sealedContent;
    assertRefused(
      () =>
        writeMappedDelivery({
          dcaData: values.dcaData,
          sealedContent: factboxOnly,
          contentMap: ARTICLE_MAP,
          page: articlePage,
        }),
      "map_item_no_ciphertext",
    );
  });

  test("Section 5.3: a target matching three elements is map_target_count", () => {
    assertRefused(
      () => writeMappedDelivery({ ...values, contentMap: ARTICLE_MAP, page: nestedTemplatePage }),
      "map_target_count",
    );
  });

  test("Section 5.3: a fill into the title element is map_target_unplaceable", () => {
    assertRefused(
      () =>
        writeMappedDelivery({
          ...values,
          contentMap: {
            version: "1",
            rules: [{ item: "factbox", op: "fill", target: "title" }],
          },
          page: articlePage,
        }),
      "map_target_unplaceable",
    );
  });

  test("Section 5.3: a fill of an element that holds another fill target is map_target_overlap", () => {
    assertRefused(
      () =>
        writeMappedDelivery({
          ...values,
          contentMap: {
            version: "1",
            rules: [
              { item: "bodytext", op: "fill", target: "#main" },
              { item: "factbox", op: "fill", target: "#factbox-inline" },
            ],
          },
          page: articlePage,
        }),
      "map_target_overlap",
    );
  });

  test("Section 5.2: a page without a doctype is in quirks mode and map_document_quirks", () => {
    assertRefused(
      () =>
        writeMappedDelivery({
          ...values,
          contentMap: ARTICLE_MAP,
          page: (carriers) => articlePage(carriers).replace("<!DOCTYPE html>", ""),
        }),
      "map_document_quirks",
    );
  });

  test("Section 5.4: a map over the host's rule limit is map_limit", () => {
    assertRefused(
      () =>
        writeMappedDelivery({
          ...values,
          contentMap: ARTICLE_MAP,
          page: articlePage,
          limits: { rules: ARTICLE_MAP.rules.length - 1 },
        }),
      "map_limit",
    );
  });

  test("a page template that leaves out the carriers it was handed is refused", () => {
    assertRefused(
      () =>
        writeMappedDelivery({
          ...values,
          contentMap: ARTICLE_MAP,
          page: () => articlePage(""),
        }),
      "bad_config",
    );
  });
});

describe("Section 7.1: the delivered form of a text/html item", () => {
  /** @type {any} */
  let world;
  /** @type {{ dcaData: any, sealedContent: Record<string, string> }} */
  let values;

  const BLOCK = "<div>x</div>";
  const LEAD_MAP = {
    version: "1",
    rules: [{ item: "lead", op: "fill", target: "#lead" }],
  };
  const leadPage = (/** @type {string} */ carriers) =>
    `<!DOCTYPE html><html><head><title>t</title></head><body><p id="lead">teaser</p>${carriers}</body></html>`;

  before(async () => {
    world = await mapWorld();
    values = await render(world, [{ name: "lead", value: BLOCK, contentType: "text/html" }]);
  });

  test("with the item text, a block div filled into a p is refused: the delivered page parses it out of the p", () => {
    assertRefused(
      () =>
        writeMappedDelivery({
          ...values,
          contentMap: LEAD_MAP,
          page: leadPage,
          items: { lead: BLOCK },
        }),
      "map_item_delivered_form",
    );
  });

  test("the same fragment in a div target passes", () => {
    const html = writeMappedDelivery({
      ...values,
      contentMap: LEAD_MAP,
      page: (carriers) =>
        leadPage(carriers).replace('<p id="lead">teaser</p>', '<div id="lead">teaser</div>'),
      items: { lead: BLOCK },
    });
    assert.match(html, /<div id="lead">teaser<\/div>/);
  });

  test("a text/html map without the item text is refused, naming the item that needs it", () => {
    assertRefused(
      () => writeMappedDelivery({ ...values, contentMap: LEAD_MAP, page: leadPage }),
      "bad_config",
    );
    assert.throws(
      () => writeMappedDelivery({ ...values, contentMap: LEAD_MAP, page: leadPage }),
      /lead/,
    );
  });

  test("no client refuses the case: a hand-built page with the div in the p reconstructs complete", async () => {
    // A client holds no author-time text before key work and does not check
    // the delivered form, so the publisher entry is the only place this duty is
    // checked. The server-side client places the div and serializes a page
    // whose delivered form has an empty p, the div and another empty p.
    const carriers = writeMarkupDelivery({
      ...values,
      dcaData: { ...values.dcaData, contentMap: LEAD_MAP },
    });
    const result = await serverRun(world, leadPage(carriers));
    assert.deepEqual(result.report, { outcome: "complete", items: { lead: "opened" } });
    assert.match(/** @type {string} */ (result.html), /<p id="lead"><div>x<\/div><\/p>/);
  });

  test("text/plain needs author-time text and places markup as literal text", async () => {
    const plain = await render(world, [{ name: "lead", value: BLOCK, contentType: "text/plain" }]);
    assertRefused(
      () => writeMappedDelivery({ ...plain, contentMap: LEAD_MAP, page: leadPage }),
      "bad_config",
    );
    const html = writeMappedDelivery({
      ...plain,
      contentMap: LEAD_MAP,
      page: leadPage,
      items: { lead: BLOCK },
    });
    assert.match(html, /<p id="lead">teaser<\/p>/);
  });

  test("empty text/plain passes publisher admission and reconstructs an empty target", async () => {
    const plain = await render(world, [{ name: "lead", value: "", contentType: "text/plain" }]);
    const html = writeMappedDelivery({
      ...plain,
      contentMap: LEAD_MAP,
      page: leadPage,
      items: { lead: "" },
    });
    const result = await serverRun(world, html);
    assert.deepEqual(result.report, { outcome: "complete", items: { lead: "opened" } });
    assert.match(/** @type {string} */ (result.html), /<p id="lead"><\/p>/);
  });

  test("text/plain carriage return and NUL cannot change through delivered serialization", async () => {
    for (const value of ["a\rb", "a\u0000b"]) {
      const plain = await render(world, [{ name: "lead", value, contentType: "text/plain" }]);
      assertRefused(
        () =>
          writeMappedDelivery({
            ...plain,
            contentMap: LEAD_MAP,
            page: leadPage,
            items: { lead: value },
          }),
        "map_item_delivered_form",
      );
    }
  });

  test("the item text names every text/html map item and nothing else", () => {
    for (const items of [{}, { lead: BLOCK, other: BLOCK }, { lead: 7 }]) {
      assertRefused(
        () =>
          writeMappedDelivery({
            ...values,
            contentMap: LEAD_MAP,
            page: leadPage,
            items: /** @type {any} */ (items),
          }),
        "bad_config",
      );
    }
  });
});

describe("the authoritative item-record contentType", () => {
  test("mixed contentData types control fills and publisher input remains unchanged", async () => {
    const world = await mapWorld();
    const values = await render(world, [
      { name: "bodytext", value: BODYTEXT, contentType: "text/plain" },
      { name: "factbox", value: FACTBOX, contentType: "text/html" },
    ]);
    values.dcaData.contentData.bodytext.contentDescription = {
      version: "1",
      description: "Article",
    };
    const snapshot = JSON.stringify(values);
    const html = writeMappedDelivery({
      ...values,
      contentMap: ARTICLE_MAP,
      page: articlePage,
      items: ARTICLE_TEXT,
    });
    assert.equal(JSON.stringify(values), snapshot);
    assert.ok(html.includes('"contentDescription":{"version":"1","description":"Article"}'));
    assert.ok(!html.includes('class="dca-content-map"'));
  });
});
