// @ts-check
//
// The browser oracle of docs/spec-proposal--html-content-map.md Section 12.2, run in
// headless Chromium. Each case takes one locked delivery from the real
// publisher and compares three results of it:
//
// - the browser client (`reconstructBrowserPage`), running in Chromium on the
//   locked page served with `Content-Security-Policy: script-src 'none'`;
// - the server-side client (`createHtmlGateway`), running in Node with parse5;
// - the oracle harness, which applies the same rules with
//   `querySelectorAll`, the `innerHTML` and `textContent` setters,
//   `classList.remove` and `remove()` and uses none of this extension's code.
//
// What each case compares: the canonical tree of each result's delivered form
// (the tree Chromium builds when it loads the serialization as a page under
// the same policy), the Section 6.4 report of both clients against the report
// the fixture's grant implies, and each rule's target path. Equal canonical
// trees cover observations 3 to 6 of Section 7.2 at once, because the
// canonical tree records every node's kind, name, namespace, sorted
// attributes and data.
//
// The suite skips when no Chromium executable is installed. It does not prove
// script execution, off-origin reconstruction or another engine's parser.

import test, { after, before, describe } from "node:test";
import assert from "node:assert/strict";

import { createHtmlGateway } from "../integration-client/createHtmlGateway.js";
import { openOracle, oracleBrowserPath } from "./chromium.js";
import {
  ARTICLE_MAP,
  BODYTEXT,
  FACTBOX,
  ISSUER_NAME,
  ORIGIN,
  bylinePage,
  mapWorld,
  nestedTemplatePage,
} from "./world.js";

const BROWSER = oracleBrowserPath();
const SKIP =
  BROWSER === null
    ? "no Chromium executable: set DCA_ORACLE_BROWSER or install chrome-headless-shell in the puppeteer cache"
    : false;

/**
 * The server-side result for one locked page, fetched from `ORIGIN/page`.
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
  return gateway.reconstruct({ url: `${ORIGIN}/page`, callerContext: "oracle" });
}

/** @param {any[]} targets */
const pathsOf = (targets) => targets.map((/** @type {any} */ target) => target.path);

describe(
  "Section 12.2: browser client, server-side client and oracle agree",
  { skip: SKIP },
  () => {
    /** @type {Awaited<ReturnType<typeof openOracle>>} */
    let oracle;
    /** @type {any} */
    let world;

    before(async () => {
      world = await mapWorld();
      const transport = {
        /** @param {string} url @param {object} request */
        post: (url, request) => world.transport.post(url, request),
      };
      oracle = await openOracle({ transport });
      // Evidence records the oracle browser and version (Section 12.2).
      process.stdout.write(`# oracle browser: ${oracle.version} at ${BROWSER}\n`);
    });

    after(async () => {
      await oracle?.close();
    });

    /**
     * Run all three on one page and assert equal delivered forms and paths.
     *
     * @param {string} html
     * @param {any} map
     * @param {Record<string, string>} opened - what the fixture grant opens
     */
    async function agree(html, map, opened) {
      const browser = await oracle.runBrowserClient(html);
      const server = await serverRun(world, html);
      const harness = await oracle.applyOracle(html, map, opened);
      assert.equal(browser.error, null);

      const items = Object.fromEntries(
        Array.from(new Set(map.rules.map((/** @type {any} */ rule) => rule.item))).map((name) => [
          name,
          Object.hasOwn(opened, name) ? "opened" : "locked",
        ]),
      );
      const outcome = Object.values(items).every((state) => state === "opened")
        ? "complete"
        : "partial";
      assert.deepEqual(browser.report, { outcome, items }, "browser report");
      assert.deepEqual(server.report, { outcome, items }, "server report");

      assert.deepEqual(
        harness.counts,
        map.rules.map(() => 1),
        "every selector matches once in Chromium",
      );
      assert.deepEqual(pathsOf(browser.targets), harness.paths, "browser target paths");
      assert.deepEqual(pathsOf(server.targets), harness.paths, "server target paths");

      const oracleForm = await oracle.deliveredForm(harness.serialized);
      assert.deepEqual(
        await oracle.deliveredForm(browser.serialized),
        oracleForm,
        "browser delivered form",
      );
      assert.deepEqual(
        await oracle.deliveredForm(/** @type {string} */ (server.html)),
        oracleForm,
        "server delivered form",
      );
      return { browser, server, harness, oracleForm };
    }

    test("the harness page runs no script and parses with the scripting flag set", async () => {
      assert.deepEqual(await oracle.policyProbe(), {
        scriptRan: false,
        compatMode: "CSS1Compat",
        noscriptChildren: 0,
      });
    });

    test("Section 12.3, both items granted: complete, and the live page equals its delivered form", async () => {
      world.grant.contentNames = "all";
      const { html } = await world.article();
      const { browser, oracleForm } = await agree(html, ARTICLE_MAP, {
        bodytext: BODYTEXT,
        factbox: FACTBOX,
      });
      // The publisher met the Section 7.1 duty, so the browser's live tree is
      // already the delivered form.
      assert.deepEqual(browser.live, oracleForm);
    });

    test("Section 12.3, only factbox granted: partial, with bodytext locked", async () => {
      world.grant.contentNames = ["factbox"];
      try {
        const { html } = await world.article();
        await agree(html, ARTICLE_MAP, { factbox: FACTBOX });
      } finally {
        world.grant.contentNames = "all";
      }
    });

    test("an explicit browser rule limit refuses admission before any unlock", async () => {
      const { html } = await world.article();
      const before = world.unlocks.length;
      const browser = await oracle.runBrowserClient(html, { limits: { rules: 1 } });
      assert.equal(browser.error, null);
      assert.deepEqual(browser.report, { outcome: "failed", failure: "map_limit" });
      assert.equal(browser.reconstructed, false);
      assert.equal(world.unlocks.length, before);
    });

    test("text/plain fill keeps markup characters as text; a carriage return becomes a line feed in the delivered form", async () => {
      const byline = "By <b>Kari</b> & Ola\r\nOslo";
      const map = {
        version: "1",
        rules: [{ item: "byline", op: "fill", target: "#byline" }],
      };
      const { html } = await world.publish({
        items: [{ name: "byline", value: byline, contentType: "text/plain" }],
        contentMap: map,
        page: bylinePage,
      });
      const { browser, oracleForm } = await agree(html, map, { byline });
      // The live DOM keeps the carriage return; the delivered form does not.
      assert.notDeepEqual(browser.live, oracleForm);
      assert.match(JSON.stringify(oracleForm), /By <b>Kari<\/b> & Ola\\nOslo/);
    });

    test("fill parses text/html in the target's context: list items, a nested table, noscript, template and misnested tags", async () => {
      const values = {
        list: "<li>a<li>b",
        cell: "<table><tr><td>inner</table>after",
        notes: "<noscript><p>shown without script</noscript><template><b>t</b></template><p>n</p>",
        lead: "<b>x<i>y</b>z</i>",
      };
      const map = {
        version: "1",
        rules: [
          { item: "list", op: "fill", target: "#list" },
          { item: "cell", op: "fill", target: "#cell" },
          { item: "notes", op: "fill", target: "#notes" },
          { item: "lead", op: "fill", target: "#lead" },
        ],
      };
      const { html } = await world.publish({
        items: Object.entries(values).map(([name, value]) => ({
          name,
          value,
          contentType: "text/html",
        })),
        contentMap: map,
        page: (/** @type {string} */ carriers) =>
          `<!DOCTYPE html><html><head><title>t</title></head><body><ul id="list"><li>teaser</li></ul><table><tbody><tr><td id="cell">teaser</td></tr></tbody></table><div id="notes"></div><p id="lead">teaser</p>${carriers}</body></html>`,
      });
      const { browser, oracleForm } = await agree(html, map, values);
      assert.deepEqual(browser.live, oracleForm);
    });

    test("a block fragment in a p breaks the Section 7.1 duty: the live tree differs, the delivered forms agree", async () => {
      const block = "<div>x</div>";
      const map = {
        version: "1",
        rules: [{ item: "block", op: "fill", target: "#lead" }],
      };
      const { html } = await world.publish({
        items: [{ name: "block", value: block, contentType: "text/html" }],
        contentMap: map,
        page: (/** @type {string} */ carriers) =>
          `<!DOCTYPE html><html><head><title>t</title></head><body><p id="lead">teaser</p>${carriers}</body></html>`,
      });
      const { browser, oracleForm } = await agree(html, map, { block });
      assert.notDeepEqual(browser.live, oracleForm, "the live p holds the div");
    });

    test("Section 12.4: Chromium matches three elements, and both clients refuse with no unlock", async () => {
      const { html } = await world.publish({
        items: [
          { name: "bodytext", value: BODYTEXT, contentType: "text/html" },
          { name: "factbox", value: FACTBOX, contentType: "text/html" },
        ],
        contentMap: ARTICLE_MAP,
        page: nestedTemplatePage,
      });
      const before = world.unlocks.length;
      const harness = await oracle.applyOracle(html, ARTICLE_MAP, {});
      assert.equal(harness.counts[0], 3);
      const browser = await oracle.runBrowserClient(html);
      const server = await serverRun(world, html);
      const failed = { outcome: "failed", failure: "map_target_count" };
      assert.deepEqual(browser.report, failed);
      assert.deepEqual(server.report, failed);
      assert.equal(browser.reconstructed, false);
      assert.equal(server.html, null);
      assert.equal(world.unlocks.length, before);
    });
  },
);

test(
  "real custom-element callbacks cannot silently change surrounding content",
  { skip: SKIP },
  async () => {
    const oracle = await openOracle();
    try {
      for (const mode of ["text", "attribute", "fill", "doctype"]) {
        const result = await oracle.placementBoundaryProbe(mode);
        assert.equal(result.report.failure, "map_target_stale", mode);
        assert.equal(result.locked, true, mode);
        assert.equal(result.targetHtml, "teaser", `${mode}: original target children restored`);
      }
    } finally {
      await oracle.close();
    }
  },
);

test(
  "browser map refuses a non-UTF8 document before delivery or key processing",
  { skip: SKIP },
  async () => {
    const oracle = await openOracle();
    try {
      const { encoding, result } = await oracle.encodingProbe();
      assert.equal(encoding, "windows-1252");
      assert.deepEqual(result.report, { outcome: "failed", failure: "source_refused" });
    } finally {
      await oracle.close();
    }
  },
);
