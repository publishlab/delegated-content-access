// @ts-check
//
// Prototype composition for the proposed protected-HTML content map, on the example of
// docs/spec-proposal--html-content-map.md Section 12.3. The publisher renders the
// locked page through its real path (`createPublisher`, then
// `writeMarkupDelivery` with embedded contentMap); the issuer
// is the real issuer core; the same delivery and the same issuer decisions
// reach both clients:
//
// - the server-side client, `createHtmlGateway`, in Node with parse5; and
// - the browser client, `reconstructBrowserPage`, in headless Chromium on the
//   page served with `Content-Security-Policy: script-src 'none'`. This half
//   skips when no Chromium executable is installed.
//
// Candidate request: dca-profile-html-content-map.
// Candidate closure: dca-profile-baseline, dca-profile-html-carrier and dca-profile-html-content-map.
// Carrier as run: the publisher writes real markup with `writeMarkupDelivery`
// and both clients extract the delivery from it, so the scenario also
// exercises the HTML-carrier dependency selected by this candidate.
// Affected roles: publisher (authors the carrier) and both clients (select the
// profile by configuration, admit, place and report). The issuer has no duty
// under the profile and sees an ordinary unlock request.
//
// One scenario also selects the chain-key extension (Section 11), because
// the gateway's chain-cache scope only shows with a real chain grant. By the
// placement rule in `test-extensions/README.md` a test that needs two
// extensions belongs there; move the chain composition when that evidence
// layout is revisited.
//
// Focused owners: map and target admission, every Section 9 code, placement,
// item states, source provenance and the three-way oracle comparison live in
// `extensions/html-content-map/test/`.

import test, { after, before, describe } from "node:test";
import assert from "node:assert/strict";
import process from "node:process";

import { parse, serialize } from "parse5";

import { createHtmlGateway } from "../extensions/html-content-map/integration-client/createHtmlGateway.js";
import { parseLockedDocument } from "../extensions/html-content-map/adapter-client/parse5Tree.js";
import { treeDeliveryRoot } from "../extensions/html-content-map/core-client/treeDeliveryRoot.js";
import { openOracle, oracleBrowserPath } from "../extensions/html-content-map/test/chromium.js";
import {
  ARTICLE_MAP,
  BODYTEXT,
  FACTBOX,
  ISSUER_NAME,
  ORIGIN,
  articlePage,
  bylinePage,
  mapWorld,
  nestedTemplatePage,
} from "../extensions/html-content-map/test/world.js";
import { utf8Decode } from "../core-shared/codec.js";
import { createBrowserClient } from "../integration-client/createBrowserClient.js";
import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { createPublisher } from "../integration-publisher/createPublisher.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { issuerKeypair, signingKeypair } from "../test-reference/support/keys.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import { chainGeneration, chainSupply, deliveryPlan } from "../extensions/chain-keys/test/world.js";

const BROWSER = oracleBrowserPath();
const SKIP =
  BROWSER === null
    ? "no Chromium executable: set DCA_ORACLE_BROWSER or install chrome-headless-shell in the puppeteer cache"
    : false;

const BYLINE = "By <b>Kari</b> & Ola";
const BYLINE_MAP = Object.freeze({
  version: "1",
  rules: [{ item: "byline", op: "fill", target: "#byline" }],
});

/**
 * The server-side client, configured for this publisher: its trusted
 * configuration is what selects the profile.
 *
 * @param {any} world
 * @param {string} html - what the publisher serves at `ORIGIN/page`
 */
async function serverRun(world, html) {
  const gateway = createHtmlGateway({
    issuerEndpoint: "https://issuer.example/unlock",
    admitCaller: () => true,
    sources: [{ origin: ORIGIN }],
    registrations: [{ id: "pub", keys: { [world.signingKid]: world.signingPublicKey } }],
    fetch: async () => ({
      status: 200,
      headers: {
        get: (name) => (name.toLowerCase() === "content-type" ? "text/html; charset=utf-8" : null),
      },
      body: new globalThis.Response(html).body,
    }),
    issuerName: ISSUER_NAME,
    transport: world.transport,
  });
  return gateway.reconstruct({ url: `${ORIGIN}/page`, callerContext: "reader-1" });
}

/**
 * Observations over an emitted page, through parse5 with the scripting flag
 * set: the delivered form's elements by a predicate, their class values and
 * their serialized children.
 *
 * @param {string} html
 */
function observe(html) {
  const document = parse(html, { scriptingEnabled: true });
  /** @type {any[]} */
  const elements = [];
  /** @param {any} node */
  const walk = (node) => {
    for (const child of node.childNodes ?? []) {
      if (child.tagName !== undefined) elements.push(child);
      walk(child);
    }
  };
  walk(document);
  /** @param {any} element @param {string} name */
  const attribute = (element, name) =>
    element.attrs.find((/** @type {any} */ a) => a.name === name)?.value ?? null;
  return {
    /** @param {string} id */
    byId: (id) => elements.find((element) => attribute(element, "id") === id) ?? null,
    /** @param {string} token */
    byClass: (token) =>
      elements.filter((element) =>
        (attribute(element, "class") ?? "").split(/[\t\n\f\r ]+/).includes(token),
      ),
    /** @param {string} name */
    byTag: (name) => elements.filter((element) => element.tagName === name),
    attribute,
    /** @param {any} element */
    inner: (element) => serialize(element, { scriptingEnabled: true }),
  };
}

/**
 * The Section 12.3 observations when both items opened.
 *
 * @param {string} html
 */
function assertComplete(html) {
  const page = observe(html);
  const [bodytext] = page.byClass("bodytext");
  assert.equal(page.inner(bodytext), BODYTEXT, "#main .bodytext holds the full body");
  assert.equal(page.attribute(bodytext, "class"), "bodytext");
  assert.equal(page.attribute(page.byTag("body")[0], "class"), "article");
  assert.equal(page.byClass("paywallTeaser").length, 0, "the prompt is gone");
  const inline = page.inner(page.byId("factbox-inline"));
  assert.equal(inline, FACTBOX);
  assert.equal(page.inner(page.byId("factbox-aside")), inline, "repeated placement");
  assert.equal(page.byClass("dca-content-map").length, 0, "the client removed the map carrier");
  assert.equal(page.byClass("dca-data").length, 1, "the base carriers stay");
}

/**
 * The Section 12.3 observations when only `factbox` opened.
 *
 * @param {string} html
 */
function assertFactboxOnly(html) {
  const page = observe(html);
  const [bodytext] = page.byClass("bodytext");
  assert.match(page.inner(bodytext), /The first lines of the story/, "the teaser stays");
  assert.equal(page.attribute(bodytext, "class"), "bodytext lab-paywall-locked teaserContent");
  assert.equal(page.attribute(page.byTag("body")[0], "class"), "article blur-content");
  assert.equal(page.byClass("paywallTeaser").length, 1, "the prompt stays");
  assert.equal(page.inner(page.byId("factbox-inline")), FACTBOX);
  assert.equal(page.inner(page.byId("factbox-aside")), FACTBOX);
}

const COMPLETE = { outcome: "complete", items: { bodytext: "opened", factbox: "opened" } };
const PARTIAL = { outcome: "partial", items: { bodytext: "locked", factbox: "opened" } };
const FATAL = { outcome: "failed", failure: "map_target_count" };
const ARTICLE_PATHS = [[1, 1, 0], [1, 1, 0], [1, 1, 0], [1], [1, 0], [1, 1, 1], [1, 2, 0]];

describe("the publisher authors the map carrier", () => {
  test("the real publisher path emits one contentMap member in the dca-data carrier", async () => {
    const world = await mapWorld();
    const { html } = await world.article();
    const page = observe(html);
    const [carrier] = page.byClass("dca-data");
    assert.equal(page.byClass("dca-content-map").length, 0);
    assert.equal(page.attribute(carrier, "type"), "application/json");
    assert.deepEqual(JSON.parse(carrier.childNodes[0].value).contentMap, ARTICLE_MAP);
    assert.equal(page.byClass("dca-data").length, 1);
    assert.equal(page.byClass("dca-sealed-content").length, 1);
  });
});

describe("server-side client: Section 12.3 and 12.4", () => {
  test("both items granted: complete, with every Section 12.3 observation", async () => {
    const world = await mapWorld();
    const { html } = await world.article();
    const result = await serverRun(world, html);
    assert.deepEqual(result.report, COMPLETE);
    assert.deepEqual(
      result.targets.map((/** @type {any} */ target) => target.path),
      ARTICLE_PATHS,
    );
    assertComplete(/** @type {string} */ (result.html));
    assert.equal(world.unlocks.length, 1, "one base unlock for both items");
    assert.deepEqual(
      world.unlocks[0].request.sealed.contentKeys
        .map((/** @type {any} */ record) => record.contentName)
        .sort(),
      ["bodytext", "factbox"],
    );
  });

  test("only factbox granted: partial, bodytext locked, its rules change nothing", async () => {
    const world = await mapWorld();
    world.grant.contentNames = ["factbox"];
    const { html } = await world.article();
    const result = await serverRun(world, html);
    assert.deepEqual(result.report, PARTIAL);
    assertFactboxOnly(/** @type {string} */ (result.html));
  });

  test("Section 12.4 nested template: map_target_count, no document and no unlock request", async () => {
    const world = await mapWorld();
    const { html } = await world.publish({
      items: [
        { name: "bodytext", value: BODYTEXT, contentType: "text/html" },
        { name: "factbox", value: FACTBOX, contentType: "text/html" },
      ],
      contentMap: ARTICLE_MAP,
      page: nestedTemplatePage,
    });
    const result = await serverRun(world, html);
    assert.deepEqual(result.report, FATAL);
    assert.equal(result.html, null);
    assert.equal(world.unlocks.length, 0, "the issuer spy saw no request");
  });

  test("text/plain fill places one text node", async () => {
    const world = await mapWorld();
    const { html } = await world.publish({
      items: [{ name: "byline", value: BYLINE, contentType: "text/plain" }],
      contentMap: BYLINE_MAP,
      page: bylinePage,
    });
    const result = await serverRun(world, html);
    assert.deepEqual(result.report, { outcome: "complete", items: { byline: "opened" } });
    const byline = observe(/** @type {string} */ (result.html)).byId("byline");
    assert.equal(byline.childNodes.length, 1);
    assert.equal(byline.childNodes[0].value, BYLINE);
  });
});

describe("selection comes from client configuration, not the carrier", () => {
  test("a client that has not selected the profile opens items as before and leaves the carrier alone", async () => {
    const world = await mapWorld();
    const { html, dcaData, sealedContent } = await world.article();
    // The same delivery, and one whose map carrier is not even JSON: an
    // unselected client never reads it.
    const broken = articlePage(
      `${writeMarkupDelivery({ dcaData, sealedContent })}\n<script type="application/json" class="dca-content-map">{ not json</script>`,
    );
    for (const page of [html, broken]) {
      const tree = parseLockedDocument(page);
      const before = tree.serialize();
      const client = createBrowserClient({
        unlockUrl: "https://issuer.example/unlock",
        root: treeDeliveryRoot(tree, ORIGIN),
        issuerName: ISSUER_NAME,
        transport: world.transport,
      });
      const answer = await client.unlock(["bodytext"]);
      assert.equal(answer.status, 200);
      const bytes = await client.opener.open({
        item: client.dcaData.contentItemFor("bodytext"),
        ciphertext: client.reader.extract("bodytext"),
        resolveKey: async () =>
          (await client.resolver.contentKeyWithOriginFor(client.dcaData, "bodytext")).key,
      });
      assert.equal(utf8Decode(bytes), BODYTEXT);
      assert.equal(tree.serialize(), before, "no placement, no carrier removal");
    }
    assert.equal(
      JSON.stringify(world.unlocks.map((unlock) => unlock.request)).includes("rules"),
      false,
      "nothing of the map reaches the issuer",
    );
  });

  test("a selected client on a delivery without a carrier reports map_absent and sends nothing", async () => {
    const world = await mapWorld();
    const { html } = await world.publish({
      items: [{ name: "bodytext", value: BODYTEXT, contentType: "text/html" }],
      page: articlePage,
    });
    const result = await serverRun(world, html);
    assert.deepEqual(result.report, { outcome: "failed", failure: "map_absent" });
    assert.equal(world.unlocks.length, 0);
  });
});

/**
 * A chain-key delivery (Section 11): the publisher supplies the `premium`
 * family as chain keys only, with no item content key, and the issuer runs
 * the chain-key engine, so an item opens only through a chain grant or a
 * chain key the client retained. `grant.periods` is the issuer's decision.
 */
async function chainWorld() {
  const clock = { now: () => new Date("2026-09-29T20:10:00Z") };
  const opening = await issuerKeypair();
  const signing = await signingKeypair();
  const plan = deliveryPlan(() => ["chain-keys"]);
  const publisher = createPublisher({
    origin: ORIGIN,
    clock,
    random: { bytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)) },
    signingKeys: { "chain-kid": signing.privateKey },
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: "open-1",
        algorithm: "ecdh-p256",
        publicKey: opening.publicKey,
      },
    ],
    issuerSupplyPlanFor: (issuer, render) => ({ ...plan(issuer, render), contentKeyNames: [] }),
    periodKeySupply: chainSupply(chainGeneration(7)),
  });
  const grant = { periods: true };
  const engine = referenceChainKeyProfile.issuerEngineFor({
    operatingIssuerNames: [ISSUER_NAME],
    accessPolicy: {
      decide: (/** @type {any} */ _claims, /** @type {any} */ requested) => ({
        contentNames: [],
        periodGrants: grant.periods
          ? requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
              accessGroup,
              futurePeriodCount: 1,
              authorizePeriod: () => true,
            }))
          : [],
      }),
    },
    clock,
  });
  const endpoint = new UnlockEndpoint(
    new IssuerProcessor(engine, {
      capabilityEncoders: /** @type {any} */ (engine).capabilityEncoders ?? {},
      selectedExtensions: /** @type {any} */ (engine).selectedExtensions ?? [],
    }),
    {},
  );
  const registration = {
    kid: "chain-kid",
    publicKey: signing.publicKey,
    openingKeys: {
      get: (/** @type {string} */ issuerName, /** @type {string} */ keyId) =>
        issuerName === ISSUER_NAME && keyId === "open-1"
          ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
          : undefined,
    },
  };
  let unlocks = 0;
  const transport = {
    async post(/** @type {string} */ _url, /** @type {object} */ request) {
      unlocks += 1;
      const { response } = await endpoint.handleDocument(
        JSON.stringify(request),
        /** @type {any} */ (registration),
      );
      return { status: response.status, contentType: "application/json", body: response.body };
    },
  };
  const map = {
    version: "1",
    rules: [{ item: "bodytext", op: "fill", target: "#body" }],
  };
  /** @type {Record<string, string>} */
  const pages = {};
  for (const resourceId of ["one", "two", "three"]) {
    const { dcaData, sealedContent } = await publisher.publish({
      resourceId,
      data: {},
      items: [
        { name: "bodytext", value: BODYTEXT, contentType: "text/html", accessGroups: ["premium"] },
      ],
    });
    pages[`${ORIGIN}/${resourceId}`] =
      `<!DOCTYPE html><html><head><title>${resourceId}</title></head><body><div id="body">teaser</div>${writeMarkupDelivery({ dcaData: { ...dcaData, contentMap: map }, sealedContent })}</body></html>`;
  }
  return {
    grant,
    transport,
    pages,
    unlocks: () => unlocks,
    registrations: [{ id: "pub", keys: { "chain-kid": signing.publicKey } }],
  };
}

describe("chain-key composition (Section 11): chain capability stays with its caller", () => {
  test("caller A reuses its chain grant; caller B on another page in that reach stays locked", async () => {
    const world = await chainWorld();
    /** @type {{ callerContext: string, registration: string }[]} */
    const scopes = [];
    let offered = 0;
    /** @type {Map<string, any>} */
    const chainCaches = new Map();
    const gateway = createHtmlGateway({
      issuerEndpoint: "https://issuer.example/unlock",
      admitCaller: () => true,
      sources: [{ origin: ORIGIN }],
      registrations: world.registrations,
      fetch: async (url) => ({
        status: world.pages[url] === undefined ? 404 : 200,
        headers: {
          get: (name) =>
            name.toLowerCase() === "content-type" ? "text/html; charset=utf-8" : null,
        },
        body: new globalThis.Response(world.pages[url] ?? "").body,
      }),
      issuerName: ISSUER_NAME,
      transport: world.transport,
      // One chain cache per caller and registration, the same one each time
      // that scope comes back. Each consultation that offers a retained chain
      // key is counted, whichever cache answered.
      chainCache: (scope) => {
        const key = JSON.stringify([scope.callerContext, scope.registration]);
        let cache = chainCaches.get(key);
        if (cache === undefined) {
          scopes.push(scope);
          cache = new ChainKeyCache({ strategy: "retain" });
          const candidates = cache.candidates.bind(cache);
          cache.candidates = async (...args) => {
            const held = await candidates(...args);
            offered += held.length;
            return held;
          };
          chainCaches.set(key, cache);
        }
        return cache;
      },
      clientOptions: {
        chainKeyProfile: referenceChainKeyProfile,
        requestBuilderFactory: (/** @type {object} */ options) =>
          new ChainKeyRequestBuilder(/** @type {any} */ (options)),
      },
    });

    // A copy of page one with a signature the publisher never made: refused
    // before any chain cache is asked for.
    const genuine = world.pages[`${ORIGIN}/one`];
    const token = /** @type {RegExpExecArray} */ (/"resourceJWT":"([^"]+)"/.exec(genuine))[1];
    world.pages[`${ORIGIN}/forged`] = genuine.replace(
      token,
      `${token.slice(0, token.lastIndexOf(".") + 1)}${"A".repeat(86)}`,
    );
    const forged = await gateway.reconstruct({ url: `${ORIGIN}/forged`, callerContext: "a" });
    assert.deepEqual(forged.report, { outcome: "failed", failure: "source_refused" });
    assert.deepEqual(scopes, [], "no chain cache before the token verified");

    const a1 = await gateway.reconstruct({ url: `${ORIGIN}/one`, callerContext: "a" });
    assert.deepEqual(a1.report, { outcome: "complete", items: { bodytext: "opened" } });
    assert.equal(world.unlocks(), 1, "A's chain grant");

    // The issuer now grants nobody. A opens page two from its retained chain key.
    world.grant.periods = false;
    const before = offered;
    const a2 = await gateway.reconstruct({ url: `${ORIGIN}/two`, callerContext: "a" });
    assert.deepEqual(a2.report, { outcome: "complete", items: { bodytext: "opened" } });
    assert.equal(world.unlocks(), 1, "A reused its chain key without the issuer");
    assert.ok(offered > before, "the retained chain key opened page two");

    // B has no grant. Page three lies in the same chain reach, and A's chain
    // key would open it; B's own cache offers nothing and the issuer refuses.
    const beforeB = offered;
    const b3 = await gateway.reconstruct({ url: `${ORIGIN}/three`, callerContext: "b" });
    assert.deepEqual(b3.report, { outcome: "partial", items: { bodytext: "locked" } });
    assert.equal(offered, beforeB, "no chain key was offered to caller B");
    assert.equal(world.unlocks(), 2, "B asked the issuer and was refused");
    assert.deepEqual(
      scopes.map((scope) => [scope.callerContext, scope.registration]),
      [
        ["a", "pub"],
        ["b", "pub"],
      ],
      "one chain cache per caller and registration",
    );
  });
});

describe("browser client in Chromium: the same delivery and decisions", { skip: SKIP }, () => {
  /** @type {Awaited<ReturnType<typeof openOracle>>} */
  let chromium;
  /** @type {any} */
  let world;

  before(async () => {
    world = await mapWorld();
    const transport = {
      /** @param {string} url @param {object} request */
      post: (url, request) => world.transport.post(url, request),
    };
    chromium = await openOracle({ transport });
    process.stdout.write(`# browser: ${chromium.version}\n`);
  });

  after(async () => {
    await chromium?.close();
  });

  /**
   * Both clients on one page; the browser's delivered form must equal the
   * server's.
   *
   * @param {string} html
   */
  async function bothClients(html) {
    const before = world.unlocks.length;
    const browser = await chromium.runBrowserClient(html);
    const browserUnlocks = world.unlocks.length - before;
    const server = await serverRun(world, html);
    assert.equal(browser.error, null);
    assert.deepEqual(browser.report, server.report);
    assert.deepEqual(browser.targets, server.targets);
    if (server.html !== null) {
      assert.deepEqual(
        await chromium.deliveredForm(browser.serialized),
        await chromium.deliveredForm(server.html),
        "equal delivered forms",
      );
    }
    return { browser, server, browserUnlocks };
  }

  test("both items granted: the browser and server clients deliver the same complete page", async () => {
    world.grant.contentNames = "all";
    const { html } = await world.article();
    const { browser } = await bothClients(html);
    assert.deepEqual(browser.report, COMPLETE);
    assertComplete(browser.serialized);
  });

  test("only factbox granted: both report partial and deliver the same page", async () => {
    world.grant.contentNames = ["factbox"];
    try {
      const { html } = await world.article();
      const { browser } = await bothClients(html);
      assert.deepEqual(browser.report, PARTIAL);
      assertFactboxOnly(browser.serialized);
    } finally {
      world.grant.contentNames = "all";
    }
  });

  test("Section 12.4 nested template: the browser refuses before any unlock request", async () => {
    const { html } = await world.publish({
      items: [
        { name: "bodytext", value: BODYTEXT, contentType: "text/html" },
        { name: "factbox", value: FACTBOX, contentType: "text/html" },
      ],
      contentMap: ARTICLE_MAP,
      page: nestedTemplatePage,
    });
    const { browser, browserUnlocks } = await bothClients(html);
    assert.deepEqual(browser.report, FATAL);
    assert.equal(browser.reconstructed, false);
    assert.equal(browserUnlocks, 0);
  });

  test("one element carrying both reserved tokens: both clients report delivery_refused", async () => {
    const { html } = await world.article();
    const dual = html
      .replace(/<script type="application\/json" class="dca-sealed-content">[\s\S]*?<\/script>/, "")
      .replace('class="dca-data"', 'class="dca-data dca-sealed-content"');
    assert.notEqual(dual, html);
    const before = world.unlocks.length;
    const { browser, server } = await bothClients(dual);
    const refused = { outcome: "failed", failure: "delivery_refused" };
    assert.deepEqual(browser.report, refused);
    assert.deepEqual(server.report, refused);
    assert.equal(world.unlocks.length, before);
  });

  test("text/plain fill: both place the same single text node", async () => {
    const { html } = await world.publish({
      items: [{ name: "byline", value: BYLINE, contentType: "text/plain" }],
      contentMap: BYLINE_MAP,
      page: bylinePage,
    });
    const { browser } = await bothClients(html);
    assert.equal(observe(browser.serialized).byId("byline").childNodes[0].value, BYLINE);
  });
});
