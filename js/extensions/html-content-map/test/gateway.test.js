// @ts-check
//
// The server-side client's source provenance and capability scope,
// docs/spec-proposal--html-content-map.md Section 8, through `createHtmlGateway` with an
// injected fetch, the real publisher and the real issuer core. Every refusal
// here is the map failure `source_refused`, reached before any unlock request.
//
// The cases follow the section's two attacks: a caller-authored page around
// genuine copied material, which the gateway never takes because it fetches
// the page itself from an admitted source; and an unsigned or wrongly signed
// page whose wraps a cached period key would open. The base cache files a
// period key under the page's own origin, so only a copy served from the
// origin the key was cached for reaches a cached key; the test for that case
// serves the copy from `https://pub.example` itself.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { createHtmlGateway } from "../integration-client/createHtmlGateway.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { decodeCompactJwt } from "../../../core-shared/compactJwt.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { es256Sign } from "../../../core-shared/cryptoProvider.js";
import { signingKeypair } from "../../../test-reference/support/keys.js";
import {
  ARTICLE_MAP,
  BODYTEXT,
  FACTBOX,
  ISSUER_NAME,
  UNLOCK_URL,
  articlePage,
  mapWorld,
} from "./world.js";

/**
 * A fetch over a table of URL answers. A string answers 200 with that page; a
 * `{ redirect }` answers 302 with that Location; a number answers that status.
 *
 * @param {Record<string, string|number|{ redirect: string }>} table
 */
function fetchOver(table) {
  /** @type {string[]} */
  const requested = [];
  /**
   * @param {string} url
   * @param {{ method: string, redirect: string }} init
   */
  async function fetch(url, init) {
    assert.equal(init.method, "GET");
    assert.equal(init.redirect, "manual", "the gateway follows redirects itself");
    requested.push(url);
    const answer = table[url];
    const respond = (
      /** @type {number} */ status,
      /** @type {string} */ body,
      /** @type {string|null} */ location = null,
    ) => ({
      status,
      headers: {
        get: (/** @type {string} */ name) =>
          name === "location"
            ? location
            : name === "content-type" && status === 200
              ? "text/html; charset=utf-8"
              : null,
      },
      body: new Response(body).body,
    });
    if (typeof answer === "string") return respond(200, answer);
    if (typeof answer === "number") return respond(answer, "");
    if (answer !== undefined) return respond(302, "", answer.redirect);
    return respond(404, "");
  }
  return { fetch, requested };
}

/** The Section 12.3 article from one world, as a page and its parts. */
async function article(/** @type {any} */ world) {
  return world.article();
}

/**
 * A gateway over one world's issuer.
 *
 * @param {any} world
 * @param {any} fetch
 * @param {object} [overrides]
 */
function gatewayFor(world, fetch, overrides = {}) {
  return createHtmlGateway({
    sources: [{ origin: world.origin }],
    registrations: [{ id: "pub", keys: { [world.signingKid]: world.signingPublicKey } }],
    fetch,
    issuerName: ISSUER_NAME,
    issuerEndpoint: UNLOCK_URL,
    admitCaller: () => true,
    transport: world.transport,
    ...overrides,
  });
}

const REFUSED = { outcome: "failed", failure: "source_refused" };

describe("Section 8, items 1 and 2: the source URL and every redirect", () => {
  test("a URL the configuration does not admit is refused before any fetch", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    const { fetch, requested } = fetchOver({ "https://pub.example/a": html });
    const gateway = gatewayFor(world, fetch);
    for (const url of [
      "https://other.example/a",
      "http://pub.example/a",
      "https://user@pub.example/a",
      "https://:pw@pub.example/a",
      "https://pub.example:8443/a",
      "not a url",
    ]) {
      const result = await gateway.reconstruct({ url, callerContext: "caller" });
      assert.deepEqual(result.report, REFUSED, url);
      assert.equal(result.html, null);
    }
    assert.deepEqual(requested, []);
    assert.equal(world.unlocks.length, 0);
  });

  test("an admitted redirect is followed and the final URL is the result identity", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    const { fetch, requested } = fetchOver({
      "https://pub.example/short/1": { redirect: "/articles/harbour" },
      "https://pub.example/articles/harbour": html,
    });
    const result = await gatewayFor(world, fetch).reconstruct({
      url: "https://pub.example/short/1#comments",
      callerContext: "caller",
    });
    assert.deepEqual(requested, [
      "https://pub.example/short/1",
      "https://pub.example/articles/harbour",
    ]);
    assert.equal(result.identity, "https://pub.example/articles/harbour");
    assert.equal(result.report.outcome, "complete");
  });

  test("a redirect to an unadmitted URL or to http, too many redirects, or a non-200 is refused", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    const cases = [
      {
        "https://pub.example/a": { redirect: "https://evil.example/a" },
        "https://evil.example/a": html,
      },
      {
        "https://pub.example/a": { redirect: "http://pub.example/a" },
        "http://pub.example/a": html,
      },
      { "https://pub.example/a": { redirect: "/b" }, "https://pub.example/b": { redirect: "/a" } },
      { "https://pub.example/a": { redirect: null }, "https://pub.example/null": html },
      { "https://pub.example/a": 404 },
      { "https://pub.example/a": 500 },
    ];
    for (const table of cases) {
      const { fetch, requested } = fetchOver(/** @type {any} */ (table));
      const result = await gatewayFor(world, fetch).reconstruct({
        url: "https://pub.example/a",
        callerContext: "caller",
      });
      assert.deepEqual(result.report, REFUSED, JSON.stringify(table).slice(0, 80));
      // A refused redirect ends the fetch: no request goes past it.
      for (const url of requested) assert.match(url, /^https:\/\/pub\.example\/[ab]$/);
    }
    assert.equal(world.unlocks.length, 0);
  });

  test("maxRedirects admits exactly that many hops; 0 admits a direct page", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    const { fetch } = fetchOver({
      "https://pub.example/two": { redirect: "/one" },
      "https://pub.example/one": { redirect: "/final" },
      "https://pub.example/final": html,
    });
    const outcome = async (/** @type {string} */ url, /** @type {number} */ maxRedirects) =>
      (await gatewayFor(world, fetch, { maxRedirects }).reconstruct({ url, callerContext: "c" }))
        .report;
    assert.equal((await outcome("https://pub.example/final", 0)).outcome, "complete");
    assert.equal((await outcome("https://pub.example/one", 1)).outcome, "complete");
    assert.deepEqual(await outcome("https://pub.example/two", 1), REFUSED);
  });

  test("a path prefix narrows a source to the pages under it", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    const { fetch } = fetchOver({
      "https://pub.example/users/x": html,
      "https://pub.example/news/x": html,
    });
    const gateway = gatewayFor(world, fetch, {
      sources: [{ origin: world.origin, pathPrefix: "/news/" }],
    });
    const outside = await gateway.reconstruct({
      url: "https://pub.example/users/x",
      callerContext: "c",
    });
    assert.deepEqual(outside.report, REFUSED);
    const inside = await gateway.reconstruct({
      url: "https://pub.example/news/x",
      callerContext: "c",
    });
    assert.equal(inside.report.outcome, "complete");
  });
});

describe("Section 8, item 4: the publisher assertion on every response", () => {
  test("the final origin must equal the verified origin claim", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    // A mirror the configuration admits serves the publisher's genuine page.
    const { fetch } = fetchOver({ "https://mirror.example/a": html });
    const result = await gatewayFor(world, fetch, {
      sources: [{ origin: world.origin }, { origin: "https://mirror.example" }],
    }).reconstruct({ url: "https://mirror.example/a", callerContext: "caller" });
    assert.deepEqual(result.report, REFUSED);
    assert.equal(world.unlocks.length, 0);
  });

  test("a token no trusted registration verifies is refused, whatever it claims", async () => {
    const world = await mapWorld();
    const stranger = await mapWorld({ signingKid: "stranger-kid" });
    const { html } = await article(stranger);
    const { fetch } = fetchOver({ "https://pub.example/a": html });
    const result = await gatewayFor(world, fetch).reconstruct({
      url: "https://pub.example/a",
      callerContext: "caller",
    });
    assert.deepEqual(result.report, REFUSED, "an unknown kid");

    // A known kid over another key's signature, and an alg:none token.
    const { html: own } = await article(world);
    const token = /** @type {RegExpExecArray} */ (/"resourceJWT":"([^"]+)"/.exec(own))[1];
    const [head, body] = token.split(".");
    const forged = `${head}.${body}.${base64urlEncode(new Uint8Array(64))}`;
    const none = `${base64urlEncode(utf8Encode(JSON.stringify({ alg: "none", typ: "JWT", kid: world.signingKid })))}.${body}.`;
    for (const replacement of [forged, none]) {
      const { fetch: forgedFetch } = fetchOver({
        "https://pub.example/a": own.replace(token, replacement),
      });
      const refused = await gatewayFor(world, forgedFetch).reconstruct({
        url: "https://pub.example/a",
        callerContext: "caller",
      });
      assert.deepEqual(refused.report, REFUSED, decodeCompactJwt(token).header.kid);
    }

    // A token that is not compact JWS, and a registration key that cannot verify (a private key).
    const { privateKey } = await signingKeypair();
    for (const [page, key, why] of [
      [own.replace(token, "not-a-compact-jwt"), world.signingPublicKey, "not compact"],
      [own, privateKey, "a key that cannot verify"],
    ]) {
      const result = await gatewayFor(world, fetchOver({ "https://pub.example/a": page }).fetch, {
        registrations: [{ id: "pub", keys: { [world.signingKid]: key } }],
      }).reconstruct({ url: "https://pub.example/a", callerContext: "caller" });
      assert.deepEqual(result.report, REFUSED, why);
    }
    assert.equal(world.unlocks.length, 0);
  });

  test("a signed token outside the ES256 JWT header pin or with a non-string kid is refused", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    const token = /** @type {RegExpExecArray} */ (/"resourceJWT":"([^"]+)"/.exec(html))[1];
    const [, body] = token.split(".");
    const signing = await signingKeypair();
    const keys = { k: signing.publicKey, 1: signing.publicKey, "": signing.publicKey };
    for (const header of [
      { alg: "ES256", typ: "JWS", kid: "k" },
      { alg: "ES384", typ: "JWT", kid: "k" },
      { alg: "ES256", typ: "JWT", kid: 1 },
      { alg: "ES256", typ: "JWT", kid: "" },
    ]) {
      const head = base64urlEncode(utf8Encode(JSON.stringify(header)));
      const signature = await es256Sign(signing.privateKey, utf8Encode(`${head}.${body}`));
      const signed = `${head}.${body}.${base64urlEncode(new Uint8Array(signature))}`;
      const { fetch } = fetchOver({ "https://pub.example/a": html.replace(token, signed) });
      const result = await gatewayFor(world, fetch, {
        registrations: [{ id: "pub", keys }],
      }).reconstruct({ url: "https://pub.example/a", callerContext: "caller" });
      assert.deepEqual(result.report, REFUSED, JSON.stringify(header));
    }
    assert.equal(world.unlocks.length, 0);
  });

  test("a kid two registrations hold is ambiguous and refused", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    const { fetch } = fetchOver({ "https://pub.example/a": html });
    const keys = { [world.signingKid]: world.signingPublicKey };
    const result = await gatewayFor(world, fetch, {
      registrations: [
        { id: "one", keys },
        { id: "two", keys },
      ],
    }).reconstruct({ url: "https://pub.example/a", callerContext: "caller" });
    assert.deepEqual(result.report, REFUSED);
  });

  test("an unsigned page on another admitted origin is refused before any issuer contact", async () => {
    const world = await mapWorld({ periodKeyInput: true });
    world.grant.periods = true;
    const { html } = await article(world);

    // The attacker's page on another origin the configuration admits: an
    // unsigned token claiming that origin, the genuine wraps and ciphertext,
    // and its own map that places bodytext into its own layout. The period key
    // the genuine read cached is filed under https://pub.example, so no cached
    // key opens this page; without verification the gateway would ask the
    // issuer. The cached-key case is the next test.
    const token = /** @type {RegExpExecArray} */ (/"resourceJWT":"([^"]+)"/.exec(html))[1];
    const payload = { ...decodeCompactJwt(token).payload, origin: "https://evil.example" };
    const unsigned = [
      base64urlEncode(utf8Encode(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "evil" }))),
      base64urlEncode(utf8Encode(JSON.stringify(payload))),
      base64urlEncode(new Uint8Array(64)),
    ].join(".");
    const evilMap = {
      version: "1",
      items: { bodytext: "text/html" },
      rules: [{ item: "bodytext", op: "fill", target: "#stolen" }],
    };
    const carriers = /** @type {RegExpExecArray} */ (
      /(<script type="application\/json" class="dca-data">[\s\S]*?<\/script>\n<script type="application\/json" class="dca-sealed-content">[\s\S]*?<\/script>)/.exec(
        html,
      )
    )[1].replace(token, unsigned);
    const evilPage = `<!DOCTYPE html><html><body><div id="stolen"></div>${carriers}<script type="application/json" class="dca-content-map">${JSON.stringify(evilMap)}</script></body></html>`;

    const { fetch } = fetchOver({
      "https://pub.example/a": html,
      "https://evil.example/x": evilPage,
    });
    const gateway = gatewayFor(world, fetch, {
      sources: [{ origin: world.origin }, { origin: "https://evil.example" }],
      clientOptions: { relayPeriodKeys: true },
    });

    const genuine = await gateway.reconstruct({ url: "https://pub.example/a", callerContext: "c" });
    assert.equal(genuine.report.outcome, "complete");
    assert.equal(world.unlocks.length, 1, "the genuine read filed the period key");

    const attack = await gateway.reconstruct({ url: "https://evil.example/x", callerContext: "c" });
    assert.deepEqual(attack.report, REFUSED);
    assert.equal(attack.html, null, "no reconstructed page");
    assert.equal(world.unlocks.length, 1, "no issuer saw the token, and nothing was placed");
  });

  test("a cached period key does not excuse verification: an unsigned or wrongly signed copy on the same origin is refused", async () => {
    const world = await mapWorld({ periodKeyInput: true });
    world.grant.periods = true;
    const { html } = await article(world);
    const token = /** @type {RegExpExecArray} */ (/"resourceJWT":"([^"]+)"/.exec(html))[1];
    const [head, body] = token.split(".");
    const zeroSignature = base64urlEncode(new Uint8Array(64));
    const copies = {
      // An unsigned token under a kid no registration holds, claiming the
      // publisher's origin.
      "https://pub.example/copy-unsigned": html.replace(
        token,
        `${base64urlEncode(utf8Encode(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "evil" })))}.${body}.${zeroSignature}`,
      ),
      // The publisher's own kid over a signature it never made.
      "https://pub.example/copy-forged": html.replace(token, `${head}.${body}.${zeroSignature}`),
    };
    const { fetch } = fetchOver({ "https://pub.example/a": html, ...copies });
    const gateway = gatewayFor(world, fetch, { clientOptions: { relayPeriodKeys: true } });

    const genuine = await gateway.reconstruct({ url: "https://pub.example/a", callerContext: "c" });
    assert.equal(genuine.report.outcome, "complete");
    assert.equal(world.unlocks.length, 1, "the genuine read filed the period key for caller c");

    // From here the issuer would deny, so only the cached key could open.
    world.grant.contentNames = [];
    world.grant.periods = false;
    for (const url of Object.keys(copies)) {
      const attack = await gateway.reconstruct({ url, callerContext: "c" });
      assert.deepEqual(attack.report, REFUSED, url);
      assert.equal(attack.html, null, `${url}: no reconstructed page`);
    }
    assert.equal(world.unlocks.length, 1, "no issuer contact for either copy");
  });

  test("a delivery the base structural processing refuses is delivery_refused, not the base code", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    const broken = [
      // A second dca-data carrier, and a dca-data carrier that is not JSON.
      html.replace(
        '<script type="application/json" class="dca-data">',
        '<script type="application/json" class="dca-data">{}</script><script type="application/json" class="dca-data">',
      ),
      html.replace(/(class="dca-data">)[^<]*/, "$1{ not json"),
      // One element carrying both reserved tokens and no other sealed carrier.
      // The base reader tells this apart only by element identity.
      html
        .replace(
          /<script type="application\/json" class="dca-sealed-content">[\s\S]*?<\/script>/,
          "",
        )
        .replace('class="dca-data"', 'class="dca-data dca-sealed-content"'),
    ];
    for (const page of broken) {
      assert.notEqual(page, html);
      const { fetch } = fetchOver({ "https://pub.example/a": page });
      const result = await gatewayFor(world, fetch).reconstruct({
        url: "https://pub.example/a",
        callerContext: "caller",
      });
      assert.deepEqual(result.report, { outcome: "failed", failure: "delivery_refused" });
      assert.equal(result.html, null);
    }
    assert.equal(world.unlocks.length, 0);
  });

  test("the gateway takes no caller HTML: its only input is a URL", async () => {
    const world = await mapWorld();
    const { fetch } = fetchOver({});
    const gateway = gatewayFor(world, fetch);
    const result = await gateway.reconstruct(
      /** @type {any} */ ({
        url: "https://pub.example/none",
        callerContext: "c",
        html: "<p>mine</p>",
      }),
    );
    assert.deepEqual(
      result.report,
      REFUSED,
      "the named URL answered 404; the submitted HTML is ignored",
    );
  });
});

describe("Section 8: capability scope", () => {
  test("a caller's retained capability opens that caller's next article and no other caller's", async () => {
    const world = await mapWorld({ periodKeyInput: true });
    const first = await world.article();
    const second = await world.publish({
      resourceId: "harbour-follow-up",
      items: [
        { name: "bodytext", value: BODYTEXT, contentType: "text/html" },
        { name: "factbox", value: FACTBOX, contentType: "text/html" },
      ],
      contentMap: ARTICLE_MAP,
      page: articlePage,
    });
    const { fetch } = fetchOver({
      "https://pub.example/1": first.html,
      "https://pub.example/2": second.html,
    });
    const gateway = gatewayFor(world, fetch, { clientOptions: { relayPeriodKeys: true } });

    world.grant.periods = true;
    const a1 = await gateway.reconstruct({ url: "https://pub.example/1", callerContext: "a" });
    assert.equal(a1.report.outcome, "complete");
    assert.equal(world.unlocks.length, 1);

    // The issuer now denies everything. Caller a opens article 2 from its own
    // retained period key; caller b has none and is refused by the issuer.
    world.grant.contentNames = [];
    world.grant.periods = false;
    const a2 = await gateway.reconstruct({ url: "https://pub.example/2", callerContext: "a" });
    assert.equal(a2.report.outcome, "complete");
    assert.equal(world.unlocks.length, 1, "no issuer contact for caller a");

    const b2 = await gateway.reconstruct({ url: "https://pub.example/2", callerContext: "b" });
    assert.deepEqual(b2.report, {
      outcome: "partial",
      items: { bodytext: "locked", factbox: "locked" },
    });
    assert.equal(world.unlocks.length, 2, "caller b needed the issuer");
  });

  test("client options cannot replace the scoped caches or the gateway's own client wiring", async () => {
    const world = await mapWorld();
    const { fetch, requested } = fetchOver({});
    for (const name of [
      "cache",
      "storage",
      "cacheNamespace",
      "cacheKeyBy",
      "chainCache",
      "resolverFactory",
      "root",
      "transport",
      "issuerName",
    ]) {
      assert.throws(
        () =>
          gatewayFor(world, fetch, {
            clientOptions: { [name]: new PeriodKeyCache() },
          }),
        (/** @type {any} */ error) => error.code === "bad_config" && error.message.includes(name),
        name,
      );
    }
    assert.deepEqual(requested, [], "each refusal comes at construction, before any fetch");
    // A chain cache comes only through the scoped provider, never as a value.
    assert.throws(
      () => gatewayFor(world, fetch, { chainCache: {} }),
      (/** @type {any} */ error) =>
        error.code === "bad_config" && error.message.includes("chainCache"),
    );
  });

  test("two registrations on one origin keep separate capability", async () => {
    // Both publishers serve from https://pub.example and happen to hold the
    // same period keys. Only the registration scope keeps publisher one's
    // grant from opening publisher two's render.
    const one = await mapWorld({ periodKeyInput: true, signingKid: "one-kid" });
    const two = await mapWorld({ periodKeyInput: true, signingKid: "two-kid" });
    one.grant.periods = true;
    two.grant.contentNames = [];
    const pageOne = await one.article();
    const pageTwo = await two.article();
    const { fetch } = fetchOver({
      "https://pub.example/one": pageOne.html,
      "https://pub.example/two": pageTwo.html,
    });
    const transport = {
      /** @param {string} url @param {any} request */
      post: (url, request) =>
        (decodeCompactJwt(request.resourceJWT).header.kid === "one-kid" ? one : two).transport.post(
          url,
          request,
        ),
    };
    const registrations = [
      { id: "one", keys: { "one-kid": one.signingPublicKey } },
      { id: "two", keys: { "two-kid": two.signingPublicKey } },
    ];

    /** @param {any} [capabilityCache] */
    const read = async (capabilityCache) => {
      const gateway = createHtmlGateway({
        sources: [{ origin: "https://pub.example" }],
        registrations,
        fetch,
        issuerName: ISSUER_NAME,
        issuerEndpoint: UNLOCK_URL,
        admitCaller: () => true,
        transport,
        clientOptions: { relayPeriodKeys: true },
        ...(capabilityCache === undefined ? {} : { capabilityCache }),
      });
      await gateway.reconstruct({ url: "https://pub.example/one", callerContext: "c" });
      return gateway.reconstruct({ url: "https://pub.example/two", callerContext: "c" });
    };

    const scoped = await read();
    assert.equal(scoped.report.outcome, "partial", "publisher two's issuer decides");
    // Control: one cache shared across registrations would open it.
    const shared = new PeriodKeyCache();
    const leaked = await read(() => shared);
    assert.equal(leaked.report.outcome, "complete", "the case discriminates the scope");
  });
});

describe("gateway admission and bounded source bytes", () => {
  test("an unknown caller cannot reach cache providers or issuer transport", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    const { fetch } = fetchOver({ "https://pub.example/a": html });
    const seen = [];
    const gateway = gatewayFor(world, fetch, {
      admitCaller: async (scope) => {
        seen.push(scope);
        return scope.callerContext === "known";
      },
      capabilityCache: () => {
        throw new Error("must not reach cache provider");
      },
      chainCache: () => {
        throw new Error("must not reach chain cache provider");
      },
    });
    const result = await gateway.reconstruct({
      url: "https://pub.example/a",
      callerContext: "unknown",
    });
    assert.deepEqual(result.report, REFUSED);
    assert.deepEqual(seen, [{ callerContext: "unknown", registration: "pub" }]);
    assert.equal(result.html, null);
    assert.equal(world.unlocks.length, 0);
    for (const admitCaller of [undefined, null, true]) {
      assert.throws(
        () => gatewayFor(world, fetch, { admitCaller }),
        (error) => error.code === "bad_config",
      );
    }
  });

  test("the trusted issuer endpoint overrides a changed carried URL after verification", async () => {
    const world = await mapWorld({ periodKeyInput: true });
    world.grant.periods = true;
    const { html } = await article(world);
    const changed = html.replace(
      '"keyId":"open-1"',
      '"keyId":"open-1","unlockUrl":"https://other-issuer.example/unlock"',
    );
    assert.notEqual(changed, html);
    const { fetch } = fetchOver({
      "https://pub.example/a": html,
      "https://pub.example/changed": changed,
    });
    const cache = new PeriodKeyCache();
    let cacheCalls = 0;
    let callerCalls = 0;
    let admitted = true;
    const gateway = gatewayFor(world, fetch, {
      clientOptions: { relayPeriodKeys: true },
      capabilityCache: () => {
        cacheCalls++;
        return cache;
      },
      admitCaller: () => {
        callerCalls++;
        return admitted;
      },
    });
    const first = await gateway.reconstruct({
      url: "https://pub.example/a",
      callerContext: "known",
    });
    assert.equal(first.report.outcome, "complete");
    assert.equal(world.unlocks.length, 1);
    const second = await gateway.reconstruct({
      url: "https://pub.example/changed",
      callerContext: "known",
    });
    assert.equal(second.report.outcome, "complete");
    assert.equal(cacheCalls, 2);
    assert.equal(callerCalls, 2);
    assert.equal(world.unlocks.length, 1);
    const fresh = await gatewayFor(world, fetch, {
      clientOptions: { relayPeriodKeys: true },
    }).reconstruct({
      url: "https://pub.example/changed",
      callerContext: "fresh",
    });
    assert.equal(fresh.report.outcome, "complete");
    assert.equal(world.unlocks.at(-1).url, UNLOCK_URL);
    assert.equal(world.unlocks.length, 2);
    admitted = false;
    const revoked = await gateway.reconstruct({
      url: "https://pub.example/a",
      callerContext: "known",
    });
    assert.deepEqual(revoked.report, REFUSED);
    assert.equal(cacheCalls, 2, "caller admission precedes cache access on every reconstruction");
    assert.equal(callerCalls, 3);
    assert.equal(world.unlocks.length, 2);
  });

  test("malformed source UTF-8 is refused without replacement or key work", async () => {
    const world = await mapWorld();
    const { html } = await article(world);
    const prefix = utf8Encode(html);
    const bytes = new Uint8Array(prefix.length + 1);
    bytes.set(prefix);
    bytes[prefix.length] = 0xff;
    const gateway = gatewayFor(
      world,
      async () => new Response(bytes, { headers: { "content-type": "text/html; charset=utf-8" } }),
      {
        capabilityCache: () => {
          throw new Error("must not reach cache");
        },
      },
    );
    const result = await gateway.reconstruct({
      url: "https://pub.example/a",
      callerContext: "known",
    });
    assert.deepEqual(result.report, { outcome: "failed", failure: "source_refused" });
    assert.equal(world.unlocks.length, 0);
  });

  test("the document limit stops and cancels a stream at the first excessive chunk", async () => {
    const world = await mapWorld();
    let reads = 0;
    let cancels = 0;
    let releases = 0;
    const fetch = async () => ({
      status: 200,
      headers: { get: (name) => (name === "content-type" ? "text/html; charset=utf-8" : null) },
      arrayBuffer: () => {
        throw new Error("unbounded buffering must not run");
      },
      body: {
        getReader: () => ({
          read: async () => {
            reads++;
            return { done: false, value: new Uint8Array(6) };
          },
          cancel: async () => {
            cancels++;
          },
          releaseLock: () => {
            releases++;
          },
        }),
      },
    });
    const result = await gatewayFor(world, fetch, { limits: { documentOctets: 10 } }).reconstruct({
      url: "https://pub.example/a",
      callerContext: "known",
    });
    assert.deepEqual(result.report, { outcome: "failed", failure: "map_limit" });
    assert.deepEqual([reads, cancels, releases], [2, 1, 1]);
    assert.equal(world.unlocks.length, 0);

    // A page of exactly the limit is admitted.
    const { html } = await article(world);
    const { fetch: exact } = fetchOver({ "https://pub.example/a": html });
    const documentOctets = utf8Encode(html).byteLength;
    const atLimit = await gatewayFor(world, exact, { limits: { documentOctets } }).reconstruct({
      url: "https://pub.example/a",
      callerContext: "known",
    });
    assert.equal(atLimit.report.outcome, "complete");
  });

  test("an arrayBuffer-only source is refused and invalid endpoint configuration fails early", async () => {
    const world = await mapWorld();
    // An admitted Content-Type, so the refusal comes from the streaming-body guard.
    const answer = (/** @type {object|undefined} */ body) => async () => ({
      status: 200,
      headers: { get: (name) => (name === "content-type" ? "text/html; charset=utf-8" : null) },
      arrayBuffer: () => {
        throw new Error("must not run");
      },
      body,
    });
    for (const body of [undefined, {}]) {
      const result = await gatewayFor(world, answer(body)).reconstruct({
        url: "https://pub.example/a",
        callerContext: "known",
      });
      assert.deepEqual(result.report, REFUSED);
    }
    const fetch = answer(undefined);
    for (const issuerEndpoint of [
      undefined,
      "http://issuer.example/unlock",
      "https://user@issuer.example/unlock",
      "https://issuer.example/unlock#fragment",
    ]) {
      assert.throws(
        () => gatewayFor(world, fetch, { issuerEndpoint }),
        (error) => error.code === "bad_config",
      );
    }
  });
});

test("a rejected fetch or body read is source_refused, not an exception", async () => {
  const world = await mapWorld();
  const failingBody = (/** @type {unknown} */ reason) => async () =>
    new Response(
      new ReadableStream({
        pull(controller) {
          controller.error(reason);
        },
      }),
      { headers: { "content-type": "text/html; charset=utf-8" } },
    );
  for (const fetch of [
    async () => {
      throw new TypeError("fetch failed");
    },
    failingBody(new TypeError("terminated")),
    failingBody(new DOMException("aborted", "AbortError")),
  ]) {
    const result = await gatewayFor(world, fetch).reconstruct({
      url: "https://pub.example/a",
      callerContext: "known",
    });
    assert.deepEqual(result.report, REFUSED);
  }
  assert.equal(world.unlocks.length, 0);
});

test("unread redirect and failure bodies are cancelled before following or refusing", async () => {
  const world = await mapWorld();
  const { html } = await article(world);
  for (const status of [302, 404]) {
    const events = [];
    const fetch = async (url) => {
      events.push(url);
      if (url.endsWith("/final"))
        return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
      return {
        status,
        headers: { get: () => "/final" },
        body: {
          getReader: () => ({
            read: async () => {
              throw new Error("unread body must not be buffered");
            },
            cancel: async () => {
              events.push("cancel");
            },
            releaseLock: () => {
              events.push("release");
            },
          }),
        },
      };
    };
    const result = await gatewayFor(world, fetch).reconstruct({
      url: "https://pub.example/start",
      callerContext: "known",
    });
    assert.deepEqual(
      events,
      status === 302
        ? ["https://pub.example/start", "cancel", "release", "https://pub.example/final"]
        : ["https://pub.example/start", "cancel", "release"],
    );
    if (status === 302) assert.equal(result.report.outcome, "complete");
    else assert.deepEqual(result.report, REFUSED);
  }
});

test("the final HTTP charset controls source admission; inert metas cannot override it", async () => {
  const world = await mapWorld();
  const { html } = await article(world);
  for (const [contentType, meta] of [
    ["text/html; charset=windows-1252", ""],
    ['text/html; charset="utf-8"; charset=iso-8859-1', ""],
    ["text/html; charset=utf-8; junk", ""],
    ["text/plain; charset=utf-8", ""],
    ["text/html", '<meta charset="windows-1252">'],
    ["text/html", '<meta charset="utf-8"><meta charset="windows-1252">'],
  ]) {
    const source = html.replace("<head>", "<head>" + meta);
    if (meta) assert.notEqual(source, html);
    const gateway = gatewayFor(
      world,
      async () => new Response(source, { headers: { "content-type": contentType } }),
      {
        capabilityCache: () => {
          throw new Error("encoding refusal precedes cache");
        },
      },
    );
    const result = await gateway.reconstruct({
      url: "https://pub.example/a",
      callerContext: "known",
    });
    assert.deepEqual(result.report, REFUSED, contentType + meta);
  }
  assert.equal(world.unlocks.length, 0);
  const accepted = gatewayFor(
    world,
    async () =>
      new Response(
        html.replace(
          "<head>",
          '<head><meta charset="windows-1252"><meta http-equiv="content-type" content="text/html; charset=iso-8859-1">',
        ),
        { headers: { "content-type": 'text/html; charset="UTF-8"; note=";charset=windows-1252"' } },
      ),
  );
  const result = await accepted.reconstruct({
    url: "https://pub.example/a",
    callerContext: "known",
  });
  assert.equal(result.report.outcome, "complete");
  // Other conforming spellings of one UTF-8 charset are admitted too.
  for (const contentType of [
    "text/html; charset=utf8",
    'text/html; charset=" utf-8 "',
    'text/html; note="a\\";b"; charset=utf-8',
    'text/html; charset="ut\\f-8"',
    "text/html; charset =utf-8",
  ]) {
    const spelled = await gatewayFor(
      world,
      async () => new Response(html, { headers: { "content-type": contentType } }),
    ).reconstruct({ url: "https://pub.example/a", callerContext: "known" });
    assert.equal(spelled.report.outcome, "complete", contentType);
  }
});

test("source bytes consume one split UTF-8 BOM and reject a second or UTF-16 BOM", async () => {
  const world = await mapWorld();
  const { html } = await article(world);
  const body = utf8Encode(html);
  const bom = Uint8Array.of(0xef, 0xbb, 0xbf);
  const responseFor = (/** @type {Uint8Array[]} */ chunks) =>
    new Response(
      new ReadableStream({
        start(controller) {
          for (const chunk of chunks) controller.enqueue(chunk);
          controller.close();
        },
      }),
      { headers: { "content-type": "text/html; charset=UTF-8" } },
    );
  const good = await gatewayFor(world, async () =>
    responseFor([bom.subarray(0, 1), bom.subarray(1), body]),
  ).reconstruct({
    url: "https://pub.example/a",
    callerContext: "reader",
  });
  assert.equal(good.report.outcome, "complete");
  for (const chunks of [
    [bom, bom, body],
    [Uint8Array.of(0xff, 0xfe), body],
  ]) {
    const refused = await gatewayFor(world, async () => responseFor(chunks)).reconstruct({
      url: "https://pub.example/a",
      callerContext: "reader",
    });
    assert.deepEqual(refused.report, REFUSED);
  }
});

test("an exhausted visible 5xx reports acquisition failure without speculative locked items", async () => {
  const world = await mapWorld();
  const { html } = await article(world);
  const { fetch } = fetchOver({ "https://pub.example/a": html });
  const gateway = gatewayFor(world, fetch, {
    transport: {
      post: async () => ({
        status: 503,
        contentType: "application/json",
        body: { error: "policy_unavailable" },
      }),
    },
  });
  const result = await gateway.reconstruct({
    url: "https://pub.example/a",
    callerContext: "reader",
  });
  assert.deepEqual(result.report, {
    outcome: "failed",
    failure: "key_acquisition_failed",
  });
});
