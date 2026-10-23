// @ts-check
//
// The browser origin, from the value the publisher signed to the header the
// issuer observes. The issuer treats `resourceJWT.origin` as the authority: it
// selects a registration by the untrusted header `kid`, verifies the exact token
// with that registration's key, reads the origin out of the verified payload, and requires
// the observed HTTP `Origin` to equal it byte for byte before the access
// policy or any issuer opening key.
//
// Each case here catches one wrong issuer. An issuer reading the expected
// origin off its own registration passes every honest case and lets a
// publisher that registered two origins serve one render from either. An
// issuer comparing hosts rather than bytes admits `http` for `https`, a
// non-default port and a subdomain. A fallback issuer that decides its health
// gate before the comparison probes its primary for a copy site and answers it
// `primary_healthy`.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import { decodeCompactJwt } from "../core-shared/compactJwt.js";
import { actorWorld, readArticle } from "../demo/scenarios/world.js";
import {
  ARTICLES,
  CONTENT_NAME,
  DOMAIN,
  FALLBACK_ISSUER_NAME,
  FALLBACK_UNLOCK_URL,
  HEALTH_URL,
  ISSUER_NAME,
  ORIGIN,
  SIGNING_KID,
  UNLOCK_URL,
  article,
  ungroupedArticle,
} from "../demo/scenarios/fixtures.js";
import { Page } from "../demo/support/Page.js";
import { rootFromPage } from "../demo/support/queryableRoot.js";
import { requestFor } from "../test-lib/harnesses/issuer-endpoint.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import { BrowserUnlockHttp } from "../adapter-issuer/BrowserUnlockHttp.js";
import { sign } from "../core-shared--publisher-issuer/jwt.js";
import { issuerBlockOf, sealedContentByName } from "../test-lib/helpers/inspect.js";
import { keyAt } from "../test-reference/support/namedRecords.js";

const OTHER_DOMAIN = "other-publisher.example";
const OTHER_ORIGIN = `https://${OTHER_DOMAIN}`;

/** A public http origin: canonical, so only the scheme rule can refuse it. */
const HTTP_ORIGIN = "http://publisher.example";

/** One canonical browser IPv6 origin, in the spelling a browser reports. */
const IPV6_ORIGIN = "https://[2001:db8::1]";

/** The delivery origin a development profile runs over. */
const LOCALHOST_ORIGIN = "http://www-default.localhost";

/**
 * Make another immutable delivery of the same render after changing its
 * untrusted dca-data. The publisher origin remains delivery context.
 *
 * @param {Page} page
 * @param {(dcaData: any) => void} change
 */
function changedPage(page, change) {
  const { sealedContent: records, ...dcaData } = page.asJson();
  const sealedContent = sealedContentByName({ sealedContent: records });
  change(dcaData);
  return new Page({ publisherOrigin: page.publisherOrigin, dcaData, sealedContent });
}

/**
 * A policy that grants everything and counts the decisions it was asked for, so
 * "refused before policy" is an assertion rather than a reading of the source.
 */
function countingPolicy() {
  const allowAll = new AllowAllPolicy();
  const asked = { count: 0 };
  return {
    asked,
    policy: {
      /** @param {any} claims @param {any} requested @param {any} input */
      decide(claims, requested, input) {
        asked.count++;
        return allowAll.decide(claims, requested, input);
      },
    },
  };
}

/**
 * Every HTTP response the browser adapter hands back while this is running,
 * headers included. The simulated network carries only status and body, so
 * "no CORS permission left the issuer" is an assertion this way rather than a
 * reading of the source.
 *
 * @returns {{ responses: any[], stop: () => void }}
 */
function adapterResponses() {
  /** @type {any[]} */
  const responses = [];
  const original = BrowserUnlockHttp.prototype.handle;
  /** @this {any} @param {any} request */
  const spy = async function (request) {
    const response = await original.call(this, request);
    responses.push(response);
    return response;
  };
  BrowserUnlockHttp.prototype.handle = spy;
  return {
    responses,
    stop() {
      BrowserUnlockHttp.prototype.handle = original;
    },
  };
}

/**
 * The CORS fields on one adapter response, by lowercase name.
 *
 * @param {any} response
 * @returns {Record<string, string>}
 */
function corsFieldsOf(response) {
  return Object.fromEntries(
    Object.entries(response?.headers ?? {}).filter(([name]) =>
      name.toLowerCase().startsWith("access-control-"),
    ),
  );
}

/**
 * Replace one byte of the signature, so the token no longer verifies under the
 * registration's key and nothing else about it changes.
 *
 * @param {string} token
 * @returns {string}
 */
function flippedSignature(token) {
  const [header, payload, signature] = token.split(".");
  return `${header}.${payload}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
}

/**
 * The actor's coded profile puts exactly the refusal code and issuer name on
 * the wire. A deep equality is deliberate: an origin refusal carrying a
 * partial `keys` or `errors` section is not a refusal that returned no key
 * material.
 *
 * @param {{ status: number, body: unknown }} answer
 * @param {number} status
 * @param {string} code
 * @param {string|null} [issuerName] - null when the adapter or core port owns
 *   the response and therefore has no actor issuer name to put on it
 */
function assertCodedRefusal(answer, status, code, issuerName = ISSUER_NAME) {
  assert.equal(answer.status, status);
  assert.deepEqual(
    answer.body,
    issuerName === null ? { error: code } : { error: code, issuerName },
  );
}

/**
 * A resourceJWT the registered publisher really signed, carrying one changed
 * origin. The demo publisher cannot seal an http origin at all, so the claim
 * this boundary refuses has to be signed here: this tests the
 * issuer's reading of a verified claim, not the publisher's refusal to make it.
 *
 * @param {any} stage
 * @param {any} page
 * @param {string} origin
 * @returns {Promise<any>}
 */
async function requestSignedFor(stage, page, origin) {
  const resourceJWT = await sign(
    { ...page.asJson().resource, origin },
    stage.signingKeys.privateKey,
    {
      kid: SIGNING_KID,
    },
  );
  return { ...requestFor(page), resourceJWT };
}

describe("browser origin and publisher registration composition", () => {
  test("matching origins unlock, while the client cache keeps two page origins apart", async () => {
    const stage = await actorWorld({ domains: [DOMAIN, OTHER_DOMAIN] });
    const firstPage = await stage.publisher.render(article("A"));
    const secondPage = await stage.publisherWith({ domain: OTHER_DOMAIN }).render(article("B"));

    const first = await readArticle(stage.browser, firstPage, [CONTENT_NAME]);
    const second = await readArticle(stage.browser, secondPage, [CONTENT_NAME]);

    assert.equal(first.unlock?.ok, true);
    assert.equal(
      second.unlock?.ok,
      true,
      "another origin does not reuse the first origin's cached period key",
    );
    assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(second.texts[CONTENT_NAME], ARTICLES.B);
    assert.equal(stage.network.stats()[UNLOCK_URL].attempts, 2);
  });

  test("a page carried to a second registered origin is refused before policy and opening key", async () => {
    /** @type {any[]} */
    const refusals = [];
    const { asked, policy } = countingPolicy();
    const stage = await actorWorld({
      domains: [DOMAIN, OTHER_DOMAIN],
      accessPolicy: policy,
      primary: { log: { refused: (/** @type {any} */ record) => refusals.push(record) } },
    });
    const page = await stage.publisher.render(article("A"));
    const root = rootFromPage(page);
    root.location.origin = OTHER_ORIGIN;

    const load = stage.browser.load(root);
    await load.resolve([CONTENT_NAME]);
    const answer = await load.unlock();

    assert.equal(answer.ok, false);
    assert.equal(answer.status, 403);
    assert.deepEqual(refusals, [{ status: 403, code: "origin_refused" }]);
    assert.equal(asked.count, 0, "refused before the access policy");
    assert.equal(stage.keyStores.primary.reachCount, 0, "refused before opening-key work");
  });
  test("every other spelling of the same site is another origin", async () => {
    // No registrable-domain match, no wildcard, no subdomain inheritance and
    // no default-port equivalence: the comparison is over bytes.
    const stage = await actorWorld();
    const page = await stage.publisher.render(article("A"));
    const request = requestFor(page);

    for (const origin of [
      "http://www.news-site.example",
      "https://www.news-site.example:8443",
      "https://news-site.example",
      "https://amp.www.news-site.example",
      "https://www.news-site.example.evil.example",
    ]) {
      const answer = await stage.network.post(UNLOCK_URL, request, { origin });
      assertCodedRefusal(answer, 403, "origin_refused");
    }
    assert.equal(stage.keyStores.primary.reachCount, 0);
  });

  test("an Origin the boundary cannot reduce to one canonical value is refused", async () => {
    const stage = await actorWorld();
    const page = await stage.publisher.render(article("A"));
    const request = requestFor(page);

    for (const origin of [
      undefined,
      "null",
      "www.news-site.example",
      "https://www.news-site.example/",
      `${ORIGIN}, ${OTHER_ORIGIN}`,
    ]) {
      const answer = await stage.network.post(
        UNLOCK_URL,
        request,
        ...(origin === undefined ? [] : [{ origin }]),
      );
      assertCodedRefusal(answer, 403, "origin_refused", null);
    }
    assert.equal(stage.keyStores.primary.reachCount, 0);
  });

  test("the honest render opens at the origin it was signed for", async () => {
    const stage = await actorWorld();
    const page = await stage.publisher.render(article("A"));

    const answer = await stage.network.post(UNLOCK_URL, requestFor(page), { origin: ORIGIN });

    assert.equal(answer.status, 200);
    assert.equal(
      typeof keyAt(answer.body.keys.contentKeys, { contentName: CONTENT_NAME }),
      "string",
    );
  });

  test("two renders of one article, signed old and new, each open only at their own origin", async () => {
    // Migration overlap: the publisher moved host and renders once per
    // origin. Neither render needs an issuer configuration change, and
    // neither opens where the other one does.
    const stage = await actorWorld({ domains: [DOMAIN, OTHER_DOMAIN] });
    const old = await stage.publisher.render(article("A"));
    const fresh = await stage.publisherWith({ domain: OTHER_DOMAIN }).render(article("A"));

    for (const [page, own, foreign] of [
      [old, ORIGIN, OTHER_ORIGIN],
      [fresh, OTHER_ORIGIN, ORIGIN],
    ]) {
      const request = requestFor(/** @type {any} */ (page));
      const opened = await stage.network.post(UNLOCK_URL, request, { origin: own });
      assert.equal(opened.status, 200);
      assert.equal(
        typeof keyAt(opened.body.keys.contentKeys, { contentName: CONTENT_NAME }),
        "string",
      );

      const refused = await stage.network.post(UNLOCK_URL, request, { origin: foreign });
      assertCodedRefusal(refused, 403, "origin_refused");
    }
  });

  test("a registration that pins only a verification key opens the render at its signed origin", async () => {
    // Key location and delivery origin are separate facts. This
    // registration carries the publisher's verification key and no origin
    // of its own - the key was collected from a source the publisher hosts
    // wherever it likes - and the render still opens at the origin its
    // resourceJWT names.
    const stage = await actorWorld();
    assert.equal(stage.publisherRegistration.origins, undefined);

    const page = await stage.publisher.render(article("A"));
    const result = await readArticle(stage.browser, page, [CONTENT_NAME]);

    assert.equal(result.unlock?.ok, true);
    assert.equal(result.texts[CONTENT_NAME], ARTICLES.A);
  });

  test("an issuer-held origin limit refuses an origin it does not list, after the signed comparison", async () => {
    // Two checks over the same origin, and the order says which one is the
    // authority: the signed origin is compared first, so a render signed for an origin
    // the registration does not list is refused for the same reason as any
    // other unlisted origin, and a listed origin the render was not signed
    // for is refused before the limit is consulted at all.
    const stage = await actorWorld({ domains: [DOMAIN, OTHER_DOMAIN], registrationOrigins: true });
    assert.deepEqual(stage.publisherRegistration.origins, [ORIGIN]);

    const other = await stage.publisherWith({ domain: OTHER_DOMAIN }).render(article("B"));
    const opened = await stage.network.post(UNLOCK_URL, requestFor(other), {
      origin: OTHER_ORIGIN,
    });
    assert.equal(opened.status, 200, "a listed origin its own render was signed for still opens");

    const limited = await actorWorld({
      domains: [DOMAIN],
      signingKids: { [DOMAIN]: [SIGNING_KID] },
      registrationOrigins: true,
    });
    const moved = await limited
      .publisherWith({ domain: "https://moved.news-site.example" })
      .render(article("A"));
    const refused = await limited.network.post(UNLOCK_URL, requestFor(moved), {
      origin: "https://moved.news-site.example",
    });

    assertCodedRefusal(refused, 403, "origin_refused");
    assert.equal(limited.keyStores.primary.reachCount, 0);
  });

  test("a signed http origin the observed header matches byte for byte is still refused", async () => {
    // The signed origin equals the observed header, but public HTTP is outside
    // the production origin grammar. Refusal still precedes policy and key use.
    /** @type {any[]} */
    const refusals = [];
    const { asked, policy } = countingPolicy();
    const stage = await actorWorld({
      accessPolicy: policy,
      primary: { log: { refused: (/** @type {any} */ record) => refusals.push(record) } },
    });
    const page = await stage.publisher.render(article("A"));
    const request = await requestSignedFor(stage, page, HTTP_ORIGIN);
    const answer = await stage.network.post(UNLOCK_URL, request, { origin: HTTP_ORIGIN });

    assertCodedRefusal(answer, 400, "bad_jwt");
    assert.deepEqual(refusals, [{ status: 400, code: "bad_jwt" }]);
    assert.equal(stage.keyStores.primary.reachCount, 0);
    assert.equal(asked.count, 0, "refused before the access policy");
  });
  test("a development profile does not widen the http scheme to a public host", async () => {
    // The same render against an issuer running the development profile. A
    // deployment that turned the profile on still cannot be handed
    // `http://publisher.example`.
    const stage = await actorWorld({ primary: { developmentHttpOrigin: true } });
    const page = await stage.publisher.render(article("A"));
    const request = await requestSignedFor(stage, page, HTTP_ORIGIN);

    const answer = await stage.network.post(UNLOCK_URL, request, { origin: HTTP_ORIGIN });

    assertCodedRefusal(answer, 400, "bad_jwt");
    assert.equal(stage.keyStores.primary.reachCount, 0);
  });

  test("a signed http localhost origin opens only under the development profile", async () => {
    // The positive control, and the two together cover the whole option: one
    // render, one observed header, and the issuer's own profile deciding
    // whether the delivery is one it admits.
    const opened = await actorWorld({ primary: { developmentHttpOrigin: true } });
    const development = await opened
      .publisherWith({
        domain: LOCALHOST_ORIGIN,
        developmentHttpOrigin: true,
      })
      .render(article("A"));
    const answer = await opened.network.post(UNLOCK_URL, requestFor(development), {
      origin: LOCALHOST_ORIGIN,
    });

    assert.equal(answer.status, 200);
    assert.equal(
      typeof keyAt(answer.body.keys.contentKeys, { contentName: CONTENT_NAME }),
      "string",
    );

    const production = await actorWorld();
    const page = await production.publisher.render(article("A"));
    const refused = await production.network.post(
      UNLOCK_URL,
      await requestSignedFor(production, page, LOCALHOST_ORIGIN),
      { origin: LOCALHOST_ORIGIN },
    );

    assertCodedRefusal(refused, 400, "bad_jwt");
    assert.equal(production.keyStores.primary.reachCount, 0);
  });

  test("a mismatching origin is refused before policy and opening-key work", async () => {
    const { asked, policy } = countingPolicy();
    const stage = await actorWorld({ periodKeySupply: null, accessPolicy: policy });
    // No supply, so the article names no group and rides its item key.
    const page = await stage.publisher.render(ungroupedArticle("A"));

    const admitted = await stage.network.post(UNLOCK_URL, requestFor(page), { origin: ORIGIN });
    assert.equal(admitted.status, 200);
    assert.equal(asked.count, 1, "an admitted request reaches the access policy");
    assert.ok(
      stage.keyStores.primary.reachCount > 0,
      "an admitted request reaches the opening key",
    );
    const policyCalls = asked.count;
    const keyReaches = stage.keyStores.primary.reachCount;

    const root = rootFromPage(page);
    root.location.origin = OTHER_ORIGIN;

    const load = stage.makeBrowser().load(root);
    await load.resolve([CONTENT_NAME]);
    const refused = await load.unlock();

    assert.equal(refused.ok, false);
    assert.equal(refused.status, 403);
    assert.equal(asked.count, policyCalls, "refused before the access policy");
    assert.equal(stage.keyStores.primary.reachCount, keyReaches, "refused before opening-key work");
  });
  test("an unknown JWT kid refuses before signature or issuer opening-key work", async () => {
    const stage = await actorWorld();
    const page = changedPage(await stage.publisher.render(article("A")), (dcaData) => {
      const token = dcaData.resourceJWT;
      const { header } = decodeCompactJwt(token);
      const [, payload, signature] = token.split(".");
      const encoded = base64urlEncode(
        utf8Encode(JSON.stringify({ ...header, kid: "unknown-publisher-key" })),
      );
      dcaData.resourceJWT = `${encoded}.${payload}.${signature}`;
    });

    const answer = await stage.network.post(UNLOCK_URL, requestFor(page), { origin: ORIGIN });

    assertCodedRefusal(answer, 400, "unknown_publisher_key");
    assert.equal(stage.keyStores.primary.reachCount, 0);
  });

  test("an unsupported alg refuses without asking the registration store", async () => {
    // The order the protocol fixes, observed at the one place that can see
    // it: a store that records what it was asked. A header naming another
    // algorithm is refused on the header, so the lookup that would select
    // a verification key never happens.
    const asked = [];
    /** @type {any} */
    let registrations = null;
    const recording = {
      /** @param {string} kid */
      get(kid) {
        asked.push(kid);
        return registrations.get(kid);
      },
    };
    const stage = await actorWorld({ primary: { publisherRegistrations: recording } });
    registrations = stage.publisherRegistrations;
    const page = await stage.publisher.render(article("A"));

    const honest = await stage.network.post(UNLOCK_URL, requestFor(page), { origin: ORIGIN });
    assert.equal(honest.status, 200);
    assert.deepEqual(
      asked,
      [SIGNING_KID],
      "an admitted header asks the store once, for its own kid",
    );

    const forged = changedPage(page, (dcaData) => {
      const token = dcaData.resourceJWT;
      const { header } = decodeCompactJwt(token);
      const [, payload, signature] = token.split(".");
      const encoded = base64urlEncode(utf8Encode(JSON.stringify({ ...header, alg: "none" })));
      dcaData.resourceJWT = `${encoded}.${payload}.${signature}`;
    });

    const reached = stage.keyStores.primary.reachCount;
    const answer = await stage.network.post(UNLOCK_URL, requestFor(forged), { origin: ORIGIN });

    assertCodedRefusal(answer, 400, "bad_alg");
    assert.deepEqual(asked, [SIGNING_KID], "the refused header added no lookup of its own");
    assert.equal(stage.keyStores.primary.reachCount, reached, "and no opening-key work either");
  });

  test("an unregistered issuer keyId cannot reach the registration opening-key view", async () => {
    const stage = await actorWorld();
    const page = changedPage(await stage.publisher.render(article("A")), (dcaData) => {
      issuerBlockOf(dcaData, ISSUER_NAME).keyId = "co-tenant-key";
    });

    const answer = await stage.network.post(UNLOCK_URL, requestFor(page), { origin: ORIGIN });

    assertCodedRefusal(answer, 503, "unknown_key", null);
    assert.equal(stage.keyStores.primary.reachCount, 0);
  });

  test("a canonical IPv6 origin signs, admits and opens like a domain origin", async () => {
    // Compatibility with a web-platform host spelling. The publisher signs
    // the bracketed literal, the browser reports those same bytes, and the
    // render opens on the comparison every domain origin goes through.
    const stage = await actorWorld({ domains: [DOMAIN, IPV6_ORIGIN] });
    const page = await stage.publisherWith({ domain: IPV6_ORIGIN }).render(article("A"));

    const answer = await stage.network.post(UNLOCK_URL, requestFor(page), { origin: IPV6_ORIGIN });

    assert.equal(answer.status, 200);
    assert.equal(
      typeof keyAt(answer.body.keys.contentKeys, { contentName: CONTENT_NAME }),
      "string",
    );
  });

  test("another literal, port or spelling is another origin, refused before policy and opening key", async () => {
    /** @type {any[]} */
    const refusals = [];
    const { asked, policy } = countingPolicy();
    const stage = await actorWorld({
      domains: [DOMAIN, IPV6_ORIGIN],
      accessPolicy: policy,
      primary: { log: { refused: (/** @type {any} */ record) => refusals.push(record) } },
    });
    const page = await stage.publisherWith({ domain: IPV6_ORIGIN }).render(article("A"));
    const request = requestFor(page);

    for (const origin of ["https://[2001:db8::2]", "https://[2001:db8::1]:8443"]) {
      const answer = await stage.network.post(UNLOCK_URL, request, { origin });
      assertCodedRefusal(answer, 403, "origin_refused");
    }
    for (const origin of ["https://[2001:db8:0:0:0:0:0:1]", "https://[2001:DB8::1]"]) {
      const answer = await stage.network.post(UNLOCK_URL, request, { origin });
      assertCodedRefusal(answer, 403, "origin_refused", null);
    }

    assert.deepEqual(refusals, [
      { status: 403, code: "origin_refused" },
      { status: 403, code: "origin_refused" },
    ]);
    assert.equal(stage.keyStores.primary.reachCount, 0, "refused before opening-key work");
    assert.equal(asked.count, 0, "refused before the access policy");
  });
  test("another origin reaches no fallback probe or health read, cold and primed", async () => {
    const stage = await actorWorld();
    const stood = await stage.standUp(FALLBACK_ISSUER_NAME, FALLBACK_UNLOCK_URL, {
      role: "fallback",
      healthCheckUrl: HEALTH_URL,
    });
    const fallback = stood.server;
    const page = await stage.publisher.render(article("A"));
    const request = requestFor(page, FALLBACK_ISSUER_NAME);

    const refused = await stage.network.post(FALLBACK_UNLOCK_URL, request, {
      origin: OTHER_ORIGIN,
    });
    assertCodedRefusal(refused, 403, "origin_refused", FALLBACK_ISSUER_NAME);
    assert.equal(fallback.stats().probes, 0);
    assert.equal(fallback.stats().healthReads, 0);

    const admitted = await stage.network.post(FALLBACK_UNLOCK_URL, request, { origin: ORIGIN });
    assert.equal(admitted.status, 403);
    assert.equal(admitted.body.error, "primary_healthy");
    const before = fallback.stats();
    assert.equal(before.probes, 1);

    const again = await stage.network.post(FALLBACK_UNLOCK_URL, request, { origin: OTHER_ORIGIN });
    assertCodedRefusal(again, 403, "origin_refused", FALLBACK_ISSUER_NAME);
    assert.equal(fallback.stats().probes - before.probes, 0);
    assert.equal(fallback.stats().healthReads - before.healthReads, 0);
  });
  test("no refusal before the verified signed-origin match carries CORS permission", async () => {
    // A page on another origin reads a response only when it carries CORS
    // permission for that page. Before the issuer has verified the resource
    // assertion and matched its signed origin to the observed one, nothing
    // it says may be readable there: under credentials, a readable 401 would
    // tell a copy site whether its visitor holds an issuer session. Each
    // refusal below keeps the status and code it always had.
    const stage = await actorWorld({ domains: [DOMAIN, OTHER_DOMAIN] });
    const page = await stage.publisher.render(article("A"));
    const request = requestFor(page);
    const unknownKid = changedPage(page, (dcaData) => {
      const token = dcaData.resourceJWT;
      const { header } = decodeCompactJwt(token);
      const [, payload, signature] = token.split(".");
      const encoded = base64urlEncode(
        utf8Encode(JSON.stringify({ ...header, kid: "unknown-publisher-key" })),
      );
      dcaData.resourceJWT = `${encoded}.${payload}.${signature}`;
    });

    const gated = await actorWorld({ primary: { requireAuthentication: true } });
    const gatedPage = await gated.publisher.render(article("A"));

    const limited = await actorWorld({
      domains: [DOMAIN],
      signingKids: { [DOMAIN]: [SIGNING_KID] },
      registrationOrigins: true,
    });
    const moved = await limited
      .publisherWith({ domain: "https://moved.news-site.example" })
      .render(article("A"));

    const cases = [
      {
        label: "a body structural admission refuses",
        send: () =>
          stage.network.post(
            UNLOCK_URL,
            { version: "1", sealed: { contentKeys: [{ contentName: "a", key: "b" }] } },
            { origin: ORIGIN },
          ),
        status: 400,
        code: "out_of_scope_issuer",
        issuerName: null,
      },
      {
        label: "a kid no registration holds",
        send: () => stage.network.post(UNLOCK_URL, requestFor(unknownKid), { origin: ORIGIN }),
        status: 400,
        code: "unknown_publisher_key",
      },
      {
        label: "a caller the issuer requires and cannot identify",
        send: () => gated.network.post(UNLOCK_URL, requestFor(gatedPage), { origin: ORIGIN }),
        status: 401,
        code: "unauthenticated",
      },
      {
        label: "a signature the registration's key refuses",
        send: () =>
          stage.network.post(
            UNLOCK_URL,
            { ...request, resourceJWT: flippedSignature(request.resourceJWT) },
            { origin: ORIGIN },
          ),
        status: 400,
        code: "bad_signature",
      },
      {
        label: "a registered, canonical origin the publisher did not sign",
        send: () => stage.network.post(UNLOCK_URL, request, { origin: OTHER_ORIGIN }),
        status: 403,
        code: "origin_refused",
      },
      {
        label: "a signed origin the registration's own limit does not list",
        send: () =>
          limited.network.post(UNLOCK_URL, requestFor(moved), {
            origin: "https://moved.news-site.example",
          }),
        status: 403,
        code: "origin_refused",
      },
    ];

    // One row per case, compared as a table, so a failure shows every case
    // that leaked rather than the first.
    const observed = [];
    for (const { label, send, status, code, issuerName } of cases) {
      const spy = adapterResponses();
      /** @type {any} */
      let answer;
      try {
        answer = await send();
      } finally {
        spy.stop();
      }
      assertCodedRefusal(answer, status, code, issuerName);
      assert.equal(spy.responses.length, 1, `${label}: one adapter response`);
      observed.push({
        label,
        cors: corsFieldsOf(spy.responses[0]),
        vary: spy.responses[0].headers?.vary,
      });
    }
    assert.deepEqual(
      observed,
      cases.map(({ label }) => ({ label, cors: {}, vary: "Origin" })),
    );
    assert.equal(stage.keyStores.primary.reachCount, 0);
  });

  test("after the verified match, a grant and a denial carry exact-origin CORS", async () => {
    // The positive control for every empty field set above. Once the signed
    // origin equals the observed one, the page at that exact origin may read
    // the answer, whether it holds keys or refuses them.
    const denying = {
      decide: () => ({ contentNames: [], periodGrants: [] }),
    };
    const stage = await actorWorld();
    const refusing = await actorWorld({ accessPolicy: denying });
    const page = await stage.publisher.render(article("A"));
    const refusedPage = await refusing.publisher.render(article("A"));

    const spy = adapterResponses();
    /** @type {any} */
    let granted;
    /** @type {any} */
    let denied;
    try {
      granted = await stage.network.post(UNLOCK_URL, requestFor(page), { origin: ORIGIN });
      denied = await refusing.network.post(UNLOCK_URL, requestFor(refusedPage), {
        origin: ORIGIN,
      });
    } finally {
      spy.stop();
    }

    assert.equal(granted.status, 200);
    assert.equal(denied.status, 401);
    assert.equal(denied.body.error, "denied");
    for (const response of spy.responses) {
      assert.deepEqual(corsFieldsOf(response), {
        "access-control-allow-origin": ORIGIN,
        "access-control-allow-credentials": "true",
      });
      assert.equal(response.headers.vary, "Origin");
    }
    assert.equal(spy.responses.length, 2);
  });
});
