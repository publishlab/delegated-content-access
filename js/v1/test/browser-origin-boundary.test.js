// @ts-check
//
// The browser origin, from the value the publisher signed to the header the
// issuer observes. The issuer treats `resourceJWT.origin` as the authority: it
// selects a registration by the untrusted header `kid`, verifies the exact token
// with that registration's key, reads the origin out of the verified payload, and requires
// the observed HTTP `Origin` to equal it byte for byte before the response
// cache, the access policy or any issuer opening key.
//
// Each case here catches one wrong issuer. An issuer reading the expected
// origin off its own registration passes every honest case and lets a
// publisher that registered two origins serve one render from either. An
// issuer comparing hosts rather than bytes admits `http` for `https`, a
// non-default port and a subdomain. An issuer that compares after its
// response-cache lookup answers a copy site out of the cache. A fallback
// issuer that decides its health gate before the comparison probes its primary
// for a copy site and answers it `primary_healthy`.

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
} from "../demo/scenarios/fixtures.js";
import { Page } from "../demo/support/Page.js";
import { rootFromPage } from "../demo/support/queryableRoot.js";
import { requestFor } from "../test-lib/harnesses/issuer-endpoint.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import { IssuerResponseCache } from "../demo/actors/issuer/IssuerResponseCache.js";
import { sign } from "../core-shared--publisher-issuer/jwt.js";

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
  const { sealedContent, ...dcaData } = page.asJson();
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
 * Every response-cache call while this is running, counted on the class the
 * server builds its own cache from. The server keeps that cache to itself, so
 * "the cache was never consulted" is an assertion this way rather than a
 * reading of the source.
 *
 * @returns {{ counts: Record<string, number>, stop: () => Record<string, number> }}
 */
function responseCacheMeter() {
  /** @type {Record<string, number>} */
  const counts = { keyFor: 0, get: 0, put: 0 };
  /** @type {Record<string, Function>} */
  const originals = {};

  for (const name of Object.keys(counts)) {
    const original = /** @type {any} */ (IssuerResponseCache.prototype)[name];
    originals[name] = original;
    /** @this {any} @param {...any} args */
    const spy = function (...args) {
      counts[name]++;
      return original.apply(this, args);
    };
    /** @type {any} */ (IssuerResponseCache.prototype)[name] = spy;
  }

  return {
    counts,
    stop() {
      for (const [name, original] of Object.entries(originals)) {
        /** @type {any} */ (IssuerResponseCache.prototype)[name] = original;
      }
      return counts;
    },
  };
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

  test("a page carried to a second registered origin is refused before cache, policy and opening key", async () => {
    // Both origins are registered here, and neither registration carries an
    // origin limit, so nothing but the origin the publisher signed can
    // answer this request. The counters below are the order: the response
    // cache, the access policy and the issuer's private key were all still
    // untouched when the refusal landed.
    /** @type {any[]} */
    const refusals = [];
    const { asked, policy } = countingPolicy();
    const stage = await actorWorld({
      domains: [DOMAIN, OTHER_DOMAIN],
      accessPolicy: policy,
      primary: {
        log: { refused: (/** @type {any} */ record) => refusals.push(record) },
        responseCache: { ttl: 60_000 },
      },
    });
    const page = await stage.publisher.render(article("A"));
    const root = rootFromPage(page);
    root.location.origin = OTHER_ORIGIN;

    const load = stage.browser.load(root);
    await load.resolve([CONTENT_NAME]);
    const meter = responseCacheMeter();
    /** @type {any} */
    let answer;
    try {
      answer = await load.unlock();
    } finally {
      meter.stop();
    }

    assert.equal(answer.ok, false);
    assert.equal(answer.status, 403);
    assert.deepEqual(refusals, [{ status: 403, code: "origin_refused" }]);
    assert.equal(stage.keyStores.primary.reachCount, 0);
    assert.equal(asked.count, 0, "refused before the access policy");
    assert.deepEqual(
      meter.counts,
      { keyFor: 0, get: 0, put: 0 },
      "refused before the response cache",
    );
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
    assert.equal(typeof answer.body.keys.contentKeys[CONTENT_NAME], "string");
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
      assert.equal(typeof opened.body.keys.contentKeys[CONTENT_NAME], "string");

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
    // The comparison passes here: the publisher signed `http://publisher.example`
    // and the browser reported it. The scheme rule of the format's Origin
    // grammar refuses this render, and no development profile widens it to a
    // public host - so the refusal lands before the response cache, the access
    // policy and the issuer's private key, exactly where a non-canonical signed
    // origin lands.
    /** @type {any[]} */
    const refusals = [];
    const { asked, policy } = countingPolicy();
    const stage = await actorWorld({
      accessPolicy: policy,
      primary: {
        log: { refused: (/** @type {any} */ record) => refusals.push(record) },
        responseCache: { ttl: 60_000 },
      },
    });
    const page = await stage.publisher.render(article("A"));
    const request = await requestSignedFor(stage, page, HTTP_ORIGIN);

    const meter = responseCacheMeter();
    /** @type {any} */
    let answer;
    try {
      answer = await stage.network.post(UNLOCK_URL, request, { origin: HTTP_ORIGIN });
    } finally {
      meter.stop();
    }

    assertCodedRefusal(answer, 400, "bad_jwt");
    assert.deepEqual(refusals, [{ status: 400, code: "bad_jwt" }]);
    assert.equal(stage.keyStores.primary.reachCount, 0);
    assert.equal(asked.count, 0, "refused before the access policy");
    assert.deepEqual(
      meter.counts,
      { keyFor: 0, get: 0, put: 0 },
      "refused before the response cache",
    );
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
    assert.equal(typeof answer.body.keys.contentKeys[CONTENT_NAME], "string");

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

  test("a mismatching origin cannot take an already cached issuer answer", async () => {
    const stage = await actorWorld({
      periodKeySupply: null,
      primary: { responseCache: { ttl: 60_000 } },
    });
    const page = await stage.publisher.render(article("A"));

    // The positive control for every all-zero count in this file. The meter
    // watches the class the server builds its cache from, so a request the
    // origin comparison admits has to move it. A meter reading zero here would
    // be watching methods nobody calls, and the zeros below would say nothing.
    const priming = responseCacheMeter();
    /** @type {any} */
    let first;
    try {
      first = await readArticle(stage.makeBrowser(), page, [CONTENT_NAME]);
    } finally {
      priming.stop();
    }
    assert.equal(first.unlock?.ok, true);
    for (const call of ["keyFor", "get", "put"]) {
      assert.ok(
        priming.counts[call] > 0,
        `an admitted request reaches the response cache: ${call} of ${JSON.stringify(priming.counts)}`,
      );
    }

    const root = rootFromPage(page);
    root.location.origin = OTHER_ORIGIN;
    const load = stage.makeBrowser().load(root);
    await load.resolve([CONTENT_NAME]);
    const meter = responseCacheMeter();
    /** @type {any} */
    let refused;
    try {
      refused = await load.unlock();
    } finally {
      meter.stop();
    }

    assert.equal(refused.ok, false);
    assert.equal(refused.status, 403);
    assert.deepEqual(
      meter.counts,
      { keyFor: 0, get: 0, put: 0 },
      "the primed response cache was not consulted",
    );
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
      dcaData.issuerData[ISSUER_NAME].keyId = "co-tenant-key";
    });

    const answer = await stage.network.post(UNLOCK_URL, requestFor(page), { origin: ORIGIN });

    assertCodedRefusal(answer, 400, "unknown_key", null);
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
    assert.equal(typeof answer.body.keys.contentKeys[CONTENT_NAME], "string");
  });

  test("another literal, port or spelling is another origin, refused before cache, policy and opening key", async () => {
    // The comparison is over bytes here as everywhere: a neighbouring
    // address, the same address on another port and two spellings a browser
    // never sends are four other origins. None of them reaches the response
    // cache, the access policy or the issuer's private key.
    /** @type {any[]} */
    const refusals = [];
    const { asked, policy } = countingPolicy();
    const stage = await actorWorld({
      domains: [DOMAIN, IPV6_ORIGIN],
      accessPolicy: policy,
      primary: {
        log: { refused: (/** @type {any} */ record) => refusals.push(record) },
        responseCache: { ttl: 60_000 },
      },
    });
    const page = await stage.publisherWith({ domain: IPV6_ORIGIN }).render(article("A"));
    const request = requestFor(page);

    const meter = responseCacheMeter();
    try {
      for (const origin of ["https://[2001:db8::2]", "https://[2001:db8::1]:8443"]) {
        const answer = await stage.network.post(UNLOCK_URL, request, { origin });
        assertCodedRefusal(answer, 403, "origin_refused");
      }
      for (const origin of ["https://[2001:db8:0:0:0:0:0:1]", "https://[2001:DB8::1]"]) {
        const answer = await stage.network.post(UNLOCK_URL, request, { origin });
        assertCodedRefusal(answer, 403, "origin_refused", null);
      }
    } finally {
      meter.stop();
    }

    // The first two are canonical origins that are not the signed one, so
    // the issuer refuses them on the signed comparison and logs it. The
    // last two are spellings a browser never sends, turned away by the
    // HTTP boundary before any issuer work at all - which is why the log
    // carries two entries and not four.
    assert.deepEqual(refusals, [
      { status: 403, code: "origin_refused" },
      { status: 403, code: "origin_refused" },
    ]);
    assert.equal(stage.keyStores.primary.reachCount, 0);
    assert.equal(asked.count, 0, "refused before the access policy");
    assert.deepEqual(
      meter.counts,
      { keyFor: 0, get: 0, put: 0 },
      "refused before the response cache",
    );
  });
});

describe("browser origin and the fallback health gate", () => {
  test("another origin reaches no fallback probe, health read or response cache, cold and primed", async () => {
    // The primary is up, so a request this fallback is allowed to consider
    // is answered `primary_healthy`. A request carrying another origin is
    // not one of those: the comparison refuses it ahead of the probe, the
    // health it caches and the response cache it keeps.
    const stage = await actorWorld();
    const stood = await stage.standUp(FALLBACK_ISSUER_NAME, FALLBACK_UNLOCK_URL, {
      role: "fallback",
      healthCheckUrl: HEALTH_URL,
      responseCache: { ttl: 60_000 },
    });
    const fallback = stood.server;

    const page = await stage.publisher.render(article("A"));
    const request = requestFor(page, FALLBACK_ISSUER_NAME);

    const cold = responseCacheMeter();
    /** @type {any} */
    let refused;
    try {
      refused = await stage.network.post(FALLBACK_UNLOCK_URL, request, { origin: OTHER_ORIGIN });
    } finally {
      cold.stop();
    }

    assertCodedRefusal(refused, 403, "origin_refused", FALLBACK_ISSUER_NAME);
    assert.equal(fallback.stats().probes, 0);
    assert.equal(fallback.stats().healthReads, 0);
    assert.deepEqual(cold.counts, { keyFor: 0, get: 0, put: 0 });

    // The same render at the origin it was signed for: through the
    // comparison, into the gate, and refused there for the reason this
    // fallback exists to refuse for. The probe it costs is what primes the
    // health the next request could have read.
    const admitted = await stage.network.post(FALLBACK_UNLOCK_URL, request, { origin: ORIGIN });
    assert.equal(admitted.status, 403);
    assert.equal(admitted.body.error, "primary_healthy");
    const before = fallback.stats();
    assert.equal(before.probes, 1);

    const warm = responseCacheMeter();
    /** @type {any} */
    let again;
    try {
      again = await stage.network.post(FALLBACK_UNLOCK_URL, request, { origin: OTHER_ORIGIN });
    } finally {
      warm.stop();
    }

    assertCodedRefusal(again, 403, "origin_refused", FALLBACK_ISSUER_NAME);
    assert.equal(fallback.stats().probes - before.probes, 0);
    assert.equal(
      fallback.stats().healthReads - before.healthReads,
      0,
      "the held answer was not read either",
    );
    assert.deepEqual(warm.counts, { keyFor: 0, get: 0, put: 0 });
  });
});
