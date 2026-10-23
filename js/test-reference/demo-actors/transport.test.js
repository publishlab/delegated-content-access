//
// The wire, and what happens when it stops working. Two stateful ends with a
// `Network` between them, a breaker on the client, and a fallback issuer that
// will not grant anything until it has checked the primary itself.
//
// Everything here is deterministic. No timer fires anywhere: a slow url is a
// latency compared against the caller's timeout budget at call time, and the
// cost of waiting is spent on the injected `Clock` rather than in real seconds.
// So "the breaker half-opens after its window" is an arithmetic statement about
// two numbers, not a race the test hopes to win.
//
// A world starts with the network up and fast, the breaker quiet, no fallback
// wired, and the clock standing still. Every one of those is turned on below by
// the test that needs it. The wiring comes from
// `demo/scenarios/world.js`'s actor family - this file's own knobs are the breaker,
// the fallback and the two policies, and nothing here builds a world of its own.
//
// The whole outage runs from a scenario module. Every test above it turns on
// one piece - the breaker, the trim, the catch-22 - and the last one is all of
// them in one run, which is why its steps live in `demo/scenarios/failover.js`
// rather than here: it carries no assertions and the demo page can take the
// same steps. What is asserted below is the trace it hands back.
//
// What an issuer answers a keyId with - held, retired or never held - is
// rotation.test.js's axis, and nothing here asserts it.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Clock } from "../../demo/actors/Clock.js";
import { Network } from "../../demo/actors/Network.js";
import { Page } from "../../demo/support/Page.js";
import { PageLoad } from "../../demo/actors/PageLoad.js";
import { IssuerServer } from "../../demo/actors/IssuerServer.js";
import { Browser } from "../../demo/actors/Browser.js";
import { MarkupDeliveryReader } from "../../adapter-client/MarkupDeliveryReader.js";
import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { DcaData } from "../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../core-client/DcaRequestBuilder.js";
import { formatT } from "../../core-shared--publisher-issuer/periodKeys.js";
import { trimToCurrentPeriod } from "../../demo/actors/issuer/trimToCurrentPeriod.js";
import { base64urlEncode } from "../../core-shared/codec.js";
import { actorWorld, readArticle } from "../../demo/scenarios/world.js";
import { rootFromPage } from "../../demo/support/queryableRoot.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { periodKeyMap } from "../support/namedRecords.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  AT,
  CONTENT_NAME,
  DOMAIN,
  FALLBACK_ISSUER_NAME as FALLBACK,
  FALLBACK_UNLOCK_URL as FALLBACK_UNLOCK,
  HEALTH_URL as PRIMARY_HEALTH,
  ISSUER_NAME as PRIMARY,
  UNLOCK_URL as PRIMARY_UNLOCK,
  article,
} from "../../demo/scenarios/fixtures.js";

const SECOND = 1000;
const clientBoundProfileStub = {
  METHOD: "test-only-client-bound",
  RANDOM_REQUIRED: false,
  seal() {
    throw new Error("client-bound profile stub reached");
  },
};

/**
 * The publisher the failover story names, folded the way the resolver folds it
 * before the cache files a key. A cache holds keys under this publisher, then
 * under its accessGroup.
 */
const PUB = `https://${DOMAIN}`;
const PUBLISHER_ORIGIN = PUB;

/**
 * The request a load would post, without posting it. Used to show the port
 * answering the same thing off the wire as on it.
 *
 * @param {any} browser
 * @param {Page} page
 * @param {string} [issuerName] - which issuer's blobs the request carries
 * @returns {Promise<any>}
 */
async function unlockRequestOf(browser, page, issuerName) {
  /** @type {any} */
  let captured = null;

  // A client of its own, over a network that keeps what it was handed and
  // then refuses to deliver it. Capturing the request the load built keeps
  // this from rebuilding one that has drifted from the real thing.
  const network = {
    post: (/** @type {string} */ url, /** @type {any} */ payload) => {
      void url;
      captured = payload;
      throw Object.assign(new Error("captured"), { code: "offline" });
    },
  };
  const capturing = new Browser({
    clock: new Clock(AT),
    network: /** @type {any} */ (network),
    issuers: browser.issuers,
    relayPeriodKeys: true,
  });
  const capture = capturing.load(rootFromPage(page));
  await capture.resolve([CONTENT_NAME]);
  await capture.unlock(issuerName === undefined ? {} : { issuerName });

  return captured;
}

test("a content key one unlock delivered is not re-requested by the next walk", async () => {
  const { browser, render } = await actorWorld();
  const page = await render("A");

  /** @type {any[]} */
  const posted = [];
  const network = {
    post: async (/** @type {string} */ url, /** @type {any} */ payload) => {
      void url;
      posted.push(payload);
      // A grant that hands over a content key for this render and no period
      // key: the resolver holds it, and nothing reaches the cache. A second
      // walk should find it already in hand rather than asking again.
      return {
        status: 200,
        body: {
          keys: {
            contentKeys: [
              { contentName: CONTENT_NAME, key: base64urlEncode(new Uint8Array(16).fill(4)) },
            ],
          },
        },
      };
    },
  };
  const client = new Browser({
    clock: new Clock(AT),
    network: /** @type {any} */ (network),
    issuers: browser.issuers,
  });
  const load = client.load(rootFromPage(page));

  await load.resolve([CONTENT_NAME]);

  const first = await load.unlock();
  assert.equal(first.ok, true);
  assert.ok(
    posted[0].sealed.contentKeys.some(
      (/** @type {any} */ record) => record.contentName === CONTENT_NAME,
    ),
    "the first unlock asked for the content key",
  );

  // The content key is held now, so a re-resolve covers the item. The next
  // unlock has no eligible coordinate and never reaches the network.
  const postsBeforeSecondUnlock = posted.length;
  const second = await load.unlock();
  assert.equal(posted.length, postsBeforeSecondUnlock, "the held key was not re-requested");
  assert.ok(second.attempts.length > 0);
  assert.ok(second.attempts.every(({ outcome }) => outcome === "no-eligible-route"));
});

describe("Page - inert", () => {
  test("a Page is data, and reaches the wire as plain JSON", async () => {
    const { render } = await actorWorld();
    const page = await render("A");

    const json = page.asJson();
    assert.equal(typeof json, "object");
    assert.equal(json.version, "1");
    assert.ok(Array.isArray(json.sealedContent), "the ciphertext travels as records");
    assert.equal(
      typeof json.sealedContent.find((record) => record.contentName === CONTENT_NAME)?.content,
      "string",
    );
    assert.deepEqual(
      JSON.parse(JSON.stringify(json)),
      json,
      "nothing in it needs encoding on the way out",
    );

    // The same page read twice is the same page, and reading it changes
    // nothing. A second read hands back an equal object rather than the same
    // one, so a caller cannot reach through it into the render.
    assert.deepEqual(page.asJson(), json);
    assert.notEqual(page.asJson(), json);

    assert.throws(
      () =>
        new Page({
          publisherOrigin: PUBLISHER_ORIGIN,
          dcaData: {},
          /** @type {any} */ sealedContent: {},
          extra: 1,
        }),
      (/** @type {any} */ err) => err.code === "unsupported_option",
    );
    assert.throws(
      () => new Page({ publisherOrigin: PUBLISHER_ORIGIN, /** @type {any} */ sealedContent: {} }),
      (/** @type {any} */ err) => err.code === "bad_config",
    );
    assert.throws(
      () =>
        new Page({
          publisherOrigin: "https://publisher.example/path",
          dcaData: {},
          sealedContent: {},
        }),
      (/** @type {any} */ err) => err.code === "bad_config",
    );

    // The construction-time promise, held to what JSON.stringify would not
    // catch on its own: stringify launders a Uint8Array into {"0":...} and a
    // CryptoKey into {}, so a render carrying one has to fail here, loudly and
    // with the path, not at a client three layers on.
    assert.throws(
      () =>
        new Page({
          publisherOrigin: PUBLISHER_ORIGIN,
          dcaData: { leak: new Uint8Array([1, 2, 3]) },
          sealedContent: {},
        }),
      (/** @type {any} */ err) => err.code === "unsafe_payload" && /leak/.test(err.message),
      "a render holding live bytes never becomes a page",
    );
  });
});

describe("Network - routing, reachability per caller, wire safety, cost", () => {
  test("the network routes a url to what serves it, and counts what crossed", async () => {
    const clock = new Clock(AT);
    const network = new Network({ clock });
    const caller = { who: "a browser" };

    network.serve("https://api.example.com/unlock", (payload) => ({
      status: 200,
      body: { echo: payload.hello },
    }));

    const answer = await network.post(
      "https://api.example.com/unlock",
      { hello: "there" },
      { from: caller, origin: PUBLISHER_ORIGIN },
    );
    assert.deepEqual(answer, { status: 200, body: { echo: "there" } });

    const stats = network.stats()["https://api.example.com/unlock"];
    assert.equal(stats.attempts, 1);
    assert.equal(stats.probes, 0);
    assert.equal(stats.failures, 0);
    assert.equal(stats.requestBytes, JSON.stringify({ hello: "there" }).length);
    assert.equal(stats.responseBytes, JSON.stringify({ echo: "there" }).length);

    // A url nobody serves is a typed failure, not a hang and not a 404 the
    // caller has to tell apart from an issuer's own answer.
    await assert.rejects(
      () =>
        network.post(
          "https://nowhere.example.com/unlock",
          {},
          { from: caller, origin: PUBLISHER_ORIGIN },
        ),
      (/** @type {any} */ err) => err.code === "no_route",
    );
    assert.equal(network.stats()["https://nowhere.example.com/unlock"].failures, 1);

    assert.throws(
      () => network.serve("https://api.example.com/unlock", () => ({ status: 200, body: {} })),
      (/** @type {any} */ err) => err.code === "bad_config",
      "two servers on one url is a wiring mistake, not a race",
    );
    assert.throws(
      () => new Network({}),
      (/** @type {any} */ err) => err.code === "bad_config",
    );
  });

  test("the wire really serialises: neither side ever holds the other's object", async () => {
    // The property every cross-boundary test in this suite silently rests on.
    // A wire that handed the live object across would make "the server saw
    // what the client sent" compare a thing to itself, let a handler read the
    // caller's later mutations, and let a cached response body be shared
    // between callers. So it is pinned here, in both directions, as identity
    // and as isolation.
    const clock = new Clock(AT);
    const network = new Network({ clock });

    const url = "https://api.example.com/unlock";
    const sent = { hello: "there", nested: { deep: true } };
    const served = { granted: ["bodytext"], nested: { deep: true } };

    /** @type {any} */
    let received;
    /** @type {any} */
    let receivedCredential;
    network.serve(url, (payload, context) => {
      received = payload;
      receivedCredential = context.credential;
      return { status: 200, body: served };
    });

    const credential = { token: "reader-1" };
    const answer = await network.post(url, sent, { credential, origin: PUBLISHER_ORIGIN });

    // Equal bytes, different objects - in, out, and beside (the credential).
    assert.deepEqual(received, sent);
    assert.notEqual(
      received,
      sent,
      "the handler gets a parse of the wire string, not the caller's object",
    );
    assert.notEqual(received.nested, sent.nested, "all the way down");
    assert.deepEqual(receivedCredential, credential);
    assert.notEqual(receivedCredential, credential, "a credential crosses like a header: as bytes");
    assert.deepEqual(answer.body, served);
    assert.notEqual(answer.body, served, "and the response comes back the same way");
    assert.notEqual(answer.body.nested, served.nested);

    // The identity split buys isolation: a mutation after the call stays on
    // its own side.
    sent.hello = "changed";
    served.granted.push("locked-data");
    assert.equal(received.hello, "there");
    assert.deepEqual(answer.body.granted, ["bodytext"]);
  });

  test("document routes receive serialized JSON text while ordinary routes stay parsed", async () => {
    const network = new Network({ clock: new Clock(AT) });
    const url = "https://api.example.com/document";
    const sent = { title: "café 🐾" };
    const expected = JSON.stringify(sent);
    let document;
    let parsed;
    network.serveDocument(url, (value) => {
      document = value;
      return { status: 200, body: { ok: true } };
    });
    network.serve(`${url}/parsed`, (value) => {
      parsed = value;
      return { status: 200, body: {} };
    });
    await network.post(url, sent);
    await network.post(`${url}/parsed`, sent);
    assert.equal(document, expected);
    assert.equal(
      new TextEncoder().encode(document).length,
      new TextEncoder().encode(expected).length,
    );
    assert.deepEqual(parsed, sent);
    assert.notEqual(parsed, sent);
  });

  test("reachability is per caller, so a url can be up for one and down for another", async () => {
    const clock = new Clock(AT);
    const network = new Network({ clock });
    const browser = { who: "browser" };
    const fallback = { who: "fallback issuer" };

    network.serve(PRIMARY_HEALTH, () => ({ status: 200, body: { healthy: true } }));

    // The default is up for everyone, which is what a world nobody has broken
    // yet asks of it.
    assert.equal((await network.probe(PRIMARY_HEALTH, { from: browser })).status, 200);
    assert.equal((await network.probe(PRIMARY_HEALTH, { from: fallback })).status, 200);

    network.offline(PRIMARY_HEALTH, { from: browser });
    await assert.rejects(
      () => network.probe(PRIMARY_HEALTH, { from: browser }),
      (/** @type {any} */ err) => err.code === "offline",
    );
    assert.equal(
      (await network.probe(PRIMARY_HEALTH, { from: fallback })).status,
      200,
      "the other vantage is fine",
    );

    network.online(PRIMARY_HEALTH, { from: browser });
    assert.equal((await network.probe(PRIMARY_HEALTH, { from: browser })).status, 200);

    // Without a caller the condition is the url's own, and setting it clears
    // the exceptions carved on it: the world first, then who differs from it.
    network.offline(PRIMARY_HEALTH);
    await assert.rejects(
      () => network.probe(PRIMARY_HEALTH, { from: fallback }),
      (/** @type {any} */ err) => err.code === "offline",
    );
    network.online(PRIMARY_HEALTH, { from: fallback });
    assert.equal((await network.probe(PRIMARY_HEALTH, { from: fallback })).status, 200);
    await assert.rejects(
      () => network.probe(PRIMARY_HEALTH, { from: browser }),
      (/** @type {any} */ err) => err.code === "offline",
    );

    // Probes are counted apart from attempts: "how often did the fallback ask"
    // is a different question from "how often did a client try to unlock".
    const stats = network.stats()[PRIMARY_HEALTH];
    assert.equal(stats.attempts, 0);
    assert.equal(stats.probes, 8);
  });

  test("slow is arithmetic against the clock: a latency past the budget is a timeout, and it costs the budget", async () => {
    const clock = new Clock(AT);
    const network = new Network({ clock });
    const caller = { who: "browser" };
    const at = () => clock.now().getTime();
    const started = at();

    network.serve(PRIMARY_UNLOCK, () => ({ status: 200, body: { ok: true } }));

    // Fast by default: an answer costs nothing, so a test that is not about
    // latency never has to think about the clock.
    await network.post(
      PRIMARY_UNLOCK,
      {},
      { from: caller, timeout: 2 * SECOND, origin: PUBLISHER_ORIGIN },
    );
    assert.equal(at(), started, "a healthy url is instant");

    // Slow but inside the budget: the answer arrives, and the caller waited
    // exactly the latency. Nothing was timed - the advance is the number the
    // scenario configured.
    network.slow(PRIMARY_UNLOCK, 1500, { from: caller });
    await network.post(
      PRIMARY_UNLOCK,
      {},
      { from: caller, timeout: 2 * SECOND, origin: PUBLISHER_ORIGIN },
    );
    assert.equal(at() - started, 1500);

    // Past the budget: the caller gives up when its budget runs out, so the
    // cost is the timeout and never the latency.
    network.slow(PRIMARY_UNLOCK, 5 * SECOND, { from: caller });
    await assert.rejects(
      () =>
        network.post(
          PRIMARY_UNLOCK,
          {},
          { from: caller, timeout: 2 * SECOND, origin: PUBLISHER_ORIGIN },
        ),
      (/** @type {any} */ err) => err.code === "timeout",
    );
    assert.equal(at() - started, 3500, "the budget, not the latency");

    // A caller with no budget has all the time in the world, and waits the
    // latency out.
    await network.post(PRIMARY_UNLOCK, {}, { from: caller, origin: PUBLISHER_ORIGIN });
    assert.equal(at() - started, 8500);

    // An unreachable url refuses at once. A host that accepts and never answers
    // is `slow` past the budget, which is the other failure.
    network.offline(PRIMARY_UNLOCK, { from: caller });
    await assert.rejects(
      () =>
        network.post(
          PRIMARY_UNLOCK,
          {},
          { from: caller, timeout: 2 * SECOND, origin: PUBLISHER_ORIGIN },
        ),
      (/** @type {any} */ err) => err.code === "offline",
    );
    assert.equal(at() - started, 8500, "a refused connection costs nothing");

    // `healthy` puts a url back the way it started, latency and all; `online`
    // only lifts the outage.
    network.healthy(PRIMARY_UNLOCK, { from: caller });
    await network.post(
      PRIMARY_UNLOCK,
      {},
      { from: caller, timeout: 2 * SECOND, origin: PUBLISHER_ORIGIN },
    );
    assert.equal(at() - started, 8500);

    assert.equal(network.stats()[PRIMARY_UNLOCK].failures, 2);
  });

  test("wire safety is always on: a stray Uint8Array or CryptoKey fails at the seam", async () => {
    const clock = new Clock(AT);
    const network = new Network({ clock });
    const caller = { who: "browser" };
    const key = await globalThis.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );

    network.serve(PRIMARY_UNLOCK, () => ({ status: 200, body: { ok: true } }));

    for (const [label, payload] of [
      [
        "raw key bytes",
        { sealed: { contentKeys: [{ contentName: "bodytext", key: new Uint8Array(16) }] } },
      ],
      ["a CryptoKey", { keys: { contentKeys: [{ contentName: "bodytext", key }] } }],
      ["a function", { onDone: () => undefined }],
      ["a Date", { issuedAt: new Date() }],
      ["a Map", { sealed: new Map() }],
      ["a member that is not there", { resourceJWT: undefined }],
    ]) {
      await assert.rejects(
        () =>
          network.post(PRIMARY_UNLOCK, /** @type {any} */ (payload), {
            from: caller,
            origin: PUBLISHER_ORIGIN,
          }),
        (/** @type {any} */ err) => err.code === "unsafe_payload",
        `${label} must not be mangled into JSON quietly`,
      );
    }

    // The message names where it was found, because a payload is nested and
    // "something in there is not JSON" is not a bug report.
    await assert.rejects(
      () =>
        network.post(
          PRIMARY_UNLOCK,
          { sealed: { contentKeys: [{ contentName: "bodytext", key: new Uint8Array(4) }] } },
          { from: caller, origin: PUBLISHER_ORIGIN },
        ),
      (/** @type {any} */ err) =>
        /sealed\.contentKeys\[0\]\.key/.test(err.message) && /Uint8Array/.test(err.message),
    );

    // A refused payload never reached the server, so it is not an attempt -
    // the url has no traffic against it at all.
    assert.equal(network.stats()[PRIMARY_UNLOCK], undefined);

    // And the same rule on the way back: a server leaking key material is
    // caught where it would have been serialised.
    network.serve(FALLBACK_UNLOCK, () => ({
      status: 200,
      body: { keys: { contentKeys: [{ contentName: "bodytext", key: new Uint8Array(16) }] } },
    }));
    await assert.rejects(
      () =>
        network.post(FALLBACK_UNLOCK, { fine: true }, { from: caller, origin: PUBLISHER_ORIGIN }),
      (/** @type {any} */ err) => err.code === "unsafe_payload",
    );

    // What the demo actually sends passes: nested plain objects, arrays,
    // strings, numbers, booleans and nulls.
    const answer = await network.post(
      PRIMARY_UNLOCK,
      {
        version: "1.0",
        sealed: { contentKeys: [{ contentName: "bodytext", key: "BASE64URL" }] },
        list: [1, true, null, { a: "b" }],
      },
      { from: caller, origin: PUBLISHER_ORIGIN },
    );
    assert.equal(answer.status, 200);
  });
});

describe("The two ends, over the wire", () => {
  test("one unlock crosses the wire and opens the article; the next one costs nothing", async () => {
    const { network, browser, servers, render } = await actorWorld();

    const first = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(first.errors[CONTENT_NAME], null);
    assert.equal(first.unlock.ok, true);
    assert.equal(first.unlock.issuerName, PRIMARY);
    assert.equal(first.unlock.status, 200);
    assert.equal(
      first.unlock.transportMode,
      "direct",
      "read off the answer, not off what was asked for",
    );
    assert.deepEqual(first.load.stats().resolved, { covered: [], missing: [CONTENT_NAME] });
    assert.equal(first.load.stats().answeredBy, PRIMARY);
    assert.equal(first.load.stats().attempts, 1);
    assert.ok(first.load.stats().trials > 0, "it tried the cache before it asked anyone");

    // The second article of the same period is opened by the key the first one
    // fetched, and never reaches the network.
    const second = await readArticle(browser, await render("B"), [CONTENT_NAME]);
    assert.equal(second.texts[CONTENT_NAME], ARTICLES.B);
    assert.equal(second.unlock, null, "nothing was missing, so nothing was asked");
    assert.deepEqual(second.load.stats().resolved, { covered: [CONTENT_NAME], missing: [] });
    assert.equal(second.load.stats().attempts, 0);

    assert.equal(network.stats()[PRIMARY_UNLOCK].attempts, 1);
    assert.ok(network.stats()[PRIMARY_UNLOCK].requestBytes > 0);
    assert.ok(network.stats()[PRIMARY_UNLOCK].responseBytes > 0);
    assert.deepEqual(servers.primary.stats(), {
      requests: 1,
      grants: 1,
      denials: 0,
      refusals: 0,
      faults: 0,
      unsealFailures: 0,
      probes: 0,
      healthReads: 0,
      transportMode: "direct",
      role: "primary",
    });

    assert.equal(browser.stats().loads, 2);
    assert.equal(browser.stats().unlocks, 1);
    assert.equal(browser.stats().unlockFailures, 0);
    assert.deepEqual(browser.stats().breaker[PRIMARY_UNLOCK], {
      state: "closed",
      failures: 0,
      openedAt: null,
    });
  });

  test("an unreachable issuer is a typed miss on the page, not a throw out of the load", async () => {
    const { network, browser, render } = await actorWorld();
    network.offline(PRIMARY_UNLOCK, { from: browser });

    const { unlock, texts, errors } = await readArticle(browser, await render("A"), [CONTENT_NAME]);

    assert.equal(unlock.ok, false);
    assert.equal(unlock.issuerName, null, "nobody answered");
    assert.deepEqual(
      unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["offline"],
    );
    assert.equal(texts[CONTENT_NAME], null);
    assert.equal(errors[CONTENT_NAME], "no_key", "the article stays locked, and says so");
    assert.equal(browser.stats().unlockFailures, 1);
  });

  test("a typed refusal is a locked item on the page, and an untyped throw goes up loud", async () => {
    const { browser, render } = await actorWorld();
    const page = await render("A");

    // Typed: nothing was unlocked, so the item stays locked and says so - the
    // code crosses as data, not as a throw out of the load.
    const locked = browser.load(rootFromPage(page));
    const miss = await locked.open(CONTENT_NAME);
    assert.deepEqual(miss, { bytes: null, error: "no_key" });
    assert.deepEqual(locked.stats().misses, [CONTENT_NAME]);

    // Untyped: a cache throwing a TypeError is a bug in this client, and a bug
    // must not read as one more locked article.
    const buggy = new PageLoad({
      delivery: new MarkupDeliveryReader(rootFromPage(page)),
      clock: new Clock(AT),
      network: /** @type {any} */ ({
        post: () => {
          throw new Error("never called");
        },
      }),
      cache: /** @type {any} */ ({
        put: async () => undefined,
        candidatesAt: () => {
          throw new TypeError("boom");
        },
        attempted: async () => undefined,
      }),
      resolverFactory: (options) => new ContentKeyResolver(options),
      requestBuilderFactory: (options) => new DcaRequestBuilder(options),
      issuers: [],
      breaker: /** @type {any} */ ({}),
      caller: {},
    });
    await assert.rejects(() => buggy.open(CONTENT_NAME), TypeError);
    assert.deepEqual(buggy.stats().misses, [], "a bug is not a miss");
  });

  test("the server keeps the state, the port keeps nothing, and the engine is callable without either", async () => {
    const { browser, servers, render, publisherRegistration } = await actorWorld();
    const page = await render("A");

    // The principal table is real and decides nothing yet: the request goes
    // through whether or not a credential resolves to someone.
    servers.primary.grant("alice", { accessGroups: [ACCESS_GROUP] });
    assert.deepEqual(servers.primary.authenticate("alice"), {
      user: "alice",
      accessGroups: [ACCESS_GROUP],
    });
    assert.equal(servers.primary.authenticate({ user: "alice" })?.user, "alice");
    assert.equal(servers.primary.authenticate("mallory"), null);
    servers.primary.expire("alice");
    assert.equal(servers.primary.authenticate("alice"), null);

    const load = browser.load(rootFromPage(page));
    await load.resolve([CONTENT_NAME]);
    const unlock = await load.unlock({ credential: { user: "alice" } });
    assert.equal(unlock.ok, true);
    assert.equal(servers.primary.stats().requests, 1);

    // The same request through the port directly, no network in the way: a core
    // and its port are callable as a library, and the wire reaches the
    // deployment around them. It is the request a load actually built, so a test
    // cannot pass against a shape the client has drifted away from.
    const request = await unlockRequestOf(browser, page);
    const direct = await unlockThroughAdmission(
      servers.primary.processor,
      servers.primary.endpoint,
      request,
      publisherRegistration,
    );
    assert.equal(direct.status, 200);
    assert.ok(periodKeyMap(direct.body.keys.periodKeys)[ACCESS_GROUP]);
    assert.equal(servers.primary.stats().requests, 1, "and the deployment never saw it");
  });

  test("an issuer the page never heard of is passed over, and an issuer the client never heard of is refused", async () => {
    const { browser, render } = await actorWorld();
    const page = await render("A");

    const load = browser.load(rootFromPage(page));
    await load.resolve([CONTENT_NAME]);
    await assert.rejects(
      () => load.unlock({ issuerName: "someone_else" }),
      (/** @type {any} */ err) => err.code === "unknown_issuer",
    );

    // A client configured with an issuer the page carries no blobs for walks
    // past it: there is nothing on the page for it to open.
    const stranger = new Browser({
      clock: new Clock(AT),
      network: /** @type {any} */ ({
        post: () => {
          throw new Error("never called");
        },
      }),
      issuers: [
        { issuerName: "not_on_this_page", unlockUrl: "https://elsewhere.example.com/unlock" },
      ],
    });
    const strange = stranger.load(rootFromPage(page));
    await strange.resolve([CONTENT_NAME]);
    const unlock = await strange.unlock();
    assert.deepEqual(
      unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["not-on-page"],
    );
    assert.equal(unlock.ok, false);
  });

  test("an unlock refuses a knob it does not have, and so do the actors", async () => {
    const { browser, render } = await actorWorld();
    const load = browser.load(rootFromPage(await render("A")));

    await assert.rejects(
      () => load.unlock({ /** @type {any} */ transportMode: "client-bound" }),
      (/** @type {any} */ err) => err.code === "unsupported_option",
    );
    assert.throws(
      () =>
        new Browser({
          clock: new Clock(AT),
          network: /** @type {any} */ ({}),
          issuers: [],
          /** @type {any} */ retries: 3,
        }),
      (/** @type {any} */ err) => err.code === "unsupported_option",
    );
  });
});

describe("The breaker", () => {
  test("an earlier eligible failure stays scoped through a skipped intermediate issuer", async () => {
    const stage = await actorWorld();
    const middle = "https://middle.example/unlock";
    const last = "https://last.example/unlock";
    await stage.standUp("middle", middle, { role: "primary" });
    await stage.standUp("last", last, { role: "primary" });
    const page = await stage.render("A");
    stage.network.offline(PRIMARY_UNLOCK);
    const load = new PageLoad({
      delivery: new MarkupDeliveryReader(rootFromPage(page)),
      clock: stage.clock,
      network: stage.network,
      cache: stage.browser.cache,
      relayPeriodKeys: true,
      issuers: stage.routes,
      caller: {},
      breaker: {
        timeout: 5000,
        allows: (url) => url !== middle,
        recordFailure() {},
        recordSuccess() {},
      },
    });
    await load.resolve([CONTENT_NAME]);
    const result = await load.unlock();
    assert.deepEqual(
      result.attempts.map(({ outcome }) => outcome),
      ["offline", "skipped", "answered"],
    );
    assert.equal(result.issuerName, "last");
    assert.equal(stage.network.stats()[middle], undefined, "the skipped issuer was never called");
    assert.ok(
      (await load.open(CONTENT_NAME)).bytes,
      "the last issuer's scoped capability opens the article",
    );
  });

  test("the breaker opens at its threshold, skips while open, half-opens after the window, and closes on success", async () => {
    const { clock, network, browser, render } = await actorWorld();
    const attemptsOnPrimary = () => network.stats()[PRIMARY_UNLOCK].attempts;
    const breaker = () => browser.stats().breaker[PRIMARY_UNLOCK];

    // The whole outage, from every vantage. Nothing here is per-caller yet -
    // that is the catch-22, and it is a test of its own.
    network.offline(PRIMARY_UNLOCK);
    network.offline(PRIMARY_HEALTH);

    const first = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.equal(first.texts[CONTENT_NAME], null);
    assert.deepEqual(
      breaker(),
      { state: "closed", failures: 1, openedAt: null },
      "one failure is not a pattern",
    );
    assert.equal(attemptsOnPrimary(), 1);

    const second = await readArticle(browser, await render("B"), [CONTENT_NAME]);
    assert.equal(second.texts[CONTENT_NAME], null);
    assert.equal(breaker().state, "open", "the threshold, and it opens");
    assert.equal(breaker().failures, 2);
    assert.equal(attemptsOnPrimary(), 2);

    // Open means the call is not made at all: a client that keeps calling a
    // dead issuer pays the timeout on every article.
    const third = await readArticle(browser, await render("C"), [CONTENT_NAME]);
    assert.deepEqual(
      third.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["skipped"],
    );
    assert.equal(attemptsOnPrimary(), 2, "nothing crossed the wire");
    assert.equal(third.load.stats().skipped, 1);

    // Inside the window it stays open, however many articles are read.
    clock.advance(29 * SECOND);
    await readArticle(browser, await render("D"), [CONTENT_NAME]);
    assert.equal(attemptsOnPrimary(), 2);
    assert.equal(breaker().state, "open");

    // Past the window the breaker half-opens and this call goes out. It fails,
    // and the breaker re-opens on that one failure rather than waiting for
    // another threshold.
    clock.advance(2 * SECOND);
    const trial = await readArticle(browser, await render("E"), [CONTENT_NAME]);
    assert.deepEqual(
      trial.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["offline"],
    );
    assert.equal(attemptsOnPrimary(), 3);
    assert.equal(breaker().state, "open");
    assert.equal(
      breaker().openedAt,
      clock.now().getTime(),
      "re-opened now, not when it first opened",
    );

    // The issuer comes back. The next call after the window succeeds, and the
    // breaker forgets everything it counted.
    network.online(PRIMARY_UNLOCK);
    clock.advance(30 * SECOND);
    const recovered = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.equal(recovered.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(attemptsOnPrimary(), 4);
    assert.deepEqual(breaker(), { state: "closed", failures: 0, openedAt: null });
  });

  test("a slow primary plus the breaker timeout is what trips it, and the waiting is spent on the clock", async () => {
    const { clock, network, browser, makeBrowser, render } = await actorWorld({
      breaker: { threshold: 2, timeout: 2 * SECOND },
    });
    const started = clock.now().getTime();

    // Reachable, and answering slower than the client will wait. No timer runs:
    // 5000 against a 2000 budget is a comparison, and the 2000 is charged to the
    // clock because that is what the client spent waiting.
    network.slow(PRIMARY_UNLOCK, 5 * SECOND);

    const first = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.deepEqual(
      first.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["timeout"],
    );
    assert.equal(clock.now().getTime() - started, 2 * SECOND);
    assert.equal(browser.stats().breaker[PRIMARY_UNLOCK].failures, 1);

    const second = await readArticle(browser, await render("B"), [CONTENT_NAME]);
    assert.equal(second.texts[CONTENT_NAME], null);
    assert.equal(
      clock.now().getTime() - started,
      4 * SECOND,
      "two budgets, and not one millisecond more",
    );
    assert.equal(browser.stats().breaker[PRIMARY_UNLOCK].state, "open");

    // A timeout is a failure of reachability, so the network records it as one
    // and the server never saw a request at all.
    assert.equal(network.stats()[PRIMARY_UNLOCK].failures, 2);
    assert.equal(network.stats()[PRIMARY_UNLOCK].responseBytes, 0);

    // The same latency under a budget that can wait for it is an answer, not a
    // failure - the timeout is the client's patience, not the issuer's state.
    const patient = makeBrowser({ breaker: { timeout: 6 * SECOND } });
    const answered = await readArticle(patient, await render("C"), [CONTENT_NAME]);
    assert.equal(answered.texts[CONTENT_NAME], ARTICLES.C);
    assert.equal(
      clock.now().getTime() - started,
      9 * SECOND,
      "and it waited the full latency for it",
    );
  });
});

describe("The fallback", () => {
  test("one fallback trim keeps the greatest started label per group and records an empty group", () => {
    const clock = new Clock(AT);

    // This is one request's presented period set. The issuer has already
    // authorized and opened these period keys when the fallback applies its
    // delivery-only trim, so the response below retains the same coordinates
    // and values. Hourly and quarter-hour labels must be evaluated at their
    // own resolutions; the third group deliberately contains only future
    // labels.
    const request = {
      sealed: {
        periodKeys: [
          { accessGroup: "hourly", period: "251023T1300", key: "hour-ended" },
          { accessGroup: "hourly", period: "251023T1400", key: "hour-current" },
          { accessGroup: "hourly", period: "251023T1500", key: "hour-ahead" },
          { accessGroup: "quarter_hour", period: "251023T1400", key: "quarter-ended" },
          { accessGroup: "quarter_hour", period: "251023T1415", key: "quarter-current" },
          { accessGroup: "quarter_hour", period: "251023T1430", key: "quarter-ahead" },
          { accessGroup: "not_started", period: "251023T1430", key: "not-started-soon" },
          { accessGroup: "not_started", period: "251023T1445", key: "not-started-later" },
        ],
      },
    };
    const response = {
      keys: {
        contentKeys: [{ contentName: CONTENT_NAME, key: "content-key-remains" }],
        periodKeys: request.sealed.periodKeys,
      },
    };

    assert.deepEqual(trimToCurrentPeriod(response, clock.now()), {
      keys: {
        contentKeys: [{ contentName: CONTENT_NAME, key: "content-key-remains" }],
        periodKeys: [
          { accessGroup: "hourly", period: "251023T1400", key: "hour-current" },
          { accessGroup: "quarter_hour", period: "251023T1415", key: "quarter-current" },
        ],
      },
    });
  });

  test("the fallback refuses while the primary is healthy, and grants only after its probe and active emergency window", async () => {
    const { clock, network, browser, servers, render } = await actorWorld({
      fallback: true,
      healthTtl: 30 * SECOND,
    });

    // The primary is up, so nothing reaches the fallback at all - but asked
    // directly, it refuses. 403 is the fallback's own answer: it is made from
    // server state before the port is reached, since a healthy primary is not
    // an engine error and the engine is never called.
    const request = await unlockRequestOf(browser, await render("A"), FALLBACK);
    const refused = await network.post(FALLBACK_UNLOCK, request, {
      from: browser,
      timeout: 2 * SECOND,
      origin: PUBLISHER_ORIGIN,
    });
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error, "primary_healthy");
    assert.equal(servers.fallback.stats().refusals, 1);
    assert.equal(servers.fallback.stats().grants, 0);

    // The outage.
    network.offline(PRIMARY_UNLOCK);
    network.offline(PRIMARY_HEALTH);

    // It keeps refusing, because it is still holding the answer it got before
    // the primary went down. That is the TTL's cost in this direction, and the
    // reason it is a knob: for as long as it runs, a fallback stands by while
    // the thing it stands in for is gone.
    const stale = await network.post(FALLBACK_UNLOCK, request, {
      from: browser,
      timeout: 2 * SECOND,
      origin: PUBLISHER_ORIGIN,
    });
    assert.equal(stale.status, 403);
    assert.equal(servers.fallback.stats().probes, 1, "and it did not ask again to find that out");

    clock.advance(31 * SECOND);
    const granted = await network.post(FALLBACK_UNLOCK, request, {
      from: browser,
      timeout: 2 * SECOND,
      origin: PUBLISHER_ORIGIN,
    });
    assert.equal(granted.status, 200);
    assert.equal(servers.fallback.stats().grants, 1);
    assert.equal(servers.fallback.stats().probes, 2, "it asked again before it granted");
  });

  test("a primary outage alone does not authorize the fallback after its server-owned window closes", async () => {
    const { network, browser, servers, render } = await actorWorld({
      fallback: true,
      fallbackEmergencyUntil: Date.parse(AT),
    });
    const request = await unlockRequestOf(browser, await render("A"), FALLBACK);

    network.offline(PRIMARY_UNLOCK);
    network.offline(PRIMARY_HEALTH);

    const refused = await network.post(FALLBACK_UNLOCK, request, {
      from: browser,
      timeout: 2 * SECOND,
      origin: PUBLISHER_ORIGIN,
    });
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error, "emergency_inactive");
    assert.equal(servers.fallback.stats().grants, 0);
  });

  test("a fallback grant is trimmed to the current period, and the primary grant is not", async () => {
    const { clock, network, browser, makeBrowser, servers, render } = await actorWorld({
      fallback: true,
    });
    const now = () => formatT(clock.now());

    // What a healthy primary hands over: the period the render was made in and
    // the forward overlap beside it, which is what covers the next boundary.
    const primary = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.equal(primary.unlock.issuerName, PRIMARY);
    const fromPrimary = await browser.cache.entries();
    assert.equal(fromPrimary.length, 2);
    assert.equal(fromPrimary[1].t, now());

    // The same page to a fallback, on a client holding nothing. It answers with
    // one period: every period it hands out stays usable until that period
    // rolls, which is after the primary is back and after whatever made this
    // grant has been reconsidered.
    network.offline(PRIMARY_UNLOCK);
    network.offline(PRIMARY_HEALTH);

    const other = makeBrowser();
    const stood = await readArticle(other, await render("B"), [CONTENT_NAME]);

    assert.equal(stood.texts[CONTENT_NAME], ARTICLES.B, "the article opens all the same");
    assert.equal(stood.unlock.issuerName, FALLBACK);
    assert.deepEqual(
      stood.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["offline", "answered"],
    );

    const fromFallback = await other.cache.entries();
    assert.deepEqual(
      fromFallback.map((/** @type {any} */ e) => e.t),
      [now()],
      "the current period, and nothing forward",
    );
    assert.equal(servers.fallback.stats().grants, 1);

    // The cost of that bound, made visible: the next period is another unlock,
    // where a primary grant would have covered it out of the cache.
    clock.advance(41 * 60 * SECOND);
    const across = await readArticle(other, await render("C"), [CONTENT_NAME]);
    assert.equal(across.texts[CONTENT_NAME], ARTICLES.C);
    assert.equal(across.unlock.issuerName, FALLBACK, "and the fallback is still the one answering");
    assert.deepEqual((await other.cache.entries()).map((/** @type {any} */ e) => e.t).sort(), [
      "251023T1400",
      "251023T1500",
    ]);
  });

  test("the trim reads each label's own resolution, so a publisher on another period is not emptied", async () => {
    const { clock, network, browser, servers, publisherWith } = await actorWorld({
      fallback: true,
    });

    // Two publishers with different periods run in one process, and a fallback
    // is told about neither. A `t` says its own resolution - nine characters is
    // an hour, eleven carries the minutes - so the label is what the clock is
    // formatted to match, rather than a length the two sides had to agree on.
    const quarterly = publisherWith({ period: { length: 15, slots: 3 } });
    const page = await quarterly.render(article("A"));
    const request = await unlockRequestOf(browser, page, FALLBACK);
    assert.deepEqual(
      Object.keys(periodKeyMap(request.sealed.periodKeys)[ACCESS_GROUP]),
      ["251023T1415", "251023T1430", "251023T1445"],
      "three quarter-hours, current first",
    );

    network.offline(PRIMARY_UNLOCK);
    network.offline(PRIMARY_HEALTH);

    const answer = await network.post(FALLBACK_UNLOCK, request, {
      from: browser,
      timeout: 2 * SECOND,
      origin: PUBLISHER_ORIGIN,
    });

    assert.equal(answer.status, 200);
    assert.deepEqual(
      Object.keys(periodKeyMap(answer.body.keys.periodKeys) ?? {}),
      [ACCESS_GROUP],
      "the group came back at all",
    );
    assert.deepEqual(
      Object.keys(periodKeyMap(answer.body.keys.periodKeys)[ACCESS_GROUP]),
      [formatT(clock.now(), 15)],
      "the quarter-hour it is reading in, and neither of the two forward",
    );
    assert.equal(
      answer.body.errors,
      undefined,
      "the group kept a period, so nothing about it was withheld",
    );
    assert.equal(servers.fallback.stats().grants, 1);
  });

  test("a render that has outlived every period it shipped is answered with the last one that started", async () => {
    const { clock, network, browser, servers, render } = await actorWorld({ fallback: true });

    // Markup out of a cache, read long after it was made: both the period it
    // was rendered in and the overlap beside it have started, and the later of
    // the two has ended too. The greatest started label is the one the client
    // is holding content for, and the clock's own label is not on the page.
    const request = await unlockRequestOf(browser, await render("A"), FALLBACK);
    assert.deepEqual(Object.keys(periodKeyMap(request.sealed.periodKeys)[ACCESS_GROUP]), [
      "251023T1400",
      "251023T1500",
    ]);

    network.offline(PRIMARY_UNLOCK);
    network.offline(PRIMARY_HEALTH);
    clock.advance(110 * 60 * SECOND);
    assert.equal(formatT(clock.now()), "251023T1600", "a period the render never carried");

    const answer = await network.post(FALLBACK_UNLOCK, request, {
      from: browser,
      timeout: 2 * SECOND,
      origin: PUBLISHER_ORIGIN,
    });

    assert.equal(answer.status, 200);
    assert.deepEqual(Object.keys(periodKeyMap(answer.body.keys.periodKeys) ?? {}), [ACCESS_GROUP]);
    assert.deepEqual(Object.keys(periodKeyMap(answer.body.keys.periodKeys)[ACCESS_GROUP]), [
      "251023T1500",
    ]);
    assert.equal(servers.fallback.stats().grants, 1);
  });

  test("a group the trim empties supplies no inferred availability reason", async () => {
    const { network, browser, servers, render } = await actorWorld({ fallback: true });
    const page = await render("A");

    // The client writes the request and is the attacker, so the period it is
    // asking in is a period it can leave out. Nothing left in the group has
    // started, so nothing in it is handed back - and the group is named,
    // because a section that quietly disappears is a grant of nothing that
    // reads like a grant.
    const request = await unlockRequestOf(browser, page, FALLBACK);
    request.sealed.periodKeys = request.sealed.periodKeys.filter(
      (/** @type {any} */ record) =>
        !(record.accessGroup === ACCESS_GROUP && record.period === "251023T1400"),
    );

    network.offline(PRIMARY_UNLOCK);
    network.offline(PRIMARY_HEALTH);

    const answer = await network.post(FALLBACK_UNLOCK, request, {
      from: browser,
      timeout: 2 * SECOND,
      origin: PUBLISHER_ORIGIN,
    });

    assert.equal(answer.status, 200);
    assert.equal(
      answer.body.keys.periodKeys,
      undefined,
      "an empty section would read as a grant of no keys",
    );
    assert.equal(answer.body.errors, undefined, "a family outcome is not a coordinate error");
    assert.equal(
      answer.body.notDelivered,
      undefined,
      "trimming is not independent missing-supply evidence",
    );
    assert.equal(servers.fallback.stats().grants, 1, "the contentKey still went over");

    // The client that sent this request reads the report as a typed family
    // outcome beside the content key it accepted, not as a malformed answer.
    const delivered = new MarkupDeliveryReader(rootFromPage(page));
    const dcaData = new DcaData(delivered.dcaData, { publisherOrigin: delivered.publisherOrigin });
    const application = await new ContentKeyResolver({}).applyResponse(
      dcaData,
      FALLBACK,
      answer.body,
      new ResponseAssociation(dcaData, FALLBACK, request, { acceptDirectResponse: true }),
    );
    assert.deepEqual(application.issues, []);
    assert.equal(application.accepted, 1, "the content key is held");
    assert.equal(application.notDelivered, undefined);
  });

  test("the health result is cached for a TTL, so a fallback under load does not probe per request", async () => {
    const { clock, network, browser, servers, render } = await actorWorld({
      fallback: true,
      healthTtl: 30 * SECOND,
    });
    const probes = () => network.stats()[PRIMARY_HEALTH].probes;

    network.offline(PRIMARY_UNLOCK);
    network.offline(PRIMARY_HEALTH);

    const request = await unlockRequestOf(browser, await render("A"), FALLBACK);
    const post = () =>
      network.post(FALLBACK_UNLOCK, request, {
        from: browser,
        timeout: 2 * SECOND,
        origin: PUBLISHER_ORIGIN,
      });

    assert.equal((await post()).status, 200);
    assert.equal(probes(), 1);

    // Inside the TTL, the answer it already has. A probe per request would put
    // more traffic on a struggling primary than the outage did.
    assert.equal((await post()).status, 200);
    assert.equal((await post()).status, 200);
    assert.equal(probes(), 1, "still the one probe");
    assert.equal(servers.fallback.stats().healthReads, 2);

    // Past it, it asks again - and the primary is back, so the fallback stands
    // down. A stale "down" is exactly what the TTL bounds.
    clock.advance(31 * SECOND);
    network.online(PRIMARY_UNLOCK);
    network.online(PRIMARY_HEALTH);

    assert.equal((await post()).status, 403);
    assert.equal(probes(), 2);
    assert.equal(servers.fallback.stats().refusals, 1);
  });

  test("a broken probe returns an observable server fault and the fallback grants nothing", async () => {
    const { clock, network, publisherRegistrations, browser, render } = await actorWorld();

    // A health url served by a handler with a bug in it. Only offline, timeout
    // and no_route mean down - a TypeError is this server broken, not the
    // primary gone, and a fallback that read the two alike would start handing
    // keys out on its own bug.
    const brokenHealth = "https://broken.example.com/health";
    const brokenUnlock = "https://broken.example.com/unlock";
    network.serve(brokenHealth, () => {
      throw new TypeError("reading a member of undefined");
    });

    const fallback = new IssuerServer({
      clock,
      network,
      issuerName: "paywall_broken_probe",
      operatingIssuerNames: [PRIMARY],
      unlockUrl: brokenUnlock,
      keyStore: { get: () => undefined },
      publisherRegistrations,
      accessPolicy: new AllowAllPolicy(),
      role: "fallback",
      healthCheckUrl: brokenHealth,
    });

    const request = await unlockRequestOf(browser, await render("A"), PRIMARY);
    const response = await network.post(brokenUnlock, request, {
      from: { who: "a reader" },
      timeout: 2 * SECOND,
      origin: PUBLISHER_ORIGIN,
    });
    assert.equal(response.status, 500, "the admitted HTTP host exposes its fault");
    assert.equal(response.body.error, "internal_error");
    assert.equal(fallback.stats().grants, 0, "nothing was handed over on the way up");
    assert.equal(fallback.stats().refusals, 0, "and nothing was decided either way");
  });

  test("a fallback that cannot check the primary is refused at construction", async () => {
    const { clock, network, publisherRegistrations } = await actorWorld();

    assert.throws(
      () =>
        new IssuerServer({
          clock,
          network,
          issuerName: "no_health_check",
          unlockUrl: "https://elsewhere.example.com/unlock",
          keyStore: { get: () => undefined },
          publisherRegistrations,
          accessPolicy: new AllowAllPolicy(),
          role: "fallback",
        }),
      (/** @type {any} */ err) => err.code === "bad_config",
      "a fallback with nothing to check would grant on hearsay",
    );
  });
});

describe("The catch-22", () => {
  test("up from the fallback and down from the browser: no content, and no loop", async () => {
    const { network, browser, servers, render } = await actorWorld({ fallback: true });

    // One url, two vantages. The browser cannot reach the primary; the fallback
    // can, so it will not stand in for an issuer it believes is fine.
    network.offline(PRIMARY_UNLOCK, { from: browser });
    network.offline(PRIMARY_HEALTH, { from: browser });

    const stuck = await readArticle(browser, await render("A"), [CONTENT_NAME]);

    assert.equal(stuck.texts[CONTENT_NAME], null, "the reader gets nothing");
    assert.equal(stuck.errors[CONTENT_NAME], "no_key");
    assert.equal(stuck.unlock.ok, false);
    assert.equal(stuck.unlock.status, 403);
    assert.deepEqual(
      stuck.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["offline", "refused"],
    );

    // And it ends. The walk is a list of configured issuers, so it runs out:
    // one call to each, and the refusal does not send the client back round to
    // the primary the fallback just vouched for.
    assert.equal(stuck.unlock.attempts.length, 2);
    assert.equal(network.stats()[PRIMARY_UNLOCK].attempts, 1);
    assert.equal(network.stats()[FALLBACK_UNLOCK].attempts, 1);
    assert.equal(servers.fallback.stats().refusals, 1);
    assert.equal(servers.primary.stats().requests, 0, "the primary never heard from this client");

    // A second article does the same finite thing rather than piling up.
    const again = await readArticle(browser, await render("B"), [CONTENT_NAME]);
    assert.equal(again.texts[CONTENT_NAME], null);
    assert.equal(again.unlock.attempts.length, 2);
    assert.equal(network.stats()[PRIMARY_UNLOCK].attempts, 2);
    assert.equal(network.stats()[FALLBACK_UNLOCK].attempts, 2);
    assert.equal(browser.stats().unlockFailures, 2);

    // The breaker counted the two unreachable calls and has opened, so a third
    // article stops asking the primary. That local skip does not qualify
    // another conditional call to the fallback.
    const third = await readArticle(browser, await render("C"), [CONTENT_NAME]);
    assert.deepEqual(
      third.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["skipped"],
    );
    assert.equal(network.stats()[PRIMARY_UNLOCK].attempts, 2);
  });
});

describe("Two tabs at once", () => {
  test("two unlocks in flight at once both go out: a breaker cannot recall a call it has already allowed", async () => {
    const { network, browser, render } = await actorWorld({ breaker: { threshold: 1 } });
    network.offline(PRIMARY_UNLOCK);

    // Two live loads of one page stand for two tabs. Both ask the breaker
    // whether the primary may be called while neither has failed yet, so both
    // are allowed through - the breaker opens one round of calls late, whatever
    // its threshold is.
    const page = await render("A");
    const [one, two] = [browser.load(rootFromPage(page)), browser.load(rootFromPage(page))];
    await Promise.all([one.resolve([CONTENT_NAME]), two.resolve([CONTENT_NAME])]);

    const answers = await Promise.all([one.unlock(), two.unlock()]);

    assert.deepEqual(
      answers.map((answer) => answer.attempts[0].outcome),
      ["offline", "offline"],
    );
    assert.equal(network.stats()[PRIMARY_UNLOCK].attempts, 2, "both were already on the wire");

    // What does not happen: the two of them reading one stale failure count and
    // writing 1 over each other. The count is incremented in place, with no
    // store under it and so no await inside the update, so two failures are two.
    assert.equal(browser.stats().breaker[PRIMARY_UNLOCK].failures, 2);
    assert.equal(browser.stats().breaker[PRIMARY_UNLOCK].state, "open");

    // The next tab to try is stopped, the round the breaker is late by.
    const third = browser.load(rootFromPage(page));
    await third.resolve([CONTENT_NAME]);
    assert.deepEqual(
      (await third.unlock()).attempts.map((/** @type {any} */ a) => a.outcome),
      ["skipped"],
    );
    assert.equal(network.stats()[PRIMARY_UNLOCK].attempts, 2);
  });

  test("a fresh breaker skip does not qualify conditional fallback", async () => {
    const { clock, network, browser, servers, render } = await actorWorld({
      fallback: true,
      // One failure is enough to open it, and the window outlasts this test:
      // what is being watched is where the second article's request goes, not
      // when the breaker gives the primary another try.
      breaker: { threshold: 1, window: 60 * 60 * SECOND },
    });

    network.offline(PRIMARY_UNLOCK);
    network.offline(PRIMARY_HEALTH);

    const first = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);
    assert.deepEqual(
      first.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["offline", "answered"],
    );
    assert.equal(browser.stats().breaker[PRIMARY_UNLOCK].state, "open");

    // The fallback trimmed its grant to the period it granted in, so crossing
    // into the next one is another unlock. A local skip supplies no new
    // retry permission, so neither issuer is asked in that walk.
    clock.advance(41 * 60 * SECOND);
    const second = await readArticle(browser, await render("B"), [CONTENT_NAME]);

    assert.equal(second.texts[CONTENT_NAME], null);
    assert.deepEqual(
      second.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["skipped"],
    );
    assert.equal(
      network.stats()[PRIMARY_UNLOCK].attempts,
      1,
      "the primary was asked once, an article ago",
    );
    assert.equal(network.stats()[FALLBACK_UNLOCK].attempts, 1);
    assert.equal(servers.fallback.stats().grants, 1);
    const independent = await second.load.unlock({ issuerName: FALLBACK });
    assert.equal(independent.ok, true, "an explicit independent invocation remains permitted");
    assert.equal(servers.fallback.stats().grants, 2);
  });
});

describe("What a 5xx is counted as", () => {
  test("a 500 out of the port is a fault and not a refusal: nobody was turned away, this server broke", async () => {
    // A policy answering with something that is not a decision. An unreadable
    // no must never be read as a yes, so the engine throws `bad_policy` - which
    // the port has no status for, and answers 500. An up-and-broken issuer that
    // counted those as refusals would be indistinguishable in the stats from
    // one correctly refusing everyone.
    const { browser, servers, render } = await actorWorld({
      accessPolicy: { decide: () => "yes" },
    });

    const answer = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.equal(answer.unlock.status, 500);
    assert.equal(answer.texts[CONTENT_NAME], null);

    const stats = servers.primary.stats();
    assert.equal(stats.faults, 1);
    assert.equal(stats.refusals, 0, "nobody was refused");
    assert.equal(stats.denials, 0);
    assert.equal(stats.grants, 0);
  });

  test("a transport policy that answers with something that is not a mode is the same fault", async () => {
    // The other 500 this server makes: a mode spelled with an underscore, the
    // typo the refusal exists for. It leaves `refusals` alone the same way,
    // because both are the same event and land on one counter.
    const { browser, servers, render } = await actorWorld({
      transportPolicy: { modeFor: () => "client_bound" },
      clientBoundProfile: clientBoundProfileStub,
    });

    const answer = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.equal(answer.unlock.status, 500);

    const stats = servers.primary.stats();
    assert.equal(stats.faults, 1);
    assert.equal(stats.refusals, 0);
    assert.equal(
      stats.transportMode,
      null,
      "a policy decides per request, so there is no mode it is in",
    );
  });

  test("a reachable 500 walks on to a healthy fallback and opens the breaker, the way a transport failure does", async () => {
    // The primary is up and broken: its policy answers `yes`, which is not a
    // decision, so its unlock port answers 500. A 500 is a fault and not a
    // refusal, so the walk carries on to the fallback rather than ending at the
    // broken primary, and the fault counts against the breaker the same as an
    // unreachable call. The primary's health probe is offline, which is what
    // lets the fallback grant while the primary's unlock port still answers.
    const { clock, network, browser, servers, render } = await actorWorld({
      accessPolicy: { decide: () => "yes" },
      fallback: true,
      // One fault opens it, and the window outlasts the clock advance below:
      // what the second article shows is the primary skipped, not the breaker
      // giving it another try.
      breaker: { threshold: 1, window: 60 * 60 * SECOND },
    });
    network.offline(PRIMARY_HEALTH);

    const first = await readArticle(browser, await render("A"), [CONTENT_NAME]);

    // (i) The broken primary did not end the walk: the fallback answered and
    // the content opened, with the 500 recorded as a fault ahead of it.
    assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(first.unlock.ok, true);
    assert.equal(first.unlock.issuerName, FALLBACK);
    assert.deepEqual(
      first.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["fault", "answered"],
    );
    assert.equal(first.unlock.attempts[0].status, 500);

    assert.equal(servers.primary.stats().faults, 1);
    assert.equal(servers.primary.stats().grants, 0);
    assert.equal(servers.fallback.stats().grants, 1);

    // (ii) The fault opened the breaker, one 500 being decisive at threshold 1.
    assert.equal(browser.stats().breaker[PRIMARY_UNLOCK].state, "open");

    // Crossing into the next period is another unlock, since the fallback
    // trimmed its grant to the period it granted in. This one skips the broken
    // primary without a call. That skip alone permits no conditional fallback;
    // the primary was asked exactly once across both reads.
    clock.advance(41 * 60 * SECOND);
    const second = await readArticle(browser, await render("B"), [CONTENT_NAME]);
    assert.equal(second.texts[CONTENT_NAME], null);
    assert.deepEqual(
      second.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["skipped"],
    );
    assert.equal(network.stats()[PRIMARY_UNLOCK].attempts, 1);
  });
});
