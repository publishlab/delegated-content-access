//
// Where the walk over the page's issuers ends, when the answer is a 200.
//
// An issuer that refuses has decided, and walking past a 401 or a 403 would be
// shopping for an issuer that says yes. A 200 holding no key is read by what
// its `errors` say. `key_retired` is the rollover the markup outlived: the
// issuer could not open what arrived, which is not a decision about this
// reader, and the next issuer the page names may still hold the key, so the
// walk goes on. A withholding decision needs a selected profile of its own;
// the base client does not infer it from a malformed group-only error. The
// issuer answered in both cases, so its breaker stays closed either way.
//
// The last case is a request that asks for nothing. A load that resolved
// everything out of its cache may still unlock, and the request it sends
// carries no coordinate at all. The issuer refuses that request whole, before
// an opening key, so what the walk gets is a 400: a refusal is terminal, the
// walk stops at the issuer that made it rather than shopping the rest of the
// list, and the article the cache already covered opens anyway.
//
// Pinned: two issuers over one publisher, direct transport, no access policy,
// one accessGroup, one content item, a network that is up and fast, and a clock
// that stands still. All of that is `demo/scenarios/world.js`'s actor family; what
// this file adds is the second issuer and the order the client walks the two
// in. What varies is whether the first issuer still holds its key, and whether
// it is standing in for a primary.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { utf8Decode } from "../core-shared/codec.js";
import { actorWorld, readArticle } from "../demo/scenarios/world.js";
import { rootFromPage } from "../demo/support/queryableRoot.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  CONTENT_NAME,
  ISSUER_NAME as SECOND,
  KEY_ID,
  UNLOCK_URL as SECOND_UNLOCK,
} from "../demo/scenarios/fixtures.js";

/**
 * The issuer the client asks first, named for where it stands in that order.
 * A name of this file's own, because the story needs two issuers and the one
 * the fixtures name is the other one - and not the fixtures' fallback either:
 * whether this one is a fallback at all is what a test varies.
 */
const FIRST = "paywall_syndication_service";
const FIRST_UNLOCK = "https://syndication.example.com/unlock";

/**
 * The primary a stand-in checks. Nothing in this world serves it, which is what
 * makes the probe say down - the fixtures' HEALTH_URL would not, since the
 * issuer standing behind this one is a primary and serves it.
 */
const PRIMARY_HEALTH = "https://primary.example.com/health";

/**
 * The actor world with a second issuer beside the one it stands up, and a
 * browser that walks the new one first - which is why the walk is spelled out
 * rather than taken from the world, whose own list has its primary in front.
 * What a test varies is whether the first issuer still holds its key.
 *
 * @param {object} [config]
 * @param {boolean} [config.fallback] - stand the first issuer up as a fallback
 *   rather than a primary. It is standing in for a primary this world does not
 *   have and nothing serves the health url, so its own probe says down and it
 *   answers - trimming what it grants to the period the client is reading in,
 *   which is what a test wanting a withheld grant is here for.
 * @returns {Promise<any>}
 */
async function world(config = {}) {
  const stage = await actorWorld();

  const first = await stage.standUp(
    FIRST,
    FIRST_UNLOCK,
    config.fallback ? { role: "fallback", healthCheckUrl: PRIMARY_HEALTH } : {},
  );

  const browser = stage.makeBrowser({
    issuers: [
      { issuerName: FIRST, unlockUrl: FIRST_UNLOCK },
      { issuerName: SECOND, unlockUrl: SECOND_UNLOCK },
    ],
  });

  return {
    network: stage.network,
    browser,
    servers: { first: first.server, second: stage.servers.primary },
    /**
     * @param {'A'|'B'} label
     * @returns {Promise<import('../demo/support/Page.js').Page>}
     */
    render: (label) => stage.render(label),
  };
}

describe("A 200 that delivered nothing", () => {
  test("an issuer that answers 200 holding no key is walked past, not taken for the answer", async () => {
    const { network, browser, servers, render } = await world();

    // The first issuer has let its key go, and the page still names it: markup
    // on an edge cache outlives a rotation.
    servers.first.retireKey(KEY_ID);

    const read = await readArticle(browser, await render("A"), [CONTENT_NAME]);

    assert.deepEqual(
      read.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["key_retired", "answered"],
      "the code the wire reported, then the issuer that still holds the key",
    );
    assert.equal(
      read.unlock.attempts[0].status,
      200,
      "the issuer was up, and the walk kept what it said",
    );

    assert.equal(read.unlock.ok, true);
    assert.equal(read.unlock.issuerName, SECOND);
    assert.equal(read.unlock.transportMode, "direct");
    assert.equal(read.load.stats().answeredBy, SECOND);

    assert.equal(read.texts[CONTENT_NAME], ARTICLES.A, "the article opens");
    assert.equal(read.errors[CONTENT_NAME], null);

    assert.equal(servers.first.stats().grants, 0);
    assert.equal(servers.second.stats().grants, 1);
    assert.ok(servers.first.stats().unsealFailures > 0, "every coordinate came back an error");
    assert.equal(network.stats()[FIRST_UNLOCK].attempts, 1);
    assert.equal(network.stats()[SECOND_UNLOCK].attempts, 1);

    // The breaker is for an issuer that cannot be reached. This one answered,
    // and taking it out of the walk for saying so would keep the client from
    // the day its key comes back.
    assert.deepEqual(browser.stats().breaker[FIRST_UNLOCK], {
      state: "closed",
      failures: 0,
      openedAt: null,
    });
    assert.equal(browser.stats().unlockFailures, 0);
  });

  test("a codeless per-item error is walked past before a later issuer answers", async () => {
    const { network, browser, render } = await world();
    const post = network.post.bind(network);
    network.post = async (url, payload, options) => {
      const answer = await post(url, payload, options);
      return url === FIRST_UNLOCK
        ? { status: 200, body: { errors: { [CONTENT_NAME]: {} } } }
        : answer;
    };

    try {
      const load = browser.load(rootFromPage(await render("A")));
      await load.resolve([CONTENT_NAME]);
      const unlock = await load.unlock();

      assert.deepEqual(
        unlock.attempts.map((/** @type {any} */ attempt) => attempt.outcome),
        ["empty", "answered"],
      );
      assert.equal(unlock.ok, true);
      assert.equal(unlock.issuerName, SECOND);
      assert.equal(utf8Decode((await load.open(CONTENT_NAME)).bytes), ARTICLES.A);
    } finally {
      network.post = post;
    }
  });

  test("a zero-accepted unsupported section is technical and the next issuer may answer", async () => {
    const { network, browser, render } = await world();
    const post = network.post.bind(network);
    network.post = async (url, payload, options) =>
      url === FIRST_UNLOCK
        ? {
            status: 200,
            body: {
              transport: { method: "client-bound-test" },
              keys: { periodChainKeys: { premium: { "251023T15": { key: "wrapped-chain" } } } },
            },
          }
        : post(url, payload, options);

    try {
      const load = browser.load(rootFromPage(await render("A")));
      await load.resolve([CONTENT_NAME]);
      const unlock = await load.unlock();

      assert.deepEqual(
        unlock.attempts.map((/** @type {any} */ attempt) => attempt.outcome),
        ["unsupported_section", "answered"],
      );
      assert.equal(unlock.ok, true);
      assert.equal(unlock.issuerName, SECOND);
      assert.equal(
        load.stats().answeredBy,
        SECOND,
        "the unsupported issuer is not reported as the answer",
      );
      assert.deepEqual(
        browser.breaker.stats()[FIRST_UNLOCK],
        {
          state: "closed",
          failures: 0,
          openedAt: null,
        },
        "local incompatibility does not count as network unavailability",
      );
    } finally {
      network.post = post;
    }
  });

  test("a walk nobody could open anything for reports the answer it got", async () => {
    const { browser, servers, render } = await world();

    // Both issuers have let the key go. The walk runs to the end of the list
    // and the article stays locked - and what it reports is the last issuer
    // that answered, because an issuer that opened nothing is a different end
    // than an issuer nobody could reach.
    servers.first.retireKey(KEY_ID);
    servers.second.retireKey(KEY_ID);

    const read = await readArticle(browser, await render("A"), [CONTENT_NAME]);

    assert.deepEqual(
      read.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["key_retired", "key_retired"],
    );
    assert.equal(read.unlock.ok, false);
    assert.equal(read.unlock.issuerName, SECOND);
    assert.equal(read.unlock.status, 200);
    assert.equal(read.unlock.transportMode, null);

    assert.equal(read.texts[CONTENT_NAME], null, "the article stays locked");
    assert.equal(read.errors[CONTENT_NAME], "no_key");
    assert.equal(browser.stats().unlockFailures, 1);
  });
});

describe("A 200 carrying a non-base withholding outcome", () => {
  test("a malformed group-only error cannot steer the base walk", async () => {
    const { network, browser, servers, render } = await world({ fallback: true });

    const load = browser.load(rootFromPage(await render("A")));
    await load.resolve([CONTENT_NAME]);

    // The client writes its own request, and this one asks the fallback for a
    // group it can hand nothing back for. The period the render was made in
    // comes off the page, leaving the forward overlap that has not started, and
    // the contentKey blob comes off with it - so the one thing the fallback has
    // to answer with is a group whose every period it withholds.
    const sealed = load.dcaData.issuerData[FIRST].sealed;
    const [current] = Object.keys(sealed.periodKeys[ACCESS_GROUP]);
    delete sealed.periodKeys[ACCESS_GROUP][current];
    delete sealed.contentKeys[CONTENT_NAME];

    const unlock = await load.unlock();

    // `accessGroup|` is not a base error coordinate. Until the fallback
    // profile defines and selects its own withholding outcome, that entry
    // cannot steer the base issuer walk.
    assert.deepEqual(
      unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["empty", "answered"],
    );
    assert.equal(unlock.ok, true);
    assert.equal(unlock.issuerName, SECOND);
    assert.equal(unlock.status, 200);
    assert.equal(network.stats()[SECOND_UNLOCK].attempts, 1, "the next issuer was asked");

    assert.equal(servers.first.stats().grants, 0, "the malformed outcome carried no grant");
    assert.equal(browser.stats().unlockFailures, 0);

    const { bytes, error } = await load.open(CONTENT_NAME);
    assert.ok(bytes, "the later issuer opens the article");
    assert.equal(error, null);
  });
});

describe("A request that asked for nothing", () => {
  test("an unlock that asks for nothing is refused, and the cached key still opens the article", async () => {
    const { network, browser, servers, render } = await world();

    const first = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.equal(first.unlock.ok, true);
    assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);

    // The next article of the same period is opened by the key the first one
    // fetched, so this load is missing nothing. It unlocks anyway, and the
    // request goes out carrying no coordinate at all.
    const load = browser.load(rootFromPage(await render("B")));
    assert.deepEqual(await load.resolve([CONTENT_NAME]), { covered: [CONTENT_NAME], missing: [] });

    const unlock = await load.unlock();

    // At least one coordinate has to be present, so this request is refused
    // whole and before an opening key. The issuer answered, which is what
    // ends the walk: a non-5xx is a decision, and walking past it would be
    // asking the rest of the list the same empty question.
    assert.equal(unlock.ok, false, "a request carrying no coordinate is not one an issuer answers");
    assert.equal(unlock.status, 400);
    assert.equal(unlock.issuerName, FIRST);
    assert.deepEqual(
      unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["rejected"],
    );
    assert.equal(unlock.transportMode, null, "no key arrived, so there is no mode to read off one");

    assert.equal(
      servers.first.stats().unsealFailures,
      0,
      "nothing was asked for, so nothing failed",
    );
    assert.equal(network.stats()[FIRST_UNLOCK].attempts, 2);
    assert.equal(network.stats()[SECOND_UNLOCK], undefined, "the walk ended at the first issuer");

    // And the read the cache already covered is unaffected: the refusal is
    // about the request, not about the key this browser already holds.
    const { bytes } = await load.open(CONTENT_NAME);
    assert.equal(utf8Decode(bytes), ARTICLES.B);
  });
});

describe("A deployment-owned HTTP refusal", () => {
  test("this reference treats 429 as terminal without opening the breaker", async () => {
    const { network, browser, render } = await world();
    const post = network.post.bind(network);
    network.post = async (url, payload, options) =>
      url === FIRST_UNLOCK
        ? { status: 429, body: { error: "rate_limited" } }
        : post(url, payload, options);

    try {
      const load = browser.load(rootFromPage(await render("A")));
      await load.resolve([CONTENT_NAME]);
      const unlock = await load.unlock();

      assert.equal(unlock.ok, false);
      assert.equal(unlock.issuerName, FIRST);
      assert.equal(unlock.status, 429);
      assert.deepEqual(unlock.attempts, [
        {
          issuerName: FIRST,
          url: FIRST_UNLOCK,
          outcome: "rejected",
          status: 429,
        },
      ]);
      assert.equal(
        network.stats()[SECOND_UNLOCK],
        undefined,
        "the reference deployment does not advance after 429",
      );
      assert.deepEqual(
        browser.stats().breaker[FIRST_UNLOCK],
        {
          state: "closed",
          failures: 0,
          openedAt: null,
        },
        "an answering endpoint is breaker-successful in this deployment",
      );
    } finally {
      network.post = post;
    }
  });
});
