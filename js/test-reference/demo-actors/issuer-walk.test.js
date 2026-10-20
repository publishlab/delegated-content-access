//
// Where the walk over the page's issuers ends, when the answer is a 200.
//
// An issuer that refuses has decided, and walking past a 401 or a 403 would be
// shopping for an issuer that says yes. This demo has no trusted complete-
// outcome retry classification, so a 200 holding no key is terminal too:
// `key_retired`, silence, admitted family outcomes, and malformed or
// unsupported answers remain visible at the issuer that returned them. Network
// failures and 5xx responses remain retryable in the ordered demo walk.
//
// The last case has no eligible route identity after a cache hit. The walk
// skips each issuer locally and sends no empty request; the cached key still
// opens the article.
//
// Pinned: two issuers over one publisher, direct transport, no access policy,
// one accessGroup, one content item, a network that is up and fast, and a clock
// that stands still. All of that is `demo/scenarios/world.js`'s actor family; what
// this file adds is the second issuer and the order the client walks the two
// in. What varies is whether the first issuer still holds its key, and whether
// it is standing in for a primary.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { DcaRequestBuilder } from "../../core-client/DcaRequestBuilder.js";
import { utf8Decode } from "../../core-shared/codec.js";
import { actorWorld, readArticle } from "../../demo/scenarios/world.js";
import { rootFromPage } from "../../demo/support/queryableRoot.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  CONTENT_NAME,
  ISSUER_NAME as SECOND,
  KEY_ID,
  UNLOCK_URL as SECOND_UNLOCK,
} from "../../demo/scenarios/fixtures.js";

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
     * @returns {Promise<import('../../demo/support/Page.js').Page>}
     */
    render: (label) => stage.render(label),
  };
}

describe("A 200 that delivered nothing", () => {
  test("an issuer that answers 200 holding no key is the terminal answer", async () => {
    const { network, browser, servers, render } = await world();

    // The first issuer has let its key go, and the page still names it: markup
    // on an edge cache outlives a rotation.
    servers.first.retireKey(KEY_ID);

    const read = await readArticle(browser, await render("A"), [CONTENT_NAME]);

    assert.deepEqual(
      read.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["key_retired"],
      "the no-key 200 remains visible at the issuer that returned it",
    );
    assert.equal(
      read.unlock.attempts[0].status,
      200,
      "the issuer was up, and the walk kept what it said",
    );

    assert.equal(read.unlock.ok, false);
    assert.equal(read.unlock.issuerName, FIRST);
    assert.equal(read.unlock.transportMode, null);
    assert.equal(read.load.stats().answeredBy, null);

    assert.equal(read.texts[CONTENT_NAME], null, "the article stays locked");
    assert.equal(read.errors[CONTENT_NAME], "no_key");

    assert.equal(servers.first.stats().grants, 0);
    assert.equal(servers.second.stats().grants, 0);
    assert.ok(servers.first.stats().unsealFailures > 0, "every coordinate came back an error");
    assert.equal(network.stats()[FIRST_UNLOCK].attempts, 1);
    assert.equal(
      network.stats()[SECOND_UNLOCK],
      undefined,
      "no keyless 200 permits a sibling attempt",
    );

    // The breaker is for an issuer that cannot be reached. This one answered,
    // and taking it out of the walk for saying so would keep the client from
    // the day its key comes back.
    assert.deepEqual(browser.stats().breaker[FIRST_UNLOCK], {
      state: "closed",
      failures: 0,
      openedAt: null,
    });
    assert.equal(browser.stats().unlockFailures, 1);
  });

  test("a codeless per-item error is terminal without a trusted retry classification", async () => {
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
        ["malformed_error"],
      );
      assert.equal(unlock.ok, false);
      assert.equal(unlock.issuerName, FIRST);
      assert.equal(network.stats()[SECOND_UNLOCK], undefined);
      assert.equal((await load.open(CONTENT_NAME)).bytes, null);
    } finally {
      network.post = post;
    }
  });

  test("a zero-accepted unsupported section is visible and terminal", async () => {
    const { network, browser, render } = await world();
    const post = network.post.bind(network);
    network.post = async (url, payload, options) =>
      url === FIRST_UNLOCK
        ? {
            status: 200,
            body: {
              transport: { method: "client-bound-test" },
              keys: { chainKeys: { premium: { "251023T15": { key: "wrapped-chain" } } } },
            },
          }
        : post(url, payload, options);

    try {
      const load = browser.load(rootFromPage(await render("A")));
      await load.resolve([CONTENT_NAME]);
      const unlock = await load.unlock();

      assert.deepEqual(
        unlock.attempts.map((/** @type {any} */ attempt) => attempt.outcome),
        ["unsupported_section"],
      );
      assert.equal(unlock.ok, false);
      assert.equal(unlock.issuerName, FIRST);
      assert.equal(
        load.stats().answeredBy,
        null,
        "an unsupported answer does not authorize a sibling attempt",
      );
      assert.equal(network.stats()[SECOND_UNLOCK], undefined);
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

  test("a no-key 200 stops the walk before another issuer can answer", async () => {
    const { browser, servers, render } = await world();

    // Both issuers have let the key go, but the first 200 is terminal: this
    // demo has no trusted classification that makes that complete outcome
    // retryable.
    servers.first.retireKey(KEY_ID);
    servers.second.retireKey(KEY_ID);

    const read = await readArticle(browser, await render("A"), [CONTENT_NAME]);

    assert.deepEqual(
      read.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["key_retired"],
    );
    assert.equal(read.unlock.ok, false);
    assert.equal(read.unlock.issuerName, FIRST);
    assert.equal(read.unlock.status, 200);
    assert.equal(read.unlock.transportMode, null);

    assert.equal(read.texts[CONTENT_NAME], null, "the article stays locked");
    assert.equal(read.errors[CONTENT_NAME], "no_key");
    assert.equal(browser.stats().unlockFailures, 1);
  });
});

describe("A 200 carrying a non-base withholding outcome", () => {
  test("a fallback trim without independent missing-supply evidence is terminal", async () => {
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

    assert.deepEqual(
      unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["empty"],
    );
    assert.equal(unlock.ok, false);
    assert.equal(unlock.issuerName, FIRST);
    assert.equal(unlock.status, 200);
    assert.equal(network.stats()[SECOND_UNLOCK], undefined, "the next issuer was not asked");

    assert.equal(servers.first.stats().grants, 0, "the malformed outcome carried no grant");
    assert.equal(browser.stats().unlockFailures, 1);

    const { bytes, error } = await load.open(CONTENT_NAME);
    assert.equal(bytes, null, "the article stays locked after the terminal family result");
    assert.equal(error, "no_key");
  });

  for (const [name, body, outcome] of [
    [
      "a denied family report",
      { keys: { contentKeys: {} }, notDelivered: { [ACCESS_GROUP]: { reason: "denied" } } },
      "denied",
    ],
    [
      "an unavailable family report without trusted retry configuration",
      { keys: {}, notDelivered: { [ACCESS_GROUP]: { reason: "unavailable" } } },
      "unavailable",
    ],
    ["a silent no-key result", { keys: { contentKeys: {} } }, "empty"],
    ["a malformed family report", { keys: {}, notDelivered: {} }, "malformed_response"],
  ]) {
    test(`${name} stays visible instead of advancing the walk`, async () => {
      const { network, browser, render } = await world();
      const post = network.post.bind(network);
      network.post = async (url, payload, options) =>
        url === FIRST_UNLOCK ? { status: 200, body } : post(url, payload, options);

      try {
        const load = browser.load(rootFromPage(await render("A")));
        await load.resolve([CONTENT_NAME]);
        const unlock = await load.unlock();

        assert.deepEqual(
          unlock.attempts.map((/** @type {any} */ attempt) => attempt.outcome),
          [outcome],
        );
        assert.equal(unlock.ok, false);
        assert.equal(unlock.issuerName, FIRST);
        assert.equal(network.stats()[SECOND_UNLOCK], undefined);
      } finally {
        network.post = post;
      }
    });
  }
});

describe("A request that asked for nothing", () => {
  test("an unlock with no eligible identity skips both issuers and the cached key still opens", async () => {
    const { network, browser, servers, render } = await world();

    const first = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.equal(first.unlock.ok, true);
    assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);

    // The next article of the same period is opened by the key the first one
    // fetched, so this load is missing nothing. It unlocks anyway, but no
    // issuer receives a request with no coordinate.
    const load = browser.load(rootFromPage(await render("B")));
    assert.deepEqual(await load.resolve([CONTENT_NAME]), { covered: [CONTENT_NAME], missing: [] });

    const unlock = await load.unlock();

    assert.equal(unlock.ok, false);
    assert.equal(unlock.status, null);
    assert.equal(unlock.issuerName, null);
    assert.deepEqual(
      unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["no-eligible-route", "no-eligible-route"],
    );
    assert.equal(unlock.transportMode, null, "no key arrived, so there is no mode to read off one");

    assert.equal(
      servers.first.stats().unsealFailures,
      0,
      "nothing was asked for, so nothing failed",
    );
    assert.equal(network.stats()[FIRST_UNLOCK].attempts, 1);
    assert.equal(network.stats()[SECOND_UNLOCK], undefined, "the second issuer was not asked");

    // The cache already covers the read even though no issuer was asked.
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

async function scopedWorld({
  retry = true,
  reason = "unavailable",
  grant = true,
  openSummary = false,
  malformed = false,
  sourceError = false,
  chainProjection = false,
  unsupportedProjection = false,
  unsolicitedBackup = false,
} = {}) {
  const stage = await actorWorld();
  await stage.standUp(FIRST, FIRST_UNLOCK);
  const page = await stage.render("A", {
    items: [{ name: "summary", value: "archive plaintext", accessGroups: ["archive"] }],
  });
  const calls = [];
  const post = stage.network.post.bind(stage.network);
  const network = {
    async post(url, request, options) {
      calls.push({ url, request: structuredClone(request) });
      // The chain case isolates projection, not chain cryptography. A real
      // period route supplies the returned key; fake extra chain envelopes
      // distinguish each issuer's own contribution in the captured request.
      const actual = structuredClone(request);
      delete actual.extensions;
      delete actual.periodGeometry;
      delete actual.requestedPeriodKeys;
      delete actual.sealed.chainKeys;
      const answer = await post(url, actual, options);
      if (url !== FIRST_UNLOCK) {
        if (unsolicitedBackup)
          answer.body.keys.contentKeys = { bodytext: "AAAAAAAAAAAAAAAAAAAAAA" };
        return answer;
      }
      const contentKeys = {};
      if (grant) contentKeys[CONTENT_NAME] = answer.body.keys.contentKeys[CONTENT_NAME];
      if (openSummary) contentKeys.summary = answer.body.keys.contentKeys.summary;
      return {
        status: 200,
        body: {
          keys: { contentKeys },
          ...(sourceError
            ? {
                errors: {
                  [`archive|${Object.keys(request.sealed.periodKeys.archive)[0]}`]: {
                    error: "unseal_failed",
                  },
                },
              }
            : {}),
          ...(reason === null || sourceError
            ? {}
            : { notDelivered: malformed ? {} : { archive: { reason } } }),
        },
      };
    },
  };
  const base = new DcaRequestBuilder({ relayPeriodKeys: true });
  const requestBuilderFactory = () => ({
    build(data, issuerName, needed) {
      const doc = base.build(data, issuerName, needed).toObject();
      if (unsupportedProjection) doc.extensions = ["invented-test-extension"];
      if (chainProjection) {
        doc.sealed.chainKeys = {
          premium: { "251023T1400": `${issuerName}-premium` },
          archive: { "251023T1400": `${issuerName}-archive` },
        };
        doc.periodGeometry = { chainsPerDay: 1, periodMinutes: 60 };
        doc.requestedPeriodKeys = { premium: ["251023T1400"], archive: ["251023T1400"] };
      }
      return { toObject: () => doc };
    },
  });
  const browser = stage.makeBrowser({
    network,
    ...(chainProjection || unsupportedProjection ? { requestBuilderFactory } : {}),
    issuers: [
      { issuerName: FIRST, unlockUrl: FIRST_UNLOCK, retryUnavailable: retry },
      { issuerName: SECOND, unlockUrl: SECOND_UNLOCK },
    ],
  });
  return { stage, page, browser, calls };
}

describe("Scoped explicitly configured availability fallback", () => {
  test("unrelated success keeps its plaintext while backup receives only the unavailable family", async () => {
    const { page, browser, calls } = await scopedWorld();
    const load = browser.load(rootFromPage(page));
    await load.resolve([CONTENT_NAME, "summary"]);
    const result = await load.unlock();
    assert.equal(result.ok, true);
    assert.equal(calls.length, 2);
    const backup = calls[1].request;
    assert.equal(calls[1].url, SECOND_UNLOCK);
    assert.deepEqual(
      backup.sealed.contentKeys,
      {},
      "silent summary content-key alternative is not retryable",
    );
    assert.deepEqual(Object.keys(backup.sealed.periodKeys), ["archive"]);
    assert.deepEqual(
      backup.sealed.periodKeys.archive,
      load.dcaData.issuerData[SECOND].sealed.periodKeys.archive,
    );
    assert.notDeepEqual(
      backup.sealed.periodKeys.archive,
      calls[0].request.sealed.periodKeys.archive,
      "the next issuer receives its own envelopes",
    );
    assert.equal(utf8Decode((await load.open(CONTENT_NAME)).bytes), ARTICLES.A);
    assert.equal(utf8Decode((await load.open("summary")).bytes), "archive plaintext");
  });

  test("equal independent batched and split outcomes select the same backup family", async () => {
    const batch = await scopedWorld();
    const batchLoad = batch.browser.load(rootFromPage(batch.page));
    await batchLoad.resolve([CONTENT_NAME, "summary"]);
    await batchLoad.unlock();
    const split = await scopedWorld({ grant: false });
    const splitLoad = split.browser.load(rootFromPage(split.page));
    await splitLoad.resolve(["summary"]);
    await splitLoad.unlock();
    assert.deepEqual(
      batch.calls[1].request.sealed.contentKeys,
      split.calls[1].request.sealed.contentKeys,
    );
    assert.deepEqual(
      Object.keys(batch.calls[1].request.sealed.periodKeys),
      Object.keys(split.calls[1].request.sealed.periodKeys),
    );
    assert.equal(utf8Decode((await splitLoad.open("summary")).bytes), "archive plaintext");
  });

  for (const [name, options] of [
    ["denial", { reason: "denied" }],
    ["source opening error without a selected retry profile", { sourceError: true }],
    ["silence", { reason: null }],
    ["malformed report", { malformed: true }],
    ["absent trusted classification", { retry: false }],
    ["an already-open item", { openSummary: true }],
  ]) {
    test(`${name} supplies no conditional retry`, async () => {
      const { page, browser, calls } = await scopedWorld(options);
      const load = browser.load(rootFromPage(page));
      await load.resolve([CONTENT_NAME, "summary"]);
      await load.unlock();
      assert.equal(calls.length, 1);
      if (name !== "malformed report")
        assert.equal(utf8Decode((await load.open(CONTENT_NAME)).bytes), ARTICLES.A);
    });
  }
});

test("chain family projection retains shared geometry and prunes article hints before association", async () => {
  const { page, browser, calls } = await scopedWorld({ chainProjection: true });
  const load = browser.load(rootFromPage(page));
  await load.resolve([CONTENT_NAME, "summary"]);
  assert.equal((await load.unlock()).ok, true);
  const request = calls[1].request;
  assert.deepEqual(request.sealed.chainKeys, { archive: { "251023T1400": `${SECOND}-archive` } });
  assert.deepEqual(request.requestedPeriodKeys, { archive: ["251023T1400"] });
  assert.deepEqual(request.periodGeometry, { chainsPerDay: 1, periodMinutes: 60 });
  assert.deepEqual(request.sealed.contentKeys, {});
  assert.equal(utf8Decode((await load.open("summary")).bytes), "archive plaintext");
});

test("unsupported extension material is not forwarded into a conditional retry", async () => {
  const { page, browser, calls } = await scopedWorld({ unsupportedProjection: true });
  const load = browser.load(rootFromPage(page));
  await load.resolve([CONTENT_NAME, "summary"]);
  const result = await load.unlock();
  assert.equal(calls.length, 1);
  assert.equal(result.attempts[1].outcome, "unsupported-retry-projection");
  assert.equal(result.ok, true, "a retained partial grant survives retry exhaustion");
  assert.equal(utf8Decode((await load.open(CONTENT_NAME)).bytes), ARTICLES.A);
});

test("association ignores a backup's unsolicited item key while admitting its family", async () => {
  const { page, browser, calls } = await scopedWorld({ unsolicitedBackup: true });
  const load = browser.load(rootFromPage(page));
  await load.resolve([CONTENT_NAME, "summary"]);
  await load.unlock();
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1].request.sealed.contentKeys, {});
  assert.equal(utf8Decode((await load.open("summary")).bytes), "archive plaintext");
  assert.equal(
    utf8Decode((await load.open(CONTENT_NAME)).bytes),
    ARTICLES.A,
    "unsolicited replacement did not overwrite the admitted content key",
  );
});
