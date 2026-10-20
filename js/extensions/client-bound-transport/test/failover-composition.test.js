// @ts-check
// Sibling to base suite: js/test-reference/demo-actors/transport.test.js
//
// A client-bound primary, a direct fallback, and the return to the primary.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { run as goingDownAndComingBack } from "../../../demo/scenarios/failover.js";
import { actorWorld, readArticle } from "../../../demo/scenarios/world.js";
import * as clientBoundEcdh from "../ecdhP256.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  CONTENT_NAME,
  DOMAIN,
  FALLBACK_ISSUER_NAME as FALLBACK,
  FALLBACK_UNLOCK_URL as FALLBACK_UNLOCK,
  HEALTH_URL as PRIMARY_HEALTH,
  ISSUER_NAME as PRIMARY,
  UNLOCK_URL as PRIMARY_UNLOCK,
} from "../../../demo/scenarios/fixtures.js";
const PUB = `https://${DOMAIN}`;

/**
 * The canonical period-key family a delivered key files under. V1 has one
 * period-key width, so the cache no longer carries a profile segment.
 */
const FAMILY = `${PUB}|${ACCESS_GROUP}`;

describe("Going down and coming back", () => {
  test("a strict endpoint's direct content-key and period-key entries cannot borrow the fallback endpoint's permission", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: clientBoundEcdh,
    });
    await stage.standUp(FALLBACK, FALLBACK_UNLOCK, { transportMode: "direct" });
    const page = await stage.render("A");
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
      "deriveKey",
    ]);
    const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const keyValue = "AAAAAAAAAAAAAAAAAAAAAA";
    const cachePuts = [];
    const browser = stage.makeBrowser({
      storage: undefined,
      cacheFactory: () => ({
        put(...args) {
          cachePuts.push(args[3].issuerName);
          return browser.cache.put(...args);
        },
        candidatesAt: (...args) => browser.cache.candidatesAt(...args),
        attempted: (...args) => browser.cache.attempted(...args),
      }),
      issuers: stage.routes.map(({ issuerName, unlockUrl }) => ({
        issuerName,
        unlockUrl,
        acceptDirectResponse: issuerName === FALLBACK,
      })),
      clientBoundKeyCapability: {
        publicKey,
        openDeliveredKeys() {
          throw new Error("neither direct response needs an opener");
        },
      },
      acceptDirectFallback: true,
      persistRawPeriodKeys: true,
      network: {
        post(url, request, context) {
          if (url !== PRIMARY_UNLOCK) return stage.network.post(url, request, context);
          const period = Object.keys(request.sealed.periodKeys[ACCESS_GROUP])[0];
          return Promise.resolve({
            status: 200,
            body: {
              keys: {
                contentKeys: { [CONTENT_NAME]: keyValue },
                periodKeys: { [ACCESS_GROUP]: { [period]: keyValue } },
              },
            },
          });
        },
      },
    });

    const read = await readArticle(browser, page, [CONTENT_NAME]);
    assert.equal(read.texts[CONTENT_NAME], null);
    assert.equal(read.errors[CONTENT_NAME], "no_key");
    assert.deepEqual(
      read.unlock.attempts.map(({ issuerName, outcome }) => [issuerName, outcome]),
      [[PRIMARY, "invalid_transport"]],
    );
    assert.equal(read.unlock.issuerName, PRIMARY);
    assert.equal(cachePuts.length, 0, "an invalid response files no period key");

    const independent = await readArticle(browser, page, [CONTENT_NAME], { issuerName: FALLBACK });
    assert.equal(independent.texts[CONTENT_NAME], ARTICLES.A);
    assert.deepEqual(
      independent.unlock.attempts.map(({ issuerName, outcome }) => [issuerName, outcome]),
      [[FALLBACK, "answered"]],
    );
    assert.equal(independent.unlock.issuerName, FALLBACK);
    assert.ok(cachePuts.length > 0, "the direct fallback files a period key");
    assert.ok(cachePuts.every((issuerName) => issuerName === FALLBACK));
  });

  test("one client rides the failover: client-bound, a direct answer trimmed to the current period, then client-bound again", async () => {
    const { steps, summary } = await goingDownAndComingBack();

    assert.deepEqual(
      steps.map((step) => step.kind),
      ["read", "advance", "outage", "read", "recovery", "read", "advance", "read"],
      "healthy, past the overlap, down, out to the fallback, back up, the tail, past the grant, resumed",
    );

    const [healthy, outage, tail, resumed] = steps.filter((step) => step.kind === "read");

    // The primary, in the mode it is configured for, and the client holds
    // two handles: the period the render was made in and the one forward.
    assert.equal(healthy.text, ARTICLES.A);
    assert.equal(healthy.answeredBy, PRIMARY);
    assert.equal(healthy.transportMode, "client-bound");
    assert.deepEqual(healthy.cache, [
      { accessGroup: FAMILY, t: "251023T1500", handle: true },
      { accessGroup: FAMILY, t: "251023T1400", handle: true },
    ]);

    // The outage. The primary is unreachable, the breaker opens on that one
    // call, and the fallback probes the primary itself before it grants. The
    // article opens all the same, and it opens on bytes.
    assert.equal(outage.text, ARTICLES.B);
    assert.deepEqual(
      outage.attempts.map((/** @type {any} */ attempt) => [attempt.issuerName, attempt.outcome]),
      [
        [PRIMARY, "offline"],
        [FALLBACK, "answered"],
      ],
    );
    assert.equal(outage.answeredBy, FALLBACK);
    assert.equal(outage.transportMode, "direct", "the client took the mode it was given");
    assert.equal(outage.breaker.state, "open");
    assert.equal(outage.wire[PRIMARY_HEALTH].probes, 1, "the fallback asked before it granted");

    // And it granted one period of it. The render shipped two; only the period
    // the client is reading in landed, in the transport a fallback has.
    assert.deepEqual(outage.periods, ["251023T1600", "251023T1700"]);
    assert.deepEqual(outage.cache[0], { accessGroup: FAMILY, t: "251023T1600", handle: false });
    assert.equal(outage.cache.length, 3, "the two handles are still there beside it");

    // The tail: the primary is back, and this article is still inside the
    // period the fallback granted during the outage. So it opens against an
    // outage key, at no unlock, after the thing that made that grant has
    // stopped being true. That reach is bounded by the period and by
    // nothing else.
    assert.equal(tail.text, ARTICLES.C);
    assert.equal(tail.calls, 0, "nothing crossed the wire for it");
    assert.equal(tail.status, null, "nothing was missing, so nobody was asked");
    assert.deepEqual(tail.cache, outage.cache, "and it collected nothing new");

    // Past that period, the client has to ask again. The primary that is
    // back answers in the mode it always had, on the same keypair this
    // client has been carrying since the first article.
    assert.equal(resumed.text, ARTICLES.D);
    assert.equal(resumed.answeredBy, PRIMARY);
    assert.equal(resumed.transportMode, "client-bound");
    assert.deepEqual(
      resumed.attempts.map((/** @type {any} */ attempt) => attempt.outcome),
      ["answered"],
      "the breaker half-opened, and the trial call was the unlock",
    );
    assert.deepEqual(resumed.breaker, { state: "closed", failures: 0, openedAt: null });

    // What the run cost, from both ends: three unlocks for four articles,
    // and one of the three went to the fallback.
    assert.equal(summary.unlocks, 3);
    assert.equal(summary.unlockFailures, 0, "every read opened its article");
    assert.equal(summary.wire[PRIMARY_UNLOCK].attempts, 3);
    assert.equal(summary.wire[PRIMARY_UNLOCK].failures, 1);
    assert.equal(summary.wire[FALLBACK_UNLOCK].attempts, 1);
    assert.equal(summary.servers.primary.grants, 2);
    assert.equal(summary.servers.fallback.grants, 1);

    // The client-bound answers stayed handles and the fallback's stayed
    // bytes, in one cache, for the whole run.
    assert.deepEqual(
      summary.cache.map((/** @type {any} */ entry) => [entry.t, entry.handle]),
      [
        ["251023T1800", true],
        ["251023T1700", true],
        ["251023T1600", false],
        ["251023T1500", true],
        ["251023T1400", true],
      ],
    );
  });
});
