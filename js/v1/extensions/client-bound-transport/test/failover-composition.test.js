// @ts-check
// Sibling to base suite: js/v1/test/transport.test.js
//
// A client-bound primary, a direct fallback, and the return to the primary.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { run as goingDownAndComingBack } from "../../../demo/scenarios/failover.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  DOMAIN,
  FALLBACK_ISSUER_NAME as FALLBACK,
  FALLBACK_UNLOCK_URL as FALLBACK_UNLOCK,
  HEALTH_URL as PRIMARY_HEALTH,
  ISSUER_NAME as PRIMARY,
  UNLOCK_URL as PRIMARY_UNLOCK,
} from "../../../demo/scenarios/fixtures.js";
const PUB = `https://${DOMAIN}`;

/**
 * The canonical exact-period family a delivered key files under. V1 has one
 * exact-key width, so the cache no longer carries a profile segment.
 */
const FAMILY = `${PUB}|${ACCESS_GROUP}`;

describe("Going down and coming back", () => {
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
      { accessGroup: FAMILY, t: "251023T15", handle: true },
      { accessGroup: FAMILY, t: "251023T14", handle: true },
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
    assert.deepEqual(outage.periods, ["251023T16", "251023T17"]);
    assert.deepEqual(outage.cache[0], { accessGroup: FAMILY, t: "251023T16", handle: false });
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
        ["251023T18", true],
        ["251023T17", true],
        ["251023T16", false],
        ["251023T15", true],
        ["251023T14", true],
      ],
    );
  });
});
