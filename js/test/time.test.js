//
// The time axis. One clock moves - the publisher's - and these watch what a
// client that holds no clock at all makes of the result.
//
// The forward overlap: a render ships the period it was made in plus the next
// one, so a client that unlocked in T14 opens a T15 article out of its cache
// and nothing ever needs a key for a period already gone. Past the overlap the
// held keys stop matching: a miss and one more unlock, not an error and not an
// eviction.
//
// The time axis leaves the other half alone. The issuer unseals blobs and
// never parses `t`, so a page from three days ago unlocks exactly as it did the
// day it was rendered. The client only string-sorts the labels it
// was handed, so its own clock - skewed, absent, or unreachable - changes
// nothing.
//
// Pinned: one issuer, direct transport, grant-all policy, one accessGroup, one
// content item. The wiring is `demo/scenarios/world.js`'s direct-endpoint family -
// two cores facing each other, no network between them, which is all a story
// about `t` labels needs. Eviction, storage, the breaker and access policy are
// each a file of their own; formatT refuses invalid dates at its producer
// boundary, and eviction in particular is why "an old cached
// article still unlocks after eviction" is not here yet.

import test from "node:test";
import assert from "node:assert/strict";

import { formatT } from "../core-shared--publisher-issuer/periodKeys.js";
import { decodeHeader } from "../core-shared--publisher-issuer/jwt.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { Client } from "../test-lib/harnesses/client.js";
import { ContentKeyResolver } from "../core-client/ContentKeyResolver.js";
import { Clock } from "../demo/actors/Clock.js";
import { base64urlEncode, utf8Decode } from "../core-shared/codec.js";
import { directWorld } from "../demo/scenarios/world.js";
import { Sealer } from "../core-publisher/Sealer.js";
import { randomPeriodKeySupply } from "../demo/support/randomPeriodKeySupply.js";
import {
  ACCESS_GROUP,
  ALGORITHM,
  ARTICLES,
  CONTENT_NAME,
  CONTENT_TYPE,
  DOMAIN,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  RESOURCE_ID,
  SIGNING_KID,
  article,
} from "../demo/scenarios/fixtures.js";
import { countingEndpoint } from "../test-lib/harnesses/issuer-endpoint.js";
import { held, issuerPeriodsOn, periodsOn } from "../test-lib/helpers/inspect.js";
import { refuses } from "../test-lib/helpers/refuses.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../test-reference/support/keys.js";
import { wholeRenderIssuerSupplyPlan } from "../core-publisher/issuerSupplyPlan.js";

/** The second publisher of the last test, which is the only one that needs it. */
const DOMAINS = [DOMAIN, "www.other-paper.example"];

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/**
 * Runs something with no clock in the process at all: every use of `Date`
 * throws for the length of the call. A client that reached for the time - to
 * pick a `t`, to expire an entry, to order candidates - fails here rather than
 * in some scenario where a skew is hard to see.
 *
 * @template T
 * @param {() => Promise<T>} run
 * @returns {Promise<T>}
 */
async function withoutAmbientTime(run) {
  const real = globalThis.Date;
  const reached = () => {
    throw new Error("the client reached for ambient time");
  };

  class NoDate {
    constructor() {
      reached();
    }

    static now() {
      return reached();
    }

    static parse() {
      return reached();
    }

    static UTC() {
      return reached();
    }
  }

  globalThis.Date = /** @type {any} */ (NoDate);
  try {
    return await run();
  } finally {
    globalThis.Date = real;
  }
}

/**
 * Runs something with the process's own clock moved. This is where a browser's
 * skew actually lives - the machine is wrong, and nothing was injected into
 * the client to say so. `null` takes the clock away entirely.
 *
 * @template T
 * @param {number|null} offsetMs
 * @param {() => Promise<T>} run
 * @returns {Promise<T>}
 */
async function withAmbientSkew(offsetMs, run) {
  if (offsetMs === null) return withoutAmbientTime(run);

  const real = globalThis.Date;
  class Skewed extends real {
    /** @param {any[]} args */
    constructor(...args) {
      if (args.length === 0) super(real.now() + offsetMs);
      else super(.../** @type {[any]} */ (args));
    }

    static now() {
      return real.now() + offsetMs;
    }
  }

  globalThis.Date = /** @type {any} */ (Skewed);
  try {
    return await run();
  } finally {
    globalThis.Date = real;
  }
}

test("the forward-overlap key carries the client across the flip, at no unlock", async () => {
  const { clock, publisherRegistration, render } = await directWorld();

  const cache = new PeriodKeyCache();
  const unsealer = new Client({ cache, publisherOrigin: ORIGIN });
  const endpoint = countingEndpoint(publisherRegistration);

  const pageA = await render("A");
  assert.deepEqual(
    periodsOn(pageA),
    ["251023T1400", "251023T1500"],
    "the period it was rendered in, and one forward",
  );

  const a = unsealer.parse(pageA);
  const { body } = await endpoint.unlock(unsealer.buildRequest(a, ISSUER_NAME, ["bodytext"]));
  await unsealer.applyResponse(a, ISSUER_NAME, body);

  assert.equal(endpoint.calls.count, 1);
  assert.deepEqual(await held(cache), ["251023T1500", "251023T1400"], "one unlock, both periods");

  // Past the flip. The next render is a period on.
  clock.advance(50 * MINUTE);
  assert.equal(formatT(clock.now()), "251023T1500");

  const pageB = await render("B");
  assert.deepEqual(periodsOn(pageB), ["251023T1500", "251023T1600"]);

  const b = unsealer.parse(pageB);
  const { covered, missing } = await unsealer.resolve(b, ["bodytext"]);
  assert.deepEqual(covered, ["bodytext"], "the overlap key from the T14 unlock opens a T15 render");
  assert.deepEqual(missing, []);

  const plaintext = await unsealer.decrypt(b, "bodytext", unsealer.extract(pageB, "bodytext"));
  assert.equal(utf8Decode(plaintext), ARTICLES.B);
  assert.equal(endpoint.calls.count, 1, "the flip cost nothing");

  // No backward key anywhere: not shipped to the client, not shipped to the
  // issuer, and never wanted. Both pages label their own period first and go
  // forward from it.
  for (const [page, renderedIn] of [
    [pageA, "251023T1400"],
    [pageB, "251023T1500"],
  ]) {
    assert.equal(periodsOn(page)[0], renderedIn);
    for (const t of periodsOn(page)) {
      assert.ok(t >= renderedIn, `${t} is behind the period the page was rendered in`);
    }
    assert.deepEqual(
      issuerPeriodsOn(page),
      periodsOn(page),
      "both sides of the wire name the same periods",
    );
  }

  assert.deepEqual(
    await held(cache),
    ["251023T1500", "251023T1400"],
    "and the client acquired nothing new to do it",
  );
});

test("a period past the overlap is a plain miss, and the keys that missed stay", async () => {
  const { clock, publisherRegistration, render } = await directWorld();

  const cache = new PeriodKeyCache();
  const unsealer = new Client({ cache, publisherOrigin: ORIGIN });
  const endpoint = countingEndpoint(publisherRegistration);

  const a = unsealer.parse(await render("A"));
  await unsealer.applyResponse(
    a,
    ISSUER_NAME,
    (await endpoint.unlock(unsealer.buildRequest(a, ISSUER_NAME, ["bodytext"]))).body,
  );
  assert.deepEqual(await held(cache), ["251023T1500", "251023T1400"]);

  // Two periods on - one further than the overlap reaches.
  clock.advance(2 * HOUR);
  assert.equal(formatT(clock.now()), "251023T1600");

  const pageC = await render("C");
  assert.deepEqual(periodsOn(pageC), ["251023T1600", "251023T1700"]);

  const c = unsealer.parse(pageC);
  const { covered, missing } = await unsealer.resolve(c, ["bodytext"]);
  assert.deepEqual(covered, []);
  assert.deepEqual(missing, ["bodytext"], "nothing held opens a period the unlock never covered");

  await assert.rejects(
    () => unsealer.decrypt(c, "bodytext", unsealer.extract(pageC, "bodytext")),
    (/** @type {any} */ err) => err.code === "no_key",
    "a miss is a typed miss, not a wrong plaintext",
  );

  assert.deepEqual(
    await held(cache),
    ["251023T1500", "251023T1400"],
    "the stale keys are still there - a failed trial evicts nothing and errors nothing",
  );

  // One unlock closes it, and the old entries sit beside the new ones.
  const { body } = await endpoint.unlock(unsealer.buildRequest(c, ISSUER_NAME, missing));
  await unsealer.applyResponse(c, ISSUER_NAME, body);

  assert.equal(endpoint.calls.count, 2);
  assert.deepEqual(await held(cache), ["251023T1700", "251023T1600", "251023T1500", "251023T1400"]);
  assert.equal(
    utf8Decode(await unsealer.decrypt(c, "bodytext", unsealer.extract(pageC, "bodytext"))),
    ARTICLES.C,
  );
});

test("the client owns no clock: skew the ambient one either way, or take it away", async () => {
  const { clock, publisherRegistration, render } = await directWorld();

  const pageA = await render("A");
  clock.advance(50 * MINUTE);
  const pageB = await render("B");
  const firstT = periodsOn(pageA)[0];

  // There is nowhere for a client clock to enter. The client takes a cache
  // and refuses anything else, so a scenario that wanted to skew the client
  // cannot hand it a moment - which is the strongest form this claim has.
  assert.throws(
    () => new Client({ cache: new PeriodKeyCache(), clock: new Clock("2025-10-23T09:00:00Z") }),
    (/** @type {any} */ err) => err.code === "unsupported_option",
    "a client that took a clock could disagree with the publisher about `t`",
  );

  // So the skew goes where a browser's actually is: the ambient clock. Three
  // clients over the same two pages, one hours behind the publisher, one
  // hours ahead, one with no `Date` at all.
  const runs = [];
  for (const skew of [-5 * HOUR, 12 * HOUR, null]) {
    const cache = new PeriodKeyCache();
    const unsealer = new Client({ cache, publisherOrigin: ORIGIN });
    const endpoint = countingEndpoint(publisherRegistration);

    runs.push(
      await withAmbientSkew(skew, async () => {
        const a = unsealer.parse(pageA);
        await unsealer.applyResponse(
          a,
          ISSUER_NAME,
          (await endpoint.unlock(unsealer.buildRequest(a, ISSUER_NAME, ["bodytext"]))).body,
        );

        const b = unsealer.parse(pageB);
        const { covered, missing } = await unsealer.resolve(b, ["bodytext"]);

        return {
          covered,
          missing,
          held: await held(cache),
          // The trial order too, not just the outcome: it is a string
          // sort on the label, so a client that thought it knew the time
          // could not change it.
          candidates: (
            await cache.candidatesAt("premium", firstT, { publisher: `https://${DOMAIN}` })
          ).map((/** @type {any} */ key) => base64urlEncode(key)),
          plaintext: utf8Decode(
            await unsealer.decrypt(b, "bodytext", unsealer.extract(pageB, "bodytext")),
          ),
          calls: endpoint.calls.count,
        };
      }),
    );
  }

  assert.deepEqual(runs[1], runs[0], "hours ahead reads the same as hours behind");
  assert.deepEqual(runs[2], runs[0], "and so does a client with no clock at all");

  assert.deepEqual(runs[0].covered, ["bodytext"]);
  assert.equal(runs[0].plaintext, ARTICLES.B);
  assert.deepEqual(runs[0].held, ["251023T1500", "251023T1400"]);
  assert.equal(runs[0].calls, 1);

  // Structural, so the sameness above is not a coincidence of these inputs:
  // no call on the client side takes a moment, so there is nowhere for a
  // skewed one to enter.
  assert.equal(PeriodKeyCache.prototype.put.length, 3, "accessGroup, t, key - and no now");
  assert.equal(PeriodKeyCache.prototype.candidatesAt.length, 2, "accessGroup, t, and no now");
  assert.equal(ContentKeyResolver.prototype.resolve.length, 2);
  assert.equal(ContentKeyResolver.prototype.contentKeyFor.length, 2);
  assert.equal(Client.prototype.decrypt.length, 3);
});

test("the client reaches for no ambient clock either", async () => {
  const { clock, publisherRegistration, render } = await directWorld();

  const pageA = await render("A");
  clock.advance(50 * MINUTE);
  const pageB = await render("B");

  const cache = new PeriodKeyCache();
  const unsealer = new Client({ cache, publisherOrigin: ORIGIN });
  const endpoint = countingEndpoint(publisherRegistration);

  const a = unsealer.parse(pageA);
  const { body } = await endpoint.unlock(unsealer.buildRequest(a, ISSUER_NAME, ["bodytext"]));

  // Everything the client does with what came back, done with `Date` taken
  // away from it.
  const outcome = await withoutAmbientTime(async () => {
    await unsealer.applyResponse(a, ISSUER_NAME, body);

    const b = unsealer.parse(pageB);
    const { covered, missing } = await unsealer.resolve(b, ["bodytext"]);
    const plaintext = await unsealer.decrypt(b, "bodytext", unsealer.extract(pageB, "bodytext"));

    return { covered, missing, plaintext: utf8Decode(plaintext), held: await held(cache) };
  });

  assert.deepEqual(outcome.covered, ["bodytext"]);
  assert.deepEqual(outcome.missing, []);
  assert.equal(outcome.plaintext, ARTICLES.B);
  assert.deepEqual(outcome.held, ["251023T1500", "251023T1400"]);
  assert.equal(endpoint.calls.count, 1);

  // The trap is armed: the same call outside the window proves it.
  await assert.rejects(
    () => withoutAmbientTime(async () => new Date()),
    /reached for ambient time/,
    "a reach for the time inside the window fails the run",
  );
});

test("an article rendered periods ago still unlocks from the keys it shipped with", async () => {
  const { clock, publisherRegistration, render } = await directWorld();

  const recorded = await render("A");
  assert.deepEqual(periodsOn(recorded), ["251023T1400", "251023T1500"]);

  // Three days on. Nothing the publisher renders now names those periods.
  clock.advance(3 * 24 * HOUR);
  assert.equal(formatT(clock.now()), "251026T1400");

  const cache = new PeriodKeyCache();
  const unsealer = new Client({ cache, publisherOrigin: ORIGIN });
  const endpoint = countingEndpoint(publisherRegistration);

  const a = unsealer.parse(recorded);
  const { status, body } = await endpoint.unlock(
    unsealer.buildRequest(a, ISSUER_NAME, ["bodytext"]),
  );

  assert.equal(status, 200);
  assert.equal(body.errors, undefined, "the issuer unseals a blob; it never reads the t on it");
  assert.deepEqual(
    Object.keys(body.keys.periodKeys.premium),
    ["251023T1400", "251023T1500"],
    "the periods the page was rendered with, handed back as they are",
  );
  assert.deepEqual(Object.keys(body.keys.contentKeys), ["bodytext"]);

  await unsealer.applyResponse(a, ISSUER_NAME, body);
  assert.deepEqual(await held(cache), ["251023T1500", "251023T1400"]);

  const plaintext = await unsealer.decrypt(a, "bodytext", unsealer.extract(recorded, "bodytext"));
  assert.equal(utf8Decode(plaintext), ARTICLES.A);

  // Its own shipped keys open it, and nothing else does: a client holding only
  // what today's render carries makes nothing of it.
  const today = await render("C");
  const other = new Client({ cache: new PeriodKeyCache(), publisherOrigin: ORIGIN });

  const todayData = other.parse(today);
  await other.applyResponse(
    todayData,
    ISSUER_NAME,
    (await endpoint.unlock(other.buildRequest(todayData, ISSUER_NAME, ["bodytext"]))).body,
  );
  assert.deepEqual(periodsOn(today), ["251026T1400", "251026T1500"]);

  assert.deepEqual(
    (await other.resolve(other.parse(recorded), ["bodytext"])).missing,
    ["bodytext"],
    "a period label repeating three days later is a different period and a different key",
  );
});

test("period length and slot count are per publisher: two of them in one process", async () => {
  // Both of them sign with the one key, which the issuer holds for both
  // domains - so nothing here is kept apart by who signed it.
  const { publisherRegistrations, publisherWith } = await directWorld({ domains: DOMAINS });

  // Two publishers alive at once, rendering in the same turn. A period settled
  // at module scope would show up here as one config answering for both.
  const hourly = publisherWith({ period: { length: 60, slots: 2 } });
  const quarterly = publisherWith({
    domain: DOMAINS[1],
    periodKeySupply: randomPeriodKeySupply({ random: seededRandom(11) }),
    period: { length: 15, slots: 3 },
  });

  const [pageA, pageB] = (
    await Promise.all([hourly.render(article("A")), quarterly.render(article("B"))])
  ).map((page) => page.asJson());

  assert.deepEqual(periodsOn(pageA), ["251023T1400", "251023T1500"], "hourly, two slots");
  assert.deepEqual(
    periodsOn(pageB),
    ["251023T1415", "251023T1430", "251023T1445"],
    "quarter-hourly, three",
  );
  assert.deepEqual(issuerPeriodsOn(pageA), periodsOn(pageA));
  assert.deepEqual(issuerPeriodsOn(pageB), periodsOn(pageB));

  // And a render after both, on the first publisher's config again.
  const again = (await hourly.render(article("C"))).asJson();
  assert.deepEqual(
    periodsOn(again),
    ["251023T1400", "251023T1500"],
    "the other publisher left nothing behind",
  );

  // The client side keeps them apart on the labels alone. One issuer serves
  // both publishers, and the accessGroup is called `premium` on both pages.
  // Both pages are read at the quarter-hourly publisher's delivery origin, the
  // one whose keys the cache holds, so the publisher segment of the coordinate
  // is held still and what separates the two families is the `t` labels.
  const cache = new PeriodKeyCache();
  const unsealer = new Client({ cache, publisherOrigin: `https://${DOMAINS[1]}` });
  const endpoint = countingEndpoint(
    publisherRegistrations.get(decodeHeader(pageB.resourceJWT).kid),
  );

  const b = unsealer.parse(pageB);
  await unsealer.applyResponse(
    b,
    ISSUER_NAME,
    (await endpoint.unlock(unsealer.buildRequest(b, ISSUER_NAME, ["bodytext"]))).body,
  );
  assert.deepEqual(await held(cache), ["251023T1445", "251023T1430", "251023T1415"]);

  assert.deepEqual(
    (await unsealer.resolve(unsealer.parse(pageA), ["bodytext"])).missing,
    ["bodytext"],
    "one publisher's periods are not the other's",
  );
  assert.equal(
    utf8Decode(await unsealer.decrypt(b, "bodytext", unsealer.extract(pageB, "bodytext"))),
    ARTICLES.B,
    "and its own page still opens",
  );
});

//
// A publisher clock that answers an invalid Date. `seal()` reads its instant
// once and refuses before a malformed period label or render can be emitted.
//

/**
 * A Sealer wired for one render, with the clock and the periodKey supply left
 * to the caller: the clock is what is under test, and the supply counts what it
 * was asked for.
 *
 * @param {{ now: () => Date }} clock
 * @param {import('../core-publisher/Sealer.js').PeriodKeySupply} periodKeySupply
 * @returns {Promise<Sealer>}
 */
async function sealerWith(clock, periodKeySupply) {
  const signing = await signingKeypair();
  const issuerKeys = await issuerKeypair();

  const sealer = new Sealer({
    origin: ORIGIN,
    clock,
    random: seededRandom(20251023),
    signingKeys: { [SIGNING_KID]: signing.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        publicKey: issuerKeys.publicKey,
      },
    ],
    periodKeySupply,
  });
  sealer.resource(RESOURCE_ID, {});
  sealer.content(CONTENT_NAME, ARTICLES.A, CONTENT_TYPE, { accessGroups: [ACCESS_GROUP] });
  return sealer;
}

test("a publisher clock answering an invalid Date refuses the render, and requests no period key", async () => {
  const chain = randomPeriodKeySupply();
  /** @type {{ accessGroup: string, t: string }[]} */
  const asked = [];
  const supply = {
    /**
     * @param {string} accessGroup
     * @param {string} t
     */
    derive: (accessGroup, t) => {
      asked.push({ accessGroup, t });
      return chain.derive(accessGroup, t);
    },
  };

  const sealer = await sealerWith({ now: () => new Date(NaN) }, supply);

  await refuses(
    () => sealer.seal(),
    { code: "bad_config", message: /valid Date/ },
    "a render instant that is not a time is a publisher misconfiguration, not a RangeError out of toISOString",
  );

  // The claim that survives a reorder. The refusal above happens to sit ahead
  // of the supply call today; this one says the call never runs on a
  // clock like this, wherever the two end up standing relative to each other.
  assert.deepEqual(asked, [], "no periodKey is requested at a coordinate a broken clock named");
});
