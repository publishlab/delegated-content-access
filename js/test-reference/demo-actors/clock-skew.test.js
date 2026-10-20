// @ts-check
//
// Client and issuer clocks that straddle a period boundary. The rest of the
// suite moves one clock, the publisher's, and watches a clockless client read
// the result. This file gives the issuer a clock of its own, set on the far
// side of a boundary from the client, and asks which side's clock the granted
// period label follows.
//
// Only a fallback's clock reshapes `t`. The publisher's clock stamps the period
// labels at render time, both sides of the wire carry the same set, and the
// client string-sorts them with no clock of its own. The one place an issuer
// reads its clock to decide a period is the fallback's stage-6 trim
// (`demo/actors/issuer/trimToCurrentPeriod.js`, applied by `IssuerServer`
// as `trimToCurrentPeriod(body, this.#clock.now())`): a fallback grants the
// current period only, and "current" is the greatest presented label its own
// clock says has already started. The primary never trims, so on the primary
// path an issuer clock hours off the client changes nothing.
//
// So the boundary is watched through a fallback. Each server here is built with
// its own `new Clock(...)`, distinct from the publisher's render clock and from
// the client's ambient time, which is the skew the shared-clock world could not
// express. The client is driven under `withAmbientSkew`, because nothing injects
// a clock into a browser: its skew lives in the machine's `Date`, and that skew
// reaches nowhere.
//
// Pinned: the fallback grants the period its own clock is in whichever side of
// the boundary that is, the same render opens under either grant, a client
// skewed across the boundary cannot move the grant or the open, a fallback whose
// clock has reached no presented period trims reusable keys without inventing
// a missing-supply report, and the primary grants the presented periods whatever
// clock reads.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Clock } from "../../demo/actors/Clock.js";
import { Network } from "../../demo/actors/Network.js";
import { IssuerServer } from "../../demo/actors/IssuerServer.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { directWorld } from "../../demo/scenarios/world.js";
import { periodsOn, held } from "../../test-lib/helpers/inspect.js";
import { utf8Decode } from "../../core-shared/codec.js";
import {
  AT,
  ISSUER_NAME,
  ACCESS_GROUP,
  CONTENT_NAME,
  ARTICLES,
  ORIGIN,
  UNLOCK_URL,
  HEALTH_URL,
  T_NOW,
  T_NEXT,
} from "../../demo/scenarios/fixtures.js";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/**
 * The render clock is `AT` (twenty past two), so every page here ships
 * `[T_NOW, T_NEXT]` - the period it was made in, and the forward overlap. The
 * three issuer instants sit one per region of that pair: inside the make period,
 * across the boundary into the overlap, and behind both of them.
 */
const ISSUER_IN_RENDER = "2025-10-23T14:20:00Z"; // T_NOW has started, T_NEXT has not
const ISSUER_CROSSED = "2025-10-23T15:05:00Z"; // both started, greatest is T_NEXT
const ISSUER_BEHIND = "2025-10-23T13:30:00Z"; // neither has started yet

/**
 * Runs something with the process's own clock moved, which is the only place a
 * browser's skew can live - nothing is injected into the client to carry it.
 * `null` takes `Date` away entirely, so a client that reached for ambient time
 * fails the run rather than reading a skew that was supposed to be unreachable.
 *
 * @template T
 * @param {number|null} offsetMs
 * @param {() => Promise<T>} run
 * @returns {Promise<T>}
 */
async function withAmbientSkew(offsetMs, run) {
  const real = globalThis.Date;

  class Moved extends real {
    /** @param {any[]} args */
    constructor(...args) {
      if (offsetMs === null) throw new Error("the client reached for ambient time");
      if (args.length === 0) super(real.now() + offsetMs);
      else super(.../** @type {[any]} */ (args));
    }

    static now() {
      if (offsetMs === null) throw new Error("the client reached for ambient time");
      return real.now() + offsetMs;
    }
  }

  globalThis.Date = /** @type {any} */ (Moved);
  try {
    return await run();
  } finally {
    globalThis.Date = real;
  }
}

/**
 * One issuer standing on the simulated network with a clock of its own. A
 * fallback's health probe travels to `HEALTH_URL`, which nobody serves here, so
 * the probe no-routes and the gate opens - the fallback answers on its own.
 *
 * @param {'primary'|'fallback'} role
 * @param {string} issuerAt - the instant this issuer's clock reads
 * @returns {Promise<{ render: (label: string) => Promise<any>, network: Network }>}
 */
async function issuerOn(role, issuerAt) {
  const { render, keyStore, publisherRegistrations, publisherRegistration } = await directWorld();
  const network = new Network({ clock: new Clock(AT) });
  new IssuerServer({
    clock: new Clock(issuerAt),
    network,
    issuerName: ISSUER_NAME,
    unlockUrl: UNLOCK_URL,
    keyStore,
    publisherRegistrations,
    accessPolicy: new AllowAllPolicy(),
    periodKeyInput: true,
    role,
    healthCheckUrl: HEALTH_URL,
    ...(role === "fallback" ? { emergencyUntil: Date.parse(issuerAt) + 6 * HOUR } : {}),
  });
  return { render, network, publisherRegistration };
}

/**
 * A render, the request a client posts for it, and the response the issuer on
 * the network hands back. Kept apart from opening it, so a test can read the
 * grant before deciding what the client makes of it.
 *
 * @param {(label: string) => Promise<any>} render
 * @param {Network} network
 * @returns {Promise<{ page: any, dca: any, client: Client, cache: PeriodKeyCache, status: number, body: any }>}
 */
async function unlock(render, network) {
  const page = await render("A");
  const cache = new PeriodKeyCache();
  const client = new Client({ cache, publisherOrigin: ORIGIN });
  const dca = client.parse(page);
  const request = client.buildRequest(dca, ISSUER_NAME, [CONTENT_NAME]);
  const { status, body } = await network.post(UNLOCK_URL, request, {
    from: {},
    origin: "https://www.news-site.example",
  });
  return { page, dca, client, cache, status, body };
}

/**
 * The premium period labels a response handed back, or `null` when it withheld
 * the family. Read as a set of labels, which is how a grant arrives.
 *
 * @param {any} body
 * @returns {string[]|null}
 */
function grantedPeriods(body) {
  const periods = body?.keys?.periodKeys?.[ACCESS_GROUP];
  return periods ? Object.keys(periods) : null;
}

describe("a fallback issuer and a client whose clocks straddle a period boundary", () => {
  test("the fallback grants the period its own clock is in, and the same render opens under either", async () => {
    const inRender = await issuerOn("fallback", ISSUER_IN_RENDER);
    const r1 = await unlock(inRender.render, inRender.network);

    const crossed = await issuerOn("fallback", ISSUER_CROSSED);
    const r2 = await unlock(crossed.render, crossed.network);

    // The two renders are the same page: made at the same publisher clock,
    // carrying the same period pair on both sides of the wire. Nothing about
    // the request differs between the runs.
    assert.deepEqual(periodsOn(r1.page), [T_NOW, T_NEXT]);
    assert.deepEqual(periodsOn(r2.page), [T_NOW, T_NEXT]);

    // The one thing that moved is the issuer's own clock, and it alone moves
    // which single period the fallback hands over: the make period from an
    // issuer still inside it, the overlap from one that has crossed the
    // boundary. A fallback grants the current period only, and current is
    // the greatest label the issuer's clock says has started.
    assert.equal(r1.status, 200);
    assert.deepEqual(grantedPeriods(r1.body), [T_NOW]);
    assert.equal(r1.body.errors, undefined);

    assert.equal(r2.status, 200);
    assert.deepEqual(grantedPeriods(r2.body), [T_NEXT]);
    assert.equal(r2.body.errors, undefined);

    // Either grant opens this render: the content key is delivered whole and
    // the page was sealed under both periods, so holding one opens it.
    await r1.client.applyResponse(r1.dca, ISSUER_NAME, r1.body);
    assert.equal(
      utf8Decode(
        await r1.client.decrypt(r1.dca, CONTENT_NAME, r1.client.extract(r1.page, CONTENT_NAME)),
      ),
      ARTICLES.A,
    );
    assert.deepEqual(await held(r1.cache), [T_NOW], "the one granted period is cached for reuse");

    await r2.client.applyResponse(r2.dca, ISSUER_NAME, r2.body);
    assert.equal(
      utf8Decode(
        await r2.client.decrypt(r2.dca, CONTENT_NAME, r2.client.extract(r2.page, CONTENT_NAME)),
      ),
      ARTICLES.A,
    );
    assert.deepEqual(
      await held(r2.cache),
      [T_NEXT],
      "the overlap period, from an issuer past the boundary",
    );
  });

  test("the client cannot move the grant: skew its clock across the boundary either way, or take it away", async () => {
    // The issuer sits past the boundary, so it granted the overlap period.
    const { render, network } = await issuerOn("fallback", ISSUER_CROSSED);
    const page = await render("A");
    const requester = new Client({ cache: new PeriodKeyCache(), publisherOrigin: ORIGIN });
    const request = requester.buildRequest(requester.parse(page), ISSUER_NAME, [CONTENT_NAME]);
    const { body } = await network.post(UNLOCK_URL, request, {
      from: {},
      origin: "https://www.news-site.example",
    });
    assert.deepEqual(
      grantedPeriods(body),
      [T_NEXT],
      "the issuer decided the period from its own clock",
    );

    // Three clients over that one grant, one hours behind the issuer, one
    // hours ahead, one with no `Date` at all - each opening the render and
    // caching what it was handed. A client that read `t` off its own clock
    // would open the wrong period or none; these read it off the labels.
    const runs = [];
    for (const skew of [-5 * HOUR, 12 * HOUR, null]) {
      const cache = new PeriodKeyCache();
      const client = new Client({ cache, publisherOrigin: ORIGIN });
      const dca = client.parse(page);

      runs.push(
        await withAmbientSkew(skew, async () => {
          await client.applyResponse(dca, ISSUER_NAME, body, request);
          const plaintext = utf8Decode(
            await client.decrypt(dca, CONTENT_NAME, client.extract(page, CONTENT_NAME)),
          );
          return { plaintext, held: await held(cache) };
        }),
      );
    }

    assert.deepEqual(runs[1], runs[0], "hours ahead reads the same as hours behind");
    assert.deepEqual(runs[2], runs[0], "and so does a client with no clock at all");
    assert.equal(runs[0].plaintext, ARTICLES.A);
    assert.deepEqual(
      runs[0].held,
      [T_NEXT],
      "the client cached the issuer-chosen period, not one of its own",
    );
  });

  test("a fallback trim before every supplied period creates no availability report", async () => {
    // The issuer is behind both periods the render carries. Neither has
    // started from where its clock stands, so the fallback has no current
    // period to grant.
    const { render, network } = await issuerOn("fallback", ISSUER_BEHIND);
    const { page, dca, client, cache, status, body } = await unlock(render, network);

    assert.equal(status, 200);
    assert.equal(grantedPeriods(body), null, "no period key crossed for the family");
    assert.equal(body.notDelivered, undefined, "trimming alone is not missing authorized supply");

    // The fallback withheld the cacheable period key. This render's content
    // key was delivered whole, so the article in hand still opens.
    // What the reader loses is the forward reuse - nothing is held, so the
    // next article of this family would have to ask again.
    await client.applyResponse(dca, ISSUER_NAME, body);
    assert.equal(
      utf8Decode(await client.decrypt(dca, CONTENT_NAME, client.extract(page, CONTENT_NAME))),
      ARTICLES.A,
    );
    assert.deepEqual(
      await held(cache),
      [],
      "nothing cached: the fallback handed back no period key",
    );
  });

  test("only a fallback reshapes t by its clock: a primary grants the presented periods whatever it reads", async () => {
    // The same two issuer instants that split a fallback's grant leave a
    // primary's untouched. A primary unseals the blobs and hands back the
    // periods the request carried; it never reads its clock to pick among
    // them, so a clock hours off the client is a non-event here.
    for (const issuerAt of [ISSUER_CROSSED, ISSUER_BEHIND]) {
      const { render, network } = await issuerOn("primary", issuerAt);
      const { status, body } = await unlock(render, network);

      assert.equal(status, 200);
      assert.deepEqual(
        grantedPeriods(body)?.sort(),
        [T_NOW, T_NEXT],
        `a primary at ${issuerAt} grants both presented periods`,
      );
      assert.equal(body.errors, undefined);
    }
  });
});
