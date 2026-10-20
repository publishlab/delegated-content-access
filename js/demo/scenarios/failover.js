// @ts-check
//
// Going down and coming back. The design calls this the scenario that forces
// the most structure. A primary answering client-bound opens the story, an
// outage moves the reader onto a fallback whose issuer-side simulated emergency
// window is active. It hands the bytes over direct and keeps one period of
// them, and then the primary comes back.
//
// The scenario builds one `Browser` holding one keypair, and walks that same
// client from the first article to the last. Nothing in it asks for a mode or
// is told one: what arrived decides. That is why a client-bound client reading
// a direct answer is a step here rather than a case the client had to be
// configured for. It offers its public half to every issuer it walks, and the
// fallback has no use for it.
//
// The scenario runs four articles where the design names three. The healthy
// read, the outage read and the resumed one are the design's; the fourth sits
// between the recovery and the roll, and the same paragraph names it as the
// tail: a key the fallback handed out during the outage stays usable until
// its period rolls, which is after the primary is back and after whatever made
// the fallback grant has been reconsidered.
//
// The scenario moves the clock twice, and each jump puts the next article on
// the wire. The first is past both periods the healthy read collected, so the
// article read during the outage has to reach an issuer at all. The second is
// past the one period the fallback granted, and past the breaker's window with
// it, so the recovered primary gets its trial call rather than being skipped.
// Without them the cache would answer every read after the first and there
// would be no failover to watch.
//
// The breaker threshold is one, because the primary is unreachable and stays
// that way: counting to a higher one would put the same failure on the wire
// twice and change nothing about where the request goes. What a threshold is
// and when it opens is `test-reference/demo-actors/transport.test.js`'s own story.
//
// No assertions and no printing, and nothing from node:*. The tests assert
// over what this hands back, and the file keeps loading in a page. Every key
// that reached this client is reported as bytes-or-handle and never as a
// value: the step says which transport it arrived in, and the key itself is
// not the page's to show.

import { actorWorld, readArticle } from "./world.js";
import { formatT } from "../../core-shared--publisher-issuer/periodKeys.js";
import { own } from "../../core-shared/wire.js";
import { dcaError } from "../../core-shared/errors.js";
import {
  ACCESS_GROUP,
  CONTENT_NAME,
  FALLBACK_ISSUER_NAME,
  HEALTH_URL,
  UNLOCK_URL,
} from "./fixtures.js";
import * as clientBoundEcdh from "../../extensions/client-bound-transport/ecdhP256.js";
import { clientBoundKeyCapability } from "../../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";

const MINUTE = 60_000;

/** Past both periods the first render shipped, so the next article has to ask. */
const PAST_THE_OVERLAP = 2 * 60 * MINUTE;

/**
 * Past the one period the fallback granted. The breaker's window is half a
 * minute, so this clears that too and the primary is tried rather than skipped.
 */
const PAST_THE_GRANT = 41 * MINUTE;

/** What this scenario takes. Anything else is refused rather than ignored. */
const OPTIONS = ["at", "seed"];

/**
 * The pair this client offers an issuer, in the shape a `Browser` holds one: a
 * private half whose bytes JavaScript cannot read, and the public half exported
 * when the pair is made, because the request it goes into is built
 * synchronously.
 *
 * @returns {Promise<{ privateKey: CryptoKey, publicKey: JsonWebKey }>}
 */
async function clientKeys() {
  const { subtle } = globalThis.crypto;
  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
  );
  return { privateKey: pair.privateKey, publicKey: await subtle.exportKey("jwk", pair.publicKey) };
}

/**
 * The periods a page ships to the client, in wire order: the period it was
 * rendered in first, then forward. Read off the page rather than derived, so a
 * step reports what the render carried and not what the clock says it should
 * have.
 *
 * @param {any} page - the delivery form
 * @returns {string[]}
 */
function periodsOn(page) {
  const entries = own(own(own(own(page, "contentData"), CONTENT_NAME), "keys"), ACCESS_GROUP);
  return Array.isArray(entries) ? entries.map((entry) => own(entry, "t")) : [];
}

/**
 * @typedef {object} Step
 * @property {'read'|'advance'|'outage'|'recovery'} kind
 * @property {{ accessGroup: string, t: string, handle: boolean }[]} cache - what
 *   the client holds after this step, newest `t` first per family
 * @property {Record<string, object>} wire - what has crossed, per url
 * @property {object|null} breaker - the client's state for the primary's url
 * @property {number} unlocks - the running total of unlock calls
 */

/**
 * Plays the story and hands back what happened.
 *
 * @param {object} [config]
 * @param {string} [config.at] - where the clock starts
 * @param {number} [config.seed] - the first seed; each `Random` takes the next
 * @returns {Promise<{ steps: Step[], summary: object }>}
 */
export async function run(config = {}) {
  for (const name of Object.keys(config)) {
    if (!OPTIONS.includes(name)) {
      throw dcaError("unsupported_option", `this scenario has no ${name}, and will not pretend to`);
    }
  }

  const stage = await actorWorld({
    ...(config.at === undefined ? {} : { at: config.at }),
    ...(config.seed === undefined ? {} : { seed: config.seed }),
    transportMode: "client-bound",
    clientBoundProfile: clientBoundEcdh,
    fallback: true,
    breaker: { threshold: 1 },
  });
  const { clock, network, servers } = stage;

  // No `Storage`: a client-bound answer is handles, and a store of strings
  // cannot hold one. That asymmetry is in the design, and a story about
  // failover is not where it is shown.
  const browser = stage.makeBrowser({
    issuers: stage.routes.map(({ issuerName, unlockUrl }) => ({
      issuerName,
      unlockUrl,
      acceptDirectResponse: issuerName === FALLBACK_ISSUER_NAME,
    })),
    storage: undefined,
    clientBoundKeyCapability: clientBoundKeyCapability(await clientKeys(), clientBoundEcdh),
    acceptDirectFallback: true,
    persistRawPeriodKeys: true,
  });

  /** @type {any[]} */
  const steps = [];

  /**
   * What the client holds, said as which transport it arrived in. The value
   * is not reported: a cache holds either direct bytes or a client-bound
   * handle, and which of the two it holds is what this step says.
   *
   * @returns {Promise<{ accessGroup: string, t: string, handle: boolean }[]>}
   */
  const cacheOf = async () =>
    (await browser.cache.entries()).map((entry) => ({
      accessGroup: entry.familyName,
      t: entry.t,
      handle: !(entry.key instanceof Uint8Array),
    }));

  /**
   * What has crossed, per url, in plain objects: `Network.stats()` reports
   * under a null prototype, which survives a stringify and not a comparison.
   *
   * @returns {Record<string, object>}
   */
  const wireOf = () => {
    /** @type {Record<string, object>} */
    const crossed = {};
    for (const [url, stats] of Object.entries(network.stats())) crossed[url] = { ...stats };
    return crossed;
  };

  /** @returns {object|null} the primary's url has no state until it is called */
  const breakerOf = () => {
    const held = browser.stats().breaker[UNLOCK_URL];
    return held === undefined ? null : { ...held };
  };

  /**
   * Every step is stamped with what is being watched, read where it happened
   * rather than at the end.
   *
   * @param {any} step
   * @returns {Promise<void>}
   */
  async function record(step) {
    steps.push({
      ...step,
      cache: await cacheOf(),
      wire: wireOf(),
      breaker: breakerOf(),
      unlocks: browser.stats().unlocks,
    });
  }

  /**
   * One article, rendered at the moment it is read, and read the whole way:
   * resolve, unlock whatever the cache could not open, decrypt.
   *
   * @param {'A'|'B'|'C'|'D'} label
   * @returns {Promise<void>}
   */
  async function read(label) {
    const page = await stage.render(label);
    const { load, unlock, texts, errors } = await readArticle(browser, page, [CONTENT_NAME]);
    const stats = load.stats();

    await record({
      kind: "read",
      label,
      t: formatT(clock.now()),
      periods: periodsOn(page.asJson()),
      text: texts[CONTENT_NAME],
      error: errors[CONTENT_NAME],
      status: unlock === null ? null : unlock.status,
      answeredBy: stats.answeredBy,
      transportMode: stats.transportMode,
      attempts:
        unlock === null
          ? []
          : unlock.attempts.map((/** @type {any} */ attempt) => ({
              issuerName: attempt.issuerName,
              outcome: attempt.outcome,
              status: attempt.status,
            })),
      calls: stats.attempts,
      skipped: stats.skipped,
    });
  }

  /**
   * @param {number} by - milliseconds
   * @returns {Promise<void>}
   */
  async function advance(by) {
    const from = clock.now();
    clock.advance(by);
    await record({
      kind: "advance",
      minutes: by / MINUTE,
      fromT: formatT(from),
      toT: formatT(clock.now()),
    });
  }

  /**
   * The whole primary, from every vantage: the unlock url and the health
   * check together. A fallback that could still reach it would refuse to
   * stand in, and an outage that only one side of the world can see is a
   * story of its own.
   *
   * @param {boolean} down
   * @returns {Promise<void>}
   */
  async function primary(down) {
    for (const url of [UNLOCK_URL, HEALTH_URL]) {
      if (down) network.offline(url);
      else network.online(url);
    }
    await record({ kind: down ? "outage" : "recovery", urls: [UNLOCK_URL, HEALTH_URL] });
  }

  // Healthy: the primary answers, and it answers client-bound.
  await read("A");

  // Past the overlap, so the next article is one the handles do not cover.
  await advance(PAST_THE_OVERLAP);
  await primary(true);

  // The outage: the primary is unreachable, the breaker opens on that one
  // call, and the fallback checks the primary itself before it considers its
  // active server-owned emergency window. It then grants the period the client
  // is reading in, direct, because it has no other mode.
  await read("B");

  await primary(false);

  // The tail. Still inside the period the fallback granted, so this article
  // opens out of the cache against a key handed out during an outage that is
  // over.
  await read("C");

  // Past that period, and past the breaker's window: the client asks again,
  // and the primary that is back answers in the mode it always had.
  await advance(PAST_THE_GRANT);
  await read("D");

  const client = browser.stats();
  return {
    steps,
    summary: {
      unlocks: client.unlocks,
      unlockFailures: client.unlockFailures,
      cache: await cacheOf(),
      wire: wireOf(),
      servers: {
        primary: servers.primary.stats(),
        fallback: servers.fallback.stats(),
      },
    },
  };
}
