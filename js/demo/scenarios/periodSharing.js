// @ts-check
//
// Two readers and one period. One holds the subscription and one holds
// nothing, and the key the issuer granted the first opens the second one's
// article for as long as the period lasts. The cached path buys that reach:
// the issuer grants once per period, and every article of that period opens
// against that grant without anyone asking the issuer again. The reach ends at
// the next period, and choosing a period length picks that moment.
//
// Two `Browser`s run over two stores on one network, the way two machines do.
// Nothing is shared between them but the wire and whatever crosses it.
//
// The key crosses twice, and the two crossings show different things. The
// first carries the key itself: a periodKey is bytes, bytes travel, and B's
// cache takes the entry as it stands. The second replays A's unlock request
// byte for byte. The issuer keeps no per-request state and consults no clock of
// its own, so it answers the same request with the same keys, before the period
// rolls and after it. The period labels rolling out from under the two readers
// bound both crossings, and nothing at the issuer does.
//
// The issuer sees nothing at all of the second reader, until the period rolls.
// Then B's own walk goes out with B's own credential and is answered 401,
// because bob holds no subscription and never did. The reads before that never
// reached the issuer, so no lenient decision was made about them.
//
// The reader with the subscription keeps reading across the roll, as the
// control. The 401 then says what this issuer decides about bob, since the
// period rolled for both readers alike.
//
// No assertions and no printing, and nothing from node:*.
// `test/access-policy.test.js` says what the steps have to be, and the file
// keeps loading in a page. Key material stays out of what comes back: a shared
// entry is reported as the coordinate it was filed at.

import { actorWorld, originForHost, readArticle } from "./world.js";
import { AccessPolicy } from "../support/AccessPolicy.js";
import { formatT } from "../../core-shared--publisher-issuer/periodKeys.js";
import { dcaError } from "../../core-shared/errors.js";
import { ACCESS_GROUP, CONTENT_NAME, DOMAIN } from "./fixtures.js";

const MINUTE = 60_000;

/** Past both periods a render ships, so nothing the client holds covers it. */
const PAST_THE_OVERLAP = 2 * 60 * MINUTE;

/** What a replayed request waits for its answer, as a load would. */
const TIMEOUT = 2_000;

/** The two readers, and what one of them bought. */
const SUBSCRIBER = "alice";
const READER = "bob";
const ENTITLEMENT = "subscriber";

/**
 * What the issuer was told this publisher sells. Both allow-lists name the
 * subscription: the item by name, and the family the cached path is granted in.
 * A reader without it is denied both, and so the whole request is denied.
 */
const RULES = {
  contentNames: { [originForHost(DOMAIN)]: { [CONTENT_NAME]: { entitlement: ENTITLEMENT } } },
  accessGroups: { [originForHost(DOMAIN)]: { [ACCESS_GROUP]: { entitlement: ENTITLEMENT } } },
};

/** What this scenario takes. Anything else is refused rather than ignored. */
const OPTIONS = ["at", "seed"];

/**
 * The world's own network with a copy kept of every request that crossed it.
 * It routes nothing and changes nothing. The call goes through the `Network`,
 * so the payload is checked, counted and serialised there as it is for every
 * other caller.
 *
 * The copy is what the replay needs: the request as it was written, held apart
 * from the client that wrote it.
 *
 * @param {any} network
 * @param {any[]} posted - appended to, in the order the calls went out
 * @returns {{ post: Function }}
 */
function recordingNetwork(network, posted) {
  return {
    /**
     * @param {string} url
     * @param {any} payload
     * @param {object} [options]
     * @returns {Promise<{ status: number, body: any }>}
     */
    post: async (url, payload, options) => {
      posted.push({ url, request: JSON.parse(JSON.stringify(payload)) });
      return network.post(url, payload, options);
    },
  };
}

/**
 * The cache entry a reader holds for period `t`, or a refusal that the story
 * was played into a state it has no honest move for. `share` hands the
 * subscriber's key for the period both readers are in to the other reader; if
 * the subscriber holds nothing for that period the step was reached out of
 * order, and there is no key to cross.
 *
 * @param {{ t: string }[]} entries
 * @param {string} t
 * @param {string} actor - whose cache the key is missing from, for the message
 * @returns {any}
 */
export function heldForPeriod(entries, t, actor) {
  const entry = entries.find((held) => held.t === t);
  if (entry === undefined) {
    throw dcaError(
      "bad_scenario",
      `${actor} holds no cached key for period "${t}", so there is nothing to share`,
    );
  }
  return entry;
}

/**
 * @typedef {object} Step
 * @property {'read'|'share'|'replay'|'advance'} kind
 * @property {object} server - what the issuer has done, after this step
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
    accessPolicy: new AccessPolicy(RULES),
  });
  const { clock, network, servers } = stage;

  // Both are known to the issuer. Only one of them bought anything, so the
  // denial below is about the subscription rather than about a credential
  // that names nobody.
  servers.primary.grant(SUBSCRIBER, { entitlements: [ENTITLEMENT] });
  servers.primary.grant(READER, {});

  /** @type {any[]} */
  const posted = [];

  const subscriber = stage.makeBrowser({ network: recordingNetwork(network, posted) });
  const reader = stage.makeBrowser();

  /** @type {any[]} */
  const steps = [];

  /**
   * What one client holds, as coordinates. The bytes stay out of the report: it
   * gives the periods a reader can open articles in, and no key material.
   *
   * @param {any} browser
   * @returns {Promise<{ accessGroup: string, t: string }[]>}
   */
  const cacheOf = async (browser) =>
    (await browser.cache.entries()).map((/** @type {any} */ entry) => ({
      accessGroup: entry.familyName,
      t: entry.t,
    }));

  /**
   * @param {any} step
   * @param {any} [browser] - whose cache this step is about, where one is
   * @returns {Promise<void>}
   */
  async function record(step, browser) {
    const stats = servers.primary.stats();
    steps.push({
      ...step,
      cache: browser === undefined ? null : await cacheOf(browser),
      server: { requests: stats.requests, grants: stats.grants, denials: stats.denials },
    });
  }

  /**
   * One article, rendered at the moment it is read, and read by one of the
   * two readers under their own credential.
   *
   * @param {any} browser
   * @param {string} credential
   * @param {'A'|'B'|'C'|'D'} label
   * @returns {Promise<void>}
   */
  async function read(browser, credential, label) {
    const page = await stage.render(label);
    const { load, unlock, texts, errors } = await readArticle(browser, page, [CONTENT_NAME], {
      credential,
    });
    const stats = load.stats();

    await record(
      {
        kind: "read",
        reader: credential,
        label,
        t: formatT(clock.now()),
        text: texts[CONTENT_NAME],
        error: errors[CONTENT_NAME],
        status: unlock === null ? null : unlock.status,
        resolved: { ...stats.resolved },
        calls: stats.attempts,
      },
      browser,
    );
  }

  /**
   * The key crossing between two machines: the entry the subscriber holds for
   * the period they are both reading in, put into the other reader's cache. The
   * bytes cross; the receiving cache files them under its own view of the
   * coordinate: the same publisher both are reading, the same accessGroup and
   * the same period. The two readers hold that family in common.
   *
   * @returns {Promise<void>}
   */
  async function share() {
    const t = formatT(clock.now());
    const entry = heldForPeriod(await subscriber.cache.entries(), t, SUBSCRIBER);

    await reader.cache.put(ACCESS_GROUP, entry.t, entry.key, { publisher: originForHost(DOMAIN) });
    await record(
      {
        kind: "share",
        from: SUBSCRIBER,
        to: READER,
        accessGroup: entry.familyName,
        t: entry.t,
      },
      reader,
    );
  }

  /**
   * The subscriber's first unlock request, posted again exactly as it was
   * written, from the other reader's machine, carrying the session it was
   * captured with. The step measures the issuer's answer to a request it has
   * already answered once.
   *
   * @returns {Promise<void>}
   */
  async function replay() {
    const { url, request } = posted[0];
    const answer = await network.post(url, request, {
      from: reader,
      timeout: TIMEOUT,
      credential: SUBSCRIBER,
      origin: originForHost(DOMAIN),
    });
    await record({ kind: "replay", url, status: answer.status, body: answer.body });
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

  // The subscriber reads, and the grant lands in a cache.
  await read(subscriber, SUBSCRIBER, "A");
  await replay();

  // The key crosses, and the other reader opens an article of the same period
  // without the issuer hearing about it.
  await share();
  await read(reader, READER, "B");

  // Past every period either of them is holding a key for.
  await advance(PAST_THE_OVERLAP);

  // The reach ends where the period does: this one goes to the issuer, and
  // the issuer answers what it would have answered all along.
  await read(reader, READER, "C");
  await replay();

  // The control: the same roll, the same articles, a live subscription.
  await read(subscriber, SUBSCRIBER, "D");

  return {
    steps,
    summary: {
      // Keyed by the part each reader plays rather than by name. Which
      // reader bought something matters here, and the credential is a
      // string this scenario picked.
      cache: {
        subscriber: await cacheOf(subscriber),
        reader: await cacheOf(reader),
      },
      wire: Object.fromEntries(
        Object.entries(network.stats()).map(([url, stats]) => [url, { ...stats }]),
      ),
      server: servers.primary.stats(),
    },
  };
}
