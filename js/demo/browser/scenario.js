// @ts-check
//
// The story a reader watches: an article arrives sealed, one unlock opens it,
// the clock crosses a period boundary, and the next article opens out of the
// cache with the unlock count still at one.
//
// It wires the world and takes steps, asserting nothing and printing nothing, so
// and `test-reference/demo-browser/scenario.test.js` run the same scenario: the page renders what comes
// back, the test asserts over it.
//
// `run()` wires the actor family from `demo/scenarios/world.js`: a `Clock`, a
// `Publisher`, one or two `IssuerServer`s on a `Network`, and a `Browser`
// walking them. Every unlock in the trace crossed that `Network`, so the byte
// counts are the strings that crossed and `assertWireSafe` runs on both
// directions of every call - a scenario that called an endpoint in-process
// would report the same steps and prove none of that.
//
// What comes back is plain JSON - strings, numbers, arrays, plain objects.
// A key that is bytes on the inside is base64url by the time it is in the
// trace, which is the same rule a payload crossing the wire is held to, and a
// key that is a handle says so rather than printing bytes nobody has. A
// `Uint8Array` in here would be silently mangled on the way to the page, and a
// `Record` with a null prototype is mangled the same way one step later, so the
// snapshots the actors hand out are copied into plain objects on the way in.
//
// The recorder takes the request and response bodies at the network seam. A
// `PageLoad` builds its own request and hands back what the walk did rather
// than what it sent, so the only place to read the bodies is the wire itself.
// The recorder below only posts through the world's own `Network` and keeps a
// copy of what came back.
//
// The publisher signs every render and the issuer verifies that signature
// before it opens anything, so the unlock request in the trace carries the
// `resourceJWT` beside the sealed blobs. One signing kid; this scenario covers
// no rotation.
//
// Pinned to one thing at a time: one publisher, one accessGroup, one content
// item, grant-all issuers, a still clock that moves only where a step says it
// does. What a caller may move is the seed, the clock's start, the period, how
// far the clock jumps, whether a fallback issuer stands behind the primary,
// whether the primary is down, and what transport the primary answers in.
// Anything else is refused rather than ignored - a control that drifted ahead
// of the scenario would show a page that was never run.

import { actorWorld } from "../scenarios/world.js";
import { rootFromPage } from "../support/queryableRoot.js";
import { writeMarkupDelivery } from "../../adapter-publisher/writeMarkupDelivery.js";
import {
  ACCESS_GROUP,
  ALGORITHM,
  ARTICLES,
  AT,
  CONTENT_NAME,
  CONTENT_TYPE,
  ORIGIN,
  HEALTH_URL,
  ISSUER_NAME,
  KEY_ID,
  SIGNING_KID,
  UNLOCK_URL,
} from "../scenarios/fixtures.js";
import { base64urlEncode, utf8Decode } from "../../core-shared/codec.js";
import { decodeCompactJwt } from "../../core-shared/compactJwt.js";
import { formatT, DEFAULT_PERIOD } from "../../core-shared--publisher-issuer/periodKeys.js";
import { dcaError } from "../../core-shared/errors.js";
import { own } from "../../core-shared/wire.js";
import { recordsByName } from "../../core-shared--client-publisher/deliveryRecords.js";

const MINUTE = 60_000;

/** Far enough to cross the hour, close enough that the forward key still covers it. */
const ADVANCE = 50 * MINUTE;

/** What this scenario takes. Anything else is a refusal, per the constraint. */
const OPTIONS = ["at", "seed", "advance", "period", "fallback", "primaryOffline", "transportMode"];

/**
 * One step of the story, as the page reads it. `kind` says which of the shapes
 * below it is; `unlockCalls`, `cache`, `wire` and `load` are on every one,
 * because the point is to read those numbers next to each other.
 *
 * @typedef {object} Step
 * @property {'render'|'resolve'|'decrypt'|'unlock'|'advance'} kind
 * @property {string} [label] - which article, A or B
 * @property {string} observedAt - the actor clock when this step finished
 * @property {number} unlockCalls - the running total, after this step
 * @property {{ accessGroup: string, t: string, key: string }[]} cache - newest t first
 * @property {Record<string, object>} wire - what has crossed, per url
 * @property {object|null} load - what this page's load has done, or null where
 *   no page was loading
 */

/**
 * @typedef {object} Trace
 * @property {object} world - the wiring, so the page can say what it is showing
 * @property {object} flow - a boundary-focused view of the first render and unlock
 * @property {object} inspection - human-readable values derived from the first crossing
 * @property {Step[]} steps
 * @property {object} summary
 */

/**
 * The item record a delivery carries for one contentName, the last whole one
 * when several name it.
 *
 * @param {any} dcaData
 * @param {string} contentName
 * @returns {any}
 */
function contentRecordOf(dcaData, contentName) {
  return recordsByName(own(dcaData, "contentData"), "contentName", () => true)?.get(contentName);
}

/**
 * The periods a page ships to the client, in wire order - the period it was
 * rendered in first, then forward.
 *
 * @param {any} page
 * @returns {string[]}
 */
function periodsOn(page) {
  const entries = own(contentRecordOf(page, CONTENT_NAME), "keys");
  return Array.isArray(entries)
    ? entries
        .filter((/** @type {any} */ entry) => own(entry, "accessGroup") === ACCESS_GROUP)
        .map((/** @type {any} */ entry) => own(entry, "period"))
    : [];
}

/**
 * The publisher-side evidence for one render, copied from the immutable page
 * before its client load begins. The markup is emitted by the real publisher
 * adapter from those exact page values rather than rebuilt for display.
 *
 * A compact `resourceJWT` is useful on the page only when an inspector can
 * also see the header and unauthenticated payload it actually encodes. The
 * issuer, not this trace, verifies its signature before granting anything.
 *
 * @param {any} page - `Page.asJson()`'s exact JSON delivery object
 * @returns {{ markup: string, dcaData: object, sealedContent: object, resourceJWT: object }}
 */
function publisherArtifact(page) {
  const { sealedContent, ...dcaData } = page;
  const token = own(dcaData, "resourceJWT");
  const decoded = decodeCompactJwt(token);
  // The writer takes the render's ciphertext by name, as the Sealer returns it.
  const byName = Object.fromEntries(
    sealedContent.map((/** @type {any} */ record) => [record.contentName, record.content]),
  );

  return {
    markup: writeMarkupDelivery({ dcaData, sealedContent: byName }),
    dcaData,
    sealedContent,
    resourceJWT: {
      compact: token,
      header: decoded.header,
      payload: decoded.payload,
    },
  };
}

/**
 * What has crossed, per url, in plain objects. `Network.stats()` reports under a
 * null prototype so a url named `constructor` cannot resolve to something else;
 * a null prototype survives `JSON.stringify` and not a comparison against what
 * came back, so the trace holds ordinary objects.
 *
 * @param {any} network
 * @returns {Record<string, object>}
 */
function wireOf(network) {
  /** @type {Record<string, object>} */
  const crossed = {};
  for (const [url, stats] of Object.entries(network.stats())) crossed[url] = { ...stats };
  return crossed;
}

/**
 * A cached key as the page may see it. Direct transport hands the client bytes;
 * client-bound hands it a key object it cannot export, and the trace says so
 * rather than pretending to have bytes it was never given.
 *
 * @param {any} key
 * @returns {string}
 */
function shownKey(key) {
  return key instanceof Uint8Array
    ? base64urlEncode(key)
    : "a CryptoKey, which does not leave the client";
}

/**
 * The keypair a client-bound unlock is negotiated with. The seed cannot cover
 * it - WebCrypto has no seeded EC keygen - so a client-bound run replays in
 * every byte but this one.
 *
 * @returns {Promise<{ privateKey: CryptoKey, publicKey: JsonWebKey }>}
 */
async function clientPair() {
  const { subtle } = globalThis.crypto;
  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
  );
  return { privateKey: pair.privateKey, publicKey: await subtle.exportKey("jwk", pair.publicKey) };
}

/**
 * The `Network` the client posts across, with a copy kept of every answer that
 * came back. The call goes straight through the world's own network, so the
 * payload is checked, counted and serialised there exactly as it is for every
 * other caller.
 *
 * A call that never got an answer records nothing here - there is no body to
 * show - and what happened to it is in the walk's own attempts.
 *
 * @param {any} network
 * @param {any[]} calls - appended to, in the order the calls were answered
 * @returns {{ post: Function }}
 */
function recordingNetwork(network, calls) {
  return {
    /**
     * @param {string} url
     * @param {any} payload
     * @param {object} [options]
     * @returns {Promise<{ status: number, body: any }>}
     */
    post: async (url, payload, options) => {
      const answer = await network.post(url, payload, options);
      calls.push({
        url,
        // The request as it crossed, copied: the trace outlives
        // the call and the caller keeps its own object.
        request: JSON.parse(JSON.stringify(payload)),
        status: answer.status,
        body: answer.body,
      });
      return answer;
    },
  };
}

/**
 * Plays the story and hands back what happened.
 *
 * @param {object} [config]
 * @param {string} [config.at] - where the clock starts
 * @param {number} [config.seed] - the first seed; each `Random` takes the next
 * @param {number} [config.advance] - how far the clock jumps, in milliseconds
 * @param {{ length?: number, slots?: number }} [config.period]
 * @param {boolean} [config.fallback] - stand a second issuer up behind the first
 * @param {boolean} [config.primaryOffline] - take the primary down, unlock url
 *   and health check together
 * @param {'direct'|'client-bound'} [config.transportMode] - what the primary
 *   answers in
 * @param {{ profile: object, capability: (keyPair: object, profile: object) => object }} [clientBound]
 * @returns {Promise<Trace>}
 */
export async function run(config = {}, clientBound) {
  for (const name of Object.keys(config)) {
    if (!OPTIONS.includes(name)) {
      throw dcaError("unsupported_option", `the scenario has no ${name}, and will not pretend to`);
    }
  }

  const at = config.at ?? AT;
  const seed = config.seed ?? 1;
  const advance = config.advance ?? ADVANCE;
  const period = {
    length: config.period?.length ?? DEFAULT_PERIOD.length,
    slots: config.period?.slots ?? DEFAULT_PERIOD.slots,
  };
  const fallback = config.fallback ?? false;
  const primaryOffline = config.primaryOffline ?? false;
  const transportMode = config.transportMode ?? "direct";
  if (
    transportMode === "client-bound" &&
    (!clientBound?.profile || typeof clientBound.capability !== "function")
  ) {
    throw dcaError(
      "bad_config",
      "client-bound scenario transport needs an injected profile and capability",
    );
  }

  const world = await actorWorld({
    at,
    seed,
    period,
    fallback,
    transportMode,
    ...(transportMode === "client-bound" ? { clientBoundProfile: clientBound.profile } : {}),
  });
  const { clock, network } = world;

  /**
   * Every answered call, in order, so a step can show the bodies it made.
   *
   * @type {any[]}
   */
  const calls = [];

  // The pair client-bound is negotiated with, made only where the control
  // asks for it: a client that offers no key uses direct transport only, and
  // the issuer decides which of the two it answers. The private half is
  // non-extractable, matching a key a client holds in earnest, and the
  // public half is exported once here because `buildRequest` cannot await one.
  const clientKeys = transportMode === "client-bound" ? await clientPair() : null;

  // Built after the world, because a `Browser` copies the issuers it walks
  // and the fallback is stood up during construction.
  //
  // A client-bound client keeps its cache in memory rather than over the
  // world's `Storage`: what it is handed are key handles, and a store of
  // strings refuses one rather than mangling it. The store that keeps handles
  // is IndexedDB, and the demo has no adapter for it. The design names that
  // asymmetry between the node and browser columns, and this scenario runs
  // into it.
  const browser = world.makeBrowser({
    network: recordingNetwork(network, calls),
    ...(clientKeys === null
      ? {}
      : {
          clientBoundKeyCapability: clientBound.capability(clientKeys, clientBound.profile),
          storage: undefined,
        }),
  });

  if (primaryOffline) {
    // The whole primary, not one url of it. A fallback decides from the
    // health check, and one that could still reach it would refuse to stand
    // in. This scenario does not cover an outage only one side of the world
    // can see.
    network.offline(UNLOCK_URL);
    network.offline(HEALTH_URL);
  }

  /** @type {Step[]} */
  const steps = [];

  /**
   * Every step is stamped with what is being watched, read at the moment it
   * finished rather than at the end.
   *
   * @param {any} step
   * @param {any} load - the page load this step happened in, or null
   * @returns {Promise<any>}
   */
  async function record(step, load) {
    const entries = await browser.cache.entries();
    const stats = load === null ? null : load.stats();
    const recorded = {
      ...step,
      observedAt: clock.now().toISOString(),
      unlockCalls: browser.stats().unlocks,
      cache: entries.map((entry) => ({
        accessGroup: entry.familyName,
        t: entry.t,
        key: shownKey(entry.key),
      })),
      wire: wireOf(network),
      load:
        stats === null
          ? null
          : {
              trials: stats.trials,
              attempts: stats.attempts,
              answeredBy: stats.answeredBy,
              transportMode: stats.transportMode,
              keyResolutions: stats.keyResolutions,
            },
    };
    steps.push(recorded);
    return recorded;
  }

  /**
   * The publisher renders, and the browser loads what arrived. Everything the
   * step reports is read off the page as the client received it.
   *
   * @param {'A'|'B'} label
   * @returns {Promise<any>} the load the client is reading it in
   */
  async function render(label) {
    const page = await world.render(label);
    const json = page.asJson();
    const publisher = publisherArtifact(json);
    // The client loads an already-parsed page root. In this demo the render
    // is fabricated in-process rather than delivered as markup, so the root
    // is built from the render's own values - platform-neutral pure JS that
    // runs the same in this page and under `node --test`, never a DOM fake
    // forced into the browser.
    const load = browser.load(rootFromPage(page));

    const resource = own(load.dcaData, "resource");
    const contentRecord = contentRecordOf(load.dcaData, CONTENT_NAME);

    await record(
      {
        kind: "render",
        label,
        at: clock.now().toISOString(),
        t: formatT(clock.now(), period.length),
        resourceId: own(resource, "resourceId"),
        renderId: own(resource, "renderId"),
        periods: periodsOn(json),
        contentName: CONTENT_NAME,
        contentType: own(contentRecord, "contentType"),
        ciphertext: own(
          own(json, "sealedContent").find(
            (/** @type {any} */ record) => own(record, "contentName") === CONTENT_NAME,
          ),
          "content",
        ),
        publisher,
      },
      load,
    );

    return load;
  }

  /**
   * @param {'A'|'B'} label
   * @param {any} load
   * @returns {Promise<string[]>} what the cache could not open
   */
  async function resolve(label, load) {
    const { covered, missing } = await load.resolve([CONTENT_NAME]);
    await record({ kind: "resolve", label, covered, missing }, load);
    return missing;
  }

  /**
   * The calls across the wire. The walk reports which issuers it tried and how
   * each one ended; the bodies come off the seam, and there are none when
   * nobody answered.
   *
   * @param {'A'|'B'} label
   * @param {any} load
   * @param {string[]} needed
   * @returns {Promise<void>}
   */
  async function unlock(label, load, needed) {
    const mark = calls.length;
    const answer = await load.unlock();
    const answered = calls.slice(mark).at(-1) ?? null;

    await record(
      {
        kind: "unlock",
        label,
        needed,
        ok: answer.ok,
        issuerName: answer.issuerName,
        status: answer.status,
        transportMode: answer.transportMode,
        attempts: answer.attempts,
        unlockUrl: answered?.url ?? null,
        request: answered?.request ?? null,
        response: answered?.body ?? null,
      },
      load,
    );
  }

  /**
   * A name with no key is a typed miss, so it is recorded as one rather than
   * thrown out of the scenario, and the page shows locked as a state.
   *
   * @param {'A'|'B'} label
   * @param {any} load
   * @returns {Promise<void>}
   */
  async function decrypt(label, load) {
    const { bytes, error } = await load.open(CONTENT_NAME);
    await record(
      {
        kind: "decrypt",
        label,
        text: bytes === null ? null : utf8Decode(bytes),
        error,
      },
      load,
    );
  }

  // Article A: sealed on arrival, refused, unlocked once, and open.
  const a = await render("A");
  const neededA = await resolve("A", a);
  await decrypt("A", a);
  await unlock("A", a, neededA);
  await decrypt("A", a);

  // Past the flip. The next render is a period on, and with the primary
  // answering, the client is handed no new keys anywhere below this line.
  const before = clock.now();
  clock.advance(advance);
  await record(
    {
      kind: "advance",
      minutes: advance / MINUTE,
      from: before.toISOString(),
      to: clock.now().toISOString(),
      fromT: formatT(before, period.length),
      toT: formatT(clock.now(), period.length),
    },
    null,
  );

  // Article B: opened out of the cache, at no unlock - unless what the first
  // unlock handed over does not reach this period. A fallback grants the
  // current period only, so a failover puts the next article back on the
  // wire, and that second call is the cost of it rather than a locked
  // article with no reason beside it.
  const b = await render("B");
  const neededB = await resolve("B", b);
  if (neededB.length > 0) await unlock("B", b, neededB);
  await decrypt("B", b);

  const entries = await browser.cache.entries();
  const client = browser.stats();
  const firstRender = steps.find((step) => step.kind === "render");
  const firstUnlock = steps.find((step) => step.kind === "unlock");
  const { dcaData, sealedContent, markup, resourceJWT } = /** @type {any} */ (firstRender)
    .publisher;

  return {
    world: {
      at,
      seed,
      period,
      advanceMinutes: advance / MINUTE,
      origin: ORIGIN,
      signingKid: SIGNING_KID,
      issuerName: ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: ALGORITHM,

      accessGroup: ACCESS_GROUP,
      contentName: CONTENT_NAME,
      contentType: CONTENT_TYPE,
      transportMode,
      fallback,
      primaryOffline,
      issuers: browser.issuers,
      articles: { A: ARTICLES.A, B: ARTICLES.B },
    },
    flow: {
      publisherDelivery: { dcaData, sealedContent, markup },
      unlockRequest: {
        unresolvedContentNames: /** @type {any} */ (firstUnlock).needed,
        body: /** @type {any} */ (firstUnlock).request,
      },
      unlockResponse: {
        status: /** @type {any} */ (firstUnlock).status,
        body: /** @type {any} */ (firstUnlock).response,
      },
    },
    inspection: { resourceJWT },
    steps,
    summary: {
      unlockCalls: client.unlocks,
      articlesOpened: steps.filter(
        (step) => step.kind === "decrypt" && /** @type {any} */ (step).text !== null,
      ).length,
      cache: entries.map((entry) => ({
        accessGroup: entry.familyName,
        t: entry.t,
        key: shownKey(entry.key),
      })),
      wire: wireOf(network),
      client: { ...client, breaker: { ...client.breaker } },
      servers: Object.fromEntries(
        Object.entries(world.servers).map(([role, server]) => [
          role,
          /** @type {any} */ (server).stats(),
        ]),
      ),
    },
  };
}
