// @ts-check
//
// The wiring a story needs before it can start. Two families of it, because the
// suite tells two kinds of story and they need different halves of the tree.
//
// The actor family wires a deployment: a clock, a network, one or two issuer
// servers on it, a publisher rendering to all of them, and a browser walking
// them in order. Everything crosses a wire, and the assertions are about what
// crossed and what it cost.
//
// The direct-endpoint family puts the two cores face to face: a publisher on
// one side, an `UnlockEndpoint` over an `IssuerEngine` on the other, and nothing
// between them. It leaves out the network, the browser and the breaker. A story
// about `t` labels or key selection has no use for any of that, and a test of
// one concept should not have to stand up a world to reach it.
//
// `world.js` asserts nothing and prints nothing, so the demo page and the
// tests can run the same wiring. Nothing here imports node:test, node:assert or
// node:fs either: this directory has to keep loading in a browser.
//
// The world is an exact-period demo preset. The network is up, the breaker
// quiet, no fallback stood up, the clock still, one issuer, direct transport,
// and a verified request granted whole. Other optional knobs start off.
//
// Both families take `signingKid` as an explicit knob, the one place here that
// departs from what the per-file worlds already did. Half of them passed the
// kid to the `Sealer` and half left it out, by descent rather than by
// decision. Those are two different paths through the Sealer's key selection.
// The default names the kid; `null` asks for the other path, where the
// publisher holds one key and the Sealer takes it.
//
// The world builds its publisher and its browser on the first ask, because
// `standUp` can add an issuer after the world is made. A `Publisher` copies its
// issuers at construction and a `Browser` copies the ones it walks, so building
// either of them eagerly would hand back a pair that copied the issuer list too
// early: every render sealed for the issuers the world happened to start with,
// and a walk that could not reach the one the caller just stood up. Their seeds are
// still drawn where they always were, so when a publisher is built does not
// move anybody's bytes.

import { Clock } from "../actors/Clock.js";
import { Random } from "../actors/Random.js";
import { Storage } from "../actors/Storage.js";
import { Network } from "../actors/Network.js";
import { Browser } from "../actors/Browser.js";
import { Publisher } from "../actors/Publisher.js";
import { IssuerServer } from "../actors/IssuerServer.js";
import { IssuerKeyStore } from "../support/IssuerKeyStore.js";
import { openingKeysOver } from "../support/PublisherRegistrations.js";
import { originForHost, publisherRegistrationsOver } from "../support/provisioning.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { utf8Decode } from "../../core-shared/codec.js";
import { exactPeriodKeySupply } from "../support/exactPeriodKeySupply.js";
import { AllowAllPolicy } from "../support/AllowAllPolicy.js";
import {
  ALGORITHM,
  AT,
  DOMAIN,
  FALLBACK_ISSUER_NAME,
  FALLBACK_UNLOCK_URL,
  HEALTH_URL,
  ISSUER_NAME,
  KEY_ID,
  SIGNING_KID,
  UNLOCK_URL,
  article,
} from "./fixtures.js";
import { rootFromPage } from "../support/queryableRoot.js";

const { subtle } = globalThis.crypto;

// Fixture-only deployment state. A real emergency authorization needs
// issuer-owned operational controls and audit; it is deliberately never read
// from a publisher render or browser request.
const DEMO_EMERGENCY_WINDOW = 6 * 60 * 60 * 1000;

// Onboarding assembly moved to `demo/support/provisioning.js`, where both
// families reach it. Re-exported here so a caller that already had it from this
// module keeps its import.
export { originForHost, publisherRegistrationsOver };

/**
 * @returns {Promise<CryptoKeyPair>}
 */
function signingKeypair() {
  return /** @type {Promise<CryptoKeyPair>} */ (
    subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
}

/**
 * The signing keys a world holds, as domain -> kid -> keypair.
 *
 * Named kids get a keypair each, per domain: two domains naming the same kid
 * hold two different keys, which is what a story about a swapped domain or a
 * rotation crossing one needs. Left unnamed, every domain holds `SIGNING_KID`
 * and one keypair signs for all of them - the wiring a story about periods or
 * transport wants and has no reason to spell.
 *
 * @param {string[]} domains
 * @param {Record<string, string[]>} [kids] - the kids each domain holds. A
 *   domain missing from it holds `SIGNING_KID`.
 * @returns {Promise<Record<string, Record<string, CryptoKeyPair>>>}
 */
async function signingKeysOver(domains, kids) {
  /** @type {Record<string, Record<string, CryptoKeyPair>>} */
  const pairs = {};
  for (const [index, domain] of domains.entries()) {
    pairs[domain] = {};
    const held =
      kids !== undefined && Object.hasOwn(kids, domain)
        ? kids[domain]
        : [domains.length === 1 ? SIGNING_KID : `${SIGNING_KID}-${index + 1}`];
    for (const kid of held) {
      pairs[domain][kid] = await signingKeypair();
    }
  }
  return pairs;
}

/**
 * The public half of each signing key, used to build exact publisher
 * registrations for the issuer application.
 *
 * @param {Record<string, Record<string, CryptoKeyPair>>} pairs
 * @returns {Record<string, Record<string, CryptoKey>>}
 */
function publicHalvesOf(pairs) {
  return Object.fromEntries(
    Object.entries(pairs).map(([domain, byKid]) => [
      domain,
      Object.fromEntries(Object.entries(byKid).map(([kid, pair]) => [kid, pair.publicKey])),
    ]),
  );
}

/**
 * The publisher side of one world's signing keys: which pair is the default,
 * which private keys a publisher on a given domain holds, and which kid it
 * signs with there.
 *
 * A domain this world holds no key for still gets the default domain's keys.
 * A publisher rendering as some other host tests what the issuer makes of the
 * domain, and it needs something to sign with before the issuer can decide.
 *
 * @param {Record<string, Record<string, CryptoKeyPair>>} pairs
 * @param {string} home - the domain the world's own publisher renders as
 * @returns {{ pair: CryptoKeyPair, keysFor: (domain: string) => Record<string, CryptoKey>, kidFor: (domain: string) => string }}
 */
function signingSideOf(pairs, home) {
  /** @param {string} domain */
  const heldBy = (domain) => (Object.hasOwn(pairs, domain) ? pairs[domain] : pairs[home]);
  /** @param {string} domain */
  const kidFor = (domain) =>
    Object.hasOwn(heldBy(domain), SIGNING_KID) ? SIGNING_KID : Object.keys(heldBy(domain))[0];

  return {
    pair: pairs[home][kidFor(home)],
    keysFor: (domain) =>
      Object.fromEntries(
        Object.entries(heldBy(domain)).map(([kid, pair]) => [kid, pair.privateKey]),
      ),
    kidFor,
  };
}

/**
 * A counter handing out one seed per `Random` in the world. Two publishers drawing
 * from one stream would make each one's bytes depend on the order the other was
 * called in; a seed apiece keeps a run replayable whatever order they render in.
 *
 * @param {number} first
 * @returns {() => Random}
 */
function seeds(first) {
  let next = first;
  return () => new Random({ seed: next++ });
}

/**
 * Both families assemble their publisher config here, so the two cannot drift
 * on what a default publisher is.
 *
 * Each world holds one opaque exact-key supply. Publishers in that world share it,
 * while a publisher with no supply keeps the direct-only path.
 *
 * @param {object} base
 * @param {object} overrides
 * @returns {Publisher}
 */
function publisherFrom(base, overrides) {
  const config = { ...base, ...overrides };
  const periodKeySupply =
    overrides.periodKeySupply === undefined ? base.periodKeySupply : overrides.periodKeySupply;
  return new Publisher({
    origin: originForHost(config.domain),
    clock: config.clock,
    random: config.random,
    signingKeys: config.signingKeys,
    ...(config.signingKid === null ? {} : { signingKid: config.signingKid }),
    ...(periodKeySupply === null
      ? {}
      : {
          periodKeySupply,
        }),
    ...(config.issuerSupplyPlanFor === undefined
      ? {}
      : {
          issuerSupplyPlanFor: config.issuerSupplyPlanFor,
        }),
    ...(config.period === undefined ? {} : { period: config.period }),
    ...(config.developmentHttpOrigin === undefined
      ? {}
      : { developmentHttpOrigin: config.developmentHttpOrigin }),
    issuers: config.issuers,
  });
}

/**
 * Stands up a deployment: a network with issuer servers on it, a publisher
 * sealing for every one of them, and a browser walking them in the order it was
 * configured with.
 *
 * @param {object} [config]
 * @param {string} [config.at] - where the clock starts
 * @param {number} [config.seed] - the first seed; each `Random` takes the next
 * @param {string[]} [config.domains] - the hosts this world's publishers render
 *   as, and the ones the issuers hold signing keys for
 * @param {Record<string, string[]>} [config.signingKids] - which kids each of
 *   those domains holds, when one pair over all of them is not the story. Every
 *   (domain, kid) named gets a keypair of its own; a domain left out holds
 *   `SIGNING_KID`. Left out entirely, one keypair signs for every domain.
 * @param {string|null} [config.signingKid] - which kid the render names. `null`
 *   leaves it to the `Sealer`, which takes the only key when there is one.
 * @param {import('../../core-publisher/Sealer.js').PeriodKeySupply|null} [config.periodKeySupply] -
 *   exact keys for the cached path; `null` selects direct-only
 * @param {{ length?: number, slots?: number }} [config.period]
 * @param {Function} [config.issuerSupplyPlanFor] - publisher-side per-issuer
 *   exact/chain supply selection
 * @param {boolean} [config.fallback] - stand a second issuer up behind the first
 * @param {number} [config.healthTtl] - how long the fallback believes a probe
 * @param {number} [config.fallbackEmergencyUntil] - server-clock deadline for
 *   the fixture fallback's simulated emergency authorization
 * @param {{ threshold?: number, window?: number, timeout?: number }} [config.breaker]
 * @param {import('../../core-issuer/IssuerEngine.js').AccessPolicy} [config.accessPolicy] - what the primary decides
 *   with. Left out, a verified request is granted whole.
 * @param {boolean} [config.relayExactPeriod] - client-side exact request selection
 * @param {boolean} [config.exactPeriodInput] - issuer-side exact input selection
 * @param {'direct'|'client-bound'} [config.transportMode] - what the primary
 *   answers in, in place of the pinned direct
 * @param {{ modeFor: Function }} [config.transportPolicy] - what decides that
 *   mode per request, in place of a pinned one
 * @param {{ METHOD: string, RANDOM_REQUIRED: boolean, seal: Function }} [config.clientBoundProfile] -
 *   explicitly selected issuer-side client-bound extension profile
 * @param {object} [config.periodChainProfile] - explicitly selected chain
 *   profile shared by publisher, issuer and client
 * @param {(options: object) => object} [config.periodChainCacheFactory] -
 *   selected chain cache construction, paired with `periodChainProfile`
 * @param {boolean} [config.registrationOrigins] - give every registration the
 *   optional issuer-held origin limit, which onboarding does not require
 * @param {object} [config.primary] - anything else the primary's `IssuerServer`
 *   takes. Options here move this world's own primary, instead of standing a
 *   special issuer beside a primary nobody asks.
 * @returns {Promise<any>}
 */
export async function actorWorld(config = {}) {
  const clock = new Clock(config.at ?? AT);
  const nextRandom = seeds(config.seed ?? 1);
  const random = nextRandom();
  const network = new Network({ clock });

  const domains =
    config.domains ??
    (config.signingKids === undefined ? [DOMAIN] : Object.keys(config.signingKids));
  const signingKeyPairs = await signingKeysOver(domains, config.signingKids);
  const signing = signingSideOf(signingKeyPairs, domains[0]);
  const signingKeys = signing.pair;
  /** @type {any[]} */
  const issuers = [];

  /**
   * One issuer stood up: its own keypair, its own store, and the issuer config
   * a publisher needs to seal for it. Both come back, because a caller wiring
   * a third issuer needs the second half as much as the first.
   *
   * @param {string} issuerName
   * @param {string} unlockUrl
   * @param {object} [extra] - anything else the `IssuerServer` takes, this
   *   issuer's own `accessPolicy` included, so one world can hold two peers
   *   that differ only in what they decide with, instead of two hand-wired worlds
   * @returns {Promise<{ server: IssuerServer, issuer: any, keyStore: IssuerKeyStore }>}
   */
  const standUp = async (issuerName, unlockUrl, extra = {}) => {
    const keys = /** @type {CryptoKeyPair} */ (
      await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
    );
    // One store per issuer, not one shared across them. The engine looks a
    // key up under the issuerName the request carried, so a store holding a
    // second issuer's keys would let this one answer for that one.
    const keyStore = new IssuerKeyStore([
      {
        issuerName,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
      },
    ]);
    const openingKeys = openingKeysOver(keyStore, [{ issuerName, keyId: KEY_ID }]);
    const publisherRegistrations = publisherRegistrationsOver(
      publicHalvesOf(signingKeyPairs),
      openingKeys,
      {
        origins: config.registrationOrigins === true,
      },
    );

    const issuer = {
      issuerName,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      publicKey: keys.publicKey,
      unlockUrl,
    };
    issuers.push(issuer);

    const server = new IssuerServer({
      clock,
      network,
      issuerName,
      unlockUrl,
      keyStore,
      publisherRegistrations,
      accessPolicy: new AllowAllPolicy(),
      ...(extra.role === "fallback" && extra.emergencyUntil === undefined
        ? { emergencyUntil: clock.now().getTime() + DEMO_EMERGENCY_WINDOW }
        : {}),
      ...(extra.periodGrantKind === "chain" && config.periodChainProfile !== undefined
        ? { periodChainProfile: config.periodChainProfile }
        : {}),
      // Every issuer added to this exact-period preset inherits the same
      // trusted input selection unless its own fixture overrides it.
      exactPeriodInput: config.exactPeriodInput ?? true,
      ...extra,
    });
    return { server, issuer, keyStore, publisherRegistrations };
  };

  const transport = {
    ...(config.transportMode === undefined ? {} : { transportMode: config.transportMode }),
    ...(config.transportPolicy === undefined ? {} : { transportPolicy: config.transportPolicy }),
    ...(config.clientBoundProfile === undefined
      ? {}
      : { clientBoundProfile: config.clientBoundProfile }),
  };
  const primary = await standUp(ISSUER_NAME, UNLOCK_URL, {
    role: "primary",
    healthCheckUrl: HEALTH_URL,
    ...(config.accessPolicy === undefined ? {} : { accessPolicy: config.accessPolicy }),
    ...transport,
    ...(Object.keys(transport).length === 0 ? {} : { random }),
    // Last, so a caller reaching for something this world has no knob for
    // moves the primary itself rather than standing a second issuer beside it.
    ...(config.primary ?? {}),
  });

  const fallback = config.fallback
    ? await standUp(FALLBACK_ISSUER_NAME, FALLBACK_UNLOCK_URL, {
        role: "fallback",
        healthCheckUrl: HEALTH_URL,
        // The fixture starts an explicit, finite server-owned demonstration
        // window. It is not carried in the render or unlock request.
        emergencyUntil:
          config.fallbackEmergencyUntil ?? clock.now().getTime() + DEMO_EMERGENCY_WINDOW,
        ...(config.healthTtl === undefined ? {} : { healthTtl: config.healthTtl }),
      })
    : null;

  const periodKeySupply =
    config.periodKeySupply === null
      ? null
      : (config.periodKeySupply ??
        exactPeriodKeySupply({
          random: new Random({ seed: (config.seed ?? 1) + 100000 }),
        }));

  const base = {
    domain: domains[0],
    clock,
    periodKeySupply,
    period: config.period,
    issuerSupplyPlanFor: config.issuerSupplyPlanFor,
    issuers,
  };

  /**
   * What a publisher on one domain signs with. The keys follow the domain: a
   * publisher rendering as another host signs with that host's key, which is
   * the coordinate an issuer files them under. A kid this world was configured
   * with is kept as it was named.
   *
   * @param {string} domain
   * @returns {{ signingKeys: Record<string, CryptoKey>, signingKid: string|null }}
   */
  const signingFor = (domain) => ({
    signingKeys: signing.keysFor(domain),
    signingKid: config.signingKid === undefined ? signing.kidFor(domain) : config.signingKid,
  });

  /**
   * Another publisher over the same issuers: a second domain, another period,
   * another key supply. Two of them in one process show that none of that is
   * settled at module scope.
   *
   * @param {object} [overrides]
   * @returns {Publisher}
   */
  const publisherWith = (overrides = {}) =>
    publisherFrom(
      { ...base, random: nextRandom(), ...signingFor(overrides.domain ?? base.domain) },
      overrides,
    );

  // Drawn here rather than where the publisher is built, so the seed it takes
  // is the same one whether a caller asks for it before a `publisherWith` or
  // after one.
  const defaultRandom = nextRandom();
  /** @type {Publisher|null} */
  let standing = null;

  /**
   * A browser of its own, over storage of its own. Two of these stand for two
   * users, because their storage is separate.
   *
   * It walks every issuer standing at the moment it is built, in the order
   * they were stood up, so an issuer added after the world was made is one the
   * client can reach.
   *
   * @param {object} [overrides]
   * @returns {Browser}
   */
  const makeBrowser = (overrides = {}) =>
    new Browser({
      clock,
      network,
      storage: new Storage(),
      issuers: issuers.map(({ issuerName, unlockUrl }) => ({ issuerName, unlockUrl })),
      ...(config.breaker ? { breaker: config.breaker } : {}),
      relayExactPeriod: config.relayExactPeriod ?? true,
      ...(config.periodChainProfile === undefined
        ? {}
        : {
            periodChainProfile: config.periodChainProfile,
            periodChainCacheFactory: config.periodChainCacheFactory,
          }),
      ...overrides,
    });

  /** @type {Browser|null} */
  let walking = null;

  const stage = {
    clock,
    random,
    periodKeySupply,
    network,
    signingKeys,
    signingKeyPairs,
    publisherRegistrations: primary.publisherRegistrations,
    publisherRegistration: primary.publisherRegistrations.get(signing.kidFor(domains[0])),
    issuers,
    servers: {
      primary: primary.server,
      ...(fallback ? { fallback: fallback.server } : {}),
    },
    keyStores: {
      primary: primary.keyStore,
      ...(fallback ? { fallback: fallback.keyStore } : {}),
    },
    standUp,
    /** The world's own publisher, built the first time it is asked for. */
    get publisher() {
      standing ??= publisherFrom(
        { ...base, random: defaultRandom, ...signingFor(base.domain) },
        {},
      );
      return standing;
    },
    publisherWith,
    /**
     * @param {'A'|'B'|'C'|'D'|'E'} label
     * @param {{ resourceId?: string, data?: object, items?: object[] }} [options]
     * @returns {Promise<import('../support/Page.js').Page>}
     */
    render: (label, options) => stage.publisher.render(article(label, options)),
    makeBrowser,
    /** The world's own browser, built the first time it is asked for. */
    get browser() {
      walking ??= makeBrowser();
      return walking;
    },
  };

  return stage;
}

/**
 * Puts the two cores face to face with nothing between them: a publisher, and
 * the endpoint an issuer answers on. A render comes out in the delivery form the
 * object delivery reader parses, because that is what this family's client
 * reads. The actor family hands over a `Page` instead, which is what a
 * `Browser` loads.
 *
 * @param {object} [config]
 * @param {string} [config.at]
 * @param {number} [config.seed]
 * @param {string[]} [config.domains]
 * @param {Record<string, string[]>} [config.signingKids] - the kids each domain
 *   holds, as in `actorWorld`
 * @param {string|null} [config.signingKid]
 * @param {import('../../core-publisher/Sealer.js').PeriodKeySupply|null} [config.periodKeySupply] -
 *   exact keys for the cached path; `null` selects direct-only
 * @param {{ length?: number, slots?: number }} [config.period]
 * @param {import('../../core-issuer/IssuerEngine.js').AccessPolicy} [config.accessPolicy]
 * @returns {Promise<any>}
 */
export async function directWorld(config = {}) {
  const clock = new Clock(config.at ?? AT);
  const nextRandom = seeds(config.seed ?? 1);

  const domains =
    config.domains ??
    (config.signingKids === undefined ? [DOMAIN] : Object.keys(config.signingKids));
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const signingKeyPairs = await signingKeysOver(domains, config.signingKids);
  const signing = signingSideOf(signingKeyPairs, domains[0]);
  const signingKeys = signing.pair;

  const keyStore = new IssuerKeyStore([
    {
      issuerName: ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      privateKey: issuerKeys.privateKey,
      publicKey: issuerKeys.publicKey,
    },
  ]);
  const openingKeys = openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]);
  const publisherRegistrations = publisherRegistrationsOver(
    publicHalvesOf(signingKeyPairs),
    openingKeys,
  );
  const defaultRegistration = publisherRegistrations.get(signing.kidFor(domains[0]));

  const issuers = [
    {
      issuerName: ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      publicKey: issuerKeys.publicKey,
      unlockUrl: UNLOCK_URL,
    },
  ];

  const periodKeySupply =
    config.periodKeySupply === null
      ? null
      : (config.periodKeySupply ??
        exactPeriodKeySupply({
          random: new Random({ seed: (config.seed ?? 1) + 100000 }),
        }));

  const base = {
    domain: domains[0],
    clock,
    periodKeySupply,
    period: config.period,
    issuers,
  };

  /**
   * What a publisher on one domain signs with: the domain's own keys, and the
   * kid this world was configured with or that domain's own.
   *
   * @param {string} domain
   * @returns {{ signingKeys: Record<string, CryptoKey>, signingKid: string|null }}
   */
  const signingFor = (domain) => ({
    signingKeys: signing.keysFor(domain),
    signingKid: config.signingKid === undefined ? signing.kidFor(domain) : config.signingKid,
  });

  /**
   * @param {object} [overrides]
   * @returns {Publisher}
   */
  const publisherWith = (overrides = {}) =>
    publisherFrom(
      { ...base, random: nextRandom(), ...signingFor(overrides.domain ?? base.domain) },
      overrides,
    );

  // Drawn here, built on first ask: the seed this publisher takes does not
  // depend on when it is built.
  const defaultRandom = nextRandom();
  /** @type {Publisher|null} */
  let standing = null;

  // The processor a library caller admits its request through before handing
  // the endpoint the miss, exposed beside `endpoint` so that caller composes
  // the two public calls itself rather than reaching for a convenience path.
  // The pairing serves migration and tests, and it is no production port.
  // A reusable integration composes `IssuerProcessor` and `UnlockEndpoint`
  // directly, so `stage.processor` is never the integration seam.
  const issuerProcessor = new IssuerProcessor(
    new IssuerEngine({
      accessPolicy: config.accessPolicy ?? new AllowAllPolicy(),
    }),
    // The direct-endpoint fixture is the exact-period preset even when a test
    // deliberately withholds publisher supply to exercise its failure path.
    { exactPeriodInput: true },
  );

  const stage = {
    clock,
    signingKeys,
    signingKeyPairs,
    issuerKeys,
    keyStore,
    publisherRegistrations,
    publisherRegistration: defaultRegistration,
    issuers,
    /** The world's own publisher, built the first time it is asked for. */
    get publisher() {
      standing ??= publisherFrom(
        { ...base, random: defaultRandom, ...signingFor(base.domain) },
        {},
      );
      return standing;
    },
    publisherWith,
    /**
     * @param {'A'|'B'|'C'|'D'|'E'} label
     * @param {{ resourceId?: string, data?: object, items?: object[] }} [options]
     * @returns {Promise<any>} the delivery form, as it reaches a client
     */
    render: async (label, options) =>
      (await stage.publisher.render(article(label, options))).asJson(),
    processor: issuerProcessor,
    endpoint: new UnlockEndpoint(issuerProcessor),
  };

  return stage;
}

/**
 * The whole client story for one page: resolve, unlock whatever is missing, and
 * read every name that was asked for. A locked item comes back as a null text
 * beside the code that says why: the load reports it as data on the page rather
 * than throwing.
 *
 * @param {any} browser
 * @param {import('../support/Page.js').Page} page
 * @param {string[]} names
 * @param {object} [options] - what the unlock is made with: a credential, or
 *   the one issuer to ask
 * @returns {Promise<{ load: any, unlock: any, texts: Record<string, string|null>, errors: Record<string, string|null> }>}
 */
export async function readArticle(browser, page, names, options = {}) {
  const load = browser.load(rootFromPage(page));
  const { missing } = await load.resolve(names);
  const unlock = missing.length === 0 ? null : await load.unlock(options);

  /** @type {Record<string, string|null>} */
  const texts = {};
  /** @type {Record<string, string|null>} */
  const errors = {};
  for (const name of names) {
    const { bytes, error } = await load.open(name);
    texts[name] = bytes === null ? null : utf8Decode(bytes);
    errors[name] = error;
  }

  return { load, unlock, texts, errors };
}
