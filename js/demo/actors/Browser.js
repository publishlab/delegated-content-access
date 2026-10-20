// @ts-check
//
// One stateful end: everything a client keeps that outlives a page. The
// periodKey cache over its `Storage`, the issuer list and its fall-through
// order, the breaker, and an optional client-bound capability supplied by its
// host.
//
// `Browser` keeps one client-bound capability per client, built by the
// selected extension. It is held here for the reason the cache is: it outlives
// the page. A pair drawn per load would make every page a new client to the
// issuer - two tabs would negotiate two transports of their own, and a store
// that kept its keys still wrapped would hold nothing the next load could
// open. Building the capability is where a keypair it cannot use is refused,
// once, rather than on every load; the private half lives inside the
// capability and no load ever reads it.
//
// Each `Browser` stands for one user. Two machines keep separate storage, so
// two `Browser`s do too. Two live `PageLoad`s over one `Browser` are two tabs,
// and what they share is exactly what a real pair of tabs shares: the store,
// and the breaker's opinion of an issuer.
//
// Each `Browser` takes its issuer list from the configuration it was built
// with. A page cannot name that list. A page may name only the primary and
// still be openable by a fallback the client knows about - the fallback needs
// sealed blobs on the page to have anything to open, but which issuers to
// walk, and in what order, is the client's.
//
// `Browser` owns the breaker, and every load it makes shares that one, so a
// second article does not have to rediscover that the primary is down. It is
// keyed per issuer url: one issuer failing says nothing about another, and two
// urls on one host are two things that can fail apart.

import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { IssuerRouteCircuitBreaker } from "../../adapter-client/IssuerRouteCircuitBreaker.js";
import { evictAfterSixHours } from "../../adapter-client/periodKeyEviction.js";
import { PageLoad } from "./PageLoad.js";
import { MarkupDeliveryReader } from "../../adapter-client/MarkupDeliveryReader.js";
import { dcaError } from "../../core-shared/errors.js";
import { ContentRepresentationOpener } from "../../core-client/ContentRepresentationOpener.js";

/**
 * @typedef {import("../../adapter-client/IssuerRouteCircuitBreaker.js").BreakerState} BreakerState
 */

/**
 * The selected chain-key extension's client profile, as a load consumes it.
 *
 * @typedef {object} ChainKeyClientProfile
 * @property {Function} parametersForResponse
 * @property {Function} candidateSourceFor
 * @property {Function} acceptsPeriodKeyResponseCoordinate
 * @property {Function} acceptsResponseCoordinate
 */

const OPTIONS = [
  "clock",
  "network",
  "storage",
  "issuers",
  "breaker",
  "cacheKeyBy",
  "cacheNamespace",
  "cacheFactory",
  "clientBoundKeyCapability",
  "acceptDirectFallback",
  "persistRawPeriodKeys",
  "relayPeriodKeys",
  "chainKeyStrategy",
  "chainKeyProfile",
  "chainKeyCacheFactory",
  "resolverFactory",
  "requestBuilderFactory",
  "contentDecoders",
];

export class Browser {
  #clock;
  #network;
  /** @type {{ issuerName: string, unlockUrl: string, acceptDirectResponse?: boolean, retryUnavailable?: boolean }[]} */
  #issuers;
  /** @type {IssuerRouteCircuitBreaker} */
  #breaker;
  /** @type {PeriodKeyCache} */
  #cache;
  /** @type {(() => { put: Function, candidatesAt: Function, attempted: Function })|null} */
  #cacheFactory;
  /** @type {any|null} */
  #chainCache;
  /** @type {ChainKeyClientProfile|null} */
  #chainKeyProfile;
  /** @type {any} the client-bound key capability, or undefined for direct transport only */
  #capability;
  /** @type {boolean|undefined} */
  #acceptDirectFallback;
  /** @type {boolean|undefined} */
  #persistRawPeriodKeys;
  /** @type {boolean|undefined} */
  #relayPeriodKeys;
  /** @type {((options: object) => object)|undefined} */
  #resolverFactory;
  /** @type {((options: object) => object)|undefined} */
  #requestBuilderFactory;
  /** @type {ContentRepresentationOpener} */
  #contentRepresentationOpener;

  #loads = 0;
  #unlocks = 0;
  #unlockFailures = 0;

  /**
   * @param {object} config
   * @param {{ now: () => Date }} config.clock
   * @param {{ post: Function }} config.network
   * @param {{ issuerName: string, unlockUrl: string, acceptDirectResponse?: boolean, retryUnavailable?: boolean }[]} config.issuers - the
   *   configured list and its fall-through order
   * @param {object} [config.storage] - what the cache is kept in. Left out,
   *   the cache is a plain Map and no tab can lose a key to another.
   * @param {{ threshold?: number, window?: number, timeout?: number }} [config.breaker]
   * @param {(context: { issuerName?: string, accessGroup: string }) => string} [config.cacheKeyBy]
   *   how the periodKey cache names a family. Left out, a family is its
   *   accessGroup and a key any issuer granted opens every article of that
   *   group, and the default because it is the behaviour worth
   *   showing. `keyByIssuer` mitigates that, on the client: the
   *   wire stays the same, and only what this browser will reuse a key for
   *   changes.
   * @param {string} [config.cacheNamespace] - the storage scope this client's
   *   period keys are filed under, when one backend serves several. This
   *   Browser owns exactly one namespace; the host injects it. Left out, the
   *   cache files under the bare prefix, which is what a Browser over its own
   *   store or an in-memory cache is. A host that runs several clients over
   *   one backend gives each its own namespace, since nothing here can name
   *   them apart on its behalf.
   * @param {() => { put: Function, candidatesAt: Function, attempted: Function }} [config.cacheFactory] - supplies one cache view per
   *   load. The host closure owns the shared store and namespace; without it,
   *   every load uses this Browser's default cache.
   * @param {'retain'|'expand'} [config.chainKeyStrategy] - how directly
   *   delivered chain keys are held across pages
   * @param {ChainKeyClientProfile} [config.chainKeyProfile] -
   *   the selected chain-key extension's client profile, injected together
   *   with its cache factory
   * @param {(options: object) => object} [config.chainKeyCacheFactory] -
   *   the selected chain-key extension's cache constructor boundary
   * @param {{ publicKey: JsonWebKey, openDeliveredKeys: Function }} [config.clientBoundKeyCapability] -
   *   the selected extension's client capability, kept across pages. Left
   *   out, this client asks for nothing but direct transport.
   * @param {boolean} [config.acceptDirectFallback] - whether this composition
   *   accepts content keys in direct representation when it offered a
   *   client-bound capability
   * @param {boolean} [config.persistRawPeriodKeys] - separate permission for
   *   accepted, directly delivered period keys to enter this browser's caches
   * @param {boolean} [config.relayPeriodKeys] - whether this browser selects
   *   period-key request relay
   * @param {(options: object) => object} [config.resolverFactory] - builds the
   *   selected resolver composition once for each page load
   * @param {(options: object) => object} [config.requestBuilderFactory] - builds
   *   the selected request composition independently of the resolver
   * @param {Record<string, (bytes: Uint8Array) => Promise<Uint8Array>|Uint8Array>} [config.contentDecoders] -
   *   the representation decoders this client composition supports
   */
  constructor(config) {
    for (const name of Object.keys(config ?? {})) {
      if (!OPTIONS.includes(name)) {
        throw dcaError("unsupported_option", `Browser has no ${name} yet, and will not pretend to`);
      }
    }
    if (!config?.clock) throw dcaError("bad_config", "Browser needs a clock");
    if (!config?.network) throw dcaError("bad_config", "Browser needs a network");
    if (!Array.isArray(config.issuers) || config.issuers.length === 0) {
      throw dcaError("bad_config", "Browser needs the issuers it walks, in order");
    }
    for (const issuer of config.issuers) {
      if (!issuer?.issuerName || !issuer?.unlockUrl) {
        throw dcaError(
          "bad_config",
          "a configured issuer is an issuerName and the unlockUrl it answers on",
        );
      }
      if (issuer.retryUnavailable !== undefined && typeof issuer.retryUnavailable !== "boolean") {
        throw dcaError("bad_config", "an issuer's retryUnavailable is boolean");
      }
      if (
        issuer.acceptDirectResponse !== undefined &&
        typeof issuer.acceptDirectResponse !== "boolean"
      ) {
        throw dcaError("bad_config", "an issuer's acceptDirectResponse is boolean");
      }
    }
    if (config.resolverFactory !== undefined && typeof config.resolverFactory !== "function") {
      throw dcaError("bad_config", "a Browser resolverFactory is a function");
    }
    if (
      config.requestBuilderFactory !== undefined &&
      typeof config.requestBuilderFactory !== "function"
    ) {
      throw dcaError("bad_config", "a Browser requestBuilderFactory is a function");
    }
    if (config.cacheFactory !== undefined && typeof config.cacheFactory !== "function") {
      throw dcaError("bad_config", "a Browser cacheFactory is a function");
    }
    for (const name of /** @type {const} */ ([
      "acceptDirectFallback",
      "persistRawPeriodKeys",
      "relayPeriodKeys",
    ])) {
      if (config[name] !== undefined && typeof config[name] !== "boolean") {
        throw dcaError("bad_config", `Browser ${name} is boolean`);
      }
    }

    this.#clock = config.clock;
    this.#network = config.network;
    this.#issuers = config.issuers.map((issuer) => ({ ...issuer }));
    this.#breaker = new IssuerRouteCircuitBreaker(config.breaker ?? {});
    // The namespace scopes this client's entries in a shared store, and it
    // is the host's to give: two clients over one backend are told apart by
    // the name it hands each. Unnamed, the cache files under the bare
    // prefix, which suits a private store or an in-memory cache. The cache
    // files under the scope it is handed.
    this.#cache = new PeriodKeyCache({
      clock: this.#clock,
      evictionPolicy: evictAfterSixHours,
      ...(config.cacheNamespace ? { namespace: config.cacheNamespace } : {}),
      ...(config.storage ? { storage: /** @type {any} */ (config.storage) } : {}),
      ...(config.cacheKeyBy ? { keyBy: config.cacheKeyBy } : {}),
    });
    this.#cacheFactory = config.cacheFactory ?? null;
    if (config.chainKeyStrategy !== undefined && config.chainKeyProfile === undefined) {
      throw dcaError("bad_config", "a chainKeyStrategy needs an injected chainKeyProfile");
    }
    if ((config.chainKeyProfile === undefined) !== (config.chainKeyCacheFactory === undefined)) {
      throw dcaError(
        "bad_config",
        "chain-key support needs an injected profile and cache factory together",
      );
    }
    this.#chainKeyProfile = config.chainKeyProfile ?? null;
    const construction = /** @type {any} */ (this.#chainKeyProfile)?.constructionProfile;
    this.#chainCache =
      this.#chainKeyProfile === null
        ? null
        : /** @type {(options: object) => object} */ (config.chainKeyCacheFactory)({
            strategy: config.chainKeyStrategy ?? "retain",
            clock: this.#clock,
            evictionPolicy: evictAfterSixHours,
            ...(config.cacheKeyBy ? { keyBy: config.cacheKeyBy } : {}),
            ...(construction === undefined ? {} : { construction: construction.name }),
          });
    this.#capability = config.clientBoundKeyCapability;
    this.#acceptDirectFallback = config.acceptDirectFallback;
    this.#persistRawPeriodKeys = config.persistRawPeriodKeys;
    this.#relayPeriodKeys = config.relayPeriodKeys;
    // A factory the host did not inject is left out, and `composeClient`
    // builds the base resolver and request composition for the load.
    this.#resolverFactory = config.resolverFactory;
    this.#requestBuilderFactory = config.requestBuilderFactory;
    this.#contentRepresentationOpener = new ContentRepresentationOpener(config.contentDecoders);
  }

  /** The periodKey cache, across pages. Two tabs read the one of these. */
  get cache() {
    return this.#cache;
  }

  /** Shared across loads: a second article does not rediscover an outage. */
  get breaker() {
    return this.#breaker;
  }

  /** @returns {{ issuerName: string, unlockUrl: string }[]} */
  get issuers() {
    return this.#issuers.map((issuer) => ({ ...issuer }));
  }

  /**
   * The client loads an already-parsed page root: anything that answers
   * `querySelectorAll`, which in a browser is the document and in a test is a
   * fabricated root. The Browser builds its configured delivery reader over
   * the root, and the load reads its render off that one reading. A root the
   * reader cannot query is refused in the reader, not here.
   *
   * @param {{ querySelectorAll: (selector: string) => any }} root
   * @returns {PageLoad}
   */
  load(root) {
    const delivery = new MarkupDeliveryReader(root);
    const cache = this.#cacheFactory === null ? this.#cache : this.#cacheFactory();
    if (cache === null || typeof cache !== "object") {
      throw dcaError("bad_config", "a Browser cacheFactory returns a cache view object");
    }
    this.#loads++;

    return new PageLoad({
      delivery,
      clock: this.#clock,
      network: this.#network,
      cache,
      ...(this.#chainCache === null
        ? {}
        : {
            chainCache: this.#chainCache,
            // The constructor builds the chain cache only beside a profile.
            chainKeyProfile: /** @type {ChainKeyClientProfile} */ (this.#chainKeyProfile),
          }),
      clientBoundKeyCapability: this.#capability,
      acceptDirectFallback: this.#acceptDirectFallback,
      persistRawPeriodKeys: this.#persistRawPeriodKeys,
      relayPeriodKeys: this.#relayPeriodKeys,
      resolverFactory: this.#resolverFactory,
      requestBuilderFactory: this.#requestBuilderFactory,
      contentRepresentationOpener: this.#contentRepresentationOpener,
      issuers: this.#issuers,
      breaker: this.#breaker,
      caller: this,
      onUnlock: (/** @type {boolean} */ ok) => {
        this.#unlocks++;
        if (!ok) this.#unlockFailures++;
      },
    });
  }

  /**
   * @returns {{ loads: number, unlocks: number, unlockFailures: number, issuers: string[], breaker: Record<string, BreakerState> }}
   */
  stats() {
    return {
      loads: this.#loads,
      unlocks: this.#unlocks,
      unlockFailures: this.#unlockFailures,
      issuers: this.#issuers.map((issuer) => issuer.issuerName),
      breaker: this.#breaker.stats(),
    };
  }
}
