// @ts-check
/// <reference lib="es2023.array" />
//
// The scripts running on one page. `Browser.load()` makes it, and everything
// it keeps is about this one load: what it resolved, what it asked for, who
// answered, what it opened. Loading the same `Page` twice gives two of these.
// Two of them compare the page over time; two at once stand for two tabs.
//
// The `Browser` owns the cache and this load owns the resolver. A periodKey
// outlives the render and opens the next article, so it belongs to the client.
// A contentKey is good for one render by construction and lives in the selected
// resolver. Each load gets one resolver, because two tabs run two JavaScript
// contexts and cannot hand each other in-memory keys. They share the store
// under the cache, which is what two real tabs share.
//
// The `Browser` owns the client-bound capability as well, and passes it down
// the same way: into this load's request builder, which offers the public
// half in the request it builds, and into its resolver, which opens an answer
// that came back wrapped. Nothing here asks for a mode or is told one. This
// load reads the mode off what arrived, the only reading that survives a
// fallback with no client-bound mode answering a client that has one.
//
// THE WALK. `unlock` tries the issuers in the `Browser`'s configured order,
// starting where the caller tells it to. It passes over an issuer the page
// carries no sealed blobs for, having nothing for that issuer to open. It
// skips an issuer whose breaker is open without calling it, which is what the
// breaker is for. It walks on when it cannot reach an issuer, and stops when
// an issuer refuses. Walking on past a 401 or a 403 would shop for an issuer
// that says yes, and the access policy settles which issuer may decide, not
// the transport.
//
// A 200 ends the walk on the response consumer's accepted count, and when it
// accepted nothing, on what the wire `errors` say. Malformed or unsupported
// local material can fall through to the next issuer without pretending that
// key-shaped input was retained. A code for a grant the issuer withheld
// reports a decision, and the walk ends there for the same reason it ends at
// a 401.
//
// `PageLoad` counts trials because the resolver has nowhere honest to count
// them: on a trial unwrap this load asks the cache for candidates and asks
// AES-GCM to open one. This load counts the asking, through a view of the
// cache that adds nothing else.

import { DcaData } from "../../core-client/DcaData.js";
import { openContent } from "../../core-client/openContent.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { composeClient } from "../../integration-client/composeClient.js";
import { deliveredKeys } from "../../core-shared--client-issuer/responseKeys.js";
import { own } from "../../core-shared/wire.js";
import {
  DcaError,
  dcaError,
  isTransportFailureCode,
  WITHHELD_CODES,
} from "../../core-shared/errors.js";

/**
 * @typedef {import("../../adapter-client/IssuerRouteCircuitBreaker.js").IssuerRouteCircuitBreaker}
 *   IssuerRouteCircuitBreaker
 */

/**
 * The `errors` codes that report a decision rather than a blob that would not
 * open. A fallback hands over the period the client is reading in and withholds
 * the rest, so for a group it kept nothing of, the issuer opened what arrived
 * and gave this reader none of it. Every other code in `errors` says the issuer
 * could not open something, which says nothing about the reader.
 */
const WITHHELD = new Set(Object.values(WITHHELD_CODES));

const UNLOCK_OPTIONS = ["issuerName", "credential"];

// This symbol deliberately stays module-private. PageLoad's public client API
// leaves the A→B teaching probe out: only the demo-only helper below can
// invoke it, with its fixed bodytext operation.
const DIRECT_KEY_MISMATCH_DEMO = Symbol("direct-key-mismatch-demo");
const DIRECT_KEY_MISMATCH_CONTENT = "bodytext";

export class PageLoad {
  #clock;
  #network;
  #issuers;
  #breaker;
  #caller;
  #onUnlock;

  /**
   * The delivery reader the Browser built over the page root, read once: this
   * load builds a request from the same reading it decrypts from.
   *
   * @type {{ dcaData: any, publisherOrigin: string, extract: (contentName: string) => (string|null) }}
   */
  #delivered;
  /** @type {DcaData} */
  #dcaData;
  /** @type {{ applyResponse: Function, resolveDetailed: Function, contentKeyWithOriginFor: Function }} */
  #resolver;
  /** @type {{ build: Function }} */
  #builder;
  /** @type {import("../../core-client/ContentRepresentationOpener.js").ContentRepresentationOpener} */
  #contentRepresentationOpener;

  /** @type {string[]|null} what the last resolve could not open */
  #needed = null;

  #unlocks = 0;
  #attempts = 0;
  #skipped = 0;
  #trials = 0;
  /** @type {string|null} */
  #answeredBy = null;
  /** @type {string|null} */
  #transportMode = null;
  /** @type {{ covered: string[], missing: string[] }|null} */
  #resolved = null;
  /** @type {string[]} */
  #decrypted = [];
  /** @type {string[]} */
  #misses = [];
  /** @type {{ operation: 'resolve'|'re-resolve-after-unlock'|'open', origins: any[] }[]} */
  #keyResolutions = [];

  /**
   * @param {object} config - supplied by `Browser.load`, not by hand
   * @param {{ dcaData: any, publisherOrigin: string, extract: (contentName: string) => (string|null) }} config.delivery -
   *   the delivery reader the Browser built over the page root
   * @param {{ now: () => Date }} config.clock
   * @param {{ post: Function }} config.network
   * @param {{ put: Function, candidatesAt: Function, attempted: Function }} config.cache
   * @param {{ put: Function, candidates: Function, attempted?: Function }} [config.chainCache]
   * @param {{ parametersForResponse: Function, candidateSourceFor: Function, acceptsExactResponseCoordinate: Function, acceptsResponseCoordinate: Function }} [config.periodChainProfile]
   * @param {any} [config.clientBoundKeyCapability] - the browser's client-bound
   *   key capability, or nothing at all when this client does direct only
   * @param {boolean} [config.acceptDirectFallback] - explicit permission to
   *   consume direct keys beside a client-bound capability
   * @param {boolean} [config.persistRawPeriodKeys] - independent permission
   *   to file direct period capabilities in this browser's caches
   * @param {boolean} [config.relayExactPeriod] - whether this load's requests
   *   relay selected exact-period material
   * @param {(options: object) => object} [config.resolverFactory] - the
   *   browser-selected resolver composition, built once for this load. Left
   *   out, this load takes the base resolver.
   * @param {(options: object) => object} [config.requestBuilderFactory] - the
   *   independently selected request composition, built once for this load.
   *   Left out, this load takes the base request builder.
   * @param {import("../../core-client/ContentRepresentationOpener.js").ContentRepresentationOpener} [config.contentRepresentationOpener] -
   *   the browser's generic representation opener
   * @param {{ issuerName: string, unlockUrl: string }[]} config.issuers
   * @param {IssuerRouteCircuitBreaker} config.breaker
   * @param {object} config.caller - who the network sees calling, so
   *   reachability can differ between this client and an issuer
   * @param {(ok: boolean) => void} [config.onUnlock]
   */
  constructor({
    delivery,
    clock,
    network,
    cache,
    chainCache,
    periodChainProfile,
    clientBoundKeyCapability,
    acceptDirectFallback,
    persistRawPeriodKeys,
    relayExactPeriod,
    resolverFactory,
    requestBuilderFactory,
    contentRepresentationOpener,
    issuers,
    breaker,
    caller,
    onUnlock,
  }) {
    // The Browser passes on a factory the host injected and leaves it out
    // otherwise, and `composeClient` then builds the base resolver and the
    // base request composition. A factory that is not callable is refused
    // here, before the counting views are built.
    if (resolverFactory !== undefined && typeof resolverFactory !== "function") {
      throw dcaError("bad_config", "a PageLoad resolverFactory is a function");
    }
    if (requestBuilderFactory !== undefined && typeof requestBuilderFactory !== "function") {
      throw dcaError("bad_config", "a PageLoad requestBuilderFactory is a function");
    }
    for (const method of ["put", "candidatesAt", "attempted"]) {
      if (typeof cache?.[method] !== "function") {
        throw dcaError("bad_config", `a PageLoad exact cache needs ${method}`);
      }
    }

    this.#clock = clock;
    this.#network = network;
    this.#issuers = issuers;
    this.#breaker = breaker;
    this.#caller = caller;
    this.#onUnlock = onUnlock ?? (() => undefined);

    // The cache the client owns, seen through a counter. The counter adds
    // nothing else: puts and reads go to the browser's cache, so the other
    // tab reads a key this load puts.
    const counting = {
      /**
       * @param {string} accessGroup
       * @param {string} t
       * @param {any} key
       * @param {object} [context] - which issuer granted it, passed
       *   through untouched for the cache to use
       */
      put: (accessGroup, t, key, context) => cache.put(accessGroup, t, key, context),
      /**
       * @param {string} accessGroup
       * @param {string} t
       * @param {object} [context]
       */
      candidatesAt: (accessGroup, t, context) => {
        this.#trials++;
        return cache.candidatesAt(accessGroup, t, context);
      },
      attempted: (context) => cache.attempted(context),
    };
    const countingChains =
      chainCache === undefined
        ? null
        : {
            put: (accessGroup, t, key, context) => chainCache.put(accessGroup, t, key, context),
            candidates: (accessGroup, t, context) => {
              this.#trials++;
              return chainCache.candidates(accessGroup, t, context);
            },
            ...(typeof chainCache.attempted !== "function"
              ? {}
              : {
                  attempted: (context) => chainCache.attempted(context),
                }),
          };

    // A client with no capability asks for direct only, and says so by
    // leaving the member out: the request builder offers no public half
    // and the resolver has nothing to open a wrapped answer with.
    //
    // The two counting views go in as this load's caches, so the browser's
    // cache and chain cache are what the resolver reads and writes.
    const { resolver, builder, opener } = composeClient({
      cache: /** @type {any} */ (counting),
      ...(countingChains === null
        ? {}
        : { chainCache: /** @type {any} */ (countingChains), periodChainProfile }),
      ...(clientBoundKeyCapability === undefined ? {} : { clientBoundKeyCapability }),
      ...(acceptDirectFallback === undefined ? {} : { acceptDirectFallback }),
      ...(persistRawPeriodKeys === undefined ? {} : { persistRawPeriodKeys }),
      ...(relayExactPeriod === undefined ? {} : { relayExactPeriod }),
      ...(resolverFactory === undefined ? {} : { resolverFactory }),
      ...(requestBuilderFactory === undefined ? {} : { requestBuilderFactory }),
    });
    // PageLoad calls three operations on an injected resolver. Validate that
    // exact surface here; the reusable browser entry needs two more.
    for (const method of ["applyResponse", "resolveDetailed", "contentKeyWithOriginFor"]) {
      if (typeof resolver?.[method] !== "function") {
        throw dcaError("bad_config", `a resolverFactory result needs ${method}`);
      }
    }
    this.#resolver = resolver;
    this.#builder = builder;
    if (
      contentRepresentationOpener !== undefined &&
      typeof contentRepresentationOpener?.open !== "function"
    ) {
      throw dcaError("bad_config", "a PageLoad contentRepresentationOpener needs open");
    }
    // The browser builds one opener and hands it to every load it makes. A
    // load given none takes the opener composed above; this constructor passes
    // no decoders, so that one opens an item naming no content encoding.
    this.#contentRepresentationOpener = contentRepresentationOpener ?? opener;
    this.#delivered = delivery;
    this.#dcaData = new DcaData(this.#delivered.dcaData, {
      publisherOrigin: this.#delivered.publisherOrigin,
    });
  }

  /** The dca-data this load is reading, for a caller that wants to look. */
  get dcaData() {
    return this.#dcaData.toObject();
  }

  /**
   * Retain only plain source metadata from an exact resolver result. The key
   * is deliberately left at the call site: a load report may explain where a
   * key came from, but it must never become another path for key material.
   *
   * @param {'resolve'|'re-resolve-after-unlock'|'open'} operation
   * @param {{ origins: { contentName: string, origin: any }[] }} resolved
   * @returns {void}
   */
  #observeKeyResolution(operation, resolved) {
    this.#keyResolutions.push({
      operation,
      origins: resolved.origins.map(({ contentName, origin }) => ({
        contentName,
        kind: origin.kind,
        ...(typeof origin.accessGroup === "string" ? { accessGroup: origin.accessGroup } : {}),
        ...(typeof origin.t === "string" ? { t: origin.t } : {}),
      })),
    });
  }

  /**
   * What the cache already opens and what still needs an unlock. When the
   * cache covers everything, this load never touches the network.
   *
   * @param {string[]} contentNames
   * @returns {Promise<{ covered: string[], missing: string[] }>}
   */
  async resolve(contentNames) {
    const resolved = await this.#resolver.resolveDetailed(this.#dcaData, contentNames);
    this.#resolved = { covered: resolved.covered, missing: resolved.missing };
    this.#needed = resolved.missing;
    this.#observeKeyResolution("resolve", resolved);
    return this.#resolved;
  }

  /**
   * The issuers to try, in order, starting at the one named. It runs to the
   * end of the list and does not come round again, since the caller stepped
   * past an earlier issuer on purpose.
   *
   * @param {string} [issuerName]
   * @returns {{ issuerName: string, unlockUrl: string }[]}
   */
  #walkFrom(issuerName) {
    if (issuerName === undefined) return this.#issuers;

    const index = this.#issuers.findIndex((issuer) => issuer.issuerName === issuerName);
    if (index === -1) {
      throw dcaError(
        "unknown_issuer",
        `this client is not configured with an issuer "${issuerName}"`,
      );
    }
    return this.#issuers.slice(index);
  }

  /**
   * What the response delivered, read by field presence rather than by what
   * this load asked for, so a client-bound request answered direct still works.
   *
   * A key handed over as a base64url string means direct. A key that arrived
   * as an object came wrapped for this client, and the resolver opens that
   * object; this load does not inspect it. A body that delivered no key at all
   * reports no mode rather than direct.
   *
   * A string settles the reading wherever one appears: this client can read
   * such a key with no transport agreed, so it travelled in the open, whatever
   * else came beside it.
   *
   * @param {any} body
   * @returns {string|null}
   */
  #modeOf(body) {
    /** @type {string|null} */
    let mode = null;
    for (const value of deliveredKeys(body?.keys)) {
      if (typeof value === "string") return "direct";
      if (value !== null && typeof value === "object") mode = "client-bound";
    }
    return mode;
  }

  /**
   * The distinct codes a 200 reported, in the order the body lists them.
   * `errors` is keyed by coordinate and every entry names its own, so one
   * retired keyId across ten coordinates is one code here.
   *
   * An entry naming no code still marks a coordinate that got nothing, and
   * this client can name it only by the field it arrived in.
   *
   * @param {{ error?: unknown }[]} errors
   * @returns {string[]}
   */
  #errorCodesIn(errors) {
    /** @type {Set<string>} */
    const codes = new Set();
    for (const error of errors) {
      const code = error?.error;
      if (typeof code === "string" && code.length > 0) codes.add(code);
    }
    return [...codes];
  }

  /**
   * The one call across the wire, and the walk when it does not answer.
   *
   * @param {{ issuerName?: string, credential?: any }} [options]
   * @returns {Promise<{ ok: boolean, issuerName: string|null, status: number|null, transportMode: string|null, attempts: any[] }>}
   */
  async unlock(options = {}) {
    for (const name of Object.keys(options)) {
      if (!UNLOCK_OPTIONS.includes(name)) {
        throw dcaError("unsupported_option", `unlock has no ${name} yet, and will not pretend to`);
      }
    }

    this.#unlocks++;

    // Everything the cache could not open. Without a resolve first, that
    // covers every item the page declares a record for, so a load that asks
    // for nothing in particular asks for the whole page.
    const needed = this.#needed ?? this.#dcaData.contentNames();

    /** @type {any[]} */
    const attempts = [];

    for (const { issuerName, unlockUrl } of this.#walkFrom(options.issuerName)) {
      /** @type {any} */
      let request;
      try {
        request = this.#builder.build(this.#dcaData, issuerName, needed).toObject();
      } catch (cause) {
        // The page carries no sealed blobs for this issuer, so it has
        // nothing to open. The issuer did not fail here, and the breaker
        // does not count it.
        if (/** @type {any} */ (cause)?.code !== "unknown_issuer") throw cause;
        attempts.push({ issuerName, url: unlockUrl, outcome: "not-on-page", status: null });
        continue;
      }
      const association = new ResponseAssociation(this.#dcaData, issuerName, request);

      if (!this.#breaker.allows(unlockUrl, this.#clock.now())) {
        this.#skipped++;
        attempts.push({ issuerName, url: unlockUrl, outcome: "skipped", status: null });
        continue;
      }

      this.#attempts++;

      /** @type {{ status: number, body: any }} */
      let answer;
      try {
        answer = await this.#network.post(unlockUrl, request, {
          from: this.#caller,
          origin: this.#delivered.publisherOrigin,
          timeout: this.#breaker.timeout,
          ...(options.credential === undefined ? {} : { credential: options.credential }),
        });
      } catch (cause) {
        const code = /** @type {any} */ (cause)?.code;
        // A payload this client should never have built comes from a bug
        // in this client rather than an unreachable issuer. It goes up loud.
        if (!isTransportFailureCode(code)) throw cause;

        this.#breaker.recordFailure(unlockUrl, this.#clock.now());
        attempts.push({ issuerName, url: unlockUrl, outcome: code, status: null });
        continue;
      }

      // A 5xx reports the port breaking rather than the issuer deciding, so
      // this load treats it as a fault like an unreachable call: the breaker
      // counts it, and the walk carries the status on to the next issuer the
      // page names, which may still open what this one could not. Recording
      // it here, before the success below, keeps the 500 from zeroing the
      // failure count it just added to.
      if (answer.status >= 500) {
        this.#breaker.recordFailure(unlockUrl, this.#clock.now());
        attempts.push({ issuerName, url: unlockUrl, outcome: "fault", status: answer.status });
        continue;
      }

      // The issuer answered, so it is up, whatever it said. A breaker
      // that opened on a refusal would drop a working issuer from the
      // walk for saying no.
      this.#breaker.recordSuccess(unlockUrl);

      if (answer.status === 200) {
        // When the selected consumers accepted a key, that 200 answers
        // the walk, and so does a partial grant: malformed or unsupported
        // shapes cannot win merely by occupying a key field.
        //
        // When a 200 handed over nothing and carries `errors` for what
        // was asked for, those errors settle the reading. A code that
        // reports a blob the issuer could not open, a keyId it has let
        // go or a blob that would not unseal, decides nothing about this
        // reader, and the next issuer the page names may still hold the
        // key, so the walk goes on carrying what the wire called it.
        //
        // A code that reports a withholding says the other thing an
        // issuer can say with no key beside it: it opened what arrived
        // and is keeping it. That reports a decision, and walking past
        // it would shop for a yes, the same reason the walk stops at a
        // 401 and a 403, so the walk ends where the issuer decided, with
        // the status it decided at.
        //
        // An unlock that asked for nothing gives the other 200 with no
        // keys in it: a load that resolved the page out of its cache
        // has no coordinate to be told about and gets no `errors`,
        // which is the whole answer and the end of the walk.
        const application = await this.#resolver.applyResponse(
          this.#dcaData,
          issuerName,
          answer.body,
          association,
        );
        if (
          !Number.isInteger(application?.accepted) ||
          application.accepted < 0 ||
          !Array.isArray(application?.issues) ||
          !Array.isArray(application?.errors)
        ) {
          throw dcaError("bad_config", "a resolver applyResponse returns an application report");
        }
        // The grant just applied may hold content keys for this render.
        // A re-resolve over what this walk asked for drops the now-held
        // items from `#needed`, so a second walk does not re-request a
        // key already in hand.
        const resolved = await this.#resolver.resolveDetailed(this.#dcaData, needed, application);
        this.#needed = resolved.missing;
        this.#observeKeyResolution("re-resolve-after-unlock", resolved);
        const reported = this.#errorCodesIn(application.errors);

        if (
          application.accepted > 0 ||
          (needed.length === 0 && reported.length === 0 && application.issues.length === 0)
        ) {
          this.#answeredBy = issuerName;
          this.#transportMode = this.#modeOf(answer.body);
          attempts.push({ issuerName, url: unlockUrl, outcome: "answered", status: 200 });
          this.#onUnlock(true);

          return {
            ok: true,
            issuerName,
            status: 200,
            transportMode: this.#transportMode,
            attempts,
          };
        }

        const local = application.issues
          .map((issue) => issue?.code)
          .filter(
            (code) =>
              typeof code === "string" &&
              code.length > 0 &&
              code !== "unsolicited_coordinate" &&
              code !== "malformed_error",
          );
        const outcome = [...new Set([...reported, ...local])];
        attempts.push({
          issuerName,
          url: unlockUrl,
          outcome: outcome.length > 0 ? outcome.join("+") : "empty",
          status: 200,
        });
        if (!reported.some((code) => WITHHELD.has(code))) continue;

        this.#onUnlock(false);
        return { ok: false, issuerName, status: 200, transportMode: null, attempts };
      }

      const outcome =
        answer.status === 403 ? "refused" : answer.status === 401 ? "denied" : "rejected";
      attempts.push({ issuerName, url: unlockUrl, outcome, status: answer.status });
      this.#onUnlock(false);

      return { ok: false, issuerName, status: answer.status, transportMode: null, attempts };
    }

    // Every issuer tried and none of them opened anything. No content, and
    // nothing left to try: the walk runs a list, so it ends here.
    //
    // The walk reports the last issuer that answered. An issuer that said
    // 200 and could open nothing ends the walk differently than an issuer
    // nobody could reach, and dropping the status here would leave the two
    // looking the same to a caller that reads no further than `status`.
    const answered = attempts.findLast((attempt) => attempt.status !== null);

    this.#onUnlock(false);
    return {
      ok: false,
      issuerName: answered?.issuerName ?? null,
      status: answered?.status ?? null,
      transportMode: null,
      attempts,
    };
  }

  /**
   * @param {string} contentName
   * @returns {Promise<{ bytes: Uint8Array|null, error: string|null }>} a name
   *   with no key returns a typed miss instead of throwing, since the page
   *   shows locked as a state
   */
  async open(contentName) {
    try {
      const record = this.#dcaData.contentDataFor(contentName);
      if (!record) {
        throw dcaError("unknown_content", `the page declares no content item "${contentName}"`);
      }
      const ciphertext = this.#delivered.extract(contentName);
      if (typeof ciphertext !== "string") {
        throw dcaError("unknown_content", `no ciphertext for "${contentName}"`);
      }
      // The aad is the page's carried transcript, so this load passes
      // the record's exact string to `openContent`. It does not rebuild
      // or compare a local transcript: neither readable resource data
      // nor an unverified decoded claim is an independent trust source.
      // The record's other members are held to the same rule by
      // `contentDataFor` above.
      const bytes = await this.#contentRepresentationOpener.open({
        record,
        contentName,
        ciphertext,
        aad: own(record, "aad"),
        resolveKey: async () => {
          const resolved = await this.#resolver.contentKeyWithOriginFor(this.#dcaData, contentName);
          this.#observeKeyResolution("open", {
            origins: [{ contentName, origin: resolved.origin }],
          });
          return resolved.key;
        },
      });
      this.#decrypted.push(contentName);
      return { bytes, error: null };
    } catch (cause) {
      // A typed refusal leaves the article locked, which the page can
      // show. Anything untyped comes from a bug in this client rather
      // than a state, so it goes up loud rather than reading as one more
      // locked item.
      if (!(cause instanceof DcaError)) throw cause;
      this.#misses.push(contentName);
      return { bytes: null, error: cause.code };
    }
  }

  /**
   * Module-private implementation for the fixed A→B teaching probe. The
   * public PageLoad surface has no cross-page key operation.
   *
   * @param {PageLoad} target
   * @returns {Promise<Readonly<{
   *   sourceRenderId: string,
   *   targetRenderId: string,
   *   contentName: 'bodytext',
   *   sourceOrigin: 'held-content-key',
   *   opened: boolean,
   *   error: string|null,
   * }>>}
   */
  async [DIRECT_KEY_MISMATCH_DEMO](target) {
    if (!(target instanceof PageLoad) || target === this) {
      throw dcaError("bad_config", "a direct-key probe needs another PageLoad target");
    }

    const sourceRenderId = this.#dcaData.renderId;
    const targetRenderId = target.#dcaData.renderId;
    if (typeof sourceRenderId !== "string" || typeof targetRenderId !== "string") {
      throw dcaError("bad_page", "a direct-key probe needs source and target renderIds");
    }

    const resolved = await this.#resolver.contentKeyWithOriginFor(
      this.#dcaData,
      DIRECT_KEY_MISMATCH_CONTENT,
    );
    if (resolved.origin.kind !== "held-content-key" || !(resolved.key instanceof Uint8Array)) {
      throw dcaError("bad_config", "a direct-key probe needs this load's held direct content key");
    }

    let opened = false;
    /** @type {string|null} */
    let error = null;
    try {
      const record = target.#dcaData.contentDataFor(DIRECT_KEY_MISMATCH_CONTENT);
      if (!record) {
        throw dcaError(
          "unknown_content",
          `the target page declares no content item "${DIRECT_KEY_MISMATCH_CONTENT}"`,
        );
      }
      const ciphertext = target.#delivered.extract(DIRECT_KEY_MISMATCH_CONTENT);
      if (typeof ciphertext !== "string") {
        throw dcaError(
          "unknown_content",
          `the target page carries no ciphertext for "${DIRECT_KEY_MISMATCH_CONTENT}"`,
        );
      }
      // Do not retain the result. The probe observes only whether the
      // real authenticated decrypt accepted the tuple.
      await openContent(
        resolved.key,
        DIRECT_KEY_MISMATCH_CONTENT,
        own(record, "nonce"),
        ciphertext,
        own(record, "aad"),
      );
      opened = true;
    } catch (cause) {
      if (!(cause instanceof DcaError)) throw cause;
      error = cause.code;
    }

    return Object.freeze({
      sourceRenderId,
      targetRenderId,
      contentName: DIRECT_KEY_MISMATCH_CONTENT,
      sourceOrigin: "held-content-key",
      opened,
      error,
    });
  }

  /**
   * @returns {object} what this one load did
   */
  stats() {
    return {
      unlocks: this.#unlocks,
      attempts: this.#attempts,
      skipped: this.#skipped,
      trials: this.#trials,
      answeredBy: this.#answeredBy,
      transportMode: this.#transportMode,
      resolved: this.#resolved
        ? {
            ...this.#resolved,
            covered: [...this.#resolved.covered],
            missing: [...this.#resolved.missing],
          }
        : null,
      keyResolutions: this.#keyResolutions.map(({ operation, origins }) => ({
        operation,
        origins: origins.map((origin) => ({ ...origin })),
      })),
      decrypted: [...this.#decrypted],
      misses: [...this.#misses],
    };
  }
}

/**
 * The only callable seam for the fixed direct A→B mismatch demonstration.
 * It intentionally accepts already-created source/target loads only; it has
 * no caller-controlled key, ciphertext, tuple or content-name argument.
 *
 * @param {PageLoad} source
 * @param {PageLoad} target
 */
export function probeDirectArticleKeyMismatchForDemo(source, target) {
  if (!(source instanceof PageLoad)) {
    throw dcaError("bad_config", "a direct-key demo probe needs a PageLoad source");
  }
  return source[DIRECT_KEY_MISMATCH_DEMO](target);
}
