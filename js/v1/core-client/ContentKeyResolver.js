// @ts-check
//
// Applying delivered keys and resolving the applicable content key for one
// render. The cache/search/response half of the dissolved `Unsealer`: the
// cache-first trial resolve, response application, the applicable-key lookup,
// and the per-render held content-key grants.
//
// Key material arrives in one of two forms. Direct delivery hands over bytes;
// client-bound hands over `CryptoKey` handles whose material this client cannot
// read. Both travel the same calls: the cache keeps whichever it is
// given, the trial unwrap opens an entry with whichever it holds, and
// `contentKeyFor` answers with whichever came back.
//
// The client and the issuer agree the representation before a leaf is used.
// Direct fallback remains an explicit composition choice. A client-bound
// response must name the mode and method the immutable request offered, and
// every supported leaf must use that representation. Accepting direct content does not implicitly permit raw
// period capabilities to enter a client-bound-only store.
//
// The resolver runs two orders, one for each question. The trial resolve asks
// the cache first, because that is the path the client can repeat: opening an
// article from the cache costs no unlock, so the resolve-before-unlock step
// reaches for cached period material before making any request. The
// applicable-key lookup asks the other way: a content-key grant held for this
// render answers first, cached period material second. Both paths recover the
// same content key, so the order is not visible in what comes out; the held
// grant answers first because it is this render's own, and the resolve step
// already proved the cached path before any unlock.
//
// Do not drop a key after a failed trial. A period key that opens nothing
// here may open the next article.
//
// This resolver holds content keys per renderId, not per resolver. Two loads of
// two pages through one client must not see each other's content keys, and a
// content key is good for one render by construction. Period keys outlive the
// render, so they go to the cache, and content keys never do.
//
// Nothing here consults time: the trial resolves against the period labels the
// page already carries, and a client that thought it knew the time could not
// change which label a string sort reaches first.
//
// Every lookup below is over an object that came off the wire, keyed by a name
// the page or the issuer chose. `map[name]` reaches Object.prototype, so
// 'constructor' resolves to a function rather than missing. The page reads go
// through `DcaData`, which is own-property throughout; the response reads here
// use `own` for the same reason.

import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { DcaError, dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";
import { isAccessGroup, isContentName } from "../core-shared/names.js";
import { isExactPeriodLabel } from "../core-shared/periodLabels.js";
import { DcaData } from "./DcaData.js";
import { attemptContentKeyWrap } from "./contentKeyWrapAttempt.js";
import { exactPeriodCandidateSource } from "./exactPeriodCandidateSource.js";
import { responseSectionEntries } from "./responseSectionEntries.js";
import { ResponseAssociation } from "./ResponseAssociation.js";

/** A delivered contentKey is this wide under every profile. */
const CONTENT_KEY_BYTES = 16;

/**
 * A response opener is injected, and the receiving section states the width.
 * Admit only the key shape that section states before holding or caching it.
 *
 * @param {unknown} key
 * @param {number} keyBytes
 * @returns {key is Uint8Array|CryptoKey}
 */
function isDeliveredKeyOfWidth(key, keyBytes) {
  if (key instanceof Uint8Array) return key.length === keyBytes;
  if (!(key instanceof globalThis.CryptoKey)) return false;
  const algorithm = /** @type {any} */ (key).algorithm;
  return algorithm?.name === "AES-GCM" && algorithm.length === keyBytes * 8;
}

/**
 * Ordinary base entries carry no inner binding marker and use no AAD. Any own
 * marker belongs to a selected extension or to nobody, so base declines an
 * entry that carries one rather than guessing.
 */
const ORDINARY_ENTRY_INTERPRETATION = ({ entry }) =>
  entry !== null && typeof entry === "object" && Object.hasOwn(entry, "bind")
    ? null
    : { aad: undefined };

/**
 * What the client keeps between articles. Duck-typed, so a scenario can hand
 * in something else that answers these three calls.
 *
 * The read and write calls carry who the key came from or who it will be taken from. A cache
 * that keys by accessGroup alone ignores that, and so leaks. A cache that
 * composes with `issuerName` uses it to keep an issuer's grant to the pages
 * that name that issuer.
 *
 * `put` is handed the opened `key` and, in `context.delivery`, the pre-open
 * delivery it came from: `{ value, transport }`, the raw value the response
 * carried for this `t` and the response's transport (undefined under direct). A
 * handle-form cache keeps `key` and ignores the delivery; a sealed-blob cache
 * keeps the delivery and re-opens it on a read, so no handle or key bytes are
 * ever held. Either way the opened `key` argument is unchanged.
 *
 * @typedef {object} Cache
 * @property {(accessGroup: string, t: string, key: any, context?: object) => Promise<void>} put
 * @property {(accessGroup: string, t: string, context?: object) => Promise<any[]>} candidatesAt
 * @property {(context: { lease: object }) => Promise<void>} attempted
 */

/**
 * The distinct retained-chain namespace. Direct chain grants are bytes; the
 * issuer adapter refuses client-bound chain delivery until a byte-free
 * expansion profile exists.
 *
 * @typedef {object} ChainCache
 * @property {(accessGroup: string, cutoffT: string, key: Uint8Array, context?: object) => Promise<void>} put
 * @property {(accessGroup: string, t: string, context?: object) => Promise<(Uint8Array|CryptoKey)[]>} candidates
 * @property {(context: { lease: object }) => Promise<void>} [attempted]
 */

/**
 * The client-bound key capability the resolver is handed for client-bound key
 * delivery. `clientBoundKeyCapability` is a provisional descriptive name for
 * that injected seam.
 *
 * It opens delivered client-bound keys. The client's private half lives inside
 * it and never leaves as bytes; the resolver hands it the issuer's client-bound
 * sealed material and gets back usable, non-extractable handles.
 *
 * @typedef {object} ClientBoundKeyCapability
 * @property {(transport: unknown) => Promise<DeliveredKeyOpener|null>} openDeliveredKeys
 */

/**
 * An opener bound to one response's agreed transport, opening each wrapped value
 * to a handle. A value it cannot read (an undecodable nonce) comes back null,
 * the way an unreadable entry always did.
 *
 * @typedef {object} DeliveredKeyOpener
 * @property {(value: any, usages: KeyUsage[]) => Promise<CryptoKey|null>} open
 */

export class ContentKeyResolver {
  /**
   * Content keys held per publisher and renderId, whether delivered directly
   * or recovered during resolution, so one publisher's render cannot open
   * another publisher's render even when identifiers collide.
   *
   * @type {Map<string|undefined, Map<string, Map<string, Uint8Array|CryptoKey>>>}
   */
  #contentKeys = new Map();

  /** @type {Cache|null} */
  #cache;

  /** @type {ChainCache|null} */
  #chainCache;

  /** @type {{ parametersForResponse: Function, acceptsExactResponseCoordinate: Function, acceptsResponseCoordinate: Function, acceptsPresentedErrorCoordinate?: Function }|null} */
  #periodChainProfile;

  /**
   * The construction profile of the chain bundle, when one is selected: its
   * identifier and the width of one positioned chain state. Null for an
   * exact-only client.
   *
   * @type {{ constructionId: string, stateBytes: number }|null}
   */
  #constructionProfile = null;

  /** @type {{ attempts: Function }[]} */
  #candidateSources;

  /** @type {WeakMap<object, object>} */
  #responseLeases = new WeakMap();

  /** @type {ClientBoundKeyCapability|null} */
  #capability;

  /** @type {boolean} */
  #acceptDirectFallback;

  /** @type {boolean} */
  #persistRawPeriodKeys;

  /** @type {(context: { entry: any, renderId: string, contentName: string, accessGroup: string }) => ({ aad?: Uint8Array }|null)} */
  #entryInterpretation;

  /**
   * @param {object} [config]
   * @param {Cache} [config.cache] - owned by the caller, because it outlives
   *   any one page. With it left out, the client has no cached path: it asks
   *   the issuer for every article and never keeps a period key.
   * @param {ChainCache} [config.chainCache] - retains or expands direct
   *   period-chain grants separately from exact period keys
   * @param {{ parametersForResponse: Function, candidateSourceFor: Function, acceptsExactResponseCoordinate: Function, acceptsResponseCoordinate: Function, acceptsPresentedErrorCoordinate?: Function }} [config.periodChainProfile] -
   *   the optional chain capability used with `chainCache`
   * @param {ClientBoundKeyCapability} [config.clientBoundKeyCapability] - opens
   *   delivered client-bound keys, holding the client's private half inside
   *   it. With it left out, this resolver can apply direct answers only.
   *   (Provisional option name; the settled name is held in the catalogue.)
   * @param {boolean} [config.acceptDirectFallback] - let a client-bound
   *   composition consume a direct response when its deployment selected
   *   that fallback
   * @param {boolean} [config.persistRawPeriodKeys] - separately permit raw
   *   period capabilities from an accepted direct response to enter the
   *   configured caches
   * @param {(context: { entry: any, renderId: string, contentName: string, accessGroup: string }) => ({ aad?: Uint8Array }|null)} [config.entryInterpretation] -
   *   the selected reading of one content-key wrap entry: its wrap AAD, or
   *   null when this composition does not own that entry. This is distinct
   *   from the item's carried content AAD, which PageLoad passes through.
   */
  constructor(config = {}) {
    // The constructor refuses any other option rather than ignoring it, as
    // PeriodKeyCache and keySealing already do. The list has no clock
    // because nothing here consults time.
    for (const name of Object.keys(config)) {
      if (
        name !== "cache" &&
        name !== "chainCache" &&
        name !== "periodChainProfile" &&
        name !== "clientBoundKeyCapability" &&
        name !== "acceptDirectFallback" &&
        name !== "persistRawPeriodKeys" &&
        name !== "entryInterpretation"
      ) {
        throw dcaError(
          "unsupported_option",
          `ContentKeyResolver has no ${name} yet, and will not pretend to`,
        );
      }
    }
    this.#cache = config.cache ?? null;
    this.#chainCache = config.chainCache ?? null;
    if (
      this.#cache &&
      (typeof this.#cache.candidatesAt !== "function" ||
        typeof this.#cache.attempted !== "function")
    ) {
      throw dcaError("bad_config", "an exact cache needs candidatesAt and attempted methods");
    }
    if (
      config.periodChainProfile?.acceptsPresentedErrorCoordinate !== undefined &&
      typeof config.periodChainProfile.acceptsPresentedErrorCoordinate !== "function"
    ) {
      throw dcaError("bad_config", "a periodChainProfile error-coordinate validator is a function");
    }
    if (
      this.#chainCache &&
      (typeof config.periodChainProfile?.parametersForResponse !== "function" ||
        typeof config.periodChainProfile?.candidateSourceFor !== "function" ||
        typeof config.periodChainProfile?.acceptsExactResponseCoordinate !== "function" ||
        typeof config.periodChainProfile?.acceptsResponseCoordinate !== "function")
    ) {
      throw dcaError(
        "bad_config",
        "a chainCache needs an injected periodChainProfile with explicit response geometry, a candidate source, and exact and chain response-coordinate validators",
      );
    }
    if (this.#chainCache) {
      // The bundle names the construction it was composed on, and that
      // construction names the exact profile its leaves have. A bundle
      // whose exact profile is not this client's would file chain state
      // and exact leaves of two different widths in one client, so the
      // disagreement is refused here.
      const construction = config.periodChainProfile.constructionProfile;
      if (typeof construction?.constructionId !== "string" || construction?.stateBytes !== 16) {
        throw dcaError(
          "bad_config",
          "a periodChainProfile names the construction profile it was composed on",
        );
      }
      this.#constructionProfile = construction;
    }
    this.#periodChainProfile = config.periodChainProfile ?? null;
    // The constructor sets the order here: the ordinary exact cache first,
    // then the optional chain namespace. Adding a chain carrier therefore can
    // never suppress an independent exact key that is already usable.
    this.#candidateSources = [];
    if (this.#cache) this.#candidateSources.push(exactPeriodCandidateSource(this.#cache));
    if (this.#chainCache) {
      const source = config.periodChainProfile.candidateSourceFor({ cache: this.#chainCache });
      if (typeof source?.attempts !== "function") {
        throw dcaError("bad_config", "a periodChainProfile candidate source answers attempts");
      }
      this.#candidateSources.push(source);
    }
    this.#capability = config.clientBoundKeyCapability ?? null;
    for (const name of ["acceptDirectFallback", "persistRawPeriodKeys"]) {
      if (config[name] !== undefined && typeof config[name] !== "boolean") {
        throw dcaError("bad_config", `ContentKeyResolver ${name} is boolean`);
      }
    }
    this.#acceptDirectFallback = config.acceptDirectFallback ?? this.#capability === null;
    this.#persistRawPeriodKeys =
      config.persistRawPeriodKeys ?? (this.#capability === null && this.#acceptDirectFallback);
    if (this.#persistRawPeriodKeys && !this.#acceptDirectFallback) {
      throw dcaError("bad_config", "raw period-key persistence requires accepted direct fallback");
    }
    if (
      config.entryInterpretation !== undefined &&
      typeof config.entryInterpretation !== "function"
    ) {
      throw dcaError("bad_config", "ContentKeyResolver entryInterpretation is a function");
    }
    this.#entryInterpretation = config.entryInterpretation ?? ORDINARY_ENTRY_INTERPRETATION;
  }

  /**
   * Ask the one selected interpretation to own or decline an entry. A broken
   * interpretation is refused as configuration rather than counted as a
   * candidate miss.
   *
   * @param {any} entry
   * @param {string} renderId
   * @param {string} contentName
   * @param {string} accessGroup
   * @returns {{ aad?: Uint8Array }|null}
   */
  #interpret(entry, renderId, contentName, accessGroup) {
    const interpreted = this.#entryInterpretation({ entry, renderId, contentName, accessGroup });
    if (interpreted === null) return null;
    if (typeof interpreted !== "object" || Array.isArray(interpreted)) {
      throw dcaError("bad_config", "entryInterpretation returns an AAD description or null");
    }
    if (typeof (/** @type {any} */ (interpreted).then) === "function") {
      throw dcaError("bad_config", "entryInterpretation returns synchronously");
    }
    const aad = own(interpreted, "aad");
    if (aad !== undefined && !(aad instanceof Uint8Array)) {
      throw dcaError("bad_config", "entryInterpretation AAD is bytes when present");
    }
    return { aad };
  }

  /**
   * The page's explicit delivery origin. The cache uses it to keep publishers
   * apart, never to decide access; it is not decoded from resourceJWT.
   *
   * @param {DcaData} dcaData
   * @param {boolean} required - true on a store, false on a read
   * @returns {string|undefined}
   */
  #publisherOf(dcaData, required) {
    const publisher = dcaData.publisherOrigin;
    if (publisher === undefined) {
      if (required)
        throw dcaError("bad_page", "the delivery carries no publisher origin to file keys under");
      return undefined;
    }
    return publisher;
  }

  /** @param {string|undefined} publisher @param {string} renderId @param {string} contentName @param {Uint8Array|CryptoKey} key */
  #holdContentKey(publisher, renderId, contentName, key) {
    let renders = this.#contentKeys.get(publisher);
    if (!renders) {
      renders = new Map();
      this.#contentKeys.set(publisher, renders);
    }
    let held = renders.get(renderId);
    if (!held) {
      held = new Map();
      renders.set(renderId, held);
    }
    held.set(contentName, key);
  }

  /**
   * The applicable key and the branch that supplied it. The key stays in the
   * resolver call; the origin is plain metadata a caller may retain without
   * retaining key material. A cached origin names the page's successful
   * sealed entry, not an inferred cache coordinate.
   *
   * @param {DcaData} dcaData
   * @param {string} contentName
   * @param {object} [application] - the report returned by the response whose
   *   private chain material this article is attempting
   * @returns {Promise<{
   *   key: Uint8Array|CryptoKey|null,
   *   origin: { kind: 'held-content-key'|'cached-period-key'|'cached-period-chain-key'|'missing', accessGroup?: string, t?: string },
   * }>}
   */
  async contentKeyWithOriginFor(dcaData, contentName, application) {
    if (!(dcaData instanceof DcaData)) {
      throw dcaError(
        "bad_config",
        "a content key is unwrapped from a DcaData; construct one first",
      );
    }

    const lease = this.#leaseFor(application);
    const result = await this.#contentKeyWithOriginFor(dcaData, contentName, lease);
    await this.#completeResponseAttempt(application, lease);
    return result;
  }

  /** @param {DcaData} dcaData @param {string} contentName @param {object|undefined} lease */
  async #contentKeyWithOriginFor(dcaData, contentName, lease) {
    // Outer admission runs on every key path, including a held or cached key
    // that needs no issuer request. The version getter admits the complete
    // delivery before renderId or cached coordinates are read.
    dcaData.version;
    const publisher = dcaData.publisherOrigin;
    const renderId = dcaData.renderId;
    if (typeof renderId !== "string") {
      throw dcaError("bad_page", "dca-data carries no renderId");
    }
    const held = this.#contentKeys.get(publisher)?.get(renderId)?.get(contentName);
    if (held) return { key: held, origin: { kind: "held-content-key" } };

    return this.#fromCache(dcaData, contentName, lease);
  }

  /**
   * The existing resolve result with one origin per requested content name.
   * `resolve` deliberately keeps its original shape for callers that use it
   * as the protocol decision boundary.
   *
   * @param {DcaData} dcaData
   * @param {string[]} contentNames
   * @param {object} [application] - the report returned by the response whose
   *   private chain material this article is attempting
   * @returns {Promise<{
   *   covered: string[],
   *   missing: string[],
   *   origins: { contentName: string, origin: { kind: 'held-content-key'|'cached-period-key'|'cached-period-chain-key'|'missing', accessGroup?: string, t?: string } }[],
   * }>}
   */
  async resolveDetailed(dcaData, contentNames, application) {
    if (!(dcaData instanceof DcaData)) {
      throw dcaError("bad_config", "a resolve is read from a DcaData; construct one first");
    }

    /** @type {string[]} */
    const covered = [];
    /** @type {string[]} */
    const missing = [];
    /** @type {{ contentName: string, origin: { kind: 'held-content-key'|'cached-period-key'|'cached-period-chain-key'|'missing', accessGroup?: string, t?: string } }[]} */
    const origins = [];
    const lease = this.#leaseFor(application);
    // Resolve may read renderId before its first per-item lookup, so force
    // the same whole-delivery admission here as the single-item entry.
    dcaData.version;
    const renderId = /** @type {string} */ (dcaData.renderId);

    for (const contentName of contentNames) {
      const { key, origin } = await this.#contentKeyWithOriginFor(dcaData, contentName, lease);
      (key ? covered : missing).push(contentName);
      if (key) this.#holdContentKey(dcaData.publisherOrigin, renderId, contentName, key);
      origins.push({ contentName, origin });
    }

    await this.#completeResponseAttempt(application, lease);
    return { covered, missing, origins };
  }

  /** @param {any} application @returns {object|undefined} */
  #leaseFor(application) {
    return application !== null && typeof application === "object"
      ? this.#responseLeases.get(application)
      : undefined;
  }

  /** Complete one response's pending grants after its article attempt. */
  async #completeResponseAttempt(application, lease) {
    if (lease === undefined) return;
    await this.#cache?.attempted({ lease });
    if (typeof this.#chainCache?.attempted === "function")
      await this.#chainCache.attempted({ lease });
    this.#responseLeases.delete(application);
  }

  /**
   * What the held and cached material already opens and what is left to ask
   * for. An item whose content key this render already holds counts as
   * covered without a cache read; otherwise the resolver tries the cached
   * period keys. Each either unwraps an entry or does not, and no cheaper
   * test exists.
   * The two halves run in the same order `contentKeyFor` uses, so a re-resolve
   * after a grant that delivered content keys reports them covered rather than
   * sending the client back to the issuer.
   *
   * A caller that just applied a response passes the application report
   * `applyResponse` returned as the optional third argument, and this render
   * then tries that one response's private chain material before the attempt
   * completes. An omitted report selects no pending grant.
   *
   * @param {DcaData} dcaData
   * @param {string[]} contentNames
   * @param {object[]} responseAttempt - optional response application report;
   *   rest form preserves the established two-argument API arity
   * @returns {Promise<{ covered: string[], missing: string[] }>}
   */
  async resolve(dcaData, contentNames, ...responseAttempt) {
    const { covered, missing } = await this.resolveDetailed(
      dcaData,
      contentNames,
      responseAttempt[0],
    );
    return { covered, missing };
  }

  /**
   * Preflight once, then let each selected section consumer validate and file
   * its own entries. Wire-level misses become local issues; configuration,
   * storage, and programming exceptions are never caught here.
   *
   * The association snapshots the exact request before transport. Base and
   * selected-extension consumers admit coordinates through that one snapshot.
   *
   * @param {DcaData} dcaData
   * @param {string} issuerName
   * @param {object} response
   * @param {ResponseAssociation} association
   * @returns {Promise<{ accepted: number, errors: object[], issues: { section?: string, code: 'malformed_key'|'unsupported_section'|'invalid_transport'|'unsolicited_coordinate'|'malformed_error' }[] }>}
   */
  async applyResponse(dcaData, issuerName, response, association) {
    if (!(dcaData instanceof DcaData)) {
      throw dcaError("bad_config", "a response is applied to a DcaData; construct one first");
    }
    if (
      !(association instanceof ResponseAssociation) ||
      !association.matches(dcaData, issuerName)
    ) {
      throw dcaError("bad_config", "a response needs its exact page and issuer association");
    }
    const renderId = dcaData.renderId;
    if (typeof renderId !== "string") {
      throw dcaError("bad_page", "dca-data carries no renderId");
    }

    const keys = own(response, "keys");
    if (keys !== undefined && (keys === null || typeof keys !== "object" || Array.isArray(keys))) {
      return this.#application(0, [{ code: "malformed_key" }]);
    }
    const sections = {
      contentKeys: responseSectionEntries(keys, "contentKeys"),
      periodKeys: responseSectionEntries(keys, "periodKeys"),
      periodChainKeys: responseSectionEntries(keys, "periodChainKeys"),
    };
    const issues = [];
    const transport = own(response, "transport");
    if (transport !== undefined && sections.periodChainKeys.present) {
      this.#issueOnce(issues, "periodChainKeys", "unsupported_section");
      sections.periodChainKeys = { present: false, entries: [], malformed: 0 };
    }
    /** @type {Map<string, Map<string, boolean>>} */
    const exactAdmissions = new Map();
    sections.contentKeys.entries = sections.contentKeys.entries.filter(
      ({ path: [contentName] }) => {
        if (association.presentsContent(contentName)) return true;
        issues.push({ section: "contentKeys", code: "unsolicited_coordinate" });
        return false;
      },
    );
    sections.periodKeys.entries = sections.periodKeys.entries.filter(
      ({ path: [accessGroup, t] }) => {
        if (!isAccessGroup(accessGroup) || !isExactPeriodLabel(t)) {
          issues.push({ section: "periodKeys", code: "unsolicited_coordinate" });
          return false;
        }
        let extensionAdmission;
        if (typeof this.#periodChainProfile?.acceptsExactResponseCoordinate === "function") {
          extensionAdmission = this.#periodChainProfile.acceptsExactResponseCoordinate(
            accessGroup,
            t,
            association.request,
          );
          if (typeof extensionAdmission !== "boolean") {
            throw dcaError(
              "bad_config",
              "a periodChainProfile exact-response validator answers boolean",
            );
          }
          let familyAdmissions = exactAdmissions.get(accessGroup);
          if (familyAdmissions === undefined) {
            familyAdmissions = new Map();
            exactAdmissions.set(accessGroup, familyAdmissions);
          }
          familyAdmissions.set(t, extensionAdmission);
        }
        if (association.presentsExact(accessGroup, t) || extensionAdmission === true) return true;
        issues.push({ section: "periodKeys", code: "unsolicited_coordinate" });
        return false;
      },
    );
    const chainLease = {};
    /** @type {Map<string, { kind: 'cache' }|null>} */
    const periodConsumers = new Map();
    if (this.#cache) {
      for (const {
        path: [accessGroup],
      } of sections.periodKeys.entries) {
        if (periodConsumers.has(accessGroup)) continue;
        periodConsumers.set(accessGroup, { kind: "cache" });
      }
    }

    const supportedEntries = [
      ...sections.contentKeys.entries,
      ...sections.periodKeys.entries.filter(({ path: [accessGroup] }) =>
        periodConsumers.get(accessGroup),
      ),
    ];
    const hasDirectLeaf = supportedEntries.some(({ value }) => typeof value === "string");
    const hasWrappedLeaf = supportedEntries.some(({ value }) => this.#isWrapped(value));

    // Representation is response-wide. Refuse it before an opener, cache,
    // or held-content write when supported sections mix representations or
    // when direct leaves appear below a client-bound transport marker.
    if ((hasDirectLeaf && hasWrappedLeaf) || (transport !== undefined && hasDirectLeaf)) {
      issues.push({ code: "invalid_transport" });
      return this.#application(0, issues);
    }

    const wrappedNeedsOpener = hasWrappedLeaf;

    /** @type {DeliveredKeyOpener|null} */
    let opener = null;
    if (
      wrappedNeedsOpener &&
      (transport === null ||
        typeof transport !== "object" ||
        Array.isArray(transport) ||
        own(transport, "mode") !== "client-bound" ||
        typeof own(transport, "method") !== "string" ||
        own(transport, "method") !== association.offeredClientBoundMethod)
    ) {
      issues.push({ code: "invalid_transport" });
      return this.#application(0, issues);
    }
    if (wrappedNeedsOpener && !this.#capability) {
      // Preserve the established refusal for a client that receives
      // ordinary wrapped content or period keys without selecting the
      // client-bound capability. An unsupported chain section is not in
      // this preflight set and remains a local section issue below.
      throw dcaError(
        "bad_response",
        "this answer is wrapped for a client, and this client has no client-bound capability",
      );
    }
    if (wrappedNeedsOpener) {
      try {
        opener = await this.#capability.openDeliveredKeys(transport);
      } catch (cause) {
        if (cause instanceof DcaError && cause.code === "bad_response") {
          issues.push({ code: "invalid_transport" });
          return this.#application(0, issues);
        }
        throw cause;
      }
      if (opener === null) {
        issues.push({ code: "invalid_transport" });
        return this.#application(0, issues);
      }
      if (typeof opener?.open !== "function") {
        throw dcaError("bad_config", "a client-bound capability returns an opener with open");
      }
    }

    let accepted = 0;
    const exactAccepted = await this.#consumePeriodKeys(
      dcaData,
      issuerName,
      response,
      sections.periodKeys,
      periodConsumers,
      opener,
      issues,
      exactAdmissions,
      chainLease,
    );
    accepted += exactAccepted;
    const chainAccepted = await this.#consumePeriodChainKeys(
      dcaData,
      issuerName,
      response,
      sections.periodChainKeys,
      chainLease,
      issues,
      association.request,
    );
    accepted += chainAccepted;
    accepted += await this.#consumeContentKeys(
      dcaData.publisherOrigin,
      renderId,
      sections.contentKeys,
      opener,
      issues,
    );
    const errors = this.#admittedErrors(response, sections, association, issues);
    const application = this.#application(accepted, issues, errors);
    if (exactAccepted > 0 || chainAccepted > 0) this.#responseLeases.set(application, chainLease);
    return application;
  }

  /** @param {number} accepted @param {any[]} issues @param {object[]} errors */
  #application(accepted, issues, errors = []) {
    return { accepted, errors: Object.freeze(errors), issues };
  }

  /** @param {string} coordinate @param {ResponseAssociation} association */
  #errorAdmission(coordinate, association) {
    const separator = coordinate.indexOf("|");
    if (separator === -1) {
      if (!isContentName(coordinate)) return "malformed_error";
      return association.presentsContent(coordinate) ? null : "unsolicited_coordinate";
    }
    if (separator <= 0 || separator !== coordinate.lastIndexOf("|")) return "malformed_error";
    const accessGroup = coordinate.slice(0, separator);
    const t = coordinate.slice(separator + 1);
    if (!isAccessGroup(accessGroup) || !isExactPeriodLabel(t)) return "malformed_error";
    if (association.presentsExact(accessGroup, t)) return null;
    if (typeof this.#periodChainProfile?.acceptsPresentedErrorCoordinate === "function") {
      const admitted = this.#periodChainProfile.acceptsPresentedErrorCoordinate(
        accessGroup,
        t,
        association.request,
      );
      if (typeof admitted !== "boolean") {
        throw dcaError(
          "bad_config",
          "a periodChainProfile error-coordinate validator answers boolean",
        );
      }
      if (admitted) return null;
    }
    return association.presentsChain(accessGroup, t) ? "malformed_error" : "unsolicited_coordinate";
  }

  /** @param {any} response @param {any} sections @param {ResponseAssociation} association @param {any[]} issues */
  #admittedErrors(response, sections, association, issues) {
    const source = own(response, "errors");
    if (source === undefined) return [];
    if (source === null || typeof source !== "object" || Array.isArray(source)) {
      issues.push({ code: "malformed_error" });
      return [];
    }
    if (Object.keys(source).length === 0) {
      issues.push({ code: "malformed_error" });
      return [];
    }
    const admitted = [];
    for (const coordinate of Object.keys(source)) {
      const coordinateIssue = this.#errorAdmission(coordinate, association);
      if (coordinateIssue !== null) {
        issues.push({ section: "errors", code: coordinateIssue });
        continue;
      }
      const entry = own(source, coordinate);
      const error = own(entry, "error");
      const message = own(entry, "message");
      if (
        entry === null ||
        typeof entry !== "object" ||
        Array.isArray(entry) ||
        typeof error !== "string" ||
        error.length === 0 ||
        (message !== undefined && typeof message !== "string") ||
        this.#responseOccupiesErrorCoordinate(coordinate, sections, association)
      ) {
        issues.push({ section: "errors", code: "malformed_error" });
        continue;
      }
      admitted.push(
        Object.freeze({ coordinate, error, ...(message === undefined ? {} : { message }) }),
      );
    }
    return admitted;
  }

  /** Compare response coordinates as structured identities, never by joining fields. */
  #responseOccupiesErrorCoordinate(coordinate, sections, association) {
    const separator = coordinate.indexOf("|");
    if (separator === -1) {
      return sections.contentKeys.entries.some(
        ({ path: [contentName] }) => contentName === coordinate,
      );
    }
    const accessGroup = coordinate.slice(0, separator);
    const t = coordinate.slice(separator + 1);
    if (
      sections.periodKeys.entries.some(
        ({ path: [group, label] }) => group === accessGroup && label === t,
      )
    )
      return true;
    return sections.periodChainKeys.entries.some(
      ({ path: [group, label] }) =>
        group === accessGroup &&
        label === t &&
        this.#errorAdmission(coordinate, association) === null,
    );
  }

  /** @param {any[]} issues @param {string} section @param {string} code */
  #issueOnce(issues, section, code) {
    if (!issues.some((issue) => issue.section === section && issue.code === code)) {
      issues.push({ section, code });
    }
  }

  /** @param {any[]} issues @param {string} section @param {number} count */
  #malformed(issues, section, count) {
    for (let i = 0; i < count; i++) issues.push({ section, code: "malformed_key" });
  }

  /** @param {string} t @param {object} parameters */
  #acceptsChainCoordinate(t, parameters) {
    const accepted = this.#periodChainProfile.acceptsResponseCoordinate(t, parameters);
    if (typeof accepted !== "boolean") {
      throw dcaError(
        "bad_config",
        "a periodChainProfile response-coordinate validator answers boolean",
      );
    }
    return accepted;
  }

  /**
   * @param {any} value
   * @param {DeliveredKeyOpener|null} opener
   * @param {KeyUsage[]} usages
   * @param {boolean} directAllowed
   * @param {number} keyBytes - the width this section's values have under the
   *   profile this client resolves on. A value of another width is malformed
   *   here: it is not a key of this route, and admitting it would file
   *   material the wrap attempt could not use.
   * @returns {Promise<{ key: Uint8Array|CryptoKey|null, issue: 'malformed_key'|'unsupported_section'|null }>}
   */
  async #deliveredKey(value, opener, usages, directAllowed, keyBytes) {
    if (typeof value === "string") {
      if (!directAllowed) return { key: null, issue: "unsupported_section" };
      // A direct leaf is admitted on its spelling as well as its width:
      // section 2.2 admits canonical unpadded base64url, and a leaf the
      // response spelled another way is malformed however it decodes.
      const key = binaryStringBytes(value);
      return key !== null && key.length === keyBytes
        ? { key, issue: null }
        : { key: null, issue: "malformed_key" };
    }
    if (!this.#isWrapped(value)) return { key: null, issue: "malformed_key" };
    if (opener === null) return { key: null, issue: "unsupported_section" };

    let key;
    try {
      key = await opener.open(value, usages);
    } catch (cause) {
      // The selected client-bound profiles use this one typed failure for
      // a wrapped wire entry that authentication or decoding could not
      // open. It is one candidate miss; every other exception keeps its
      // identity as configuration, storage, or programming failure.
      if (cause instanceof DcaError && cause.code === "unwrap_failed") {
        return { key: null, issue: "malformed_key" };
      }
      throw cause;
    }
    return key !== null && isDeliveredKeyOfWidth(key, keyBytes)
      ? { key, issue: null }
      : { key: null, issue: "malformed_key" };
  }

  /**
   * @param {DcaData} dcaData
   * @param {string} issuerName
   * @param {any} response
   * @param {{ present: boolean, entries: any[], malformed: number }} section
   * @param {Map<string, { kind: 'cache' }|null>} consumers
   * @param {DeliveredKeyOpener|null} opener
   * @param {any[]} issues
   * @param {Map<string, Map<string, boolean>>} exactAdmissions - selected-extension
   *   decisions already made before transport opening
   * @param {object} lease - the response's immediate resolution scope
   */
  async #consumePeriodKeys(
    dcaData,
    issuerName,
    response,
    section,
    consumers,
    opener,
    issues,
    exactAdmissions,
    lease,
  ) {
    if (!section.present) return 0;
    if (!this.#cache && !this.#chainCache) {
      this.#issueOnce(issues, "periodKeys", "unsupported_section");
      return 0;
    }
    this.#malformed(issues, "periodKeys", section.malformed);

    let accepted = 0;
    for (const {
      path: [accessGroup, t],
      value,
    } of section.entries) {
      const consumer = consumers.get(accessGroup) ?? null;
      if (consumer === null) {
        this.#issueOnce(issues, "periodKeys", "unsupported_section");
        continue;
      }
      if (exactAdmissions.get(accessGroup)?.get(t) === false) {
        issues.push({ section: "periodKeys", code: "malformed_key" });
        continue;
      }
      const publisher = this.#publisherOf(dcaData, true);
      const opened = await this.#deliveredKey(
        value,
        opener,
        ["unwrapKey"],
        this.#acceptDirectFallback && this.#persistRawPeriodKeys,
        16,
      );
      if (opened.issue) {
        if (opened.issue === "malformed_key")
          issues.push({ section: "periodKeys", code: opened.issue });
        else this.#issueOnce(issues, "periodKeys", opened.issue);
        continue;
      }
      const delivery = { value, transport: own(response, "transport") };
      await this.#cache.put(accessGroup, t, opened.key, {
        publisher,
        issuerName,
        delivery,
        lease,
      });
      accepted++;
    }
    return accepted;
  }

  /**
   * @param {DcaData} dcaData
   * @param {string} issuerName
   * @param {object} response
   * @param {{ present: boolean, entries: any[], malformed: number }} section
   * @param {object} lease
   * @param {any[]} issues
   * @param {object|undefined} request - the request document this response
   *   answers, when the caller held it
   */
  async #consumePeriodChainKeys(dcaData, issuerName, response, section, lease, issues, request) {
    if (!section.present) return 0;
    if (!this.#chainCache || !this.#acceptDirectFallback || !this.#persistRawPeriodKeys) {
      this.#issueOnce(issues, "periodChainKeys", "unsupported_section");
      return 0;
    }
    if (own(response, "transport") !== undefined) {
      this.#issueOnce(issues, "periodChainKeys", "unsupported_section");
      return 0;
    }
    this.#malformed(issues, "periodChainKeys", section.malformed);

    let accepted = 0;
    for (const {
      path: [accessGroup, cutoffT],
      value,
    } of section.entries) {
      const chainParameters =
        this.#periodChainProfile?.parametersForResponse(
          response,
          dcaData,
          accessGroup,
          request,
          cutoffT,
        ) ?? null;
      if (chainParameters === null) {
        issues.push({ section: "periodChainKeys", code: "malformed_key" });
        continue;
      }
      if (!this.#acceptsChainCoordinate(cutoffT, chainParameters)) {
        issues.push({ section: "periodChainKeys", code: "malformed_key" });
        continue;
      }
      // A wrapped chain value is unsupported by this profile and never
      // reaches the response opener with an empty usage set.
      if (this.#isWrapped(value)) {
        this.#issueOnce(issues, "periodChainKeys", "unsupported_section");
        continue;
      }
      const opened = await this.#deliveredKey(
        value,
        null,
        [],
        true,
        /** @type {any} */ (this.#constructionProfile).stateBytes,
      );
      if (opened.issue) {
        if (opened.issue === "malformed_key")
          issues.push({ section: "periodChainKeys", code: opened.issue });
        else this.#issueOnce(issues, "periodChainKeys", opened.issue);
        continue;
      }
      const publisher = this.#publisherOf(dcaData, true);
      await this.#chainCache.put(accessGroup, cutoffT, opened.key, {
        publisher,
        issuerName,
        lease,
        ...chainParameters,
      });
      accepted++;
    }
    return accepted;
  }

  /**
   * @param {string|undefined} publisher
   * @param {string} renderId
   * @param {{ present: boolean, entries: any[], malformed: number }} section
   * @param {DeliveredKeyOpener|null} opener
   * @param {any[]} issues
   */
  async #consumeContentKeys(publisher, renderId, section, opener, issues) {
    if (!section.present) return 0;
    this.#malformed(issues, "contentKeys", section.malformed);

    let accepted = 0;
    for (const {
      path: [contentName],
      value,
    } of section.entries) {
      // A contentKey is always the canonical 16-byte delivered value;
      // this section does not vary with route representation.
      const opened = await this.#deliveredKey(
        value,
        opener,
        ["decrypt"],
        this.#acceptDirectFallback,
        CONTENT_KEY_BYTES,
      );
      if (opened.issue) {
        if (opened.issue === "malformed_key")
          issues.push({ section: "contentKeys", code: opened.issue });
        else this.#issueOnce(issues, "contentKeys", opened.issue);
        continue;
      }
      this.#holdContentKey(publisher, renderId, contentName, opened.key);
      accepted++;
    }
    return accepted;
  }

  /**
   * Whether a value in a response is one key wrapped for this client: an
   * object carrying the wrapped blob under `key`. A `nonce` beside it is the
   * ECDH profile's field; the RSA profile carries the key alone, so the
   * resolver reads only the member both share and leaves each profile to read
   * its own. Direct hands over a base64url string in the same position. This
   * shape classification is only the response-wide preflight input; whether
   * wrapped is allowed follows from the association's immutable request offer.
   *
   * @param {any} value
   * @returns {boolean}
   */
  #isWrapped(value) {
    return value !== null && typeof value === "object" && typeof own(value, "key") === "string";
  }

  /**
   * The trial unwrap: every cached period key of every accessGroup the item
   * is wrapped under, newest `t` first, against every entry the page ships
   * for that group. AES-GCM decides - a wrong key is a tag failure, never
   * silent garbage - and the first success wins.
   *
   * Null when nothing in the cache opens it, which is the ordinary miss that
   * sends the client to an issuer.
   *
   * The cache is told which issuers this page entrusts the group to. A cache
   * may ignore that list, and the flat cache does, which causes the whole
   * hazard. A cache keyed by issuer needs the list to know whose keys may be
   * tried here.
   *
   * @param {DcaData} dcaData
   * @param {string} contentName
   * @param {object|undefined} lease
   * @returns {Promise<{
   *   key: Uint8Array|CryptoKey|null,
   *   origin: { kind: 'cached-period-key'|'cached-period-chain-key'|'missing', accessGroup?: string, t?: string },
   * }>}
   */
  async #fromCache(dcaData, contentName, lease) {
    if (this.#candidateSources.length === 0) return { key: null, origin: { kind: "missing" } };

    const publisher = this.#publisherOf(dcaData, false);
    const renderId = /** @type {string} */ (dcaData.renderId);
    for (const accessGroup of dcaData.accessGroupsFor(contentName)) {
      const entries = dcaData.sealedEntriesFor(contentName, accessGroup);
      if (entries.length === 0) continue;

      const issuerNames = dcaData.issuerNamesFor(accessGroup);
      // Each route reads under the issuers the publisher sealed that route for.
      // One list for both would let a chain-only issuer lose its own chain grant
      // under an issuer-keyed chain cache, and would read a base exact key under
      // the issuer list the chain route supplied.
      const chainIssuerNames = dcaData.chainIssuerNamesFor(accessGroup);
      // Exact-key trials are finite per authored access group. With one budget
      // across groups, an early group could spend it and leave a later
      // alternative route unattempted.
      const exactBudget = { remaining: 64 };
      // The profile is part of what a candidate source asks its cache
      // for, so every candidate offered below comes out of this client's
      // own profile partition. One walk therefore stays inside one
      // profile by construction: there is no candidate of the other
      // width to reach, and no attempt is retried under another profile.
      const context = {
        dcaData,
        contentName,
        accessGroup,
        entries,
        publisher,
        issuerNames,
        chainIssuerNames,
        lease,
        budget: exactBudget,
      };
      for (const source of this.#candidateSources) {
        for await (const { entry, periodKey, origin } of source.attempts(context)) {
          const interpretation = this.#interpret(entry, renderId, contentName, accessGroup);
          if (interpretation === null) continue;
          const key = await attemptContentKeyWrap(entry, periodKey, interpretation.aad);
          if (key !== null) return { key, origin };
        }
      }
    }

    return { key: null, origin: { kind: "missing" } };
  }

  /**
   * The key material for one item, or null when nothing opens it.
   *
   * This call tries the content-key grant the issuer handed back for this
   * render first and falls back to the cached period material. The caller
   * cannot tell raw bytes from an opaque handle, so client-bound key delivery
   * arrives without changing this call.
   *
   * @param {DcaData} dcaData
   * @param {string} contentName
   * @param {object[]} responseAttempt - optional response application report;
   *   rest form preserves the established two-argument API arity
   * @returns {Promise<Uint8Array|CryptoKey|null>}
   */
  async contentKeyFor(dcaData, contentName, ...responseAttempt) {
    return (await this.contentKeyWithOriginFor(dcaData, contentName, responseAttempt[0])).key;
  }
}
