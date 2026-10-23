// @ts-check
import { ReaderContext } from "./ReaderContext.js";
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
// The client and the issuer agree the representation before a key entry is used.
// Direct fallback remains an explicit composition choice. A client-bound
// response must name the mode and method the immutable request offered, and
// every supported key entry must use that representation. Accepting content keys
// under direct fallback does not implicitly permit raw period capabilities to enter
// a client-bound-only store.
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
import { base64urlEncode } from "../core-shared/codec.js";
import { contentKeyWrapNonce } from "../core-shared/contentKeyWrapNonce.js";
import { DcaError, dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";
import { isAccessGroup, isContentName } from "../core-shared/names.js";
import { isPeriodKeyLabel } from "../core-shared/periodLabels.js";
import { DcaData } from "./DcaData.js";
import { attemptContentKeyWrap } from "./contentKeyWrapAttempt.js";
import { periodKeyCandidateSource } from "./periodKeyCandidateSource.js";
import { responseSectionEntries } from "./responseSectionEntries.js";
import { ResponseAssociation } from "./ResponseAssociation.js";

/** A delivered contentKey is this wide under every profile. */
const CONTENT_KEY_BYTES = 16;

/** @param {Uint8Array|CryptoKey} left @param {Uint8Array|CryptoKey} right */
function sameContentKey(left, right) {
  if (left === right) return true;
  return (
    left instanceof Uint8Array &&
    right instanceof Uint8Array &&
    left.length === right.length &&
    left.every((byte, index) => byte === right[index])
  );
}

/** The two reasons period keys Section 5.6 gives a not-delivered family entry. */
const NOT_DELIVERED_REASONS = Object.freeze(["denied", "unavailable"]);

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Core Section 7.1 error-object shape: a nonempty string `error` and an
 * optional string `message`.
 * @param {unknown} entry
 */
function isErrorObject(entry) {
  if (!isRecord(entry)) return false;
  const error = own(entry, "error");
  const message = own(entry, "message");
  return (
    typeof error === "string" &&
    error.length > 0 &&
    (message === undefined || typeof message === "string")
  );
}

/**
 * Whether a collection is an array holding a record whose own `accessGroup`
 * is `accessGroup`. A request presents a family this way, and a response
 * section carries a key entry for it this way, before any label or key in the
 * record is judged.
 *
 * @param {unknown} collection @param {string} accessGroup
 */
function namesFamily(collection, accessGroup) {
  return (
    Array.isArray(collection) &&
    collection.some((record) => isRecord(record) && own(record, "accessGroup") === accessGroup)
  );
}

/**
 * Descriptor and status records by identity (data format Section 2.3): the
 * last whole record for each string `member` value, in first-appearance
 * order. `stray` counts the elements that name no identity: a non-record, or
 * a record whose `member` is not an own string.
 *
 * @param {unknown[]} collection @param {string} member
 * @returns {{ records: Map<string, Record<string, unknown>>, stray: number }}
 */
function lastWholeRecords(collection, member) {
  /** @type {Map<string, Record<string, unknown>>} */
  const records = new Map();
  let stray = 0;
  for (const record of collection) {
    const name = own(record, member);
    if (!isRecord(record) || typeof name !== "string") {
      stray++;
      continue;
    }
    records.set(name, record);
  }
  return { records, stray };
}

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
 *
 * @type {(context: { entry: any }) => ({ aad?: Uint8Array }|null)}
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
 * Synchronous collaborators are supported: these results are awaited.
 * @typedef {object} Cache
 * @property {(accessGroup: string, t: string, key: Uint8Array|CryptoKey, context?: object) => void|Promise<void>} put
 * @property {(accessGroup: string, t: string, context?: object) => (Uint8Array|CryptoKey)[]|Promise<(Uint8Array|CryptoKey)[]>} candidatesAt
 * @property {(context: { lease: object }) => void|Promise<void>} attempted
 */

/**
 * The distinct retained-chain namespace. A direct chain grant is bytes, and a
 * client-bound chain grant opens to the same 16-octet chain key. Unlike
 * content keys and period keys, a chain key must be usable by Step and Leaf.
 *
 * @typedef {object} ChainCache
 * @property {(accessGroup: string, cutoffT: string, key: Uint8Array, context?: object) => void|Promise<void>} put
 * @property {(accessGroup: string, t: string, context?: object) => (Uint8Array|CryptoKey)[]|Promise<(Uint8Array|CryptoKey)[]>} candidates
 * @property {(accessGroup: string, t: string, context?: object) => Uint8Array[]|Promise<Uint8Array[]>} [periodCandidates] - ordinary derived-period view
 * @property {(context: { lease: object }) => void|Promise<void>} [promote] - joinable promotion without releasing private material
 * @property {(context: { lease: object }) => void|Promise<void>} [attempted]
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
 * @property {(transport: unknown) => DeliveredKeyOpener|null|Promise<DeliveredKeyOpener|null>} openDeliveredKeys
 * @property {() => void} [assertCanOpenChainKeys] - synchronous profile-owned
 *   admission for chain-capable clients; required when chainCache is selected
 */

/**
 * An opener bound to one response's agreed transport, opening each wrapped value
 * to a handle. A value it cannot read (an undecodable nonce) comes back null,
 * the way an unreadable entry always did.
 *
 * @typedef {object} DeliveredKeyOpener
 * @property {(value: any, usages: KeyUsage[], keyKind: 'contentKey'|'periodKey'|'chainKey') => CryptoKey|Uint8Array|null|Promise<CryptoKey|Uint8Array|null>} open
 */

/**
 * The injected chain-key capability. The constructor checks its members
 * before a chainCache uses it.
 *
 * @typedef {object} ChainKeyProfile
 * @property {{ name: string, constructionId: string, chainKeyBytes: number }} [constructionProfile]
 * @property {Function} parametersForResponse
 * @property {Function} [periodCacheFor] - geometry-free ordinary derived-period view
 * @property {Function} candidateSourceFor
 * @property {Function} acceptsPeriodKeyResponseCoordinate
 * @property {Function} acceptsResponseCoordinate
 * @property {Function} [acceptsPresentedErrorCoordinate]
 */

/**
 * @typedef {{ section?: string, code: 'malformed_key'|'unsupported_section'|'invalid_transport'|'unsolicited_coordinate'|'malformed_error'|'malformed_response' }} ResponseIssue
 */

/**
 * A retirement a response-section consumer reports for one of its own
 * coordinates: `error` is `"key_retired"` and every other member is a string
 * naming the coordinate. The application carries it with `consumer`, the
 * consumer's member name; it never has a core `coordinate` string.
 *
 * @typedef {{ error: 'key_retired', [member: string]: string }} ConsumerErrorRecord
 */

/**
 * The application's `errors`: core entries, then consumer records.
 *
 * @typedef {Readonly<{ coordinate: string, error: string, message?: string }>
 *   | Readonly<ConsumerErrorRecord & { consumer: string }>} ApplicationError
 */

/**
 * One response section as `responseSectionEntries` walks it. An admitted
 * chain entry also carries the geometry its profile read for it.
 *
 * @typedef {{ present: boolean, entries: { path: string[], value: any, parameters?: object }[], malformed: number }} ResponseSection
 */

/** @typedef {{ contentKeys: ResponseSection, periodKeys: ResponseSection, chainKeys: ResponseSection }} ResponseSections */

/**
 * What a resolver reports about where an item key came from. A recovered key
 * carries the source's own descriptive members beside its kind.
 *
 * @typedef {{ kind: 'held-content-key'|'cached-period-key'|'cached-chain-key'|'recovered-content-key'|'missing', accessGroup?: string, t?: string, [detail: string]: unknown }} KeyOrigin
 */

/**
 * What a recovery source reads for one item. `check` throws once the reader
 * context that started this call has been retired; a source calls it after
 * every await before it derives, files or yields anything.
 *
 * @typedef {object} RecoveryContext
 * @property {DcaData} dcaData
 * @property {string} contentName
 * @property {string|undefined} publisher - the page's host-supplied origin
 * @property {string} renderId
 * @property {object|undefined} lease - the private lease of the response
 *   this call attempts, when the caller passed its application report
 * @property {() => void} check
 */

/**
 * A selected extension's item-key recovery. It yields candidate content keys
 * for one item, never period keys; the resolver authenticates each with the
 * caller's predicate, spends at most `maxTrialsPerItem` trials of one item in
 * one call, holds the first that opens and closes the walk. Recovery runs only
 * on authenticated paths. A source that retains material reaches completion
 * through `promote` and `attempted`, and reset through `clearReaderContext`.
 *
 * @typedef {object} RecoverySource
 * @property {(context: RecoveryContext) => AsyncIterable<{ contentKey: Uint8Array, origin?: Record<string, unknown> }>} candidates
 * @property {number} maxTrialsPerItem
 * @property {(context: { lease: object }) => Promise<void>} [promote]
 * @property {(context: { lease: object }) => Promise<void>} [attempted]
 * @property {() => void|Promise<void>} [clearReaderContext]
 */

/**
 * What a response-section consumer receives with its member. `openKey` opens
 * one key value under this response's agreed representation: a direct string
 * when this composition admits direct keys of that use, or a wrapped value
 * through the client-bound opener the request offered, refusing a value of the
 * wrong width. `raw: true` asks for derivation bytes rather than a key handle
 * and follows the raw retained-capability rule chain keys use. `lease` is this
 * response's private lease; the resolver keeps it for a later attempt only
 * when some consumer, or a base period or chain section, accepted a key.
 *
 * @typedef {object} ResponseSectionContext
 * @property {DcaData} dcaData
 * @property {string} issuerName
 * @property {string|undefined} publisher
 * @property {object} response - the response as the resolver received it
 * @property {ResponseAssociation} association - the one captured exchange
 * @property {object} lease
 * @property {() => void} check - throws once this application is retired
 * @property {(value: unknown, use: { keyKind: string, usages?: KeyUsage[], keyBytes?: number, raw?: boolean }) => Promise<{ key: Uint8Array|CryptoKey, issue: null }|{ key: null, issue: 'malformed_key'|'unsupported_section' }>} openKey
 * @property {(contentName: string, key: Uint8Array|CryptoKey) => void} holdContentKey -
 *   hold one item content key the consumer admitted for an item it asked for,
 *   as base holds a `keys.contentKeys` entry: the plain key path then finds it,
 *   and reader reset drops it. Throws once this application is retired.
 */

/**
 * A selected extension's reading of one top-level response member, `name`.
 * `keyValues` lists, synchronously and without opening anything, every key
 * value in the member, so the response-wide representation rules and the
 * strict-endpoint rule count them with the base sections. `admit` validates
 * the member against the association, opens and files what it accepts, and
 * answers how many keys it accepted and its issues; the resolver stamps each
 * issue with `name`. A refusal of the whole member is the consumer's
 * `malformed_response` issue with nothing accepted. An admitted member may
 * also answer `errors`: one record per coordinate whose opening key the issuer
 * reported retired, `{ error: "key_retired", ...coordinate }` with string
 * coordinate members only. The resolver freezes each, stamps it with
 * `consumer: name` and appends it to the application's `errors` after the core
 * `{ coordinate, error }` entries. A consumer that files
 * under the lease joins completion through `promote` and `attempted`, and
 * reset through `clearReaderContext`.
 *
 * @typedef {object} ResponseSectionConsumer
 * @property {string} name
 * @property {(section: unknown) => unknown[]} keyValues
 * @property {(section: unknown, context: ResponseSectionContext)
 *   => Promise<{ accepted: number, issues: { code: ResponseIssue['code'] }[], errors?: ConsumerErrorRecord[] }>} admit
 * @property {(context: { lease: object }) => Promise<void>} [promote]
 * @property {(context: { lease: object }) => Promise<void>} [attempted]
 * @property {() => void|Promise<void>} [clearReaderContext]
 */

/** Response members base reads itself; no consumer may own one. */
const BASE_RESPONSE_MEMBERS = Object.freeze([
  "keys",
  "transport",
  "errors",
  "notDelivered",
  "periodGeometry",
]);

/** The issue codes a response application reports. */
const ISSUE_CODES = Object.freeze([
  "malformed_key",
  "unsupported_section",
  "invalid_transport",
  "unsolicited_coordinate",
  "malformed_error",
  "malformed_response",
]);

/** Members a response-section consumer may carry. */
const RESPONSE_SECTION_MEMBERS = Object.freeze([
  "name",
  "keyValues",
  "admit",
  "promote",
  "attempted",
  "clearReaderContext",
]);

/** Members a recovery source may carry. */
// The predicate learns each candidate's origin. An opener reports a failed
// delivered, unwrapped or held key as a wrong key, and a current recovered
// guess as a miss. Held material may itself have been recovered earlier.
const HELD_ORIGIN = Object.freeze({ kind: /** @type {const} */ ("held-content-key") });

const RECOVERY_SOURCE_MEMBERS = Object.freeze([
  "candidates",
  "maxTrialsPerItem",
  "promote",
  "attempted",
  "clearReaderContext",
]);

export class ContentKeyResolver {
  #reader = new ReaderContext();
  /**
   * Content keys held per publisher and renderId, whether delivered directly
   * or recovered during resolution, so one publisher's render cannot open
   * another publisher's render even when identifiers collide.
   *
   * Each item holds its distinct candidates, oldest first.
   *
   * @type {Map<string|undefined, Map<string, Map<string, (Uint8Array|CryptoKey)[]>>>}
   */
  #contentKeys = new Map();

  /** @type {Cache|null} */
  #cache;

  /** @type {ChainCache|null} */
  #chainCache;

  /** @type {ChainKeyProfile|null} */
  #chainKeyProfile;

  /** @type {((accessGroup: string, t: string, request: any) => boolean)|null} */
  #periodKeyResponseCoordinate;

  /**
   * The construction profile of the chain bundle, when one is selected: its
   * profile name, its construction identifier and the width of one positioned
   * chain key. Null for a period-key-only client.
   *
   * @type {{ name: string, constructionId: string, chainKeyBytes: number }|null}
   */
  #constructionProfile = null;

  /** @type {{ attempts: Function }[]} */
  #candidateSources;

  /** @type {RecoverySource[]} */
  #recoverySources = [];

  /** @type {ResponseSectionConsumer[]} */
  #responseSections = [];
  #ordinaryPeriodHandled = false;

  /** @type {WeakMap<object, object>} */
  #responseLeases = new WeakMap();
  /** @type {WeakMap<object, { readers: number, waiters: (() => void)[], completion?: Promise<void> }>} */
  #responseAttempts = new WeakMap();

  /** @type {ClientBoundKeyCapability|null} */
  #capability;

  /** @type {boolean} */
  #acceptDirectFallback;

  /** @type {boolean} */
  #persistRawPeriodKeys;

  /** @type {(context: { entry: any, renderId: string, contentName: string, accessGroup: string }) => ({ aad?: Uint8Array }|null)} */
  #entryInterpretation;

  /** @type {((request: any) => string[])|null} */
  #presentedContentNames;

  /**
   * @param {object} [config]
   * @param {Cache} [config.cache] - owned by the caller, because it outlives
   *   any one page. With it left out, the client has no cached path: it asks
   *   the issuer for every article and never keeps a period key.
   * @param {ChainCache} [config.chainCache] - retains or expands directly
   *   delivered chain keys separately from period keys
   * @param {ChainKeyProfile} [config.chainKeyProfile] - the optional
   *   chain capability used with `chainCache`; its constructionProfile is
   *   required when that cache is selected
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
   *   from the item's content AAD, which the client rebuilds from the
   *   captured item (`DcaData#contentItemFor`).
   * @param {(request: any) => string[]} [config.presentedContentNames] - the
   *   item coordinates the selected request composition presented outside
   *   `sealed.contentKeys`, read from the request associated with a response.
   *   A returned key or error for such an item is solicited.
   * @param {(accessGroup: string, t: string, request: any) => boolean} [config.periodKeyResponseCoordinate] -
   *   selected relay's admission of period projections, using only the frozen
   *   associated request. A chainKeyProfile validator takes precedence.
   * @param {RecoverySource[]} [config.recoverySources] - selected item-key
   *   recoveries, tried in order after the cached wrap paths on authenticated
   *   calls only
   * @param {ResponseSectionConsumer[]} [config.responseSections] - selected
   *   readers of their own top-level response members
   */
  constructor(config = {}) {
    // The constructor refuses any other option rather than ignoring it, as
    // PeriodKeyCache and keySealing already do. The list has no clock
    // because nothing here consults time.
    for (const name of Object.keys(config)) {
      if (
        name !== "cache" &&
        name !== "chainCache" &&
        name !== "chainKeyProfile" &&
        name !== "clientBoundKeyCapability" &&
        name !== "acceptDirectFallback" &&
        name !== "persistRawPeriodKeys" &&
        name !== "entryInterpretation" &&
        name !== "presentedContentNames" &&
        name !== "periodKeyResponseCoordinate" &&
        name !== "recoverySources" &&
        name !== "responseSections"
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
      throw dcaError("bad_config", "a period-key cache needs candidatesAt and attempted methods");
    }
    /** @type {ChainKeyProfile|undefined} */
    const chainKeyProfile = config.chainKeyProfile;
    if (
      chainKeyProfile?.periodCacheFor !== undefined &&
      typeof chainKeyProfile.periodCacheFor !== "function"
    )
      throw dcaError("bad_config", "a chainKeyProfile ordinary period view factory is a function");
    if (this.#chainCache?.promote !== undefined && typeof this.#chainCache.promote !== "function")
      throw dcaError("bad_config", "a chain-cache promotion hook is a function");
    if (
      chainKeyProfile?.acceptsPresentedErrorCoordinate !== undefined &&
      typeof chainKeyProfile.acceptsPresentedErrorCoordinate !== "function"
    ) {
      throw dcaError("bad_config", "a chainKeyProfile error-coordinate validator is a function");
    }
    /** @type {ChainKeyProfile|null} */
    let chainProfile = null;
    if (this.#chainCache) {
      if (
        typeof chainKeyProfile?.parametersForResponse !== "function" ||
        typeof chainKeyProfile.candidateSourceFor !== "function" ||
        typeof chainKeyProfile.acceptsPeriodKeyResponseCoordinate !== "function" ||
        typeof chainKeyProfile.acceptsResponseCoordinate !== "function"
      ) {
        throw dcaError(
          "bad_config",
          "a chainCache needs an injected chainKeyProfile with explicit response geometry, a candidate source, and period-key and chain-key response-coordinate validators",
        );
      }
      // The bundle names the construction it was composed on, and that
      // construction names the period-key profile its period keys have. A bundle
      // whose period-key profile is not this client's would file chain keys
      // and period keys of two different widths in one client, so the
      // disagreement is refused here.
      const construction = chainKeyProfile.constructionProfile;
      if (typeof construction?.name !== "string" || construction?.chainKeyBytes !== 16) {
        throw dcaError(
          "bad_config",
          "a chainKeyProfile names the construction profile it was composed on",
        );
      }
      this.#constructionProfile = construction;
      chainProfile = chainKeyProfile;
    }
    this.#chainKeyProfile = chainKeyProfile ?? null;
    if (
      config.periodKeyResponseCoordinate !== undefined &&
      typeof config.periodKeyResponseCoordinate !== "function"
    ) {
      throw dcaError("bad_config", "ContentKeyResolver periodKeyResponseCoordinate is a function");
    }
    this.#periodKeyResponseCoordinate = config.periodKeyResponseCoordinate ?? null;
    // Merge ordinary returned/derived period views first under one rival bound,
    // then offer actual chain derivation under the same finite trial budget.
    this.#candidateSources = [];
    const derivedPeriodView = chainProfile?.periodCacheFor?.({ cache: this.#chainCache }) ?? null;
    this.#ordinaryPeriodHandled = derivedPeriodView !== null;
    if (this.#cache || derivedPeriodView)
      this.#candidateSources.push(periodKeyCandidateSource(this.#cache, derivedPeriodView));
    if (chainProfile) {
      const source = chainProfile.candidateSourceFor({ cache: this.#chainCache });
      if (typeof source?.attempts !== "function") {
        throw dcaError("bad_config", "a chainKeyProfile candidate source answers attempts");
      }
      this.#candidateSources.push(source);
    }
    this.#capability = config.clientBoundKeyCapability ?? null;
    if (this.#chainCache && this.#capability) {
      if (typeof this.#capability.assertCanOpenChainKeys !== "function") {
        throw dcaError(
          "bad_config",
          "a chain-capable client-bound key capability needs assertCanOpenChainKeys",
        );
      }
      const result = this.#capability.assertCanOpenChainKeys();
      if (
        result !== undefined &&
        result !== null &&
        typeof (/** @type {any} */ (result).then) === "function"
      ) {
        throw dcaError("bad_config", "chain-key capability admission must be synchronous");
      }
    }
    for (const name of /** @type {const} */ (["acceptDirectFallback", "persistRawPeriodKeys"])) {
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
    if (
      config.presentedContentNames !== undefined &&
      typeof config.presentedContentNames !== "function"
    ) {
      throw dcaError("bad_config", "ContentKeyResolver presentedContentNames is a function");
    }
    this.#presentedContentNames = config.presentedContentNames ?? null;
    this.#recoverySources = this.#admittedRecoverySources(config.recoverySources);
    this.#responseSections = this.#admittedResponseSections(config.responseSections);
  }

  /**
   * @param {unknown} consumers
   * @returns {ResponseSectionConsumer[]}
   */
  #admittedResponseSections(consumers) {
    if (consumers === undefined) return [];
    if (!Array.isArray(consumers)) {
      throw dcaError("bad_config", "ContentKeyResolver responseSections is a list");
    }
    const names = new Set();
    return consumers.map((consumer) => {
      if (consumer === null || typeof consumer !== "object") {
        throw dcaError("bad_config", "a response-section consumer is an object");
      }
      for (const name of Object.keys(consumer)) {
        if (!RESPONSE_SECTION_MEMBERS.includes(name)) {
          throw dcaError("bad_config", `a response-section consumer has no ${name} member`);
        }
      }
      const name = consumer.name;
      if (typeof name !== "string" || name.length === 0 || BASE_RESPONSE_MEMBERS.includes(name)) {
        throw dcaError("bad_config", "a response-section consumer owns one non-base member");
      }
      if (names.has(name)) {
        throw dcaError("bad_config", `two response-section consumers own ${name}`);
      }
      names.add(name);
      if (typeof consumer.keyValues !== "function" || typeof consumer.admit !== "function") {
        throw dcaError("bad_config", "a response-section consumer answers keyValues and admit");
      }
      for (const hook of ["promote", "attempted", "clearReaderContext"]) {
        if (consumer[hook] !== undefined && typeof consumer[hook] !== "function") {
          throw dcaError("bad_config", `a response-section consumer ${hook} is a function`);
        }
      }
      return /** @type {ResponseSectionConsumer} */ (consumer);
    });
  }

  /**
   * @param {unknown} sources
   * @returns {RecoverySource[]}
   */
  #admittedRecoverySources(sources) {
    if (sources === undefined) return [];
    if (!Array.isArray(sources)) {
      throw dcaError("bad_config", "ContentKeyResolver recoverySources is a list");
    }
    return sources.map((source) => {
      if (source === null || typeof source !== "object") {
        throw dcaError("bad_config", "a recovery source is an object");
      }
      for (const name of Object.keys(source)) {
        if (!RECOVERY_SOURCE_MEMBERS.includes(name)) {
          throw dcaError("bad_config", `a recovery source has no ${name} member`);
        }
      }
      if (typeof source.candidates !== "function") {
        throw dcaError("bad_config", "a recovery source answers candidates");
      }
      if (!Number.isSafeInteger(source.maxTrialsPerItem) || source.maxTrialsPerItem < 1) {
        throw dcaError("bad_config", "a recovery source bounds its trials per item");
      }
      for (const hook of ["promote", "attempted", "clearReaderContext"]) {
        if (source[hook] !== undefined && typeof source[hook] !== "function") {
          throw dcaError("bad_config", `a recovery source ${hook} is a function`);
        }
      }
      return /** @type {RecoverySource} */ (source);
    });
  }

  /** The selected extension owners that retain material between calls. @returns {object[]} */
  #extensionOwners() {
    return [...new Set([...this.#recoverySources, ...this.#responseSections])];
  }

  /** Validate the recursive retaining-owner contract used by the browser.
   * Lower-level compositions need this duty only when selecting full reset.
   * @returns {void}
   */
  assertReaderContextReset() {
    for (const cache of [this.#cache, this.#chainCache])
      if (cache && typeof (/** @type {any} */ (cache).clearReaderContext) !== "function")
        throw dcaError("bad_config", "a browser retaining cache needs clearReaderContext");
    for (const owner of this.#extensionOwners())
      if (typeof (/** @type {any} */ (owner).clearReaderContext) !== "function")
        throw dcaError("bad_config", "a retaining extension owner needs clearReaderContext");
  }

  /** Retire item keys and response sessions before asking every owner to clear.
   * Existing readers retain their completion bookkeeping until they drain;
   * retiring a context does not wait for those readers or network work.
   * @returns {Promise<void>}
   */
  clearReaderContext() {
    return this.#reader.clear(async () => {
      this.#contentKeys.clear();
      this.#responseLeases = new WeakMap();
      const extensionOwners = new Set(this.#extensionOwners());
      const owners = new Set([
        this.#cache,
        this.#chainCache,
        this.#capability,
        this.#chainKeyProfile,
        ...extensionOwners,
      ]);
      const results = await Promise.allSettled(
        [...owners].filter(Boolean).map((owner) => {
          try {
            const reset = /** @type {any} */ (owner).clearReaderContext;
            if (typeof reset === "function") return reset.call(owner);
            if (owner === this.#cache || owner === this.#chainCache)
              throw dcaError("bad_config", "a retaining cache needs clearReaderContext");
            if (extensionOwners.has(/** @type {object} */ (owner)))
              throw dcaError("bad_config", "a retaining extension owner needs clearReaderContext");
            // The configured capability/profile contract retains no delivered
            // state beyond an operation. Custom retaining versions supply reset.
            return undefined;
          } catch (error) {
            return Promise.reject(error);
          }
        }),
      );
      const failed = results.find((result) => result.status === "rejected");
      if (failed?.status === "rejected") throw failed.reason;
    });
  }

  /**
   * Whether the associated request presented this item coordinate, in base's
   * `sealed.contentKeys` or through the selected composition's own member.
   *
   * @param {ResponseAssociation} association
   * @param {string} contentName
   * @returns {boolean}
   */
  #presentsContent(association, contentName) {
    if (association.presentsContent(contentName)) return true;
    if (this.#presentedContentNames === null || !isContentName(contentName)) return false;
    const presented = this.#presentedContentNames(association.request);
    if (!Array.isArray(presented)) {
      throw dcaError("bad_config", "presentedContentNames answers a list of content names");
    }
    return presented.includes(contentName);
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
   * The page's host-supplied publisher context origin. The cache uses it as a
   * coordinate to keep publishers apart, never to decide access; it is not a
   * verified identity and is not decoded from resourceJWT.
   *
   * @param {DcaData} dcaData
   * @param {boolean} required - true on a store, false on a read
   * @returns {string|undefined}
   */
  #publisherOf(dcaData, required) {
    const publisher = dcaData.publisherOrigin;
    if (publisher === undefined) {
      if (required)
        throw dcaError("bad_page", "the page has no publisher context origin to file keys under");
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
    // Several response records for one item are rival candidates (core
    // Section 7). Each distinct one is kept, and one held again moves to the
    // newest place. The response's raw record count bounds what one
    // application adds, so no cap here can push a working candidate out.
    const candidates = (held.get(contentName) ?? []).filter(
      (candidate) => !sameContentKey(candidate, key),
    );
    candidates.push(key);
    held.set(contentName, candidates);
  }

  /** The held candidates of one item, newest first.
   * @param {string|undefined} publisher @param {string} renderId @param {string} contentName
   * @returns {(Uint8Array|CryptoKey)[]}
   */
  #heldContentKeys(publisher, renderId, contentName) {
    return [...(this.#contentKeys.get(publisher)?.get(renderId)?.get(contentName) ?? [])].reverse();
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
   *   origin: { kind: 'held-content-key'|'cached-period-key'|'cached-chain-key'|'missing', accessGroup?: string, t?: string },
   * }>}
   */
  async contentKeyWithOriginFor(dcaData, contentName, application) {
    const readerRevision = this.#reader.capture();
    if (!(dcaData instanceof DcaData)) {
      throw dcaError(
        "bad_config",
        "a content key is unwrapped from a DcaData; construct one first",
      );
    }

    const lease = this.#leaseFor(application);
    return this.#reader.accept(
      await this.#leasedOperation(application, lease, () =>
        this.#contentKeyWithOriginFor(dcaData, contentName, lease),
      ),
      readerRevision,
    );
  }

  /**
   * Select and retain the first candidate that the caller proves opens this
   * item's sealed bytes. Ordinary key acquisition keeps its established
   * held-key-first behavior; this path exists for route walks that can test
   * authenticated opening before deciding another issuer is unnecessary.
   *
   * @param {DcaData} dcaData
   * @param {string} contentName
   * @param {(candidate: Uint8Array|CryptoKey, origin?: { kind: string }) => Promise<boolean>} authenticate
   * @returns {Promise<Uint8Array|CryptoKey|null>}
   */
  async contentKeyForAuthenticatedItem(dcaData, contentName, authenticate) {
    const readerRevision = this.#reader.capture();
    if (!(dcaData instanceof DcaData))
      throw dcaError(
        "bad_config",
        "an authenticated item key is selected from a DcaData; construct one first",
      );
    if (typeof authenticate !== "function")
      throw dcaError("bad_config", "an authenticated item key needs an async predicate");
    return this.#reader.accept(
      await this.#authenticatedItem(dcaData, contentName, authenticate, undefined),
      readerRevision,
    ).key;
  }

  /** Authenticate all obtaining items under one response-private lifetime.
   * @param {DcaData} dcaData
   * @param {string[]} contentNames
   * @param {(contentName: string, candidate: Uint8Array|CryptoKey, origin?: { kind: string }) => Promise<boolean>} authenticate
   * @param {object} [application]
   * @returns {Promise<{covered: string[], missing: string[], origins: {contentName: string, origin: KeyOrigin}[]}>}
   */
  async resolveAuthenticated(dcaData, contentNames, authenticate, application) {
    const readerRevision = this.#reader.capture();
    if (
      !(dcaData instanceof DcaData) ||
      !Array.isArray(contentNames) ||
      typeof authenticate !== "function"
    )
      throw dcaError("bad_config", "authenticated resolve needs a DcaData, names and predicate");
    const lease = this.#leaseFor(application);
    /** @type {string[]} */
    const covered = [];
    /** @type {string[]} */
    const missing = [];
    /** @type {{contentName: string, origin: KeyOrigin}[]} */
    const origins = [];
    return this.#reader.accept(
      await this.#leasedOperation(application, lease, async () => {
        dcaData.version;
        for (const contentName of contentNames) {
          const result = this.#reader.accept(
            await this.#authenticatedItem(
              dcaData,
              contentName,
              (candidate, origin) => authenticate(contentName, candidate, origin),
              lease,
            ),
            readerRevision,
          );
          (result.key ? covered : missing).push(contentName);
          origins.push({ contentName, origin: result.origin });
        }
        return { covered, missing, origins };
      }),
      readerRevision,
    );
  }

  /** @param {DcaData} dcaData @param {string} contentName
   * @param {(candidate: Uint8Array|CryptoKey, origin?: { kind: string }) => Promise<boolean>} authenticate
   * @param {object|undefined} lease
   * @returns {Promise<{key: Uint8Array|CryptoKey|null, origin: KeyOrigin}>}
   */
  async #authenticatedItem(dcaData, contentName, authenticate, lease) {
    const readerRevision = this.#reader.capture();
    dcaData.version;
    const publisher = this.#publisherOf(dcaData, false);
    const renderId = dcaData.renderId;
    if (typeof renderId !== "string") throw dcaError("bad_page", "dca-data carries no renderId");
    for (const held of this.#heldContentKeys(publisher, renderId, contentName)) {
      if (
        this.#reader.accept(
          await this.#authenticatedCandidate(authenticate, held, HELD_ORIGIN),
          readerRevision,
        )
      ) {
        // The candidate that opened moves to the newest place, so a plain
        // lookup after this one answers with the key that opens the item.
        this.#holdContentKey(publisher, renderId, contentName, held);
        return { key: held, origin: { kind: "held-content-key" } };
      }
    }
    /** @param {Uint8Array|CryptoKey} candidate @param {{ kind: string }} [origin] */
    const authenticated = (candidate, origin) =>
      this.#authenticatedCandidate(authenticate, candidate, origin);
    /** @type {{ key: Uint8Array|CryptoKey|null, origin: KeyOrigin }} */
    let found = this.#reader.accept(
      await this.#fromCache(dcaData, contentName, lease, authenticated),
      readerRevision,
    );
    if (!found.key)
      found = this.#reader.accept(
        await this.#recovered(dcaData, contentName, lease, authenticated),
        readerRevision,
      );
    if (found.key) this.#holdContentKey(publisher, renderId, contentName, found.key);
    return found;
  }

  /**
   * Ask each selected recovery source for this item's candidate content keys
   * and return the first the caller authenticates. Each candidate passes the
   * reader fence before it reaches the predicate, so a source that awaited
   * across a reset can yield but never have its key tried or held.
   *
   * @param {DcaData} dcaData
   * @param {string} contentName
   * @param {object|undefined} lease
   * @param {(candidate: Uint8Array|CryptoKey, origin?: { kind: string }) => Promise<boolean>} authenticate
   * @returns {Promise<{ key: Uint8Array|null, origin: KeyOrigin }>}
   */
  async #recovered(dcaData, contentName, lease, authenticate) {
    const readerRevision = this.#reader.capture();
    if (this.#recoverySources.length === 0) return { key: null, origin: { kind: "missing" } };
    /** @type {RecoveryContext} */
    const context = Object.freeze({
      dcaData,
      contentName,
      publisher: this.#publisherOf(dcaData, false),
      renderId: /** @type {string} */ (dcaData.renderId),
      lease,
      check: () => this.#reader.check(readerRevision),
    });
    for (const source of this.#recoverySources) {
      let trials = 0;
      for await (const candidate of source.candidates(context)) {
        this.#reader.check(readerRevision);
        const contentKey = candidate?.contentKey;
        if (!(contentKey instanceof Uint8Array) || contentKey.length !== CONTENT_KEY_BYTES) {
          throw dcaError("bad_config", "a recovery source yields 16-byte content keys");
        }
        const origin = candidate.origin ?? {};
        if (origin === null || typeof origin !== "object" || Array.isArray(origin)) {
          throw dcaError("bad_config", "a recovery source origin is a plain object");
        }
        if (++trials > source.maxTrialsPerItem) break;
        const key = Uint8Array.from(contentKey);
        if (
          this.#reader.accept(
            await authenticate(key, { kind: "recovered-content-key" }),
            readerRevision,
          )
        )
          return { key, origin: { ...origin, kind: "recovered-content-key" } };
      }
    }
    return { key: null, origin: { kind: "missing" } };
  }

  /**
   * @param {(candidate: Uint8Array|CryptoKey, origin?: { kind: string }) => Promise<boolean>} authenticate
   * @param {Uint8Array|CryptoKey} candidate
   * @param {{ kind: string }} [origin] - where the candidate came from
   */
  async #authenticatedCandidate(authenticate, candidate, origin) {
    const readerRevision = this.#reader.capture();
    const accepted = this.#reader.accept(await authenticate(candidate, origin), readerRevision);
    if (typeof accepted !== "boolean") {
      throw dcaError("bad_config", "an authenticated item-key predicate answers boolean");
    }
    return accepted;
  }

  /**
   * @param {DcaData} dcaData
   * @param {string} contentName
   * @param {object|undefined} lease
   * @returns {Promise<{
   *   key: Uint8Array|CryptoKey|null,
   *   origin: { kind: 'held-content-key'|'cached-period-key'|'cached-chain-key'|'missing', accessGroup?: string, t?: string },
   * }>}
   */
  async #contentKeyWithOriginFor(dcaData, contentName, lease) {
    const readerRevision = this.#reader.capture();
    // Outer admission runs on every key path, including a held or cached key
    // that needs no issuer request. The version getter admits the complete
    // delivery before renderId or cached coordinates are read.
    dcaData.version;
    const publisher = this.#publisherOf(dcaData, false);
    const renderId = dcaData.renderId;
    if (typeof renderId !== "string") {
      throw dcaError("bad_page", "dca-data carries no renderId");
    }
    // Without a predicate to try candidates with, the newest one answers, as
    // a single held key did.
    const [held] = this.#heldContentKeys(publisher, renderId, contentName);
    if (held) return { key: held, origin: { kind: "held-content-key" } };

    return this.#reader.accept(await this.#fromCache(dcaData, contentName, lease), readerRevision);
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
   *   origins: { contentName: string, origin: { kind: 'held-content-key'|'cached-period-key'|'cached-chain-key'|'missing', accessGroup?: string, t?: string } }[],
   * }>}
   */
  async resolveDetailed(dcaData, contentNames, application) {
    const readerRevision = this.#reader.capture();
    if (!(dcaData instanceof DcaData)) {
      throw dcaError("bad_config", "a resolve is read from a DcaData; construct one first");
    }

    /** @type {string[]} */
    const covered = [];
    /** @type {string[]} */
    const missing = [];
    /** @type {{ contentName: string, origin: { kind: 'held-content-key'|'cached-period-key'|'cached-chain-key'|'missing', accessGroup?: string, t?: string } }[]} */
    const origins = [];
    const lease = this.#leaseFor(application);
    return this.#reader.accept(
      await this.#leasedOperation(application, lease, async () => {
        // Resolve may read renderId before its first per-item lookup, so force
        // the same whole-delivery admission here as the single-item entry.
        dcaData.version;
        const renderId = /** @type {string} */ (dcaData.renderId);
        for (const contentName of contentNames) {
          const { key, origin } = this.#reader.accept(
            await this.#contentKeyWithOriginFor(dcaData, contentName, lease),
            readerRevision,
          );
          (key ? covered : missing).push(contentName);
          if (key)
            this.#holdContentKey(this.#publisherOf(dcaData, false), renderId, contentName, key);
          origins.push({ contentName, origin });
        }
        return { covered, missing, origins };
      }),
      readerRevision,
    );
  }

  /**
   * Run one operation as a reader of a response application and complete
   * that response's attempt when the operation ends, by a fault as well as by
   * a return. Completion files the response's private grants for reuse, so a
   * storage or predicate fault still completes the obtaining attempt. Failed
   * retention releases private material only after captured readers finish;
   * completion runs once per lease and never retries a failed promotion.
   *
   * @template T
   * @param {object|undefined} application
   * @param {object|undefined} lease
   * @param {() => Promise<T>} operation
   * @returns {Promise<T>}
   */
  async #leasedOperation(application, lease, operation) {
    const readerRevision = this.#reader.capture();
    this.#beginResponseAttempt(lease);
    /** @type {T} */
    let result;
    try {
      result = this.#reader.accept(await operation(), readerRevision);
    } catch (fault) {
      this.#endResponseAttempt(lease);
      // The operation's fault is the answer to the caller's question. A
      // completion fault behind it would replace that answer, so it stays on
      // the shared completion promise instead of being thrown here.
      this.#reader.accept(
        await this.#completeResponseAttempt(application, lease).catch(() => undefined),
        readerRevision,
      );
      throw fault;
    }
    this.#endResponseAttempt(lease);
    this.#reader.accept(await this.#completeResponseAttempt(application, lease), readerRevision);
    return result;
  }

  /** @param {any} application @returns {object|undefined} */
  #leaseFor(application) {
    return application !== null && typeof application === "object"
      ? this.#responseLeases.get(application)
      : undefined;
  }

  /**
   * Complete one response's pending grants after its article attempt.
   *
   * @param {object|undefined} application
   * @param {object|undefined} lease - present only when `#leaseFor` found it
   *   under an application object
   */
  async #completeResponseAttempt(application, lease) {
    const readerRevision = this.#reader.capture();
    if (lease === undefined) return;
    const state = this.#responseAttempts.get(lease);
    if (!state) return;
    if (!state.completion) {
      state.completion = (async () => {
        let failed = false;
        /** @type {unknown} */
        let fault;
        // Promotion preserves the private grant while readers join/finish.
        try {
          this.#reader.accept(await this.#chainCache?.promote?.({ lease }), readerRevision);
          for (const owner of this.#extensionOwners())
            this.#reader.accept(
              await /** @type {any} */ (owner).promote?.({ lease }),
              readerRevision,
            );
        } catch (error) {
          failed = true;
          fault = error;
          // A failed promotion is terminal. Already captured readers retain
          // their lease, but a later operation must not join this failure.
          this.#responseLeases.delete(/** @type {object} */ (application));
        }
        while (state.readers > 0) {
          this.#reader.accept(
            await new Promise((resolve) => state.waiters.push(() => resolve(undefined))),
            readerRevision,
          );
        }
        // End association before asynchronous cleanup: a new call now begins
        // a later operation, while all captured readers have completed.
        this.#responseLeases.delete(/** @type {object} */ (application));
        // Each owner gets its release even when another owner fails. Preserve
        // the first completion fault; #leasedOperation gives an operation's
        // own fault precedence over it.
        for (const cache of [this.#cache, this.#chainCache, ...this.#extensionOwners()]) {
          try {
            this.#reader.accept(
              await /** @type {any} */ (cache)?.attempted?.({ lease }),
              readerRevision,
            );
          } catch (error) {
            if (!failed) {
              failed = true;
              fault = error;
            }
          }
        }
        this.#responseAttempts.delete(lease);
        if (failed) throw fault;
      })();
    }
    this.#reader.accept(await state.completion, readerRevision);
  }

  /** @param {object|undefined} lease */
  #beginResponseAttempt(lease) {
    if (lease === undefined) return;
    let state = this.#responseAttempts.get(lease);
    if (!state) {
      state = { readers: 0, waiters: [] };
      this.#responseAttempts.set(lease, state);
    }
    state.readers++;
  }

  /** @param {object|undefined} lease */
  #endResponseAttempt(lease) {
    if (lease === undefined) return;
    const state = this.#responseAttempts.get(lease);
    if (!state) return;
    state.readers--;
    if (state.readers === 0) for (const wake of state.waiters.splice(0)) wake();
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
    const readerRevision = this.#reader.capture();
    const { covered, missing } = this.#reader.accept(
      await this.resolveDetailed(dcaData, contentNames, responseAttempt[0]),
      readerRevision,
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
   * An admitted `notDelivered` report comes back as its own frozen
   * `notDelivered` list of `{ accessGroup, reason, message? }`, present only
   * when the response carried one. A report that fails validation yields a
   * scoped `malformed_response` issue and suppresses this response's stock
   * family keys; independent item keys and extension sections still apply
   * after representation admission. An unusable client-bound transport rejects every wrapped key
   * entry with `invalid_transport` and keeps the admitted report; a
   * whole-response refusal (mixed representations, or a direct key-section
   * answer from a strict endpoint) returns no report.
   *
   * @param {DcaData} dcaData
   * @param {string} issuerName
   * @param {object} response
   * @param {ResponseAssociation} association
   * @returns {Promise<{ accepted: number, errors: readonly ApplicationError[], notDelivered?: readonly { accessGroup: string, reason: 'denied'|'unavailable', message?: string }[], issues: { section?: string, code: 'malformed_key'|'unsupported_section'|'invalid_transport'|'unsolicited_coordinate'|'malformed_error'|'malformed_response' }[] }>}
   */
  async applyResponse(dcaData, issuerName, response, association) {
    const readerRevision = this.#reader.capture();
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
    // Reject an invalid optional report and this response's reusable family
    // grants, without discarding independent item keys or unrelated sections.
    // Keep the original entries through representation classification below.
    const familyReport = this.#admittedNotDelivered(response, keys, association);
    const notDelivered = familyReport ?? [];
    // The endpoint agreement is fixed before the request is sent. Refuse a
    // response carrying a key section from a strict endpoint as a whole, before
    // any section can decode, cache, or retain entries. An empty key section
    // still selects a representation; sectionless error-only answers do not.
    const extensionSections = this.#responseSections
      .filter(({ name }) => own(response, name) !== undefined)
      .map((consumer) => {
        const section = own(response, consumer.name);
        const values = consumer.keyValues(section);
        if (!Array.isArray(values)) {
          throw dcaError("bad_config", "a response-section consumer lists its key values");
        }
        return { consumer, section, entries: values.map((value) => ({ value })) };
      });
    if (
      own(response, "transport") === undefined &&
      !association.acceptDirectResponse &&
      (["contentKeys", "periodKeys", "chainKeys"].some((name) => Object.hasOwn(keys ?? {}, name)) ||
        extensionSections.length > 0)
    ) {
      return this.#application(0, [{ section: "response", code: "invalid_transport" }]);
    }
    /** @type {ResponseSections} */
    const sections = {
      contentKeys: responseSectionEntries(keys, "contentKeys"),
      periodKeys: responseSectionEntries(keys, "periodKeys"),
      chainKeys: responseSectionEntries(keys, "chainKeys"),
    };
    // A key/error collision belongs to the response as received. Later
    // report, support or coordinate filtering must not unmask that error.
    const errorSections = {
      contentKeys: { ...sections.contentKeys },
      periodKeys: { ...sections.periodKeys },
      chainKeys: { ...sections.chainKeys },
    };
    /** @type {ResponseIssue[]} */
    const issues =
      familyReport === null
        ? [{ section: "notDelivered", code: /** @type {const} */ ("malformed_response") }]
        : [];
    const transport = own(response, "transport");
    // Classify every leaf in supported, structurally admitted key maps before
    // coordinate filtering. An unsolicited entry still contributes to the
    // response representation, but this scan opens and retains nothing.
    const representationEntries = [
      ...sections.contentKeys.entries,
      ...(this.#cache ? sections.periodKeys.entries : []),
      ...(this.#chainCache ? sections.chainKeys.entries : []),
      ...extensionSections.flatMap(({ entries }) => entries),
    ];
    const hasDirectEntry = representationEntries.some(({ value }) => typeof value === "string");
    const hasObjectEntry = representationEntries.some(
      ({ value }) => value !== null && typeof value === "object" && !Array.isArray(value),
    );
    if ((hasDirectEntry && hasObjectEntry) || (transport !== undefined && hasDirectEntry)) {
      return this.#application(0, [{ section: "response", code: "invalid_transport" }]);
    }
    if (familyReport === null) {
      // No status from the rejected report can qualify fallback, and no
      // stock family key from this response may escape its contradictory or
      // unscoped status. Previously retained capability remains untouched.
      sections.periodKeys = { present: false, entries: [], malformed: 0 };
      sections.chainKeys = { present: false, entries: [], malformed: 0 };
    }
    /** @type {Map<string, Map<string, boolean>>} */
    const periodKeyAdmissions = new Map();
    sections.contentKeys.entries = sections.contentKeys.entries.filter(
      ({ path: [contentName] }) => {
        if (this.#presentsContent(association, contentName)) return true;
        issues.push({ section: "contentKeys", code: "unsolicited_coordinate" });
        return false;
      },
    );
    sections.periodKeys.entries = sections.periodKeys.entries.filter(
      ({ path: [accessGroup, t] }) => {
        if (!isAccessGroup(accessGroup) || !isPeriodKeyLabel(t)) {
          issues.push({ section: "periodKeys", code: "unsolicited_coordinate" });
          return false;
        }
        let extensionAdmission;
        const profileValidator = this.#chainKeyProfile?.acceptsPeriodKeyResponseCoordinate;
        const validator =
          typeof profileValidator === "function"
            ? profileValidator.bind(this.#chainKeyProfile)
            : this.#periodKeyResponseCoordinate;
        if (typeof validator === "function") {
          extensionAdmission = validator(accessGroup, t, association.request);
          if (typeof extensionAdmission !== "boolean") {
            throw dcaError(
              "bad_config",
              "a period-key response coordinate validator answers boolean",
            );
          }
          let familyAdmissions = periodKeyAdmissions.get(accessGroup);
          if (familyAdmissions === undefined) {
            familyAdmissions = new Map();
            periodKeyAdmissions.set(accessGroup, familyAdmissions);
          }
          familyAdmissions.set(
            t,
            association.presentsPeriodKey(accessGroup, t) || extensionAdmission,
          );
        }
        if (association.presentsPeriodKey(accessGroup, t) || extensionAdmission === true)
          return true;
        issues.push({ section: "periodKeys", code: "unsolicited_coordinate" });
        return false;
      },
    );
    // Chain geometry and request association must pass before a wrapped chain
    // key can obtain an opener that reaches the client's transport private key.
    // Representation classification above does not acquire that opener.
    if (!this.#chainCache) {
      if (sections.chainKeys.present) {
        this.#issueOnce(issues, "chainKeys", "unsupported_section");
        sections.chainKeys = { present: false, entries: [], malformed: 0 };
      }
    } else {
      this.#malformed(issues, "chainKeys", sections.chainKeys.malformed);
      sections.chainKeys.malformed = 0;
      sections.chainKeys.entries = sections.chainKeys.entries.filter((entry) => {
        const [accessGroup, cutoffT] = entry.path;
        const parameters =
          this.#chainKeyProfile?.parametersForResponse(
            response,
            dcaData,
            accessGroup,
            association.request,
            cutoffT,
          ) ?? null;
        if (parameters === null || !this.#acceptsChainCoordinate(cutoffT, parameters)) {
          issues.push({ section: "chainKeys", code: "malformed_key" });
          return false;
        }
        entry.parameters = parameters;
        return true;
      });
    }
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
      ...sections.chainKeys.entries,
      ...extensionSections.flatMap(({ entries }) => entries),
    ];
    // Only coordinate-admitted wrapped entries can require private-key work.
    const wrappedNeedsOpener = supportedEntries.some(({ value }) => this.#isWrapped(value));

    // From here an unusable transport rejects every wrapped key entry and no
    // more (response binding Sections 6 and 10). Independently admitted core
    // errors and the non-key report keep their meaning; nothing is retried as
    // direct bytes.
    const rejectWrappedKeys = () =>
      this.#application(
        0,
        issues,
        this.#admittedErrors(response, errorSections, association, issues),
        notDelivered,
      );
    /** @type {DeliveredKeyOpener|null} */
    let opener = null;
    if (
      wrappedNeedsOpener &&
      (transport === null ||
        typeof transport !== "object" ||
        Array.isArray(transport) ||
        typeof own(transport, "method") !== "string" ||
        own(transport, "method") !== association.offeredClientBoundMethod)
    ) {
      issues.push({ code: "invalid_transport" });
      return rejectWrappedKeys();
    }
    if (wrappedNeedsOpener) {
      if (!this.#capability) {
        // Preserve the established refusal for a client that receives
        // ordinary wrapped content, period, or admitted chain keys without
        // selecting the client-bound capability.
        throw dcaError(
          "bad_response",
          "this answer is wrapped for a client, and this client has no client-bound capability",
        );
      }
      try {
        opener = this.#reader.accept(
          await this.#capability.openDeliveredKeys(transport),
          readerRevision,
        );
      } catch (cause) {
        if (cause instanceof DcaError && cause.code === "bad_response") {
          issues.push({ code: "invalid_transport" });
          return rejectWrappedKeys();
        }
        throw cause;
      }
      if (opener === null) {
        issues.push({ code: "invalid_transport" });
        return rejectWrappedKeys();
      }
      if (typeof opener?.open !== "function") {
        throw dcaError("bad_config", "a client-bound capability returns an opener with open");
      }
    }

    let accepted = 0;
    const periodKeysAccepted = this.#reader.accept(
      await this.#consumePeriodKeys(
        dcaData,
        issuerName,
        response,
        sections.periodKeys,
        periodConsumers,
        opener,
        issues,
        periodKeyAdmissions,
        chainLease,
      ),
      readerRevision,
    );
    accepted += periodKeysAccepted;
    const chainAccepted = this.#reader.accept(
      await this.#consumeChainKeys(
        dcaData,
        issuerName,
        sections.chainKeys,
        chainLease,
        issues,
        opener,
      ),
      readerRevision,
    );
    accepted += chainAccepted;
    accepted += this.#reader.accept(
      await this.#consumeContentKeys(
        this.#publisherOf(dcaData, false),
        renderId,
        sections.contentKeys,
        opener,
        issues,
      ),
      readerRevision,
    );
    let extensionAccepted = 0;
    /** @type {ApplicationError[]} */
    const consumerErrors = [];
    for (const { consumer, section } of extensionSections) {
      extensionAccepted += this.#reader.accept(
        await this.#consumeExtensionSection(
          consumer,
          section,
          { dcaData, issuerName, response, association, lease: chainLease },
          opener,
          issues,
          readerRevision,
          consumerErrors,
        ),
        readerRevision,
      );
    }
    accepted += extensionAccepted;
    const errors = [
      ...this.#admittedErrors(response, errorSections, association, issues),
      ...consumerErrors,
    ];
    const application = this.#application(accepted, issues, errors, notDelivered);
    if (periodKeysAccepted > 0 || chainAccepted > 0 || extensionAccepted > 0)
      this.#responseLeases.set(application, chainLease);
    return application;
  }

  /**
   * Hand one consumer its member and count what it accepted.
   *
   * @param {ResponseSectionConsumer} consumer
   * @param {unknown} section
   * @param {{ dcaData: DcaData, issuerName: string, response: any, association: ResponseAssociation, lease: object }} exchange
   * @param {DeliveredKeyOpener|null} opener
   * @param {ResponseIssue[]} issues
   * @param {number} readerRevision
   * @param {ApplicationError[]} errors - receives the consumer's retirement records
   * @returns {Promise<number>}
   */
  async #consumeExtensionSection(
    consumer,
    section,
    exchange,
    opener,
    issues,
    readerRevision,
    errors,
  ) {
    /** @type {ResponseSectionContext} */
    const context = Object.freeze({
      ...exchange,
      publisher: this.#publisherOf(exchange.dcaData, false),
      check: () => this.#reader.check(readerRevision),
      openKey: async (
        /** @type {unknown} */ value,
        /** @type {{ keyKind: string, usages?: KeyUsage[], keyBytes?: number, raw?: boolean }} */ use,
      ) => {
        const { keyKind, usages = [], keyBytes = CONTENT_KEY_BYTES, raw = false } = use ?? {};
        if (typeof keyKind !== "string" || !Array.isArray(usages) || typeof raw !== "boolean")
          throw dcaError("bad_config", "openKey names a key kind, its usages and raw or not");
        if (!Number.isSafeInteger(keyBytes) || keyBytes < 1)
          throw dcaError("bad_config", "openKey names a whole key width");
        return this.#reader.accept(
          await this.#deliveredKey(
            value,
            opener,
            usages,
            /** @type {any} */ (keyKind),
            raw
              ? this.#acceptDirectFallback && this.#persistRawPeriodKeys
              : this.#acceptDirectFallback,
            keyBytes,
            raw,
          ),
          readerRevision,
        );
      },
      holdContentKey: (/** @type {unknown} */ contentName, /** @type {unknown} */ key) => {
        this.#reader.check(readerRevision);
        if (
          typeof contentName !== "string" ||
          !exchange.dcaData.contentNames().includes(contentName)
        )
          throw dcaError("bad_config", "a consumer holds keys only for items this page carries");
        const handle =
          typeof CryptoKey !== "undefined" &&
          key instanceof CryptoKey &&
          key.algorithm.name === "AES-GCM" &&
          key.usages.includes("decrypt");
        if (!handle && !(key instanceof Uint8Array && key.length === CONTENT_KEY_BYTES))
          throw dcaError("bad_config", "a held item key is an AES-GCM handle or 16 key bytes");
        this.#holdContentKey(
          this.#publisherOf(exchange.dcaData, false),
          /** @type {string} */ (exchange.dcaData.renderId),
          contentName,
          /** @type {Uint8Array|CryptoKey} */ (key),
        );
      },
    });
    const result = this.#reader.accept(await consumer.admit(section, context), readerRevision);
    const accepted = result?.accepted;
    if (!Number.isSafeInteger(accepted) || accepted < 0 || !Array.isArray(result?.issues)) {
      throw dcaError("bad_config", "a response-section consumer answers accepted and issues");
    }
    for (const issue of result.issues) {
      if (!ISSUE_CODES.includes(issue?.code)) {
        throw dcaError("bad_config", "a response-section consumer reports a known issue code");
      }
      issues.push({ section: consumer.name, code: issue.code });
    }
    const reported = result.errors ?? [];
    if (!Array.isArray(reported))
      throw dcaError("bad_config", "a response-section consumer lists its error records");
    for (const record of reported) {
      // Consumer code is trusted composition; a record that could carry key
      // bytes or pose as a core entry is its fault, never a response issue.
      if (
        record === null ||
        typeof record !== "object" ||
        Array.isArray(record) ||
        own(record, "error") !== "key_retired" ||
        Object.hasOwn(record, "coordinate") ||
        Object.hasOwn(record, "consumer") ||
        Object.values(record).some((value) => typeof value !== "string")
      )
        throw dcaError(
          "bad_config",
          "a response-section consumer reports key_retired records with string coordinates",
        );
      errors.push(Object.freeze({ ...record, consumer: consumer.name }));
    }
    return accepted;
  }

  /**
   * @param {number} accepted
   * @param {ResponseIssue[]} issues
   * @param {readonly ApplicationError[]} errors
   * @param {{ accessGroup: string, reason: 'denied'|'unavailable', message?: string }[]} notDelivered -
   *   admitted family reports; the report carries the member only when the
   *   response did, so a response without one keeps its established shape
   */
  #application(accepted, issues, errors = [], notDelivered = []) {
    return {
      accepted,
      errors: Object.freeze(errors),
      issues,
      ...(notDelivered.length > 0
        ? {
            notDelivered: Object.freeze(notDelivered),
          }
        : {}),
    };
  }

  /**
   * The admitted `notDelivered` entries, an empty list when the response has
   * no such member, or null when the report is malformed under response-binding
   * Section 3. No stock family key from that response is retained on null.
   * A named family must be one the
   * request presented in a period section, and the same response may carry no
   * period key, chain key or period-coordinate error for it. A content key
   * or content-name error is independent of the family and may stand beside
   * it.
   *
   * @param {any} response
   * @param {any} keys
   * @param {ResponseAssociation} association
   * @returns {{ accessGroup: string, reason: 'denied'|'unavailable', message?: string }[]|null}
   */
  #admittedNotDelivered(response, keys, association) {
    const report = own(response, "notDelivered");
    if (report === undefined) return [];
    if (!Array.isArray(report) || report.length === 0) return null;

    const { records, stray } = lastWholeRecords(report, "accessGroup");
    if (stray > 0) return null;
    const sealed = own(association.request, "sealed");
    // Every entry's family is admitted, the replaced ones too; only the last
    // whole entry per family supplies its reason and message.
    for (const accessGroup of records.keys()) {
      if (
        !isAccessGroup(accessGroup) ||
        !(
          namesFamily(own(sealed, "periodKeys"), accessGroup) ||
          namesFamily(own(sealed, "chainKeys"), accessGroup)
        )
      ) {
        return null;
      }
    }
    const erroredFamilies = this.#admittedErrorFamilies(response, association);
    const admitted = [];
    for (const [accessGroup, entry] of records) {
      const reason = own(entry, "reason");
      const message = own(entry, "message");
      if (!NOT_DELIVERED_REASONS.includes(/** @type {any} */ (reason))) return null;
      if (message !== undefined && typeof message !== "string") return null;
      // A record naming the family conflicts before any label or key in it
      // is admitted.
      if (
        namesFamily(own(keys, "periodKeys"), accessGroup) ||
        namesFamily(own(keys, "chainKeys"), accessGroup) ||
        erroredFamilies.has(accessGroup)
      ) {
        return null;
      }
      admitted.push(
        Object.freeze({
          accessGroup,
          reason: /** @type {'denied'|'unavailable'} */ (reason),
          ...(message === undefined ? {} : { message }),
        }),
      );
    }
    return admitted;
  }

  /**
   * The families named by admitted period-coordinate errors, read from the
   * last whole record per coordinate. A malformed or unsolicited coordinate,
   * or a record without the error-object shape, is ignored here as
   * everywhere: it never decides a family conflict. Key occupancy is not
   * checked: an occupied period coordinate means a key record naming the
   * family, which conflicts on its own.
   *
   * @param {any} response
   * @param {ResponseAssociation} association
   * @returns {Set<string>}
   */
  #admittedErrorFamilies(response, association) {
    const source = own(response, "errors");
    /** @type {Set<string>} */
    const families = new Set();
    if (!Array.isArray(source)) return families;
    for (const [coordinate, record] of lastWholeRecords(source, "coordinate").records) {
      const separator = coordinate.indexOf("|");
      if (separator === -1) continue;
      if (this.#errorAdmission(coordinate, association) !== null) continue;
      if (!isErrorObject(record)) continue;
      families.add(coordinate.slice(0, separator));
    }
    return families;
  }

  /** @param {string} coordinate @param {ResponseAssociation} association */
  #errorAdmission(coordinate, association) {
    const separator = coordinate.indexOf("|");
    if (separator === -1) {
      if (!isContentName(coordinate)) return "malformed_error";
      return this.#presentsContent(association, coordinate) ? null : "unsolicited_coordinate";
    }
    if (separator <= 0 || separator !== coordinate.lastIndexOf("|")) return "malformed_error";
    const accessGroup = coordinate.slice(0, separator);
    const t = coordinate.slice(separator + 1);
    if (!isAccessGroup(accessGroup) || !isPeriodKeyLabel(t)) return "malformed_error";
    if (association.presentsPeriodKey(accessGroup, t)) return null;
    if (typeof this.#chainKeyProfile?.acceptsPresentedErrorCoordinate === "function") {
      const admitted = this.#chainKeyProfile.acceptsPresentedErrorCoordinate(
        accessGroup,
        t,
        association.request,
      );
      if (typeof admitted !== "boolean") {
        throw dcaError(
          "bad_config",
          "a chainKeyProfile error-coordinate validator answers boolean",
        );
      }
      if (admitted) return null;
    }
    return association.presentsChainKey(accessGroup, t)
      ? "malformed_error"
      : "unsolicited_coordinate";
  }

  /**
   * @param {any} response @param {ResponseSections} sections @param {ResponseAssociation} association
   * @param {ResponseIssue[]} issues
   * @returns {ApplicationError[]}
   */
  #admittedErrors(response, sections, association, issues) {
    const source = own(response, "errors");
    if (source === undefined) return [];
    if (!Array.isArray(source) || source.length === 0) {
      issues.push({ code: "malformed_error" });
      return [];
    }
    const { records, stray } = lastWholeRecords(source, "coordinate");
    // An element without a coordinate is one malformed record; its siblings
    // keep their own admission.
    for (let i = 0; i < stray; i++) issues.push({ section: "errors", code: "malformed_error" });
    /** @type {ApplicationError[]} */
    const admitted = [];
    for (const [coordinate, record] of records) {
      const coordinateIssue = this.#errorAdmission(coordinate, association);
      if (coordinateIssue !== null) {
        issues.push({ section: "errors", code: coordinateIssue });
        continue;
      }
      const error = own(record, "error");
      const message = own(record, "message");
      if (
        !isErrorObject(record) ||
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

  /**
   * Compare response coordinates as structured identities, never by joining fields.
   *
   * @param {string} coordinate
   * @param {ResponseSections} sections
   * @param {ResponseAssociation} association
   */
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
    return sections.chainKeys.entries.some(
      ({ path: [group, label] }) =>
        group === accessGroup &&
        label === t &&
        this.#errorAdmission(coordinate, association) === null,
    );
  }

  /** @param {ResponseIssue[]} issues @param {string} section @param {ResponseIssue['code']} code */
  #issueOnce(issues, section, code) {
    if (!issues.some((issue) => issue.section === section && issue.code === code)) {
      issues.push({ section, code });
    }
  }

  /** @param {ResponseIssue[]} issues @param {string} section @param {number} count */
  #malformed(issues, section, count) {
    for (let i = 0; i < count; i++) issues.push({ section, code: "malformed_key" });
  }

  /** @param {string} t @param {object} parameters */
  #acceptsChainCoordinate(t, parameters) {
    // Only the chainCache branch asks, and the constructor admits a chainCache
    // only together with its profile.
    const profile = /** @type {ChainKeyProfile} */ (this.#chainKeyProfile);
    const accepted = profile.acceptsResponseCoordinate(t, parameters);
    if (typeof accepted !== "boolean") {
      throw dcaError(
        "bad_config",
        "a chainKeyProfile response-coordinate validator answers boolean",
      );
    }
    return accepted;
  }

  /**
   * @param {any} value
   * @param {DeliveredKeyOpener|null} opener
   * @param {KeyUsage[]} usages
   * @param {'contentKey'|'periodKey'|'chainKey'} keyKind
   * @param {boolean} directAllowed
   * @param {number} keyBytes - the width this section's values have under the
   *   profile this client resolves on. A value of another width is malformed
   *   here: it is not a key of this route, and admitting it would file
   *   material the wrap attempt could not use.
   * @param {boolean} [rawOnly] - a selected derivation kind: only bytes count
   * @returns {Promise<{ key: Uint8Array|CryptoKey, issue: null }|{ key: null, issue: 'malformed_key'|'unsupported_section' }>}
   */
  async #deliveredKey(value, opener, usages, keyKind, directAllowed, keyBytes, rawOnly = false) {
    const readerRevision = this.#reader.capture();
    if (typeof value === "string") {
      if (!directAllowed) return { key: null, issue: "unsupported_section" };
      // A direct key entry is admitted on its spelling as well as its width:
      // section 2.2 admits canonical unpadded base64url, and a key entry the
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
      key = this.#reader.accept(await opener.open(value, usages, keyKind), readerRevision);
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
    if (rawOnly)
      return key instanceof Uint8Array && key.length === keyBytes
        ? { key, issue: null }
        : { key: null, issue: "malformed_key" };
    return key !== null &&
      isDeliveredKeyOfWidth(key, keyBytes) &&
      (key instanceof globalThis.CryptoKey ? key.extractable === false : keyKind === "chainKey")
      ? { key, issue: null }
      : { key: null, issue: "malformed_key" };
  }

  /**
   * @param {DcaData} dcaData
   * @param {string} issuerName
   * @param {any} response
   * @param {ResponseSection} section
   * @param {Map<string, { kind: 'cache' }|null>} consumers
   * @param {DeliveredKeyOpener|null} opener
   * @param {ResponseIssue[]} issues
   * @param {Map<string, Map<string, boolean>>} periodKeyAdmissions - selected-extension
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
    periodKeyAdmissions,
    lease,
  ) {
    const readerRevision = this.#reader.capture();
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
      if (periodKeyAdmissions.get(accessGroup)?.get(t) === false) {
        issues.push({ section: "periodKeys", code: "malformed_key" });
        continue;
      }
      const publisher = this.#publisherOf(dcaData, true);
      const opened = this.#reader.accept(
        await this.#deliveredKey(
          value,
          opener,
          ["unwrapKey"],
          "periodKey",
          this.#acceptDirectFallback && this.#persistRawPeriodKeys,
          16,
        ),
        readerRevision,
      );
      if (opened.issue) {
        if (opened.issue === "malformed_key")
          issues.push({ section: "periodKeys", code: opened.issue });
        else this.#issueOnce(issues, "periodKeys", opened.issue);
        continue;
      }
      const delivery = { value, transport: own(response, "transport") };
      // A period consumer exists only when a cache was configured.
      this.#reader.accept(
        await /** @type {Cache} */ (this.#cache).put(accessGroup, t, opened.key, {
          publisher,
          issuerName,
          delivery,
          lease,
        }),
        readerRevision,
      );
      accepted++;
    }
    return accepted;
  }

  /**
   * @param {DcaData} dcaData
   * @param {string} issuerName
   * @param {ResponseSection} section
   * @param {object} lease
   * @param {ResponseIssue[]} issues
   * @param {DeliveredKeyOpener|null} opener
   */
  async #consumeChainKeys(dcaData, issuerName, section, lease, issues, opener) {
    const readerRevision = this.#reader.capture();
    if (!section.present) return 0;
    if (!this.#chainCache) {
      this.#issueOnce(issues, "chainKeys", "unsupported_section");
      return 0;
    }

    let accepted = 0;
    for (const {
      path: [accessGroup, cutoffT],
      value,
      parameters: chainParameters,
    } of section.entries) {
      const opened = this.#reader.accept(
        await this.#deliveredKey(
          value,
          opener,
          [],
          "chainKey",
          this.#acceptDirectFallback && this.#persistRawPeriodKeys,
          /** @type {any} */ (this.#constructionProfile).chainKeyBytes,
        ),
        readerRevision,
      );
      if (opened.issue) {
        if (opened.issue === "malformed_key")
          issues.push({ section: "chainKeys", code: opened.issue });
        else this.#issueOnce(issues, "chainKeys", opened.issue);
        continue;
      }
      // Step and Leaf read a chain key as bytes, so an opened key handle is
      // not a chain key at any width.
      if (!(opened.key instanceof Uint8Array)) {
        issues.push({ section: "chainKeys", code: "malformed_key" });
        continue;
      }
      const publisher = this.#publisherOf(dcaData, true);
      this.#reader.accept(
        await this.#chainCache.put(accessGroup, cutoffT, opened.key, {
          publisher,
          issuerName,
          lease,
          ...chainParameters,
        }),
        readerRevision,
      );
      accepted++;
    }
    return accepted;
  }

  /**
   * @param {string|undefined} publisher
   * @param {string} renderId
   * @param {ResponseSection} section
   * @param {DeliveredKeyOpener|null} opener
   * @param {ResponseIssue[]} issues
   */
  async #consumeContentKeys(publisher, renderId, section, opener, issues) {
    const readerRevision = this.#reader.capture();
    if (!section.present) return 0;
    this.#malformed(issues, "contentKeys", section.malformed);

    let accepted = 0;
    for (const {
      path: [contentName],
      value,
    } of section.entries) {
      // A contentKey is always the canonical 16-byte delivered value;
      // this section does not vary with route representation.
      const opened = this.#reader.accept(
        await this.#deliveredKey(
          value,
          opener,
          ["decrypt"],
          "contentKey",
          this.#acceptDirectFallback,
          CONTENT_KEY_BYTES,
        ),
        readerRevision,
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
   * its own. Direct hands over a base64url string in the same position. The
   * response-wide representation check classifies by JSON type instead; this
   * shape decides only whether an entry needs the opener and can be opened.
   * Whether wrapped is allowed follows from the association's immutable
   * request offer.
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
   * @param {(candidate: Uint8Array|CryptoKey, origin?: { kind: string }) => Promise<boolean>} [authenticate]
   * @returns {Promise<{
   *   key: Uint8Array|CryptoKey|null,
   *   origin: { kind: 'cached-period-key'|'cached-chain-key'|'missing', accessGroup?: string, t?: string },
   * }>}
   */
  async #fromCache(dcaData, contentName, lease, authenticate) {
    const readerRevision = this.#reader.capture();
    if (this.#candidateSources.length === 0) return { key: null, origin: { kind: "missing" } };

    const publisher = this.#publisherOf(dcaData, false);
    // Every wrap nonce frames the render ID's 16 decoded octets. Read it once
    // here, before the first await, so a later edit of the delivery cannot move
    // the attempts below to another render. A delivery whose ID is not 16
    // canonical octets has no wrap any nonce opens.
    const renderId = dcaData.renderId;
    if (typeof renderId !== "string" || binaryStringBytes(renderId)?.length !== 16) {
      return { key: null, origin: { kind: "missing" } };
    }
    for (const accessGroup of dcaData.accessGroupsFor(contentName)) {
      const entries = dcaData.sealedEntriesFor(contentName, accessGroup);
      if (entries.length === 0) continue;
      // Rival period keys for one entry share its nonce. This map lives for
      // this group of this call only, so no derived value outlives a reset.
      /** @type {Map<string, Uint8Array|null>} */
      const nonces = new Map();

      const chainIssuerNames = dcaData.chainIssuerNamesFor(accessGroup);
      // Selected chain suppliers may project an ordinary period response.
      // This is scoped to this family, never every issuer in the delivery.
      const issuerNames = [
        ...new Set([...dcaData.issuerNamesFor(accessGroup), ...chainIssuerNames]),
      ];
      // Actual chain derivation still uses only the selected chain suppliers.
      // Period-key trials are finite per authored access group. With one budget
      // across groups, an early group could spend it and leave a later
      // alternative route unattempted.
      const periodKeyBudget = { remaining: 64 };
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
        ordinaryPeriodHandled: this.#ordinaryPeriodHandled,
        lease,
        budget: periodKeyBudget,
      };
      for (const source of this.#candidateSources) {
        for await (const { entry, periodKey, origin } of source.attempts(context)) {
          this.#reader.check(readerRevision);
          // The nonce uses the coordinate the wrap was authored at: this
          // group's own name and the entry's own `t`. `origin` says where a
          // source found the key and is never part of the transcript.
          const t = own(entry, "t");
          const interpretation = this.#interpret(entry, renderId, contentName, accessGroup);
          if (interpretation === null || typeof t !== "string") continue;
          // One copy serves the nonce transcript and GCM, so both see the same bytes.
          const aad = interpretation.aad && Uint8Array.from(interpretation.aad);
          const memo = `${t}|${aad ? base64urlEncode(aad) : ""}`;
          let nonce = nonces.get(memo);
          if (nonce === undefined) {
            nonce = this.#reader.accept(
              await contentKeyWrapNonce({ renderId, contentName, accessGroup, t, aad }),
              readerRevision,
            );
            nonces.set(memo, nonce);
          }
          if (nonce === null) continue;
          const key = this.#reader.accept(
            await attemptContentKeyWrap(entry, periodKey, nonce, aad),
            readerRevision,
          );
          if (
            key !== null &&
            (!authenticate || this.#reader.accept(await authenticate(key, origin), readerRevision))
          )
            return { key, origin };
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
    const readerRevision = this.#reader.capture();
    return this.#reader.accept(
      await this.contentKeyWithOriginFor(dcaData, contentName, responseAttempt[0]),
      readerRevision,
    ).key;
  }
}
