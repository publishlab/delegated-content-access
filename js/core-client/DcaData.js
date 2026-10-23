// @ts-check

// One page's `dca-data`, read through fixed accessors. A page adapter parses
// the delivery format and hands the parsed object here; the request builder
// and the content-key resolver read it through this view rather than walking
// the nested containers themselves.
//
// This view checks the shape of what it reads and makes no access decision:
// the issuer verifies the publisher's signature over the resource, applies its
// policy, and answers with what opens. The view checks the shape the format
// states in the accessor that a caller derives a request or a key from.
//
// Every accessor re-reads the underlying object at call time and caches
// nothing, so a caller threads one instance and still sees mid-load mutations.
// Do not memoize. Resource coordinates come from the required signed-envelope
// payload. Decoding does not authenticate it.
//
// This view reads own properties only. Items and issuer blocks arrive as
// arrays of records named by `contentName` and `issuerName`; the view looks
// them up through a Map built per read, so a name such as 'constructor' never
// reaches Object.prototype. The fixed fields (version, resource, resourceJWT)
// are a closed set and get one read each.
//
// Several records with one name resolve to the last whole record, and nothing
// merges: an item's `keys` or an issuer's `keyId` never comes from an earlier
// record with the same name. Several wrap records at one (accessGroup, period)
// are candidate alternatives, and the view hands on every one of them.
//
// The format sets the scope of each failure, and each check sits at that scope.
//
// The outer object is delivery-wide: `version` "1", a string `resourceJWT`, a
// `contentData` array, a non-empty `issuerData` array, and a `resource` object
// when the page carries one. `#admitted` holds them, and the accessors a
// request is derived from read through it, so a delivery short of one of them
// answers nothing a caller sends.
//
// A failure in one item's record stays with that item: `contentDataFor` checks
// `contentType` and the encoding list, so a malformed record fails
// where the item is used and leaves its siblings alone. Carried `nonce` and
// `aad` members are unknown and ignored, whatever their types. `contentItemFor`
// captures the values an opening uses, with the content AAD built from them,
// in one synchronous read. `contentData`
// itself is required, so a page carrying none is a bad page rather than a page
// with no items.
//
// A failure in one route stays with that route. A cached-wrap container the
// format does not admit supplies no cached route for its item and leaves the
// issuer-mediated route alone, and one malformed candidate inside an admitted
// collection loses only itself. This
// view treats an issuer block missing its `sealed` container or a string
// `keyId` as an issuer this page does not carry, and the sibling
// issuer stays usable.
//
// This view checks the identity of every record in a collection before it
// reads any record. The format's identifier section rejects the whole
// collection when one record's identity is missing or falls outside the
// grammar; it does not skip that record. One bad identity in `contentData` or
// `issuerData` therefore fails the delivery. An element that is not a
// non-array object is skipped and leaves its siblings usable. A cached-wrap
// collection with an invalid accessGroup supplies no cached route for its
// item, and a sealed route collection with an invalid identity supplies no
// route of that kind.
//
// This view checks sealed `chainKeys` through the same accessor as the other
// route collections. It requires an array of records named by `accessGroup`;
// an invalid identity rejects that collection, while a non-record element is
// skipped. A present `chainKeys` that is not an array supplies no chain route.
// The envelope read and the cached-walk coordinates stay off the outer gate; the
// file is short of the format there and nowhere else.

import { decodeCompactJwt } from "../core-shared/compactJwt.js";
import { normalizePublisherOrigin } from "../core-shared/publisherOrigin.js";
import { isAccessGroup, isContentName, isIssuerName } from "../core-shared/names.js";
import { own, setOwn } from "../core-shared/wire.js";
import { dcaError } from "../core-shared/errors.js";
import { contentEncodingsFrom } from "./contentEncodings.js";
import { contentAad } from "../core-shared--client-publisher/contentAad.js";
import { contentHandlingIsValid } from "../core-shared--client-publisher/contentHandling.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { recordsByName } from "../core-shared--client-publisher/deliveryRecords.js";

// Local item-opening resource bound, retained from the former signing-input
// admission. Check before compact-token splitting, decoding or JSON traversal.
// This is an implementation limit, not a protocol-wide wire ceiling.
const MAX_CONTENT_TOKEN_CHARACTERS = 1024 * 1024 + 2;

/**
 * One item as an opening uses it, captured once from the live delivery.
 * `contentEncodings` is empty when the record declares none.
 *
 * @typedef {Readonly<{
 *   contentName: string,
 *   contentType: string,
 *   contentEncodings: readonly string[],
 *   contentAad: Uint8Array,
 * }>} ContentItemView
 */

/**
 * Whether one wire value is a container at all. Every map and record the format
 * declares is a non-array object, so an array, a scalar and null are none.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isContainer(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * One descriptor collection whose rejection fails the whole delivery, as a
 * Map from name to its last whole record. This function throws the refusal so
 * every accessor that reads through the collection refuses the same way.
 *
 * @param {unknown} collection - already through `Array.isArray`
 * @param {string} member - `contentName` or `issuerName`
 * @param {(name: unknown) => boolean} isName
 * @param {string} which - which collection, for the message
 * @returns {Map<string, any>}
 */
function refuseUnlessRecordsAdmit(collection, member, isName, which) {
  const records = recordsByName(collection, member, isName);
  if (records === null) {
    throw dcaError("bad_page", `dca-data carries a ${which} record outside the grammar`);
  }
  return records;
}

/**
 * The selected issuer block, or undefined when the page carries none the format
 * admits. A block is usable only when its `sealed` member is a non-array
 * object and its `keyId` is a non-empty string. An unusable block
 * supplies no route at all, and a valid sibling issuer stays usable.
 *
 * @param {Map<string, any>} issuerBlocks - the admitted `issuerData` by name
 * @param {string} issuerName
 * @returns {any} the usable block, or undefined
 */
function usableIssuer(issuerBlocks, issuerName) {
  const block = issuerBlocks.get(issuerName);
  if (!isContainer(block)) return undefined;
  const keyId = own(block, "keyId");
  if (typeof keyId !== "string" || keyId.length === 0) return undefined;
  return isContainer(own(block, "sealed")) ? block : undefined;
}

/**
 * The fields that name a coordinate in each sealed route collection, with the
 * grammar of the identity field. A record's other coordinate field (`period`,
 * `cutoff`) is only checked to be a string here; the issuer and the selected
 * profile own its grammar.
 */
const ROUTE_FIELDS = Object.freeze({
  contentKeys: Object.freeze({ identity: "contentName", isName: isContentName, label: null }),
  periodKeys: Object.freeze({ identity: "accessGroup", isName: isAccessGroup, label: "period" }),
  chainKeys: Object.freeze({ identity: "accessGroup", isName: isAccessGroup, label: "cutoff" }),
});

/**
 * One kind of sealed route collection out of a usable block, as the records
 * that can supply a candidate, or undefined when the block carries no
 * collection of that kind the format admits. A container that is not an
 * array supplies no route of its kind and leaves the other kinds in the same
 * block alone.
 *
 * A record whose identity field is missing or outside its grammar rejects the
 * whole collection, which costs that one route kind and leaves the other kinds
 * in the same block and the sibling issuers' collections alone. An element
 * that is not a non-array object, or a record without a string `period` or
 * `cutoff`, supplies no candidate and leaves its siblings. Several records at
 * one coordinate all stay: they are candidate alternatives, and the client
 * relays each one.
 *
 * @param {any} block - already through `usableIssuer`
 * @param {'contentKeys'|'periodKeys'|'chainKeys'} kind
 * @returns {Record<string, unknown>[]|undefined}
 */
function routeRecords(block, kind) {
  const collection = own(own(block, "sealed"), kind);
  if (!Array.isArray(collection)) return undefined;
  const { identity, isName, label } = ROUTE_FIELDS[kind];
  /** @type {Record<string, unknown>[]} */
  const records = [];
  for (const record of collection) {
    if (!isContainer(record)) continue;
    if (!isName(own(record, identity))) return undefined;
    if (label !== null && typeof own(record, label) !== "string") continue;
    records.push(record);
  }
  return records;
}

/**
 * The records of one route kind for one identity, in page order, or
 * undefined when the block offers none of that kind for it.
 *
 * @param {any} block - already through `usableIssuer`
 * @param {'contentKeys'|'periodKeys'|'chainKeys'} kind
 * @param {string} name - the contentName or accessGroup
 * @returns {Record<string, unknown>[]|undefined}
 */
function routeFamily(block, kind, name) {
  const { identity } = ROUTE_FIELDS[kind];
  const family = (routeRecords(block, kind) ?? []).filter(
    (record) => own(record, identity) === name,
  );
  return family.length > 0 ? family : undefined;
}

/**
 * The wrap records one item record offers cached routes out of, or an empty
 * list when it offers none. The format holds `keys` to a non-empty array of
 * wrap records. A malformed container, or a collection with a record whose
 * `accessGroup` is missing or outside the grammar, supplies no cached route
 * for that item rather than failing the item. An element that is not a
 * record carries no group and is left out here; `isCandidate` drops it too.
 * The issuer-mediated route for the same item is independent of every cached
 * route.
 *
 * An absent `keys` is an item with no cached path, which the format allows.
 *
 * @param {any} record
 * @returns {any[]} the admitted wrap records, in page order
 */
function cachedWraps(record) {
  const keys = own(record, "keys");
  if (!Array.isArray(keys) || keys.length === 0) return [];
  const records = keys.filter(isContainer);
  if (!records.every((entry) => isAccessGroup(own(entry, "accessGroup")))) return [];
  return records;
}

/**
 * Whether one wrap record is a candidate at all. A record without string
 * `period` and `key` supplies no candidate, and its valid siblings stay. The
 * wrap nonce is derived from the coordinate, so a carried `nonce` member is
 * unknown and ignored, whatever its type.
 *
 * @param {any} entry - already through `cachedWraps`
 * @returns {boolean}
 */
function isCandidate(entry) {
  return ["period", "key"].every((member) => typeof own(entry, member) === "string");
}

/**
 * One wrap record as a candidate source reads it: the record's own members
 * without its coordinate fields, and its `period` label as `t`, the name the
 * period-key profile, the caches and the wrap nonce use. A copy, so a later
 * edit of the page cannot move a candidate a caller already holds.
 *
 * @param {any} entry - already through `isCandidate`
 * @returns {Record<string, unknown>}
 */
function candidateEntry(entry) {
  /** @type {Record<string, unknown>} */
  const view = {};
  for (const member of Object.keys(entry)) {
    if (member !== "accessGroup" && member !== "period") setOwn(view, member, entry[member]);
  }
  setOwn(view, "t", own(entry, "period"));
  return view;
}

export class DcaData {
  /** @type {any} */
  #data;

  /** @type {string|undefined} */
  #publisherOrigin;

  /**
   * @param {unknown} data - one parsed `dca-data`, still untrusted
   * @param {{ publisherOrigin?: string }} [context] - delivery context, not a
   *   dca-data member. Browser markup supplies the page origin; object and
   *   edge delivery supply their equivalent explicitly.
   */
  constructor(data, context = {}) {
    for (const name of Object.keys(context)) {
      if (name !== "publisherOrigin") {
        throw dcaError("unsupported_option", `DcaData context has no ${name}`);
      }
    }
    const publisherOrigin =
      context.publisherOrigin === undefined
        ? undefined
        : normalizePublisherOrigin(context.publisherOrigin);
    if (context.publisherOrigin !== undefined && publisherOrigin === null) {
      throw dcaError("bad_config", "DcaData publisherOrigin is a canonical HTTP(S) origin");
    }
    this.#data = data;
    this.#publisherOrigin = publisherOrigin ?? undefined;
  }

  /**
   * The outer object and the members the format requires of it, admitted
   * before this delivery answers anything a request or a content key is
   * derived from. The admission is one read of the same live data every
   * accessor reads, so a delivery edited mid-load is admitted as it stands at
   * the call rather than as it stood at construction.
   *
   * The accessor that uses an item record or an issuer block checks its
   * detail, as the format permits. The outer requirement cannot be deferred,
   * because the whole delivery fails on it.
   *
   * @returns {any} the delivery, admitted
   */
  #admitted() {
    const data = this.#data;
    const bad = (/** @type {string} */ why) => {
      throw dcaError("bad_page", `dca-data ${why}`);
    };

    if (!isContainer(data)) bad("is not an object");
    if (own(data, "version") !== "1") bad('carries no version "1"');
    if (typeof own(data, "resourceJWT") !== "string") bad("carries no resourceJWT string");
    const contentData = own(data, "contentData");
    if (!Array.isArray(contentData)) bad("carries no contentData array");
    refuseUnlessRecordsAdmit(contentData, "contentName", isContentName, "contentData");
    const issuerData = own(data, "issuerData");
    if (!Array.isArray(issuerData) || issuerData.length === 0) {
      bad("carries no issuerData array");
    }
    refuseUnlessRecordsAdmit(issuerData, "issuerName", isIssuerName, "issuerData");
    const resource = own(data, "resource");
    if (resource !== undefined && !isContainer(resource)) {
      bad("carries a resource that is not an object");
    }
    return data;
  }

  /** @returns {unknown} */
  get version() {
    return own(this.#admitted(), "version");
  }

  /** @returns {unknown} */
  get resource() {
    return own(this.#data, "resource");
  }

  /**
   * The render every blob on this page is bound to, read without
   * authentication from the required envelope payload.
   *
   * @returns {unknown}
   */
  get renderId() {
    return own(decodeCompactJwt(own(this.#data, "resourceJWT")).payload, "renderId");
  }

  /**
   * The publisher origin supplied by the delivery boundary. It partitions
   * the client cache but grants nothing and is never read from resourceJWT.
   *
   * @returns {string|undefined}
   */
  get publisherOrigin() {
    return this.#publisherOrigin;
  }

  /** @returns {unknown} */
  get resourceJWT() {
    return own(this.#admitted(), "resourceJWT");
  }

  /**
   * One issuer's block as the format admits it, read at call time like every
   * other accessor here.
   *
   * @param {string} issuerName
   * @returns {any} the usable block, or undefined
   */
  #issuer(issuerName) {
    const issuerData = own(this.#admitted(), "issuerData");
    return usableIssuer(
      refuseUnlessRecordsAdmit(issuerData, "issuerName", isIssuerName, "issuerData"),
      issuerName,
    );
  }

  /**
   * Whether the page carries a usable block for this issuer. A client asking
   * about an issuer the publisher never sealed for has nothing to send, and
   * neither does a client asking about one whose block the format does not
   * admit. A request is derived from the block, its `sealed` member,
   * and `keyId`, so this view treats a block missing any of them
   * as an issuer this page does not carry.
   *
   * @param {string} issuerName
   * @returns {boolean}
   */
  hasIssuer(issuerName) {
    return this.#issuer(issuerName) !== undefined;
  }

  /**
   * Which of the issuer's keys sealed this render, when the page says.
   *
   * @param {string} issuerName
   * @returns {unknown}
   */
  keyIdFor(issuerName) {
    return own(this.#issuer(issuerName), "keyId");
  }

  /**
   * The envelope procedure this issuer block selects, as the page carries it.
   * Undefined means the block selects the key's ordinary procedure, when the
   * issuer's configuration permits it. The
   * client relays the value and never interprets it: only the issuer knows
   * which procedures its key permits.
   *
   * @param {string} issuerName
   * @returns {unknown}
   */
  envelopeFor(issuerName) {
    return own(this.#issuer(issuerName), "envelope");
  }

  /**
   * The blobs this issuer can open for one content item: every `key` of the
   * item's `{contentName, key}` records, in page order. Several are candidate
   * alternatives, so the client relays each; empty when the block offers none.
   * A value is handed on unchecked; the request builder relays only a
   * canonical one.
   *
   * @param {string} issuerName
   * @param {string} contentName
   * @returns {unknown[]}
   */
  sealedContentKeysFor(issuerName, contentName) {
    return (routeFamily(this.#issuer(issuerName), "contentKeys", contentName) ?? []).map((record) =>
      own(record, "key"),
    );
  }

  /**
   * The whole carried period family for one accessGroup: its
   * `{accessGroup, period, key}` records as the page carries them, rivals at
   * one period included. The client cannot tell which period the article it
   * reads next was rendered in, so the family travels together and the
   * overlap key covers the boundary.
   *
   * @param {string} issuerName
   * @param {string} accessGroup
   * @returns {Record<string, unknown>[]|undefined}
   */
  sealedPeriodKeysFor(issuerName, accessGroup) {
    return routeFamily(this.#issuer(issuerName), "periodKeys", accessGroup);
  }

  /**
   * The terminal chain keys this issuer can open for one accessGroup: its
   * `{accessGroup, cutoff, key}` records as the page carries them. They stay
   * distinct from period keys because one grants derivation reach and the
   * other opens exactly one period.
   *
   * @param {string} issuerName
   * @param {string} accessGroup
   * @returns {Record<string, unknown>[]|undefined}
   */
  sealedChainKeysFor(issuerName, accessGroup) {
    return routeFamily(this.#issuer(issuerName), "chainKeys", accessGroup);
  }

  /**
   * The accessGroups one content item is wrapped under, in the order the
   * page lists them. Empty for an item with no cached path.
   *
   * @param {string} contentName
   * @returns {string[]}
   */
  accessGroupsFor(contentName) {
    const wraps = cachedWraps(this.#contentData().get(contentName));
    return [...new Set(wraps.map((entry) => own(entry, "accessGroup")))];
  }

  /**
   * The wrapped contentKey entries this item carries under one accessGroup -
   * `{ t, key }` each, plus any other member the record carries, such as an
   * extension's marker. A list because one item may be wrapped under more than
   * one period, and because several records at one period are all candidates:
   * none replaces another. The wire names the label `period`; this view hands
   * it on as `t`.
   *
   * @param {string} contentName
   * @param {string} accessGroup
   * @returns {any[]}
   */
  sealedEntriesFor(contentName, accessGroup) {
    return cachedWraps(this.#contentData().get(contentName))
      .filter((entry) => own(entry, "accessGroup") === accessGroup && isCandidate(entry))
      .map(candidateEntry);
  }

  /**
   * The issuers this page entrusts one accessGroup to: the ones the publisher
   * sealed that family's periodKeys for. A key granted by any of them opens
   * the same items here, so a cache keyed by issuer takes one from any of
   * them and from nobody else.
   *
   * Read off the page rather than carried in from the client's configuration,
   * because the publisher decides which issuer holds which family, and the
   * client decides only who to ask.
   *
   * @param {string} accessGroup
   * @returns {string[]} in the order the page lists them
   */
  issuerNamesFor(accessGroup) {
    return this.#issuerNamesOf("periodKeys", accessGroup);
  }

  /**
   * The issuers this page entrusts one accessGroup's chain-key route to: the
   * ones the publisher sealed that family's `chainKeys` for. It is a list
   * of its own because a publisher may seal the chain-key route and the
   * period-key route for different issuers, and because an extension member
   * never decides which issuer a base period key may be read under.
   *
   * @param {string} accessGroup
   * @returns {string[]} in the order the page lists them
   */
  chainIssuerNamesFor(accessGroup) {
    return this.#issuerNamesOf("chainKeys", accessGroup);
  }

  /**
   * The issuers carrying one kind of route collection for one accessGroup.
   * Both kinds go through the same identifier admission, so an issuer whose
   * collection names something outside the accessGroup grammar supplies no
   * route of that kind.
   *
   * @param {'periodKeys'|'chainKeys'} kind
   * @param {string} accessGroup
   * @returns {string[]}
   */
  #issuerNamesOf(kind, accessGroup) {
    const issuerData = own(this.#data, "issuerData");
    if (!Array.isArray(issuerData)) return [];
    const issuerBlocks = refuseUnlessRecordsAdmit(
      issuerData,
      "issuerName",
      isIssuerName,
      "issuerData",
    );

    /** @type {string[]} */
    const names = [];
    for (const issuerName of issuerBlocks.keys()) {
      const block = usableIssuer(issuerBlocks, issuerName);
      if (routeFamily(block, kind, accessGroup) !== undefined) names.push(issuerName);
    }
    return names;
  }

  /**
   * The item inventory the page declares, by name. The format requires it, so
   * a page carrying none is a bad page rather than a page with no items on it.
   * An old document carrying the retired parallel maps, or the name-keyed map
   * this collection replaced, fails this check.
   *
   * @returns {Map<string, any>}
   */
  #contentData() {
    const inventory = own(this.#data, "contentData");
    if (!Array.isArray(inventory)) {
      throw dcaError("bad_page", "dca-data carries no contentData");
    }
    return refuseUnlessRecordsAdmit(inventory, "contentName", isContentName, "contentData");
  }

  /**
   * The contentNames the page declares records for: the items it ships
   * encrypted, and a load naming nothing in particular asks the issuer to
   * open them.
   *
   * @returns {string[]}
   */
  contentNames() {
    return [...this.#contentData().keys()];
  }

  /**
   * One item's record: what it was encrypted under, and the wrapped
   * contentKey candidates under `keys` when the page offers a cached path.
   * Undefined when the page declares no such item.
   *
   * This method checks the record's shape because the open path reads the
   * record through it. Carried `nonce` and `aad` members are ignored whatever
   * their types. The client rebuilds content AAD in `contentItemFor`.
   *
   * @param {string} contentName
   * @returns {unknown}
   */
  contentDataFor(contentName) {
    const record = this.#contentData().get(contentName);
    if (record === undefined) return undefined;
    if (typeof own(record, "contentType") !== "string") {
      throw dcaError(
        "bad_page",
        `the contentData record for "${contentName}" carries no contentType`,
      );
    }
    contentEncodingsFrom(record, contentName);
    return record;
  }

  /**
   * One item captured synchronously from the live delivery: admitted handling
   * metadata and AAD computed from its JWT renderId and contentName. A caller
   * keeps these values and the ciphertext across asynchronous key resolution.
   * Invalid render/name or handling inputs fail this item as `bad_page`.
   * The frozen view's AAD bytes still need a private copy before an await.
   *
   * @param {string} contentName
   * @returns {ContentItemView|null}
   */
  contentItemFor(contentName) {
    const token = own(this.#admitted(), "resourceJWT");
    const record = this.contentDataFor(contentName);
    if (record === undefined) return null;
    if (typeof token !== "string" || token.length > MAX_CONTENT_TOKEN_CHARACTERS) {
      throw dcaError("bad_page", `the resourceJWT for "${contentName}" exceeds the local limit`);
    }
    const contentType = own(record, "contentType");
    const contentEncodings = Object.freeze(contentEncodingsFrom(record, contentName));
    let renderId;
    try {
      renderId = own(decodeCompactJwt(token).payload, "renderId");
      // The wire renderId is canonical unpadded base64url for sixteen octets.
      const bytes = binaryStringBytes(renderId);
      if (bytes === null || bytes.length !== 16) throw new Error("invalid renderId");
    } catch {
      throw dcaError("bad_page", `the renderId for "${contentName}" is malformed`);
    }
    const aad = contentAad({ renderId, contentName });
    if (
      aad === null ||
      typeof contentType !== "string" ||
      !contentHandlingIsValid(contentType, contentEncodings)
    ) {
      throw dcaError(
        "bad_page",
        `the content inputs for "${contentName}" are malformed or over the local limits`,
      );
    }
    return Object.freeze({ contentName, contentType, contentEncodings, contentAad: aad });
  }

  /**
   * The parsed page data itself, for a caller that has to hand it on
   * unchanged. This view hands back the object it was constructed from.
   *
   * @returns {any}
   */
  toObject() {
    return this.#data;
  }
}
