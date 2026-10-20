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
// This view reads own properties only. The containers are keyed by names the
// publisher chose (contentName, accessGroup, issuerName), so `map[name]` would
// return Object.prototype.constructor for the name 'constructor'. The fixed
// fields (version, resource, resourceJWT) are a closed set and get one read
// each.
//
// The format sets the scope of each failure, and each check sits at that scope.
//
// The outer object is delivery-wide: `version` "1", a string `resourceJWT`, a
// `contentData` object, a non-empty `issuerData` map, and a `resource` object
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
// issuer-mediated route alone; a malformed group value loses only that group,
// and one malformed candidate inside an admitted array loses only itself. This
// view treats an issuer block missing its `sealed` container or a string
// `keyId` as an issuer this page does not carry, and the sibling
// issuer stays usable.
//
// This view checks every member name of a name-keyed map before it reads any
// member. The format's identifier section rejects the whole map when one member
// name falls outside the grammar; it does not skip that member. So one bad name
// in `contentData` or `issuerData` fails the delivery, a cached-wrap map keyed
// by anything but accessGroups supplies no cached route for its item, and a
// sealed route map keyed by anything but names of its kind supplies no route of
// that kind.
//
// This view checks the chain route map the same way as the other two, because
// it reads that map through the same route-map accessor: a `chainKeys`
// map keyed by anything but accessGroups supplies no chain route, and a present
// `chainKeys` that is not a non-array object supplies none either. The
// envelope read and the cached-walk coordinates stay off the outer gate; the
// file is short of the format there and nowhere else.

import { decodeCompactJwt } from "../core-shared/compactJwt.js";
import { normalizePublisherOrigin } from "../core-shared/publisherOrigin.js";
import { isAccessGroup, isContentName, isIssuerName } from "../core-shared/names.js";
import { own } from "../core-shared/wire.js";
import { dcaError } from "../core-shared/errors.js";
import { contentEncodingsFrom } from "./contentEncodings.js";
import { contentAad } from "../core-shared--client-publisher/contentAad.js";
import { contentHandlingIsValid } from "../core-shared--client-publisher/contentHandling.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";

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
 * Whether every own member name one identifier-keyed map carries is a name of
 * its kind. The format rejects such a map when one member name violates the
 * grammar, and it does not pass over the invalid name and read the siblings,
 * so a caller asks this of the whole map before it reads any member of it.
 *
 * @param {any} map - already through `isContainer`
 * @param {(name: unknown) => boolean} isName
 * @returns {boolean}
 */
function namesAdmit(map, isName) {
  return Object.keys(map).every((name) => isName(name));
}

/**
 * The same check for a map whose rejection fails the whole delivery instead
 * of one route. This function throws the refusal so every accessor that reads
 * through the map refuses the same way.
 *
 * @param {any} map - already through `isContainer`
 * @param {(name: unknown) => boolean} isName
 * @param {string} which - which map, for the message
 * @returns {any} the same map
 */
function refuseUnlessNamesAdmit(map, isName, which) {
  if (!namesAdmit(map, isName)) {
    throw dcaError("bad_page", `dca-data carries a ${which} name outside the grammar`);
  }
  return map;
}

/**
 * The selected issuer block, or undefined when the page carries none the format
 * admits. A block is usable only when it and its `sealed` member are non-array
 * objects and its `keyId` is a non-empty string. An unusable block
 * supplies no route at all, and a valid sibling issuer stays usable.
 *
 * @param {any} issuerData
 * @param {string} issuerName
 * @returns {any} the usable block, or undefined
 */
function usableIssuer(issuerData, issuerName) {
  const block = own(issuerData, issuerName);
  if (!isContainer(block)) return undefined;
  const keyId = own(block, "keyId");
  if (typeof keyId !== "string" || keyId.length === 0) return undefined;
  return isContainer(own(block, "sealed")) ? block : undefined;
}

/**
 * One kind of route map out of a usable block, or undefined when the block
 * carries no map of that kind the format admits. A container that is not a
 * non-array object supplies no route of its kind and leaves the other kind in
 * the same block alone.
 *
 * A map carrying a member name outside the grammar of the kind it is keyed by
 * is rejected whole, which costs that one route map and leaves the other kind
 * in the same block and the sibling issuer's maps alone. The chain-key
 * carrier is keyed by accessGroup and gets the same check; the extension
 * fixes the shape of a family rather than the spelling of its name.
 *
 * @param {any} block - already through `usableIssuer`
 * @param {string} kind - `contentKeys`, `periodKeys` or an extension carrier
 * @param {(name: unknown) => boolean} [isName] - the grammar the keys answer to
 * @returns {any} the route map, or undefined
 */
function routeMap(block, kind, isName) {
  const map = own(own(block, "sealed"), kind);
  if (!isContainer(map)) return undefined;
  if (isName !== undefined && !namesAdmit(map, isName)) return undefined;
  return map;
}

/**
 * Whether one period-key family supplies a route. The delivery format
 * requires a non-empty object for each `sealed.periodKeys[accessGroup]`.
 * A malformed family costs only that access group; a sibling family in the
 * same admitted map remains available for the client to relay.
 *
 * @param {unknown} family
 * @returns {boolean}
 */
function isPeriodKeyFamily(family) {
  return (
    family !== null &&
    typeof family === "object" &&
    !Array.isArray(family) &&
    Object.keys(family).length > 0
  );
}

/**
 * The cached-wrap map one record offers routes out of, or an empty map when it
 * offers none. The format holds `keys` to a non-empty non-array object of
 * accessGroup to a non-empty array. A malformed map container supplies no
 * cached route for that item rather than failing the item; a malformed group
 * value loses only that group. The issuer-mediated route for the same item is
 * independent of every cached route.
 *
 * An absent `keys` is an item with no cached path, which the format allows.
 *
 * @param {any} record
 * @returns {any} the admitted container, or an empty one
 */
function cachedWraps(record) {
  const keys = own(record, "keys");
  if (keys === null || typeof keys !== "object" || Array.isArray(keys)) return {};

  const accessGroups = Object.keys(keys);
  if (accessGroups.length === 0) return {};
  if (!namesAdmit(keys, isAccessGroup)) return {};
  return keys;
}

/**
 * Whether one publisher cached-wrap family has the container the format
 * requires. A malformed group value is not a route, but does not reject the
 * identifier-keyed map or suppress valid sibling groups.
 *
 * @param {unknown} entries
 * @returns {entries is any[]}
 */
function isCachedWrapFamily(entries) {
  return Array.isArray(entries) && entries.length > 0;
}

/**
 * Whether one array member is a candidate at all. A member that is not a
 * non-array object with string `t`, `nonce` and `key` supplies no candidate,
 * and its valid siblings under the same accessGroup stay.
 *
 * @param {any} entry
 * @returns {boolean}
 */
function isCandidate(entry) {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return false;
  return ["t", "nonce", "key"].every((member) => typeof own(entry, member) === "string");
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
    if (!isContainer(contentData)) bad("carries no contentData object");
    refuseUnlessNamesAdmit(contentData, isContentName, "contentData");
    const issuerData = own(data, "issuerData");
    if (!isContainer(issuerData) || Object.keys(issuerData).length === 0) {
      bad("carries no issuerData map");
    }
    refuseUnlessNamesAdmit(issuerData, isIssuerName, "issuerData");
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
    return usableIssuer(own(this.#admitted(), "issuerData"), issuerName);
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
   * The blob this issuer can open for one content item.
   *
   * @param {string} issuerName
   * @param {string} contentName
   * @returns {unknown}
   */
  sealedContentKeyFor(issuerName, contentName) {
    return own(routeMap(this.#issuer(issuerName), "contentKeys", isContentName), contentName);
  }

  /**
   * The whole carried period family for one accessGroup, by `t`. The client
   * cannot tell which period the article it reads next was rendered in, so
   * the family travels together and the overlap key covers the boundary.
   *
   * @param {string} issuerName
   * @param {string} accessGroup
   * @returns {unknown}
   */
  sealedPeriodKeysFor(issuerName, accessGroup) {
    const family = own(
      routeMap(this.#issuer(issuerName), "periodKeys", isAccessGroup),
      accessGroup,
    );
    return isPeriodKeyFamily(family) ? family : undefined;
  }

  /**
   * The terminal chain keys this issuer can open for one accessGroup.
   * They stay distinct from period keys because one grants derivation
   * reach and the other opens exactly one period.
   *
   * @param {string} issuerName
   * @param {string} accessGroup
   * @returns {unknown}
   */
  sealedChainKeysFor(issuerName, accessGroup) {
    const family = own(routeMap(this.#issuer(issuerName), "chainKeys", isAccessGroup), accessGroup);
    return isContainer(family) ? family : undefined;
  }

  /**
   * The accessGroups one content item is wrapped under, in the order the
   * page lists them. Empty for an item with no cached path.
   *
   * @param {string} contentName
   * @returns {string[]}
   */
  accessGroupsFor(contentName) {
    const wraps = cachedWraps(own(this.#contentData(), contentName));
    return Object.keys(wraps).filter((accessGroup) => isCachedWrapFamily(own(wraps, accessGroup)));
  }

  /**
   * The wrapped contentKey entries this item carries under one accessGroup -
   * `{ nonce, key }` each, and a list because one item may be wrapped under
   * more than one period.
   *
   * @param {string} contentName
   * @param {string} accessGroup
   * @returns {any[]}
   */
  sealedEntriesFor(contentName, accessGroup) {
    const entries = own(cachedWraps(own(this.#contentData(), contentName)), accessGroup);
    return isCachedWrapFamily(entries) ? entries.filter(isCandidate) : [];
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
   * The issuers carrying one kind of route map for one accessGroup. Both kinds
   * go through the same identifier admission, so a map naming something outside
   * the accessGroup grammar supplies no route of its kind for any issuer.
   *
   * @param {'periodKeys'|'chainKeys'} kind
   * @param {string} accessGroup
   * @returns {string[]}
   */
  #issuerNamesOf(kind, accessGroup) {
    const issuerData = own(this.#data, "issuerData");
    if (issuerData === null || typeof issuerData !== "object") return [];
    refuseUnlessNamesAdmit(issuerData, isIssuerName, "issuerData");

    /** @type {string[]} */
    const names = [];
    for (const issuerName of Object.keys(issuerData)) {
      const block = usableIssuer(issuerData, issuerName);
      const routes = routeMap(block, kind, isAccessGroup);
      const family = own(routes, accessGroup);
      if (kind === "periodKeys" ? isPeriodKeyFamily(family) : family !== undefined) {
        names.push(issuerName);
      }
    }
    return names;
  }

  /**
   * The item inventory the page declares. The format requires it, so a page
   * carrying none is a bad page rather than a page with no items on it. An
   * old document carrying the retired parallel maps fails this check.
   *
   * @returns {any}
   */
  #contentData() {
    const inventory = own(this.#data, "contentData");
    if (inventory === null || typeof inventory !== "object" || Array.isArray(inventory)) {
      throw dcaError("bad_page", "dca-data carries no contentData");
    }
    return refuseUnlessNamesAdmit(inventory, isContentName, "contentData");
  }

  /**
   * The contentNames the page declares records for: the items it ships
   * encrypted, and a load naming nothing in particular asks the issuer to
   * open them.
   *
   * @returns {string[]}
   */
  contentNames() {
    return Object.keys(this.#contentData());
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
    const record = own(this.#contentData(), contentName);
    if (record === undefined) return undefined;
    if (record === null || typeof record !== "object" || Array.isArray(record)) {
      throw dcaError("bad_page", `the contentData record for "${contentName}" is not an object`);
    }
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
