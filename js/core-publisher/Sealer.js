// @ts-check
//
// The publisher side. Collects the items of one render, then produces the
// dca-data a page carries and the sealed ciphertext beside it.
//
// This module: one contentKey per content item, sealed with ECDH P-256 for
// each issuer whose plan selects that item's contentName, plus the cached
// path - a periodKey per (accessGroup, t) taken from the injected
// `periodKeySupply`, wrapping each contentKey into that item's `contentData`
// record and sealed under `sealed.periodKeys` for each issuer whose plan
// supplies that group, and both signed envelopes over the result.
//
// The publisher signs the resource as `resourceJWT`, and an issuer acts on that
// signature: the claims it reads when deciding access came from the publisher
// and not from the client that forwarded them. Every sealed blob of this render
// is bound to its `renderId`, which is why one signed copy of it is enough.
//
// Each render carries one publisher context origin. The publisher configures
// it instead of passing it per call: it is signed as `resourceJWT.origin`. In
// the browser-origin profile, the issuer compares it with the observed HTTP
// `Origin` before opening anything. It does not identify a JSON fetch or
// storage location. A publisher using two page origins renders once per origin.
//
// The blobs travel through the client, so each one is sealed and bound to its own
// coordinate (`js/core-shared--publisher-issuer/bind.js`). A blob presented
// under another name, or lifted into another render, does not open. The
// coordinate is sealed into the blob rather than carried beside it.
//
// Signing keys are plural and keyed by `kid`, which the header carries. A
// rotation changes which one signs; the markup an edge cache is still serving
// carries the kid of the key that signed it, and the issuer picks by kid.
//
// A publisher without a `periodKeySupply` has no periodKeys to derive - the
// content-key-only case - so an item names no accessGroup and its record carries no
// `keys` member at all. A publisher holding a supply wraps each item under the
// groups that item names, and each group's periodKey unwraps the item's
// contentKey. Period access is optional per item: an item that names no group
// carries no `keys` member and relies on its item content-key route.
//
// The two paths carry the same contentKey. The content-key path hands it to
// one client for one render; the cached path hands out the periodKey that
// unwraps it, and every article of that family and period unwraps with the
// same periodKey.
//
// Each contentKey and renderId comes from the injected `random`; `issuedAt`
// and every `t` come from the injected `clock`. Ordinary ECDH envelopes use a
// fresh internally generated ephemeral pair and an implicit zero nonce.
// A period-key wrap draws no
// nonce: it derives one from the render, item, group, period and selected aad.
//
// A composition may take two roles here, at two different scopes. The
// content-key wrap strategy is selected once for the render, because an
// item record's `keys` is emitted once and every issuer reads the same
// entries. The issuer supply plan is asked once per issuer, and says only
// what that issuer is supplied. Both are settled before this module draws a
// random byte, asks the period-key supply, seals to an issuer or signs. Base
// then executes plans that can no longer change.
//
// A selected contribution may add per-item work through `itemPreparations`.
// It names the items it gives a route before anything is drawn, so the route
// check still runs first. After the render id and every item's fresh content key
// are drawn, it returns signed claims,
// item record members, issuer sealed sections and page members. The resource
// is signed after that and the items are encrypted last, so a claim may commit
// to a content key without a cycle. Base reads none of those members; it
// refuses one that names a member base writes or another contribution wrote.

import { base64urlEncode } from "../core-shared/codec.js";
import { encrypt, NONCE_BYTES } from "../core-shared/aead.js";
import { periodsFor, settledPeriod } from "../core-shared--publisher-issuer/periodKeys.js";
import { sign } from "../core-shared--publisher-issuer/jwt.js";
import { AAD_DELIMITER, validateResourceId } from "../core-shared--client-publisher/names.js";
import { contentAad } from "../core-shared--client-publisher/contentAad.js";
import { contentKeyWrapNonce } from "../core-shared/contentKeyWrapNonce.js";
import { contentHandlingIsValid } from "../core-shared--client-publisher/contentHandling.js";
import { validateAccessGroup, validateContentName } from "../core-shared/names.js";
import { formatT, isPeriodKeyLabel } from "../core-shared/periodLabels.js";
import { dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";
import { chainMemberLimit } from "../core-shared/chainMemberLimit.js";
import {
  inspectPeriodGeometryBounds,
  periodGeometriesAgree,
  MAX_CHAIN_MEMBERS_PER_FAMILY,
} from "../core-shared/geometryBounds.js";
import { RENDER_ID_BYTES, validateRenderId } from "../core-shared--publisher-issuer/bind.js";
import {
  assertCompleteIssuerRoutes,
  normalizedIssuerSupplyPlan,
  suppliesNothing,
} from "./issuerSupplyPlan.js";
import { validatePublisherConfig } from "./publisherConfig.js";
import { assertIssuerRequestBudget } from "./issuerRequestBudget.js";
import {
  isContentRepresentation,
  normalizeContentRepresentation,
} from "./contentRepresentation.js";

/** Re-exported for callers that generate publisher fixtures. */
export { RENDER_ID_BYTES };

/** DCA data format version this sealer emits. */
const VERSION = "1";

/** Canonical AES-128 content key. */
const CONTENT_KEY_BYTES = 16;

/**
 * Both carriers receive their binding and the injected random source. The
 * ordinary RSA-OAEP and ECDH procedures do not consume that source; ECDH
 * generates a fresh ephemeral pair internally and uses an implicit zero nonce. An
 * issuer that selects an extension procedure adds `envelope`, which the
 * configured key sealing must implement; the default procedure adds nothing.
 *
 * @param {{ bytes: (n: number) => Uint8Array }} random
 * @param {{ renderId: string } & Omit<EphemeralContext, 'issuerName'>} binding
 * @param {string} [envelope]
 * @returns {any}
 */
function carrierOptions(random, binding, envelope) {
  const options = {
    random,
    binding,
    ...(envelope === undefined ? {} : { envelope }),
  };
  return options;
}

/**
 * An issuer this publisher seals for, as configured at onboarding.
 *
 * @typedef {object} IssuerConfig
 * @property {string} issuerName
 * @property {string} keyId
 * @property {string} algorithm - the envelope provisioning token, 'ecdh-p256' or 'rsa-oaep'
 * @property {CryptoKey} publicKey
 * @property {Partial<typeof import('../core-shared/requestLimits.js').DEFAULT_REQUEST_LIMITS>} [limits] - trusted endpoint caps; omitted values use reference deployment assumptions
 * @property {number} [maxChainMembersPerMessage] - trusted chain supply capacity, default 16; higher values exceed current specification bounds
 * @property {number} [clientRequestExtraBytes] - bound for client-added serialized fields; absent leaves complete byte compatibility unverified
 * @property {string} [envelope] - an extension envelope procedure for every
 *   seal to this issuer, written into its block; absent selects `algorithm`
 */

/**
 * @typedef {object} ContentItem
 * @property {string} name
 * @property {Uint8Array} bytes
 * @property {string} contentType
 * @property {readonly string[]} contentEncodings
 * @property {string[]} accessGroups
 * @property {Record<string, unknown>} options - the declared extension item
 *   options, as JSON copies taken when the item was added
 */

/**
 * The read-only view of one item a contribution receives.
 *
 * @typedef {object} PreparedItemView
 * @property {string} name
 * @property {string} contentType
 * @property {readonly string[]} contentEncodings
 * @property {readonly string[]} accessGroups
 * @property {Readonly<Record<string, unknown>>} options - this render's copies
 *   of the declared extension item options
 */

/**
 * The read-only view of one configured issuer a contribution receives.
 *
 * @typedef {object} PreparedIssuerView
 * @property {string} issuerName
 * @property {string} keyId
 * @property {string} algorithm
 * @property {CryptoKey} publicKey
 * @property {string} [envelope] - the selected extension procedure, if any
 */

/**
 * What one contribution adds to a render. Every member is optional. Each value
 * is plain JSON and names no member base writes.
 *
 * @typedef {object} ItemPreparationResult
 * @property {Record<string, unknown>} [claims] - members added to the signed
 *   resource beside `data`
 * @property {Record<string, Record<string, unknown>>} [contentRecords] - by
 *   content name, members added to that item's `contentData` record
 * @property {Record<string, Record<string, unknown>>} [issuerSealed] - by
 *   issuer name, members added to that issuer block's `sealed`; an issuer the
 *   base plan supplies nothing still gets a block when it receives one
 * @property {Record<string, unknown>} [pageMembers] - members added to the
 *   delivery root; `periodGeometry` must equal the base one when both exist,
 *   or complete base's `periodMinutes` alone with a pair of the same minutes
 */

/**
 * Per-item work a selected contribution adds to every render. `routes` runs
 * before the render draws anything and names the items this contribution gives
 * a usable issuer route; base then requires its own route only for the others.
 * `prepare` runs once the render id and every content key are drawn and before
 * the resource is signed. It receives copies of the content keys.
 *
 * @typedef {object} ItemPreparation
 * @property {readonly string[]} [envelopes] - extension envelope procedures
 *   this preparation seals its own fields under; a render refuses its fields
 *   in the block of an issuer that selects another one
 * @property {(render: { items: readonly PreparedItemView[], issuers: readonly PreparedIssuerView[], now: Date }) => string[]} routes
 * @property {(context: { renderId: string, now: Date, origin: string, resourceId: string, items: readonly PreparedItemView[], issuers: readonly PreparedIssuerView[], contentKeys: Readonly<Record<string, Uint8Array>> }) => Promise<ItemPreparationResult>} prepare
 * @property {(delivery: DcaData, issuerName: string) => import('./issuerRequestBudget.js').RequestRelay | undefined} [requestRelay]
 *   the members a client composed with this contribution adds to its request
 *   to that issuer when it needs every item, projected from the assembled
 *   delivery the way the client projects it; the issuer request budget counts
 *   them beside the base members
 */

/** Members of the signed resource base writes. */
const BASE_CLAIMS = ["renderId", "origin", "issuedAt", "resourceId", "data"];
/** Members of a content record base writes. */
const BASE_RECORD_MEMBERS = ["contentName", "contentType", "nonce", "contentEncodings", "keys"];
/** Members of an issuer block's `sealed` base writes. */
const BASE_SEALED_MEMBERS = ["contentKeys", "periodKeys", "chainKeys"];
/** Delivery root members base writes; `periodGeometry` is shared, see `pageGeometry`. */
const BASE_PAGE_MEMBERS = ["version", "resource", "resourceJWT", "contentData", "issuerData"];
const PREPARATION_RESULT_MEMBERS = ["claims", "contentRecords", "issuerSealed", "pageMembers"];

/**
 * One wrapped contentKey, as an item record's `keys` collection carries it:
 * its coordinate in named fields, then the members the render's wrap strategy
 * wrote beside `key`. `period` is the label the strategy received as `t`.
 *
 * @typedef {object} SealedContentKeyEntry
 * @property {string} accessGroup
 * @property {string} period
 * @property {string} key - base64url contentKey wrapped under the periodKey; its
 *   nonce is derived from the coordinate, so the entry carries none
 */

/**
 * One content item as the client reads it: what the item was encrypted under,
 * and the contentKey candidates a cached path can unwrap. `keys` is absent on
 * an item the render offers no cached path for. The record carries no AAD: the
 * item is sealed under LP(renderId) || LP(contentName), which a client rebuilds.
 *
 * @typedef {object} ContentDataRecord
 * @property {string} contentName
 * @property {string} contentType - handling metadata; encoding traversal does not read it
 * @property {string[]} [contentEncodings] - applied in order, reversed by the client
 * @property {SealedContentKeyEntry[]} [keys] - in group order, then period order
 */

/**
 * The publisher-to-client wire shape. Its collections are arrays of records
 * named by contentName, issuerName, accessGroup and period. The publisher
 * chose every one of those names, which is why the reading side looks a
 * record up by its field and never does a bare `map[name]`.
 *
 * @typedef {object} DcaData
 * @property {string} version
 * @property {{ renderId: string, origin: string, issuedAt: string, resourceId: string, data: object }} resource
 * @property {string} resourceJWT - ES256 over `resource`, shared across issuers
 * @property {{ chainsPerDay?: number, periodMinutes: number }} [periodGeometry]
 * @property {ContentDataRecord[]} contentData
 * @property {Array<{ issuerName: string, sealed: { contentKeys?: { contentName: string, key: string }[], periodKeys?: { accessGroup: string, period: string, key: string }[], chainKeys?: { accessGroup: string, cutoff: string, key: string }[] }, keyId: string }>} issuerData
 */

/**
 * @typedef {object} Render
 * @property {DcaData} dcaData
 * @property {Record<string, string>} sealedContent - base64url ciphertext per
 *   contentName; an in-memory map that each delivery writer turns into the
 *   wire's `{contentName, content}` records
 */

/**
 * Where a periodKey's opaque bytes come from. Base consumes an injected period-key
 * supply, and a selected extension may answer the same call.
 *
 * Base requires `derive` alone, and asks it only for period keys. An extension
 * may additionally provide one synchronous `familyPlan` snapshot per access
 * group; base still receives only labels and opaque key-acquisition
 * operations, never a derivation construction.
 *
 * All acquisitions for one family in one render must use one immutable
 * generation, including a derive-only provider. A rotating provider captures
 * that generation before any asynchronous acquisition. A family plan's
 * periodKeyAt must match the period key derived at that coordinate from any
 * selected capability. A chain key itself need not equal that period key.
 * Each answer belongs to the requested publisher namespace, family, coordinate
 * and construction. The Sealer checks shape/width, not provider equivalence.
 * Only configured issuer routes promise acquisition; a wrap is not such a promise.
 *
 * The base slice ships no default supply and imports no derivation profile: a
 * periodKey's bytes are the publisher's to choose, so a publisher on the cached
 * path injects its supply. The Sealer is asked for bytes at a coordinate and
 * assigns no derivation meaning to them.
 *
 * @typedef {object} PeriodKeySupply
 * @property {(accessGroup: string, t: string) => Promise<Uint8Array>} derive
 * @property {(accessGroup: string, now: Date, period: object, chainRequested: boolean) => object} [familyPlan]
 */

/** Canonical period-key and chain-key width. */
const PERIOD_KEY_BYTES = 16;

/**
 * This module accepts the signed resource context only as a JSON tree. A
 * JavaScript object that merely survives one call to JSON.stringify does not
 * pass. In particular, do not let a
 * getter, toJSON hook, sparse member or host object change what the publisher
 * thought it was signing while serialization is under way.
 *
 * This deliberately reads descriptors rather than serializing. It does not
 * invoke accessors or toJSON hooks, and snapshots the JSON tree immediately so
 * mutation after resource() cannot change the value later signed. Publisher
 * metadata is opaque to DCA core (though issuer policy may read the verified
 * signed value), so a valid JSON value including a string that looks like
 * markup is not sanitized.
 *
 * @param {unknown} data
 * @returns {object}
 */
function snapshotResourceData(data) {
  try {
    if (!isPlainObject(data)) invalidResourceData();
    return /** @type {object} */ (snapshotJsonValue(data, new Set()));
  } catch (error) {
    if (/** @type {any} */ (error)?.code === "bad_config") throw error;
    invalidResourceData();
  }
}

/** @param {unknown} value @returns {value is object} */
function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** @returns {never} */
function invalidResourceData() {
  throw dcaError(
    "bad_config",
    "resource data is a non-array plain JSON object with no omitted or runtime-defined members",
  );
}

/**
 * @param {unknown} value
 * @param {Set<object>} ancestors
 */
function snapshotJsonValue(value, ancestors) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (Number.isFinite(value)) return value;
    invalidResourceData();
  }
  if (typeof value !== "object") invalidResourceData();
  if (ancestors.has(value)) invalidResourceData();

  ancestors.add(value);
  try {
    if (Array.isArray(value)) return snapshotJsonArray(value, ancestors);
    if (isPlainObject(value)) return snapshotJsonObject(value, ancestors);
    invalidResourceData();
  } finally {
    ancestors.delete(value);
  }
}

/**
 * @param {object} value
 * @param {Set<object>} ancestors
 */
function snapshotJsonObject(value, ancestors) {
  const snapshot = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") invalidResourceData();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value") || !descriptor.enumerable)
      invalidResourceData();
    // defineProperty, rather than assignment, keeps a legal own
    // "__proto__" JSON member as data instead of invoking the inherited
    // Object.prototype setter.
    Object.defineProperty(snapshot, key, {
      value: snapshotJsonValue(descriptor.value, ancestors),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  return snapshot;
}

/**
 * A plain JSON copy of a value a contribution hands in, refused with a message
 * naming what it was.
 *
 * @param {unknown} value
 * @param {string} what
 */
function snapshotContributedJson(value, what) {
  try {
    return snapshotJsonValue(value, new Set());
  } catch {
    throw dcaError("bad_config", `${what} is a plain JSON value`);
  }
}

/**
 * A frozen deep copy of a JSON value, so one contribution cannot change what
 * another or the Sealer later reads.
 *
 * @param {unknown} value
 * @returns {any}
 */
function frozenJson(value) {
  if (value === null || typeof value !== "object") return value;
  const copy = Array.isArray(value)
    ? value.map(frozenJson)
    : Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, frozenJson(entry)]));
  return Object.freeze(copy);
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecordValue(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * @param {unknown[]} value
 * @param {Set<object>} ancestors
 */
function snapshotJsonArray(value, ancestors) {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1) invalidResourceData();
  const snapshot = new Array(value.length);

  for (const key of keys) {
    if (key === "length") continue;
    if (typeof key !== "string") invalidResourceData();
    const index = Number(key);
    if (
      !Number.isSafeInteger(index) ||
      index < 0 ||
      index >= value.length ||
      String(index) !== key
    ) {
      invalidResourceData();
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) invalidResourceData();
    Object.defineProperty(snapshot, key, {
      value: snapshotJsonValue(descriptor.value, ancestors),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  return snapshot;
}

/**
 * Labels a supply or an extension's family plan hands over. Base wraps and
 * seals at each one, so a label that a client or issuer would not admit is
 * refused here, before any key is acquired at it.
 *
 * @param {unknown} labels @param {string} accessGroup @param {string} field
 */
function checkedLabels(labels, accessGroup, field) {
  if (
    !Array.isArray(labels) ||
    labels.length === 0 ||
    labels.some(
      (t) =>
        typeof t !== "string" ||
        t.length === 0 ||
        t.includes(AAD_DELIMITER) ||
        !isPeriodKeyLabel(t),
    ) ||
    new Set(labels).size !== labels.length
  ) {
    throw dcaError(
      "bad_config",
      `${field} for accessGroup "${accessGroup}" is a nonempty list of unique binding-safe labels, each spelled YYMMDDTHHMM`,
    );
  }
  return Object.freeze([...labels]);
}

/** One authored label must lie on the shared UTC period grid. */
function alignedPeriodLabel(/** @type {string} */ t, /** @type {number} */ minutes) {
  const year = 2000 + Number(t.slice(0, 2));
  const month = Number(t.slice(2, 4));
  const day = Number(t.slice(4, 6));
  const hour = Number(t.slice(7, 9));
  const minute = Number(t.slice(9, 11));
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute));
  try {
    return formatT(date, minutes) === t;
  } catch {
    return false;
  }
}

/**
 * @param {unknown} declared
 * @param {string} accessGroup
 */
function checkedFamilyPlan(declared, accessGroup) {
  if (declared === null || typeof declared !== "object" || Array.isArray(declared)) {
    throw dcaError("bad_config", `the period family plan for "${accessGroup}" is an object`);
  }
  const plan = /** @type {any} */ (declared);
  for (const name of Object.keys(plan)) {
    if (
      name !== "periods" &&
      name !== "periodKeyAt" &&
      name !== "chain" &&
      name !== "periodMinutes"
    ) {
      throw dcaError(
        "unsupported_option",
        `a period family plan has no ${name} yet, and will not pretend to`,
      );
    }
  }
  if (typeof plan.periodKeyAt !== "function") {
    throw dcaError(
      "bad_config",
      `the period family plan for "${accessGroup}" acquires a period key at each label`,
    );
  }
  const periods = checkedLabels(plan.periods, accessGroup, "periods");
  if (
    plan.periodMinutes !== undefined &&
    (!Number.isInteger(plan.periodMinutes) ||
      plan.periodMinutes <= 0 ||
      1440 % plan.periodMinutes !== 0)
  ) {
    throw dcaError(
      "bad_config",
      `the period family plan for "${accessGroup}" carries valid periodMinutes`,
    );
  }
  if (plan.chain === undefined)
    return Object.freeze({
      periods,
      periodKeyAt: plan.periodKeyAt,
      periodMinutes: plan.periodMinutes,
    });

  if (plan.chain === null || typeof plan.chain !== "object" || Array.isArray(plan.chain)) {
    throw dcaError("bad_config", `the chain plan for "${accessGroup}" is an object`);
  }
  const { geometry, suppliedTs, capabilityAt } = plan.chain;
  for (const name of Object.keys(plan.chain)) {
    if (name !== "geometry" && name !== "suppliedTs" && name !== "capabilityAt") {
      throw dcaError(
        "unsupported_option",
        `a chain family plan has no ${name} yet, and will not pretend to`,
      );
    }
  }
  const geometryBounds =
    geometry === null || typeof geometry !== "object"
      ? null
      : inspectPeriodGeometryBounds(geometry.chainsPerDay, geometry.periodMinutes);
  if (geometryBounds?.kind !== "valid") {
    throw dcaError(
      "bad_config",
      `the chain plan for "${accessGroup}" carries valid complete geometry`,
    );
  }
  for (const name of Object.keys(geometry)) {
    if (name !== "chainsPerDay" && name !== "periodMinutes") {
      throw dcaError(
        "unsupported_option",
        `chain geometry has no ${name} yet, and will not pretend to`,
      );
    }
  }
  if (plan.periodMinutes !== undefined && plan.periodMinutes !== geometry.periodMinutes) {
    throw dcaError("bad_config", "chain and period family geometry use one periodMinutes");
  }
  if (typeof capabilityAt !== "function") {
    throw dcaError(
      "bad_config",
      `the chain plan for "${accessGroup}" acquires a capability at each supplied label`,
    );
  }
  const checkedSuppliedTs = checkedLabels(suppliedTs, accessGroup, "supplied chain labels");
  if (checkedSuppliedTs.length > MAX_CHAIN_MEMBERS_PER_FAMILY) {
    throw dcaError(
      "bad_config",
      `the chain plan for "${accessGroup}" supplies at most ${MAX_CHAIN_MEMBERS_PER_FAMILY} capabilities`,
    );
  }
  // An issuer refuses a whole family whose members share one stationary
  // window (docs/spec-profile--chain-keys.md, 11.2-11.3), so a plan that supplies two
  // would publish a route no issuer serves. Refused here, before any key is
  // acquired, whichever issuer later selects chain delivery.
  /** @type {Map<number, string>} */
  const windows = new Map();
  for (const t of checkedSuppliedTs) {
    const source = chainPosition(t, geometry);
    if (!source) {
      throw dcaError(
        "bad_config",
        `chain source "${t}" for "${accessGroup}" is a real aligned UTC coordinate`,
      );
    }
    const other = windows.get(source.window);
    if (other !== undefined) {
      throw dcaError(
        "bad_config",
        `the chain plan for "${accessGroup}" supplies one position per window; "${other}" and "${t}" share one`,
      );
    }
    windows.set(source.window, t);
  }
  return Object.freeze({
    periods,
    periodKeyAt: plan.periodKeyAt,
    chain: Object.freeze({
      geometry: Object.freeze({
        chainsPerDay: geometry.chainsPerDay,
        periodMinutes: geometry.periodMinutes,
      }),
      suppliedTs: checkedSuppliedTs,
      capabilityAt,
    }),
  });
}

/**
 * Numeric chain reach only. A source at one aligned position reaches earlier
 * aligned positions in its stationary UTC window; it never reaches another
 * window. This does not infer an issuer grant policy.
 *
 * @param {string} t
 * @param {{ chainsPerDay: number, periodMinutes: number }} geometry
 * @returns {{ window: number, position: number }|null}
 */
function chainPosition(t, geometry) {
  const year = 2000 + Number(t.slice(0, 2));
  const month = Number(t.slice(2, 4));
  const day = Number(t.slice(4, 6));
  const hour = Number(t.slice(7, 9));
  const minute = Number(t.slice(9, 11));
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute));
  if (
    !isPeriodKeyLabel(t) ||
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() + 1 !== month ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute
  ) {
    return null;
  }
  const minuteOfDay = hour * 60 + minute;
  const windowMinutes = 1440 / geometry.chainsPerDay;
  const windowMinute = minuteOfDay % windowMinutes;
  if (windowMinute % geometry.periodMinutes !== 0) {
    return null;
  }
  return {
    window: Math.floor(date.getTime() / 60000 / windowMinutes),
    position: windowMinute / geometry.periodMinutes,
  };
}

/**
 * @param {import('./issuerSupplyPlan.js').IssuerSupplyPlan} plan
 * @param {string} accessGroup
 * @param {readonly string[]} periods
 * @returns {readonly string[]}
 */
function selectedPeriodSourceTs(plan, accessGroup, periods) {
  if (!plan.periodKeyDelivery[accessGroup].includes("period-keys")) return [];
  return Object.hasOwn(plan.periodKeySourceTs, accessGroup)
    ? plan.periodKeySourceTs[accessGroup]
    : periods;
}

/**
 * One acquired key, at the width the selected profile states. A key of the
 * other profile's width is refused here, at the coordinate that produced it,
 * rather than wrapped at whatever arrived.
 *
 * @param {unknown} value
 * @param {string} kind
 * @param {string} accessGroup
 * @param {string} t
 * @param {number} width - the stated width, from the selected profile
 */
function checkedKeyBytes(value, kind, accessGroup, t, width) {
  if (!(value instanceof Uint8Array) || value.length !== width) {
    throw dcaError(
      "bad_key",
      `${kind} for accessGroup "${accessGroup}" at "${t}" is ${width} bytes`,
    );
  }
  return Uint8Array.from(value);
}

/**
 * How a key is sealed to an issuer. An explicit `keySealing` replaces the core
 * default, and is then responsible for every selected producer requirement,
 * including a fresh ECDH pair per envelope and the selected construction's
 * nonce procedure.
 * The core default conforms. A variant may commit to another coordinate or
 * carrier when its selected profile defines that construction.
 *
 * @typedef {object} KeySealing
 * @property {(keyBytes: Uint8Array, publicKey: CryptoKey, algorithm: string, options: any) => Promise<string>} seal
 */

/**
 * What a sealed blob is for, so a supplied ephemeral keypair can be matched to
 * it. A contentKey blob names its contentName; a period capability names its
 * accessGroup, its period label and whether it is a chain key. The member name
 * is `t` for a period key and `suppliedT` for a chain key. Keyed by context
 * rather than by call order, so a provider does not have to know how many blobs
 * a render makes.
 *
 * @typedef {object} EphemeralContext
 * @property {string} issuerName
 * @property {string} [contentName]
 * @property {string} [accessGroup]
 * @property {string} [t]
 * @property {string} [suppliedT]
 * @property {boolean} [chainKey]
 * @property {number} [chainsPerDay]
 * @property {number} [periodMinutes]
 */

/**
 * The one geometry a page carries when base and a contribution may each write
 * one. They agree by field, or base wrote `periodMinutes` alone, because no
 * group of this render rides a chain, and the contribution's complete pair
 * names the same minutes: the page then carries that pair, since every base
 * period key on it reads the same minutes either way. Any other difference
 * refuses.
 *
 * @param {{ chainsPerDay?: number, periodMinutes: number }|undefined} base
 * @param {unknown} contributed
 * @returns {{ chainsPerDay?: number, periodMinutes: number }|undefined}
 */
function pageGeometry(base, contributed) {
  if (contributed === undefined) return base;
  if (base === undefined) return /** @type {any} */ (contributed);
  if (periodGeometriesAgree(contributed, base)) return base;
  if (
    !Object.hasOwn(base, "chainsPerDay") &&
    isRecordValue(contributed) &&
    Object.hasOwn(contributed, "chainsPerDay") &&
    periodGeometriesAgree(contributed, {
      chainsPerDay: contributed.chainsPerDay,
      periodMinutes: base.periodMinutes,
    })
  ) {
    return /** @type {any} */ (contributed);
  }
  throw dcaError(
    "bad_config",
    "one periodGeometry applies to the page; a contribution's differs from the base one",
  );
}

/**
 * The entries of one optional map a contribution returned.
 *
 * @param {unknown} value
 * @param {string} by
 * @param {string} what
 * @returns {[string, any][]}
 */
function entriesOf(value, by, what) {
  if (value === undefined) return [];
  if (!isRecordValue(value)) throw dcaError("bad_config", `${by}'s ${what} is an object`);
  return Object.entries(value);
}

/**
 * @param {ContentItem} item
 * @returns {PreparedItemView}
 */
function preparedItemView(item) {
  return Object.freeze({
    name: item.name,
    contentType: item.contentType,
    contentEncodings: Object.freeze([...item.contentEncodings]),
    accessGroups: Object.freeze([...item.accessGroups]),
    options: frozenJson(item.options),
  });
}

/**
 * @param {IssuerConfig} issuer
 * @returns {PreparedIssuerView}
 */
function preparedIssuerView(issuer) {
  return Object.freeze({
    issuerName: issuer.issuerName,
    keyId: issuer.keyId,
    algorithm: issuer.algorithm,
    publicKey: issuer.publicKey,
    ...(issuer.envelope === undefined ? {} : { envelope: issuer.envelope }),
  });
}

export class Sealer {
  /** @type {string} */
  #origin;
  #clock;
  #random;
  /** @type {Record<string, CryptoKey>} */
  #signingKeys;
  /** @type {string} */
  #signingKid;
  /** @type {import('../core-shared--publisher-issuer/periodKeys.js').Period} */
  #period;
  /** @type {PeriodKeySupply|null} */
  #periodKeySupply;
  /** @type {KeySealing} */
  #keySealing;
  /** @type {import('./contentKeyWrap.js').CheckedContentKeyWrap} */
  #contentKeyWrap;
  /** @type {(issuer: IssuerConfig, render: { accessGroups: string[], contentNames: string[], now: Date }) => any} */
  #issuerSupplyPlanFor;
  /** @type {IssuerConfig[]} */
  #issuers;
  /** @type {readonly ({ name: string } & ItemPreparation)[]} */
  #itemPreparations;
  /** @type {readonly string[]} */
  #itemOptionMembers;
  /** @type {ContentItem[]} */
  #items = [];
  /** @type {{ resourceId: string, data: object }|null} */
  #resource = null;

  /**
   * @param {object} config
   * @param {string} config.origin - the canonical publisher context origin,
   *   `scheme://host[:port]`, signed as `resourceJWT.origin`. Under the
   *   browser-origin profile, it is the calling page's origin and the issuer
   *   compares it with the observed HTTP `Origin`.
   * @param {boolean} [config.developmentHttpOrigin] - the explicit
   *   development profile. With it off, this publisher signs https and nothing
   *   else. With it on, it may also sign http for a localhost host, and still
   *   not for a public one. A production deployment leaves it off.
   * @param {{ now: () => Date }} config.clock
   * @param {{ bytes: (n: number) => Uint8Array }} config.random
   * @param {IssuerConfig[]} config.issuers
   * @param {import('../core-shared--publisher-issuer/periodKeys.js').Period} [config.period] - `{ length,
   *   slots }`, hourly and two slots by default. Two publishers with
   *   different periods run in one process, so each publisher configures its
   *   own.
   * @param {PeriodKeySupply} [config.periodKeySupply] - where a periodKey's
   *   bytes come from, and the whole of the cached path. With it left out,
   *   the render carries no cached path at all: no `keys` on an item
   *   record, no `sealed.periodKeys`, and an issuer can only answer with
   *   contentKeys. An item that names an accessGroup is then refused.
   *   A selected extension may instead provide a grant with a different
   *   reach; its bundle stays outside this base role slice.
   * @param {KeySealing} [config.keySealing] - how each key is sealed to an
   *   issuer. `core-shared--publisher-issuer/keySealing.js` by default; a variant module carries
   *   another binding, and it is handed the same coordinate either way.
   * @param {Record<string, CryptoKey>} config.signingKeys - the publisher's
   *   ECDSA P-256 private keys, keyed by `kid`. Plural because a rotation has
   *   to leave the previous key resolvable: markup an edge cache is still
   *   serving carries the kid of the key that signed it, and the issuer
   *   selects by kid.
   * @param {string} [config.signingKid] - which one signs this render.
   *   Optional while there is only one, required as soon as there are two:
   *   a publisher holding two keys has to say which of them signs.
   * @param {import('./contentKeyWrap.js').ContentKeyWrapStrategy} [config.contentKeyWrapStrategy]
   *   how this render writes each item record's `keys`: the aad each
   *   wrap is made under and the entry that carries it. One per render,
   *   because that member is emitted once and every issuer reads the same
   *   entries. `ordinaryContentKeyWrap` by default, which is the format's v1
   *   representation.
   * @param {(issuer: IssuerConfig, render: { accessGroups: string[], contentNames: string[], now: Date }) => object}
   *   config.issuerSupplyPlanFor - what one issuer is supplied, asked once
   *   per issuer before the render draws anything. It answers a value and
   *   writes nothing: the content names that receive a sealed content key,
   *   the access groups that issuer's period material covers, the content
   *   names it must be able to reach through those groups, and the extra
   *   members its block carries. Required, and so are the first two members
   *   of every plan: nothing defaults to every name or group.
   *   `wholeRenderIssuerSupplyPlan` supplies everything when a publisher
   *   means that. Every plan is checked before the first random byte, so
   *   base refuses a plan this render cannot serve before producing anything.
   */
  constructor(config) {
    const {
      origin,
      clock,
      random,
      issuers,
      signingKeys,
      signingKid,
      period,
      periodKeySupply,
      keySealing,
      contentKeyWrap,
      issuerSupplyPlanFor,
      itemPreparations,
      itemOptionMembers,
    } = validatePublisherConfig(config);

    this.#origin = origin;
    this.#signingKeys = signingKeys;
    this.#signingKid = signingKid;
    this.#clock = clock;
    this.#random = random;
    this.#period = settledPeriod(period);
    this.#periodKeySupply = periodKeySupply;
    this.#keySealing = keySealing;
    this.#contentKeyWrap = contentKeyWrap;
    this.#issuerSupplyPlanFor = issuerSupplyPlanFor;
    this.#issuers = issuers;
    this.#itemPreparations = itemPreparations;
    this.#itemOptionMembers = itemOptionMembers;
  }

  /**
   * @param {string} resourceId
   * @param {object} data - publisher-defined metadata an issuer decides on
   * @returns {this}
   */
  resource(resourceId, data) {
    // A resourceId is a value and never a member name, so it keeps the
    // publisher's own identifier scheme, `|` included: neither content AAD
    // nor a BIND grammar carries it. The format's own
    // example is `123456`, which no member-name grammar would admit.
    validateResourceId(resourceId);
    this.#resource = { resourceId, data: snapshotResourceData(data) };
    return this;
  }

  /**
   * The item names the accessGroups it is wrapped under, so two articles can
   * assign the same contentName differently.
   *
   * The item's contentKey is wrapped under the `accessGroups` named here: one
   * set of wrap records per group in the item's `keys`, and every issuer
   * granted that group can hand out the periodKey that opens it.
   *
   * Groups are optional per item. An item with omitted or empty groups ships
   * no `keys` and relies on an item content-key route, which `seal()` checks
   * before any render work; no group is assigned by default. A sealer without
   * a `periodKeySupply` is content-key-only, and refuses an item that names a
   * group here, because it could only drop the wraps that group asks for.
   *
   * Bare strings keep the legacy API and are UTF-8 encoded here. Bare bytes
   * and descriptor bytes are copied here, and a descriptor's ordered
   * contentEncodings are copied with them. Descriptor bytes are already
   * encoded; base records their layers and never applies a codec.
   *
   * @param {string} name
   * @param {string|Uint8Array|{ bytes: Uint8Array, contentType: string, contentEncodings: string[] }} value
   * Options also carry the per-item options a selected contribution declared;
   * each one present is copied here as plain JSON, so a later change to the
   * caller's object reaches no render.
   *
   * @param {string|{ accessGroups?: string[] } & Record<string, unknown>} [contentTypeOrOptions]
   * @param {{ accessGroups?: string[] } & Record<string, unknown>} [legacyOptions]
   * @returns {this}
   */
  content(name, value, contentTypeOrOptions, legacyOptions) {
    // Both names identify records on the wire (an item's `contentName` and
    // a wrap's `accessGroup`), and the contentName also enters the item's
    // AAD. This method refuses a bad name here rather than at seal(), so the
    // call that introduced the name is the one that fails.
    validateContentName(name);
    // A publisher emits one record per contentName. A second item under one
    // name would be a second record that a reader replaces the first with,
    // so the call that repeats the name fails instead.
    if (this.#items.some((item) => item.name === name)) {
      throw dcaError("bad_config", `content "${name}" is already in this render`);
    }
    const descriptor = isContentRepresentation(value);
    if (descriptor && legacyOptions !== undefined) {
      throw dcaError(
        "bad_config",
        `content "${name}" uses descriptor options as its third argument`,
      );
    }
    const options = descriptor ? (contentTypeOrOptions ?? {}) : (legacyOptions ?? {});
    if (options === null || typeof options !== "object" || Array.isArray(options)) {
      throw dcaError("bad_config", `content "${name}" options are an object`);
    }
    const representation = normalizeContentRepresentation(
      value,
      descriptor ? undefined : contentTypeOrOptions,
    );
    if (!contentHandlingIsValid(representation.contentType, representation.contentEncodings)) {
      throw dcaError(
        "bad_config",
        `content "${name}" has malformed or oversized handling metadata`,
      );
    }
    const accessGroups = own(options, "accessGroups");
    const groups = accessGroups ?? [];
    if (!Array.isArray(groups)) {
      throw dcaError("bad_config", `content "${name}" accessGroups are a list`);
    }
    for (const accessGroup of groups) validateAccessGroup(accessGroup);
    if (!this.#periodKeySupply && groups.length) {
      throw dcaError(
        "bad_config",
        `content "${name}" names accessGroups, and this publisher holds no periodKeySupply to wrap under`,
      );
    }
    /** @type {Record<string, unknown>} */
    const extensionOptions = {};
    for (const member of this.#itemOptionMembers) {
      const value = own(options, member);
      if (value !== undefined) {
        extensionOptions[member] = snapshotContributedJson(
          value,
          `content "${name}" option ${member}`,
        );
      }
    }
    this.#items.push({
      name,
      bytes: representation.bytes,
      contentType: representation.contentType,
      contentEncodings: representation.contentEncodings,
      accessGroups: [...groups],
      options: extensionOptions,
    });
    return this;
  }

  /**
   * One render. The core default, and any conforming selected provider, gives
   * a fresh renderId, contentKey per item, and ECDH ephemeral keypair per
   * sealed blob. Each period-key wrap derives its nonce from that renderId and
   * its own coordinate. An explicit
   * provider is responsible for its own producer conformance; deterministic replay is
   * fixture-only and intentionally nonconforming.
   *
   * The periodKeys are the exception, and deliberately: a shared supply
   * returns the same bytes for one (accessGroup, t) in every render, and the
   * client's cache is built on that.
   *
   * @returns {Promise<Render>}
   */
  async seal() {
    if (!this.#resource) throw dcaError("bad_config", "Sealer needs a resource before it can seal");
    if (!this.#items.length)
      throw dcaError("bad_config", "Sealer needs a content item before it can seal");

    // Capture one operation before invoking host callbacks or awaiting.
    // resource() owns its admitted data; replacement and later content additions
    // belong to subsequent calls, including their route checks.
    const resourceInput = this.#resource;
    const items = this.#items.slice();

    // One render instant for the whole render, read once and checked here.
    // Two reads would let a clock that turned invalid between them stamp a
    // valid `issuedAt` and still name the periods, and `formatT` does not
    // reject NaN: every slot would collapse onto `NaNNaNNaNTNaN`, one label
    // covering everything sealed while the clock was broken. Checking at the
    // read also keeps the refusal independent of the order the statements
    // below happen to stand in.
    const observedNow = this.#clock.now();
    if (!(observedNow instanceof Date) || !Number.isFinite(observedNow.getTime())) {
      throw dcaError("bad_config", "a publisher render instant is a valid Date");
    }
    // Keep the captured instant even if a caller-owned Clock returns a
    // mutable Date and supplier code later changes that same object.
    const now = new Date(observedNow.getTime());

    // Base settles every plan first, and settles the compatibility question
    // at the same time. What follows draws from the random source, asks the
    // supply for key material and seals to an issuer, and a refusal after any
    // of that would leave a caller holding a partial answer it cannot tell
    // from a complete one.
    // Without a period-key supply the render wraps nothing, so no group can
    // be supplied and every item needs a content-key route from the
    // publisher.
    const accessGroups = this.#periodKeySupply ? this.#accessGroups(items) : [];
    const contentNames = items.map((item) => item.name);
    const plans = this.#issuerSupplyPlans(accessGroups, contentNames, now, items);
    const routePlans = plans;
    const itemViews = Object.freeze(items.map(preparedItemView));
    const issuerViews = Object.freeze(this.#issuers.map(preparedIssuerView));
    const routed = this.#contributedRoutes(items, itemViews, issuerViews, now);
    assertCompleteIssuerRoutes(
      items.filter((item) => !routed.has(item.name)),
      routePlans,
    );
    const periodKeys = await this.#derivePeriodKeys(
      now,
      plans,
      accessGroups,
      routePlans,
      items,
      routed,
    );

    const renderId = base64urlEncode(this.#random.bytes(RENDER_ID_BYTES));
    try {
      validateRenderId(renderId);
    } catch {
      throw dcaError("bad_config", "the random source supplied an invalid renderId");
    }

    // Each encryption gets an independent fresh key. The content nonce is
    // fixed, so a key must never be used for another encryption.
    const drawn = items.map(() => ({
      contentKey: this.#random.bytes(CONTENT_KEY_BYTES),
    }));
    const prepared = await this.#prepareItems(
      renderId,
      resourceInput.resourceId,
      now,
      items,
      itemViews,
      issuerViews,
      drawn.map(({ contentKey }) => contentKey),
    );

    const resource = {
      renderId,
      origin: this.#origin,
      issuedAt: now.toISOString(),
      resourceId: resourceInput.resourceId,
      // Each render gets its own copy. A host may annotate or otherwise
      // mutate one returned delivery without changing the next render's
      // signed resource context.
      data: snapshotResourceData(resourceInput.data),
      ...prepared.claims,
    };

    const resourceJWT = await this.#sign(resource);

    // Built by name while the render fills it in; the wire record carries the
    // name as its first field, written at assembly below.
    /** @type {Record<string, Omit<ContentDataRecord, "contentName">>} */
    const contentData = {};
    /** @type {Record<string, string>} */
    const sealedContent = {};
    /** @type {Record<string, Uint8Array>} */
    const contentKeys = {};

    for (const [index, item] of items.entries()) {
      const aad = contentAad({ renderId, contentName: item.name });
      if (aad === null) {
        throw dcaError("bad_config", `content "${item.name}" has invalid content AAD inputs`);
      }
      const { contentKey } = drawn[index];
      const ciphertext = await encrypt(contentKey, new Uint8Array(NONCE_BYTES), item.bytes, aad);

      contentData[item.name] = {
        contentType: item.contentType,
        ...(item.contentEncodings.length === 0
          ? {}
          : { contentEncodings: [...item.contentEncodings] }),
        ...(prepared.contentRecords[item.name] ?? {}),
      };
      sealedContent[item.name] = base64urlEncode(ciphertext);
      contentKeys[item.name] = contentKey;
    }

    if (periodKeys)
      await this.#wrapContentKeys(renderId, contentData, contentKeys, periodKeys, items);

    /** @type {any[]} */
    const issuerData = [];

    for (const [index, issuer] of this.#issuers.entries()) {
      const plan = plans[index];
      const contributedSealed = prepared.issuerSealed[issuer.issuerName];
      if (suppliesNothing(plan) && contributedSealed === undefined) continue;

      /** @type {{ contentKeys?: { contentName: string, key: string }[], periodKeys?: { accessGroup: string, period: string, key: string }[], chainKeys?: { accessGroup: string, cutoff: string, key: string }[] }} */
      const sealed = {};
      if (plan.contentKeyNames.length > 0) {
        /** @type {{ contentName: string, key: string }[]} */
        const sealedKeys = [];
        for (const contentName of plan.contentKeyNames) {
          const key = await this.#keySealing.seal(
            contentKeys[contentName],
            issuer.publicKey,
            issuer.algorithm,
            carrierOptions(
              this.#random,
              {
                renderId,
                contentName,
              },
              issuer.envelope,
            ),
          );
          sealedKeys.push({ contentName, key });
        }
        sealed.contentKeys = sealedKeys;
      }
      if (periodKeys) {
        const sealedPeriodKeys = await this.#sealPeriodKeys(issuer, plan, renderId, periodKeys);
        if (sealedPeriodKeys.length > 0) sealed.periodKeys = sealedPeriodKeys;
        const chains = await this.#sealChainKeys(issuer, plan, renderId, periodKeys);
        if (chains.length > 0) sealed.chainKeys = chains;
      }
      // An extension contributes whole sealed collections of its own, such
      // as `contentWindowSeeds`, already in their record shape.
      Object.defineProperties(sealed, Object.getOwnPropertyDescriptors(contributedSealed ?? {}));

      // A group declaration can select no actual source (for example, an
      // empty ordinary-source selector). Do not publish an issuer endpoint
      // that has no material or extension members for this article.
      if (Object.keys(sealed).length === 0 && Object.keys(plan.issuerMembers).length === 0) {
        continue;
      }

      issuerData.push({
        issuerName: issuer.issuerName,
        // The planned members follow the name. They say which route the
        // rest of it is written for, and a reader meets them before it
        // reads a `sealed` that may be shaped for that route.
        ...plan.issuerMembers,
        sealed,
        keyId: issuer.keyId,
        // The client relays this beside keyId, and the issuer opens every
        // sealed value of the block with the procedure it names.
        ...(issuer.envelope === undefined ? {} : { envelope: issuer.envelope }),
      });
    }

    // Assembled here rather than filled in as it goes, because the wire has
    // an order: the format's example carries the envelope between the
    // resource and contentData, and a JSON object's key order is the order
    // its keys were first set.
    const { periodGeometry: contributedGeometry, ...pageMembers } = prepared.pageMembers;
    const basePeriodGeometry = periodKeys ? periodKeys.periodGeometry : undefined;
    const periodGeometry = pageGeometry(basePeriodGeometry, contributedGeometry);

    /** @type {DcaData} */
    const dcaData = {
      version: VERSION,
      resource,
      resourceJWT,
      ...(periodGeometry !== undefined && Object.hasOwn(periodGeometry, "chainsPerDay")
        ? { periodGeometry: /** @type {any} */ (periodGeometry) }
        : {}),
      ...pageMembers,
      contentData: Object.entries(contentData).map(([contentName, record]) => ({
        contentName,
        ...record,
      })),
      issuerData,
    };

    // Each relay reads its own copy, so no projection can change the delivery.
    const relays = this.#itemPreparations.flatMap(({ requestRelay }) =>
      requestRelay === undefined
        ? []
        : [
            (/** @type {any} */ delivery, /** @type {string} */ issuerName) =>
              requestRelay(structuredClone(delivery), issuerName),
          ],
    );
    for (const issuer of this.#issuers) assertIssuerRequestBudget(dcaData, issuer, relays);
    return { dcaData, sealedContent };
  }

  /**
   * The items the selected contributions give a route, asked before the render
   * draws anything. Each answer is a list of this render's content names.
   *
   * @param {ContentItem[]} items
   * @param {readonly PreparedItemView[]} itemViews
   * @param {readonly PreparedIssuerView[]} issuerViews
   * @param {Date} now
   * @returns {Set<string>}
   */
  #contributedRoutes(items, itemViews, issuerViews, now) {
    /** @type {Set<string>} */
    const routed = new Set();
    for (const preparation of this.#itemPreparations) {
      const names = preparation.routes(
        Object.freeze({ items: itemViews, issuers: issuerViews, now: new Date(now.getTime()) }),
      );
      if (
        !Array.isArray(names) ||
        names.some((name) => !items.some((item) => item.name === name))
      ) {
        throw dcaError(
          "bad_config",
          `${preparation.name} answers its routes as a list of this render's content names`,
        );
      }
      for (const name of names) routed.add(name);
    }
    return routed;
  }

  /**
   * Run every selected item preparation once, in contribution order, and merge
   * what they return. Each one receives its own copies of the content keys.
   *
   * @param {string} renderId
   * @param {string} resourceId - captured at seal entry
   * @param {Date} now
   * @param {ContentItem[]} items
   * @param {readonly PreparedItemView[]} itemViews
   * @param {readonly PreparedIssuerView[]} issuerViews
   * @param {Uint8Array[]} contentKeys - in item order
   * @returns {Promise<{ claims: Record<string, unknown>, contentRecords: Record<string, Record<string, unknown>>, issuerSealed: Record<string, Record<string, unknown>>, pageMembers: Record<string, unknown> }>}
   */
  async #prepareItems(renderId, resourceId, now, items, itemViews, issuerViews, contentKeys) {
    /** @type {Record<string, unknown>} */
    const claims = Object.create(null);
    /** @type {Record<string, Record<string, unknown>>} */
    const contentRecords = Object.create(null);
    /** @type {Record<string, Record<string, unknown>>} */
    const issuerSealed = Object.create(null);
    /** @type {Record<string, unknown>} */
    const pageMembers = Object.create(null);
    for (const preparation of this.#itemPreparations) {
      const by = preparation.name;
      const result = await preparation.prepare(
        Object.freeze({
          renderId,
          now: new Date(now.getTime()),
          origin: this.#origin,
          resourceId,
          items: itemViews,
          issuers: issuerViews,
          contentKeys: Object.freeze(
            Object.fromEntries(
              items.map((item, index) => [item.name, Uint8Array.from(contentKeys[index])]),
            ),
          ),
        }),
      );
      if (!isRecordValue(result)) {
        throw dcaError("bad_config", `${by} prepares items with an object`);
      }
      for (const member of Object.keys(result)) {
        if (!PREPARATION_RESULT_MEMBERS.includes(member)) {
          throw dcaError(
            "unsupported_option",
            `${by} prepares ${member}, which base does not take`,
          );
        }
      }
      for (const [name, value] of entriesOf(result.claims, by, "claims")) {
        if (BASE_CLAIMS.includes(name) || Object.hasOwn(claims, name)) {
          throw dcaError("bad_config", `${by} sets the claim ${name}, which is already set`);
        }
        claims[name] = snapshotContributedJson(value, `${by}'s claim ${name}`);
      }
      for (const [contentName, record] of entriesOf(result.contentRecords, by, "contentRecords")) {
        if (!items.some((item) => item.name === contentName)) {
          throw dcaError(
            "bad_config",
            `${by} adds a record to "${contentName}", not in this render`,
          );
        }
        const target = (contentRecords[contentName] ??= Object.create(null));
        for (const [name, value] of entriesOf(record, by, `the record of "${contentName}"`)) {
          if (BASE_RECORD_MEMBERS.includes(name) || Object.hasOwn(target, name)) {
            throw dcaError(
              "bad_config",
              `${by} sets the record member ${name}, which is already set`,
            );
          }
          target[name] = snapshotContributedJson(value, `${by}'s record member ${name}`);
        }
      }
      for (const [issuerName, members] of entriesOf(result.issuerSealed, by, "issuerSealed")) {
        const issuer = this.#issuers.find((entry) => entry.issuerName === issuerName);
        if (issuer === undefined) {
          throw dcaError("bad_config", `${by} seals for "${issuerName}", not a configured issuer`);
        }
        // A block that selects a procedure holds no field sealed under
        // another one. Each preparation answers for its own fields here,
        // before they merge, so a declaring preparation in the same block
        // cannot cover one that does not declare.
        if (
          issuer.envelope !== undefined &&
          !(preparation.envelopes ?? []).includes(issuer.envelope)
        ) {
          throw dcaError(
            "bad_config",
            `issuer "${issuerName}" selects ${issuer.envelope}, which the item preparation ` +
              `${by} does not seal under`,
          );
        }
        const target = (issuerSealed[issuerName] ??= Object.create(null));
        for (const [name, value] of entriesOf(members, by, `the sealed of "${issuerName}"`)) {
          if (BASE_SEALED_MEMBERS.includes(name) || Object.hasOwn(target, name)) {
            throw dcaError(
              "bad_config",
              `${by} sets the sealed member ${name}, which is already set`,
            );
          }
          target[name] = snapshotContributedJson(value, `${by}'s sealed member ${name}`);
        }
      }
      for (const [name, value] of entriesOf(result.pageMembers, by, "pageMembers")) {
        if (BASE_PAGE_MEMBERS.includes(name) || Object.hasOwn(pageMembers, name)) {
          throw dcaError("bad_config", `${by} sets the page member ${name}, which is already set`);
        }
        pageMembers[name] = snapshotContributedJson(value, `${by}'s page member ${name}`);
      }
    }
    return { claims, contentRecords, issuerSealed, pageMembers };
  }

  /**
   * One token under the active signing key, with its `kid` in the header so
   * the issuer knows which public half verifies it.
   *
   * @param {object} payload
   * @returns {Promise<string>}
   */
  #sign(payload) {
    return sign(payload, this.#signingKeys[this.#signingKid], { kid: this.#signingKid });
  }

  /**
   * One closed plan per issuer, in the order the render lists them. Each one
   * is asked and checked on its own, against the coordinates of this render
   * and the one wrap strategy it selected, so the render refuses an
   * incompatible plan whichever issuer it belongs to.
   *
   * @param {string[]} accessGroups
   * @param {string[]} contentNames
   * @param {ContentItem[]} items - the render's captured item set
   * @param {Date} now - the render's single captured instant
   * @returns {import('./issuerSupplyPlan.js').IssuerSupplyPlan[]}
   */
  #issuerSupplyPlans(accessGroups, contentNames, now, items) {
    return this.#issuers.map((issuer) =>
      normalizedIssuerSupplyPlan(
        issuer.issuerName,
        this.#issuerSupplyPlanFor(issuer, {
          accessGroups: [...accessGroups],
          contentNames: [...contentNames],
          now: new Date(now.getTime()),
        }),
        { accessGroups, items, contentKeyWrapStrategy: this.#contentKeyWrap.strategy },
      ),
    );
  }

  /**
   * The accessGroups this render wraps under, in the order the items named
   * them. Two items in one group share its periodKey family.
   *
   * @param {ContentItem[]} items
   * @returns {string[]}
   */
  #accessGroups(items) {
    /** @type {string[]} */
    const groups = [];
    for (const item of items) {
      for (const accessGroup of item.accessGroups) {
        if (!groups.includes(accessGroup)) groups.push(accessGroup);
      }
    }
    return groups;
  }

  /**
   * One periodKey per (accessGroup, t) for this render, requested once and
   * reused; the same bytes come back however many times it is asked for.
   * Null when this publisher has no periodKeySupply, which is the content-key-only
   * case.
   *
   * An ordinary period-key supply retains the base `periodsFor` plan. An optional
   * family planner may replace that list for a family while exposing only
   * opaque period-key and positioned chain-key acquisition to base.
   *
   * @param {Date} now - the render instant, already checked by `seal()`
   * @param {ContentItem[]} items - the render's captured item set
   * @param {import('./issuerSupplyPlan.js').IssuerSupplyPlan[]} issuerPlans
   * @param {string[]} accessGroups - collected once for this render
   * @param {import('./issuerSupplyPlan.js').IssuerSupplyPlan[]} routePlans - the
   *   plans of issuers whose block a client can use, the only complete routes
   * @param {Set<string>} routed - items a selected contribution gives a route
   * @returns {Promise<{
   *   periodsFor: (accessGroup: string) => readonly string[],
   *   keyFor: (accessGroup: string, t: string) => Uint8Array,
   *   chainKeysFor: (accessGroup: string) => { t: string, key: Uint8Array }[],
   *   geometryFor: (accessGroup: string) => { chainsPerDay: number, periodMinutes: number }|null,
   *   periodGeometry?: { chainsPerDay?: number, periodMinutes: number }
   * }|null>}
   */
  async #derivePeriodKeys(now, issuerPlans, accessGroups, routePlans, items, routed) {
    const supply = this.#periodKeySupply;
    if (!supply) {
      if (
        issuerPlans.some((plan) =>
          Object.values(plan.periodKeyDelivery).some((modes) => modes.includes("chain-keys")),
        )
      ) {
        throw dcaError("bad_config", "chain delivery needs a configured period-family supply");
      }
      return null;
    }

    const chainNeeded = new Set();
    for (const issuerPlan of issuerPlans) {
      for (const accessGroup of issuerPlan.suppliedAccessGroups) {
        const modes = issuerPlan.periodKeyDelivery[accessGroup];
        if (modes.includes("chain-keys")) {
          chainNeeded.add(accessGroup);
        }
      }
    }

    /** @type {Map<string, any>} */
    const familyPlans = new Map();
    for (const accessGroup of accessGroups) {
      const declared = supply.familyPlan
        ? supply.familyPlan(
            accessGroup,
            new Date(now.getTime()),
            { ...this.#period },
            chainNeeded.has(accessGroup),
          )
        : {
            periods: periodsFor(now, this.#period),
            periodKeyAt: (/** @type {string} */ t) => supply.derive(accessGroup, t),
          };
      familyPlans.set(accessGroup, checkedFamilyPlan(declared, accessGroup));
    }
    const periodMinutes = [...familyPlans.values()].map(
      (plan) => plan.periodMinutes ?? plan.chain?.geometry.periodMinutes ?? this.#period.length,
    );
    if (new Set(periodMinutes).size > 1) {
      throw dcaError("bad_config", "one periodMinutes applies to every period family");
    }
    const commonMinutes = periodMinutes[0] ?? this.#period.length;
    /** @type {Map<string, { chainsPerDay: number, periodMinutes: number }>} */
    const geometries = new Map();
    let commonChainGeometry = null;
    for (const [accessGroup, family] of familyPlans) {
      if (family.periods.some((/** @type {string} */ t) => !alignedPeriodLabel(t, commonMinutes))) {
        throw dcaError(
          "bad_config",
          `period labels for "${accessGroup}" align to shared periodMinutes`,
        );
      }
      if (chainNeeded.has(accessGroup) && !family.chain) {
        throw dcaError(
          "bad_config",
          `issuer chain delivery for accessGroup "${accessGroup}" has no configured chain family route`,
        );
      }
      if (family.chain) {
        const geometry = family.chain.geometry;
        if (
          commonChainGeometry &&
          (geometry.chainsPerDay !== commonChainGeometry.chainsPerDay ||
            geometry.periodMinutes !== commonChainGeometry.periodMinutes)
        ) {
          throw dcaError(
            "bad_config",
            "one period geometry applies to every chain family and period key",
          );
        }
        commonChainGeometry = geometry;
        if (chainNeeded.has(accessGroup)) geometries.set(accessGroup, geometry);
      }
    }

    // Determine each issuer's actual source reach before acquisition. A wrap
    // alone promises no new key: a declared reachable item needs at least one
    // matching source, while an independent content-key route can complete an
    // item whose group wraps are cached-only.
    /** @type {Map<import('./issuerSupplyPlan.js').IssuerSupplyPlan, Map<string, Set<string>>>} */
    const reach = new Map();
    for (const issuerPlan of issuerPlans) {
      /** @type {Map<string, Set<string>>} */
      const byGroup = new Map();
      reach.set(issuerPlan, byGroup);
      for (const accessGroup of issuerPlan.suppliedAccessGroups) {
        const modes = issuerPlan.periodKeyDelivery[accessGroup];
        const family = familyPlans.get(accessGroup);
        const selected = selectedPeriodSourceTs(issuerPlan, accessGroup, family.periods);
        const planned = new Set(family.periods);
        for (const t of selected) {
          if (!planned.has(t)) {
            throw dcaError(
              "bad_config",
              `issuer "${issuerPlan.issuerName}" selects unplanned period-key source "${t}" for "${accessGroup}"`,
            );
          }
        }
        if (modes.includes("chain-keys")) {
          if (!family?.chain) {
            throw dcaError(
              "bad_config",
              `issuer chain delivery for accessGroup "${accessGroup}" has no configured chain family route`,
            );
          }
        }
        const sources =
          family.chain && modes.includes("chain-keys")
            ? family.chain.suppliedTs.map((/** @type {string} */ t) => {
                const source = chainPosition(t, family.chain.geometry);
                if (!source) {
                  throw dcaError(
                    "bad_config",
                    `chain source "${t}" for "${accessGroup}" is a real aligned UTC coordinate`,
                  );
                }
                return source;
              })
            : [];
        const selectedSet = new Set(selected);
        for (const t of family.periods) {
          if (selectedSet.has(t)) continue;
          const target =
            family.chain && modes.includes("chain-keys")
              ? chainPosition(t, family.chain.geometry)
              : null;
          if (
            target &&
            sources.some(
              (/** @type {{ window: number, position: number }} */ source) =>
                source.window === target.window && source.position >= target.position,
            )
          ) {
            selectedSet.add(t);
          }
        }
        byGroup.set(accessGroup, selectedSet);
      }
    }

    /** @param {import('./issuerSupplyPlan.js').IssuerSupplyPlan} plan @param {{ accessGroups: string[] }} item */
    const canReachItem = (plan, item) =>
      item.accessGroups.some((accessGroup) => (reach.get(plan)?.get(accessGroup)?.size ?? 0) > 0);
    for (const issuerPlan of issuerPlans) {
      for (const contentName of issuerPlan.reachableContentNames) {
        const item = items.find((candidate) => candidate.name === contentName);
        if (!item || !canReachItem(issuerPlan, item)) {
          throw dcaError(
            "bad_config",
            `issuer "${issuerPlan.issuerName}" must reach "${contentName}" through a selected period source`,
          );
        }
      }
    }
    for (const item of items) {
      if (routed.has(item.name)) continue;
      if (
        !routePlans.some(
          (plan) => plan.contentKeyNames.includes(item.name) || canReachItem(plan, item),
        )
      ) {
        throw dcaError(
          "bad_config",
          `no complete issuer route for protected content "${item.name}"`,
        );
      }
    }

    for (const issuerPlan of issuerPlans) {
      let chainMemberCount = 0;
      for (const accessGroup of issuerPlan.suppliedAccessGroups) {
        if (issuerPlan.periodKeyDelivery[accessGroup].includes("chain-keys")) {
          chainMemberCount += familyPlans.get(accessGroup).chain.suppliedTs.length;
        }
      }
      const maximum = chainMemberLimit(
        this.#issuers.find((issuer) => issuer.issuerName === issuerPlan.issuerName)
          ?.maxChainMembersPerMessage,
      );
      if (chainMemberCount > maximum) {
        throw dcaError("bad_config", `one issuer supply contains at most ${maximum} chain keys`);
      }
    }

    /** @type {Map<string, Uint8Array>} */
    const derived = new Map();
    /** @type {Map<string, { t: string, key: Uint8Array }[]>} */
    const chainKeys = new Map();
    for (const accessGroup of accessGroups) {
      const family = familyPlans.get(accessGroup);
      for (const t of family.periods) {
        derived.set(
          [accessGroup, t].join(AAD_DELIMITER),
          checkedKeyBytes(
            await family.periodKeyAt(t),
            "periodKey",
            accessGroup,
            t,
            PERIOD_KEY_BYTES,
          ),
        );
      }

      if (chainNeeded.has(accessGroup)) {
        const { suppliedTs, capabilityAt } = family.chain;
        const entries = [];
        for (const t of suppliedTs) {
          entries.push({
            t,
            key: checkedKeyBytes(
              await capabilityAt(t),
              "chainKey",
              accessGroup,
              t,
              PERIOD_KEY_BYTES,
            ),
          });
        }
        chainKeys.set(accessGroup, entries);
      }
    }

    const result = /** @type {any} */ ({
      periodsFor: (/** @type {string} */ accessGroup) =>
        familyPlans.get(accessGroup)?.periods ?? [],
      keyFor: (/** @type {string} */ accessGroup, /** @type {string} */ t) =>
        /** @type {Uint8Array} */ (derived.get([accessGroup, t].join(AAD_DELIMITER))),
      chainKeysFor: (/** @type {string} */ accessGroup) => chainKeys.get(accessGroup) ?? [],
      geometryFor: (/** @type {string} */ accessGroup) => geometries.get(accessGroup) ?? null,
    });
    // Complete chain geometry stays on deliveries even when this issuer supplies
    // period keys only: a client may already hold a matching chain key.
    result.periodGeometry = commonChainGeometry
      ? { ...commonChainGeometry }
      : { periodMinutes: commonMinutes };
    return result;
  }

  /**
   * Fills the item record's `keys`, the client's side of the cached path,
   * into the record the item already has. One wrap record per group and
   * period, written as `{accessGroup, period, ...entry}` from the strategy's
   * `{t, key, ...}` entry. Each wrap's nonce is derived from the render ID, the item name, the
   * group, the period and the selected aad, so the entry carries none.
   *
   * This member is emitted once for the whole render, which is why the wrap
   * strategy is selected once: it says what each wrap is bound to and what
   * the entry carrying it looks like, and every issuer of the render reads
   * the same entries. The ordinary strategy passes no aad, because the
   * periodKey is already specific to its accessGroup, per the format.
   *
   * The member is written last, so a record reads in the format's order and
   * an item with no cached path carries no `keys` at all.
   *
   * @param {ContentItem[]} items - the render's captured item set
   * @param {string} renderId - the coordinate every wrap is offered under
   * @param {Record<string, Omit<ContentDataRecord, "contentName">>} contentData - by
   *   contentName, changed in place
   * @param {Record<string, Uint8Array>} contentKeys
   * @param {{ periodsFor: (accessGroup: string) => readonly string[], keyFor: (accessGroup: string, t: string) => Uint8Array,
   * }} periodKeys
   * @returns {Promise<void>}
   */
  async #wrapContentKeys(renderId, contentData, contentKeys, periodKeys, items) {
    for (const item of items) {
      if (item.accessGroups.length === 0) continue;
      /** @type {object[]} */
      const records = [];
      for (const accessGroup of item.accessGroups) {
        for (const t of periodKeys.periodsFor(accessGroup)) {
          const coordinate = { renderId, contentName: item.name, accessGroup, t };
          // Ask the strategy once and copy its bytes before the digest await: the strategy
          // still owns its buffer, and the nonce transcript and GCM must see the same bytes.
          // Any other value passes through uncopied, so the nonce helper refuses it below.
          const selected = this.#contentKeyWrap.aad(coordinate);
          const aad = selected instanceof Uint8Array ? Uint8Array.from(selected) : selected;
          const nonce = await contentKeyWrapNonce({ ...coordinate, aad });
          if (nonce === null) {
            throw dcaError(
              "bad_config",
              `the wrap aad for "${item.name}" at ${accessGroup} ${t} is bytes or undefined`,
            );
          }
          const key = await encrypt(
            periodKeys.keyFor(accessGroup, t),
            nonce,
            contentKeys[item.name],
            aad,
          );
          // The checked entry carries `t` and `key`; the wire spells `t` as
          // `period` beside the accessGroup.
          const { t: period, ...entry } = /** @type {{ t: string, key: string }} */ (
            this.#contentKeyWrap.entry({ t, key: base64urlEncode(key) })
          );
          records.push({ accessGroup, period, ...entry });
        }
      }
      contentData[item.name].keys = /** @type {any} */ (records);
    }
  }

  /**
   * The issuer's side of the same path, the issuer block's
   * `sealed.periodKeys` records `{accessGroup, period, key}`: each periodKey
   * sealed to that issuer's public key, with `period` the label `t`.
   *
   * The groups are the ones this issuer's plan supplies, and the plan was
   * already checked against the render's groups and against what that issuer
   * has to reach.
   *
   * @param {IssuerConfig} issuer
   * @param {import('./issuerSupplyPlan.js').IssuerSupplyPlan} plan
   * @param {string} renderId - the render every one of these blobs is bound to
   * @param {{ periodsFor: (accessGroup: string) => readonly string[], keyFor: (accessGroup: string, t: string) => Uint8Array,
   * }} periodKeys
   * @returns {Promise<{ accessGroup: string, period: string, key: string }[]>}
   */
  async #sealPeriodKeys(issuer, plan, renderId, periodKeys) {
    /** @type {{ accessGroup: string, period: string, key: string }[]} */
    const sealed = [];

    for (const accessGroup of plan.suppliedAccessGroups) {
      if (!plan.periodKeyDelivery[accessGroup].includes("period-keys")) continue;
      for (const t of selectedPeriodSourceTs(
        plan,
        accessGroup,
        periodKeys.periodsFor(accessGroup),
      )) {
        const key = await this.#keySealing.seal(
          periodKeys.keyFor(accessGroup, t),
          issuer.publicKey,
          issuer.algorithm,
          carrierOptions(
            this.#random,
            {
              renderId,
              accessGroup,
              t,
            },
            issuer.envelope,
          ),
        );
        sealed.push({ accessGroup, period: t, key });
      }
    }

    return sealed;
  }

  /**
   * The terminal chain keys this supply gives an issuer. They
   * have their own BIND kind because moving one into a `periodKeys` slot
   * must not turn derivation authority into a period-key answer.
   *
   * @param {IssuerConfig} issuer
   * @param {import('./issuerSupplyPlan.js').IssuerSupplyPlan} plan
   * @param {string} renderId
   * @param {{ chainKeysFor: (accessGroup: string) => { t: string, key: Uint8Array }[], geometryFor: (accessGroup: string) => { chainsPerDay: number, periodMinutes: number }|null }} periodKeys
   * @returns {Promise<{ accessGroup: string, cutoff: string, key: string }[]>}
   */
  async #sealChainKeys(issuer, plan, renderId, periodKeys) {
    /** @type {{ accessGroup: string, cutoff: string, key: string }[]} */
    const sealed = [];

    for (const accessGroup of plan.suppliedAccessGroups) {
      if (!plan.periodKeyDelivery[accessGroup].includes("chain-keys")) continue;
      const geometry = periodKeys.geometryFor(accessGroup);
      if (!geometry) {
        throw dcaError(
          "bad_config",
          `the chain supply for "${accessGroup}" carries the complete geometry its envelope binds`,
        );
      }
      for (const { t, key: chainKey } of periodKeys.chainKeysFor?.(accessGroup) ?? []) {
        const key = await this.#keySealing.seal(
          chainKey,
          issuer.publicKey,
          issuer.algorithm,
          carrierOptions(
            this.#random,
            {
              renderId,
              accessGroup,
              suppliedT: t,
              chainKey: true,
              ...geometry,
            },
            issuer.envelope,
          ),
        );
        sealed.push({ accessGroup, cutoff: t, key });
      }
    }

    return sealed;
  }
}
