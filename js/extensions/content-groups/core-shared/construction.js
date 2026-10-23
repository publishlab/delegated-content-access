// Content-groups construction, validation and cache identities. Portable WebCrypto only.
import { utf8Encode } from "../../../core-shared/codec.js";
import { signableOrigin } from "../../../core-shared/publisherOrigin.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { own } from "../../../core-shared/wire.js";
import { inspectPeriodGeometryBounds } from "../../../core-shared/geometryBounds.js";
import {
  validateAccessGroup,
  validateContentName,
  validateIssuerName,
  isResourceId,
} from "../../../core-shared/names.js";

import {
  chainKeyCoordinate,
  chainKeyLabelAt,
  settleChainGeometry,
} from "../../chain-keys/core-shared/chainKeyConstruction.js";

const STOCK_CHAIN_GEOMETRY = Object.freeze({
  coordinate: chainKeyCoordinate,
  labelAt: chainKeyLabelAt,
  settleGeometry: settleChainGeometry,
});

/**
 * Every production name of the content-groups contract. Renaming one changes a
 * transcript, a wire member or a cache identity, so they live in one place.
 */
export const CONTRACT = Object.freeze({
  profile: "dca-profile-content-groups",
  construction: "dca-construction-content-groups",
  seedSalt: "dca-construction-content-name-seeds",
  seedInfoLabel: "content-name-window",
  seedAadLabel: "dca-bind-content-name-seed",
  envelopeAlgorithm: "ecdh-p256-content-name-seed",
  itemPadSalt: "dca-construction-content-connectors",
  itemPadLabel: "item-pad",
  wire: Object.freeze({
    sealedSeeds: "contentWindowSeeds",
    connectors: "connectors",
    requestedContentGroups: "requestedContentGroups",
    requestedContentKeys: "requestedContentKeys",
    requestedChainCutoffs: "requestedChainCutoffs",
    response: "contentGroupKeys",
    chainKeys: "chainKeys",
    periodKeys: "periodKeys",
    contentKeys: "contentKeys",
    errors: "errors",
  }),
  keyKinds: Object.freeze({
    periodKey: "contentGroupPeriodKey",
    chainKey: "contentGroupChainKey",
  }),
});

/**
 * Trusted deployment bounds. `maxItems` bounds every per-exchange content-name
 * collection; `maxPeriodKeysPerContentGroup` counts period results per (content name,
 * group). None of them grants access or is negotiated on the wire.
 */
export const DEFAULT_LIMITS = Object.freeze({
  maxItems: 64,
  maxGroups: 1024,
  maxPeriodKeysPerContentGroup: 48,
  maxSeedWindows: 2,
  maxWindowsPerGroup: 2,
  maxResponseMembers: 2048,
  maxCachedWindows: 4096,
  maxRivalsPerWindow: 4,
  maxTrialsPerItem: 4096,
});
/** @typedef {typeof DEFAULT_LIMITS} ContentGroupLimits */
const subtle = globalThis.crypto.subtle;

/**
 * Fill trusted limits from the defaults. An unknown name is refused, including
 * the retired `maxScopes` and `maxPeriodKeysPerGroup`.
 * @param {Record<string, unknown>} [input]
 * @returns {ContentGroupLimits}
 */
export function settleLimits(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new Error("limits are trusted configuration");
  for (const name of Object.keys(input))
    if (!Object.hasOwn(DEFAULT_LIMITS, name))
      throw new Error(`unknown content-groups limit ${name}`);
  const limits = { ...DEFAULT_LIMITS, ...input };
  for (const [name, value] of Object.entries(limits))
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0)
      throw new Error(`${name} must be a positive safe integer`);
  return /** @type {ContentGroupLimits} */ (Object.freeze(limits));
}

/**
 * Whether a parsed JSON value is a member map rather than an array or a scalar.
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
export function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** @param {unknown} value @param {number} size @param {string} label */
export function bytes(value, size, label) {
  const result = binaryStringBytes(value);
  if (result === null || result.length !== size)
    throw new Error(`${label} is canonical ${size}-byte base64url`);
  return result;
}
/** @param {unknown} value @param {number} size @param {string} label */
export function keyBytes(value, size, label) {
  if (!(value instanceof Uint8Array) || value.length !== size)
    throw new Error(`${label} is ${size} bytes`);
  return Uint8Array.from(value);
}
/** @param {unknown[]} parts */
export function frame(parts) {
  // This finite transcript has no optional escapes or serializer defaults.
  const tokens = parts.map((part) => {
    if (typeof part === "string" && /^[\x20-\x7e]*$/.test(part) && !/["\\]/.test(part))
      return `"${part}"`;
    if (typeof part === "number" && Number.isSafeInteger(part) && part >= 0) return String(part);
    throw new Error("transcript fields are literal ASCII strings or nonnegative safe integers");
  });
  return utf8Encode(`[${tokens.join(",")}]`);
}
/** @param {unknown} value */
export function checkedPublisher(value) {
  if (typeof value !== "string" || !/^[\x21-\x7e]+$/.test(value) || signableOrigin(value) !== value)
    throw new Error("publisher must be a canonical ASCII HTTPS origin");
  return value;
}
/** @param {unknown} value */
export function checkedResourceId(value) {
  if (!isResourceId(value)) throw new Error("resourceId is a nonempty Unicode scalar string");
  return value;
}
/** @param {string} label @param {any} geometry @param {any} [chain] */
export function checkedWindow(label, geometry, chain = STOCK_CHAIN_GEOMETRY) {
  const at = chain.coordinate(label, geometry);
  if (at.position !== 0) throw new Error("window label is not an aligned start");
  return at;
}
/** @param {any} input @param {any} [chain] */
export function checkedGeometry(input, chain = STOCK_CHAIN_GEOMETRY) {
  if (!input || Object.keys(input).sort().join(",") !== "chainsPerDay,periodMinutes")
    throw new Error("common geometry is one complete pair");
  const g = chain.settleGeometry(input);
  return Object.freeze({ chainsPerDay: g.chainsPerDay, periodMinutes: g.periodMinutes });
}
/** @param {string} value @param {any} geometry @param {any} [chain] */
export function checkedPeriod(value, geometry, chain = STOCK_CHAIN_GEOMETRY) {
  return chain.coordinate(value, geometry);
}
/** @param {unknown} value */
export function checkedRenderId(value) {
  bytes(value, 16, "renderId");
  return value;
}
/** @param {Uint8Array} ikm @param {string} salt @param {unknown[]} info @param {number} length */
export async function hkdf(ikm, salt, info, length) {
  const material = await subtle.importKey("raw", Uint8Array.from(ikm), "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: Uint8Array.from(utf8Encode(salt)),
        info: Uint8Array.from(frame(info)),
      },
      material,
      length * 8,
    ),
  );
}
/** Hash the exact canonical signed origin; lowercase hex is ASCII-only and unambiguous.
 * @param {string} publisher
 */
export async function publisherNamespace(publisher) {
  const origin = checkedPublisher(publisher);
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(origin)),
  );
  return Array.from(digest, (octet) => octet.toString(16).padStart(2, "0")).join("");
}
/** @param {Uint8Array} periodKey @param {{renderId:string,contentName:string}} context */
export async function itemPad(periodKey, { renderId, contentName }) {
  const key = keyBytes(periodKey, 16, "period key");
  checkedRenderId(renderId);
  validateContentName(contentName);
  return hkdf(key, CONTRACT.itemPadSalt, [CONTRACT.itemPadLabel, renderId, contentName], 16);
}
/** @param {Uint8Array} a @param {Uint8Array} b */
export function xor16(a, b) {
  keyBytes(a, 16, "left XOR input");
  keyBytes(b, 16, "right XOR input");
  return Uint8Array.from(a, (n, i) => n ^ b[i]);
}
/** @param {number} minutes @param {any} [chain] */
export function labelAt(minutes, chain = STOCK_CHAIN_GEOMETRY) {
  return chain.labelAt(minutes);
}
/** @param {any} claim @param {string} publisher */
export function validateClaim(claim, publisher) {
  if (!claim || typeof claim !== "object" || claim.origin !== checkedPublisher(publisher))
    throw new Error("verified publisher mismatch");
  checkedRenderId(claim.renderId);
  checkedResourceId(claim.resourceId);
  return {};
}
/** @param {any} input @param {any} [chain] */
export function checkedScope(input, chain = STOCK_CHAIN_GEOMETRY) {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new Error("root derivation scope is required");
  if (Object.hasOwn(input, "groupChains") || Object.hasOwn(input, "chainGeometry"))
    throw new Error("legacy group or chain geometry is unsupported");
  const geometry = checkedGeometry(input.periodGeometry, chain);
  return {
    geometry,
    period: checkedPeriod(input.renderPeriod, geometry, chain),
  };
}
/**
 * One item's connector collection, `[{group, connector}]`, holding only groups
 * with a route. Absent means an ordinary-only item. An empty array, a value
 * that is not an array, or an element that is not a `{group, connector}`
 * record with a valid group and a canonical 16-byte connector is refused,
 * never read as "no route". Raw records count against `maxGroups`. Several
 * records for one group are candidate connectors and each distinct one is
 * kept; an identical copy is dropped.
 * @param {unknown} connectors
 * @param {{maxGroups:number}} limits
 * @returns {Array<{group:string,connector:string}>}
 */
export function checkedConnectors(connectors, limits) {
  if (connectors === undefined) return [];
  if (!Array.isArray(connectors))
    throw new Error("connectors is a collection of {group, connector} records");
  if (connectors.length === 0 || connectors.length > limits.maxGroups)
    throw new Error("connectors holds between one and maxGroups records");
  /** @type {Array<{group:string,connector:string}>} */
  const routes = [];
  for (const entry of connectors) {
    if (!record(entry)) throw new Error("a connector is a {group, connector} record");
    const group = own(entry, "group");
    const connector = own(entry, "connector");
    validateAccessGroup(group);
    bytes(connector, 16, "connector");
    const route = {
      group: /** @type {string} */ (group),
      connector: /** @type {string} */ (connector),
    };
    if (!routes.some((held) => held.group === route.group && held.connector === route.connector))
      routes.push(route);
  }
  return routes;
}

/**
 * Admit a delivery's content records: each content name with its connector
 * routes under `contentData[].connectors`. A root `contentGroups` dictionary
 * is the retired indexed form and is refused rather than read.
 * @param {any} page
 * @param {{maxItems:number,maxGroups:number}} limits
 * @returns {Record<string, Array<{group:string,connector:string}>>}
 */
export function checkedContentRecords(page, limits) {
  if (!record(page) || Object.hasOwn(page, "contentGroups"))
    throw new Error("root contentGroups is the retired indexed form");
  const records = page.contentData;
  if (!Array.isArray(records) || records.length > limits.maxItems)
    throw new Error("invalid contentData");
  /** @type {Record<string, Array<{group:string,connector:string}>>} */
  const items = Object.create(null);
  const selected = new Map();
  for (const entry of records) {
    if (!record(entry)) continue;
    const name = validateContentName(own(entry, "contentName"));
    selected.set(name, entry);
  }
  // Validate only the payload of each selected whole record.
  for (const [name, entry] of selected) {
    items[name] = checkedConnectors(own(entry, CONTRACT.wire.connectors), limits);
  }
  return items;
}

/**
 * One 32-byte seed per publisher, content name, geometry and window:
 * HKDF-SHA256 over the retained secret with info
 * F(["content-name-window", publisherNamespace, contentName, chainsPerDay,
 * periodMinutes, windowStartLabel]).
 * @param {Uint8Array} retainedSecret
 * @param {string} publisher
 * @param {any} geometry
 * @param {string} contentName
 * @param {string} windowStartLabel
 * @param {any} [chain]
 * @returns {Promise<Uint8Array>}
 */
export async function contentNameSeed(
  retainedSecret,
  publisher,
  geometry,
  contentName,
  windowStartLabel,
  chain = STOCK_CHAIN_GEOMETRY,
) {
  const secret = keyBytes(retainedSecret, 32, "retained secret");
  validateContentName(contentName);
  const g = checkedGeometry(geometry, chain);
  const start = checkedWindow(windowStartLabel, g, chain);
  return hkdf(
    secret,
    CONTRACT.seedSalt,
    [
      CONTRACT.seedInfoLabel,
      await publisherNamespace(publisher),
      contentName,
      g.chainsPerDay,
      g.periodMinutes,
      start.startT,
    ],
    32,
  );
}

/**
 * The seed envelope's AAD: F(["dca-bind-content-name-seed", publisherNamespace,
 * renderId, issuerName, contentName, windowStartLabel, chainsPerDay, periodMinutes]).
 * @param {{publisher:string,renderId:string,issuerName:string,contentName:string,
 *   windowStartLabel:string,periodGeometry:any}} binding
 * @param {any} [chain]
 * @returns {Promise<Uint8Array>}
 */
export async function contentNameSeedAad(
  { publisher, renderId, issuerName, contentName, windowStartLabel, periodGeometry },
  chain = STOCK_CHAIN_GEOMETRY,
) {
  checkedPublisher(publisher);
  checkedRenderId(renderId);
  validateIssuerName(issuerName);
  validateContentName(contentName);
  const g = checkedGeometry(periodGeometry, chain);
  checkedWindow(windowStartLabel, g, chain);
  return frame([
    CONTRACT.seedAadLabel,
    await publisherNamespace(publisher),
    renderId,
    issuerName,
    contentName,
    windowStartLabel,
    g.chainsPerDay,
    g.periodMinutes,
  ]);
}

/**
 * @typedef {{kind:string, parts:ReadonlyArray<string>}} ContentGroupPartition
 */

/**
 * @param {string} kind @param {string} publisher @param {any} geometry
 * @param {string} contentName @param {string} group
 * @returns {Readonly<ContentGroupPartition>}
 */
function partition(kind, publisher, geometry, contentName, group) {
  checkedPublisher(publisher);
  const { chainsPerDay, periodMinutes } = geometry ?? {};
  if (inspectPeriodGeometryBounds(chainsPerDay, periodMinutes).kind !== "valid")
    throw new Error("partition geometry is a valid { chainsPerDay, periodMinutes } pair");
  validateContentName(contentName);
  validateAccessGroup(group);
  const parts = [
    CONTRACT.construction,
    publisher,
    String(chainsPerDay),
    String(periodMinutes),
    contentName,
    group,
  ];
  return Object.freeze({ kind, parts: Object.freeze(parts) });
}

/**
 * Cache family of the chain keys of one content name and group. Issuer is not a
 * member: seeds take no issuer input, so two issuers derive equal keys.
 * @param {string} publisher @param {any} geometry @param {string} contentName @param {string} group
 */
export function chainKeyPartition(publisher, geometry, contentName, group) {
  return partition(CONTRACT.keyKinds.chainKey, publisher, geometry, contentName, group);
}

/**
 * Cache family of the period keys of one content name and group; its kind keeps
 * it apart from every ordinary period-key family.
 * @param {string} publisher @param {any} geometry @param {string} contentName @param {string} group
 */
export function periodKeyPartition(publisher, geometry, contentName, group) {
  return partition(CONTRACT.keyKinds.periodKey, publisher, geometry, contentName, group);
}
