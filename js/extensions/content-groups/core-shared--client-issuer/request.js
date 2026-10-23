import { isAccessGroup, isContentName } from "../../../core-shared/names.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own, setOwn } from "../../../core-shared/wire.js";
import { CONTRACT, record, settleLimits } from "../core-shared/construction.js";

// Content-name request members.
const WIRE = CONTRACT.wire;
/** The local narrowing names; the last two never reach the wire. */
export const NARROWING = Object.freeze([
  "requestedContentGroups",
  "requestedContentKeys",
  "requestedChainCutoffs",
  "requestedContentItems",
  "seedWindows",
]);
/** Request members this extension adds beside the base request. */
export const REQUEST_MEMBERS = Object.freeze([
  WIRE.requestedContentGroups,
  WIRE.requestedContentKeys,
  WIRE.requestedChainCutoffs,
  "renderPeriod",
  "periodGeometry",
]);
/** The `sealed` member this extension adds beside the base sealed collections. */
export const SEALED_MEMBERS = Object.freeze([WIRE.sealedSeeds]);

/** @param {string} why @returns {never} */
function badNarrowing(why) {
  throw dcaError("bad_config", `content-group request narrowing: ${why}`);
}

/** @param {unknown} value @param {number} max @param {string} label */
function nameList(value, max, label) {
  if (
    !Array.isArray(value) ||
    value.length > max ||
    new Set(value).size !== value.length ||
    value.some((name) => typeof name !== "string")
  )
    badNarrowing(`${label} is a list of at most ${max} unique names`);
  return /** @type {string[]} */ (value);
}

/**
 * Admit trusted local narrowing before any page read, so a page fault never
 * masks a configuration fault. Every content-name map is bounded by maxItems.
 * @param {unknown} input
 * @param {import("../core-shared/construction.js").ContentGroupLimits} limits
 */
export function settleNarrowing(input, limits) {
  if (input === undefined) return Object.freeze({});
  if (!record(input)) badNarrowing("narrowing is an object");
  const narrowing = /** @type {Record<string, unknown>} */ (structuredClone(input));
  for (const name of Object.keys(narrowing))
    if (!NARROWING.includes(name)) badNarrowing(`unknown field ${name}`);
  const groups = narrowing.requestedContentGroups;
  if (groups !== undefined) {
    if (!record(groups) || Object.keys(groups).length > limits.maxItems)
      badNarrowing("requestedContentGroups is a map of at most maxItems content names");
    for (const [name, list] of Object.entries(groups)) {
      if (!isContentName(name)) badNarrowing(`${JSON.stringify(name)} is no content name`);
      const admitted = nameList(list, limits.maxGroups, `requestedContentGroups.${name}`);
      if (admitted.length === 0) badNarrowing(`requestedContentGroups.${name} names no group`);
      if (!admitted.every(isAccessGroup)) badNarrowing(`requestedContentGroups.${name} names`);
    }
  }
  const keys = narrowing.requestedContentKeys;
  if (keys !== undefined) {
    if (!record(keys) || Object.keys(keys).length > limits.maxItems)
      badNarrowing("requestedContentKeys is a map of at most maxItems content names");
    for (const [name, group] of Object.entries(keys))
      if (!isContentName(name) || typeof group !== "string" || !isAccessGroup(group))
        badNarrowing("requestedContentKeys maps a content name to one group name");
  }
  if (narrowing.requestedContentItems !== undefined) {
    const items = nameList(
      narrowing.requestedContentItems,
      limits.maxItems,
      "requestedContentItems",
    );
    if (!items.every(isContentName)) badNarrowing("requestedContentItems names content names");
  }
  if (narrowing.seedWindows !== undefined)
    nameList(narrowing.seedWindows, limits.maxSeedWindows * limits.maxItems, "seedWindows");
  const cutoffs = narrowing.requestedChainCutoffs;
  if (
    cutoffs !== undefined &&
    (!record(cutoffs) ||
      Object.keys(cutoffs).length > limits.maxSeedWindows * limits.maxItems ||
      Object.values(cutoffs).some((label) => typeof label !== "string"))
  )
    badNarrowing("requestedChainCutoffs maps a window start to one cutoff label");
  return Object.freeze(narrowing);
}

/** @param {string} why @returns {never} */
function malformed(why) {
  throw dcaError("binding_failed", `content-group request: ${why}`);
}
/** @param {string} why @returns {never} */
function overBound(why) {
  throw dcaError("too_many_entries", `content-group request: ${why}`);
}

/**
 * @typedef {object} ContentGroupRequestView
 * @property {Readonly<Record<string, {groups: readonly string[], windows: readonly string[]}>>} contentGroups
 *   - per content name, the union of its requested groups and its seeded windows
 * @property {Readonly<Record<string, readonly {group: string, connector: string}[]>>} contentKeys
 *   - per content name, every distinct item-route alternative
 * @property {Readonly<Record<string, readonly string[]>>|undefined} cutoffs - per window start,
 *   every distinct requested cutoff label; the caller admits all of them, then takes the lowest
 * @property {Readonly<Record<string, Readonly<Record<string, readonly string[]>>>>} seeds - per
 *   content name and window start, every distinct seed envelope
 * @property {string} renderPeriod
 * @property {unknown} periodGeometry
 */

/**
 * Whether `value` is a record with exactly the named members.
 * @param {unknown} value @param {readonly string[]} members
 * @returns {value is Record<string, unknown>}
 */
function exactly(value, members) {
  return (
    record(value) &&
    Object.keys(value).length === members.length &&
    members.every((name) => Object.hasOwn(value, name))
  );
}

/**
 * Extensible request records still carry every required member as an own field.
 * @param {unknown} value @param {readonly string[]} members
 * @returns {value is Record<string, unknown>}
 */
function requiredOwn(value, members) {
  return record(value) && members.every((name) => Object.hasOwn(value, name));
}

/**
 * Count raw records per content name, before any record is checked or merged.
 * A record without a string `contentName` counts under no name; the shape
 * check refuses it later.
 * @param {readonly unknown[]} records @param {(record: unknown) => number} weight
 */
function rawPerName(records, weight = () => 1) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const entry of records) {
    const name = own(entry, "contentName");
    if (typeof name === "string") counts.set(name, (counts.get(name) ?? 0) + weight(entry));
  }
  return counts;
}

/**
 * Read one request's content-group members, raw and bounded, the same way on
 * the issuer and on the client. Null when the request carries none of them.
 * Bounds come first and refuse as `too_many_entries`; every other fault is
 * `binding_failed`. Coordinates (labels, geometry, grid) are the caller's to
 * admit with its chain port; this reader settles only shapes and names.
 * Settled refusals: an empty requested group list, a group or item without a
 * seed, a seed for a name nothing requests, and a request selecting nothing.
 *
 * Each member is an array of records. Raw records count against the bounds
 * before they merge: repeated `requestedContentGroups` records of one name
 * union their groups; `requestedContentKeys` records are item-route
 * alternatives, each `{group, connector}` pair kept; seed records at one
 * window are candidates; every cutoff label of a window is kept, and the
 * caller admits each before it takes the lowest. Identical copies merge.
 * @param {unknown} request
 * @param {Record<string, number>} [inputLimits]
 * @returns {Readonly<ContentGroupRequestView>|null}
 */
export function readContentGroupRequest(request, inputLimits) {
  const limits = settleLimits(inputLimits);
  const groupsIn = own(request, WIRE.requestedContentGroups);
  const keysIn = own(request, WIRE.requestedContentKeys);
  const seedsIn = own(own(request, "sealed"), WIRE.sealedSeeds);
  if (groupsIn === undefined && keysIn === undefined && seedsIn === undefined) return null;
  const cutoffsIn = own(request, WIRE.requestedChainCutoffs);
  for (const [label, list, max] of /** @type {const} */ ([
    [WIRE.requestedContentGroups, groupsIn === undefined ? [] : groupsIn, limits.maxItems],
    [WIRE.requestedContentKeys, keysIn === undefined ? [] : keysIn, limits.maxItems],
    [WIRE.sealedSeeds, seedsIn, limits.maxItems * limits.maxSeedWindows],
    [
      WIRE.requestedChainCutoffs,
      cutoffsIn === undefined ? [] : cutoffsIn,
      limits.maxSeedWindows * limits.maxItems,
    ],
  ])) {
    if (!Array.isArray(list)) malformed(`${label} is an array of records`);
    if (list.length > max) overBound(`${label} carries over its bound of records`);
  }
  const groupRecords = /** @type {unknown[]} */ (groupsIn === undefined ? [] : groupsIn);
  const keyRecords = /** @type {unknown[]} */ (keysIn === undefined ? [] : keysIn);
  const seedRecords = /** @type {unknown[]} */ (seedsIn);
  const cutoffRecords = /** @type {unknown[]|undefined} */ (cutoffsIn);
  for (const count of rawPerName(groupRecords, (entry) => {
    const list = own(entry, "groups");
    return Array.isArray(list) ? list.length : 0;
  }).values())
    if (count > limits.maxGroups) overBound("requested groups over maxGroups");
  const seedCounts = rawPerName(seedRecords);
  if (seedCounts.size > limits.maxItems) overBound("seeded content names over maxItems");
  for (const count of seedCounts.values())
    if (count > limits.maxSeedWindows) overBound("seed records over maxSeedWindows");

  /** @type {Record<string, Record<string, string[]>>} */
  const seeds = {};
  for (const entry of seedRecords) {
    if (
      !requiredOwn(entry, ["contentName", "windowStart", "key"]) ||
      !isContentName(entry.contentName) ||
      typeof entry.windowStart !== "string" ||
      entry.windowStart.length === 0 ||
      typeof entry.key !== "string"
    )
      malformed("a seed is {contentName, windowStart, key}");
    const name = /** @type {string} */ (entry.contentName);
    if (!Object.hasOwn(seeds, name)) setOwn(seeds, name, {});
    const windows = own(seeds, name);
    if (!Object.hasOwn(windows, entry.windowStart)) setOwn(windows, entry.windowStart, []);
    const envelopes = own(windows, entry.windowStart);
    if (!envelopes.includes(entry.key)) envelopes.push(entry.key);
  }
  /** @param {string} name */
  const windowsOf = (name) => {
    if (!Object.hasOwn(seeds, name)) malformed(`${name} is requested without a seed`);
    return Object.freeze(Object.keys(own(seeds, name)));
  };

  /** @type {Record<string, string[]>} */
  const groupSets = {};
  for (const entry of groupRecords) {
    if (
      !requiredOwn(entry, ["contentName", "groups"]) ||
      !isContentName(entry.contentName) ||
      !Array.isArray(entry.groups) ||
      entry.groups.length === 0 ||
      new Set(entry.groups).size !== entry.groups.length ||
      !entry.groups.every((group) => typeof group === "string" && isAccessGroup(group))
    )
      malformed("requested groups are {contentName, groups} with a nonempty list of unique names");
    const name = /** @type {string} */ (entry.contentName);
    if (!Object.hasOwn(groupSets, name)) setOwn(groupSets, name, []);
    const union = own(groupSets, name);
    for (const group of entry.groups) if (!union.includes(group)) union.push(group);
  }
  /** @type {Record<string, {groups: readonly string[], windows: readonly string[]}>} */
  const contentGroups = {};
  for (const [name, groups] of Object.entries(groupSets))
    setOwn(
      contentGroups,
      name,
      Object.freeze({ groups: Object.freeze(groups), windows: windowsOf(name) }),
    );

  /** @type {Record<string, {group: string, connector: string}[]>} */
  const contentKeys = {};
  for (const entry of keyRecords) {
    if (
      !exactly(entry, ["contentName", "group", "connector"]) ||
      !isContentName(entry.contentName) ||
      typeof entry.group !== "string" ||
      !isAccessGroup(entry.group) ||
      binaryStringBytes(entry.connector)?.length !== 16
    )
      malformed("a requested content key is {contentName, group, connector16}");
    const name = /** @type {string} */ (entry.contentName);
    windowsOf(name);
    if (!Object.hasOwn(contentKeys, name)) setOwn(contentKeys, name, []);
    const routes = own(contentKeys, name);
    const route = { group: entry.group, connector: /** @type {string} */ (entry.connector) };
    if (
      !routes.some(
        (/** @type {any} */ r) => r.group === route.group && r.connector === route.connector,
      )
    )
      routes.push(Object.freeze(route));
  }
  for (const routes of Object.values(contentKeys)) Object.freeze(routes);

  for (const name of Object.keys(seeds))
    if (!Object.hasOwn(contentGroups, name) && !Object.hasOwn(contentKeys, name))
      malformed(`${name} carries a seed nothing requests`);
  if (Object.keys(contentGroups).length === 0 && Object.keys(contentKeys).length === 0)
    malformed("the request selects no content-group route");
  const renderPeriod = own(request, "renderPeriod");
  const periodGeometry = own(request, "periodGeometry");
  if (typeof renderPeriod !== "string" || !record(periodGeometry))
    malformed("renderPeriod and periodGeometry are required");
  /** @type {Record<string, string[]>|undefined} */
  let cutoffs;
  const suppliedWindows = new Set(Object.values(seeds).flatMap((windows) => Object.keys(windows)));
  if (cutoffRecords !== undefined) {
    cutoffs = {};
    for (const entry of cutoffRecords) {
      if (
        !requiredOwn(entry, ["windowStart", "cutoff"]) ||
        typeof entry.windowStart !== "string" ||
        typeof entry.cutoff !== "string"
      )
        malformed("a requested chain cutoff is {windowStart, cutoff}");
      if (!suppliedWindows.has(entry.windowStart))
        malformed("a requested chain cutoff names no supplied seed window");
      const held = /** @type {Record<string, string[]>} */ (cutoffs);
      if (!Object.hasOwn(held, entry.windowStart)) setOwn(held, entry.windowStart, []);
      const labels = own(held, entry.windowStart);
      if (!labels.includes(entry.cutoff)) labels.push(entry.cutoff);
    }
    for (const labels of Object.values(/** @type {Record<string, string[]>} */ (cutoffs)))
      Object.freeze(labels);
  }
  for (const windows of Object.values(seeds)) {
    for (const envelopes of Object.values(windows)) Object.freeze(envelopes);
    Object.freeze(windows);
  }
  return Object.freeze({
    contentGroups: Object.freeze(contentGroups),
    contentKeys: Object.freeze(contentKeys),
    cutoffs: cutoffs === undefined ? undefined : Object.freeze(cutoffs),
    seeds: Object.freeze(seeds),
    renderPeriod,
    periodGeometry,
  });
}

/**
 * Wire records. Each record names its coordinates; array position carries
 * none. The type parameter is the transported key value: a string for direct
 * delivery, or the selected transport's protected value. These declarations
 * describe structure; they do not validate incoming JSON or distinguish
 * content names, groups and labels that are all represented as strings.
 * A section holds the records the issuer returned, not every requested
 * coordinate: a lookup can find nothing.
 *
 * @template Key
 * @typedef {{ contentName: string, group: string, cutoff: string, key: Key }} ContentGroupChainKey
 */
/** @template Key @typedef {{ contentName: string, group: string, period: string, key: Key }} ContentGroupPeriodKey */
/** @template Key @typedef {{ contentName: string, key: Key }} ContentGroupContentKey */
/** @template Key @typedef {ContentGroupChainKey<Key>[]} ContentGroupChainKeys */
/** @template Key @typedef {ContentGroupPeriodKey<Key>[]} ContentGroupPeriodKeys */
/** @template Key @typedef {ContentGroupContentKey<Key>[]} ContentGroupContentKeys */
/** @typedef {{ error: 'key_retired' }} ContentGroupRetirement */
/**
 * Error records carry their key kind's coordinate fields and the fixed
 * retirement error, never a `key`.
 *
 * @typedef {object} ContentGroupResponseErrors
 * @property {({ contentName: string, group: string, cutoff: string, key?: never } & ContentGroupRetirement)[]} [chainKeys]
 * @property {({ contentName: string, group: string, period: string, key?: never } & ContentGroupRetirement)[]} [periodKeys]
 * @property {({ contentName: string, key?: never } & ContentGroupRetirement)[]} [contentKeys]
 */
/**
 * The `contentGroupKeys` member, excluding the ordinary sibling `keys`.
 * Absent subsections are omitted. Use only after the appropriate admission
 * checks when reading untrusted input; a type annotation is not admission.
 *
 * @template Key
 * @typedef {object} ContentGroupResponse
 * @property {ContentGroupChainKeys<Key>} [chainKeys]
 * @property {ContentGroupPeriodKeys<Key>} [periodKeys]
 * @property {ContentGroupContentKeys<Key>} [contentKeys]
 * @property {ContentGroupResponseErrors} [errors]
 */

/**
 * The three response sections of the content-groups answer, as trusted
 * composition hands them to the response walk and to client-bound wrapping:
 * `contentGroupKeys.chainKeys = [{contentName, group, cutoff, key}]`,
 * `contentGroupKeys.periodKeys = [{contentName, group, period, key}]` and
 * `contentGroupKeys.contentKeys = [{contentName, key}]`. Recovered item keys
 * keep the ordinary `contentKey` kind and its AES handle. Each section
 * reports a retired opening key under `contentGroupKeys.errors` with a record of
 * the same coordinate fields and `error: "key_retired"`.
 */
export const RESPONSE_SECTIONS = Object.freeze([
  Object.freeze({
    path: Object.freeze([WIRE.response, WIRE.chainKeys]),
    fields: Object.freeze(["contentName", "group", "cutoff"]),
    keyKind: CONTRACT.keyKinds.chainKey,
    errorPath: Object.freeze([WIRE.response, WIRE.errors, WIRE.chainKeys]),
  }),
  Object.freeze({
    path: Object.freeze([WIRE.response, WIRE.periodKeys]),
    fields: Object.freeze(["contentName", "group", "period"]),
    keyKind: CONTRACT.keyKinds.periodKey,
    errorPath: Object.freeze([WIRE.response, WIRE.errors, WIRE.periodKeys]),
  }),
  Object.freeze({
    path: Object.freeze([WIRE.response, WIRE.contentKeys]),
    fields: Object.freeze(["contentName"]),
    keyKind: "contentKey",
    errorPath: Object.freeze([WIRE.response, WIRE.errors, WIRE.contentKeys]),
  }),
]);

/**
 * The two derivation kinds this extension defines for client-bound transport:
 * each opens to exactly 16 raw bytes, never to a key handle. Composition hands
 * this to the transport's descriptor settlement; the wire never names a kind.
 */
export const KIND_DESCRIPTORS = Object.freeze({
  [CONTRACT.keyKinds.periodKey]: Object.freeze({ width: 16, open: "raw" }),
  [CONTRACT.keyKinds.chainKey]: Object.freeze({ width: 16, open: "raw" }),
});
