import { isAccessGroup, isContentName } from "../../../core-shared/names.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
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
  "requestedChainCutoffs",
  "renderPeriod",
  "periodGeometry",
]);
/** The `sealed` member this extension adds beside the base route maps. */
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
 * @property {Readonly<Record<string, {group: string, connector: string}>>} contentKeys
 * @property {Readonly<Record<string, string>>|undefined} cutoffs
 * @property {Readonly<Record<string, Readonly<Record<string, string>>>>} seeds
 * @property {string} renderPeriod
 * @property {unknown} periodGeometry
 */

/**
 * Read one request's content-group members, raw and bounded, the same way on
 * the issuer and on the client. Null when the request carries none of them.
 * Bounds come first and refuse as `too_many_entries`; every other fault is
 * `binding_failed`. Coordinates (labels, geometry, grid) are the caller's to
 * admit with its chain port; this reader settles only shapes and names.
 * Settled refusals: an empty requested group list, a group or item without a
 * seed, a seed for a name nothing requests, and a request selecting nothing.
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
  for (const [label, map] of /** @type {const} */ ([
    ["requestedContentGroups", groupsIn ?? {}],
    ["requestedContentKeys", keysIn ?? {}],
    ["contentWindowSeeds", seedsIn],
  ])) {
    if (!record(map)) malformed(`${label} is a map`);
    if (Object.keys(map).length > limits.maxItems) overBound(`${label} names over maxItems`);
  }
  const groupsMap = /** @type {Record<string, unknown>} */ (groupsIn ?? {});
  const keysMap = /** @type {Record<string, unknown>} */ (keysIn ?? {});
  const seedsMap = /** @type {Record<string, unknown>} */ (seedsIn);
  for (const list of Object.values(groupsMap))
    if (Array.isArray(list) && list.length > limits.maxGroups)
      overBound("group list over maxGroups");
  for (const windows of Object.values(seedsMap))
    if (record(windows) && Object.keys(windows).length > limits.maxSeedWindows)
      overBound("seed windows over maxSeedWindows");
  const cutoffsIn = own(request, "requestedChainCutoffs");
  if (cutoffsIn !== undefined) {
    if (!record(cutoffsIn)) malformed("requestedChainCutoffs is a map");
    if (Object.keys(cutoffsIn).length > limits.maxSeedWindows * limits.maxItems)
      overBound("requestedChainCutoffs over its bound");
  }

  /** @type {Record<string, {groups: readonly string[], windows: readonly string[]}>} */
  const contentGroups = {};
  /** @type {Record<string, {group: string, connector: string}>} */
  const contentKeys = {};
  /** @type {Record<string, Readonly<Record<string, string>>>} */
  const seeds = {};
  for (const [name, windows] of Object.entries(seedsMap)) {
    if (!isContentName(name) || !record(windows) || Object.keys(windows).length === 0)
      malformed("each seeded content name carries at least one window");
    for (const [label, envelope] of Object.entries(windows))
      if (label.length === 0 || typeof envelope !== "string") malformed("seed envelope");
    seeds[name] = Object.freeze({ .../** @type {Record<string, string>} */ (windows) });
  }
  /** @param {string} name */
  const windowsOf = (name) => {
    if (!Object.hasOwn(seeds, name)) malformed(`${name} is requested without a seed`);
    return Object.freeze(Object.keys(seeds[name]));
  };
  for (const [name, list] of Object.entries(groupsMap)) {
    if (
      !isContentName(name) ||
      !Array.isArray(list) ||
      list.length === 0 ||
      new Set(list).size !== list.length ||
      !list.every((group) => typeof group === "string" && isAccessGroup(group))
    )
      malformed("requested groups are a nonempty list of unique group names");
    contentGroups[name] = Object.freeze({
      groups: Object.freeze([.../** @type {string[]} */ (list)]),
      windows: windowsOf(name),
    });
  }
  for (const [name, entry] of Object.entries(keysMap)) {
    if (
      !isContentName(name) ||
      !record(entry) ||
      Object.keys(entry).sort().join(",") !== "connector,group" ||
      typeof entry.group !== "string" ||
      !isAccessGroup(entry.group) ||
      binaryStringBytes(entry.connector)?.length !== 16
    )
      malformed("a requested content key is {group, connector16}");
    windowsOf(name);
    contentKeys[name] = Object.freeze({
      group: /** @type {string} */ (entry.group),
      connector: /** @type {string} */ (entry.connector),
    });
  }
  for (const name of Object.keys(seeds))
    if (!Object.hasOwn(contentGroups, name) && !Object.hasOwn(contentKeys, name))
      malformed(`${name} carries a seed nothing requests`);
  if (Object.keys(contentGroups).length === 0 && Object.keys(contentKeys).length === 0)
    malformed("the request selects no content-group route");
  const renderPeriod = own(request, "renderPeriod");
  const periodGeometry = own(request, "periodGeometry");
  if (typeof renderPeriod !== "string" || !record(periodGeometry))
    malformed("renderPeriod and periodGeometry are required");
  /** @type {Record<string, string>|undefined} */
  let cutoffs;
  if (cutoffsIn !== undefined) {
    const entries = Object.entries(/** @type {Record<string, unknown>} */ (cutoffsIn));
    if (entries.some(([, label]) => typeof label !== "string"))
      malformed("requestedChainCutoffs maps a window start to one cutoff label");
    cutoffs = Object.freeze(/** @type {Record<string, string>} */ (Object.fromEntries(entries)));
  }
  return Object.freeze({
    contentGroups: Object.freeze(contentGroups),
    contentKeys: Object.freeze(contentKeys),
    cutoffs,
    seeds: Object.freeze(seeds),
    renderPeriod,
    periodGeometry,
  });
}

/**
 * The three response sections of the content-groups answer, as trusted
 * composition hands them to the response walk and to client-bound wrapping:
 * `contentGroups.chainKeys.<name>.<group>.<cutoff> = key`,
 * `contentGroups.periodKeys.<name>.<group>.<period> = key` and
 * `contentGroups.contentKeys.<name> = key`. Recovered item keys keep the
 * ordinary `contentKey` kind and its AES handle. Each section reports a
 * retired opening key at the same coordinate under `contentGroups.errors`,
 * with the fixed leaf `{error: "key_retired"}`.
 */
export const RESPONSE_SECTIONS = Object.freeze([
  Object.freeze({
    path: Object.freeze([WIRE.response, WIRE.chainKeys]),
    depth: 3,
    keyKind: CONTRACT.keyKinds.chainKey,
    errorPath: Object.freeze([WIRE.response, WIRE.errors, WIRE.chainKeys]),
  }),
  Object.freeze({
    path: Object.freeze([WIRE.response, WIRE.periodKeys]),
    depth: 3,
    keyKind: CONTRACT.keyKinds.periodKey,
    errorPath: Object.freeze([WIRE.response, WIRE.errors, WIRE.periodKeys]),
  }),
  Object.freeze({
    path: Object.freeze([WIRE.response, WIRE.contentKeys]),
    depth: 1,
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
