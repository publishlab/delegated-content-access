// The content-group members a client adds to its request to one issuer,
// projected from the delivery. The client's request builder sends them; the
// publisher's request budget sizes the same projection, so the two cannot
// drift apart. The issuer reads requests with `readContentGroupRequest`.

import { isContentName } from "../../../core-shared/names.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { isPeriodKeyLabel } from "../../../core-shared/periodLabels.js";
import { inspectPeriodGeometryBounds } from "../../../core-shared/geometryBounds.js";
import { CONTRACT, checkedConnectors, record } from "../core-shared/construction.js";

const WIRE = CONTRACT.wire;

/**
 * @typedef {object} ContentGroupRequestSelection
 * @property {Record<string, Record<string, string>>} seeds - content name to window to envelope
 * @property {Record<string, string[]>} groups - content name to requested groups
 * @property {Record<string, {group: string, connector: string}>} contentKeys
 * @property {Record<string, string>|undefined} cutoffs - window start to cutoff label
 * @property {unknown} renderPeriod
 * @property {unknown} periodGeometry
 */

/** @param {string} why @returns {never} */
function badNarrowing(why) {
  throw dcaError("bad_config", `content-group request narrowing: ${why}`);
}

/**
 * The page's connector maps, group to connector per content name, or null
 * when the page's content records do not admit.
 * @param {any} page
 * @param {import("../core-shared/construction.js").ContentGroupLimits} limits
 */
function pageConnectorMaps(page, limits) {
  if (!record(page) || Object.hasOwn(page, "contentGroups")) return null;
  const records = own(page, "contentData");
  if (!record(records) || Object.keys(records).length > limits.maxItems) return null;
  /** @type {Record<string, Record<string, string>>} */
  const maps = Object.create(null);
  for (const [name, entry] of Object.entries(records)) {
    if (!isContentName(name)) return null;
    try {
      if (!record(entry)) continue;
      const routes = checkedConnectors(own(entry, WIRE.connectors), limits);
      maps[name] = Object.fromEntries(routes.map(({ group, connector }) => [group, connector]));
    } catch {
      // A malformed map supplies no connector route for this item. Producer
      // validation remains strict; valid sibling maps keep their own routes.
    }
  }
  return maps;
}

/**
 * Identify only the render window needed to offer an item connector. This is
 * request projection, not a grant or an authenticated assertion. The issuer
 * still validates the complete geometry and calendar coordinates.
 * @param {any} page
 * @returns {string|null}
 */
function renderWindow(page) {
  const t = own(page, "renderPeriod");
  const g = own(page, "periodGeometry");
  if (
    !isPeriodKeyLabel(t) ||
    !record(g) ||
    Object.keys(g).sort().join(",") !== "chainsPerDay,periodMinutes"
  )
    return null;
  const bounds = inspectPeriodGeometryBounds(g.chainsPerDay, g.periodMinutes);
  if (bounds.kind !== "valid") return null;
  const hour = Number(t.slice(7, 9));
  const minute = Number(t.slice(9, 11));
  const minutes = hour * 60 + minute;
  if (hour > 23 || minute > 59 || minutes % /** @type {number} */ (g.periodMinutes) !== 0)
    return null;
  const start = Math.floor(minutes / bounds.windowMinutes) * bounds.windowMinutes;
  return `${t.slice(0, 7)}${String(Math.floor(start / 60)).padStart(2, "0")}${String(start % 60).padStart(2, "0")}`;
}

/**
 * The issuer's seed windows per content name; undefined when the page offers
 * that issuer no seed, null when it offers seeds that do not admit. Without
 * narrowing, malformed seeds relay no content-group member and base routes keep
 * their own admission; explicit narrowing of a needed name refuses them.
 * @param {any} page
 * @param {string} issuerName
 * @param {import("../core-shared/construction.js").ContentGroupLimits} limits
 * @returns {Record<string, Record<string, string>>|null|undefined}
 */
function issuerSeeds(page, issuerName, limits) {
  const held = own(own(own(own(page, "issuerData"), issuerName), "sealed"), WIRE.sealedSeeds);
  if (held === undefined) return undefined;
  if (!record(held) || Object.keys(held).length > limits.maxItems) return null;
  /** @type {Record<string, Record<string, string>>} */
  const seeds = Object.create(null);
  for (const [name, windows] of Object.entries(held)) {
    if (!isContentName(name) || !record(windows)) return null;
    const entries = Object.entries(windows);
    if (entries.length === 0 || entries.length > limits.maxSeedWindows) return null;
    if (entries.some(([label, envelope]) => label.length === 0 || typeof envelope !== "string"))
      return null;
    seeds[name] = /** @type {Record<string, string>} */ (Object.fromEntries(entries));
  }
  return seeds;
}

/**
 * Select one issuer's content-group request members for the content names
 * this attempt concerns. Without narrowing, each needed name with a seed from
 * this issuer asks every group and offers one render-window item connector.
 * An explicit request-kind map replaces that default; its entries for names outside this
 * attempt, or without a seed from this issuer, are skipped, never widened. For
 * an offered route, a group outside the item's connector map, a `seedWindows`
 * choice that selects none of its windows and malformed seeds still refuse.
 * Returns null when no route is selected: the builder then sends no
 * content-group member at all.
 * @param {any} page - the parsed delivery
 * @param {string} issuerName
 * @param {readonly string[]} candidates - content names this attempt concerns
 * @param {Readonly<Record<string, any>>} narrowing - settled by `settleNarrowing`
 * @param {import("../core-shared/construction.js").ContentGroupLimits} limits
 * @returns {ContentGroupRequestSelection|null}
 */
export function contentGroupRequestSelection(page, issuerName, candidates, narrowing, limits) {
  const maps = pageConnectorMaps(page, limits);
  const held = issuerSeeds(page, issuerName, limits);
  const wanted = new Set(candidates);
  const windowFilter = narrowing.seedWindows;
  /**
   * One host narrowing serves every issuer of the walk: a needed name this
   * issuer holds no seed for goes to it as an ordinary route only, so an
   * issuer that denied it does not block the siblings a later issuer serves.
   * @param {string} name
   */
  const unseeded = (name) => held === undefined || (held !== null && held[name] === undefined);
  /** @param {string} name @param {boolean} explicit */
  const windowsOf = (name, explicit) => {
    if (held === null) {
      if (explicit)
        throw dcaError("bad_config", `issuer ${issuerName}'s content-group seeds do not admit`);
      return null;
    }
    const windows = held?.[name];
    if (windows === undefined) return null;
    const labels = Object.keys(windows).filter(
      (label) => windowFilter === undefined || windowFilter.includes(label),
    );
    if (labels.length === 0) {
      if (explicit) badNarrowing(`seedWindows selects no window of ${name}`);
      return null;
    }
    return Object.fromEntries(labels.map((label) => [label, windows[label]]));
  };
  /** @param {string} name */
  const connectorMap = (name) => maps?.[name] ?? {};

  /** @type {Record<string, Record<string, string>>} */
  const seeds = {};
  /** @type {Record<string, string[]>} */
  const groups = {};
  /** @type {Record<string, {group: string, connector: string}>} */
  const contentKeys = {};
  const explicitGroups = narrowing.requestedContentGroups;
  if (explicitGroups !== undefined) {
    for (const [name, list] of Object.entries(explicitGroups)) {
      // One client serves many pages and issuers: a name this attempt does not
      // need, or this issuer offers no seed for, may lack a connector here
      // without being a misconfiguration.
      if (!wanted.has(name) || unseeded(name)) continue;
      for (const group of list)
        if (!Object.hasOwn(connectorMap(name), group))
          badNarrowing(`${name} has no connector for group ${group}`);
      const windows = windowsOf(name, true);
      if (windows === null) continue;
      groups[name] = [...list];
      seeds[name] = windows;
    }
  } else if (maps !== null && held !== null && held !== undefined) {
    for (const name of candidates) {
      const list = Object.keys(connectorMap(name));
      const windows = list.length === 0 ? null : windowsOf(name, false);
      if (windows === null) continue;
      groups[name] = list;
      seeds[name] = windows;
      if (narrowing.requestedContentKeys === undefined) {
        const window = renderWindow(page);
        if (window !== null && Object.hasOwn(windows, window)) {
          const group = [...list].sort()[0];
          contentKeys[name] = { group, connector: connectorMap(name)[group] };
        }
      }
    }
  }
  for (const [name, group] of Object.entries(narrowing.requestedContentKeys ?? {})) {
    if (!wanted.has(name) || unseeded(name)) continue;
    const map = connectorMap(name);
    if (!Object.hasOwn(map, group)) badNarrowing(`${name} has no connector for group ${group}`);
    const windows = windowsOf(name, true);
    if (windows === null) continue;
    contentKeys[name] = { group, connector: map[group] };
    seeds[name] = windows;
  }
  if (Object.keys(seeds).length === 0) return null;
  return {
    seeds,
    groups,
    contentKeys,
    cutoffs: narrowing.requestedChainCutoffs,
    renderPeriod: own(page, "renderPeriod"),
    periodGeometry: own(page, "periodGeometry"),
  };
}

/**
 * Write a selection as request members: the `sealed` member and the root
 * members, each a fresh copy.
 * @param {ContentGroupRequestSelection} selection
 */
export function contentGroupRequestMembers(selection) {
  return {
    sealed: { [WIRE.sealedSeeds]: structuredClone(selection.seeds) },
    members: {
      renderPeriod: structuredClone(selection.renderPeriod),
      periodGeometry: structuredClone(selection.periodGeometry),
      [WIRE.requestedContentGroups]: structuredClone(selection.groups),
      ...(Object.keys(selection.contentKeys).length === 0
        ? {}
        : { [WIRE.requestedContentKeys]: structuredClone(selection.contentKeys) }),
      ...(selection.cutoffs === undefined
        ? {}
        : { requestedChainCutoffs: structuredClone(selection.cutoffs) }),
    },
  };
}
