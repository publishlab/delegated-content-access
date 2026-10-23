// The content-group members a client adds to its request to one issuer,
// projected from the delivery. The client's request builder sends them; the
// publisher's request budget sizes the same projection, so the two cannot
// drift apart. The issuer reads requests with `readContentGroupRequest`.

import { isContentName, isIssuerName } from "../../../core-shared/names.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { isPeriodKeyLabel } from "../../../core-shared/periodLabels.js";
import { inspectPeriodGeometryBounds } from "../../../core-shared/geometryBounds.js";
import { recordsByName } from "../../../core-shared--client-publisher/deliveryRecords.js";
import { CONTRACT, checkedConnectors, record } from "../core-shared/construction.js";

const WIRE = CONTRACT.wire;

/** @typedef {{ group: string, connector: string }} ConnectorRoute */

/**
 * @typedef {object} ContentGroupRequestSelection
 * @property {Record<string, Record<string, readonly string[]>>} seeds - content name to window
 *   to its distinct seed envelopes
 * @property {Record<string, string[]>} groups - content name to requested groups
 * @property {Record<string, readonly ConnectorRoute[]>} contentKeys - content name to its item
 *   routes, each group with its own connector
 * @property {{ windowStart: string, cutoff: string }[]|undefined} cutoffs
 * @property {unknown} renderPeriod
 * @property {unknown} periodGeometry
 */

/** @param {string} why @returns {never} */
function badNarrowing(why) {
  throw dcaError("bad_config", `content-group request narrowing: ${why}`);
}

/**
 * The page's connector routes per content name, in record order, or null
 * when the page's content records do not admit. Several connectors for one
 * group are candidate routes, and each is kept.
 * @param {any} page
 * @param {import("../core-shared/construction.js").ContentGroupLimits} limits
 */
function pageConnectorRoutes(page, limits) {
  if (!record(page) || Object.hasOwn(page, "contentGroups")) return null;
  const records = recordsByName(own(page, "contentData"), "contentName", isContentName);
  if (records === null || records.size > limits.maxItems) return null;
  /** @type {Map<string, ConnectorRoute[]>} */
  const routes = new Map();
  for (const [name, entry] of records) {
    try {
      routes.set(name, checkedConnectors(own(entry, WIRE.connectors), limits));
    } catch {
      // A malformed collection supplies no connector route for this item.
      // Producer validation remains strict; valid sibling items keep theirs.
    }
  }
  return routes;
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
 * The issuer's seed envelopes per content name and window; undefined when
 * the page offers that issuer no seed, null when it offers seeds that do not
 * admit. Several records at one window are candidate seeds and each is kept.
 * Malformed seed collections relay no content-group member, including with
 * explicit narrowing; ordinary routes and other issuers keep their admission.
 * @param {any} page
 * @param {string} issuerName
 * @param {import("../core-shared/construction.js").ContentGroupLimits} limits
 * @returns {Record<string, Record<string, string[]>>|null|undefined}
 */
function issuerSeeds(page, issuerName, limits) {
  const block = recordsByName(own(page, "issuerData"), "issuerName", isIssuerName)?.get(issuerName);
  const held = own(own(block, "sealed"), WIRE.sealedSeeds);
  if (held === undefined) return undefined;
  if (!Array.isArray(held)) return null;
  /** @type {Map<string, number>} */
  const raw = new Map();
  /** @type {Record<string, Record<string, string[]>>} */
  const seeds = Object.create(null);
  for (const entry of held) {
    const name = own(entry, "contentName");
    const window = own(entry, "windowStart");
    const envelope = own(entry, "key");
    if (
      !record(entry) ||
      !isContentName(name) ||
      typeof window !== "string" ||
      window.length === 0 ||
      typeof envelope !== "string"
    )
      return null;
    // Raw records count against the bounds before copies merge.
    raw.set(name, (raw.get(name) ?? 0) + 1);
    if (/** @type {number} */ (raw.get(name)) > limits.maxSeedWindows) return null;
    if (raw.size > limits.maxItems) return null;
    seeds[name] ??= Object.create(null);
    const envelopes = (seeds[name][window] ??= []);
    if (!envelopes.includes(envelope)) envelopes.push(envelope);
  }
  return seeds;
}

/**
 * Select one issuer's content-group request members for the content names
 * this attempt concerns. Without narrowing, each needed name with a seed from
 * this issuer asks every group and offers, as item-route alternatives, every
 * connector record of its lexically first group.
 * An explicit request-kind map replaces that default; its entries for names outside this
 * attempt, or without a seed from this issuer, are skipped, never widened. For
 * an offered route, a group outside the item's connector records, a `seedWindows`
 * choice that selects none of its admitted windows still refuse.
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
  const held = issuerSeeds(page, issuerName, limits);
  if (held === undefined || held === null) return null;
  const routesByName = pageConnectorRoutes(page, limits);
  const wanted = new Set(candidates);
  const windowFilter = narrowing.seedWindows;
  /**
   * One host narrowing serves every issuer of the walk: a needed name this
   * issuer holds no seed for goes to it as an ordinary route only, so an
   * issuer that denied it does not block the siblings a later issuer serves.
   * @param {string} name
   */
  const unseeded = (name) => held[name] === undefined;
  /** @param {string} name @param {boolean} explicit */
  const windowsOf = (name, explicit) => {
    const windows = held[name];
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
  /** @param {string} name @returns {ConnectorRoute[]} */
  const routesOf = (name) => routesByName?.get(name) ?? [];
  /** @param {string} name @param {string} group */
  const routesThrough = (name, group) => routesOf(name).filter((route) => route.group === group);

  /** @type {Record<string, Record<string, readonly string[]>>} */
  const seeds = {};
  /** @type {Record<string, string[]>} */
  const groups = {};
  /** @type {Record<string, readonly ConnectorRoute[]>} */
  const contentKeys = {};
  const explicitGroups = narrowing.requestedContentGroups;
  if (explicitGroups !== undefined) {
    for (const [name, list] of Object.entries(explicitGroups)) {
      // One client serves many pages and issuers: a name this attempt does not
      // need, or this issuer offers no seed for, may lack a connector here
      // without being a misconfiguration.
      if (!wanted.has(name) || unseeded(name)) continue;
      for (const group of list)
        if (routesThrough(name, group).length === 0)
          badNarrowing(`${name} has no connector for group ${group}`);
      const windows = windowsOf(name, true);
      if (windows === null) continue;
      groups[name] = [...list];
      seeds[name] = windows;
    }
  } else if (routesByName !== null) {
    for (const name of candidates) {
      const list = [...new Set(routesOf(name).map((route) => route.group))];
      const windows = list.length === 0 ? null : windowsOf(name, false);
      if (windows === null) continue;
      groups[name] = list;
      seeds[name] = windows;
      if (narrowing.requestedContentKeys === undefined) {
        const window = renderWindow(page);
        if (window !== null && Object.hasOwn(windows, window))
          // Every connector record of the chosen group is one candidate route.
          contentKeys[name] = routesThrough(name, [...list].sort()[0]);
      }
    }
  }
  for (const [name, group] of Object.entries(narrowing.requestedContentKeys ?? {})) {
    if (!wanted.has(name) || unseeded(name)) continue;
    const routes = routesThrough(name, group);
    if (routes.length === 0) badNarrowing(`${name} has no connector for group ${group}`);
    const windows = windowsOf(name, true);
    if (windows === null) continue;
    contentKeys[name] = routes;
    seeds[name] = windows;
  }
  if (Object.keys(seeds).length === 0) return null;
  const cutoffs = narrowing.requestedChainCutoffs;
  const selectedWindows = new Set(Object.values(seeds).flatMap((windows) => Object.keys(windows)));
  return {
    seeds,
    groups,
    contentKeys,
    cutoffs:
      cutoffs === undefined
        ? undefined
        : Object.entries(/** @type {Record<string, string>} */ (cutoffs))
            .filter(([windowStart]) => selectedWindows.has(windowStart))
            .map(([windowStart, cutoff]) => ({ windowStart, cutoff })),
    renderPeriod: own(page, "renderPeriod"),
    periodGeometry: own(page, "periodGeometry"),
  };
}

/**
 * Write a selection as request members: the `sealed` member and the root
 * members, each a fresh copy and each a collection of records.
 * @param {ContentGroupRequestSelection} selection
 */
export function contentGroupRequestMembers(selection) {
  const seeds = Object.entries(selection.seeds).flatMap(([contentName, windows]) =>
    Object.entries(windows).flatMap(([windowStart, envelopes]) =>
      envelopes.map((key) => ({ contentName, windowStart, key })),
    ),
  );
  const windows = new Set(seeds.map(({ windowStart }) => windowStart));
  const items = Object.entries(selection.contentKeys).flatMap(([contentName, routes]) =>
    routes.map(({ group, connector }) => ({ contentName, group, connector })),
  );
  return {
    sealed: { [WIRE.sealedSeeds]: seeds },
    members: {
      renderPeriod: structuredClone(selection.renderPeriod),
      periodGeometry: structuredClone(selection.periodGeometry),
      [WIRE.requestedContentGroups]: Object.entries(selection.groups).map(
        ([contentName, groups]) => ({ contentName, groups: [...groups] }),
      ),
      ...(items.length === 0 ? {} : { [WIRE.requestedContentKeys]: items }),
      ...(selection.cutoffs === undefined
        ? {}
        : {
            [WIRE.requestedChainCutoffs]: selection.cutoffs
              .filter(({ windowStart }) => windows.has(windowStart))
              .map((entry) => ({ ...entry })),
          }),
    },
  };
}
