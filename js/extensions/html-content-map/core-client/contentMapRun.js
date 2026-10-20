// @ts-check
//
// Explicit reconstruction sessions over one admitted HTML delivery. Placement
// is opt-in, keeps the delivery carrier, and retries only items still locked.

import { DcaError, dcaError } from "../../../core-shared/errors.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import {
  admitMapItems,
  mapCarrier,
  mapLimits,
  parseContentMap,
} from "../core-shared--client-publisher/contentMap.js";
import { openMapItems } from "./mapItems.js";
import { admitLockedDocument, resolveTargets } from "../core-shared--client-publisher/targets.js";
import { classValueWithout, treeEntries } from "../core-shared--client-publisher/treePort.js";

/** The map failure codes of Section 9. */
export const MAP_FAILURES = Object.freeze([
  "source_refused",
  "delivery_refused",
  "map_absent",
  "map_malformed",
  "map_limit",
  "map_version_unsupported",
  "map_type_unsupported",
  "map_item_undeclared",
  "map_item_no_ciphertext",
  "map_selector_unsupported",
  "map_document_quirks",
  "map_target_count",
  "map_target_overlap",
  "map_target_unplaceable",
  "map_target_carrier",
  "map_class_absent",
  "map_target_stale",
  "map_placement_refused",
  "map_output_unstable",
  "item_failed",
  "key_acquisition_failed",
]);

/**
 * The report of Section 6.4. It is conformance evidence, not a DCA wire member.
 *
 * @typedef {{ outcome: 'complete'|'partial', items: Record<string, import('./mapItems.js').ItemState> }
 *   | { outcome: 'failed', failure: string, items?: Record<string, import('./mapItems.js').ItemState> }} MapReport
 */

/**
 * What one run returns: the report, whether the tree now holds a
 * reconstructed document, and each rule's target path on the locked document
 * (Section 7.2, observation 2), empty after a map failure.
 *
 * @typedef {object} MapRunResult
 * @property {MapReport} report
 * @property {boolean} reconstructed
 * @property {{ rule: number, path: number[] }[]} targets
 */

/**
 * The failed result for one refusal, or null when the error is not a map
 * failure and belongs to the caller.
 *
 * @param {unknown} cause
 * @returns {MapRunResult|null}
 */
export function mapFailure(cause) {
  if (!(cause instanceof DcaError) || !MAP_FAILURES.includes(cause.code)) return null;
  return { report: { outcome: "failed", failure: cause.code }, reconstructed: false, targets: [] };
}

/**
 * The failed result for a delivery the base structural processing refused
 * (Section 6.1, step 2): `delivery_refused`. The base code, such as
 * `bad_page`, is this implementation's own and never reaches the report.
 *
 * @param {unknown} cause
 * @returns {MapRunResult|null}
 */
export function structuralFailure(cause) {
  if (!(cause instanceof DcaError) || cause.code !== "bad_page") return null;
  return {
    report: { outcome: "failed", failure: "delivery_refused" },
    reconstructed: false,
    targets: [],
  };
}

/**
 * The Section 4.2 delivery facts, read through the base reader and delivery
 * view: an item is declared when `contentData` names it, and carried when the
 * sealed-content carrier holds canonical base64url for it.
 *
 * @param {{ dcaData: any, reader: { extract: (contentName: string) => string|null } }} client
 * @returns {import('../core-shared--client-publisher/contentMap.js').MapDelivery}
 */
export function mapDeliveryOf(client) {
  return {
    declares: (contentName) => client.dcaData.contentNames().includes(contentName),
    contentType: (contentName) => {
      const record = client.dcaData.contentDataFor(contentName);
      return record && Object.hasOwn(record, "contentType") ? record.contentType : null;
    },
    carriesCiphertext: (contentName) => {
      const ciphertext = client.reader.extract(contentName);
      return ciphertext !== null && binaryStringBytes(ciphertext) !== null;
    },
  };
}

/**
 * @typedef {object} MapRunOptions
 * @property {import('../core-shared--client-publisher/treePort.js').TreePort} tree
 * @property {import('../core-shared--client-publisher/contentMap.js').MapDelivery} delivery
 * @property {() => import('./mapItems.js').MapKeyClient|Promise<import('./mapItems.js').MapKeyClient>} keyClient
 * @property {() => boolean} [isEligible] - host lifetime check, immediately before live effects
 * @property {Partial<import('../core-shared--client-publisher/contentMap.js').MapLimits>} [limits]
 */

/**
 * @typedef {object} ContentMapSession
 * @property {() => void} dispose - permanently retires this session, including pending work
 * @property {() => Promise<MapRunResult>} run - first attempt or explicit retry of locked items
 * @property {() => {html: string, report: MapReport}} snapshot - current output, refused after external mutation
 */

/**
 * Capture one delivery and its target identities before key acquisition.
 * Completed placements are never replayed. A failure ends the session;
 * creating a new session requires a fresh locked document.
 *
 * @param {MapRunOptions} options
 * @returns {ContentMapSession}
 */
export function createContentMapSession({
  tree,
  delivery,
  keyClient,
  limits,
  isEligible = () => true,
}) {
  let disposed = false;
  const eligible = () => {
    try {
      return !disposed && isEligible() === true;
    } catch {
      return false;
    }
  };
  /** @type {MapRunResult|null} */
  let latest = null;
  /** @type {import('../core-shared--client-publisher/contentMap.js').ContentMap|null} */
  let map = null;
  /** @type {import('../core-shared--client-publisher/targets.js').ResolvedRule[]} */
  let resolved = [];
  /** @type {Record<string, import('./mapItems.js').ItemState>} */
  const states = {};
  let running = false;
  const capture = () => ({
    html: tree.serialize(),
    elements: treeEntries(tree).map((entry) => entry.element),
  });
  /** @param {{children: any[], removed: any[], classes: any[]}} mask */
  const identitiesOutside = (mask) =>
    treeEntries(tree)
      .filter((entry) => {
        if (mask.removed.includes(entry.element)) return false;
        for (let at = entry.parent; at !== null; at = at.parent) {
          if (mask.children.includes(at.element) || mask.removed.includes(at.element)) return false;
        }
        return true;
      })
      .map((entry) => entry.element);
  let expected = { html: "", elements: /** @type {any[]} */ ([]) };
  const current = () => {
    const actual = capture();
    return (
      actual.html === expected.html &&
      actual.elements.length === expected.elements.length &&
      actual.elements.every((element, index) => element === expected.elements[index])
    );
  };
  try {
    const admittedLimits = mapLimits(limits);
    admitLockedDocument(tree, admittedLimits);
    const entries = treeEntries(tree);
    const carrier = mapCarrier(tree, entries);
    let data;
    try {
      data = JSON.parse(tree.text(carrier.element));
    } catch {
      throw dcaError("map_malformed", "the delivery carrier is not JSON");
    }
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      throw dcaError("map_malformed", "the delivery carrier is not an object");
    }
    if (!Object.hasOwn(data, "contentMap"))
      throw dcaError("map_absent", "the delivery has no contentMap");
    map = parseContentMap(JSON.stringify(data.contentMap), admittedLimits);
    admitMapItems(map, delivery);
    resolved = resolveTargets(tree, entries, map);
    expected = capture();
  } catch (cause) {
    latest = mapFailure(cause);
    if (latest === null) throw cause;
  }

  const copy = (/** @type {MapRunResult} */ result) =>
    /** @type {MapRunResult} */ (JSON.parse(JSON.stringify(result)));
  const failure = (/** @type {string} */ code) => {
    latest = {
      report: {
        outcome: "failed",
        failure: code,
        ...(Object.keys(states).length ? { items: { ...states } } : {}),
      },
      reconstructed: false,
      targets: [],
    };
    return copy(latest);
  };

  return {
    dispose() {
      disposed = true;
    },
    async run() {
      if (running) throw dcaError("bad_config", "a map session is already running");
      if (latest?.report.outcome === "failed") return copy(latest);
      if (!eligible() || !current()) return failure("map_target_stale");
      if (latest?.report.outcome === "complete") return copy(latest);
      running = true;
      try {
        const pending = Object.keys(
          /** @type {import('../core-shared--client-publisher/contentMap.js').ContentMap} */ (map)
            .items,
        ).filter((name) => states[name] === undefined || states[name] === "locked");
        let opened;
        try {
          const client = await keyClient();
          if (!eligible() || !current()) return failure("map_target_stale");
          opened = await openMapItems(client, pending);
        } catch (cause) {
          if (cause instanceof DcaError && cause.code === "bad_config") throw cause;
          if (cause instanceof DcaError && cause.code === "key_acquisition_failed") {
            const known = /** @type {any} */ (cause).knownItems ?? {};
            for (const [name, item] of Object.entries(known)) {
              if (
                Object.hasOwn(/** @type {any} */ (map).items, name) &&
                /** @type {any} */ (
                  item.state === "opened" || /** @type {any} */ (item).state === "failed"
                )
              ) {
                states[name] = /** @type {any} */ (item).state;
              }
            }
          }
          return failure("key_acquisition_failed");
        }
        if (!eligible() || !current()) return failure("map_target_stale");
        for (const name of pending) {
          const item = opened[name];
          if (item.state !== "opened") {
            states[name] = item.state;
            continue;
          }
          // The map admitted this type before the key was awaited. The fill
          // takes that captured type; a delivery whose record changed between
          // the two reads is defective. Content AAD does not bind the type.
          if (item.contentType !== /** @type {any} */ (map).items[name]) {
            states[name] = "failed";
            continue;
          }
          const rules = resolved.filter(({ rule }) => rule.item === name);
          /** @type {import('../core-shared--client-publisher/treePort.js').PreparedFill[]} */
          const fills = [];
          const fillTargets = rules
            .filter(({ rule }) => rule.op === "fill")
            .map(({ target }) => target.element);
          try {
            for (const { rule, target } of rules) {
              if (rule.op === "fill")
                fills.push(tree.prepareFill(target.element, item.text, item.contentType));
            }
            if (!eligible() || !current()) return failure("map_target_stale");
            for (let index = 0; index < fills.length; index++) {
              if (!eligible()) throw dcaError("map_target_stale", "the owning context ended");
              const mask = { children: [fillTargets[index]], removed: [], classes: [] };
              const before = tree.snapshotWithout(mask);
              const identities = identitiesOutside(mask);
              fills[index].commit();
              const after = identitiesOutside(mask);
              if (
                !eligible() ||
                tree.snapshotWithout(mask) !== before ||
                !fills[index].matches() ||
                after.length !== identities.length ||
                !after.every((element, i) => element === identities[i])
              ) {
                throw dcaError(
                  "map_target_stale",
                  "a fill changed content outside its controlled effect",
                );
              }
            }
          } catch (cause) {
            for (const fill of [...fills].reverse()) {
              try {
                fill.rollback();
              } catch {
                /* A refusal still cannot become success. */
              }
            }
            states[name] = "failed";
            return failure(
              cause instanceof DcaError && cause.code === "map_target_stale"
                ? "map_target_stale"
                : "map_placement_refused",
            );
          }
          // Every fill for this item committed before revealing any gate.
          try {
            for (const { rule, target } of rules) {
              if (rule.op === "fill") continue;
              if (!eligible()) throw dcaError("map_target_stale", "the owning context ended");
              const mask = {
                children: [],
                removed: rule.op === "remove" ? [target.element] : [],
                classes: rule.op === "removeClass" ? [target.element] : [],
              };
              const before = tree.snapshotWithout(mask);
              const identities = identitiesOutside(mask);
              const expectedClass =
                rule.op === "removeClass"
                  ? classValueWithout(
                      /** @type {string} */ (tree.attribute(target.element, "class")),
                      /** @type {string} */ (rule.className),
                    )
                  : null;
              if (rule.op === "remove") tree.remove(target.element);
              else tree.removeClass(target.element, /** @type {string} */ (rule.className));
              const after = identitiesOutside(mask);
              const remaining = treeEntries(tree).map((entry) => entry.element);
              if (
                !eligible() ||
                tree.snapshotWithout(mask) !== before ||
                after.length !== identities.length ||
                !after.every((element, i) => element === identities[i]) ||
                (rule.op === "remove"
                  ? remaining.includes(target.element)
                  : tree.attribute(target.element, "class") !== expectedClass)
              ) {
                throw dcaError(
                  "map_target_stale",
                  "a gate changed content outside its controlled effect",
                );
              }
            }
          } catch (cause) {
            states[name] = "failed";
            expected = capture();
            return failure(
              cause instanceof DcaError && cause.code === "map_target_stale"
                ? "map_target_stale"
                : "map_placement_refused",
            );
          }
          states[name] = "opened";
          expected = capture();
        }
        if (Object.values(states).includes("failed")) return failure("item_failed");
        latest = {
          report: {
            outcome: Object.values(states).every((state) => state === "opened")
              ? "complete"
              : "partial",
            items: { ...states },
          },
          reconstructed: true,
          targets: resolved.map(({ rule, target }) => ({ rule: rule.index, path: target.path })),
        };
        return copy(latest);
      } finally {
        running = false;
      }
    },
    snapshot() {
      if (running || latest === null)
        throw dcaError("bad_config", "the session has no completed attempt");
      if (latest.report.outcome === "failed")
        throw dcaError(latest.report.failure, "a failed session has no reconstructed output");
      if (!eligible() || !current())
        throw dcaError("map_target_stale", "the reconstructed document changed");
      return { html: tree.serialize(), report: copy(latest).report };
    },
  };
}

/**
 * One explicit reconstruction attempt. Retain a session to retry locked items.
 * @param {MapRunOptions} options
 * @returns {Promise<MapRunResult>}
 */
export async function runContentMap(options) {
  return createContentMapSession(options).run();
}
