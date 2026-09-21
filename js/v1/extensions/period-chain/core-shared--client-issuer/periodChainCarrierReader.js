// @ts-check
//
// Read one untrusted period-chain carrier. A request seals its members under
// `sealed.periodChainKeys` and a response returns them under
// `keys.periodChainKeys`. The two sides spell only three things differently:
// the container, the context and the member-value name. Every rule below
// applies the same way on
// both sides: whole-pair geometry with no label inference, one
// member per window, the two message bounds, and invalid kept distinguishable
// from absent without carrying parser detail onward.

import { own } from "../../../core-shared/wire.js";
import {
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
} from "../../../core-shared/geometryBounds.js";
import {
  periodChainCoordinate,
  resolvePeriodChainGeometry,
  validatePeriodChainAccessGroup,
} from "../core-shared/periodChainConstruction.js";

export const PERIOD_CHAIN_COLLECTION = "periodChainKeys";

const INVALID = Object.freeze({ kind: /** @type {const} */ ("invalid") });
const ABSENT = Object.freeze({ kind: /** @type {const} */ ("absent") });

/** @param {unknown} value */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Place one family's labels on its geometry, in label order. A label that does
 * not resolve to a coordinate, and a second member in a window already taken,
 * both answer `null`, and neither carries parser detail onward. The catch here
 * sees only the construction's typed refusal.
 *
 * @param {object} rawFamily
 * @param {readonly string[]} labels - in the order members are placed
 * @param {import('../core-shared/periodChainConstruction.js').ChainGeometry} geometry
 * @param {string} valueName
 * @returns {readonly any[]|null}
 */
function membersOn(rawFamily, labels, geometry, valueName) {
  const windows = new Set();
  const members = [];
  for (const t of labels) {
    let coordinate;
    try {
      coordinate = periodChainCoordinate(t, geometry);
    } catch {
      return null;
    }
    if (windows.has(coordinate.windowStart)) return null;
    windows.add(coordinate.windowStart);
    members.push(
      Object.freeze({
        t,
        [valueName]: /** @type {string} */ (own(rawFamily, t)),
        coordinate,
      }),
    );
  }
  return Object.freeze(members);
}

/**
 * @typedef {object} ChainCarrierView
 * @property {readonly string[]} presented
 * @property {(accessGroup: string) => any} family
 */

/**
 * @param {object} carrier
 * @param {unknown} carrier.container - the `sealed` or `keys` object holding the collection
 * @param {unknown} carrier.context - the sibling `periodChain` geometry context
 * @param {string} carrier.valueName - what this carrier calls one member value
 * @returns {ChainCarrierView}
 */
export function periodChainCarrierReader({ container, context, valueName }) {
  const hasCollection = record(container) && Object.hasOwn(container, PERIOD_CHAIN_COLLECTION);
  const rawCollection = own(container, PERIOD_CHAIN_COLLECTION);
  const malformedCollection = hasCollection && !record(rawCollection);
  const collection = malformedCollection || !record(rawCollection) ? {} : rawCollection;
  const presented = Object.freeze(Object.keys(collection));
  /** @type {Map<string, any>} */
  const families = new Map();
  let messageMembers = 0;

  for (const accessGroup of presented) {
    const rawFamily = own(collection, accessGroup);
    try {
      validatePeriodChainAccessGroup(accessGroup);
    } catch {
      families.set(accessGroup, INVALID);
      continue;
    }
    if (!record(rawFamily)) {
      families.set(accessGroup, INVALID);
      continue;
    }
    const labels = Object.keys(rawFamily);
    messageMembers += labels.length;
    const geometry = resolvePeriodChainGeometry(context, accessGroup);
    if (
      geometry === null ||
      labels.length === 0 ||
      labels.length > MAX_CHAIN_MEMBERS_PER_FAMILY ||
      labels.some((t) => typeof own(rawFamily, t) !== "string")
    ) {
      families.set(accessGroup, INVALID);
      continue;
    }

    const members = membersOn(rawFamily, labels.sort(), geometry, valueName);
    if (members === null) {
      families.set(accessGroup, INVALID);
      continue;
    }
    families.set(
      accessGroup,
      Object.freeze({
        kind: /** @type {const} */ ("valid"),
        geometry,
        members,
      }),
    );
  }

  if (messageMembers > MAX_CHAIN_MEMBERS_PER_MESSAGE) {
    for (const accessGroup of presented) families.set(accessGroup, INVALID);
  }

  return Object.freeze({
    presented,
    family(accessGroup) {
      if (malformedCollection) return INVALID;
      return families.get(accessGroup) ?? ABSENT;
    },
  });
}
