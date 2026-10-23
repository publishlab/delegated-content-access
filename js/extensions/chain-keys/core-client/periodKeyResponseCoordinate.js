// @ts-check

import { chainKeyCarrierReader } from "../core-shared--client-issuer/chainKeyCarrierReader.js";
import { chainKeyCoordinate } from "../core-shared/chainKeyConstruction.js";
import { own } from "../../../core-shared/wire.js";

// The request this answer came back to, read through the same carrier reader
// the issuer reads it with, and kept by request identity so one response
// association costs one reading whatever the number of access groups. The
// client profile reads the request itself rather than importing the issuer's
// request module, which stays on the issuer side of the extension.
/** @type {WeakMap<object, Map<number, any>>} */
const resolvedRequests = new WeakMap();

/** @param {unknown} request @param {number} maximum
 * @returns {import("../core-shared--client-issuer/chainKeyCarrierReader.js").ChainCarrierView}
 */
export function requestCarrierOf(request, maximum) {
  const read = () =>
    chainKeyCarrierReader({
      container: own(request, "sealed"),
      context: own(request, "periodGeometry"),
      valueName: "sealed",
      maxChainMembersPerMessage: maximum,
    });
  if (request === null || typeof request !== "object") return read();
  let capacities = resolvedRequests.get(request);
  if (capacities === undefined) {
    capacities = new Map();
    resolvedRequests.set(request, capacities);
  }
  const held = capacities.get(maximum);
  if (held !== undefined) return held;
  const view = read();
  capacities.set(maximum, view);
  return view;
}

/**
 * A response cutoff is reachable from at least one source member the associated
 * request presented: same stationary window, at or below its supplied
 * position.
 *
 * @param {string} cutoffT
 * @param {{ geometry: object, members: readonly { coordinate: { windowStart: number, position: number } }[] }} asked
 * @returns {boolean}
 */
export function cutoffWithinPresentedReach(cutoffT, asked) {
  let cutoff;
  try {
    cutoff = chainKeyCoordinate(cutoffT, /** @type {any} */ (asked.geometry));
  } catch {
    return false;
  }
  return asked.members.some(
    ({ coordinate }) =>
      coordinate.windowStart === cutoff.windowStart && cutoff.position <= coordinate.position,
  );
}

/** @param {unknown} value */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * A returned period key may sit at a coordinate whose period key the request
 * relayed unchanged, or be projected from one of its chain members. Projected
 * period keys use request geometry; the response needs none.
 *
 * @param {string} accessGroup
 * @param {string} t
 * @param {unknown} request
 * @param {number} maximum
 * @returns {boolean}
 */
export function acceptsPeriodKeyResponseCoordinate(accessGroup, t, request, maximum) {
  const presented = own(own(request, "sealed"), "periodKeys");
  if (
    Array.isArray(presented) &&
    presented.some(
      (entry) =>
        record(entry) &&
        own(entry, "accessGroup") === accessGroup &&
        own(entry, "period") === t &&
        typeof own(entry, "key") === "string",
    )
  )
    return true;

  const asked = requestCarrierOf(request, maximum).family(accessGroup);
  return asked.kind === "valid" && cutoffWithinPresentedReach(t, asked);
}
