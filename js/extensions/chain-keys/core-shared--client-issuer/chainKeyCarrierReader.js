// @ts-check
//
// Read one untrusted chain-key carrier. A request seals its members under
// `sealed.chainKeys` and a response returns them under `keys.chainKeys`, both
// as `{accessGroup, cutoff, key}` records. The two sides spell only two things
// differently: the context and what a member value is called once read. Every
// rule below applies the same way on both sides: whole-pair geometry with no
// label inference, one cutoff per window, the two raw-record bounds, rival
// records at one cutoff kept as candidates, and invalid kept distinguishable
// from absent without carrying parser detail onward.

import { own } from "../../../core-shared/wire.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { chainMemberLimit } from "../../../core-shared/chainMemberLimit.js";
import { MAX_CHAIN_MEMBERS_PER_FAMILY } from "../../../core-shared/geometryBounds.js";
import {
  chainKeyCoordinate,
  resolveChainGeometry,
  validateChainKeyAccessGroup,
} from "../core-shared/chainKeyConstruction.js";

export const CHAIN_KEYS_MEMBER = "chainKeys";

const INVALID = Object.freeze({ kind: /** @type {const} */ ("invalid") });
const ABSENT = Object.freeze({ kind: /** @type {const} */ ("absent") });

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Place syntactically valid labels before inspecting envelope values. A bad
 * value still occupies its window, so it cannot hide a duplicate. Labels that
 * do not resolve to a coordinate are skipped. Rival records share one label
 * and so one position; only two different labels in one window collide.
 *
 * @param {readonly string[]} labels - distinct, in the order members are placed
 * @param {import('../core-shared/chainKeyConstruction.js').ChainGeometry} geometry
 * @returns {readonly { t: string, coordinate: any }[]|null}
 */
function positionedOn(labels, geometry) {
  const windows = new Set();
  const positioned = [];
  for (const t of labels) {
    let coordinate;
    try {
      coordinate = chainKeyCoordinate(t, geometry);
    } catch {
      continue;
    }
    if (windows.has(coordinate.windowStart)) return null;
    windows.add(coordinate.windowStart);
    positioned.push(Object.freeze({ t, coordinate }));
  }
  return Object.freeze(positioned);
}

/**
 * @typedef {object} ChainCarrierView
 * @property {readonly string[]} presented
 * @property {(accessGroup: string) => any} family
 */

/**
 * @param {object} carrier
 * @param {unknown} carrier.container - the `sealed` or `keys` object holding the collection
 * @param {unknown} carrier.context - the sibling `periodGeometry` geometry context
 * @param {string} carrier.valueName - what this carrier calls one member value
 * @param {(value: unknown) => boolean} [carrier.valueIsValid] - the direct
 *   carrier accepts strings; response composition may also admit a
 *   client-bound key entry object before its selected transport opener validates it
 * @param {number} [carrier.maxChainMembersPerMessage] - trusted capacity, default 16
 * @returns {ChainCarrierView}
 */
export function chainKeyCarrierReader({
  container,
  context,
  valueName,
  maxChainMembersPerMessage,
  valueIsValid = (value) => binaryStringBytes(value) !== null,
}) {
  const maximum = chainMemberLimit(maxChainMembersPerMessage);
  const hasCollection = record(container) && Object.hasOwn(container, CHAIN_KEYS_MEMBER);
  const rawCollection = own(container, CHAIN_KEYS_MEMBER);
  const malformedCollection = hasCollection && !Array.isArray(rawCollection);
  const collection = Array.isArray(rawCollection) ? rawCollection : [];

  // An element that is not a record, or names no string access group, names
  // no family and is skipped. Every other record counts as raw toward both
  // bounds before any dedupe.
  /** @type {Map<string, Record<string, unknown>[]>} */
  const byFamily = new Map();
  let messageMembers = 0;
  for (const element of collection) {
    const accessGroup = own(element, "accessGroup");
    if (!record(element) || typeof accessGroup !== "string") continue;
    messageMembers++;
    if (!byFamily.has(accessGroup)) byFamily.set(accessGroup, []);
    /** @type {Record<string, unknown>[]} */ (byFamily.get(accessGroup)).push(element);
  }
  const presented = Object.freeze([...byFamily.keys()]);
  /** @type {Map<string, any>} */
  const families = new Map();

  for (const [accessGroup, records] of byFamily) {
    try {
      validateChainKeyAccessGroup(accessGroup);
    } catch {
      families.set(accessGroup, INVALID);
      continue;
    }
    const labels = [
      ...new Set(
        records
          .map((member) => own(member, "cutoff"))
          .filter((/** @type {unknown} */ t) => typeof t === "string"),
      ),
    ];
    const geometry = resolveChainGeometry(context, accessGroup);
    if (geometry === null || records.length > MAX_CHAIN_MEMBERS_PER_FAMILY) {
      families.set(accessGroup, INVALID);
      continue;
    }

    const positioned = positionedOn(/** @type {string[]} */ (labels).sort(), geometry);
    if (positioned === null) {
      families.set(accessGroup, INVALID);
      continue;
    }
    const members = [];
    const malformedMembers = [];
    for (const { t, coordinate } of positioned) {
      // Every distinct valid value at this cutoff is a candidate member. A
      // cutoff none of whose records holds a valid value is one malformed
      // member, so an authorized coordinate there still gets its answer.
      /** @type {unknown[]} */
      const values = [];
      for (const member of records) {
        if (own(member, "cutoff") !== t) continue;
        const value = own(member, "key");
        if (valueIsValid(value) && !values.some((held) => sameValue(held, value)))
          values.push(value);
      }
      for (const value of values)
        members.push(Object.freeze({ t, [valueName]: value, coordinate }));
      if (values.length === 0) malformedMembers.push(Object.freeze({ t, coordinate }));
    }
    families.set(
      accessGroup,
      Object.freeze({
        kind: /** @type {const} */ ("valid"),
        geometry,
        members: Object.freeze(members),
        malformedMembers: Object.freeze(malformedMembers),
      }),
    );
  }

  if (messageMembers > maximum) {
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

/**
 * Identical candidates are one candidate. A string compares by value; a
 * client-bound key entry object compares by its JSON text, which is what an
 * identical record repeats.
 *
 * @param {unknown} left @param {unknown} right
 */
function sameValue(left, right) {
  if (typeof left === "string" || typeof right === "string") return left === right;
  return JSON.stringify(left) === JSON.stringify(right);
}
