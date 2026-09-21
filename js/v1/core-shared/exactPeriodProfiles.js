// @ts-check
//
// The canonical exact-period construction: one 16-byte `periodKey[t]` leaf
// wrapping one 16-byte content key under AES-128-GCM.
//
// This retained identity is construction metadata for callers that describe
// the canonical route. It is not a render or issuer width selector.

import { dcaError } from "./errors.js";

/** The one canonical exact-period construction identity. */
export const EXACT_PERIOD_PROFILE = "dca-v1-exact-period";

/**
 * @typedef {object} ExactPeriodProfile
 * @property {string} name - the profile identifier, which is not a wire member
 * @property {number} leafBytes - the exact `periodKey[t]` width. The wrap uses the
 *   leaf as its AES key, so this is also the AES key width
 * @property {string} wrapAlgorithm - the wrap algorithm that follows from that
 *   width, spelled out for a reader and for vector metadata
 */

/** @type {Record<string, ExactPeriodProfile>} */
const PROFILES = {
  [EXACT_PERIOD_PROFILE]: Object.freeze({
    name: EXACT_PERIOD_PROFILE,
    leafBytes: 16,
    wrapAlgorithm: "AES-128-GCM",
  }),
};

/**
 * Returns the named exact-period profile. It reports an unknown name as a
 * configuration fault to whoever stated it, so a deployment that misspells its
 * profile fails closed at selection instead of at a width check further down.
 *
 * @param {string} name
 * @returns {ExactPeriodProfile}
 */
export function exactPeriodProfile(name) {
  if (typeof name !== "string" || !Object.hasOwn(PROFILES, name)) {
    throw dcaError(
      "unsupported_option",
      `there is no exact-period profile ${JSON.stringify(name)}; the profiles are ` +
        `${Object.keys(PROFILES).join(" and ")}`,
    );
  }
  return PROFILES[name];
}
