// @ts-check
//
// The conformance profile descriptor of the period-key profile: its name, the fixed
// 16-byte `periodKey[t]` width and the AES-128-GCM wrap that width implies.
//
// Callers read the descriptor to name the profile and state its fixed width, for
// example in a planner report. It derives no key, and no render or issuer selects a
// width through it: v1 fixes the period key at 16 bytes.

import { dcaError } from "./errors.js";

/** The name of the period-key conformance profile. */
export const PERIOD_KEY_PROFILE = "dca-profile-period-keys";

/**
 * @typedef {object} PeriodKeyProfile
 * @property {string} name - the profile identifier, which is not a wire member
 * @property {number} periodKeyBytes - the `periodKey[t]` width. The wrap uses the
 *   period key as its AES key, so this is also the AES key width
 * @property {string} wrapAlgorithm - the wrap algorithm that follows from that
 *   width, spelled out for a reader and for vector metadata
 */

/** @type {Record<string, PeriodKeyProfile>} */
const PROFILES = {
  [PERIOD_KEY_PROFILE]: Object.freeze({
    name: PERIOD_KEY_PROFILE,
    periodKeyBytes: 16,
    wrapAlgorithm: "AES-128-GCM",
  }),
};

/**
 * Returns the descriptor of the named period-key profile. It reports an unknown name as a
 * configuration fault to whoever stated it, so a deployment that misspells its
 * profile fails closed at selection instead of at a width check further down.
 *
 * @param {string} name
 * @returns {PeriodKeyProfile}
 */
export function periodKeyProfile(name) {
  if (typeof name !== "string" || !Object.hasOwn(PROFILES, name)) {
    throw dcaError(
      "unsupported_option",
      `there is no period-key profile ${JSON.stringify(name)}; the profiles are ` +
        `${Object.keys(PROFILES).join(" and ")}`,
    );
  }
  return PROFILES[name];
}
