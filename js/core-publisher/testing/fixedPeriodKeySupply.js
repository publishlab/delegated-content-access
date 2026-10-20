// @ts-check
//
// A period-key supply for tests that answers from a fixed table and refuses
// every other coordinate. A repeatable test hands it one key per access group
// and period label, so a render wraps under known keys, and an unexpected
// coordinate fails the render instead of getting a key made up on the spot.
// The demo's `demo/support/randomPeriodKeySupply.js` differs on purpose: it
// generates a key for a coordinate it does not list.
//
// The table is trusted test setup, never publisher or request data. The test
// Sealer factory beside this module composes it when its setup holds
// `fixedPeriodKeys`.

import { dcaError } from "../../core-shared/errors.js";

/**
 * A supply that answers the period key per access group and period label in
 * `keys`, and refuses a coordinate `keys` does not list with `bad_config`.
 * The table is copied, so a later change to `keys` does not reach it, and
 * each answer is a new copy.
 *
 * @param {unknown} keys - `{ [accessGroup]: { [t]: Uint8Array } }`
 * @returns {{ derive: (accessGroup: string, t: string) => Promise<Uint8Array> }}
 */
export function fixedPeriodKeySupply(keys) {
  /** @type {Map<string, Map<string, Uint8Array>>} */
  const table = new Map();
  for (const [accessGroup, periods] of recordEntries(keys)) {
    /** @type {Map<string, Uint8Array>} */
    const byPeriod = new Map();
    for (const [t, key] of recordEntries(periods)) {
      if (!(key instanceof Uint8Array)) throw periodKeysShape();
      byPeriod.set(t, Uint8Array.from(key));
    }
    table.set(accessGroup, byPeriod);
  }
  return {
    async derive(accessGroup, t) {
      const key = table.get(accessGroup)?.get(t);
      if (key === undefined)
        throw dcaError("bad_config", `no fixed period key for ${accessGroup} at ${t}`);
      return Uint8Array.from(key);
    },
  };
}

/** @param {unknown} value @returns {[string, unknown][]} */
function recordEntries(value) {
  const record = value !== null && typeof value === "object" && !Array.isArray(value);
  if (!record) throw periodKeysShape();
  return Object.entries(/** @type {Record<string, unknown>} */ (value));
}

function periodKeysShape() {
  return dcaError(
    "bad_config",
    "fixed period keys are records of bytes by access group and period",
  );
}
