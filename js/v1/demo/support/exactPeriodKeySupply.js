// @ts-check

import { Random } from "../actors/Random.js";
import { dcaError } from "../../core-shared/errors.js";

/**
 * Supply opaque, independent canonical 16-byte period keys. Each call creates
 * a separate registry, so publishers sharing one scenario supply share a key
 * for a coordinate, and unrelated coordinates get independent bytes.
 *
 * @param {{ random?: Random, keys?: Record<string, Record<string, Uint8Array>> }} [options]
 * @returns {{ derive: (accessGroup: string, t: string) => Promise<Uint8Array> }}
 */
export function exactPeriodKeySupply(options = {}) {
  for (const name of Object.keys(options)) {
    if (name !== "random" && name !== "keys") {
      throw dcaError(
        "unsupported_option",
        `exactPeriodKeySupply has no ${name} yet, and will not pretend to`,
      );
    }
  }
  const random = options.random ?? new Random();
  if (!random || typeof random.bytes !== "function") {
    throw dcaError("bad_config", "the exact period-key supply needs a random byte source");
  }

  /** @type {Map<string, Map<string, Uint8Array>>} */
  const keys = new Map();
  for (const [accessGroup, periods] of Object.entries(options.keys ?? {})) {
    const byPeriod = new Map();
    for (const [t, value] of Object.entries(periods)) {
      if (!(value instanceof Uint8Array) || value.length !== 16) {
        throw dcaError("bad_config", "exact period keys must be 16-byte Uint8Arrays");
      }
      byPeriod.set(t, Uint8Array.from(value));
    }
    keys.set(accessGroup, byPeriod);
  }

  return {
    async derive(accessGroup, t) {
      if (!accessGroup || !t) {
        throw dcaError("bad_config", "the exact period-key supply needs an accessGroup and a t");
      }
      let byPeriod = keys.get(accessGroup);
      if (!byPeriod) {
        byPeriod = new Map();
        keys.set(accessGroup, byPeriod);
      }
      let key = byPeriod.get(t);
      if (!key) {
        key = random.bytes(16);
        byPeriod.set(t, Uint8Array.from(key));
      }
      return Uint8Array.from(key);
    },
  };
}
