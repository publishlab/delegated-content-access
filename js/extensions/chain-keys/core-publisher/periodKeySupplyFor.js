// @ts-check

import { dcaError } from "../../../core-shared/errors.js";

/**
 * The base publisher's view of one generation: period-key derivation and nothing
 * else. The `Sealer` takes a `derive(accessGroup, t)` and assigns no
 * derivation meaning to the bytes it gets back, so the chain operations stay
 * behind the extension composition that holds the handle itself.
 *
 * @param {{ periodKey: (accessGroup: string, t: string) => Promise<Uint8Array> }} generation
 * @returns {{ derive: (accessGroup: string, t: string) => Promise<Uint8Array> }}
 */
export function periodKeySupplyFor(generation) {
  if (typeof generation?.periodKey !== "function") {
    throw dcaError("bad_config", "a period-key supply is made over a period-family generation");
  }
  return Object.freeze({
    derive: (accessGroup, t) => generation.periodKey(accessGroup, t),
  });
}
