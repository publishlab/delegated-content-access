// @ts-check
//
// This module exposes the ordinary exact-period cache as one resolver
// candidate source. For each authored wrap, it asks the cache only for the
// rivals retained at that wrap's byte-identical exact coordinate.

import { dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";

const MAX_RIVALS_PER_WRAP = 4;
const MAX_TRIALS_PER_RESOLUTION = 64;

/**
 * @param {{ candidatesAt: Function, attempted: Function }} cache
 * @returns {{ attempts: (context: any) => AsyncGenerator<any> }}
 */
export function exactPeriodCandidateSource(cache) {
  if (typeof cache?.candidatesAt !== "function" || typeof cache?.attempted !== "function") {
    throw dcaError(
      "bad_config",
      "an exact-period candidate source needs candidatesAt and attempted cache methods",
    );
  }

  return Object.freeze({
    /**
     * @param {{ accessGroup: string, entries: any[], publisher?: string,
     *   issuerNames: string[], lease?: object,
     *   budget?: { remaining: number } }} context
     */
    async *attempts({
      accessGroup,
      entries,
      publisher,
      issuerNames,
      lease,
      budget = { remaining: MAX_TRIALS_PER_RESOLUTION },
    }) {
      for (const entry of entries) {
        if (budget.remaining <= 0) return;
        const t = own(entry, "t");
        if (typeof t !== "string") continue;
        const candidates = await cache.candidatesAt(accessGroup, t, {
          publisher,
          issuerNames,
          lease,
        });
        for (const periodKey of candidates.slice(0, MAX_RIVALS_PER_WRAP)) {
          if (budget.remaining <= 0) return;
          budget.remaining--;
          yield {
            entry,
            periodKey,
            origin: { kind: "cached-period-key", accessGroup, t },
          };
        }
      }
    },
  });
}
