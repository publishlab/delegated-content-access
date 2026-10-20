// @ts-check

// Query one chain partition selected by the article's explicit geometry.
// Response geometry is used only when a grant is filed.
//
// One walk stays inside one construction profile without naming it: the cache
// this source reads was composed on one profile, and every partition name it
// holds carries that profile as a segment. So the candidates offered here are chain
// keys and period keys of that profile's widths, and a rival trial never reaches a key of
// the other one.

import {
  takePeriodCandidate,
  triedPeriodKeys,
} from "../../../core-client/periodKeyCandidateSource.js";
import { own } from "../../../core-shared/wire.js";
import { dcaError } from "../../../core-shared/errors.js";
import { chainKeyCoordinate, resolveChainGeometry } from "../core-shared/chainKeyConstruction.js";

/** @param {{ candidates: Function, }} cache */
export function chainKeyCandidateSource(cache) {
  if (typeof cache?.candidates !== "function") {
    throw dcaError(
      "bad_config",
      "a chain-key candidate source needs a cache that answers candidates",
    );
  }
  return Object.freeze({
    /** @param {{ dcaData: any, accessGroup: string, entries: any[], publisher?: string, issuerNames: string[], chainIssuerNames: string[], lease?: object, ordinaryPeriodHandled?: boolean, budget?: any }} context */
    async *attempts({
      dcaData,
      accessGroup,
      entries,
      publisher,
      chainIssuerNames,
      ordinaryPeriodHandled = false,
      lease,
      budget = { remaining: 64 },
    }) {
      const geometry = resolveChainGeometry(own(dcaData.toObject(), "periodGeometry"), accessGroup);

      const context = {
        publisher,
        // The chain route's own accept-list: the issuers the publisher sealed
        // `chainKeys` for. The base period-key list never reaches this read.
        issuerNames: chainIssuerNames,
        lease,
        chainOnly: ordinaryPeriodHandled,
        chainsPerDay: geometry?.chainsPerDay,
        periodMinutes: geometry?.periodMinutes,
      };
      for (const entry of entries) {
        const t = own(entry, "t");
        if (typeof t !== "string") continue;
        if (geometry === null || budget.remaining <= 0) continue;
        try {
          chainKeyCoordinate(t, geometry);
        } catch {
          continue;
        }
        // The cache skips a walk only for a memo already tried on this wrap;
        // a memo the ordinary ceiling left out never stands in for its walk.
        const candidates = await cache.candidates(accessGroup, t, {
          ...context,
          triedPeriodKeys: triedPeriodKeys(budget, entry),
        });
        for (const periodKey of candidates) {
          if (!takePeriodCandidate(budget, entry, periodKey)) continue;
          yield {
            entry,
            periodKey,
            origin: { kind: "cached-chain-key", accessGroup, t },
          };
        }
      }
    },
  });
}
