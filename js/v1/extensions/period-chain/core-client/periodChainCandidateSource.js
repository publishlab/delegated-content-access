// @ts-check

// Query one chain partition selected by the article's explicit geometry.
// Response geometry is used only when a grant is filed.
//
// One walk stays inside one construction profile without naming it: the cache
// this source reads was composed on one profile, and every partition name it
// holds carries that profile as a segment. So the candidates offered here are state
// and leaves of that profile's widths, and a rival trial never reaches a key of
// the other one.

import { own } from "../../../core-shared/wire.js";
import { dcaError } from "../../../core-shared/errors.js";
import {
  periodChainCoordinate,
  resolvePeriodChainGeometry,
} from "../core-shared/periodChainConstruction.js";

/** @param {{ candidates: Function }} cache */
export function periodChainCandidateSource(cache) {
  if (typeof cache?.candidates !== "function") {
    throw dcaError(
      "bad_config",
      "a period-chain candidate source needs a cache that answers candidates",
    );
  }
  return Object.freeze({
    /** @param {{ dcaData: any, accessGroup: string, entries: any[], publisher?: string, chainIssuerNames: string[], lease?: object }} context */
    async *attempts({ dcaData, accessGroup, entries, publisher, chainIssuerNames, lease }) {
      const geometry = resolvePeriodChainGeometry(
        own(dcaData.toObject(), "periodChain"),
        accessGroup,
      );
      if (geometry === null) return;
      const context = {
        publisher,
        // The chain route's own accept-list: the issuers the publisher sealed
        // `periodChainKeys` for. The base exact list never reaches this read.
        issuerNames: chainIssuerNames,
        lease,
        chainsPerDay: geometry.chainsPerDay,
        periodMinutes: geometry.periodMinutes,
      };
      for (const entry of entries) {
        const t = own(entry, "t");
        if (typeof t !== "string") continue;
        try {
          periodChainCoordinate(t, geometry);
        } catch {
          continue;
        }
        const candidates = await cache.candidates(accessGroup, t, context);
        for (const periodKey of candidates) {
          yield {
            entry,
            periodKey,
            origin: { kind: "cached-period-chain-key", accessGroup, t },
          };
        }
      }
    },
  });
}
