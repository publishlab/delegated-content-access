// @ts-check

// A fallback grants the current period only. At stage 6 of delivery, after the
// endpoint has answered, the issuer server trims a fallback response down to the
// greatest started period per accessGroup. This step sits beside `FailoverGate`,
// which settles whether this server may stand in at all.

import { currentT } from "../../../core-shared--publisher-issuer/periodKeys.js";
import { setOwn } from "../../../core-shared/wire.js";
import { WITHHELD_CODES } from "../../../core-shared/errors.js";

/**
 * Keep only the greatest started period per accessGroup. Each `t` label carries
 * its own resolution, the only period length this step reads.
 * A group with no started label is named in `errors` and omitted from keys.
 *
 * @param {any} body
 * @param {Date} now
 * @returns {any}
 */
export function trimToCurrentPeriod(body, now) {
  const periodKeys = body?.keys?.periodKeys;
  if (!periodKeys) return body;

  /** @type {Record<string, Record<string, string>>} */
  const kept = {};
  /** @type {Record<string, { error: string, message: string }>} */
  const withheld = {};

  for (const accessGroup of Object.keys(periodKeys)) {
    const periods = periodKeys[accessGroup];
    const carried = periods !== null && typeof periods === "object" ? Object.keys(periods) : [];

    const t = currentT(now, carried);
    if (t === null) {
      withheld[`${accessGroup}|`] = {
        error: WITHHELD_CODES.noCurrentPeriod,
        message: `a fallback grants the current period only, and no "${accessGroup}" period presented has started`,
      };
      continue;
    }
    setOwn(kept, accessGroup, { [t]: periods[t] });
  }

  const keys = { ...body.keys };
  if (Object.keys(kept).length > 0) keys.periodKeys = kept;
  else delete keys.periodKeys;

  const trimmed = { ...body, keys };
  if (Object.keys(withheld).length > 0) trimmed.errors = { ...body.errors, ...withheld };

  return trimmed;
}
