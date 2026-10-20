// @ts-check

// A fallback grants the current period only. At stage 6 of delivery, after the
// endpoint has answered, the issuer server trims a fallback response down to the
// greatest started period per accessGroup. This step sits beside `FailoverGate`,
// which settles whether this server may stand in at all.

import { currentT } from "../../../core-shared--publisher-issuer/periodKeys.js";
import { setOwn } from "../../../core-shared/wire.js";

/**
 * Keep only the greatest started period per accessGroup. Labels are canonical minute coordinates.
 * A group with no started label is omitted. Trimming proves neither an
 * independently authorized missing coordinate nor unavailable supply, so it
 * creates no family report. Existing engine reports and errors are preserved.
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

  for (const accessGroup of Object.keys(periodKeys)) {
    const periods = periodKeys[accessGroup];
    const carried = periods !== null && typeof periods === "object" ? Object.keys(periods) : [];

    const t = currentT(now, carried);
    if (t === null) continue;
    setOwn(kept, accessGroup, { [t]: periods[t] });
  }

  const keys = { ...body.keys };
  if (Object.keys(kept).length > 0) keys.periodKeys = kept;
  else delete keys.periodKeys;

  return { ...body, keys };
}
