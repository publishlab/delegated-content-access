// @ts-check

// A fallback grants the current period only. At stage 6 of delivery, after the
// endpoint has answered, the issuer server trims a fallback response down to the
// greatest started period per accessGroup. This step sits beside `FailoverGate`,
// which settles whether this server may stand in at all.

import { currentT } from "../../../core-shared--publisher-issuer/periodKeys.js";
import { own } from "../../../core-shared/wire.js";

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
  if (!Array.isArray(periodKeys)) return body;

  /** @type {Map<string, string[]>} */
  const labels = new Map();
  for (const record of periodKeys) {
    const accessGroup = own(record, "accessGroup");
    const period = own(record, "period");
    if (typeof accessGroup !== "string" || typeof period !== "string") continue;
    labels.set(accessGroup, [...(labels.get(accessGroup) ?? []), period]);
  }
  /** @type {Map<string, string>} */
  const current = new Map();
  for (const [accessGroup, carried] of labels) {
    const t = currentT(now, carried);
    if (t !== null) current.set(accessGroup, t);
  }
  // Every record at the kept label stays: rivals there are candidates.
  const kept = periodKeys.filter(
    (record) => current.get(own(record, "accessGroup")) === own(record, "period"),
  );

  const keys = { ...body.keys };
  if (kept.length > 0) keys.periodKeys = kept;
  else delete keys.periodKeys;

  return { ...body, keys };
}
