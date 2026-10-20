// @ts-check
// Reference deployment assumptions, not protocol-wide interoperability floors.
import { dcaError } from "./errors.js";

export const DEFAULT_REQUEST_LIMITS = Object.freeze({
  maxBodyBytes: 65536,
  maxEntries: 16,
  maxEntriesPerGroup: 4,
});

/** @param {unknown} input @returns {Readonly<Record<keyof typeof DEFAULT_REQUEST_LIMITS, number>>} */
export function requestLimits(input) {
  if (input !== undefined && (input === null || typeof input !== "object" || Array.isArray(input)))
    throw dcaError("bad_config", "issuer limits must be an object");
  /** @type {Record<keyof typeof DEFAULT_REQUEST_LIMITS, number>} */
  const limits = { ...DEFAULT_REQUEST_LIMITS };
  for (const [name, value] of Object.entries(input ?? {})) {
    if (!Object.hasOwn(limits, name) || !Number.isSafeInteger(value) || value <= 0)
      throw dcaError("bad_config", `invalid issuer request limit ${name}`);
    limits[/** @type {keyof typeof DEFAULT_REQUEST_LIMITS} */ (name)] = value;
  }
  return Object.freeze(limits);
}

/**
 * Count the raw sealed maps before any value or envelope validation. Period
 * and chain entries share a group's limit. Arrays count their enumerable keys.
 * @param {any} sealed
 * @returns {{ entries: number, groups: Map<string, number> }}
 */
export function requestEntryCounts(sealed) {
  const groups = new Map();
  if (sealed === null || typeof sealed !== "object") return { entries: 0, groups };
  const content = Object.hasOwn(sealed, "contentKeys") ? sealed.contentKeys : undefined;
  let entries = content !== null && typeof content === "object" ? Object.keys(content).length : 0;
  for (const field of ["periodKeys", "chainKeys"]) {
    const families = Object.hasOwn(sealed, field) ? sealed[field] : undefined;
    if (families === null || typeof families !== "object") continue;
    for (const group of Object.keys(families)) {
      const family = families[group];
      if (family === null || typeof family !== "object") continue;
      const count = Object.keys(family).length;
      groups.set(group, (groups.get(group) ?? 0) + count);
      entries += count;
    }
  }
  return { entries, groups };
}
