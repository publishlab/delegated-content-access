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
 * Count the raw sealed records before any record, value or envelope
 * validation, and before any copy is dropped: every array element counts,
 * including a repeated record and one that is not a record at all. Period and
 * chain records share their `accessGroup`'s limit. A section that is not an
 * array counts nothing here; admission refuses it on its shape.
 * @param {any} sealed
 * @returns {{ entries: number, groups: Map<string, number> }}
 */
export function requestEntryCounts(sealed) {
  const groups = new Map();
  if (sealed === null || typeof sealed !== "object") return { entries: 0, groups };
  const content = Object.hasOwn(sealed, "contentKeys") ? sealed.contentKeys : undefined;
  let entries = Array.isArray(content) ? content.length : 0;
  for (const field of ["periodKeys", "chainKeys"]) {
    const records = Object.hasOwn(sealed, field) ? sealed[field] : undefined;
    if (!Array.isArray(records)) continue;
    entries += records.length;
    for (const record of records) {
      const group =
        record !== null && typeof record === "object" && Object.hasOwn(record, "accessGroup")
          ? record.accessGroup
          : undefined;
      if (typeof group === "string") groups.set(group, (groups.get(group) ?? 0) + 1);
    }
  }
  return { entries, groups };
}
