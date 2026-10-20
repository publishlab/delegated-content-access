// @ts-check
//
// Numeric bounds shared by base's period-family extension seam and extensions
// that implement such a family, and the one rule for when two period
// geometries agree. This module contains no chain construction, labels,
// coordinates or key material.

/** Minutes in the UTC day that period-family geometry divides. */
export const PERIOD_GEOMETRY_MINUTES_PER_DAY = 1440;

/** Maximum number of period positions admitted in one stationary window. */
export const MAX_POSITIONS_PER_WINDOW = 288;

/** Maximum positioned capabilities admitted for one family. */
export const MAX_CHAIN_MEMBERS_PER_FAMILY = 2;

/** Maximum positioned capabilities admitted across one message. */
export const MAX_CHAIN_MEMBERS_PER_MESSAGE = 16;

/** Maximum period keys returned for one period family. */
export const MAX_PERIOD_KEYS_PER_FAMILY = 288;

/** Maximum period keys returned across one response. */
export const MAX_PERIOD_KEYS_PER_RESPONSE = 512;

/**
 * Inspect only the numeric geometry contract. The boundary that calls this
 * check is responsible for object shape, unknown members, refusal codes and
 * refusal wording.
 *
 * @param {unknown} chainsPerDay
 * @param {unknown} periodMinutes
 * @returns {(
 *   { kind: 'invalidChainsPerDay' }
 *   | { kind: 'invalidPeriodMinutes', windowMinutes: number }
 *   | { kind: 'tooManyPositions', windowMinutes: number, positionsPerWindow: number }
 *   | { kind: 'valid', windowMinutes: number, positionsPerWindow: number }
 * )}
 */
export function inspectPeriodGeometryBounds(chainsPerDay, periodMinutes) {
  if (
    !Number.isInteger(chainsPerDay) ||
    /** @type {number} */ (chainsPerDay) <= 0 ||
    PERIOD_GEOMETRY_MINUTES_PER_DAY % /** @type {number} */ (chainsPerDay) !== 0
  ) {
    return Object.freeze({ kind: /** @type {const} */ ("invalidChainsPerDay") });
  }

  const windowMinutes = PERIOD_GEOMETRY_MINUTES_PER_DAY / /** @type {number} */ (chainsPerDay);
  if (
    !Number.isInteger(periodMinutes) ||
    /** @type {number} */ (periodMinutes) <= 0 ||
    windowMinutes % /** @type {number} */ (periodMinutes) !== 0
  ) {
    return Object.freeze({ kind: /** @type {const} */ ("invalidPeriodMinutes"), windowMinutes });
  }

  const positionsPerWindow = windowMinutes / /** @type {number} */ (periodMinutes);
  if (positionsPerWindow > MAX_POSITIONS_PER_WINDOW) {
    return Object.freeze({
      kind: /** @type {const} */ ("tooManyPositions"),
      windowMinutes,
      positionsPerWindow,
    });
  }
  return Object.freeze({
    kind: /** @type {const} */ ("valid"),
    windowMinutes,
    positionsPerWindow,
  });
}

/** The members a period geometry may carry. */
const PERIOD_GEOMETRY_MEMBERS = Object.freeze(["chainsPerDay", "periodMinutes"]);

/**
 * Whether two period geometries name the same geometry. Both are plain
 * records with only `chainsPerDay` and `periodMinutes`; they agree when each
 * member is present in both with the same value, or absent from both. Member
 * order is no part of a geometry, so `{periodMinutes: 60, chainsPerDay: 2}`
 * agrees with `{chainsPerDay: 2, periodMinutes: 60}`; `{periodMinutes: 60}`
 * does not, because only one of them names a chain count.
 *
 * @param {unknown} first
 * @param {unknown} second
 * @returns {boolean}
 */
export function periodGeometriesAgree(first, second) {
  /** @param {unknown} value @returns {value is Record<string, unknown>} */
  const geometry = (value) =>
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).every((name) => PERIOD_GEOMETRY_MEMBERS.includes(name));
  if (!geometry(first) || !geometry(second)) return false;
  return PERIOD_GEOMETRY_MEMBERS.every(
    (name) =>
      Object.hasOwn(first, name) === Object.hasOwn(second, name) && first[name] === second[name],
  );
}
