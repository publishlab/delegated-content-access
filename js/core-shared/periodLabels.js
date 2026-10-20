// @ts-check

import { dcaError } from "./errors.js";

/** Base period-key label grammar: YYMMDDTHHMM. */
const PERIOD_KEY_LABEL_PATTERN = /^\d{6}T\d{4}$/;

/**
 * Base consumers admit a period-key label lexically. Producers remain
 * responsible for calendar and ordinary time ranges.
 *
 * @param {unknown} value
 * @returns {value is string}
 */
export function isPeriodKeyLabel(value) {
  return typeof value === "string" && PERIOD_KEY_LABEL_PATTERN.test(value);
}

/** @param {number} value */
function pad(value) {
  return String(value).padStart(2, "0");
}

/**
 * The UTC start label of the period a moment falls in: `YYMMDDTHHMM`.
 *
 * @param {Date} date
 * @param {number} length - period length in minutes
 * @returns {string}
 */
export function formatT(date, length) {
  const start = startOf(date, length);
  const stamp =
    `${pad(start.getUTCFullYear() % 100)}${pad(start.getUTCMonth() + 1)}${pad(start.getUTCDate())}` +
    `T${pad(start.getUTCHours())}`;
  return `${stamp}${pad(start.getUTCMinutes())}`;
}

/**
 * @param {Date} date
 * @param {number} length - period length in minutes
 * @returns {Date}
 */
function startOf(date, length) {
  if (!(date instanceof Date) || !Number.isSafeInteger(length) || length <= 0) {
    throw badConfig();
  }
  // Do not call getTime through the supplied object: an own getTime must not determine the label.
  const epochMilliseconds = Date.prototype.getTime.call(date);
  if (!Number.isFinite(epochMilliseconds)) throw badConfig();
  const alignedMilliseconds = Math.floor(epochMilliseconds / 60000 / length) * length * 60000;
  const aligned = new Date(alignedMilliseconds);
  const year = Date.prototype.getUTCFullYear.call(aligned);
  if (!Number.isFinite(Date.prototype.getTime.call(aligned)) || year < 2000 || year > 2099) {
    throw badConfig();
  }
  return aligned;
}

function badConfig() {
  return dcaError(
    "bad_config",
    "period date and length must be valid and within 2000 through 2099",
  );
}
