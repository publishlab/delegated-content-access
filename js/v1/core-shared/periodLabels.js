// @ts-check

import { dcaError } from "./errors.js";

const MINUTES_PER_HOUR = 60;

/** Base exact-period wire grammar: YYMMDDTHH or YYMMDDTHHMM. */
const EXACT_PERIOD_LABEL_PATTERN = /^\d{6}T\d{2}(?:\d{2})?$/;

/**
 * Base consumers admit an exact-period label lexically. Producers remain
 * responsible for calendar and ordinary time ranges.
 *
 * @param {unknown} value
 * @returns {value is string}
 */
export function isExactPeriodLabel(value) {
  return typeof value === "string" && EXACT_PERIOD_LABEL_PATTERN.test(value);
}

/** @param {number} value */
function pad(value) {
  return String(value).padStart(2, "0");
}

/**
 * The label of the period a moment falls in: `YYMMDDTHH`, or `YYMMDDTHHMM`
 * when the period does not divide into whole hours.
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
  return length % MINUTES_PER_HOUR === 0 ? stamp : `${stamp}${pad(start.getUTCMinutes())}`;
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
