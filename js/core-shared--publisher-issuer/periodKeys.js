// @ts-check
//
// This file handles the label side of the cached path: which periods a render
// ships and what they are called. The bytes behind each label are a separate publisher concern;
// the base format here carries opaque keys and names no derivation default.
//
// A periodKey is `f(accessGroup, t)`: it has the same bytes for every article the
// publisher renders in that family and period. That is the whole reason the
// client can cache one key and open the next article without asking again. This
// file makes the `t`; an injected supply provides the key behind it.
//
// A label labels the period, not the instant, so every moment inside one period
// gets the same string. It is UTC and lexicographically sortable, and sorting
// is very nearly the only thing done to one: the client string-sorts, and the
// issuer compares canonical minute labels against its captured policy instant.
// Selection never rewrites a supplied coordinate.
//
// `t` is computed here from an injected `now` and nowhere else. `Clock` reports
// the moment; it does not also format periods.

import { dcaError } from "../core-shared/errors.js";
import { formatT as formatPeriodLabel, isPeriodKeyLabel } from "../core-shared/periodLabels.js";

/**
 * The default is hourly, current period plus one forward. Callers may choose
 * another supported period length and slot count; every call takes the
 * configuration as an argument.
 *
 * @typedef {object} Period
 * @property {number} [length] - period length in minutes
 * @property {number} [slots] - how many periods a render ships, current first
 */

/** @type {Required<Period>} */
export const DEFAULT_PERIOD = { length: 60, slots: 2 };

/**
 * The period a render runs under: each omitted option at its default, each
 * given one checked. A publisher calls it at construction too, so a period it
 * cannot use fails there and not at the first render.
 *
 * @param {Period} [period]
 * @returns {Required<Period>}
 */
export function settledPeriod(period = {}) {
  const length = period.length ?? DEFAULT_PERIOD.length;
  const slots = period.slots ?? DEFAULT_PERIOD.slots;

  if (!Number.isSafeInteger(length) || length <= 0) {
    throw dcaError(
      "bad_config",
      `period length must be a positive whole number of minutes, got ${length}`,
    );
  }
  if (1440 % length !== 0) {
    throw dcaError("bad_config", "period length must divide one UTC day");
  }
  if (!Number.isSafeInteger(slots) || slots <= 0) {
    throw dcaError("bad_config", `period slots must be a positive integer, got ${slots}`);
  }
  return { length, slots };
}

/**
 * The UTC start label of the period a moment falls in: `YYMMDDTHHMM`.
 * Every moment inside one period gets the same canonical label, including
 * minute digits for hourly periods. The configured length aligns the start;
 * label spelling does not encode the length.
 *
 * @param {Date} date
 * @param {number} [length] - period length in minutes, for the resolution
 * @returns {string}
 */
export function formatT(date, length = DEFAULT_PERIOD.length) {
  return formatPeriodLabel(date, length);
}

/**
 * Picks the label to read in now from the labels a render carried: the greatest
 * one that has already started, or null when none of them has.
 *
 * It is here rather than in the one actor that asks, because it is a rule about
 * `t` and this module is where `t` is made.
 *
 * The pick depends on the clock, and the request does not move it. The client writes the
 * labels it sends and chooses their order, so the greatest started label is the
 * only pick a client cannot move. If the client drops the current label, it gets
 * an older period or nothing. A label ahead of now sorts above the now-label, and
 * this function skips it.
 *
 * No agreement on period length is needed: every admitted label carries the
 * UTC start to minute precision. Compare against the captured issuer instant
 * at that precision and select only a coordinate actually presented.
 * This source-selection rule does not itself authorize a grant.
 *
 * @param {Date} now - from the injected `Clock`
 * @param {string[]} labels
 * @returns {string|null}
 */
export function currentT(now, labels) {
  /** @type {string|null} */
  let current = null;
  const started = formatT(now, 1);

  for (const label of labels) {
    if (!isPeriodKeyLabel(label)) continue;
    if (label <= started && (current === null || label > current)) current = label;
  }

  return current;
}

/**
 * The periods a render ships, from the moment it is rendered: the period
 * `now` falls in, then forward. It never ships a backward period. A client that
 * has yesterday's key needs nothing from this render, and a client that has none
 * gets the overlap key, so a page cached across the boundary still opens.
 *
 * Chronological order, current first, which is the order the wire carries.
 * The cache sorts newest-first; this supply does not.
 *
 * @param {Date} now - from the injected `Clock`
 * @param {Period} [period]
 * @returns {string[]}
 */
export function periodsFor(now, period = {}) {
  const { length, slots } = settledPeriod(period);
  // formatT checks the date and length. This module reads the aligned instant
  // back from its label, so it does not export a mutable Date helper.
  const start = labelStart(formatT(now, length));

  const labels = [];
  for (let slot = 0; slot < slots; slot++) {
    labels.push(formatT(new Date(start + slot * length * 60000), length));
  }
  return labels;
}

/** @param {string} label */
function labelStart(label) {
  const minutes = Number(label.slice(9, 11));
  return Date.UTC(
    2000 + Number(label.slice(0, 2)),
    Number(label.slice(2, 4)) - 1,
    Number(label.slice(4, 6)),
    Number(label.slice(7, 9)),
    minutes,
  );
}
