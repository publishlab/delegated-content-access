// @ts-check
//
// Admission and normalization for the optional unsigned article-coordinate
// selector. It is a hint only: callers must authorize each selected coordinate
// independently before opening a publisher envelope.

import { dcaError } from "../../../core-shared/errors.js";
import { own, setOwn } from "../../../core-shared/wire.js";
import {
  chainKeyCoordinate,
  validateChainKeyAccessGroup,
} from "../core-shared/chainKeyConstruction.js";

export const MAX_REQUESTED_PERIODS_PER_FAMILY = 288;
export const MAX_REQUESTED_PERIODS_PER_REQUEST = 512;

const LABEL = /^(\d{2})(\d{2})(\d{2})T(\d{2})(\d{2})$/;

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** @param {unknown} label */
function canonicalLabel(label) {
  if (typeof label !== "string") return false;
  const match = LABEL.exec(label);
  if (!match) return false;
  const year = 2000 + Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day &&
    date.getUTCHours() === hour &&
    date.getUTCMinutes() === minute
  );
}

/** @param {string} message @returns {never} */
function malformed(message) {
  throw dcaError("binding_failed", message);
}

/**
 * Validate the `[{accessGroup, periods}]` selector and return its union per
 * group as a deterministic own-property map. Raw labels count across every
 * record of a group, and across the request, before any union or dedupe
 * (chain keys Section 12.4). `family` must return the already-admitted chain
 * input view. Geometry/grid checks apply only to valid source families; hints
 * never repair or change the scope of a malformed or absent source.
 *
 * @param {unknown} value
 * @param {(accessGroup: string) => any} family
 * @returns {Record<string, string[]>}
 */
export function normalizeRequestedPeriodKeys(value, family) {
  if (value === undefined) return {};
  if (!Array.isArray(value) || value.length === 0) {
    malformed("requestedPeriodKeys is a non-empty record array");
  }

  /** @type {Map<string, unknown[]>} */
  const byGroup = new Map();
  let rawTotal = 0;
  for (const entry of value) {
    if (!record(entry)) malformed("each requestedPeriodKeys element is a record");
    const accessGroup = own(entry, "accessGroup");
    try {
      validateChainKeyAccessGroup(/** @type {any} */ (accessGroup));
    } catch {
      malformed("requestedPeriodKeys names an admitted access group");
    }
    const labels = own(entry, "periods");
    if (!Array.isArray(labels) || labels.length === 0) {
      malformed("each requestedPeriodKeys record holds a non-empty label array");
    }
    const group = /** @type {string} */ (accessGroup);
    const held = byGroup.get(group) ?? [];
    held.push(...labels);
    byGroup.set(group, held);
    if (held.length > MAX_REQUESTED_PERIODS_PER_FAMILY) {
      malformed("a requestedPeriodKeys family exceeds its input bound");
    }
    rawTotal += labels.length;
    if (rawTotal > MAX_REQUESTED_PERIODS_PER_REQUEST) {
      malformed("requestedPeriodKeys exceeds its request input bound");
    }
  }

  /** @type {Record<string, string[]>} */
  const normalized = {};
  for (const [accessGroup, labels] of byGroup) {
    const admittedFamily = family(accessGroup);
    for (const label of labels) {
      if (!canonicalLabel(label)) {
        malformed("requestedPeriodKeys labels are canonical chain-profile coordinates");
      }
      if (admittedFamily?.kind === "valid") {
        try {
          chainKeyCoordinate(/** @type {string} */ (label), admittedFamily.geometry);
        } catch {
          malformed("requestedPeriodKeys labels lie on their admitted family geometry");
        }
      }
    }
    setOwn(normalized, accessGroup, [...new Set(/** @type {string[]} */ (labels))].sort());
  }
  return normalized;
}

/**
 * The wire spelling of a normalized selector: one record per group, in the
 * map's order.
 *
 * @param {Record<string, string[]>} normalized
 * @returns {{ accessGroup: string, periods: string[] }[]}
 */
export function requestedPeriodKeyRecords(normalized) {
  return Object.entries(normalized).map(([accessGroup, periods]) => ({
    accessGroup,
    periods: [...periods],
  }));
}
