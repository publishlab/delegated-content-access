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
 * Validate raw selector bounds before deduplicating, then return a deterministic
 * own-property map. `family` must return the already-admitted chain input view.
 * Geometry/grid checks apply only to valid source families; hints never repair
 * or change the scope of a malformed or absent source.
 *
 * @param {unknown} value
 * @param {(accessGroup: string) => any} family
 * @returns {Record<string, string[]>}
 */
export function normalizeRequestedPeriodKeys(value, family) {
  if (value === undefined) return {};
  if (!record(value) || Object.keys(value).length === 0) {
    malformed("requestedPeriodKeys is a non-empty access-group map");
  }

  const groups = Object.keys(value);
  let rawTotal = 0;
  for (const accessGroup of groups) {
    try {
      validateChainKeyAccessGroup(accessGroup);
    } catch {
      malformed("requestedPeriodKeys names an admitted access group");
    }
    const labels = own(value, accessGroup);
    if (!Array.isArray(labels) || labels.length === 0) {
      malformed("each requestedPeriodKeys family is a non-empty label array");
    }
    if (labels.length > MAX_REQUESTED_PERIODS_PER_FAMILY) {
      malformed("a requestedPeriodKeys family exceeds its input bound");
    }
    rawTotal += labels.length;
    if (rawTotal > MAX_REQUESTED_PERIODS_PER_REQUEST) {
      malformed("requestedPeriodKeys exceeds its request input bound");
    }
  }

  /** @type {Record<string, string[]>} */
  const normalized = {};
  for (const accessGroup of groups) {
    const labels = /** @type {unknown[]} */ (own(value, accessGroup));
    const admittedFamily = family(accessGroup);
    for (const label of labels) {
      if (!canonicalLabel(label)) {
        malformed("requestedPeriodKeys labels are canonical chain-profile coordinates");
      }
      if (admittedFamily?.kind === "valid") {
        try {
          chainKeyCoordinate(label, admittedFamily.geometry);
        } catch {
          malformed("requestedPeriodKeys labels lie on their admitted family geometry");
        }
      }
    }
    setOwn(normalized, accessGroup, [...new Set(/** @type {string[]} */ (labels))].sort());
  }
  return normalized;
}
