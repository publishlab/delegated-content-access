// @ts-check

// Only this module reads an item's ordered content-encoding list. The page-data view
// and the representation opener both use it, so a malformed list cannot pass
// one path and fail differently in the other.

import { dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";

export const DEFAULT_CONTENT_ENCODING_LIMITS = Object.freeze({
  maxLayers: 8,
  maxNameLength: 128,
  maxInputBytes: 16 * 1024 * 1024,
  maxOutputBytes: 64 * 1024 * 1024,
  maxTotalInputBytes: 128 * 1024 * 1024,
  maxTotalOutputBytes: 128 * 1024 * 1024,
});

/** @param {Partial<typeof DEFAULT_CONTENT_ENCODING_LIMITS>} overrides */
export function contentEncodingLimits(overrides = {}) {
  const limits = { ...DEFAULT_CONTENT_ENCODING_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1)
      throw dcaError("bad_config", `content encoding limit ${name} is a positive safe integer`);
  }
  return Object.freeze(limits);
}

/** @param {unknown} value @param {typeof DEFAULT_CONTENT_ENCODING_LIMITS} limits */
function isNonemptyEncodingList(value, limits) {
  if (!Array.isArray(value) || value.length === 0) return false;
  if (value.length > limits.maxLayers) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (
      !Object.hasOwn(value, index) ||
      typeof value[index] !== "string" ||
      value[index].length === 0 ||
      value[index].length > limits.maxNameLength
    )
      return false;
  }
  return true;
}

/**
 * Read and snapshot the ordered layers declared for one item. An absent member
 * leaves the representation unencoded. A publisher omits an empty list, so this
 * function rejects an empty list on the wire as malformed.
 *
 * @param {unknown} record
 * @param {string} contentName
 * @param {typeof DEFAULT_CONTENT_ENCODING_LIMITS} [limits]
 * @returns {string[]}
 */
export function contentEncodingsFrom(
  record,
  contentName,
  limits = DEFAULT_CONTENT_ENCODING_LIMITS,
) {
  const declared = own(record, "contentEncodings");
  if (declared === undefined) return [];
  if (!isNonemptyEncodingList(declared, limits)) {
    throw dcaError(
      "bad_page",
      `the contentEncodings for "${contentName}" exceed limits or are malformed`,
    );
  }
  return [...declared];
}

/**
 * Check an already captured list against these limits. An empty list is a
 * captured absence, so it passes; a capture never holds a present empty list.
 *
 * @param {readonly string[]} captured
 * @param {string} contentName
 * @param {typeof DEFAULT_CONTENT_ENCODING_LIMITS} [limits]
 * @returns {string[]}
 */
export function capturedContentEncodings(
  captured,
  contentName,
  limits = DEFAULT_CONTENT_ENCODING_LIMITS,
) {
  if (Array.isArray(captured) && captured.length === 0) return [];
  if (!isNonemptyEncodingList(captured, limits)) {
    throw dcaError(
      "bad_page",
      `the contentEncodings for "${contentName}" exceed limits or are malformed`,
    );
  }
  return [...captured];
}
