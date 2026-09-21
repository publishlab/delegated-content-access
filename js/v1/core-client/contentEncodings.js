// @ts-check

// Only this module reads an item's ordered content-encoding list. The page-data view
// and the representation opener both use it, so a malformed list cannot pass
// one path and fail differently in the other.

import { dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";

/** @param {unknown} value */
function isNonemptyEncodingList(value) {
  if (!Array.isArray(value) || value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (
      !Object.hasOwn(value, index) ||
      typeof value[index] !== "string" ||
      value[index].length === 0
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
 * @returns {string[]}
 */
export function contentEncodingsFrom(record, contentName) {
  const declared = own(record, "contentEncodings");
  if (declared === undefined) return [];
  if (!isNonemptyEncodingList(declared)) {
    throw dcaError(
      "bad_page",
      `the contentEncodings for "${contentName}" are a nonempty list of nonempty strings`,
    );
  }
  return [...declared];
}
