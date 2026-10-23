// @ts-check
//
// The delivery carries its descriptor collections (`contentData`,
// `issuerData`, `sealedContent`) as arrays of named records. A reader looks a
// record up by its identity field, so this module turns one such array into a
// lookup map once per read.
//
// Several records with one identity resolve to the last whole record. The
// earlier record is dropped entire: a reader never sees `keyId` from one issuer
// block beside `sealed` from another. "Last" is array order, not time.
//
// The collection is refused whole when it is not an array, or when one
// element's identity is missing, inherited, not a string or outside the
// caller's grammar: the format's identifier rule does not let a reader skip a
// bad name and accept its siblings. An element that is not a non-array object
// carries no identity to refuse, so it supplies nothing and its siblings stay,
// as a malformed record value did when the collection was a map. The caller
// decides what a refusal costs: the whole delivery for `contentData` and
// `issuerData`, one route for a projection.

import { own } from "../core-shared/wire.js";

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * One descriptor collection as a map from identity to its last whole record,
 * or null when the collection is refused. Elements that are not records are
 * left out. A Map keeps `__proto__` and `constructor` ordinary names.
 *
 * @param {unknown} collection - the wire array, still untrusted
 * @param {string} member - the identity field, such as `contentName`
 * @param {(name: unknown) => boolean} isName - the identity grammar
 * @returns {Map<string, any> | null}
 */
export function recordsByName(collection, member, isName) {
  if (!Array.isArray(collection)) return null;
  /** @type {Map<string, any>} */
  const records = new Map();
  for (const record of collection) {
    if (!isRecord(record)) continue;
    const name = own(record, member);
    if (typeof name !== "string" || !isName(name)) return null;
    records.set(name, record);
  }
  return records;
}
