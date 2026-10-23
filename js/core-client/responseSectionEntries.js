// @ts-check
//
// This module walks the structure of the three known response sections and
// the sections a selected extension composes. Each is an array of named
// records. It leaves each key entry uninterpreted; the selected consumer
// decides whether a key entry holds direct bytes or a client-bound carrier.
// The record is the array element and its own `key` member is the key entry,
// so a client-bound `{key, nonce}` value is told apart from its record by
// position, never by its members.

import { own } from "../core-shared/wire.js";
import { recordPath } from "../core-shared--client-issuer/responseKeys.js";

const FIELDS = Object.freeze({
  contentKeys: Object.freeze(["contentName"]),
  periodKeys: Object.freeze(["accessGroup", "period"]),
  chainKeys: Object.freeze(["accessGroup", "cutoff"]),
});

/**
 * Walk one record collection. A collection that is not an array counts as one
 * malformed branch and yields nothing. An element that is not a non-array
 * object, lacks a string at one of `fields` or lacks its `valueMember` counts
 * as malformed, never as an entry. Several records at one coordinate each
 * yield an entry.
 *
 * @param {any} collection
 * @param {readonly string[]} fields
 * @param {string} valueMember - `key` for a key record, `error` for an error record
 * @param {boolean} wholeRecord - whether `value` is the record rather than its member
 * @returns {{ entries: { path: string[], value: any, record: any }[], malformed: number }}
 */
function walk(collection, fields, valueMember, wholeRecord) {
  if (!Array.isArray(collection)) return { entries: [], malformed: 1 };
  /** @type {{ path: string[], value: any, record: any }[]} */
  const entries = [];
  let malformed = 0;
  for (const record of collection) {
    const path = recordPath(record, fields, valueMember);
    if (path === null) malformed += 1;
    else entries.push({ path, value: wholeRecord ? record : own(record, valueMember), record });
  }
  return { entries, malformed };
}

/**
 * @param {any} keys
 * @param {'contentKeys'|'periodKeys'|'chainKeys'} section
 * @returns {{ present: boolean, entries: { path: string[], value: any, record: any }[], malformed: number }}
 */
export function responseSectionEntries(keys, section) {
  const value = own(keys, section);
  if (value === undefined) return { present: false, entries: [], malformed: 0 };
  return { present: true, ...walk(value, FIELDS[section], "key", false) };
}

/**
 * A key-bearing response section a selected extension composes beside `keys`.
 * `path` names its member from the response root, which holds an array of
 * records; `fields` names each record's coordinate fields in order, and the
 * record's `key` member is its key entry. `keyKind` is the kind its entries
 * are bound to under client-bound transport. Trusted composition supplies
 * these; nothing here reads a kind or a path off the wire.
 *
 * @typedef {object} ComposedResponseSection
 * @property {readonly string[]} path
 * @property {readonly string[]} fields
 * @property {string} keyKind
 * @property {readonly string[]} [errorPath] - where the section reports a
 *   retired opening key per coordinate, as records with the same fields
 */

/**
 * Walk one composed section of a response. An entry carries its coordinate as
 * `path`, the field values in `fields` order, its key value and the whole
 * record it came from. A record of the wrong shape counts as malformed, never
 * as an entry.
 *
 * @param {any} response
 * @param {ComposedResponseSection} section
 * @returns {{ present: boolean, entries: { path: string[], value: any, record: any }[], malformed: number }}
 */
export function composedSectionEntries(response, section) {
  let value = response;
  for (const name of section.path) value = own(value, name);
  if (value === undefined) return { present: false, entries: [], malformed: 0 };
  return { present: true, ...walk(value, section.fields, "key", false) };
}

/**
 * Walk the error records a composed section declares at its `errorPath`. An
 * entry carries its coordinate as `path` and the error record as the response
 * carried it, as both `value` and `record`; the caller checks the record. A
 * record without its fields or an `error` member counts as malformed. A
 * section without `errorPath`, or a response without the collection, has
 * nothing present.
 *
 * @param {any} response
 * @param {ComposedResponseSection} section
 * @returns {{ present: boolean, entries: { path: string[], value: any, record: any }[], malformed: number }}
 */
export function composedSectionErrors(response, section) {
  if (section.errorPath === undefined) return { present: false, entries: [], malformed: 0 };
  let value = response;
  for (const name of section.errorPath) value = own(value, name);
  if (value === undefined) return { present: false, entries: [], malformed: 0 };
  return { present: true, ...walk(value, section.fields, "error", true) };
}
