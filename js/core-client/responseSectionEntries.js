// @ts-check
//
// This module walks the structure of the three known response sections. It
// leaves each key entry uninterpreted; the selected consumer decides whether a
// key entry holds direct bytes or a client-bound carrier.

import { own } from "../core-shared/wire.js";

const DEPTH = Object.freeze({ contentKeys: 1, periodKeys: 2, chainKeys: 2 });

/** @param {any} value */
function container(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * @param {any} node
 * @param {number} depth
 * @param {string[]} path
 * @param {{ path: string[], value: any }[]} entries
 * @returns {number} malformed intermediate branches
 */
function descend(node, depth, path, entries) {
  if (depth === 0) {
    entries.push({ path, value: node });
    return 0;
  }
  if (!container(node)) return 1;

  let malformed = 0;
  for (const name of Object.keys(node)) {
    malformed += descend(own(node, name), depth - 1, [...path, name], entries);
  }
  return malformed;
}

/**
 * @param {any} keys
 * @param {'contentKeys'|'periodKeys'|'chainKeys'} section
 * @returns {{ present: boolean, entries: { path: string[], value: any }[], malformed: number }}
 */
export function responseSectionEntries(keys, section) {
  const value = own(keys, section);
  if (value === undefined) return { present: false, entries: [], malformed: 0 };

  /** @type {{ path: string[], value: any }[]} */
  const entries = [];
  const malformed = descend(value, DEPTH[section], [], entries);
  return { present: true, entries, malformed };
}

/**
 * A key-bearing response section a selected extension composes beside `keys`.
 * `path` names its member from the response root, `depth` the names between it
 * and one key entry, and `keyKind` the kind its entries are bound to under
 * client-bound transport. With `leafKey`, each position holds a record and the
 * key entry is that record's `leafKey` member: a chain leaf `{position, key}`
 * reads with `leafKey: "key"`. Trusted composition supplies these; nothing
 * here reads a kind or a path off the wire.
 *
 * @typedef {object} ComposedResponseSection
 * @property {readonly string[]} path
 * @property {number} depth
 * @property {string} keyKind
 * @property {string} [leafKey]
 * @property {readonly string[]} [errorPath] - where the section reports a
 *   retired opening key per coordinate, at the same depth
 */

/**
 * Walk one composed section of a response. An entry carries its name path,
 * its key value, and with `leafKey` the whole leaf record it came from. A
 * branch or leaf of the wrong shape counts as malformed, never as an entry.
 *
 * @param {any} response
 * @param {ComposedResponseSection} section
 * @returns {{ present: boolean, entries: { path: string[], value: any, leaf?: any }[], malformed: number }}
 */
export function composedSectionEntries(response, section) {
  let value = response;
  for (const name of section.path) value = own(value, name);
  if (value === undefined) return { present: false, entries: [], malformed: 0 };

  /** @type {{ path: string[], value: any }[]} */
  const positions = [];
  let malformed = descend(value, section.depth, [], positions);
  if (section.leafKey === undefined) return { present: true, entries: positions, malformed };
  /** @type {{ path: string[], value: any, leaf: any }[]} */
  const entries = [];
  for (const { path, value: leaf } of positions) {
    const key = own(leaf, section.leafKey);
    if (!container(leaf) || key === undefined) malformed += 1;
    else entries.push({ path, value: key, leaf });
  }
  return { present: true, entries, malformed };
}

/**
 * Walk the error map a composed section declares at its `errorPath`, at the
 * section's depth. An entry carries its name path and the error record as the
 * response carried it; the caller checks the record. A branch of the wrong
 * shape counts as malformed. A section without `errorPath`, or a response
 * without the map, has nothing present.
 *
 * @param {any} response
 * @param {ComposedResponseSection} section
 * @returns {{ present: boolean, entries: { path: string[], value: any }[], malformed: number }}
 */
export function composedSectionErrors(response, section) {
  if (section.errorPath === undefined) return { present: false, entries: [], malformed: 0 };
  let value = response;
  for (const name of section.errorPath) value = own(value, name);
  if (value === undefined) return { present: false, entries: [], malformed: 0 };
  /** @type {{ path: string[], value: any }[]} */
  const entries = [];
  const malformed = descend(value, section.depth, [], entries);
  return { present: true, entries, malformed };
}
