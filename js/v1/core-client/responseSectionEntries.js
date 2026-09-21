// @ts-check
//
// This module walks the structure of the three known response sections. It
// leaves each leaf uninterpreted; the selected consumer decides whether a leaf
// holds direct bytes or a client-bound carrier.

import { own } from "../core-shared/wire.js";

const DEPTH = Object.freeze({ contentKeys: 1, periodKeys: 2, periodChainKeys: 2 });

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
 * @param {'contentKeys'|'periodKeys'|'periodChainKeys'} section
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
