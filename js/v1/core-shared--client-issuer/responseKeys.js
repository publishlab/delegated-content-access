// @ts-check
//
// This module walks the `keys` section of an unlock response in one place.
//
// A response carries key material in three sections that nest differently:
// `contentKeys[contentName]` holds one key, `periodKeys[accessGroup][t]` holds
// one a level deeper, and `periodChainKeys` has the same keyed depth. Every
// reader of a whole response reaches the same values. The client reads them to
// tell which transport answered, and the issuer reads them to wrap each one for
// the client that asked. The descent lives here once rather than in each
// reader, because a per-reader descent would have to be found again in every
// reader when a section moves.
//
// This module records each section's nesting as a depth number, so a section
// that gains a level changes that number here instead of needing another loop
// somewhere else.
//
// No code here inspects the value at the bottom. A key is a base64url string
// under direct transport and a `{ key, nonce }` pair under client-bound, and
// the caller works out which of the two arrived. This walk stops at each
// position and yields whatever it holds, including a value that is neither.
//
// All three sections are keyed by names the page or the issuer chose, so the section
// lookups are own-property like every other read of something off the wire.

import { own, setOwn } from "../core-shared/wire.js";

/**
 * Every key-bearing section of `keys`, and how many names stand between it and one
 * key. contentKeys first, which is the order a response lists them in and the
 * order an issuer wraps them in.
 *
 * @type {[string, number][]}
 */
const SECTIONS = [
  ["contentKeys", 1],
  ["periodKeys", 2],
  ["periodChainKeys", 2],
];

/**
 * @param {any} node
 * @param {number} depth
 * @param {string[]} [path]
 * @returns {Generator<{ path: string[], key: any }>}
 */
function* leaves(node, depth, path = []) {
  if (depth === 0) {
    yield { path, key: node };
    return;
  }
  if (node === null || typeof node !== "object") return;
  for (const name of Object.keys(node)) yield* leaves(node[name], depth - 1, [...path, name]);
}

/**
 * @param {any} keys
 * @returns {Generator<{ section: string, path: string[], key: any }>}
 */
function* entries(keys) {
  for (const [section, depth] of SECTIONS) {
    for (const entry of leaves(own(keys, section), depth)) yield { section, ...entry };
  }
}

/**
 * Every key a response delivers, in the order it lists them.
 *
 * A section that is missing, or that did not arrive as an object, delivers
 * nothing rather than throwing: a malformed response is the caller's to answer
 * for, and it cannot answer for one from a TypeError three frames down.
 *
 * @param {any} keys
 * @returns {Generator<any>}
 */
export function* deliveredKeys(keys) {
  for (const { key } of entries(keys)) yield key;
}

/**
 * Every coordinate the response actually delivers. This is derived from the
 * final response, because fallback trimming and unseal failures can narrow a
 * policy decision before anything leaves the issuer.
 *
 * @param {any} keys
 * @returns {Generator<({ type: 'contentKey', contentName: string }|{ type: 'periodKey'|'periodChainKey', accessGroup: string, t: string })>}
 */
export function* deliveredCoordinates(keys) {
  for (const { section, path } of entries(keys)) {
    if (section === "contentKeys") {
      yield { type: "contentKey", contentName: path[0] };
    } else {
      yield {
        type: section === "periodKeys" ? "periodKey" : "periodChainKey",
        accessGroup: path[0],
        t: path[1],
      };
    }
  }
}

/**
 * @param {any} node
 * @param {number} depth
 * @param {(key: any) => any} fn
 * @returns {Promise<any>}
 */
async function mapLeaves(node, depth, fn) {
  if (depth === 0) return fn(node);
  if (node === null || typeof node !== "object") return node;

  /** @type {Record<string, any>} */
  const mapped = {};
  for (const name of Object.keys(node))
    setOwn(mapped, name, await mapLeaves(node[name], depth - 1, fn));
  return mapped;
}

/**
 * Returns a copy of `keys` with every delivered key replaced by the result of
 * `fn(key)`. It copies rather than writes through, because the caller may not
 * own the body it passes in, and one cached answer is served to more than one
 * client.
 *
 * It calls `fn` on one key at a time and awaits each call in order, because
 * replacing a key may consume a nonce, and two answers built from the same
 * response have to consume their nonces in the same order.
 *
 * If `keys` did not arrive as an object, it has no section to descend, so this
 * function returns it unchanged instead of spreading it. `{ ...'AAAA' }` would
 * turn a string into an index-keyed object, which is a different value that no
 * reader of the result asked for. `deliveredKeys` behaves the same way and
 * reads nothing out of such a non-object.
 *
 * @param {any} keys
 * @param {(key: any) => any} fn
 * @returns {Promise<any>}
 */
export async function mapDeliveredKeys(keys, fn) {
  if (keys === null || typeof keys !== "object") return keys;

  const mapped = { ...keys };

  for (const [section, depth] of SECTIONS) {
    const delivered = own(keys, section);
    if (delivered === undefined) continue;
    mapped[section] = await mapLeaves(delivered, depth, fn);
  }

  return mapped;
}
