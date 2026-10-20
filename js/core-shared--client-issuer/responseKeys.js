// @ts-check
//
// This module walks the `keys` section of an unlock response in one place.
//
// A response carries key material in three sections that nest differently:
// `contentKeys[contentName]` holds one key, `periodKeys[accessGroup][t]` holds
// one a level deeper, and `chainKeys` has the same keyed depth. Every
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
import { dcaError } from "../core-shared/errors.js";

/**
 * Every key-bearing response section of `keys`, how many names stand between
 * it and one key, and the key kind the section fixes for each of its keys.
 * `section` names the wire field (`contentKeys`, `periodKeys`, `chainKeys`);
 * `keyKind` names the meaning assigned to each key entry. contentKeys
 * first, which is the order a response lists them in and the order an issuer
 * wraps them in.
 *
 * @type {[string, number, 'contentKey'|'periodKey'|'chainKey'][]}
 */
const SECTIONS = [
  ["contentKeys", 1, "contentKey"],
  ["periodKeys", 2, "periodKey"],
  ["chainKeys", 2, "chainKey"],
];

/**
 * @param {any} node
 * @param {number} depth
 * @param {string[]} [path]
 * @returns {Generator<{ path: string[], key: any }>}
 */
function* keyEntries(node, depth, path = []) {
  if (depth === 0) {
    yield { path, key: node };
    return;
  }
  if (node === null || typeof node !== "object") return;
  for (const name of Object.keys(node)) yield* keyEntries(node[name], depth - 1, [...path, name]);
}

/**
 * @param {any} keys
 * @returns {Generator<{ section: string, path: string[], key: any }>}
 */
function* entries(keys) {
  for (const [section, depth] of SECTIONS) {
    for (const entry of keyEntries(own(keys, section), depth)) yield { section, ...entry };
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
 * @returns {Generator<({ type: 'contentKey', contentName: string }|{ type: 'periodKey'|'chainKey', accessGroup: string, t: string })>}
 */
export function* deliveredCoordinates(keys) {
  for (const { section, path } of entries(keys)) {
    if (section === "contentKeys") {
      yield { type: "contentKey", contentName: path[0] };
    } else {
      yield {
        type: section === "periodKeys" ? "periodKey" : "chainKey",
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
async function mapKeyEntries(node, depth, fn) {
  if (depth === 0) return fn(node);
  if (node === null || typeof node !== "object") return node;

  /** @type {Record<string, any>} */
  const mapped = {};
  for (const name of Object.keys(node))
    setOwn(mapped, name, await mapKeyEntries(node[name], depth - 1, fn));
  return mapped;
}

/**
 * Returns a copy of `keys` with every delivered key replaced by the result of
 * `fn(key, keyKind)`, where `keyKind` is the kind the key's section fixes:
 * `contentKey`, `periodKey` or `chainKey`. It copies rather than writes
 * through, because the caller may not own the body it passes in, and one
 * cached answer is served to more than one client.
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
 * @param {(key: any, keyKind: 'contentKey'|'periodKey'|'chainKey') => any} fn
 * @returns {Promise<any>}
 */
export async function mapDeliveredKeys(keys, fn) {
  if (keys === null || typeof keys !== "object") return keys;

  const mapped = { ...keys };

  for (const [section, depth, keyKind] of SECTIONS) {
    const delivered = own(keys, section);
    if (delivered === undefined) continue;
    mapped[section] = await mapKeyEntries(delivered, depth, (key) => fn(key, keyKind));
  }

  return mapped;
}

/**
 * A key-bearing response section a selected extension composes beside `keys`,
 * as trusted composition declares it. `path` names its member from the
 * response root, `depth` the names between it and one key position, and
 * `keyKind` the kind its entries bind under client-bound transport. With
 * `leafKey`, each position holds a record and the key entry is that record's
 * `leafKey` member, for example a metadata record can declare `leafKey: "key"`.
 * With `errorPath`, the section also reports a retired opening key per
 * coordinate in a map at that path, nested at the same `depth`, whose every
 * leaf is exactly `{ error: "key_retired" }` (`isRetirementLeaf`). An error
 * leaf is never a key entry and is never wrapped.
 *
 * @typedef {object} ComposedSection
 * @property {readonly string[]} path
 * @property {number} depth
 * @property {string} keyKind
 * @property {string} [leafKey]
 * @property {readonly string[]} [errorPath]
 */

/** The one error a composed section's error map may carry. */
const RETIREMENT_ERROR = "key_retired";

/**
 * Whether `value` is the fixed retirement leaf `{ error: "key_retired" }`,
 * with no other member: a free-form record could carry key bytes past a guard
 * that does not wrap error records.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isRetirementLeaf(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const names = Object.keys(value);
  return names.length === 1 && names[0] === "error" && own(value, "error") === RETIREMENT_ERROR;
}

/**
 * Admit composed sections once, at composition. A path or error path is one or
 * more member names and never starts at `keys`, `transport`, `errors` or
 * `notDelivered`; no two of the declared paths and error paths are equal or
 * contain one another.
 *
 * @param {unknown} sections
 * @returns {readonly Readonly<ComposedSection>[]}
 */
export function settleComposedSections(sections) {
  /** @param {unknown} path */
  const memberPath = (path) =>
    Array.isArray(path) &&
    path.length > 0 &&
    path.every((name) => typeof name === "string" && name.length > 0) &&
    !["keys", "transport", "errors", "notDelivered"].includes(path[0]);
  const bad = (/** @type {string} */ why) =>
    dcaError("bad_config", `composed response sections: ${why}`);
  if (!Array.isArray(sections)) throw bad("a list");
  const seen = new Set();
  /** @type {string[][]} */
  const paths = [];
  return Object.freeze(
    sections.map((section) => {
      const { path, depth, keyKind, leafKey, errorPath, ...rest } = section ?? {};
      if (Object.keys(rest).length > 0 || !memberPath(path))
        throw bad("each names a non-base member path");
      if (errorPath !== undefined && !memberPath(errorPath))
        throw bad("an errorPath is a non-base member path");
      if (!Number.isSafeInteger(depth) || depth < 1 || depth > 4) throw bad("depth is 1 to 4");
      if (typeof keyKind !== "string" || keyKind.length === 0) throw bad("each names its key kind");
      if (leafKey !== undefined && (typeof leafKey !== "string" || leafKey.length === 0))
        throw bad("leafKey is a member name");
      for (const declared of errorPath === undefined ? [path] : [path, errorPath]) {
        const id = JSON.stringify(declared);
        if (seen.has(id)) throw bad(`two sections at ${declared.join(".")}`);
        if (
          paths.some((other) =>
            other
              .slice(0, Math.min(other.length, declared.length))
              .every((name, i) => name === declared[i]),
          )
        )
          throw bad(`overlapping section paths at ${declared.join(".")}`);
        seen.add(id);
        paths.push([...declared]);
      }
      return Object.freeze({
        path: Object.freeze([...path]),
        depth,
        keyKind,
        ...(leafKey === undefined ? {} : { leafKey }),
        ...(errorPath === undefined ? {} : { errorPath: Object.freeze([...errorPath]) }),
      });
    }),
  );
}

/**
 * @param {any} node
 * @param {number} depth
 * @param {string|undefined} leafKey
 * @param {(key: any) => any} fn
 * @returns {Promise<any>}
 */
async function mapComposedEntries(node, depth, leafKey, fn) {
  if (depth === 0) {
    if (leafKey === undefined) return fn(node);
    if (node === null || typeof node !== "object" || own(node, leafKey) === undefined) return node;
    /** @type {Record<string, any>} */
    const leaf = {};
    for (const name of Object.keys(node)) setOwn(leaf, name, node[name]);
    setOwn(leaf, leafKey, await fn(own(node, leafKey)));
    return leaf;
  }
  if (node === null || typeof node !== "object") return node;
  /** @type {Record<string, any>} */
  const mapped = {};
  for (const name of Object.keys(node))
    setOwn(mapped, name, await mapComposedEntries(node[name], depth - 1, leafKey, fn));
  return mapped;
}

/**
 * Every key entry of the composed sections, in declaration order, with the
 * kind its section fixes.
 *
 * @param {any} response
 * @param {readonly Readonly<ComposedSection>[]} sections - settled
 * @returns {Generator<{ section: Readonly<ComposedSection>, path: string[], key: any }>}
 */
export function* composedKeys(response, sections) {
  for (const section of sections) {
    let node = response;
    for (const name of section.path) node = own(node, name);
    for (const { path, key: position } of keyEntries(node, section.depth)) {
      if (section.leafKey === undefined) yield { section, path, key: position };
      else if (position !== null && typeof position === "object") {
        const key = own(position, section.leafKey);
        if (key !== undefined) yield { section, path, key };
      }
    }
  }
}

/**
 * Returns a copy of `response` with every key entry of the composed sections
 * replaced by `fn(key, keyKind)`, awaited one at a time in declaration order,
 * the way `mapDeliveredKeys` treats `keys`. A leaf record keeps its other
 * members; only its `leafKey` member is replaced. Members outside the declared
 * paths are copied unchanged.
 *
 * @param {any} response
 * @param {readonly Readonly<ComposedSection>[]} sections - settled
 * @param {(key: any, keyKind: string) => any} fn
 * @returns {Promise<any>}
 */
export async function mapComposedSections(response, sections, fn) {
  if (response === null || typeof response !== "object") return response;
  const mapped = { ...response };
  for (const section of sections) {
    /** @type {any[]} */
    const parents = [mapped];
    for (const name of section.path.slice(0, -1)) {
      const parent = parents.at(-1);
      const child = own(parent, name);
      if (child === null || typeof child !== "object" || Array.isArray(child)) break;
      const copy = { ...child };
      setOwn(parent, name, copy);
      parents.push(copy);
    }
    if (parents.length !== section.path.length) continue;
    const last = section.path.at(-1) ?? "";
    const parent = parents.at(-1);
    const delivered = own(parent, last);
    if (delivered === undefined) continue;
    setOwn(
      parent,
      last,
      await mapComposedEntries(delivered, section.depth, section.leafKey, (key) =>
        fn(key, section.keyKind),
      ),
    );
  }
  return mapped;
}
