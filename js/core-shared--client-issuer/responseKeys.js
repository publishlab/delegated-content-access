// @ts-check
//
// This module walks the `keys` section of an unlock response in one place.
//
// A response carries key material in three sections, each an array of named
// records: `contentKeys` holds `{contentName, key}`, `periodKeys` holds
// `{accessGroup, period, key}` and `chainKeys` holds `{accessGroup, cutoff,
// key}`. Every reader of a whole response reaches the same values. The client
// reads them to tell which transport answered, and the issuer reads them to
// wrap each one for the client that asked. The walk lives here once rather
// than in each reader, so a section that gains a field changes its field list
// here instead of a loop somewhere else.
//
// No code here inspects the value a record carries. A key is a base64url
// string under direct transport and a `{ key, nonce }` pair under
// client-bound, and the caller works out which of the two arrived. The walk
// tells the record and its carried value apart by position: the array element
// is the record and its own `key` member is the value, whatever that holds.
// Several records at one coordinate are candidate alternatives, so the walk
// yields each one and never lets a later record overwrite an earlier one.
//
// Every field is read as an own member, like every other read off the wire.

import { own, setOwn } from "../core-shared/wire.js";
import { dcaError } from "../core-shared/errors.js";

/**
 * Every key-bearing response section of `keys`, the coordinate fields of its
 * records, and the key kind the section fixes for each of its keys.
 * `section` names the wire field (`contentKeys`, `periodKeys`, `chainKeys`);
 * `keyKind` names the meaning assigned to each key entry. contentKeys
 * first, which is the order a response lists them in and the order an issuer
 * wraps them in.
 *
 * @type {[string, readonly string[], 'contentKey'|'periodKey'|'chainKey'][]}
 */
const SECTIONS = [
  ["contentKeys", ["contentName"], "contentKey"],
  ["periodKeys", ["accessGroup", "period"], "periodKey"],
  ["chainKeys", ["accessGroup", "cutoff"], "chainKey"],
];

/**
 * The member of every key record that holds its key value.
 */
const KEY = "key";

/**
 * The coordinate a key record names, as its field values in `fields` order,
 * or null when the value is not a non-array object with a string at every
 * field and an own `key` member.
 *
 * @param {unknown} record
 * @param {readonly string[]} fields
 * @param {string} [valueMember]
 * @returns {string[]|null}
 */
export function recordPath(record, fields, valueMember = KEY) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) return null;
  if (!Object.hasOwn(record, valueMember)) return null;
  /** @type {string[]} */
  const path = [];
  for (const field of fields) {
    const value = own(record, field);
    if (typeof value !== "string") return null;
    path.push(value);
  }
  return path;
}

/**
 * @param {any} collection
 * @param {readonly string[]} fields
 * @returns {Generator<{ path: string[], key: any, record: any }>}
 */
function* keyEntries(collection, fields) {
  if (!Array.isArray(collection)) return;
  for (const record of collection) {
    const path = recordPath(record, fields);
    if (path !== null) yield { path, key: own(record, KEY), record };
  }
}

/**
 * @param {any} keys
 * @returns {Generator<{ section: string, path: string[], key: any }>}
 */
function* entries(keys) {
  for (const [section, fields] of SECTIONS) {
    for (const { path, key } of keyEntries(own(keys, section), fields))
      yield { section, path, key };
  }
}

/**
 * Every key a response delivers, in the order it lists them.
 *
 * A section that is missing, or that did not arrive as an array, delivers
 * nothing rather than throwing, and so does a record that does not name its
 * coordinate: a malformed response is the caller's to answer
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
 * A copy of one record collection with the `key` member of every well-formed
 * record replaced by `await fn(key)`, in array order. A record keeps its other
 * members; an element that names no coordinate stays as it arrived and is
 * never handed to `fn`.
 *
 * @param {any} collection
 * @param {readonly string[]} fields
 * @param {(key: any) => any} fn
 * @returns {Promise<any>}
 */
async function mapRecords(collection, fields, fn) {
  if (!Array.isArray(collection)) return collection;
  const mapped = [];
  for (const record of collection) {
    if (recordPath(record, fields) === null) {
      mapped.push(record);
      continue;
    }
    /** @type {Record<string, any>} */
    const copy = {};
    for (const name of Object.keys(record)) setOwn(copy, name, record[name]);
    setOwn(copy, KEY, await fn(own(record, KEY)));
    mapped.push(copy);
  }
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

  for (const [section, fields, keyKind] of SECTIONS) {
    const delivered = own(keys, section);
    if (delivered === undefined) continue;
    mapped[section] = await mapRecords(delivered, fields, (key) => fn(key, keyKind));
  }

  return mapped;
}

/**
 * A key-bearing response section a selected extension composes beside `keys`,
 * as trusted composition declares it. `path` names its member from the
 * response root, which holds an array of records. `fields` names the
 * coordinate fields of each record in order, and the record's `key` member is
 * its key entry. `keyKind` names the kind its entries bind under client-bound
 * transport. With `errorPath`, the section also reports a retired opening key
 * per coordinate in an array of records at that path, each carrying the same
 * `fields` and exactly `error: "key_retired"` (`isRetirementLeaf`). An error
 * record is never a key entry and is never wrapped.
 *
 * @typedef {object} ComposedSection
 * @property {readonly string[]} path
 * @property {readonly string[]} fields
 * @property {string} keyKind
 * @property {readonly string[]} [errorPath]
 */

/** The one error a composed section's error records may carry. */
const RETIREMENT_ERROR = "key_retired";

/** The most coordinate fields a composed record may name. */
const MAX_FIELDS = 4;

/**
 * Whether `value` is a retirement record of a composed section with these
 * coordinate `fields`: a non-array object holding each field as a string and
 * `error: "key_retired"`, with no other member. A free-form record could carry
 * key bytes past a guard that does not wrap error records.
 *
 * @param {unknown} value
 * @param {readonly string[]} fields
 * @returns {boolean}
 */
export function isRetirementLeaf(value, fields) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const names = Object.keys(value);
  return (
    names.length === fields.length + 1 &&
    own(value, "error") === RETIREMENT_ERROR &&
    fields.every((field) => typeof own(value, field) === "string")
  );
}

/**
 * Admit composed sections once, at composition. A path or error path is one or
 * more member names and never starts at `keys`, `transport`, `errors` or
 * `notDelivered`; no two of the declared paths and error paths are equal or
 * contain one another. `fields` lists one to four distinct member names, none
 * of them `key` or `error`, which the record itself uses.
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
  /** @param {unknown} fields */
  const recordFields = (fields) =>
    Array.isArray(fields) &&
    fields.length > 0 &&
    fields.length <= MAX_FIELDS &&
    fields.every(
      (name) => typeof name === "string" && name.length > 0 && name !== KEY && name !== "error",
    ) &&
    new Set(fields).size === fields.length;
  const bad = (/** @type {string} */ why) =>
    dcaError("bad_config", `composed response sections: ${why}`);
  if (!Array.isArray(sections)) throw bad("a list");
  const seen = new Set();
  /** @type {string[][]} */
  const paths = [];
  return Object.freeze(
    sections.map((section) => {
      const { path, fields, keyKind, errorPath, ...rest } = section ?? {};
      if (Object.keys(rest).length > 0 || !memberPath(path))
        throw bad("each names a non-base member path");
      if (errorPath !== undefined && !memberPath(errorPath))
        throw bad("an errorPath is a non-base member path");
      if (!recordFields(fields))
        throw bad("fields are one to four distinct member names other than key and error");
      if (typeof keyKind !== "string" || keyKind.length === 0) throw bad("each names its key kind");
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
        fields: Object.freeze([...fields]),
        keyKind,
        ...(errorPath === undefined ? {} : { errorPath: Object.freeze([...errorPath]) }),
      });
    }),
  );
}

/**
 * Every key entry of the composed sections, in declaration order and then
 * array order, with the kind its section fixes and the record it came from.
 * Several records at one coordinate each yield an entry.
 *
 * @param {any} response
 * @param {readonly Readonly<ComposedSection>[]} sections - settled
 * @returns {Generator<{ section: Readonly<ComposedSection>, path: string[], key: any, record: any }>}
 */
export function* composedKeys(response, sections) {
  for (const section of sections) {
    let node = response;
    for (const name of section.path) node = own(node, name);
    for (const entry of keyEntries(node, section.fields)) yield { section, ...entry };
  }
}

/**
 * Returns a copy of `response` with every key entry of the composed sections
 * replaced by `fn(key, keyKind)`, awaited one at a time in declaration order,
 * the way `mapDeliveredKeys` treats `keys`. A record keeps its other members;
 * only its `key` member is replaced. Members outside the declared paths are
 * copied unchanged.
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
      await mapRecords(delivered, section.fields, (key) => fn(key, section.keyKind)),
    );
  }
  return mapped;
}
