//
// The two sections of a response nest differently. `contentKeys[name]` holds
// one key, `periodKeys[group][t]` holds one a level deeper, and three readers
// used to descend into them on their own. These are the rules that walk now
// stands on: where a key sits, what a malformed section delivers, and that a
// rebuild spends its per-key work in the order the response lists.

import test from "node:test";
import assert from "node:assert/strict";

import {
  deliveredCoordinates,
  deliveredKeys,
  mapDeliveredKeys,
} from "../../core-shared--client-issuer/responseKeys.js";

const INHERITED = ["constructor", "toString", "valueOf"];

/**
 * A direct answer carrying both sections. The names in it are made up rather
 * than the fixtures': the walk answers where a key sits, so groups the suite
 * has never heard of, beside `t` labels in a format `formatT` never emits,
 * state that claim out loud. In the fixtures' own names it would instead read
 * as a walk that knew them.
 */
function keys() {
  return {
    contentKeys: { bodytext: "AAAA", image: "BBBB" },
    periodKeys: {
      subscriber: { "2025-10-23T14": "CCCC", "2025-10-23T15": "DDDD" },
      member: { "2025-10-23T14": "EEEE" },
    },
    chainKeys: {
      subscriber: { "2025-10-23T23": "FFFF" },
    },
  };
}

test("every key of all sections is delivered, content and period keys before chain keys", () => {
  assert.deepEqual([...deliveredKeys(keys())], ["AAAA", "BBBB", "CCCC", "DDDD", "EEEE", "FFFF"]);
});

test("every delivered coordinate is named without exposing its key", () => {
  assert.deepEqual(
    [...deliveredCoordinates(keys())],
    [
      { type: "contentKey", contentName: "bodytext" },
      { type: "contentKey", contentName: "image" },
      { type: "periodKey", accessGroup: "subscriber", t: "2025-10-23T14" },
      { type: "periodKey", accessGroup: "subscriber", t: "2025-10-23T15" },
      { type: "periodKey", accessGroup: "member", t: "2025-10-23T14" },
      { type: "chainKey", accessGroup: "subscriber", t: "2025-10-23T23" },
    ],
  );
});

test("a wrapped contentKey is one key, not a map of them", () => {
  // Client-bound puts a `{ key, nonce }` pair where direct puts a string. A
  // walk that descended into it would deliver two keys for one, and read the
  // nonce beside a key as a key.
  const wrapped = { contentKeys: { bodytext: { key: "AAAA", nonce: "BBBB" } } };

  assert.deepEqual([...deliveredKeys(wrapped)], [{ key: "AAAA", nonce: "BBBB" }]);
});

test("a section that is absent or not an object delivers nothing", () => {
  for (const keysSection of [
    undefined,
    null,
    {},
    "AAAA",
    { contentKeys: null },
    { periodKeys: "AAAA" },
  ]) {
    assert.deepEqual(
      [...deliveredKeys(keysSection)],
      [],
      JSON.stringify(keysSection) ?? "undefined",
    );
  }

  // A group that did not arrive as a map of periods is skipped rather than
  // delivered as a key: what is at the bottom is the caller's to judge, but
  // where the bottom is, is not.
  assert.deepEqual([...deliveredKeys({ periodKeys: { subscriber: "AAAA" } })], []);
});

test("an inherited section name delivers nothing", () => {
  for (const name of INHERITED) {
    assert.deepEqual([...deliveredKeys(Object.create({ [name]: { x: "AAAA" } }))], []);
  }
});

test("a rebuild replaces every key at its own depth", async () => {
  const rebuilt = await mapDeliveredKeys(keys(), (key) => `${key}!`);

  assert.deepEqual(rebuilt, {
    contentKeys: { bodytext: "AAAA!", image: "BBBB!" },
    periodKeys: {
      subscriber: { "2025-10-23T14": "CCCC!", "2025-10-23T15": "DDDD!" },
      member: { "2025-10-23T14": "EEEE!" },
    },
    chainKeys: {
      subscriber: { "2025-10-23T23": "FFFF!" },
    },
  });
});

test("a rebuild preserves malformed nested key sections without wrapping them", async () => {
  const malformed = {
    contentKeys: { bodytext: "AAAA" },
    periodKeys: { subscriber: "not-a-period-map" },
    chainKeys: { member: null },
  };
  /** @type {string[]} */
  const seen = [];

  const rebuilt = await mapDeliveredKeys(malformed, (key) => {
    seen.push(key);
    return `${key}!`;
  });

  assert.deepEqual(seen, ["AAAA"]);
  assert.deepEqual(rebuilt, {
    contentKeys: { bodytext: "AAAA!" },
    periodKeys: { subscriber: "not-a-period-map" },
    chainKeys: { member: null },
  });
});

test("a client-bound rebuild preserves an own __proto__ coordinate without changing a prototype", async () => {
  // `__proto__` is not a grammar-legal contentName (see names.test.js), but
  // this walker receives a parsed wire response before a caller judges its
  // shape. JSON makes it an ordinary own member, whereas bracket assignment
  // on the rebuilt `{}` would invoke Object.prototype's legacy setter.
  const original = JSON.parse('{"contentKeys":{"__proto__":"AAAA"}}');
  const objectPrototype = Object.getOwnPropertyDescriptors(Object.prototype);
  const wrapped = { key: "wrapped-key", nonce: "wrapped-nonce" };

  // This is the value KeyDelivery's client-bound path writes at each key entry.
  const rebuilt = await mapDeliveredKeys(original, () => wrapped);

  assert.equal(
    Object.hasOwn(rebuilt.contentKeys, "__proto__"),
    true,
    "the coordinate remains an own member",
  );
  assert.strictEqual(
    rebuilt.contentKeys.__proto__,
    wrapped,
    "the client-bound wrapped key entry remains at that coordinate",
  );
  assert.equal(
    Object.getPrototypeOf(rebuilt.contentKeys),
    Object.prototype,
    "the wrapped key entry was not installed as the map prototype",
  );
  assert.deepEqual(
    Object.getOwnPropertyDescriptors(Object.prototype),
    objectPrototype,
    "the rebuild leaves Object.prototype unchanged",
  );
});

test("a rebuild spends its per-key work in the order the response lists", async () => {
  // The issuer takes a nonce per key it wraps, so two answers built from one
  // response have to reach the keys in the same order.
  /** @type {string[]} */
  const seen = [];
  await mapDeliveredKeys(keys(), async (key) => {
    await Promise.resolve();
    seen.push(key);
    return key;
  });

  assert.deepEqual(seen, [...deliveredKeys(keys())]);
});

test("a rebuild copies, and leaves everything that is not a key alone", async () => {
  const original = { ...keys(), errors: { image: "no_grant" } };
  const before = structuredClone(original);

  const rebuilt = await mapDeliveredKeys(original, () => "ZZZZ");

  assert.deepEqual(original, before, "the body handed in is not the one to write through");
  assert.deepEqual(rebuilt.errors, { image: "no_grant" });
  assert.notEqual(rebuilt.contentKeys, original.contentKeys);
});

test("a rebuild leaves an absent section absent", async () => {
  const rebuilt = await mapDeliveredKeys({ contentKeys: { bodytext: "AAAA" } }, () => "ZZZZ");

  assert.deepEqual(rebuilt, { contentKeys: { bodytext: "ZZZZ" } });
  assert.equal(
    Object.hasOwn(rebuilt, "periodKeys"),
    false,
    "an empty section would read as a grant of no keys",
  );
});

test("a rebuild of a keys that did not arrive as an object hands it back unchanged", async () => {
  // `deliveredKeys` reads nothing out of a non-object keys; a rebuild has the
  // same nothing to replace, so it returns the value rather than spreading a
  // string into index-keyed characters a caller never meant.
  for (const keysValue of ["AAAA", undefined, null, 42]) {
    assert.deepEqual(
      await mapDeliveredKeys(keysValue, () => "ZZZZ"),
      keysValue,
      JSON.stringify(keysValue) ?? "undefined",
    );
  }
});
