//
// Each response section is an array of named records: `contentKeys` holds
// `{contentName, key}`, `periodKeys` holds `{accessGroup, period, key}` and
// `chainKeys` holds `{accessGroup, cutoff, key}`. Three readers used to
// descend into them on their own. These are the rules that walk now stands
// on: which member of a record is the key, what a malformed record delivers,
// that several records at one coordinate all stay, and that a rebuild spends
// its per-key work in the order the response lists.

import test from "node:test";
import assert from "node:assert/strict";

import {
  composedKeys,
  deliveredCoordinates,
  deliveredKeys,
  isRetirementLeaf,
  mapComposedSections,
  mapDeliveredKeys,
  settleComposedSections,
} from "../../core-shared--client-issuer/responseKeys.js";
import {
  composedSectionEntries,
  composedSectionErrors,
  responseSectionEntries,
} from "../../core-client/responseSectionEntries.js";

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
    contentKeys: [
      { contentName: "bodytext", key: "AAAA" },
      { contentName: "image", key: "BBBB" },
    ],
    periodKeys: [
      { accessGroup: "subscriber", period: "2025-10-23T14", key: "CCCC" },
      { accessGroup: "subscriber", period: "2025-10-23T15", key: "DDDD" },
      { accessGroup: "member", period: "2025-10-23T14", key: "EEEE" },
    ],
    chainKeys: [{ accessGroup: "subscriber", cutoff: "2025-10-23T23", key: "FFFF" }],
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

test("a wrapped contentKey is the record's key member, not the record", () => {
  // Client-bound puts a `{ key, nonce }` pair where direct puts a string, so
  // the record and its carried value both have a member named `key`. The walk
  // tells them apart by position: the record is the array element, and its
  // `key` member is the value, whatever that value holds.
  const wrapped = {
    contentKeys: [{ contentName: "bodytext", key: { key: "AAAA", nonce: "BBBB" } }],
  };

  assert.deepEqual([...deliveredKeys(wrapped)], [{ key: "AAAA", nonce: "BBBB" }]);
});

test("several records at one coordinate are all delivered, in array order", () => {
  // Candidate alternatives: the walk keeps each one rather than letting a
  // later record overwrite an earlier one at its coordinate.
  const rivals = {
    contentKeys: [
      { contentName: "bodytext", key: "AAAA" },
      { contentName: "bodytext", key: "BBBB" },
    ],
    periodKeys: [
      { accessGroup: "member", period: "2025-10-23T14", key: "CCCC" },
      { accessGroup: "member", period: "2025-10-23T14", key: "DDDD" },
    ],
  };

  assert.deepEqual([...deliveredKeys(rivals)], ["AAAA", "BBBB", "CCCC", "DDDD"]);
  assert.deepEqual(
    [...deliveredCoordinates(rivals)],
    [
      { type: "contentKey", contentName: "bodytext" },
      { type: "contentKey", contentName: "bodytext" },
      { type: "periodKey", accessGroup: "member", t: "2025-10-23T14" },
      { type: "periodKey", accessGroup: "member", t: "2025-10-23T14" },
    ],
  );
});

test("a section that is absent or not an array delivers nothing", () => {
  for (const keysSection of [
    undefined,
    null,
    {},
    "AAAA",
    { contentKeys: null },
    { periodKeys: "AAAA" },
    { contentKeys: { bodytext: "AAAA" } },
  ]) {
    assert.deepEqual(
      [...deliveredKeys(keysSection)],
      [],
      JSON.stringify(keysSection) ?? "undefined",
    );
  }

  // A record that does not name its coordinate is skipped rather than
  // delivered as a key: what its `key` holds is the caller's to judge, but
  // which member is the key, and where it sits, is not.
  for (const record of [
    "AAAA",
    null,
    ["AAAA"],
    { accessGroup: "subscriber", key: "AAAA" },
    { accessGroup: "subscriber", period: 7, key: "AAAA" },
    { accessGroup: "subscriber", period: "2025-10-23T14" },
  ]) {
    assert.deepEqual([...deliveredKeys({ periodKeys: [record] })], [], JSON.stringify(record));
  }
});

test("an inherited section name or record field delivers nothing", () => {
  for (const name of INHERITED) {
    assert.deepEqual(
      [...deliveredKeys(Object.create({ [name]: [{ contentName: "x", key: "AAAA" }] }))],
      [],
    );
  }
  const inheritedKey = Object.create({ key: "AAAA" });
  inheritedKey.contentName = "bodytext";
  assert.deepEqual([...deliveredKeys({ contentKeys: [inheritedKey] })], []);
});

test("a rebuild replaces the key member of every record and keeps its fields", async () => {
  const rebuilt = await mapDeliveredKeys(keys(), (key) => `${key}!`);

  assert.deepEqual(rebuilt, {
    contentKeys: [
      { contentName: "bodytext", key: "AAAA!" },
      { contentName: "image", key: "BBBB!" },
    ],
    periodKeys: [
      { accessGroup: "subscriber", period: "2025-10-23T14", key: "CCCC!" },
      { accessGroup: "subscriber", period: "2025-10-23T15", key: "DDDD!" },
      { accessGroup: "member", period: "2025-10-23T14", key: "EEEE!" },
    ],
    chainKeys: [{ accessGroup: "subscriber", cutoff: "2025-10-23T23", key: "FFFF!" }],
  });
});

test("a rebuild preserves malformed sections and records without wrapping them", async () => {
  const malformed = {
    contentKeys: [{ contentName: "bodytext", key: "AAAA" }],
    periodKeys: [{ accessGroup: "subscriber", key: "no-period" }, "not-a-record"],
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
    contentKeys: [{ contentName: "bodytext", key: "AAAA!" }],
    periodKeys: [{ accessGroup: "subscriber", key: "no-period" }, "not-a-record"],
    chainKeys: { member: null },
  });
});

test("a client-bound rebuild preserves an own __proto__ record member without changing a prototype", async () => {
  // `__proto__` is no record field, but this walker receives a parsed wire
  // response before a caller judges its shape. JSON makes it an ordinary own
  // member, whereas bracket assignment on a rebuilt `{}` would invoke
  // Object.prototype's legacy setter.
  const original = JSON.parse(
    '{"contentKeys":[{"contentName":"bodytext","__proto__":"x","key":"AAAA"}]}',
  );
  const objectPrototype = Object.getOwnPropertyDescriptors(Object.prototype);
  const wrapped = { key: "wrapped-key", nonce: "wrapped-nonce" };

  // This is the value KeyDelivery's client-bound path writes at each key entry.
  const rebuilt = await mapDeliveredKeys(original, () => wrapped);
  const [record] = rebuilt.contentKeys;

  assert.equal(Object.hasOwn(record, "__proto__"), true, "the member remains an own member");
  assert.strictEqual(record.key, wrapped, "the wrapped key entry replaces the record's key");
  assert.equal(
    Object.getPrototypeOf(record),
    Object.prototype,
    "the copied member was not installed as the record prototype",
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
  const original = { ...keys(), errors: [{ coordinate: "image", error: "no_grant" }] };
  const before = structuredClone(original);

  const rebuilt = await mapDeliveredKeys(original, () => "ZZZZ");

  assert.deepEqual(original, before, "the body handed in is not the one to write through");
  assert.deepEqual(rebuilt.errors, [{ coordinate: "image", error: "no_grant" }]);
  assert.notEqual(rebuilt.contentKeys, original.contentKeys);
  assert.notEqual(rebuilt.contentKeys[0], original.contentKeys[0]);
});

test("a rebuild leaves an absent section absent", async () => {
  const rebuilt = await mapDeliveredKeys(
    { contentKeys: [{ contentName: "bodytext", key: "AAAA" }] },
    () => "ZZZZ",
  );

  assert.deepEqual(rebuilt, { contentKeys: [{ contentName: "bodytext", key: "ZZZZ" }] });
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

test("the client walk yields each record's coordinate and key, and counts malformed records", () => {
  const section = responseSectionEntries(
    {
      periodKeys: [
        { accessGroup: "member", period: "2025-10-23T14", key: "CCCC" },
        { accessGroup: "member", period: "2025-10-23T14", key: { key: "DDDD", nonce: "EEEE" } },
        { accessGroup: "member", key: "FFFF" },
        "GGGG",
      ],
    },
    "periodKeys",
  );

  assert.equal(section.present, true);
  assert.equal(section.malformed, 2);
  assert.deepEqual(
    section.entries.map(({ path, value }) => ({ path, value })),
    [
      { path: ["member", "2025-10-23T14"], value: "CCCC" },
      { path: ["member", "2025-10-23T14"], value: { key: "DDDD", nonce: "EEEE" } },
    ],
  );
  assert.deepEqual(responseSectionEntries({}, "chainKeys"), {
    present: false,
    entries: [],
    malformed: 0,
  });
  // A section that is not an array is present and wholly malformed.
  assert.deepEqual(responseSectionEntries({ contentKeys: { bodytext: "AAAA" } }, "contentKeys"), {
    present: true,
    entries: [],
    malformed: 1,
  });
  assert.deepEqual(
    responseSectionEntries(
      { chainKeys: [{ accessGroup: "member", cutoff: "2025-10-23T23", key: "HHHH" }] },
      "chainKeys",
    ).entries.map(({ path }) => path),
    [["member", "2025-10-23T23"]],
  );
});

/**
 * A made-up composed section beside `keys`: records `{item, slot, key}`, and
 * retirement records `{item, slot, error}` at their own path.
 */
const COMPOSED = Object.freeze({
  path: ["extra", "slotKeys"],
  fields: ["item", "slot"],
  keyKind: "slotKey",
  errorPath: ["extra", "errors", "slotKeys"],
});

function composedBody() {
  return {
    keys: { contentKeys: [] },
    extra: {
      slotKeys: [
        { item: "a", slot: "one", key: "AAAA" },
        { item: "a", slot: "one", key: "BBBB" },
        { item: "b", slot: "two", key: { key: "CCCC", nonce: "DDDD" } },
      ],
      errors: { slotKeys: [{ item: "c", slot: "one", error: "key_retired" }] },
    },
  };
}

test("composed sections settle with their record fields, and refuse a depth or leafKey", () => {
  assert.deepEqual(settleComposedSections([COMPOSED]), [
    {
      path: ["extra", "slotKeys"],
      fields: ["item", "slot"],
      keyKind: "slotKey",
      errorPath: ["extra", "errors", "slotKeys"],
    },
  ]);
  for (const bad of [
    { ...COMPOSED, fields: [] },
    { ...COMPOSED, fields: ["item", "item"] },
    { ...COMPOSED, fields: ["item", "key"] },
    { ...COMPOSED, fields: ["item", "error"] },
    { ...COMPOSED, fields: ["item", ""] },
    { ...COMPOSED, fields: ["a", "b", "c", "d", "e"] },
    { ...COMPOSED, fields: undefined },
    { ...COMPOSED, depth: 2 },
    { ...COMPOSED, leafKey: "key" },
  ]) {
    assert.throws(() => settleComposedSections([bad]), { code: "bad_config" }, JSON.stringify(bad));
  }
});

test("composed keys yield every record, rivals included, with its path and record", () => {
  const [section] = settleComposedSections([COMPOSED]);
  const walked = [...composedKeys(composedBody(), [section])];

  assert.deepEqual(
    walked.map(({ path, key }) => ({ path, key })),
    [
      { path: ["a", "one"], key: "AAAA" },
      { path: ["a", "one"], key: "BBBB" },
      { path: ["b", "two"], key: { key: "CCCC", nonce: "DDDD" } },
    ],
  );
  assert.deepEqual(walked[2].record, {
    item: "b",
    slot: "two",
    key: { key: "CCCC", nonce: "DDDD" },
  });
});

test("a composed rebuild replaces only each record's key, in array order", async () => {
  const [section] = settleComposedSections([COMPOSED]);
  const original = composedBody();
  const before = structuredClone(original);
  /** @type {string[]} */
  const seen = [];

  const rebuilt = await mapComposedSections(original, [section], async (key, kind) => {
    await Promise.resolve();
    seen.push(JSON.stringify(key));
    return `${kind}:${typeof key === "string" ? key : "wrapped"}`;
  });

  assert.deepEqual(original, before);
  assert.deepEqual(seen, ['"AAAA"', '"BBBB"', '{"key":"CCCC","nonce":"DDDD"}']);
  assert.deepEqual(rebuilt.extra.slotKeys, [
    { item: "a", slot: "one", key: "slotKey:AAAA" },
    { item: "a", slot: "one", key: "slotKey:BBBB" },
    { item: "b", slot: "two", key: "slotKey:wrapped" },
  ]);
  assert.deepEqual(rebuilt.extra.errors, before.extra.errors);
});

test("the client walks a composed section and its error records by their fields", () => {
  const [section] = settleComposedSections([COMPOSED]);
  const body = composedBody();
  body.extra.slotKeys.push(
    /** @type {any} */ ({ item: "d", key: "EEEE" }),
    /** @type {any} */ ("x"),
  );

  const walked = composedSectionEntries(body, section);
  assert.equal(walked.malformed, 2);
  assert.deepEqual(
    walked.entries.map(({ path, value }) => ({ path, value })),
    [
      { path: ["a", "one"], value: "AAAA" },
      { path: ["a", "one"], value: "BBBB" },
      { path: ["b", "two"], value: { key: "CCCC", nonce: "DDDD" } },
    ],
  );
  assert.deepEqual(walked.entries[0].record, { item: "a", slot: "one", key: "AAAA" });

  const errors = composedSectionErrors(body, section);
  assert.deepEqual(errors, {
    present: true,
    entries: [
      {
        path: ["c", "one"],
        value: { item: "c", slot: "one", error: "key_retired" },
        record: { item: "c", slot: "one", error: "key_retired" },
      },
    ],
    malformed: 0,
  });
  assert.equal(
    composedSectionErrors({ extra: { errors: { slotKeys: {} } } }, section).malformed,
    1,
  );
  assert.equal(composedSectionEntries({ extra: {} }, section).present, false);
});

test("a retirement record is error key_retired beside its string coordinate fields only", () => {
  const fields = ["item", "slot"];
  assert.equal(isRetirementLeaf({ item: "c", slot: "one", error: "key_retired" }, fields), true);
  for (const bad of [
    { item: "c", slot: "one", error: "no_grant" },
    { item: "c", slot: "one", error: "key_retired", key: "AAAA" },
    { item: "c", slot: 1, error: "key_retired" },
    { item: "c", error: "key_retired" },
    ["key_retired"],
    null,
  ]) {
    assert.equal(isRetirementLeaf(bad, fields), false, JSON.stringify(bad));
  }
});
