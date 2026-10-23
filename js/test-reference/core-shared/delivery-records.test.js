// @ts-check
import { test } from "../support/portable-test.js";
import assert from "node:assert/strict";
import { recordsByName } from "../../core-shared--client-publisher/deliveryRecords.js";
import { isContentName } from "../../core-shared/names.js";

test("records resolve by their identity field, whatever their array position", () => {
  const a = { contentName: "a", contentType: "text/plain" };
  const b = { contentName: "b", contentType: "text/html" };
  for (const collection of [
    [a, b],
    [b, a],
  ]) {
    const records = recordsByName(collection, "contentName", isContentName);
    assert.ok(records);
    assert.equal(records.get("a"), a);
    assert.equal(records.get("b"), b);
    assert.equal(records.size, 2);
  }
});

test("the last whole record for one identity replaces the earlier one and nothing merges", () => {
  const first = { issuerName: "x", keyId: "k1", envelope: "e1", sealed: { contentKeys: {} } };
  const last = { issuerName: "x", keyId: "k2", sealed: {} };
  const forward = recordsByName([first, last], "issuerName", () => true);
  assert.equal(forward?.get("x"), last);
  assert.equal(Object.hasOwn(/** @type {any} */ (forward?.get("x")), "envelope"), false);
  const reversed = recordsByName([last, first], "issuerName", () => true);
  assert.equal(reversed?.get("x"), first);
});

test("a name such as __proto__ or constructor is an ordinary identity", () => {
  const records = recordsByName(
    [
      { contentName: "constructor", v: 1 },
      { contentName: "__proto__", v: 2 },
    ],
    "contentName",
    () => true,
  );
  assert.equal(records?.get("constructor")?.v, 1);
  assert.equal(records?.get("__proto__")?.v, 2);
  assert.equal(recordsByName([], "contentName", () => true)?.get("constructor"), undefined);
});

test("an element that is not a record supplies nothing, and its siblings stay", () => {
  const good = { contentName: "a" };
  for (const element of [null, 7, "a", ["a"], [good]]) {
    for (const collection of [
      [good, element],
      [element, good],
    ]) {
      const records = recordsByName(collection, "contentName", isContentName);
      assert.ok(records, JSON.stringify(collection));
      assert.deepEqual([...records.keys()], ["a"]);
      assert.equal(records.get("a"), good);
    }
  }
});

test("the collection is refused whole for a non-array or a bad identity", () => {
  const good = { contentName: "a" };
  for (const collection of [
    undefined,
    null,
    "a",
    { a: good },
    [good, {}],
    [good, { contentName: 7 }],
    [good, { contentName: "bad name" }],
  ]) {
    assert.equal(recordsByName(collection, "contentName", isContentName), null);
  }
});

test("an inherited identity member does not count", () => {
  const inherited = Object.create({ contentName: "a" });
  assert.equal(
    recordsByName([inherited], "contentName", () => true),
    null,
  );
});
