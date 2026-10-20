import test from "node:test";
import assert from "node:assert/strict";
import { inspect } from "node:util";

import { HandleTable } from "../handles.mjs";
import { decodeValue, encodeValue } from "../serializer.mjs";

/** A class description as a module description carries it. */
const COUNTER = Object.freeze({
  id: "class-1",
  sourceModule: "counter.js",
  sourceExport: "Counter",
  members: Object.freeze([
    Object.freeze({ id: "op-7", sourceMember: "add", callShape: "sync" }),
    Object.freeze({ id: "op-8", sourceMember: "later", callShape: "async" }),
  ]),
});

/**
 * A handle table over the one fixture class. Each member call is recorded
 * with its receiver's tag and answered with `answer`.
 *
 * @param {(member: { id: string }, input: unknown[]) => unknown} [answer]
 */
function fixtureTable(answer = () => 42) {
  /** @type {{ operation: string, receiver: unknown, input: unknown[] }[]} */
  const calls = [];
  const table = new HandleTable({
    classOf: (id) => (id === COUNTER.id ? COUNTER : undefined),
    invoke: (member, receiver, input) => {
      calls.push({ operation: member.id, receiver: table.encode(receiver), input });
      return answer(member, input);
    },
  });
  return { table, calls };
}

const TAG = Object.freeze({ $type: "Handle", class: "class-1", handle: "h-a-1" });

test("a returned handle becomes one proxy per session whose claimed members call the test target", async () => {
  const { table, calls } = fixtureTable();
  const counter = /** @type {any} */ (decodeValue(TAG, table));
  assert.equal(decodeValue({ ...TAG }, table), counter, "the same handle is the same proxy");
  assert.equal(counter.add(2), 42);
  assert.equal(await counter.later(3), 42);
  assert.deepEqual(calls, [
    { operation: "op-7", receiver: TAG, input: [2] },
    { operation: "op-8", receiver: TAG, input: [3] },
  ]);
  assert.equal(counter.add, counter.add, "a member is one function");
  assert.deepEqual(encodeValue({ list: [counter], record: { inner: counter } }, table), {
    list: [TAG],
    record: { inner: TAG },
  });
  const other = decodeValue({ ...TAG, handle: "h-a-2" }, table);
  assert.notEqual(other, counter);
});

test("a proxy claims only what the test target describes and borrows nothing", () => {
  const { table, calls } = fixtureTable();
  const counter = /** @type {any} */ (decodeValue(TAG, table));
  assert.throws(() => counter.count, /counter\.js Counter: the test target claims no member count/);
  assert.throws(() => counter.toObject(), /claims no member toObject/);
  assert.equal(counter.then, undefined, "a proxy is not a promise");
  assert.equal(counter[Symbol.iterator], undefined);
  assert.equal("add" in counter, true);
  assert.equal("count" in counter, false);
  assert.equal(Object.getPrototypeOf(counter), null);
  assert.deepEqual(Object.keys(counter), []);
  assert.throws(() => {
    counter.add = () => 1;
  }, /bridge handles are read-only/);
  assert.throws(() => Object.defineProperty(counter, "count", { value: 1 }), /read-only/);
  assert.throws(() => Object.setPrototypeOf(counter, {}), /read-only/);
  assert.match(inspect(counter), /\[Object: null prototype\] \{\}/);
  assert.deepEqual(calls, []);
});

test("an ordinary record shaped like a handle stays a record", () => {
  const { table } = fixtureTable();
  const counter = decodeValue(TAG, table);
  const lookalike = { $type: "Handle", class: "class-1", handle: "h-a-1" };
  const encoded = encodeValue([lookalike, counter], table);
  assert.deepEqual(encoded, [{ $type: "Record", value: lookalike }, TAG]);
  const decoded = /** @type {unknown[]} */ (decodeValue(encoded, table));
  assert.deepEqual(decoded[0], lookalike);
  assert.equal(decoded[1], counter);
});

test("a handle needs its session: without one, or with an unknown class, it does not decode", () => {
  const { table } = fixtureTable();
  assert.throws(() => decodeValue(TAG), /bridge handle needs its session/);
  assert.throws(
    () => decodeValue({ ...TAG, class: "class-9" }, table),
    /bridge handle names class class-9, which no described module declares/,
  );
  assert.throws(() => decodeValue({ ...TAG, extra: 1 }, table), /exact known shape/);
  assert.throws(() => decodeValue({ $type: "Handle", class: "", handle: "h" }, table), /exact/);
  decodeValue(TAG, table);
  assert.throws(
    () => decodeValue({ ...TAG, class: "class-2" }, table),
    /bridge handle h-a-1 changed its class/,
  );
});

test("a disposed or foreign session's proxy is refused before any call", () => {
  const first = fixtureTable();
  const second = fixtureTable();
  const counter = /** @type {any} */ (decodeValue(TAG, first.table));
  assert.throws(() => encodeValue([counter], second.table), /belongs to another session/);
  assert.throws(() => encodeValue([counter]), /bridge values are JSON data/);
  first.table.dispose();
  assert.throws(() => counter.add(1), /belongs to a disposed session/);
  assert.throws(() => encodeValue([counter], first.table), /disposed session/);
  assert.throws(() => encodeValue([counter], second.table), /disposed session/);
  assert.throws(() => decodeValue(TAG, first.table), /disposed session/);
  assert.deepEqual(first.calls, []);
  assert.deepEqual(second.calls, []);
});
