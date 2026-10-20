import test from "node:test";
import assert from "node:assert/strict";

import { decodeValue, decodeValueAsync, encodeValue, encodeValueAsync } from "../serializer.mjs";

test("the tagged codec round-trips bytes, undefined, instants, and dense records", () => {
  const input = {
    bytes: new Uint8Array([0, 255]),
    absent: undefined,
    when: new Date("2026-01-02T03:04:05.000Z"),
    list: [false, 4],
  };
  const output = decodeValue(encodeValue(input));
  assert.deepEqual(output.bytes, new Uint8Array([0, 255]));
  assert.equal(output.absent, undefined);
  assert.equal(output.when.toISOString(), "2026-01-02T03:04:05.000Z");
  assert.deepEqual(output.list, [false, 4]);
  assert.deepEqual(encodeValue(undefined), { $type: "undefined" });
  assert.deepEqual(encodeValue(new Uint8Array([0])), { $type: "Uint8Array", base64url: "AA" });
  assert.deepEqual(encodeValue(new Date("2026-01-02T03:04:05.000Z")), {
    $type: "Date",
    iso: "2026-01-02T03:04:05.000Z",
  });
});

test("the reserved type member is escaped for ordinary records", () => {
  const input = { $type: "caller-value", nested: { $type: "another", value: 4 } };
  assert.deepEqual(encodeValue(input), {
    $type: "Record",
    value: {
      $type: "caller-value",
      nested: { $type: "Record", value: { $type: "another", value: 4 } },
    },
  });
  assert.deepEqual(decodeValue(encodeValue(input)), input);
});

test("the codec excludes callbacks, arbitrary instances, cycles, and non-finite values", () => {
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => encodeValue(() => {}), /JSON data/);
  assert.throws(() => encodeValue(new Map()), /JSON data/);
  assert.throws(() => encodeValue(cyclic), /acyclic/);
  assert.throws(() => encodeValue(Infinity), /finite/);
  const sparse = [];
  sparse.length = 2;
  sparse[1] = 1;
  assert.throws(() => encodeValue(sparse), /dense/);
  assert.throws(() => decodeValue({ $type: "Uint8Array", base64url: "AA=" }), /exact known shape/);
  assert.throws(() => decodeValue({ $type: "Callback", callback: "c-1" }), /exact known shape/);
  assert.throws(() => decodeValue({ $type: "Date", iso: "2026-01-02T03:04:05Z" }), /canonical ISO/);
});

test("async serialization exports extractable CryptoKeys with exact metadata", async () => {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const wire = await encodeValueAsync(pair.privateKey);
  assert.deepEqual(Object.keys(wire).sort(), [
    "$type",
    "algorithm",
    "extractable",
    "format",
    "keyType",
    "usages",
    "value",
  ]);
  assert.equal(wire.$type, "CryptoKey");
  assert.equal(wire.keyType, "private");
  assert.deepEqual(wire.algorithm, { name: "ECDH", namedCurve: "P-256" });
  assert.equal(wire.extractable, true);
  assert.deepEqual(wire.usages, ["deriveBits"]);
  assert.equal(wire.format, "jwk");
  const restored = await decodeValueAsync(wire);
  assert.equal(restored.type, "private");
  assert.deepEqual(restored.algorithm, pair.privateKey.algorithm);
  assert.deepEqual([...restored.usages], ["deriveBits"]);
});

test("CryptoKey materialization rejects mismatched metadata and unknown nonextractable keys", async () => {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const wire = await encodeValueAsync(pair.privateKey);
  await assert.rejects(
    () => decodeValueAsync({ ...wire, keyType: "public" }),
    /metadata did not survive import/,
  );
  const protectedPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  await assert.rejects(
    () => encodeValueAsync(protectedPair.privateKey),
    /unknown nonextractable CryptoKey/,
  );
  assert.throws(() => encodeValue(protectedPair.privateKey), /requires an async semantic call/);
});

test("an Array subclass is a runtime object, not a bridge list", async () => {
  class Renders extends Array {}
  const renders = Renders.from([1, 2]);
  assert.throws(() => encodeValue(renders), /bridge lists are plain arrays/);
  assert.throws(() => encodeValue({ nested: [renders] }), /bridge lists are plain arrays/);
  await assert.rejects(() => encodeValueAsync(renders), /bridge lists are plain arrays/);
  assert.deepEqual(encodeValue([1, [2]]), [1, [2]]);
});
