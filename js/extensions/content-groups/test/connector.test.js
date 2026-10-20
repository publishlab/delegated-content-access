import test from "node:test";
import assert from "node:assert/strict";
import { itemPad, xor16 } from "../core-shared/construction.js";

test("the item pad and connector match the independent HMAC transcript", async () => {
  // Independently computed with Python stdlib RFC 5869 HMAC extract/expand.
  const periodKey = Uint8Array.from({ length: 16 }, (_, i) => i);
  const pad = await itemPad(periodKey, {
    renderId: "AAECAwQFBgcICQoLDA0ODw",
    contentName: "bodytext",
  });
  assert.equal(Buffer.from(pad).toString("hex"), "a542731601b70098974ed71b45171cba");
  const contentKey = Uint8Array.from({ length: 16 }, (_, i) => 0xf0 + i);
  const connector = xor16(contentKey, pad);
  assert.equal(Buffer.from(connector).toString("hex"), "55b381e5f542f66f6fb72de0b9eae245");
  assert.deepEqual(xor16(connector, pad), contentKey);
});

test("item pads separate render IDs, item names and input period keys", async () => {
  const periodKey = Uint8Array.from({ length: 16 }, (_, i) => i);
  const context = {
    renderId: "AAECAwQFBgcICQoLDA0ODw",
    contentName: "bodytext",
  };
  const original = await itemPad(periodKey, context);
  assert.notDeepEqual(
    await itemPad(periodKey, { ...context, renderId: "AQECAwQFBgcICQoLDA0ODw" }),
    original,
  );
  assert.notDeepEqual(await itemPad(periodKey, { ...context, contentName: "headline" }), original);
  const otherPeriodKey = periodKey.slice();
  otherPeriodKey[0] ^= 1;
  assert.notDeepEqual(await itemPad(otherPeriodKey, context), original);
});
