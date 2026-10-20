// @ts-check
import { test } from "../support/portable-test.js";
import assert from "node:assert/strict";
import { CONTENT_AAD_LIMITS, contentAad } from "../../core-shared--client-publisher/contentAad.js";

/** @param {string} value */
function hex(value) {
  return Uint8Array.from(value.replace(/\s/g, "").match(/../g) ?? [], (x) => parseInt(x, 16));
}

test("AAD is exactly two U32BE length-prefixed UTF-8 coordinates", () => {
  assert.deepEqual(
    contentAad({ renderId: "r-1", contentName: "bodytext" }),
    hex("00000003 722d31 00000008 626f647974657874"),
  );
  assert.deepEqual(
    contentAad({ renderId: "é😀", contentName: "x" }),
    hex("00000006 c3a9f09f9880 00000001 78"),
  );
});
test("the two coordinates cannot alias through concatenation", () => {
  assert.notDeepEqual(
    contentAad({ renderId: "ab", contentName: "c" }),
    contentAad({ renderId: "a", contentName: "bc" }),
  );
});
test("no normalization changes coordinate octets", () => {
  assert.notDeepEqual(
    contentAad({ renderId: "café", contentName: "x" }),
    contentAad({ renderId: "cafe\u0301", contentName: "x" }),
  );
});
test("malformed coordinate strings form no transcript", () => {
  for (const value of [undefined, null, 1, {}, [], "x\ud800", "\udfff"]) {
    assert.equal(
      contentAad(/** @type {any} */ ({ renderId: value, contentName: "bodytext" })),
      null,
    );
    assert.equal(contentAad(/** @type {any} */ ({ renderId: "r-1", contentName: value })), null);
  }
});
test("coordinate limits count UTF-8 octets", () => {
  const { maxValueBytes: n } = CONTENT_AAD_LIMITS;
  assert.ok(Number.isSafeInteger(n) && n > 0);
  for (const name of ["renderId", "contentName"]) {
    const fields = { renderId: "r-1", contentName: "bodytext" };
    assert.ok(contentAad({ ...fields, [name]: "a".repeat(n) }));
    assert.equal(contentAad({ ...fields, [name]: "a".repeat(n + 1) }), null);
    assert.equal(contentAad({ ...fields, [name]: "é".repeat(n / 2 + 1) }), null);
  }
});
