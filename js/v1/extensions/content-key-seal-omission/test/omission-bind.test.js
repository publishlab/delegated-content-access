// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { omissionBindAad, omissionBindValue } from "../core-shared/omissionBind.js";

const BINDING = {
  renderId: "AAECAwQFBgcICQoLDA0ODw",
  contentName: "bodytext",
  accessGroup: "premium",
  t: "251023T14",
};
const TRANSCRIPT = "dca-seal-omission-bind-v1|AAECAwQFBgcICQoLDA0ODw|bodytext|premium|251023T14";

test("the omission binding has one literal transcript and UTF-8 AAD", () => {
  assert.equal(omissionBindValue(BINDING), TRANSCRIPT);
  assert.deepEqual(omissionBindAad(BINDING), new TextEncoder().encode(TRANSCRIPT));
});

for (const [name, binding] of [
  ["a non-object container", null],
  ["an empty field", { ...BINDING, contentName: "" }],
  ["a non-string field", { ...BINDING, accessGroup: 1 }],
  ["a delimiter-bearing field", { ...BINDING, t: "251023|T14" }],
  ["a malformed renderId", { ...BINDING, renderId: "not base64url ***" }],
  ["a noncanonical renderId", { ...BINDING, renderId: "AAECAwQFBgcICQoLDA0ODw=" }],
  ["a 15-byte renderId", { ...BINDING, renderId: "AAECAwQFBgcICQoLDA0O" }],
]) {
  test(`the omission binding refuses ${name}`, () => {
    assert.throws(
      () => omissionBindValue(/** @type {any} */ (binding)),
      (/** @type {any} */ error) => error.code === "binding_failed",
    );
  });
}
