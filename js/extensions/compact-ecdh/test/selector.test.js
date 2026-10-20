// @ts-check
//
// The `envelope` selector of docs/spec-profile--compact-ecdh.md Section 3.1.
// An omitted member means the key's ordinary procedure, when the issuer's
// configuration permits it; the one defined value selects compact ECDH; every
// other present value is refused, never read as omission.

import test from "node:test";
import assert from "node:assert/strict";

import {
  COMPACT_ECDH,
  ENVELOPE_MEMBER,
  readEnvelopeSelector,
} from "../core-shared--publisher-issuer/selector.js";

test("the selector literal and member name are the spec's", () => {
  assert.equal(COMPACT_ECDH, "compact-ecdh");
  assert.equal(ENVELOPE_MEMBER, "envelope");
});

test("an absent member reads as omitted", () => {
  assert.equal(readEnvelopeSelector({ keyId: "issuer-key-A" }), "omitted");
});

test("the defined value reads as compact", () => {
  assert.equal(readEnvelopeSelector({ envelope: "compact-ecdh" }), "compact");
});

test("a present malformed or unknown value reads as refuse", () => {
  for (const value of [
    null,
    undefined,
    "",
    "ecdh-p256",
    "default",
    "Compact-ECDH",
    "compact-ecdh ",
    0,
    false,
    true,
    {},
    ["compact-ecdh"],
  ]) {
    assert.equal(
      readEnvelopeSelector({ envelope: value }),
      "refuse",
      `envelope ${JSON.stringify(value)}`,
    );
  }
});

test("only an own member counts: an inherited one is absent", () => {
  const block = Object.create({ envelope: "compact-ecdh" });
  assert.equal(readEnvelopeSelector(block), "omitted");
});

test("a carrier that is not a record reads as refuse", () => {
  for (const carrier of [null, undefined, "compact-ecdh", 7, ["compact-ecdh"]]) {
    assert.equal(readEnvelopeSelector(carrier), "refuse", `carrier ${JSON.stringify(carrier)}`);
  }
});
