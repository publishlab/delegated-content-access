// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import * as naiveSealing from "../implementation/naiveSealing.js";
import * as unboundSealing from "../implementation/unboundSealing.js";
import { bindSelfTest, bindFailureClass } from "../../../test-lib/harnesses/bindSelfTest.js";

const vector = JSON.parse(
  readFileSync(
    new URL(
      "../../../../../verification/vectors/v1-alt--bind-on-renderId-and-slot/bind-blobs.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

test("the issuer fixture separates concrete binding mistakes from request tampering", async () => {
  const privateKey = await globalThis.crypto.subtle.importKey(
    "jwk",
    vector.input.ecdh.issuer.privateKeyJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const fixture = {
    renderId: vector.input.renderId,
    contentName: vector.input.contentName,
    blob: vector.expected.ecdh.contentBlob,
    keyBase64url: vector.input.contentKeyBase64url,
  };
  const outcomes = [
    { coordinate: "contentKeys.bodytext", ok: false },
    { coordinate: "contentKeys.premiumtext", ok: false },
  ];

  for (const [label, keySealing] of [
    ["delimiter-less binding", naiveSealing],
    ["unbound carrier", unboundSealing],
  ]) {
    const selfTest = await bindSelfTest({
      fixture,
      privateKey,
      algorithm: "ECDH-P256",
      keySealing,
    });

    assert.equal(selfTest.ok, false, label);
    assert.equal(bindFailureClass(selfTest, outcomes).class, "all-blobs-fail", label);
  }
});
