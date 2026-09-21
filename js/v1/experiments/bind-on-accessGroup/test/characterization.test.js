// @ts-check
// Target-local shape checks for the accessGroup-only research implementation.
// These do not define or modify the shared relabel requirement.

import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { bindValue } from "../../_implementation/bind-on-accessGroup/bind.js";
import * as boundSealing from "../../_implementation/bind-on-accessGroup/keySealing.js";
import { unsealSection } from "../../_implementation/bind-on-accessGroup/sealedSection.js";
import { DcaError } from "../../../core-shared/errors.js";

describe("accessGroup-only implementation characterization", () => {
  test('a premium key is bound only to the "premium" accessGroup', () => {
    assert.equal(bindValue({ accessGroup: "premium" }), "premium");
    assert.equal(bindValue({ accessGroup: "free" }), "free");
  });

  test("no binding is refused with binding_failed, the same code as core", async () => {
    await assert.rejects(
      () => boundSealing.seal(new Uint8Array(16), /** @type {any} */ (null), "ECDH-P256", {}),
      (error) => /** @type {DcaError} */ (error).code === "binding_failed",
    );
  });

  test("the wrapper keeps this row's binding and retired-option refusals", async () => {
    await assert.rejects(
      () =>
        boundSealing.seal(new Uint8Array(16), /** @type {any} */ (null), "ECDH-P256", {
          binding: { accessGroup: "premium" },
          bind: "not-a-binding",
        }),
      (error) =>
        error instanceof DcaError &&
        error.code === "unsupported_option" &&
        error.message === "the binding is built from an accessGroup here, not passed as a string",
    );
    await assert.rejects(
      () =>
        boundSealing.seal(new Uint8Array(16), /** @type {any} */ (null), "RSA-OAEP", {
          binding: { accessGroup: "premium" },
          kdf: "none",
        }),
      (error) =>
        error instanceof DcaError &&
        error.code === "unsupported_option" &&
        error.message.startsWith("keySealing applies no KDF"),
    );
  });

  test("a malformed content value names its exact wire coordinate", async () => {
    await assert.rejects(
      () =>
        unsealSection({
          sealed: { contentKeys: { premiumtext: {} } },
          accessGroupOf: { premiumtext: "premium" },
          privateKey: /** @type {any} */ (null),
          algorithm: "ECDH-P256",
          granted: { contentNames: ["premiumtext"] },
        }),
      (error) =>
        error instanceof DcaError &&
        error.code === "binding_failed" &&
        error.message === "the sealed value at contentKeys.premiumtext is not a wire string",
    );
  });

  test("an RSA blob relabelled to another accessGroup keeps this row's refusal", async () => {
    const keys = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      false,
      ["encrypt", "decrypt"],
    );
    const blob = await boundSealing.seal(new Uint8Array(16), keys.publicKey, "RSA-OAEP", {
      binding: { accessGroup: "premium" },
    });

    await assert.rejects(
      () =>
        boundSealing.unseal(blob, keys.privateKey, "RSA-OAEP", {
          binding: { accessGroup: "free" },
        }),
      (error) =>
        error instanceof DcaError &&
        error.code === "unseal_failed" &&
        error.message === "RSA-OAEP unseal failed: the plaintext is not bound to this access tier",
    );
  });
});
