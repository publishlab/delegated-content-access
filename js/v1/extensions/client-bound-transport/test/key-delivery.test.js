// @ts-check

// Direct adapter coverage. The server composition is exercised separately by
// the actor target; this file pins the KeyDelivery preflight/prepare boundary
// without routing through that actor.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { KeyDelivery } from "../../../adapter-issuer/KeyDelivery.js";
import * as ecdhProfile from "../ecdhP256.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlEncode } from "../../../core-shared/codec.js";

const random = { bytes: (length) => new Uint8Array(length).fill(1) };

describe("KeyDelivery", () => {
  // A client's public half, in the JWK shape a request carries it.
  async function clientPublicKey() {
    const pair = /** @type {CryptoKeyPair} */ (
      await globalThis.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
        "deriveBits",
      ])
    );
    return globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
  }

  test("direct needs no extension, while an injected client-bound profile has the surface it calls", async () => {
    const directOnly = new KeyDelivery();
    await assert.rejects(
      () => directOnly.preflight("client-bound", new DcaRequest({ clientPublicKey: {} })),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    for (const profile of [
      {},
      { METHOD: "ECDH-P256" },
      { seal: async () => ({}) },
      { METHOD: 42, seal: async () => ({}) },
    ]) {
      assert.throws(
        () => new KeyDelivery(/** @type {any} */ ({ profile })),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
    assert.doesNotThrow(() => new KeyDelivery({ profile: ecdhProfile }));
    assert.doesNotThrow(
      () =>
        new KeyDelivery({
          profile: {
            METHOD: "seal-only-profile/v1",
            async seal() {
              return {};
            },
          },
        }),
      "KeyDelivery does not require the client capability's validator hook",
    );
  });

  test("agrees client-bound delivery before it runs, and never downgrades a missing key", async () => {
    const delivery = new KeyDelivery({ random, profile: ecdhProfile });

    await assert.rejects(
      () => delivery.preflight("client-bound", new DcaRequest({})),
      (/** @type {any} */ error) => error.code === "client_key_required",
    );
    await assert.rejects(
      () =>
        delivery.preflight(
          "client-bound",
          new DcaRequest({ clientPublicKey: { kty: "not-a-key" } }),
        ),
      (/** @type {any} */ error) => error.code === "bad_client_key",
    );
    const direct = await delivery.preflight("direct", new DcaRequest({}));
    assert.equal(direct.mode, "direct");
    assert.equal(direct.isDirect(), true);
    await assert.rejects(
      () => delivery.preflight("direct", /** @type {any} */ ({})),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    await assert.rejects(
      () => delivery.preflight(/** @type {any} */ ("sealed-envelope"), new DcaRequest({})),
      (/** @type {any} */ error) => error.code === "unsupported_option",
    );
  });

  // The old seam took the mode again at prepare time, allowing a caller that
  // had agreed client-bound to request a direct body. The mode now sits in
  // the opaque view, so prepare cannot be asked to disagree with preflight.
  test("a client-bound view has no path to a raw-bytes body", async () => {
    const delivery = new KeyDelivery({ random, profile: ecdhProfile });
    const request = new DcaRequest({ clientPublicKey: await clientPublicKey() });

    const view = await delivery.preflight("client-bound", request);
    assert.equal(view.mode, "client-bound");
    assert.equal(view.isDirect(), false);

    const raw = base64urlEncode(new Uint8Array(16).fill(7));
    const body = { keys: { contentKeys: { "news/a": raw } } };
    const finalBody = await delivery.prepare(body, view);

    assert.equal(finalBody.transport.mode, "client-bound");
    const delivered = finalBody.keys.contentKeys["news/a"];
    assert.deepEqual(Object.keys(delivered).sort(), ["key", "nonce"]);
    assert.notEqual(delivered.key, raw);
    assert.equal(JSON.stringify(finalBody).includes(raw), false);
  });

  test("writes the outer transport mode and method after the selected profile payload", async () => {
    const profile = {
      METHOD: "test-profile",
      async seal() {
        return {
          transport: { mode: "direct", method: "another-profile", profileValue: true },
          async wrap(bytes) {
            return { key: base64urlEncode(bytes) };
          },
        };
      },
    };
    const delivery = new KeyDelivery({ profile });
    const view = await delivery.preflight("client-bound", new DcaRequest({ clientPublicKey: {} }));
    const body = await delivery.prepare(
      { keys: { contentKeys: { premium: base64urlEncode(new Uint8Array(16)) } } },
      view,
    );

    assert.deepEqual(
      body.transport,
      {
        mode: "client-bound",
        method: "test-profile",
        profileValue: true,
      },
      "profile data may add payload fields but cannot replace the envelope fields",
    );
  });

  test("rejects malformed client-bound delivered leaves before any raw value can reach its wrapper", async () => {
    let wraps = 0;
    const delivery = new KeyDelivery({
      profile: {
        METHOD: "counting-test-profile",
        async seal() {
          return {
            transport: {},
            async wrap() {
              wraps++;
              return { key: "wrapped" };
            },
          };
        },
      },
    });
    const view = await delivery.preflight("client-bound", new DcaRequest({ clientPublicKey: {} }));

    for (const [body, message] of [
      [{ keys: "AAAA" }, "client-bound delivery needs a keys object"],
      [
        { keys: { contentKeys: { "news/a": { raw: "must-not-leak" } } } },
        "client-bound delivery needs string key leaves",
      ],
      [
        { keys: { periodKeys: { premium: "must-not-leak" } } },
        "client-bound delivery needs correctly nested key sections",
      ],
      [
        { keys: { contentKeys: { "news/a": base64urlEncode(new Uint8Array(32)) } } },
        "client-bound delivery needs 16-byte contentKey leaves",
      ],
      [
        { keys: { periodKeys: { premium: { "251023T17": base64urlEncode(new Uint8Array(32)) } } } },
        "client-bound delivery needs 16-byte periodKey leaves",
      ],
      [
        // The standard alphabet spells `-` as `+` and `_` as `/`, so
        // this leaf decodes to the same 16 bytes the canonical spelling
        // does. It is admitted or refused on its spelling alone, and a
        // wrapper that saw it would re-wrap bytes the response is not
        // allowed to have carried.
        {
          keys: {
            contentKeys: {
              "news/a": base64urlEncode(new Uint8Array(16).fill(0xfb))
                .replace(/-/g, "+")
                .replace(/_/g, "/"),
            },
          },
        },
        "client-bound delivery needs canonical base64url key leaves",
      ],
    ]) {
      await assert.rejects(
        () => delivery.prepare(body, view),
        (/** @type {any} */ error) => error.code === "bad_config" && error.message === message,
      );
    }
    assert.equal(wraps, 0, "no malformed keys shape reaches the wrapper");
  });

  test("permits canonical content and exact-period keys under client-bound", async () => {
    const delivery = new KeyDelivery({ random, profile: ecdhProfile });
    const view = await delivery.preflight(
      "client-bound",
      new DcaRequest({ clientPublicKey: await clientPublicKey() }),
    );
    const body = {
      keys: {
        contentKeys: { bodytext: base64urlEncode(new Uint8Array(16).fill(3)) },
        periodKeys: { premium: { "251023T17": base64urlEncode(new Uint8Array(16).fill(4)) } },
      },
    };
    const prepared = await delivery.prepare(body, view);
    assert.equal(prepared.transport.mode, "client-bound");
  });

  test("the removed exact-profile selector is refused", () => {
    assert.throws(
      () => new KeyDelivery({ random, profile: ecdhProfile, exactProfile: "dca-v1-exact-period" }),
      (error) => error.code === "unsupported_option",
    );
  });

  test("refuses chain grants under client-bound until a byte-free expansion profile is selected", async () => {
    const delivery = new KeyDelivery({ random, profile: ecdhProfile });
    const view = await delivery.preflight(
      "client-bound",
      new DcaRequest({ clientPublicKey: await clientPublicKey() }),
    );

    await assert.rejects(
      () =>
        delivery.prepare(
          {
            keys: {
              periodChainKeys: { premium: { "251023T17": base64urlEncode(new Uint8Array(16)) } },
            },
          },
          view,
        ),
      (/** @type {any} */ error) =>
        error.code === "unsupported_option" && /byte-free expansion profile/.test(error.message),
    );
  });
});
