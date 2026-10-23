// @ts-check

// Direct adapter coverage. The server composition is exercised separately by
// the actor target; this file pins the KeyDelivery preflight/prepare boundary
// without routing through that actor.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { KeyDelivery } from "../../../adapter-issuer/KeyDelivery.js";
import * as ecdhProfile from "../ecdhP256.js";
import * as rsaProfile from "../rsaOaep.js";
import { clientBoundKeyCapability } from "../core-client/clientBoundKeyCapability.js";
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
    const body = { keys: { contentKeys: [{ contentName: "news/a", key: raw }] } };
    const finalBody = await delivery.prepare(body, view);

    assert.equal(Object.hasOwn(finalBody.transport, "mode"), false);
    const [record] = finalBody.keys.contentKeys;
    assert.equal(record.contentName, "news/a");
    const delivered = record.key;
    assert.deepEqual(Object.keys(delivered).sort(), ["key", "nonce"]);
    assert.notEqual(delivered.key, raw);
    assert.equal(JSON.stringify(finalBody).includes(raw), false);
  });

  test("writes the selected transport method after the profile payload", async () => {
    const profile = {
      METHOD: "test-profile",
      async seal() {
        return {
          transport: { method: "another-profile", profileValue: true },
          async wrap(bytes) {
            return { key: base64urlEncode(bytes) };
          },
        };
      },
    };
    const delivery = new KeyDelivery({ profile });
    const view = await delivery.preflight("client-bound", new DcaRequest({ clientPublicKey: {} }));
    const body = await delivery.prepare(
      {
        keys: {
          contentKeys: [{ contentName: "premium", key: base64urlEncode(new Uint8Array(16)) }],
        },
      },
      view,
    );

    assert.deepEqual(
      body.transport,
      {
        method: "test-profile",
        profileValue: true,
      },
      "profile data may add payload fields but cannot replace the envelope fields",
    );
  });

  test("rejects malformed client-bound delivered key entries before any raw value can reach its wrapper", async () => {
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
        { keys: { contentKeys: [{ contentName: "news/a", key: { raw: "must-not-leak" } }] } },
        "client-bound delivery needs string key entries",
      ],
      [
        { keys: { periodKeys: { premium: "must-not-leak" } } },
        "client-bound delivery needs key record arrays",
      ],
      [
        { keys: { periodKeys: ["must-not-leak"] } },
        "client-bound delivery needs key records with their coordinate fields",
      ],
      [
        // The record names no period, so it has no coordinate a client
        // could bind; its key must not leave raw beside wrapped siblings.
        { keys: { periodKeys: [{ accessGroup: "premium", key: "must-not-leak" }] } },
        "client-bound delivery needs key records with their coordinate fields",
      ],
      [
        {
          keys: {
            contentKeys: [{ contentName: "news/a", key: base64urlEncode(new Uint8Array(32)) }],
          },
        },
        "client-bound delivery needs 16-byte contentKey values",
      ],
      [
        {
          keys: {
            periodKeys: [
              {
                accessGroup: "premium",
                period: "251023T1700",
                key: base64urlEncode(new Uint8Array(32)),
              },
            ],
          },
        },
        "client-bound delivery needs 16-byte periodKey values",
      ],
      [
        {
          keys: {
            chainKeys: [
              {
                accessGroup: "premium",
                cutoff: "251023T1700",
                key: base64urlEncode(new Uint8Array(17)),
              },
            ],
          },
        },
        "client-bound delivery needs 16-byte chainKey values",
      ],
      [
        // The standard alphabet spells `-` as `+` and `_` as `/`, so
        // this key entry decodes to the same 16 bytes the canonical spelling
        // does. It is admitted or refused on its spelling alone, and a
        // wrapper that saw it would re-wrap bytes the response is not
        // allowed to have carried.
        {
          keys: {
            contentKeys: [
              {
                contentName: "news/a",
                key: base64urlEncode(new Uint8Array(16).fill(0xfb))
                  .replace(/-/g, "+")
                  .replace(/_/g, "/"),
              },
            ],
          },
        },
        "client-bound delivery needs canonical base64url key entries",
      ],
    ]) {
      await assert.rejects(
        () => delivery.prepare(body, view),
        (/** @type {any} */ error) => error.code === "bad_config" && error.message === message,
      );
    }
    assert.equal(wraps, 0, "no malformed keys shape reaches the wrapper");
  });

  for (const profile of [ecdhProfile, rsaProfile]) {
    test(`${profile.METHOD} opens all three delivered key kinds under one selected transport`, async () => {
      const pair = /** @type {CryptoKeyPair} */ (
        await globalThis.crypto.subtle.generateKey(
          profile === ecdhProfile
            ? { name: "ECDH", namedCurve: "P-256" }
            : {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
              },
          false,
          profile === ecdhProfile ? ["deriveKey"] : ["unwrapKey", "decrypt"],
        )
      );
      const exported = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
      if (profile === ecdhProfile) {
        exported.ext = false;
        exported.key_ops = ["verify"];
      } else {
        exported.alg = "RSA-OAEP-256";
        exported.use = "enc";
        exported.ext = false;
        exported.key_ops = ["wrapKey"];
      }
      const capability = clientBoundKeyCapability(
        {
          privateKey: pair.privateKey,
          publicKey: exported,
        },
        profile,
      );
      if (profile === ecdhProfile) {
        assert.deepEqual(Object.keys(capability.publicKey).sort(), ["crv", "kty", "x", "y"]);
        assert.equal(capability.publicKey.x, exported.x);
        assert.equal(capability.publicKey.y, exported.y);
      } else {
        assert.equal(capability.publicKey.alg, "RSA-OAEP-256");
        assert.equal(capability.publicKey.use, "enc");
        assert.equal(capability.publicKey.ext, false);
        assert.deepEqual(capability.publicKey.key_ops, ["wrapKey"]);
      }
      const delivery = new KeyDelivery({ random, profile });
      const request = new DcaRequest({ clientPublicKey: capability.publicKey });
      if (profile === ecdhProfile) {
        assert.deepEqual(Object.keys(request.clientPublicKey).sort(), ["crv", "kty", "x", "y"]);
      }
      const view = await delivery.preflight("client-bound", request);
      const raw = [3, 4, 5].map((value) => new Uint8Array(16).fill(value));
      const geometry = { chainsPerDay: 2, periodMinutes: 15 };
      const prepared = await delivery.prepare(
        {
          keys: {
            contentKeys: [{ contentName: "bodytext", key: base64urlEncode(raw[0]) }],
            periodKeys: [
              { accessGroup: "premium", period: "251023T1700", key: base64urlEncode(raw[1]) },
            ],
            chainKeys: [
              { accessGroup: "premium", cutoff: "251023T1700", key: base64urlEncode(raw[2]) },
            ],
          },
          periodGeometry: geometry,
        },
        view,
      );
      assert.equal(Object.hasOwn(prepared.transport, "mode"), false);
      assert.equal(prepared.transport.method, profile.METHOD);
      assert.deepEqual(prepared.periodGeometry, geometry);
      const opener = await capability.openDeliveredKeys(prepared.transport);
      // Each record keeps its coordinate fields; only its `key` became the
      // client-bound carrier, so the opener reads `record.key`.
      assert.deepEqual(
        [prepared.keys.periodKeys[0].accessGroup, prepared.keys.periodKeys[0].period],
        ["premium", "251023T1700"],
      );
      assert.equal(prepared.keys.chainKeys[0].cutoff, "251023T1700");
      const content = await opener.open(
        prepared.keys.contentKeys[0].key,
        ["decrypt"],
        "contentKey",
      );
      const period = await opener.open(prepared.keys.periodKeys[0].key, ["unwrapKey"], "periodKey");
      const chain = await opener.open(prepared.keys.chainKeys[0].key, [], "chainKey");
      for (const handle of [content, period]) {
        assert.ok(handle instanceof globalThis.CryptoKey);
        assert.equal(handle.extractable, false);
      }
      assert.deepEqual(chain, raw[2]);
      // Prove the opaque handles contain the intended bytes, including that
      // content-key and period-key entries were not interchanged while mapping sections.
      const iv = new Uint8Array(12);
      const ciphertext = await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        await globalThis.crypto.subtle.importKey("raw", raw[0], "AES-GCM", false, ["encrypt"]),
        raw[2],
      );
      assert.deepEqual(
        new Uint8Array(
          await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv }, content, ciphertext),
        ),
        raw[2],
      );
      const wrapped = await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        await globalThis.crypto.subtle.importKey("raw", raw[1], "AES-GCM", false, ["encrypt"]),
        raw[0],
      );
      const recovered = await globalThis.crypto.subtle.unwrapKey(
        "raw",
        wrapped,
        period,
        { name: "AES-GCM", iv },
        "AES-GCM",
        false,
        ["decrypt"],
      );
      assert.deepEqual(
        new Uint8Array(
          await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv }, recovered, ciphertext),
        ),
        raw[2],
      );
    });
  }

  test("wrapping key entries preserves the not-delivered family report unchanged", async () => {
    const delivery = new KeyDelivery({ random, profile: ecdhProfile });
    const view = await delivery.preflight(
      "client-bound",
      new DcaRequest({ clientPublicKey: await clientPublicKey() }),
    );
    const notDelivered = [
      { accessGroup: "premium", reason: "denied" },
      { accessGroup: "archive", reason: "unavailable" },
    ];
    const errors = [
      {
        coordinate: "summary",
        error: "unseal_failed",
        message: "sealed value could not be opened",
      },
    ];
    const prepared = await delivery.prepare(
      {
        keys: {
          contentKeys: [
            { contentName: "bodytext", key: base64urlEncode(new Uint8Array(16).fill(3)) },
          ],
        },
        errors,
        notDelivered,
      },
      view,
    );
    assert.equal(Object.hasOwn(prepared.transport, "mode"), false);
    assert.deepEqual(Object.keys(prepared.keys.contentKeys[0].key).sort(), ["key", "nonce"]);
    assert.deepEqual(prepared.errors, errors);
    assert.deepEqual(prepared.notDelivered, notDelivered);

    // The no-key result keeps its report too.
    const noKey = await delivery.prepare({ keys: { contentKeys: [] }, notDelivered }, view);
    assert.deepEqual(noKey.notDelivered, notDelivered);
  });

  test("rival records at one coordinate are each wrapped and keep their order", async () => {
    const delivery = new KeyDelivery({ random, profile: ecdhProfile });
    const view = await delivery.preflight(
      "client-bound",
      new DcaRequest({ clientPublicKey: await clientPublicKey() }),
    );
    const rivals = [5, 6].map((fill) => base64urlEncode(new Uint8Array(16).fill(fill)));
    const prepared = await delivery.prepare(
      {
        keys: {
          contentKeys: rivals.map((key) => ({ contentName: "bodytext", key })),
          periodKeys: rivals.map((key) => ({ accessGroup: "premium", period: "251023T1700", key })),
        },
      },
      view,
    );
    for (const section of ["contentKeys", "periodKeys"]) {
      assert.equal(prepared.keys[section].length, 2, section);
      const [first, second] = prepared.keys[section];
      assert.notDeepEqual(first.key, second.key, `${section} keeps two distinct carriers`);
      assert.equal(JSON.stringify(prepared).includes(rivals[0]), false);
    }
  });

  test("an unknown option is refused", () => {
    assert.throws(
      () =>
        new KeyDelivery({
          random,
          profile: ecdhProfile,
          inventedSelector: "dca-profile-period-keys-invented",
        }),
      (error) => error.code === "unsupported_option",
    );
  });

  test("rejects malformed chain-key entries before a client-bound wrapper sees bytes", async () => {
    const delivery = new KeyDelivery({ random, profile: ecdhProfile });
    const view = await delivery.preflight(
      "client-bound",
      new DcaRequest({ clientPublicKey: await clientPublicKey() }),
    );

    await assert.rejects(() =>
      delivery.prepare(
        {
          keys: {
            chainKeys: [
              {
                accessGroup: "premium",
                cutoff: "251023T1700",
                key: base64urlEncode(new Uint8Array(17)),
              },
            ],
          },
        },
        view,
      ),
    );
  });
});
