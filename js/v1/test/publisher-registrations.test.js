// @ts-check

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { PublisherRegistrations, openingKeysOver } from "../demo/support/PublisherRegistrations.js";
import { IssuerServer } from "../demo/actors/IssuerServer.js";
import { IssuerKeyStore } from "../demo/support/IssuerKeyStore.js";

const ORIGIN = "https://publisher.example";

function registration(overrides = {}) {
  return {
    kid: "publisher-key-1",
    publicKey: {},
    openingKeys: { get() {} },
    ...overrides,
  };
}

describe("PublisherRegistrations", () => {
  test("one exact kid selects one immutable publisher registration, and onboarding needs no origin", () => {
    const source = registration();
    const registrations = new PublisherRegistrations([source]);
    const selected = registrations.get(source.kid);

    assert.deepEqual(selected, source);
    assert.equal(
      selected.origins,
      undefined,
      "the origin a render is delivered from is the one it signed",
    );
    assert.equal(Object.isFrozen(selected), true);
    assert.equal(registrations.get("publisher-key-2"), undefined);
  });

  test("an origin limit is kept when it is given, and refused when it is not canonical", () => {
    const limited = new PublisherRegistrations([
      registration({ origins: [ORIGIN, "https://amp.publisher.example"] }),
    ]);
    assert.deepEqual(limited.get("publisher-key-1")?.origins, [
      ORIGIN,
      "https://amp.publisher.example",
    ]);

    for (const origins of [
      [],
      "https://publisher.example",
      ["publisher.example"],
      ["https://publisher.example/"],
      ["https://publisher.example/path"],
      [ORIGIN, "HTTPS://publisher.example"],
    ]) {
      assert.throws(
        () => new PublisherRegistrations([registration({ origins })]),
        (/** @type {any} */ error) => error.code === "bad_config",
        `${JSON.stringify(origins)} is not a limit an exact comparison can be made against`,
      );
    }
  });

  test("rejects an ambiguous kid at onboarding", () => {
    assert.throws(
      () =>
        new PublisherRegistrations([
          registration(),
          registration({ origins: ["https://other.example"] }),
        ]),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });
});

describe("openingKeysOver", () => {
  test("a copied co-tenant coordinate misses without reaching the private-key store", () => {
    const keyStore = new IssuerKeyStore([
      {
        issuerName: "issuer-a",
        keyId: "key-a",
        algorithm: "ECDH-P256",
        privateKey: {},
      },
      {
        issuerName: "issuer-b",
        keyId: "key-b",
        algorithm: "ECDH-P256",
        privateKey: {},
      },
    ]);
    const openingKeys = openingKeysOver(keyStore, [{ issuerName: "issuer-a", keyId: "key-a" }]);

    assert.equal(openingKeys.get("issuer-b", "key-b"), undefined);
    assert.equal(keyStore.reachCount, 0);

    assert.equal(openingKeys.get("issuer-a", "key-a")?.algorithm, "ECDH-P256");
    assert.equal(keyStore.reachCount, 1);
  });

  test("a co-tenant cannot address another registration's real key, and its rotation stays scoped", () => {
    const keyStore = new IssuerKeyStore([
      {
        issuerName: "issuer-a",
        keyId: "key-a",
        algorithm: "ECDH-P256",
        privateKey: {},
      },
      {
        issuerName: "issuer-a",
        keyId: "key-b",
        algorithm: "ECDH-P256",
        privateKey: {},
      },
      {
        issuerName: "issuer-a",
        keyId: "key-a-next",
        algorithm: "ECDH-P256",
        privateKey: {},
      },
    ]);
    const aKeys = openingKeysOver(keyStore, [{ issuerName: "issuer-a", keyId: "key-a" }]);
    const bKeys = openingKeysOver(keyStore, [{ issuerName: "issuer-a", keyId: "key-b" }]);
    const registrations = new PublisherRegistrations([
      registration({ kid: "publisher-a", openingKeys: aKeys }),
      registration({ kid: "publisher-b", openingKeys: bKeys }),
    ]);

    assert.equal(registrations.get("publisher-a")?.openingKeys.get("issuer-a", "key-b"), undefined);
    assert.equal(keyStore.reachCount, 0);

    registrations.addOpeningKey("issuer-a", "key-a-next", "key-a");
    assert.equal(aKeys.get("issuer-a", "key-a-next")?.algorithm, "ECDH-P256");
    assert.equal(keyStore.reachCount, 1);
    assert.equal(bKeys.get("issuer-a", "key-a-next"), undefined);
    assert.equal(
      keyStore.reachCount,
      1,
      "B never reaches the underlying store for A's rotated key",
    );

    assert.throws(
      () => registrations.prepareOpeningKeyRotation("issuer-a", "key-server-wide"),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });
});

describe("IssuerServer rotation ordering", () => {
  test("a registration rotation refusal leaves the key store unchanged", () => {
    let rotations = 0;
    const server = new IssuerServer({
      clock: { now: () => new Date() },
      network: { serve() {} },
      issuerName: "issuer-a",
      unlockUrl: "https://unlock.example",
      keyStore: {
        get() {},
        rotate() {
          rotations++;
        },
      },
      publisherRegistrations: {
        get() {},
        prepareOpeningKeyRotation() {
          throw new Error("cannot extend registrations");
        },
      },
      accessPolicy: { decide() {} },
    });

    assert.throws(
      () => server.rotateKey("key-next", { algorithm: "ECDH-P256", privateKey: {} }),
      /cannot extend registrations/,
    );
    assert.equal(rotations, 0);
  });
});
