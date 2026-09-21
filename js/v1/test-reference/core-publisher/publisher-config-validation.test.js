// @ts-check

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../core-publisher/Sealer.js";
import { validatePublisherConfig } from "../../core-publisher/publisherConfig.js";

const ORIGIN = "https://publisher.example";

function validConfig() {
  return {
    origin: ORIGIN,
    clock: { now: () => new Date("2025-10-23T14:20:00Z") },
    random: { bytes: (n) => new Uint8Array(n) },
    issuers: [
      {
        issuerName: "issuer-a",
        keyId: "key-a",
        algorithm: "ECDH-P256",
        publicKey: {},
        unlockUrl: "https://issuer.example/unlock",
      },
    ],
    signingKeys: { signing: {} },
    signingKid: "signing",
  };
}

function deepFreeze(value) {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function") ||
    Object.isFrozen(value)
  ) {
    return value;
  }
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function refusal(operation) {
  try {
    operation();
  } catch (error) {
    return { code: error?.code, message: error?.message };
  }
  assert.fail("expected configuration refusal");
}

describe("Publisher configuration can be checked before construction", () => {
  test("the direct validator and Sealer refuse representative config faults identically", () => {
    const base = validConfig();
    const cases = [
      ["origin", { origin: "https://publisher.example/" }],
      ["clock", { clock: undefined }],
      ["random", { random: undefined }],
      ["issuers", { issuers: [] }],
      ["retired periodSecret", { periodSecret: null }],
      ["unknown option", { periodKeySupplies: {} }],
      ["period supply", { periodKeySupply: {} }],
      ["family planner", { periodKeySupply: { derive() {}, familyPlan: true } }],
      ["key sealing", { keySealing: {} }],
      ["signing map", { signingKeys: {} }],
      ["signing selection", { signingKid: "missing" }],
      ["issuer name", { issuers: [{ ...base.issuers[0], issuerName: "bad|name" }] }],
      ["duplicate issuer", { issuers: [base.issuers[0], { ...base.issuers[0] }] }],
      ["issuer kdf", { issuers: [{ ...base.issuers[0], kdf: "hkdf" }] }],
      ["content wrap", { contentKeyWrapStrategy: {} }],
      ["issuer planner", { issuerSupplyPlanFor: {} }],
    ];

    for (const [label, change] of cases) {
      const config = { ...base, ...change };
      assert.deepEqual(
        refusal(() => validatePublisherConfig(/** @type {any} */ (config))),
        refusal(() => new Sealer(/** @type {any} */ (config))),
        label,
      );
    }
  });

  test("an issuer record naming a derivation is refused, not dropped", () => {
    // Sealer forwards no `kdf` to the carrier and keySealing refuses one, so
    // a deployment that still states it would seal raw-secret blobs with no
    // error unless the record is refused here.
    const base = validConfig();
    const config = { ...base, issuers: [{ ...base.issuers[0], kdf: "hkdf" }] };

    assert.deepEqual(
      refusal(() => validatePublisherConfig(/** @type {any} */ (config))),
      {
        code: "unsupported_option",
        message: 'issuer "issuer-a" states kdf, and a sealed blob carries no derivation',
      },
    );
  });

  test("validation reads no operational dependency and does not mutate caller data", () => {
    const calls = { clock: 0, random: 0, derive: 0, seal: 0, wrap: 0, plan: 0 };
    const config = {
      ...validConfig(),
      clock: {
        now: () => {
          calls.clock += 1;
          return new Date();
        },
      },
      random: {
        bytes: (n) => {
          calls.random += 1;
          return new Uint8Array(n);
        },
      },
      periodKeySupply: {
        derive: async () => {
          calls.derive += 1;
          return new Uint8Array(16);
        },
      },
      keySealing: {
        seal: async () => {
          calls.seal += 1;
          return "sealed";
        },
      },
      contentKeyWrapStrategy: {
        aad: () => {
          calls.wrap += 1;
          return undefined;
        },
        entry: (entry) => {
          calls.wrap += 1;
          return entry;
        },
      },
      issuerSupplyPlanFor: () => {
        calls.plan += 1;
        return {};
      },
    };
    deepFreeze(config);

    const validated = validatePublisherConfig(/** @type {any} */ (config));

    assert.deepEqual(calls, { clock: 0, random: 0, derive: 0, seal: 0, wrap: 0, plan: 0 });
    assert.notEqual(validated.issuers, config.issuers);
    assert.notEqual(validated.signingKeys, config.signingKeys);
  });
});
