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
        algorithm: "ecdh-p256",
        publicKey: {},
      },
    ],
    signingKeys: { signing: {} },
    signingKid: "signing",
    issuerSupplyPlanFor: () => ({ contentKeyNames: [], suppliedAccessGroups: [] }),
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
      ["issuer keyId", { issuers: [{ ...base.issuers[0], keyId: null }] }],
      ["issuer empty keyId", { issuers: [{ ...base.issuers[0], keyId: "" }] }],
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

  test("an issuer record without a string keyId is refused at construction", () => {
    // docs/spec--data-format.md, 4.2: a producer identifies its opening key. A
    // record that lacks it would otherwise construct and later serialize an
    // issuer block no client can use.
    const base = validConfig();
    const { keyId: _keyId, ...withoutKeyId } = base.issuers[0];
    const cases = [
      ["missing keyId", withoutKeyId, /issuer "issuer-a" needs a string keyId/],
      ...[42, null, {}, ["https://issuer.example/unlock"], new String("x")].flatMap((value) => [
        [
          `keyId ${JSON.stringify(value)}`,
          { ...base.issuers[0], keyId: value },
          /issuer "issuer-a" needs a string keyId/,
        ],
      ]),
    ];

    for (const [label, issuer, message] of cases) {
      const config = { ...base, issuers: [issuer] };
      for (const construct of [
        () => validatePublisherConfig(/** @type {any} */ (config)),
        () => new Sealer(/** @type {any} */ (config)),
      ]) {
        const refused = refusal(construct);
        assert.equal(refused.code, "bad_config", /** @type {string} */ (label));
        assert.match(
          refused.message,
          /** @type {RegExp} */ (message),
          /** @type {string} */ (label),
        );
      }
    }
  });

  test("an issuer record with an empty keyId is refused at construction", () => {
    // docs/spec--core-protocol.md, section 9: a usable issuer route carries a
    // non-empty keyId, and every configured issuer here is such a route.
    const base = validConfig();
    const config = { ...base, issuers: [{ ...base.issuers[0], keyId: "" }] };

    for (const construct of [
      () => validatePublisherConfig(/** @type {any} */ (config)),
      () => new Sealer(/** @type {any} */ (config)),
    ]) {
      assert.deepEqual(refusal(construct), {
        code: "bad_config",
        message: 'issuer "issuer-a" needs a nonempty keyId',
      });
    }
  });

  test("a one-character keyId needs no endpoint configuration", () => {
    // Endpoints belong to client integration, not publisher configuration.
    const base = validConfig();
    for (const change of [{ keyId: "k" }]) {
      const issuer = { ...base.issuers[0], ...change };
      const config = { ...base, issuers: [issuer] };
      const validated = validatePublisherConfig(/** @type {any} */ (config));
      assert.equal(validated.issuers[0].keyId, issuer.keyId);
      assert.doesNotThrow(() => new Sealer(/** @type {any} */ (config)));
    }
  });

  test("string issuer fields and extra issuer metadata are admitted as given", () => {
    const base = validConfig();
    const issuer = {
      ...base.issuers[0],
      keyId: "2025-10",
      displayName: "Issuer A",
    };

    const validated = validatePublisherConfig(/** @type {any} */ ({ ...base, issuers: [issuer] }));
    assert.equal(validated.issuers[0].keyId, issuer.keyId);
    assert.equal(validated.issuers[0].displayName, issuer.displayName);
    assert.doesNotThrow(() => new Sealer(/** @type {any} */ ({ ...base, issuers: [issuer] })));
  });

  test("an unknown option is refused", () => {
    // The Sealer reads only derive and familyPlan from a supply, so any other
    // member would seal as if this build had honored it.
    const config = {
      ...validConfig(),
      periodKeySupply: {
        inventedSelector: "dca-profile-period-keys-invented",
        derive: async () => new Uint8Array(16),
      },
    };

    assert.deepEqual(
      refusal(() => validatePublisherConfig(/** @type {any} */ (config))),
      {
        code: "unsupported_option",
        message: "periodKeySupply has no inventedSelector yet, and will not pretend to",
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

describe("The signing selection and the period are checked as supplied", () => {
  test("a signingKid that is not a nonempty string is refused before key lookup", () => {
    // docs/spec--core-protocol.md, 4.1: the resourceJWT kid is a nonempty
    // string. Object.hasOwn would find { 2024: key } under the number 2024 and
    // the header would carry "kid":2024.
    const base = validConfig();
    for (const [label, change] of /** @type {const} */ ([
      ["numeric kid", { signingKeys: { 2024: {} }, signingKid: 2024 }],
      ["empty sole key name", { signingKeys: { "": {} }, signingKid: undefined }],
      ["empty kid", { signingKeys: { "": {} }, signingKid: "" }],
      ["object kid", { signingKid: { toString: () => "signing" } }],
    ])) {
      const config = { ...base, ...change };
      for (const construct of [
        () => validatePublisherConfig(/** @type {any} */ (config)),
        () => new Sealer(/** @type {any} */ (config)),
      ]) {
        assert.deepEqual(
          refusal(construct),
          { code: "bad_config", message: "the Sealer's signingKid is a nonempty string" },
          label,
        );
      }
    }
  });

  test("the selected own signing key reaches the runtime view, enumerable or not", () => {
    const base = validConfig();
    const key = {};
    const held = { other: {} };
    Object.defineProperty(held, "signing", { value: key, enumerable: false });
    const validated = validatePublisherConfig(
      /** @type {any} */ ({ ...base, signingKeys: held, signingKid: "signing" }),
    );
    assert.equal(validated.signingKeys.signing, key);
    assert.equal(validated.signingKeys.other, held.other);
    // An inherited entry is still not a held key.
    const inherited = Object.create({ signing: key });
    inherited.other = {};
    assert.deepEqual(
      refusal(() =>
        validatePublisherConfig(
          /** @type {any} */ ({ ...base, signingKeys: inherited, signingKid: "signing" }),
        ),
      ),
      { code: "bad_config", message: 'Sealer holds no signing key "signing"' },
    );
  });

  test("a supplied period that is not the documented options record is refused", () => {
    // A period the Sealer cannot read used to spread to {} and select hourly
    // periods, a wider key reach than the publisher chose.
    const base = validConfig();
    const cases = [
      ["a number", 15, "bad_config", "period is an options object with length and slots"],
      ["null", null, "bad_config", "period is an options object with length and slots"],
      ["a string", "hourly", "bad_config", "period is an options object with length and slots"],
      ["a list", [15], "bad_config", "period is an options object with length and slots"],
      [
        "the chain geometry spelling",
        { periodMinutes: 15 },
        "unsupported_option",
        "period has no periodMinutes yet, and will not pretend to",
      ],
      [
        "a misspelt length",
        { lenght: 15, slots: 2 },
        "unsupported_option",
        "period has no lenght yet, and will not pretend to",
      ],
      [
        "a misspelt length the host keeps non-enumerable",
        Object.defineProperty({ slots: 2 }, "lenght", { value: 15, enumerable: false }),
        "unsupported_option",
        "period has no lenght yet, and will not pretend to",
      ],
      [
        "zero length",
        { length: 0 },
        "bad_config",
        "period length must be a positive whole number of minutes, got 0",
      ],
      [
        "a string length",
        { length: "15" },
        "bad_config",
        "period length must be a positive whole number of minutes, got 15",
      ],
      [
        "fractional slots",
        { slots: 1.5 },
        "bad_config",
        "period slots must be a positive integer, got 1.5",
      ],
    ];
    for (const [label, period, code, message] of cases) {
      const config = { ...base, period };
      for (const construct of [
        () => validatePublisherConfig(/** @type {any} */ (config)),
        () => new Sealer(/** @type {any} */ (config)),
      ]) {
        assert.deepEqual(refusal(construct), { code, message }, /** @type {string} */ (label));
      }
    }
  });

  test("an omitted period and omitted options keep the documented defaults", () => {
    const base = validConfig();
    const { period: _period, ...omitted } = /** @type {any} */ (base);
    for (const [label, config, expected] of /** @type {const} */ ([
      ["no period member", omitted, {}],
      ["period undefined", { ...base, period: undefined }, {}],
      ["empty options", { ...base, period: {} }, {}],
      ["length only", { ...base, period: { length: 15 } }, { length: 15 }],
      ["slots only", { ...base, period: { slots: 3 } }, { slots: 3 }],
      ["both", { ...base, period: { length: 15, slots: 3 } }, { length: 15, slots: 3 }],
      // What construction checks is what the render runs under: an option the
      // host keeps non-enumerable is still its option, and a spread drops it.
      [
        "a non-enumerable length",
        {
          ...base,
          period: Object.defineProperty({}, "length", { value: 15, enumerable: false }),
        },
        { length: 15 },
      ],
    ])) {
      assert.deepEqual(
        validatePublisherConfig(/** @type {any} */ (config)).period,
        expected,
        label,
      );
      assert.doesNotThrow(() => new Sealer(/** @type {any} */ (config)), label);
    }
  });
});
