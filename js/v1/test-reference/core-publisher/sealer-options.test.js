// @ts-check
//
// The Sealer's config surface. A name the constructor does not read is refused
// where it arrives, not dropped in the destructure: an option that never
// reaches the wire makes a caller believe it configured something, and the
// render comes out of the other end looking correct. `domain` is the one that
// proved it. It was read out of the signed resource and every call site kept
// passing it, so the vector generator failed as a byte diff and one wire test
// asserted a fixture constant it could no longer change. The render's delivery
// coordinate is `origin` now, and `domain` is a name this Sealer has never
// read; it stays here as the case the rule was written for.
//
// `periodSecret` keeps its own refusal, and a `bad_config` rather than this
// one, because it is a retired base configuration shape rather than a typo.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../core-publisher/Sealer.js";
import { Clock } from "../../demo/actors/Clock.js";
import {
  ALGORITHM,
  AT,
  DOMAIN,
  ISSUER_NAME,
  ORIGIN,
  KEY_ID,
  SIGNING_KID,
  UNLOCK_URL,
} from "../../demo/scenarios/fixtures.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../support/keys.js";

/**
 * Everything the Sealer does read, so a refusal below is about the one name
 * added to it and never about a missing required value.
 *
 * @returns {Promise<Record<string, any>>}
 */
async function validConfig() {
  const signing = await signingKeypair();
  const issuerKeys = await issuerKeypair();

  return {
    origin: ORIGIN,
    clock: new Clock(AT),
    random: seededRandom(20251023),
    signingKeys: { [SIGNING_KID]: signing.privateKey },
    signingKid: SIGNING_KID,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        publicKey: issuerKeys.publicKey,
        unlockUrl: UNLOCK_URL,
      },
    ],
  };
}

describe("The Sealer refuses a config name it does not read", () => {
  test("the valid config on its own constructs", async () => {
    assert.ok(new Sealer(/** @type {any} */ (await validConfig())));
  });

  test("a domain is refused rather than dropped", async () => {
    const config = await validConfig();
    assert.throws(
      () => new Sealer(/** @type {any} */ ({ ...config, domain: DOMAIN })),
      (/** @type {any} */ error) => error.code === "unsupported_option",
      "the Sealer signs no domain and says so",
    );
  });

  test("a misspelled option is refused rather than dropped", async () => {
    const config = await validConfig();
    assert.throws(
      () =>
        new Sealer(/** @type {any} */ ({ ...config, periodKeySupplies: config.periodKeySupply })),
      (/** @type {any} */ error) => error.code === "unsupported_option",
      "a near-miss on a real option name is the same failure",
    );
  });

  test("an ECDH ephemeral-key provider is not a production Sealer option", async () => {
    // A supplied pair makes an ECDH envelope replayable. That is useful to
    // fixture-only code which calls the lower-level envelope primitive, but
    // exposing it here would let a publisher reuse a pair across renders.
    const config = await validConfig();
    assert.throws(
      () => new Sealer(/** @type {any} */ ({ ...config, ephemeralKeyPairs: () => undefined })),
      (/** @type {any} */ error) => error.code === "unsupported_option",
      "the production Sealer cannot be configured with reusable ECDH material",
    );
  });

  test("a periodSecret keeps its own migration refusal", async () => {
    const config = await validConfig();
    assert.throws(
      () => new Sealer(/** @type {any} */ ({ ...config, periodSecret: null })),
      (/** @type {any} */ error) => error.code === "bad_config",
      "the message that says base takes exact key supply survives the option guard",
    );
  });
});

describe("The Sealer refuses unusable publisher seams", () => {
  test("content accepts strings or bytes and refuses another value shape at entry", async () => {
    const sealer = new Sealer(/** @type {any} */ (await validConfig()));
    assert.throws(
      () => sealer.content("bodytext", /** @type {any} */ (42), "text/html", {}),
      (/** @type {any} */ error) => error.code === "bad_config",
      "a value that is neither string, bytes nor descriptor is refused for its shape",
    );
    assert.throws(
      () =>
        sealer.content("bodytext", /** @type {any} */ ([1, 2, 3]), { accessGroups: ["premium"] }),
      (/** @type {any} */ error) => error.code === "unsupported_option",
      "an array selects the descriptor overload, and its indices are not descriptor members",
    );
    assert.throws(
      () =>
        sealer.content("bodytext", "article", "text/html", {
          accessGroups: /** @type {any} */ ("premium"),
        }),
      (/** @type {any} */ error) => error.code === "bad_config",
      "a group name is not silently expanded into one-character groups",
    );
  });

  test("a legacy string or byte item carries a string content type", async () => {
    const config = await validConfig();

    for (const contentType of [undefined, 7]) {
      const sealer = new Sealer(/** @type {any} */ (config));
      assert.throws(
        () =>
          sealer.content("bodytext", "<p>x</p>", /** @type {any} */ (contentType), {
            accessGroups: ["premium"],
          }),
        (/** @type {any} */ error) => error.code === "bad_config",
        "base cannot seal a record its own client refuses as bad_page",
      );
    }
  });

  test("an explicit representation has one unambiguous descriptor overload", async () => {
    const config = await validConfig();
    const descriptor = {
      bytes: new Uint8Array([1, 2, 3]),
      contentType: "text/html",
      contentEncodings: ["example"],
    };

    const malformed = [
      [{}, "bad_config"],
      [{ ...descriptor, bytes: [1, 2, 3] }, "bad_config"],
      [{ bytes: descriptor.bytes, contentType: "text/html" }, "bad_config"],
      [{ ...descriptor, contentType: undefined }, "bad_config"],
      [{ ...descriptor, contentEncodings: "example" }, "bad_config"],
      [{ ...descriptor, contentEncodings: [""] }, "bad_config"],
      [{ ...descriptor, contentEncodings: ["example", 7] }, "bad_config"],
      [{ ...descriptor, contentEncodings: Array(1) }, "bad_config"],
      [{ ...descriptor, extra: true }, "unsupported_option"],
    ];
    for (const [value, code] of malformed) {
      const sealer = new Sealer(/** @type {any} */ (config));
      assert.throws(
        () => sealer.content("bodytext", /** @type {any} */ (value), {}),
        (/** @type {any} */ error) => error.code === code,
      );
    }

    assert.throws(
      () =>
        new Sealer(/** @type {any} */ (config)).content(
          "bodytext",
          descriptor,
          "text/html",
          /** @type {any} */ ({}),
        ),
      (/** @type {any} */ error) => error.code === "bad_config",
      "a descriptor never reuses the legacy contentType and fourth options positions",
    );
    assert.throws(
      () => new Sealer(/** @type {any} */ (config)).content("bodytext", descriptor, "text/html"),
      (/** @type {any} */ error) => error.code === "bad_config",
      "the descriptor third argument is options, never contentType",
    );
  });

  test("constructor dependencies and selected hooks name their typed refusal", async () => {
    const config = await validConfig();

    const cases = [
      ["a missing clock", () => ({ clock: undefined }), /needs a clock/],
      ["a missing random source", () => ({ random: undefined }), /needs a random/],
      ["no issuers", () => ({ issuers: [] }), /at least one issuer/],
      [
        "two entries under one issuer name",
        () => ({ issuers: [config.issuers[0], { ...config.issuers[0] }] }),
        /issuerName .* is configured more than once/,
      ],
      [
        "a supply without derive",
        () => ({ periodKeySupply: {} }),
        /periodKeySupply is an object with a derive/,
      ],
      [
        "a legacy three-argument supply",
        () => ({
          periodKeySupply: {
            derive: (a, b, c) => {
              void a;
              void b;
              void c;
            },
          },
        }),
        /3-arg supply is the old shape/,
      ],
      [
        "a non-function family planner",
        () => ({ periodKeySupply: { derive: () => {}, familyPlan: true } }),
        /periodKeySupply\.familyPlan is a function/,
      ],
      [
        "a sealing hook without seal",
        () => ({ keySealing: {} }),
        /keySealing is an object with a seal/,
      ],
      ["an empty signing-key map", () => ({ signingKeys: {} }), /needs a signingKeys map/],
      [
        "multiple signing keys without a selection",
        () => ({
          signingKeys: { ...config.signingKeys, next: config.signingKeys[SIGNING_KID] },
          signingKid: undefined,
        }),
        /more than one signing key and needs a signingKid/,
      ],
      [
        "a selected signing key absent from the map",
        () => ({ signingKid: "not-present" }),
        /holds no signing key/,
      ],
    ];

    for (const [label, change, message] of cases) {
      assert.throws(
        () => new Sealer(/** @type {any} */ ({ ...config, ...change() })),
        (/** @type {any} */ error) => {
          assert.equal(error.code, "bad_config");
          assert.match(error.message, message);
          return true;
        },
        label,
      );
    }
  });

  test("seal requires a resource and then a content item", async () => {
    const cases = [
      ["a resource", (/** @type {Sealer} */ sealer) => sealer, /needs a resource/],
      [
        "a content item",
        (/** @type {Sealer} */ sealer) => sealer.resource("123456", { section: "politics" }),
        /needs a content item/,
      ],
    ];

    for (const [label, prepare, message] of cases) {
      const sealer = prepare(new Sealer(/** @type {any} */ (await validConfig())));
      await assert.rejects(
        sealer.seal(),
        (/** @type {any} */ error) => {
          assert.equal(error.code, "bad_config");
          assert.match(error.message, message);
          return true;
        },
        label,
      );
    }
  });
});
