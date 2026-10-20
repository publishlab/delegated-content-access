// @ts-check
//
// The copyable publisher entry. A host hands `createPublisher` the inputs it
// renders under and calls `publish` once per render; the entry builds a fresh
// `Sealer` for each call. The Sealer's own suites under
// `test-reference/core-publisher/` own every sealing rule, so this file pins
// what the entry adds: which configuration it takes, that each host input
// reaches the Sealer unchanged, one period-key render through it, and a
// clean copy of `copy-manifest--publisher.json` that runs on its own.
//
// Expected keys are the host's own: the period keys its supply was given,
// and the content key those unwrap. No issuer or client code takes part.

import { copyManifestFiles } from "../../tools/copyManifest.js";
import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createPublisher } from "../../integration-publisher/createPublisher.js";
import { writeMarkupDelivery } from "../../adapter-publisher/writeMarkupDelivery.js";
import { decrypt } from "../../core-shared/aead.js";
import { base64urlDecode, utf8Decode, utf8Encode } from "../../core-shared/codec.js";
import { decodeHeader, verify } from "../../core-shared--publisher-issuer/jwt.js";
import { Sealer } from "../../core-publisher/Sealer.js";
import { ordinaryContentKeyWrap } from "../../core-publisher/contentKeyWrap.js";
import { seal as sealKey } from "../../core-shared--publisher-issuer/keySealing.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";
import { contentAadOctets } from "../support/contentAadOctets.js";
import { refuses } from "../../test-lib/helpers/refuses.js";

const V1 = new URL("../../", import.meta.url);

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const ORIGIN = "https://www.news-site.example";
const AT = "2025-10-23T14:20:00Z";
const CONTENT_NAME = "bodytext";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const GROUP = "premium";

// An hourly, two-slot render at AT wraps under the hour AT falls in and the
// next one, spelled YYMMDDTHHMM (docs/spec-profile--period-keys.md, 5.5); a three-slot
// render adds the hour after.
const T_NOW = "251023T1400";
const T_NEXT = "251023T1500";
const T_LATER = "251023T1600";

/** The period keys the host's supply holds, fixed before any run. */
const PERIOD_KEYS = Object.freeze({
  [T_NOW]: Uint8Array.from({ length: 16 }, (_, i) => 0x40 + i),
  [T_NEXT]: Uint8Array.from({ length: 16 }, (_, i) => 0x60 + i),
  [T_LATER]: Uint8Array.from({ length: 16 }, (_, i) => 0x80 + i),
});

/** Supplies every group the render wraps under, and no item content key. */
const periodOnly = (
  /** @type {unknown} */ _issuer,
  /** @type {{ accessGroups: string[] }} */ render,
) => ({ contentKeyNames: [], suppliedAccessGroups: [...render.accessGroups] });

/**
 * A host's inputs, with a record of every call the Sealer makes into them.
 *
 * @param {Record<string, unknown>} [overrides]
 */
async function hostInputs(overrides = {}) {
  const issuerKeys = await issuerKeypair();
  const signingKeys = await signingKeypair();
  const calls = { now: 0, bytes: 0, derive: /** @type {string[][]} */ ([]), plans: 0 };
  const config = {
    origin: ORIGIN,
    clock: {
      now() {
        calls.now++;
        return new Date(AT);
      },
    },
    random: {
      /** @param {number} n */
      bytes(n) {
        calls.bytes++;
        return globalThis.crypto.getRandomValues(new Uint8Array(n));
      },
    },
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
    issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) => {
      calls.plans++;
      return periodOnly(issuer, render);
    },
    periodKeySupply: {
      /** @param {string} accessGroup @param {string} t */
      async derive(accessGroup, t) {
        calls.derive.push([accessGroup, t]);
        return Uint8Array.from(PERIOD_KEYS[/** @type {keyof PERIOD_KEYS} */ (t)]);
      },
    },
    period: { length: 60, slots: 2 },
    ...overrides,
  };
  return { config, calls, issuerKeys, signingKeys };
}

/** One article of one item under one access group. */
function article(value = ARTICLE) {
  return {
    resourceId: "123456",
    data: { section: "politics" },
    items: [{ name: CONTENT_NAME, value, contentType: "text/html", accessGroups: [GROUP] }],
  };
}

describe("What createPublisher takes", () => {
  test("a missing or non-object configuration is refused", async () => {
    await refuses(() => createPublisher(), "bad_config", "no configuration at all");
    await refuses(
      () => createPublisher(/** @type {any} */ (null)),
      "bad_config",
      "a null configuration",
    );
    await refuses(
      () => createPublisher(/** @type {any} */ ([])),
      "bad_config",
      "an array in place of the configuration",
    );
  });

  test("each required host input is refused at construction when it is missing", async () => {
    for (const name of [
      "origin",
      "clock",
      "random",
      "signingKeys",
      "issuers",
      "issuerSupplyPlanFor",
    ]) {
      const { config } = await hostInputs();
      delete (/** @type {any} */ (config)[name]);
      await refuses(
        () => createPublisher(config),
        "bad_config",
        `a publisher without ${name} is refused before its first render`,
      );
    }
  });

  test("configuration fields inherited from a prototype are not publisher inputs", async () => {
    const { config } = await hostInputs();
    await refuses(
      () => createPublisher(Object.create(config)),
      "bad_config",
      "required configuration values must be own members",
    );
    // Each value would be admitted as an own member; only the inheritance is wrong.
    for (const [name, value] of [
      ["developmentHttpOrigin", true],
      ["signingKid", SIGNING_KID],
      ["period", { length: 60, slots: 3 }],
      ["keySealing", { seal: sealKey }],
      ["contentKeyWrapStrategy", ordinaryContentKeyWrap],
    ]) {
      const own = { ...config };
      delete (/** @type {any} */ (own)[name]);
      await refuses(
        () => createPublisher(Object.assign(Object.create({ [name]: value }), own)),
        "bad_config",
        `an optional ${name} inherited from a prototype is refused`,
      );
    }
  });

  test("a malformed host input is refused at construction", async () => {
    const cases = [
      ["an http origin outside the development profile", { origin: "http://www.news.example" }],
      [
        "a three-argument period-key supply",
        { periodKeySupply: { derive: (/** @type {any} */ _a, _b, _c) => _c } },
      ],
      ["a signingKid naming no held key", { signingKid: "sign-1999-01" }],
      ["a development profile that is not a boolean", { developmentHttpOrigin: "yes" }],
      ["an issuerSupplyPlanFor that is not a function", { issuerSupplyPlanFor: {} }],
      ["a keySealing without seal", { keySealing: {} }],
      ["a contentKeyWrapStrategy without entry", { contentKeyWrapStrategy: { aad() {} } }],
      ...[
        "developmentHttpOrigin",
        "signingKid",
        "periodKeySupply",
        "period",
        "keySealing",
        "contentKeyWrapStrategy",
      ].map((name) => [`an optional ${name} explicitly set to undefined`, { [name]: undefined }]),
    ];
    for (const [why, override] of cases) {
      const { config } = await hostInputs(/** @type {any} */ (override));
      await refuses(() => createPublisher(config), "bad_config", /** @type {string} */ (why));
    }
  });

  test("an issuer without a nonempty string keyId is refused at construction", async () => {
    // A late failure would be a render whose issuer block lacks the member;
    // the entry refuses the record before it is built, so no render exists.
    const notString = /needs a string (unlockUrl|keyId)/;
    const cases = [
      ["no keyId", { keyId: undefined }, notString],
      ["a null keyId", { keyId: null }, notString],
      ["an empty keyId", { keyId: "" }, /needs a nonempty keyId/],
    ];
    for (const [why, change, message] of cases) {
      const { config, calls } = await hostInputs();
      // An undefined change removes the member, so "no unlockUrl" is absent.
      const issuer = Object.fromEntries(
        Object.entries({ ...config.issuers[0], .../** @type {object} */ (change) }).filter(
          ([, value]) => value !== undefined,
        ),
      );
      assert.throws(
        () => createPublisher({ ...config, issuers: [issuer] }),
        (/** @type {any} */ error) => {
          assert.equal(error.code, "bad_config", /** @type {string} */ (why));
          assert.match(error.message, /** @type {RegExp} */ (message), /** @type {string} */ (why));
          return true;
        },
        /** @type {string} */ (why),
      );
      assert.deepEqual(
        { now: calls.now, bytes: calls.bytes, plans: calls.plans },
        { now: 0, bytes: 0, plans: 0 },
        /** @type {string} */ (why),
      );
    }
  });

  test("string issuer fields reach the issuer block as given, beside extra issuer metadata", async () => {
    const { config } = await hostInputs();
    const issuer = { ...config.issuers[0], keyId: "2025-11", displayName: "Subscriptions" };
    const { dcaData } = await createPublisher({ ...config, issuers: [issuer] }).publish(article());
    const block = /** @type {any} */ (dcaData.issuerData[ISSUER_NAME]);
    assert.equal(Object.hasOwn(block, "unlockUrl"), false);
    assert.equal(block.keyId, "2025-11");
  });

  test("a configuration member this entry does not take is refused by name", async () => {
    for (const name of ["periodSecret", "registrations"]) {
      const { config } = await hostInputs({ [name]: {} });
      await refuses(
        () => createPublisher(config),
        { code: "unsupported_option", message: new RegExp(name) },
        `createPublisher names ${name} when it refuses it`,
      );
    }
  });

  test("publish refuses a render it cannot read before sealing anything", async () => {
    // The plan also supplies each item key, so an item the entry wrongly
    // admitted would publish under its item-key route instead of failing later.
    const { config, calls } = await hostInputs({
      issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ render) => ({
        contentKeyNames: [...render.contentNames],
        suppliedAccessGroups: [...render.accessGroups],
      }),
    });
    const publisher = createPublisher(config);
    const inheritedRender = Object.create(article());
    const inheritedValue = Object.create({ value: ARTICLE });
    inheritedValue.name = CONTENT_NAME;
    inheritedValue.contentType = "text/html";
    inheritedValue.accessGroups = [GROUP];
    const inheritedGroups = Object.create({ accessGroups: [GROUP] });
    inheritedGroups.name = CONTENT_NAME;
    inheritedGroups.value = ARTICLE;
    inheritedGroups.contentType = "text/html";
    const hiddenDescriptorMember = {
      bytes: utf8Encode(ARTICLE),
      contentType: "text/html",
      contentEncodings: [],
    };
    Object.defineProperty(hiddenDescriptorMember, "decoder", { value: "unexpected" });
    const cases = [
      ["no render at all", undefined, "bad_config"],
      [
        "a render member the entry does not take",
        { ...article(), issuerName: "x" },
        "unsupported_option",
      ],
      ["items that are not a list", { ...article(), items: {} }, "bad_config"],
      ["a render item that is not a record", { ...article(), items: [null] }, "bad_config"],
      ["a render whose required members are inherited", inheritedRender, "bad_config"],
      [
        "an item whose required value is inherited",
        { ...article(), items: [inheritedValue] },
        "bad_config",
      ],
      [
        "an item whose optional accessGroups are inherited",
        { ...article(), items: [inheritedGroups] },
        "bad_config",
      ],
      [
        "an item whose optional accessGroups are explicitly undefined",
        {
          ...article(),
          items: [{ ...article().items[0], accessGroups: undefined }],
        },
        "bad_config",
      ],
      [
        "an item member the entry does not take",
        { ...article(), items: [{ ...article().items[0], contentKey: "x" }] },
        "unsupported_option",
      ],
      [
        "a representation descriptor beside a second contentType",
        {
          ...article(),
          items: [
            {
              name: CONTENT_NAME,
              value: { bytes: utf8Encode(ARTICLE), contentType: "text/html", contentEncodings: [] },
              contentType: "text/plain",
              accessGroups: [GROUP],
            },
          ],
        },
        "bad_config",
      ],
      [
        "a representation descriptor beside an explicitly undefined contentType",
        {
          ...article(),
          items: [
            {
              name: CONTENT_NAME,
              value: { bytes: utf8Encode(ARTICLE), contentType: "text/html", contentEncodings: [] },
              contentType: undefined,
              accessGroups: [GROUP],
            },
          ],
        },
        "bad_config",
      ],
      [
        "a representation descriptor with a non-enumerable unsupported member",
        {
          ...article(),
          items: [{ name: CONTENT_NAME, value: hiddenDescriptorMember, accessGroups: [GROUP] }],
        },
        "unsupported_option",
      ],
      ["resource data left out", { resourceId: "123456", items: article().items }, "bad_config"],
      ["no item", { ...article(), items: [] }, "bad_config"],
    ];
    for (const [why, render, code] of cases) {
      await refuses(
        () => publisher.publish(/** @type {any} */ (render)),
        /** @type {string} */ (code),
        /** @type {string} */ (why),
      );
    }
    assert.equal(calls.bytes, 0, "a refused render draws no random byte");
    assert.equal(calls.derive.length, 0, "a refused render asks the supply for no key");
  });
});

describe("Host inputs reach the Sealer", () => {
  test("an explicit key sealer handles the issuer envelopes", async () => {
    const { config } = await hostInputs();
    const calls = [];
    const keySealing = {
      /** @type {typeof sealKey} */
      async seal(keyBytes, publicKey, algorithm, options) {
        calls.push(options);
        return sealKey(keyBytes, publicKey, algorithm, options);
      },
    };
    const { dcaData } = await createPublisher({ ...config, keySealing }).publish(article());
    assert.equal(calls.length, 2, "each period-key envelope uses the selected key sealer");
    assert.deepEqual(Object.keys(dcaData.issuerData[ISSUER_NAME].sealed.periodKeys[GROUP]), [
      T_NOW,
      T_NEXT,
    ]);
  });

  test("clock, random, supply, period, plan and origin each reach the render", async () => {
    const { config, calls } = await hostInputs({ period: { length: 60, slots: 3 } });
    const { dcaData } = await createPublisher(config).publish(article());

    assert.equal(calls.now, 1, "the render instant is read once, from the host's clock");
    assert.ok(
      calls.bytes > 0,
      "every nonce, content key and renderId comes from the host's random",
    );
    assert.equal(calls.plans, 1, "the plan is asked once for the one issuer");
    assert.deepEqual(
      calls.derive,
      [
        [GROUP, T_NOW],
        [GROUP, T_NEXT],
        [GROUP, T_LATER],
      ],
      "the supply is asked for each label the host's three-slot period names",
    );
    assert.equal(dcaData.resource.origin, ORIGIN);
    assert.equal(dcaData.resource.issuedAt, new Date(AT).toISOString());
    assert.deepEqual(
      Object.keys(/** @type {any} */ (dcaData.issuerData[ISSUER_NAME].sealed.periodKeys)[GROUP]),
      [T_NOW, T_NEXT, T_LATER],
    );
  });

  test("the host's signingKid selects which held key signs", async () => {
    const other = await signingKeypair();
    const { config, signingKeys } = await hostInputs();
    const held = { [SIGNING_KID]: signingKeys.privateKey, "sign-2025-11": other.privateKey };

    await refuses(
      () => createPublisher({ ...config, signingKeys: held }),
      "bad_config",
      "two held keys and no signingKid",
    );
    const { dcaData } = await createPublisher({
      ...config,
      signingKeys: held,
      signingKid: "sign-2025-11",
    }).publish(article());
    assert.equal(decodeHeader(dcaData.resourceJWT).kid, "sign-2025-11");
  });

  test("a signingKid that is not a nonempty string is refused at construction", async () => {
    // docs/spec--core-protocol.md, 4.1: the resourceJWT kid is a nonempty
    // string. A number finds its key through property-key coercion and then
    // signs "kid":2024, which every issuer refuses.
    const { config, signingKeys } = await hostInputs();
    for (const [label, change] of /** @type {const} */ ([
      ["numeric kid", { signingKeys: { 2024: signingKeys.privateKey }, signingKid: 2024 }],
      ["empty sole key name", { signingKeys: { "": signingKeys.privateKey } }],
      ["empty kid", { signingKeys: { "": signingKeys.privateKey }, signingKid: "" }],
    ])) {
      await refuses(
        () => createPublisher(/** @type {any} */ ({ ...config, ...change })),
        { code: "bad_config", message: /signingKid is a nonempty string/ },
        label,
      );
    }
  });

  test("a selected signing key held as a non-enumerable own entry signs the render", async () => {
    // Admission finds the named kid by own membership, enumerable or not, so
    // the render signs with that key. A copy of only the enumerable entries
    // would pass construction and lose the key before publish.
    const { config, signingKeys } = await hostInputs();
    const other = await signingKeypair();
    const held = { "sign-2025-11": other.privateKey };
    Object.defineProperty(held, SIGNING_KID, {
      value: signingKeys.privateKey,
      enumerable: false,
    });
    const hidden = { ...config, signingKeys: held, signingKid: SIGNING_KID };
    const plainSealer = () => {
      const sealer = new Sealer(/** @type {any} */ (hidden));
      sealer.resource("123456", { section: "politics" });
      sealer.content(CONTENT_NAME, ARTICLE, "text/html", { accessGroups: [GROUP] });
      return sealer.seal();
    };
    for (const [label, publish] of /** @type {const} */ ([
      ["plain Sealer", plainSealer],
      ["publisher entry", () => createPublisher(hidden).publish(article())],
      [
        "composed publisher entry",
        () => createPublisher(hidden, { name: "alpha" }).publish(article()),
      ],
    ])) {
      const { dcaData } = await publish();
      assert.equal(decodeHeader(dcaData.resourceJWT).kid, SIGNING_KID, label);
      await verify(dcaData.resourceJWT, signingKeys.publicKey);
    }
    // The host's map is not changed into an enumerable one.
    assert.deepEqual(Object.keys(held), ["sign-2025-11"]);
  });

  test("the development profile admits a loopback http origin and is passed as given", async () => {
    const { config } = await hostInputs({ origin: "http://localhost:8080" });
    await refuses(() => createPublisher(config), "bad_config", "http without the profile");
    const { dcaData } = await createPublisher({ ...config, developmentHttpOrigin: true }).publish(
      article(),
    );
    assert.equal(dcaData.resource.origin, "http://localhost:8080");
  });

  test("each publish is a fresh render over a snapshot of the configuration", async () => {
    const { config } = await hostInputs();
    const publisher = createPublisher(config);
    const first = await publisher.publish(article());

    // The host edits its own records after construction; renders keep what
    // the publisher was built with, and a host rotates by building another.
    config.issuers[0].keyId = "changed-after-construction";
    const second = await publisher.publish({
      resourceId: "654321",
      data: { section: "sport" },
      items: [
        { name: "summary", value: "<p>Ferry</p>", contentType: "text/html", accessGroups: [GROUP] },
      ],
    });

    assert.deepEqual(Object.keys(second.dcaData.contentData), ["summary"]);
    assert.deepEqual(Object.keys(second.sealedContent), ["summary"]);
    assert.notEqual(second.dcaData.resource.renderId, first.dcaData.resource.renderId);
    assert.equal(Object.hasOwn(second.dcaData.issuerData[ISSUER_NAME], "unlockUrl"), false);
  });

  for (const [label, contributions] of /** @type {const} */ ([
    ["no contribution", []],
    ["one contribution", [{ name: "alpha" }]],
  ])) {
    test(`${label}: a host that edits an issuer's limits after construction changes no render`, async () => {
      const { config } = await hostInputs();
      const limits = { maxEntries: 1 };
      const issuers = [{ ...config.issuers[0], limits }];
      const publisher = createPublisher({ ...config, issuers }, ...contributions);
      limits.maxEntries = 100;

      await refuses(
        () => publisher.publish(article()),
        { code: "bad_config", message: /exceeds maxEntries/ },
        "the publisher keeps the limit it was built with",
      );
    });

    test(`${label}: a period option the host keeps non-enumerable reaches the render`, async () => {
      const { config } = await hostInputs();
      const period = Object.defineProperty({ length: 60 }, "slots", {
        value: 3,
        enumerable: false,
      });
      const { dcaData } = await createPublisher({ ...config, period }, ...contributions).publish(
        article(),
      );
      assert.deepEqual(
        Object.keys(/** @type {any} */ (dcaData.issuerData[ISSUER_NAME].sealed.periodKeys)[GROUP]),
        [T_NOW, T_NEXT, T_LATER],
        "admission checked three slots, so the render seals three period keys",
      );
    });

    test(`${label}: a host that edits its period or signing-key map after construction changes no render`, async () => {
      const other = await signingKeypair();
      const { config, signingKeys } = await hostInputs();
      /** @type {Record<string, CryptoKey>} */
      const held = { [SIGNING_KID]: signingKeys.privateKey };
      const period = { length: 60, slots: 2 };
      const publisher = createPublisher({ ...config, signingKeys: held, period }, ...contributions);
      period.slots = 3;
      delete held[SIGNING_KID];
      held["sign-2025-11"] = other.privateKey;

      const { dcaData } = await publisher.publish(article());
      assert.equal(decodeHeader(dcaData.resourceJWT).kid, SIGNING_KID);
      assert.deepEqual(
        Object.keys(/** @type {any} */ (dcaData.issuerData[ISSUER_NAME].sealed.periodKeys)[GROUP]),
        [T_NOW, T_NEXT],
      );
    });
  }

  test("concurrent publishes snapshot each render's data, bytes and item assignments", async () => {
    let releaseDerivations = /** @type {() => void} */ (() => {});
    const derivationGate = new Promise((resolve) => {
      releaseDerivations = resolve;
    });
    let firstDerivations = 0;
    let releaseFirstDerivations = /** @type {() => void} */ (() => {});
    const bothFirstDerivations = new Promise((resolve) => {
      releaseFirstDerivations = resolve;
    });
    /** @type {{ accessGroups: string[], contentNames: string[] }[]} */
    const plannedRenders = [];
    const { config } = await hostInputs({
      periodKeySupply: {
        async derive(accessGroup, t) {
          firstDerivations += 1;
          if (firstDerivations === 2) releaseFirstDerivations();
          await derivationGate;
          return Uint8Array.from(
            PERIOD_KEYS[/** @type {keyof PERIOD_KEYS} */ (t)],
            (byte) => byte ^ accessGroup.charCodeAt(0),
          );
        },
      },
      issuerSupplyPlanFor(issuer, render) {
        plannedRenders.push({
          accessGroups: [...render.accessGroups],
          contentNames: [...render.contentNames],
        });
        return periodOnly(issuer, render);
      },
    });
    const publisher = createPublisher(config);
    const firstInput = {
      resourceId: "123456",
      data: { section: "politics" },
      items: [
        {
          name: "first",
          value: "First snapshot",
          contentType: "text/plain",
          accessGroups: [GROUP],
        },
      ],
    };
    const secondInput = {
      resourceId: "654321",
      data: { section: "sport" },
      items: [
        {
          name: "second",
          value: utf8Encode("Second snapshot"),
          contentType: "text/plain",
          accessGroups: ["free"],
        },
      ],
    };

    const firstPending = publisher.publish(firstInput);
    const secondPending = publisher.publish(secondInput);
    await bothFirstDerivations;

    firstInput.resourceId = "999999";
    firstInput.data.section = "changed";
    firstInput.items[0].name = "changed-first";
    firstInput.items[0].value = "Changed first bytes";
    firstInput.items[0].accessGroups[0] = "changed-group";
    secondInput.resourceId = "888888";
    secondInput.data.section = "changed";
    secondInput.items[0].name = "changed-second";
    secondInput.items[0].value.fill(0);
    secondInput.items[0].accessGroups[0] = "changed-group";

    releaseDerivations();
    const [first, second] = await Promise.all([firstPending, secondPending]);
    assert.equal(first.dcaData.resource.resourceId, "123456");
    assert.deepEqual(first.dcaData.resource.data, { section: "politics" });
    assert.equal(second.dcaData.resource.resourceId, "654321");
    assert.deepEqual(second.dcaData.resource.data, { section: "sport" });
    assert.deepEqual(Object.keys(first.dcaData.contentData), ["first"]);
    assert.deepEqual(Object.keys(second.dcaData.contentData), ["second"]);
    assert.deepEqual(plannedRenders, [
      { accessGroups: [GROUP], contentNames: ["first"] },
      { accessGroups: ["free"], contentNames: ["second"] },
    ]);

    for (const [render, contentName, group, expected] of [
      [first, "first", GROUP, "First snapshot"],
      [second, "second", "free", "Second snapshot"],
    ]) {
      const record = /** @type {any} */ (render.dcaData.contentData[contentName]);
      assert.deepEqual(Object.keys(record.keys), [group]);
      const wrap = record.keys[group][0];
      const periodKey = Uint8Array.from(
        PERIOD_KEYS[/** @type {keyof PERIOD_KEYS} */ (wrap.t)],
        (byte) => byte ^ group.charCodeAt(0),
      );
      const contentKey = await decrypt(
        periodKey,
        base64urlDecode(wrap.nonce),
        base64urlDecode(wrap.key),
      );
      const plaintext = await decrypt(
        contentKey,
        new Uint8Array(12),
        base64urlDecode(render.sealedContent[contentName]),
        contentAadOctets(render.dcaData, contentName),
      );
      assert.equal(utf8Decode(plaintext), expected);
    }
  });

  test("a representation descriptor passes to the Sealer with its own contentType", async () => {
    const { config } = await hostInputs();
    const { dcaData } = await createPublisher(config).publish({
      ...article(),
      items: [
        {
          name: CONTENT_NAME,
          value: { bytes: utf8Encode(ARTICLE), contentType: "text/html", contentEncodings: [] },
          accessGroups: [GROUP],
        },
      ],
    });
    assert.equal(dcaData.contentData[CONTENT_NAME].contentType, "text/html");
  });
});

describe("One period-key render through the entry", () => {
  test("the item is wrapped under each period key and each key is sealed to the issuer", async () => {
    const { config } = await hostInputs();
    const render = await createPublisher(config).publish(article());
    const { dcaData, sealedContent } = render;
    const record = /** @type {any} */ (dcaData.contentData[CONTENT_NAME]);

    // The item wrap: one entry per period-key label, each opened by the key the
    // host's supply holds at that label, all to the same content key.
    assert.deepEqual(
      record.keys[GROUP].map((/** @type {any} */ entry) => entry.t),
      [T_NOW, T_NEXT],
    );
    const contentKeys = [];
    for (const entry of record.keys[GROUP]) {
      contentKeys.push(
        await decrypt(
          PERIOD_KEYS[/** @type {keyof PERIOD_KEYS} */ (entry.t)],
          base64urlDecode(entry.nonce),
          base64urlDecode(entry.key),
        ),
      );
    }
    assert.deepEqual(contentKeys[0], contentKeys[1]);
    const plaintext = await decrypt(
      contentKeys[0],
      new Uint8Array(12),
      base64urlDecode(sealedContent[CONTENT_NAME]),
      contentAadOctets(dcaData, CONTENT_NAME),
    );
    assert.equal(utf8Decode(plaintext), ARTICLE);

    // The issuer block carries the period keys sealed for it and, under this
    // plan, no item content key.
    const sealed = /** @type {any} */ (dcaData.issuerData[ISSUER_NAME].sealed);
    assert.equal(Object.hasOwn(sealed, "contentKeys"), false);
    assert.deepEqual(Object.keys(sealed.periodKeys[GROUP]), [T_NOW, T_NEXT]);
    assert.equal(Object.hasOwn(dcaData, "periodGeometry"), false);

    // Markup stays a separate host call over the same render.
    const markup = writeMarkupDelivery(render);
    assert.ok(markup.includes(dcaData.resourceJWT));
    assert.ok(markup.includes(sealedContent[CONTENT_NAME]));
  });
});

describe("One mixed render through the entry", () => {
  test("grouped items carry wraps and ungrouped items carry only their item-key route", async () => {
    /** @type {Record<string, Uint8Array>} */
    const sealedItemKeys = {};
    const { config, calls } = await hostInputs({
      issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ render) => ({
        contentKeyNames: ["sidebar", "footer"],
        suppliedAccessGroups: [...render.accessGroups],
      }),
      keySealing: {
        /** @type {typeof sealKey} */
        async seal(keyBytes, publicKey, algorithm, options) {
          if (options.binding.contentName !== undefined) {
            sealedItemKeys[options.binding.contentName] = Uint8Array.from(keyBytes);
          }
          return sealKey(keyBytes, publicKey, algorithm, options);
        },
      },
    });
    const texts = {
      [CONTENT_NAME]: ARTICLE,
      sidebar: "<p>Ferry times</p>",
      footer: "<p>Letters</p>",
    };
    const render = await createPublisher(config).publish({
      resourceId: "123456",
      data: { section: "politics" },
      items: [
        {
          name: CONTENT_NAME,
          value: texts[CONTENT_NAME],
          contentType: "text/html",
          accessGroups: [GROUP],
        },
        { name: "sidebar", value: texts.sidebar, contentType: "text/html" },
        { name: "footer", value: texts.footer, contentType: "text/html", accessGroups: [] },
      ],
    });
    // Read what crossed the wire, not the objects the entry returned.
    const { dcaData, sealedContent } = JSON.parse(JSON.stringify(render));

    /** @param {string} name @param {Uint8Array} contentKey */
    const opened = async (name, contentKey) =>
      utf8Decode(
        await decrypt(
          contentKey,
          new Uint8Array(12),
          base64urlDecode(sealedContent[name]),
          contentAadOctets(dcaData, name),
        ),
      );

    const grouped = dcaData.contentData[CONTENT_NAME];
    assert.deepEqual(Object.keys(grouped.keys), [GROUP]);
    for (const entry of grouped.keys[GROUP]) {
      const contentKey = await decrypt(
        PERIOD_KEYS[/** @type {keyof PERIOD_KEYS} */ (entry.t)],
        base64urlDecode(entry.nonce),
        base64urlDecode(entry.key),
      );
      assert.equal(await opened(CONTENT_NAME, contentKey), ARTICLE, entry.t);
    }
    for (const name of ["sidebar", "footer"]) {
      assert.deepEqual(Object.keys(dcaData.contentData[name]), ["contentType"]);
      assert.equal(await opened(name, sealedItemKeys[name]), texts[name], name);
    }

    // Each issuer member is exactly what the plan selected: item keys for the
    // two ungrouped items, and period keys only for the group one item names.
    const sealed = dcaData.issuerData[ISSUER_NAME].sealed;
    assert.deepEqual(Object.keys(sealedItemKeys), ["sidebar", "footer"]);
    assert.deepEqual(Object.keys(sealed.contentKeys), ["sidebar", "footer"]);
    assert.deepEqual(Object.keys(sealed.periodKeys), [GROUP]);
    assert.deepEqual(calls.derive, [
      [GROUP, T_NOW],
      [GROUP, T_NEXT],
    ]);

    const markup = writeMarkupDelivery(render);
    for (const name of [CONTENT_NAME, "sidebar", "footer"]) {
      assert.ok(markup.includes(sealedContent[name]), name);
    }
  });

  test("a named group is refused when the entry holds no periodKeySupply", async () => {
    const { config, calls } = await hostInputs({
      issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ render) => ({
        contentKeyNames: [...render.contentNames],
        suppliedAccessGroups: [],
      }),
    });
    delete (/** @type {any} */ (config).periodKeySupply);
    const publisher = createPublisher(config);

    await refuses(
      () => publisher.publish(article()),
      { code: "bad_config", message: /content "bodytext" names accessGroups/ },
      "the requested wraps are refused rather than dropped",
    );
    assert.equal(calls.bytes, 0, "a refused render draws no random byte");

    const { dcaData } = await publisher.publish({
      ...article(),
      items: [{ name: CONTENT_NAME, value: ARTICLE, contentType: "text/html" }],
    });
    assert.equal(Object.hasOwn(dcaData.contentData[CONTENT_NAME], "keys"), false);
  });
});

/**
 * Copy what a manifest names into a scratch tree: every `.js` file directly in
 * each named directory, under the same directory names.
 *
 * @param {string} manifestName
 * @returns {{ root: string, files: string[] }}
 */
function copySlice(manifestName) {
  const manifest = JSON.parse(readFileSync(new URL(manifestName, V1), "utf8"));
  const root = mkdtempSync(join(tmpdir(), "dca-copy-slice-"));
  /** @type {string[]} */
  const files = [];
  for (const path of copyManifestFiles(manifest, V1)) {
    const directory = path.slice(0, path.lastIndexOf("/"));
    mkdirSync(join(root, directory), { recursive: true });
    copyFileSync(fileURLToPath(new URL(path, V1)), join(root, path));
    files.push(path);
  }
  return { root, files };
}

/**
 * Every import and re-export specifier in one copied file, static or dynamic.
 *
 * @param {string} source
 */
function specifiersIn(source) {
  return [
    ...[...source.matchAll(/^(?:import|export)\b[^'"]*?from\s*(['"])([^'"]+)\1/gm)].map(
      (match) => match[2],
    ),
    ...[...source.matchAll(/\bimport\s*\(\s*(['"])([^'"]+)\1/g)].map((match) => match[2]),
  ];
}

describe("A clean copy of the publisher manifest", () => {
  test("every copied import resolves inside the copy, and the copied entry publishes", async () => {
    const { root, files } = copySlice("copy-manifest--publisher.json");
    try {
      const copied = new Set(files);
      for (const file of files) {
        const source = readFileSync(join(root, file), "utf8");
        for (const specifier of specifiersIn(source)) {
          assert.ok(
            specifier.startsWith("."),
            `${file} imports ${specifier}, which no copy carries`,
          );
          const target = new URL(specifier, `file:///slice/${file}`).pathname.slice(
            "/slice/".length,
          );
          assert.ok(copied.has(target), `${file} imports ${target}, which the manifest leaves out`);
        }
      }

      const { createPublisher: copiedEntry } = await import(
        pathToFileURL(join(root, "integration-publisher/createPublisher.js")).href
      );
      const { writeMarkupDelivery: copiedMarkup } = await import(
        pathToFileURL(join(root, "adapter-publisher/writeMarkupDelivery.js")).href
      );
      const { config } = await hostInputs();
      const render = await copiedEntry(config).publish(article());
      assert.deepEqual(Object.keys(render.dcaData.contentData), [CONTENT_NAME]);
      assert.ok(copiedMarkup(render).includes(render.dcaData.resourceJWT));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
