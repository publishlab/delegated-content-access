// @ts-check
//
// The Sealer's two composition roles, and the boundary they finish at.
//
// `contentKeyWrapStrategy` is selected once for a render, because
// `contentData[contentName].keys` is emitted once and every issuer reads the
// same entries. `issuerSupplyPlanFor` is asked once per issuer, and answers
// only what that issuer is supplied: which access groups its period material
// covers, whether it receives the ordinary direct content-key map, the content
// names it has to be able to reach through those groups, and the extra members
// its block carries.
//
// Both are resolved before the render draws its first random byte, asks the
// period-key supply, seals to an issuer or signs. A plan that cannot be served
// refuses with nothing produced, rather than rendering with a hole in it.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../core-publisher/Sealer.js";
import { ordinaryContentKeyWrap } from "../../core-publisher/contentKeyWrap.js";
import { normalizedIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { decrypt } from "../../core-shared/aead.js";
import { EXACT_PERIOD_PROFILE } from "../../core-shared/exactPeriodProfiles.js";
import { base64urlDecode, utf8Encode } from "../../core-shared/codec.js";
import { Clock } from "../../demo/actors/Clock.js";
import {
  ALGORITHM,
  AT,
  CONTENT_TYPE,
  ISSUER_NAME,
  FALLBACK_ISSUER_NAME,
  ORIGIN,
  KEY_ID,
  RESOURCE_ID,
  SIGNING_KID,
  UNLOCK_URL,
} from "../../demo/scenarios/fixtures.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../support/keys.js";
import { deterministicEcdhFixtureSealing } from "../../tools/vector-fixtures/deterministicEcdhSealing.js";

const THIRD_ISSUER_NAME = "paywall_third_service";
const PERIODS = ["251023T14", "251023T15"];

/**
 * A supply whose bytes are a function of the coordinate alone, so two renders
 * of one coordinate wrap under the same key and a comparison is about the
 * publisher rather than about the supply.
 *
 * @returns {{ derive: (accessGroup: string, t: string) => Promise<Uint8Array> }}
 */
function fixedPeriodKeySupply() {
  return {
    async derive(accessGroup, t) {
      const label = utf8Encode(`${accessGroup}/${t}`);
      const key = new Uint8Array(16);
      for (let i = 0; i < key.length; i += 1) key[i] = label[i % label.length] ^ i;
      return key;
    },
  };
}

/**
 * One publisher, three onboarded issuers and a pool of ephemeral keypairs
 * handed out by seal context, so two renders of the same ordered configuration
 * compare byte for byte.
 */
async function world() {
  const signing = await signingKeypair();
  /** @type {Record<string, CryptoKeyPair>} */
  const issuerKeys = {};
  for (const issuerName of [ISSUER_NAME, FALLBACK_ISSUER_NAME, THIRD_ISSUER_NAME]) {
    issuerKeys[issuerName] = await issuerKeypair();
  }

  /** @type {CryptoKeyPair[]} */
  const pool = [];
  for (let i = 0; i < 48; i += 1) pool.push(await issuerKeypair());

  /** @param {string} issuerName */
  function issuerConfig(issuerName) {
    return {
      issuerName,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      publicKey: issuerKeys[issuerName].publicKey,
      unlockUrl: UNLOCK_URL,
    };
  }

  /** One provider per render, all drawing from the one pool. */
  function ephemeralKeyPairs() {
    /** @type {Map<string, CryptoKeyPair>} */
    const assigned = new Map();
    return (/** @type {object} */ context) => {
      const key = JSON.stringify(context);
      let pair = assigned.get(key);
      if (!pair) {
        pair = pool[assigned.size];
        if (!pair) throw new Error("the ephemeral pool ran out; raise its size");
        assigned.set(key, pair);
      }
      return pair;
    };
  }

  /** @param {object} [options] */
  function sealerConfig({
    ephemeralKeyPairs: fixturePairs = ephemeralKeyPairs(),
    ...options
  } = {}) {
    return {
      origin: ORIGIN,
      clock: new Clock(AT),
      random: seededRandom(20251023),
      signingKeys: { [SIGNING_KID]: signing.privateKey },
      signingKid: SIGNING_KID,
      periodKeySupply: fixedPeriodKeySupply(),
      issuers: [issuerConfig(ISSUER_NAME)],
      keySealing: deterministicEcdhFixtureSealing((issuerPublicKey, binding) => {
        const issuerName = Object.entries(issuerKeys).find(
          ([, pair]) => pair.publicKey === issuerPublicKey,
        )?.[0];
        return issuerName === undefined ? undefined : fixturePairs({ issuerName, ...binding });
      }),
      ...options,
    };
  }

  return { issuerConfig, sealerConfig };
}

/**
 * @param {any} sealer
 * @param {{ items?: { name: string, value?: string|Uint8Array, accessGroups: string[] }[] }} [options]
 * @returns {Promise<any>}
 */
async function render(sealer, options = {}) {
  sealer.resource(RESOURCE_ID, { section: "politics" });
  const items = options.items ?? [{ name: "bodytext", accessGroups: ["premium"] }];
  for (const item of items) {
    sealer.content(item.name, item.value ?? `<p>${item.name}</p>`, CONTENT_TYPE, {
      accessGroups: item.accessGroups,
    });
  }
  const sealed = await sealer.seal();
  return JSON.parse(JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }));
}

/** @param {string} token @returns {string} the compact JWT's header and payload */
function payloadOf(token) {
  return token.split(".").slice(0, 2).join(".");
}

/**
 * The optional family planner arrives with the supply, and the key acquisitions
 * a declared plan exposes count as supplier events, as `derive` does: a render
 * that refuses on the declared plan has asked the planner and drawn nothing
 * through what came back. The declared plan is copied member for member, so
 * every name base refuses still arrives.
 *
 * @param {(accessGroup: string, now: Date, period: object) => any} familyPlan
 * @param {{ plan: number, derive: number }} counts
 */
function watchedFamilyPlan(familyPlan, counts) {
  /** @param {unknown} value */
  const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

  return (
    /** @type {string} */ accessGroup,
    /** @type {Date} */ now,
    /** @type {object} */ period,
  ) => {
    counts.plan += 1;
    const plan = familyPlan(accessGroup, now, period);
    if (!record(plan)) return plan;

    const watchedPlan = { ...plan };
    if (typeof plan.exactAt === "function") {
      watchedPlan.exactAt = (/** @type {string} */ t) => {
        counts.derive += 1;
        return plan.exactAt(t);
      };
    }
    if (record(plan.chain)) {
      watchedPlan.chain = { ...plan.chain };
      if (typeof plan.chain.capabilityAt === "function") {
        watchedPlan.chain.capabilityAt = (/** @type {string} */ t) => {
          counts.derive += 1;
          return plan.chain.capabilityAt(t);
        };
      }
    }
    return watchedPlan;
  };
}

/**
 * Every call a render makes that a plan has to be settled before: the random
 * source, the ask for a family plan, the key acquisitions that plan exposes,
 * the seal to an issuer and the signature. `plan` counts the
 * `familyPlan(accessGroup, ...)` call itself, so a zero `derive` beside a
 * nonzero `plan` says base reached the seam and drew nothing through it.
 *
 * A direct-only configuration hands over no supply, and the watched config
 * carries none either, so the refusal a chain plan draws there is base's own.
 *
 * @param {object} config
 * @returns {{
 *   config: object,
 *   counts: { random: number, plan: number, derive: number, seal: number, sign: number }
 * }}
 */
function watched(config) {
  const counts = { random: 0, plan: 0, derive: 0, seal: 0, sign: 0 };
  const random = /** @type {any} */ (config).random;
  const supply = /** @type {any} */ (config).periodKeySupply;
  const signingKeys = /** @type {any} */ (config).signingKeys;

  /** @type {Record<string, any>} */
  const watchedKeys = {};
  for (const [kid, key] of Object.entries(signingKeys)) {
    watchedKeys[kid] = new Proxy(/** @type {object} */ (key), {
      get(target, name, receiver) {
        counts.sign += 1;
        return Reflect.get(target, name, receiver);
      },
    });
  }

  return {
    counts,
    config: {
      ...config,
      random: {
        bytes: (/** @type {number} */ n) => {
          counts.random += 1;
          return random.bytes(n);
        },
      },
      periodKeySupply: supply && {
        derive: (/** @type {string} */ group, /** @type {string} */ t) => {
          counts.derive += 1;
          return supply.derive(group, t);
        },
        ...(typeof supply.familyPlan === "function"
          ? { familyPlan: watchedFamilyPlan(supply.familyPlan, counts) }
          : {}),
      },
      signingKeys: watchedKeys,
      keySealing: {
        seal: async () => {
          counts.seal += 1;
          return "sealed";
        },
      },
    },
  };
}

describe("The default composition is the render base already made", () => {
  test("the same ordered configuration and pinned inputs replay byte for byte", async () => {
    const { sealerConfig } = await world();
    const first = await render(new Sealer(/** @type {any} */ (sealerConfig())));
    const second = await render(new Sealer(/** @type {any} */ (sealerConfig())));

    // Every byte but the signature: ECDSA draws its own nonce inside
    // WebCrypto, which the injected random does not reach, so two renders
    // compare on the payload under the token.
    const { resourceJWT: firstJwt, ...firstRest } = first;
    const { resourceJWT: secondJwt, ...secondRest } = second;
    assert.equal(JSON.stringify(secondRest), JSON.stringify(firstRest));
    assert.equal(payloadOf(secondJwt), payloadOf(firstJwt));
  });

  test("the two roles named explicitly render what the defaults render", async () => {
    const { sealerConfig } = await world();
    const plain = await render(new Sealer(/** @type {any} */ (sealerConfig())));
    const composed = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            contentKeyWrapStrategy: ordinaryContentKeyWrap,
            issuerSupplyPlanFor: () => ({}),
          })
        ),
      ),
    );

    const { resourceJWT: plainJwt, ...plainRest } = plain;
    const { resourceJWT: composedJwt, ...composedRest } = composed;
    assert.equal(JSON.stringify(composedRest), JSON.stringify(plainRest));
    assert.equal(payloadOf(composedJwt), payloadOf(plainJwt));
  });

  test("byte input matches UTF-8 string input and is snapshotted at content()", async () => {
    const { sealerConfig } = await world();
    const expected = await render(new Sealer(/** @type {any} */ (sealerConfig())));

    const bytes = utf8Encode("<p>bodytext</p>");
    const sealer = new Sealer(/** @type {any} */ (sealerConfig()));
    sealer.resource(RESOURCE_ID, { section: "politics" });
    sealer.content("bodytext", bytes, CONTENT_TYPE, { accessGroups: ["premium"] });
    bytes.fill(0);
    const sealed = await sealer.seal();
    const actual = JSON.parse(
      JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
    );

    const { resourceJWT: expectedJwt, ...expectedRest } = expected;
    const { resourceJWT: actualJwt, ...actualRest } = actual;
    assert.equal(
      Object.hasOwn(expected.contentData.bodytext, "contentEncodings"),
      false,
      "legacy strings declare no additional representation layer",
    );
    assert.equal(
      Object.hasOwn(actual.contentData.bodytext, "contentEncodings"),
      false,
      "legacy bytes declare no additional representation layer",
    );
    assert.equal(JSON.stringify(actualRest), JSON.stringify(expectedRest));
    assert.equal(payloadOf(actualJwt), payloadOf(expectedJwt));
  });

  test("an explicit already-represented descriptor is snapshotted and base applies no codec", async () => {
    const { sealerConfig } = await world();
    const expected = await render(new Sealer(/** @type {any} */ (sealerConfig())), {
      items: [
        { name: "bodytext", value: utf8Encode("<p>bodytext</p>"), accessGroups: ["premium"] },
      ],
    });

    const bytes = utf8Encode("<p>bodytext</p>");
    const contentEncodings = ["first", "second", "first"];
    const sealer = new Sealer(/** @type {any} */ (sealerConfig()));
    sealer.resource(RESOURCE_ID, { section: "politics" });
    sealer.content(
      "bodytext",
      {
        bytes,
        contentType: CONTENT_TYPE,
        contentEncodings,
      },
      { accessGroups: ["premium"] },
    );
    bytes.fill(0);
    contentEncodings.reverse();
    contentEncodings.push("late");
    const sealed = await sealer.seal();
    const actual = JSON.parse(
      JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
    );

    assert.deepEqual(actual.contentData.bodytext.contentEncodings, ["first", "second", "first"]);
    const { contentEncodings: layers, ...actualRecord } = actual.contentData.bodytext;
    assert.deepEqual(actualRecord, expected.contentData.bodytext);
    assert.equal(
      actual.sealedContent.bodytext,
      expected.sealedContent.bodytext,
      "base encrypted the supplied descriptor bytes unchanged despite its declared layers",
    );
    assert.deepEqual(actual.issuerData, expected.issuerData);
    assert.equal(payloadOf(actual.resourceJWT), payloadOf(expected.resourceJWT));
    assert.deepEqual(layers, ["first", "second", "first"]);
  });

  test("an explicit representation with no layers preserves the legacy render", async () => {
    const { sealerConfig } = await world();
    const expected = await render(new Sealer(/** @type {any} */ (sealerConfig())));

    const sealer = new Sealer(/** @type {any} */ (sealerConfig()));
    sealer.resource(RESOURCE_ID, { section: "politics" });
    sealer.content(
      "bodytext",
      {
        bytes: utf8Encode("<p>bodytext</p>"),
        contentType: CONTENT_TYPE,
        contentEncodings: [],
      },
      { accessGroups: ["premium"] },
    );
    const sealed = await sealer.seal();
    const actual = JSON.parse(
      JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
    );

    assert.equal(Object.hasOwn(actual.contentData.bodytext, "contentEncodings"), false);
    const { resourceJWT: expectedJwt, ...expectedRest } = expected;
    const { resourceJWT: actualJwt, ...actualRest } = actual;
    assert.equal(JSON.stringify(actualRest), JSON.stringify(expectedRest));
    assert.equal(payloadOf(actualJwt), payloadOf(expectedJwt));
  });

  test("one content key, ciphertext and wrap set per coordinate, whatever the issuer count", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const one = await render(new Sealer(/** @type {any} */ (sealerConfig())));
    const three = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            issuers: [
              issuerConfig(ISSUER_NAME),
              issuerConfig(FALLBACK_ISSUER_NAME),
              issuerConfig(THIRD_ISSUER_NAME),
            ],
          })
        ),
      ),
    );

    assert.equal(JSON.stringify(three.contentData), JSON.stringify(one.contentData));
    assert.equal(JSON.stringify(three.sealedContent), JSON.stringify(one.sealedContent));
    assert.deepEqual(Object.keys(three.issuerData), [
      ISSUER_NAME,
      FALLBACK_ISSUER_NAME,
      THIRD_ISSUER_NAME,
    ]);
  });
});

describe("One wrap strategy owns the shared content-key entries", () => {
  test("strategy shape is checked at construction, with a valid control", async () => {
    const { sealerConfig } = await world();
    const cases = [
      ["null", null],
      ["an array", []],
      ["a string", "ordinary"],
      ["an empty object", {}],
      ["only aad", { aad: () => undefined }],
      ["only entry", { entry: (/** @type {any} */ wrap) => wrap }],
    ];

    for (const [label, contentKeyWrapStrategy] of cases) {
      assert.throws(
        () => new Sealer(/** @type {any} */ (sealerConfig({ contentKeyWrapStrategy }))),
        (/** @type {any} */ error) => {
          assert.equal(error.code, "bad_config");
          assert.match(
            error.message,
            /contentKeyWrapStrategy is an object with aad\(coordinate\) and entry\(wrap\)/,
          );
          return true;
        },
        label,
      );
    }

    assert.ok(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            contentKeyWrapStrategy: {
              aad: () => undefined,
              entry: (/** @type {any} */ wrap) => wrap,
            },
          })
        ),
      ),
    );
  });

  test("the strategy names the aad and writes the entry", async () => {
    const { sealerConfig } = await world();
    const strategy = {
      aad: (/** @type {any} */ coordinate) =>
        utf8Encode(
          `probe|${coordinate.renderId}|${coordinate.contentName}|${coordinate.accessGroup}|${coordinate.t}`,
        ),
      entry: (/** @type {any} */ wrap) => ({ ...wrap, probe: "probe-v1" }),
    };
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            contentKeyWrapStrategy: strategy,
            issuerSupplyPlanFor: () => ({}),
          })
        ),
      ),
    );

    const entries = page.contentData.bodytext.keys.premium;
    assert.deepEqual(
      entries.map((/** @type {any} */ entry) => entry.probe),
      ["probe-v1", "probe-v1"],
    );
    assert.deepEqual(
      entries.map((/** @type {any} */ entry) => entry.t),
      PERIODS,
    );

    const entry = entries[0];
    const periodKey = await fixedPeriodKeySupply().derive("premium", entry.t);
    const nonce = base64urlDecode(entry.nonce);
    const wrapped = base64urlDecode(entry.key);
    await assert.rejects(decrypt(periodKey, nonce, wrapped), "the entry does not open unbound");
    const contentKey = await decrypt(
      periodKey,
      nonce,
      wrapped,
      strategy.aad({
        renderId: page.resource.renderId,
        contentName: "bodytext",
        accessGroup: "premium",
        t: entry.t,
      }),
    );
    assert.equal(contentKey.length, 16);
  });

  test("a plan requiring another wrap than the render selected is refused", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const other = { aad: () => undefined, entry: (/** @type {any} */ wrap) => wrap };
    const { config, counts } = watched(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_NAME), issuerConfig(FALLBACK_ISSUER_NAME)],
        contentKeyWrapStrategy: ordinaryContentKeyWrap,
        issuerSupplyPlanFor: (/** @type {any} */ issuer) =>
          issuer.issuerName === FALLBACK_ISSUER_NAME ? { contentKeyWrap: other } : {},
      }),
    );

    await assert.rejects(
      render(new Sealer(/** @type {any} */ (config))),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_config");
        return true;
      },
    );
    assert.deepEqual(counts, { random: 0, plan: 0, derive: 0, seal: 0, sign: 0 });
  });

  test("the hooks a render wraps with are the ones the strategy arrived with", async () => {
    const { sealerConfig } = await world();
    // A strategy is one decision for the render, read where it arrives. A
    // member replaced while the render is already planning would put a
    // second representation into entries the first ones stand beside.
    const strategy = {
      aad: () => undefined,
      entry: (/** @type {any} */ wrap) => ({ ...wrap, probe: "selected" }),
    };
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            contentKeyWrapStrategy: strategy,
            issuerSupplyPlanFor: () => {
              strategy.aad = () => utf8Encode("swapped");
              strategy.entry = (/** @type {any} */ wrap) => ({ ...wrap, probe: "swapped" });
              return {};
            },
          })
        ),
      ),
    );

    const entries = page.contentData.bodytext.keys.premium;
    assert.deepEqual(
      entries.map((/** @type {any} */ entry) => entry.probe),
      ["selected", "selected"],
    );
    const entry = entries[0];
    const periodKey = await fixedPeriodKeySupply().derive("premium", entry.t);
    const contentKey = await decrypt(
      periodKey,
      base64urlDecode(entry.nonce),
      base64urlDecode(entry.key),
    );
    assert.equal(
      contentKey.length,
      16,
      "the wraps were made under the aad the strategy arrived with",
    );
  });

  test("an entry the shared traversal cannot read is refused", async () => {
    const { sealerConfig } = await world();

    for (const entry of [
      () => null,
      () => undefined,
      () => "an entry",
      (/** @type {any} */ wrap) => ({ nonce: wrap.nonce, key: wrap.key }),
    ]) {
      await assert.rejects(
        render(
          new Sealer(
            /** @type {any} */ (
              sealerConfig({
                contentKeyWrapStrategy: { aad: () => undefined, entry },
              })
            ),
          ),
        ),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
  });

  test("an entry missing nonce or key is refused rather than replaced", async () => {
    const { sealerConfig } = await world();
    const cases = [
      ["nonce", (/** @type {any} */ wrap) => ({ t: wrap.t, key: wrap.key })],
      ["key", (/** @type {any} */ wrap) => ({ t: wrap.t, nonce: wrap.nonce })],
    ];

    for (const [member, entry] of cases) {
      await assert.rejects(
        render(
          new Sealer(
            /** @type {any} */ (
              sealerConfig({
                contentKeyWrapStrategy: { aad: () => undefined, entry },
              })
            ),
          ),
        ),
        (/** @type {any} */ error) => {
          assert.equal(error.code, "bad_config");
          assert.match(error.message, new RegExp(`entry carries ${member}, and this one does not`));
          return true;
        },
        member,
      );
    }
  });

  test("which issuer stands first decides no refusal", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const other = { aad: () => undefined, entry: (/** @type {any} */ wrap) => wrap };
    const composition = {
      contentKeyWrapStrategy: ordinaryContentKeyWrap,
      issuerSupplyPlanFor: (/** @type {any} */ issuer) =>
        issuer.issuerName === FALLBACK_ISSUER_NAME ? { contentKeyWrap: other } : {},
    };

    for (const issuers of [
      [issuerConfig(ISSUER_NAME), issuerConfig(FALLBACK_ISSUER_NAME)],
      [issuerConfig(FALLBACK_ISSUER_NAME), issuerConfig(ISSUER_NAME)],
    ]) {
      await assert.rejects(
        render(new Sealer(/** @type {any} */ (sealerConfig({ ...composition, issuers })))),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
  });
});

describe("An issuer receives exactly what its plan supplies", () => {
  test("the planner refuses an unusable declared value before any render work", async () => {
    const { sealerConfig } = await world();
    const cases = [
      ["a null plan", () => null, "bad_config", /supply plan for issuer .* is an object/],
      [
        "an unknown plan member",
        () => ({ later: true }),
        "unsupported_option",
        /supply plan has no later yet/,
      ],
      [
        "a direct map other than on or off",
        () => ({ directContentKeys: "yes" }),
        "bad_config",
        /direct content-key map .* is on or off/,
      ],
      [
        "supplied groups outside a list",
        () => ({ suppliedAccessGroups: "premium" }),
        "bad_config",
        /supplied accessGroups .* are a list/,
      ],
      [
        "an unknown supplied group",
        () => ({ suppliedAccessGroups: ["unwrapped"] }),
        "bad_config",
        /is supplied "unwrapped", which this render wraps nothing under/,
      ],
      [
        "reachable names outside a list",
        () => ({ reachableContentNames: "bodytext" }),
        "bad_config",
        /reachable contentNames .* are a list/,
      ],
      [
        "extra issuer members outside an object",
        () => ({ issuerMembers: [] }),
        "bad_config",
        /extra issuer members .* are an object/,
      ],
      [
        "period delivery outside an object",
        () => ({ periodKeyDelivery: [] }),
        "bad_config",
        /period-key delivery .* is an object/,
      ],
      [
        "period delivery outside a typed set",
        () => ({ periodKeyDelivery: { premium: "chain" } }),
        "bad_config",
        /is \[exact\], \[chain\]/,
      ],
      [
        "duplicate period delivery",
        () => ({ periodKeyDelivery: { premium: ["chain", "chain"] } }),
        "bad_config",
        /is \[exact\], \[chain\]/,
      ],
      [
        "delivery for an unsupplied group",
        () => ({ suppliedAccessGroups: ["premium"], periodKeyDelivery: { free: ["exact"] } }),
        "bad_config",
        /unsupplied accessGroup "free"/,
      ],
    ];

    for (const [label, issuerSupplyPlanFor, code, message] of cases) {
      const { config, counts } = watched(
        sealerConfig({
          contentKeyWrapStrategy: ordinaryContentKeyWrap,
          issuerSupplyPlanFor,
        }),
      );
      await assert.rejects(
        render(new Sealer(/** @type {any} */ (config))),
        (/** @type {any} */ error) => {
          assert.equal(error.code, code);
          assert.match(error.message, message);
          return true;
        },
        label,
      );
      assert.deepEqual(counts, { random: 0, plan: 0, derive: 0, seal: 0, sign: 0 }, label);
    }
  });

  test("a non-function planner is refused at construction", async () => {
    const { sealerConfig } = await world();
    assert.throws(
      () => new Sealer(/** @type {any} */ (sealerConfig({ issuerSupplyPlanFor: {} }))),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_config");
        assert.match(error.message, /issuerSupplyPlanFor is a function/);
        return true;
      },
    );
  });

  test("a supplied group is emitted in render order and normalized values are frozen", async () => {
    const { sealerConfig } = await world();
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            contentKeyWrapStrategy: ordinaryContentKeyWrap,
            issuerSupplyPlanFor: () => ({
              suppliedAccessGroups: ["free", "premium"],
              directContentKeys: false,
            }),
          })
        ),
      ),
      {
        items: [
          { name: "bodytext", accessGroups: ["premium"] },
          { name: "sidebar", accessGroups: ["free"] },
        ],
      },
    );
    assert.deepEqual(Object.keys(page.issuerData[ISSUER_NAME].sealed.periodKeys), [
      "premium",
      "free",
    ]);

    const plan = normalizedIssuerSupplyPlan(
      ISSUER_NAME,
      {
        issuerMembers: { probe: ["probe-v1"] },
      },
      {
        accessGroups: ["premium"],
        items: [{ name: "bodytext", accessGroups: ["premium"] }],
        contentKeyWrapStrategy: ordinaryContentKeyWrap,
      },
    );
    assert.equal(Object.isFrozen(plan), true);
    assert.equal(Object.isFrozen(plan.issuerMembers), true);
    assert.equal(Object.isFrozen(plan.periodKeyDelivery), true);
    assert.equal(Object.isFrozen(plan.periodKeyDelivery.premium), true);
    assert.deepEqual(plan.periodKeyDelivery.premium, ["exact"]);
    assert.equal(plan.periodKeyDeliveryDeclared, false);
  });

  test("the planned groups, direct map and extra members reach the block", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            issuers: [issuerConfig(ISSUER_NAME), issuerConfig(FALLBACK_ISSUER_NAME)],
            contentKeyWrapStrategy: ordinaryContentKeyWrap,
            issuerSupplyPlanFor: (/** @type {any} */ issuer) =>
              issuer.issuerName === ISSUER_NAME
                ? {
                    suppliedAccessGroups: ["premium"],
                    directContentKeys: false,
                    reachableContentNames: ["bodytext"],
                    issuerMembers: { probe: ["probe-v1"] },
                  }
                : {},
          })
        ),
      ),
      {
        items: [
          { name: "bodytext", accessGroups: ["premium"] },
          { name: "sidebar", accessGroups: ["free"] },
        ],
      },
    );

    const planned = page.issuerData[ISSUER_NAME];
    assert.deepEqual(planned.probe, ["probe-v1"]);
    assert.deepEqual(Object.keys(planned), ["probe", "sealed", "unlockUrl", "keyId"]);
    assert.equal(Object.hasOwn(planned.sealed, "contentKeys"), false);
    assert.deepEqual(Object.keys(planned.sealed.periodKeys), ["premium"]);

    const ordinary = page.issuerData[FALLBACK_ISSUER_NAME];
    assert.equal(Object.hasOwn(ordinary, "probe"), false);
    assert.deepEqual(Object.keys(ordinary.sealed.contentKeys), ["bodytext", "sidebar"]);
    assert.deepEqual(Object.keys(ordinary.sealed.periodKeys), ["premium", "free"]);
  });

  test("an extra member cannot overwrite a member base owns", async () => {
    const { sealerConfig } = await world();
    for (const name of ["sealed", "unlockUrl", "keyId"]) {
      await assert.rejects(
        render(
          new Sealer(
            /** @type {any} */ (
              sealerConfig({
                contentKeyWrapStrategy: ordinaryContentKeyWrap,
                issuerSupplyPlanFor: () => ({ issuerMembers: { [name]: "taken over" } }),
              })
            ),
          ),
        ),
        (/** @type {any} */ error) => error.code === "bad_config",
        `a plan may not write ${name}`,
      );
    }
  });

  test("a planned content name the render does not carry refuses before any material is drawn", async () => {
    const { sealerConfig } = await world();
    const { config, counts } = watched(
      sealerConfig({
        contentKeyWrapStrategy: ordinaryContentKeyWrap,
        issuerSupplyPlanFor: () => ({ reachableContentNames: ["footnote"] }),
      }),
    );

    await assert.rejects(
      render(new Sealer(/** @type {any} */ (config))),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.deepEqual(counts, { random: 0, plan: 0, derive: 0, seal: 0, sign: 0 });
  });

  test("a planned content name outside the supplied groups refuses at the same boundary", async () => {
    const { sealerConfig } = await world();
    const { config, counts } = watched(
      sealerConfig({
        contentKeyWrapStrategy: ordinaryContentKeyWrap,
        issuerSupplyPlanFor: () => ({
          suppliedAccessGroups: ["premium"],
          reachableContentNames: ["bodytext", "sidebar"],
        }),
      }),
    );

    await assert.rejects(
      render(new Sealer(/** @type {any} */ (config))),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.deepEqual(counts, { random: 0, plan: 0, derive: 0, seal: 0, sign: 0 });
  });

  test("every protected item has a complete issuer route before render work", async () => {
    const { sealerConfig } = await world();
    const { config, counts } = watched(
      sealerConfig({
        contentKeyWrapStrategy: ordinaryContentKeyWrap,
        issuerSupplyPlanFor: () => ({
          suppliedAccessGroups: ["premium"],
          directContentKeys: false,
        }),
      }),
    );

    await assert.rejects(
      render(new Sealer(/** @type {any} */ (config)), {
        items: [
          { name: "bodytext", accessGroups: ["premium"] },
          { name: "sidebar", accessGroups: ["free"] },
        ],
      }),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_config");
        assert.match(error.message, /no complete issuer route for protected content "sidebar"/);
        return true;
      },
    );
    assert.deepEqual(counts, { random: 0, plan: 0, derive: 0, seal: 0, sign: 0 });
  });
});

describe("Every protected item keeps a planned issuer route", () => {
  test("two group-only issuer plans collectively cover the render", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            issuers: [issuerConfig(ISSUER_NAME), issuerConfig(FALLBACK_ISSUER_NAME)],
            contentKeyWrapStrategy: ordinaryContentKeyWrap,
            issuerSupplyPlanFor: (/** @type {any} */ issuer) =>
              issuer.issuerName === ISSUER_NAME
                ? { suppliedAccessGroups: ["premium"], directContentKeys: false }
                : { suppliedAccessGroups: ["free"], directContentKeys: false },
          })
        ),
      ),
      {
        items: [
          { name: "bodytext", accessGroups: ["premium"] },
          { name: "sidebar", accessGroups: ["free"] },
        ],
      },
    );

    assert.deepEqual(Object.keys(page.issuerData[ISSUER_NAME].sealed.periodKeys), ["premium"]);
    assert.equal(Object.hasOwn(page.issuerData[ISSUER_NAME].sealed, "contentKeys"), false);
    assert.deepEqual(Object.keys(page.issuerData[FALLBACK_ISSUER_NAME].sealed.periodKeys), [
      "free",
    ]);
    assert.equal(Object.hasOwn(page.issuerData[FALLBACK_ISSUER_NAME].sealed, "contentKeys"), false);
  });

  test("a direct-only render whose one plan drops the direct map refuses", async () => {
    const { sealerConfig } = await world();
    const sourceConfig = sealerConfig({
      issuerSupplyPlanFor: () => ({ directContentKeys: false }),
    });
    delete (/** @type {any} */ (sourceConfig).periodKeySupply);
    const { config, counts } = watched(sourceConfig);

    await assert.rejects(
      render(new Sealer(/** @type {any} */ (config)), {
        items: [{ name: "bodytext", accessGroups: [] }],
      }),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_config");
        assert.match(error.message, /content "bodytext"/);
        return true;
      },
    );
    assert.deepEqual(counts, { random: 0, plan: 0, derive: 0, seal: 0, sign: 0 });
  });
});

describe("Issuer order decides no plan", () => {
  test("each issuer is planned the same whichever order the render lists them in", async () => {
    const { issuerConfig, sealerConfig } = await world();
    /** @type {Record<string, any>[]} */
    const asked = [];
    const composition = () => ({
      contentKeyWrapStrategy: ordinaryContentKeyWrap,
      issuerSupplyPlanFor: (/** @type {any} */ issuer) => {
        const plan =
          issuer.issuerName === ISSUER_NAME
            ? {
                suppliedAccessGroups: ["premium"],
                directContentKeys: false,
                reachableContentNames: ["bodytext"],
              }
            : { suppliedAccessGroups: ["free"] };
        asked.push({ issuerName: issuer.issuerName, ...plan });
        return plan;
      },
    });
    const items = [
      { name: "bodytext", accessGroups: ["premium"] },
      { name: "sidebar", accessGroups: ["free"] },
    ];

    const forward = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            ...composition(),
            issuers: [issuerConfig(ISSUER_NAME), issuerConfig(FALLBACK_ISSUER_NAME)],
          })
        ),
      ),
      { items },
    );
    const reversed = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            ...composition(),
            issuers: [issuerConfig(FALLBACK_ISSUER_NAME), issuerConfig(ISSUER_NAME)],
          })
        ),
      ),
      { items },
    );

    // The plan each issuer was asked for, read back by name rather than by
    // the order the two renders walked.
    const byName = (/** @type {string} */ name) => asked.filter((plan) => plan.issuerName === name);
    assert.equal(byName(ISSUER_NAME).length, 2);
    assert.equal(JSON.stringify(byName(ISSUER_NAME)[0]), JSON.stringify(byName(ISSUER_NAME)[1]));
    assert.equal(
      JSON.stringify(byName(FALLBACK_ISSUER_NAME)[0]),
      JSON.stringify(byName(FALLBACK_ISSUER_NAME)[1]),
    );

    // And what each block was supplied, which is the same answer read off
    // the wire. The bytes differ: the render draws its entropy in the
    // order it walks the issuers.
    for (const page of [forward, reversed]) {
      assert.equal(Object.hasOwn(page.issuerData[ISSUER_NAME].sealed, "contentKeys"), false);
      assert.deepEqual(Object.keys(page.issuerData[ISSUER_NAME].sealed.periodKeys), ["premium"]);
      assert.deepEqual(Object.keys(page.issuerData[FALLBACK_ISSUER_NAME].sealed.contentKeys), [
        "bodytext",
        "sidebar",
      ]);
      assert.deepEqual(Object.keys(page.issuerData[FALLBACK_ISSUER_NAME].sealed.periodKeys), [
        "free",
      ]);
    }
    assert.deepEqual(Object.keys(forward.issuerData), [ISSUER_NAME, FALLBACK_ISSUER_NAME]);
    assert.deepEqual(Object.keys(reversed.issuerData), [FALLBACK_ISSUER_NAME, ISSUER_NAME]);
  });
});

/**
 * The declared family plan, as base's optional `familyPlan` seam hands it over.
 * Every case below starts from this and changes the one member under test, so a
 * refusal is about that member and never about a missing required one.
 *
 * @param {object} [overrides]
 */
function declaredExactPlan(overrides = {}) {
  return {
    periods: ["251023T1415", "251023T1430"],
    exactAt: async () => new Uint8Array(16).fill(7),
    ...overrides,
  };
}

/** @param {object} [chainOverrides] */
function declaredChainPlan(chainOverrides = {}) {
  return declaredExactPlan({
    chain: {
      geometry: { chainsPerDay: 2, periodMinutes: 15 },
      suppliedTs: ["251023T1415"],
      capabilityAt: async () => new Uint8Array(16).fill(9),
      ...chainOverrides,
    },
  });
}

/**
 * A supply that plans per family. Base still sees only labels and opaque
 * acquisitions, so these cases drive base's own contract for the seam rather
 * than any extension's way of filling it.
 *
 * @param {(accessGroup: string) => any} planFor
 */
function planningSupply(planFor) {
  return {
    derive: async () => new Uint8Array(16).fill(5),
    familyPlan: (/** @type {string} */ accessGroup) => planFor(accessGroup),
  };
}

/**
 * Every group the per-issuer chain-capability ceiling needs to be crossed. Nine
 * families ask for seventeen against a ceiling of sixteen: eight families carry
 * two members and the ninth carries one. That arithmetic stays written out
 * rather than read from `MAX_CHAIN_MEMBERS_PER_MESSAGE`, so a changed constant
 * turns the case red instead of following it.
 */
const NINE_FAMILIES = [
  "fam_a",
  "fam_b",
  "fam_c",
  "fam_d",
  "fam_e",
  "fam_f",
  "fam_g",
  "fam_h",
  "fam_i",
];

describe("The family-plan seam is base's own contract", () => {
  test("an unusable declared plan is refused before any material is drawn", async () => {
    const { sealerConfig } = await world();
    const cases = [
      [
        "a plan that is not an object",
        () => null,
        "bad_config",
        /period family plan for "premium" is an object/,
      ],
      [
        "a plan that is a list",
        () => [],
        "bad_config",
        /period family plan for "premium" is an object/,
      ],
      [
        "an unknown plan member",
        () => declaredExactPlan({ chainWindows: 2 }),
        "unsupported_option",
        /a period family plan has no chainWindows yet/,
      ],
      [
        "a plan that acquires no exact key",
        () => ({ periods: ["251023T1415"] }),
        "bad_config",
        /period family plan for "premium" acquires an exact key at each label/,
      ],
      [
        "planned periods outside a list",
        () => declaredExactPlan({ periods: "251023T1415" }),
        "bad_config",
        /periods for accessGroup "premium" is a nonempty list of unique binding-safe labels/,
      ],
      [
        "an empty period list",
        () => declaredExactPlan({ periods: [] }),
        "bad_config",
        /periods for accessGroup "premium"/,
      ],
      [
        "a repeated planned period",
        () => declaredExactPlan({ periods: ["251023T1415", "251023T1415"] }),
        "bad_config",
        /periods for accessGroup "premium"/,
      ],
      [
        "a planned period carrying the aad join",
        () => declaredExactPlan({ periods: ["251023T1415|251023T1430"] }),
        "bad_config",
        /periods for accessGroup "premium"/,
      ],
      [
        "a chain plan that is not an object",
        () => declaredExactPlan({ chain: "dca-period-chain-v1" }),
        "bad_config",
        /the chain plan for "premium" is an object/,
      ],
      [
        "an unknown chain member",
        () => declaredChainPlan({ windowStart: 29353680 }),
        "unsupported_option",
        /a chain family plan has no windowStart yet/,
      ],
      [
        "a chain plan without geometry",
        () => declaredChainPlan({ geometry: undefined }),
        "bad_config",
        /the chain plan for "premium" carries valid complete geometry/,
      ],
      [
        "a half geometry",
        () => declaredChainPlan({ geometry: { chainsPerDay: 2 } }),
        "bad_config",
        /the chain plan for "premium" carries valid complete geometry/,
      ],
      [
        "a geometry outside its bounds",
        () => declaredChainPlan({ geometry: { chainsPerDay: 4, periodMinutes: 1 } }),
        "bad_config",
        /the chain plan for "premium" carries valid complete geometry/,
      ],
      [
        "an unknown geometry member",
        () =>
          declaredChainPlan({
            geometry: { chainsPerDay: 2, periodMinutes: 15, windowMinutes: 720 },
          }),
        "unsupported_option",
        /chain geometry has no windowMinutes yet/,
      ],
      [
        "a chain plan that acquires no capability",
        () => declaredChainPlan({ capabilityAt: undefined }),
        "bad_config",
        /the chain plan for "premium" acquires a capability at each supplied label/,
      ],
      [
        "supplied chain labels outside a list",
        () => declaredChainPlan({ suppliedTs: "251023T1415" }),
        "bad_config",
        /supplied chain labels for accessGroup "premium" is a nonempty list of unique binding-safe labels/,
      ],
      [
        "a supplied chain label carrying the aad join",
        () => declaredChainPlan({ suppliedTs: ["251023T1415|251023T1430"] }),
        "bad_config",
        /supplied chain labels for accessGroup "premium"/,
      ],
      [
        // spec--period-key-chains.md Bounds: maxChainMembersPerFamily is 2.
        "a third supplied capability in one family",
        () =>
          declaredChainPlan({
            suppliedTs: ["251023T1145", "251023T2345", "251024T1145"],
          }),
        "bad_config",
        /the chain plan for "premium" supplies at most 2 capabilities/,
      ],
    ];

    for (const [label, planFor, code, message] of cases) {
      const { config, counts } = watched(
        sealerConfig({
          contentKeyWrapStrategy: ordinaryContentKeyWrap,
          periodKeySupply: planningSupply(/** @type {any} */ (planFor)),
        }),
      );
      await assert.rejects(
        render(new Sealer(/** @type {any} */ (config))),
        (/** @type {any} */ error) => {
          assert.equal(error.code, code, label);
          assert.match(error.message, /** @type {RegExp} */ (message), label);
          return true;
        },
        label,
      );
      // One access group on this render, so base asked the planner once
      // and drew nothing through the plan it got back.
      assert.deepEqual(counts, { random: 0, plan: 1, derive: 0, seal: 0, sign: 0 }, label);
    }
  });

  test("a chain delivery no supply can serve refuses before any material is drawn", async () => {
    const { sealerConfig } = await world();
    const cases = [
      [
        // No supply to ask, so the planner is never reached.
        "chain delivery on a publisher with no supply at all",
        { periodKeySupply: undefined },
        /chain delivery needs a configured period-family supply/,
        0,
      ],
      [
        "chain delivery on a family the plan gave no chain route",
        { periodKeySupply: planningSupply(() => declaredExactPlan()) },
        /issuer chain delivery for accessGroup "premium" has no configured chain family route/,
        1,
      ],
    ];

    for (const [label, supplyConfig, message, plan] of cases) {
      const { config, counts } = watched(
        sealerConfig({
          contentKeyWrapStrategy: ordinaryContentKeyWrap,
          issuerSupplyPlanFor: () => ({ periodKeyDelivery: { premium: ["chain"] } }),
          .../** @type {object} */ (supplyConfig),
        }),
      );
      await assert.rejects(
        render(new Sealer(/** @type {any} */ (config))),
        (/** @type {any} */ error) => {
          assert.equal(error.code, "bad_config", label);
          assert.match(error.message, /** @type {RegExp} */ (message), label);
          return true;
        },
        label,
      );
      assert.deepEqual(counts, { random: 0, plan, derive: 0, seal: 0, sign: 0 }, label);
    }
  });

  test("one issuer supply carries at most the chain capabilities the bounds allow", async () => {
    // spec--period-key-chains.md Bounds: maxChainMembersPerMessage is 16.
    // Eight two-member families and one one-member family ask for exactly
    // seventeen; the adjacent eight-family case below admits sixteen.
    const { sealerConfig } = await world();
    const { config, counts } = watched(
      sealerConfig({
        contentKeyWrapStrategy: ordinaryContentKeyWrap,
        periodKeySupply: planningSupply((accessGroup) =>
          declaredChainPlan({
            suppliedTs: accessGroup === "fam_i" ? ["251023T1145"] : ["251023T1145", "251023T2345"],
          }),
        ),
        issuerSupplyPlanFor: () => ({
          periodKeyDelivery: Object.fromEntries(NINE_FAMILIES.map((group) => [group, ["chain"]])),
        }),
      }),
    );

    await assert.rejects(
      render(new Sealer(/** @type {any} */ (config)), {
        items: [{ name: "bodytext", accessGroups: NINE_FAMILIES }],
      }),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_config");
        assert.match(
          error.message,
          /one issuer supply contains at most 16 period-chain capabilities/,
        );
        return true;
      },
    );
    // Every one of the nine families was planned, and no plan was drawn on.
    assert.deepEqual(counts, {
      random: 0,
      plan: NINE_FAMILIES.length,
      derive: 0,
      seal: 0,
      sign: 0,
    });
  });

  test("eight families at the same ceiling render, so the refusal is the count and not the plan", async () => {
    const { sealerConfig } = await world();
    const eight = NINE_FAMILIES.slice(0, 8);
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            contentKeyWrapStrategy: ordinaryContentKeyWrap,
            periodKeySupply: planningSupply(() =>
              declaredChainPlan({
                suppliedTs: ["251023T1145", "251023T2345"],
              }),
            ),
            issuerSupplyPlanFor: () => ({
              periodKeyDelivery: Object.fromEntries(eight.map((group) => [group, ["chain"]])),
            }),
          })
        ),
      ),
      { items: [{ name: "bodytext", accessGroups: eight }] },
    );

    const sealed = page.issuerData[ISSUER_NAME].sealed;
    assert.deepEqual(Object.keys(sealed.periodChainKeys), eight);
    assert.deepEqual(Object.keys(sealed.periodChainKeys.fam_a), ["251023T1145", "251023T2345"]);
  });

  test("a supplied key of the wrong width is refused at the coordinate that produced it", async () => {
    const { sealerConfig } = await world();
    const cases = [
      [
        "an exact key short of the period-key width",
        {
          periodKeySupply: planningSupply(() =>
            declaredExactPlan({ exactAt: async () => new Uint8Array(31) }),
          ),
        },
        {},
        /periodKey for accessGroup "premium" at "251023T1415" is 16 bytes/,
      ],
      [
        "a chain capability short of the period-key width",
        {
          periodKeySupply: planningSupply(() =>
            declaredChainPlan({ capabilityAt: async () => new Uint8Array(31) }),
          ),
        },
        { issuerSupplyPlanFor: () => ({ periodKeyDelivery: { premium: ["chain"] } }) },
        /periodChainKey for accessGroup "premium" at "251023T1415" is 16 bytes/,
      ],
    ];

    for (const [label, supplyConfig, planConfig, message] of cases) {
      const { config, counts } = watched(
        sealerConfig({
          contentKeyWrapStrategy: ordinaryContentKeyWrap,
          .../** @type {object} */ (supplyConfig),
          .../** @type {object} */ (planConfig),
        }),
      );
      await assert.rejects(
        render(new Sealer(/** @type {any} */ (config))),
        (/** @type {any} */ error) => {
          assert.equal(error.code, "bad_key", label);
          assert.match(error.message, /** @type {RegExp} */ (message), label);
          return true;
        },
        label,
      );
      // The width is read at acquisition, so the supply was asked; a
      // render that refuses there has still drawn no entropy and sealed
      // nothing.
      assert.ok(counts.plan > 0, `${label}: base asked for a family plan`);
      assert.ok(counts.derive > 0, `${label}: base drew a key through that plan`);
      assert.equal(counts.random, 0, label);
      assert.equal(counts.seal, 0, label);
      assert.equal(counts.sign, 0, label);
    }
  });
});
