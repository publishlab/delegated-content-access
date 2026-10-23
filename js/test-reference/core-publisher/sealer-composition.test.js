// @ts-check
//
// The Sealer's two composition roles, and the boundary they finish at.
//
// `contentKeyWrapStrategy` is selected once for a render, because
// each item record's `keys` is emitted once and every issuer reads the
// same entries. `issuerSupplyPlanFor` is asked once per issuer, and answers
// only what that issuer is supplied: which content names receive a sealed
// content key, which access groups its period material covers, the content
// names it has to be able to reach through those groups, and the extra members
// its block carries. A case about another member lays it over the whole-render
// plan, so the scope stays explicit.
//
// Both are resolved before the render draws its first random byte, asks the
// period-key supply, seals to an issuer or signs. A plan that cannot be served
// refuses with nothing produced, rather than rendering with a hole in it.

import { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../core-publisher/Sealer.js";
import { ordinaryContentKeyWrap } from "../../core-publisher/contentKeyWrap.js";
import {
  normalizedIssuerSupplyPlan,
  wholeRenderIssuerSupplyPlan,
} from "../../core-publisher/issuerSupplyPlan.js";
import { decrypt } from "../../core-shared/aead.js";
import { base64urlDecode, utf8Encode } from "../../core-shared/codec.js";
import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
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
} from "../../demo/scenarios/fixtures.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../support/keys.js";
import { deterministicEcdhFixtureSealing } from "../../tools/vector-fixtures/deterministicEcdhSealing.js";
import { sealerForRender } from "../../core-publisher/testing/sealerFactory.js";
import { portableTest, test } from "../support/portable-test.js";
import { openEcdhEnvelope } from "../support/ecdhEnvelope.js";
import { openRsaEnvelope } from "../support/rsaEnvelope.js";
import { contentAadOctets } from "../support/contentAadOctets.js";
import { contentKeyWrapNonceOctets } from "../support/contentKeyWrapNonceOctets.js";
import {
  periodKey,
  TEST_ISSUER_PRIVATE_KEY_PKCS8,
  TEST_ISSUER_PUBLIC_KEY_SPKI,
  TEST_RSA_ISSUER_PRIVATE_KEY_PKCS8,
  TEST_SIGNING_KEY_PKCS8,
} from "../support/keys.js";
import {
  sealerContentRepresentations,
  sealerIssuersRender,
  sealerIssuersSetup,
  sealerOriginRender,
  sealerOriginSetup,
} from "../support/sealerCases.js";
import {
  contentNamesOn,
  contentRecordOf,
  issuerBlockOf,
  issuerNamesOn,
  wrapGroupsOn,
  wrapsOf,
} from "../../test-lib/helpers/inspect.js";
import { contentKeyMap, periodKeyMap } from "../support/namedRecords.js";

const THIRD_ISSUER_NAME = "paywall_third_service";
const portableSealerIssuersTest = portableTest("portable-sealer-issuers");
const portableSealerDescriptorsTest = portableTest("portable-sealer-descriptors");
const PERIODS = ["251023T1400", "251023T1500"];

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
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
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

/**
 * The whole-render plan with `extra` laid over it, for a case about a member
 * other than the scope. `extra` may depend on the issuer.
 *
 * @param {object | ((issuer: any) => object)} extra
 */
function wholeWith(extra) {
  return (/** @type {any} */ issuer, /** @type {any} */ render) => ({
    ...wholeRenderIssuerSupplyPlan(issuer, render),
    ...(typeof extra === "function" ? extra(issuer) : extra),
  });
}

/** @param {string} token @returns {string} the compact JWT's header and payload */
function payloadOf(token) {
  return token.split(".").slice(0, 2).join(".");
}

/**
 * The origin case's one-item render through the Sealer factory, with the item
 * given as `value` and the arguments after it. A descriptor takes its options
 * third; a string or bytes take the content type third and the options
 * fourth.
 *
 * @param {unknown} value
 * @returns {Promise<any>}
 */
async function renderItemThroughFactory(value) {
  const sealer = await sealerForRender(sealerOriginSetup(AT, "sealer-origin"));
  const {
    resource,
    content: [item],
  } = sealerOriginRender();
  // The origin setup holds no period-key supply, so the item names no group:
  // a group there would ask for wraps the render cannot make.
  const options = {};
  sealer.resource(resource.resourceId, resource.data);
  if (typeof value === "string" || value instanceof Uint8Array) {
    sealer.content(item.name, value, item.contentType, options);
  } else {
    sealer.content(item.name, value, options);
  }
  const sealed = await sealer.seal();
  return JSON.parse(JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }));
}

/**
 * Two ciphertexts under one key and nonce whose plaintexts match: the body is
 * the same bytes, including the tag, because encoding declarations do not
 * enter the content AAD.
 *
 * @param {string} actual @param {string} expected @param {string} why
 */
function assertSameCiphertext(actual, expected, why) {
  const a = new Uint8Array(Buffer.from(actual, "base64url"));
  const e = new Uint8Array(Buffer.from(expected, "base64url"));
  assert.equal(a.length, e.length, why);
  assert.deepEqual(a.subarray(0, -16), e.subarray(0, -16), why);
  assert.deepEqual(
    a.subarray(-16),
    e.subarray(-16),
    `${why}: handling metadata does not enter the tag`,
  );
}

/**
 * A content-key-only factory render with each ECDH content-key envelope replaced
 * by its carrier width and the key it opens to at its coordinate. Each render
 * draws a fresh ephemeral key, so
 * two renders of one stream differ in their envelope bytes and in nothing an
 * issuer reads out of them. The signature is left out: ECDSA draws its own
 * nonce.
 *
 * @param {any} rendered
 */
async function comparableRender(rendered) {
  const { resourceJWT, issuerData, ...rest } = rendered;
  /** @param {string} text */
  const bytesOf = (text) => new Uint8Array(Buffer.from(text, "base64url"));
  /** @param {Uint8Array} bytes */
  const text = (bytes) => Buffer.from(bytes).toString("base64url");
  /** @type {any[]} */
  const issuers = [];
  for (const block of issuerData) {
    /** @type {{ contentName: string, key: { carrierBytes: number, opensTo: string } }[]} */
    const contentKeys = [];
    for (const { contentName, key: envelope } of block.sealed.contentKeys) {
      const opened = await openEcdhEnvelope(
        envelope,
        `dca-bind-key-envelope|c|${rendered.resource.renderId}|${contentName}`,
        TEST_ISSUER_PRIVATE_KEY_PKCS8,
      );
      contentKeys.push({
        contentName,
        key: { carrierBytes: bytesOf(envelope).length, opensTo: text(opened) },
      });
    }
    issuers.push({ ...block, sealed: { ...block.sealed, contentKeys } });
  }
  return { ...rest, issuerData: issuers, token: payloadOf(resourceJWT) };
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
    if (typeof plan.periodKeyAt === "function") {
      watchedPlan.periodKeyAt = (/** @type {string} */ t) => {
        counts.derive += 1;
        return plan.periodKeyAt(t);
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
 * A content-key-only configuration hands over no supply, and the watched config
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

test("fresh item keys are drawn; content and envelopes use zero nonce, period wraps derive it", async () => {
  const { sealerConfig } = await world();
  const config = sealerConfig();
  const random = config.random;
  /** @type {Uint8Array[]} */
  const draws = [];
  config.random = {
    bytes(n) {
      const bytes = random.bytes(n);
      draws.push(Uint8Array.from(bytes));
      return bytes;
    },
  };
  const page = await render(new Sealer(config), {
    items: [
      { name: "bodytext", accessGroups: ["premium"] },
      { name: "sidebar", accessGroups: ["premium"] },
    ],
  });
  const renderId = page.resource.renderId;
  /** @type {string[]} */
  const wrapNonces = [];
  for (const record of page.contentData) {
    const contentName = record.contentName;
    assert.equal(Object.hasOwn(record, "nonce"), false);
    for (const wrap of wrapsOf(page, contentName, "premium")) {
      assert.deepEqual(
        Object.keys(wrap).sort(),
        ["accessGroup", "key", "period"],
        "an ordinary entry is { accessGroup, period, key }",
      );
      const nonce = contentKeyWrapNonceOctets({
        renderId,
        contentName,
        accessGroup: "premium",
        t: wrap.period,
      });
      wrapNonces.push(Buffer.from(nonce).toString("hex"));
      const periodKey = await fixedPeriodKeySupply().derive("premium", wrap.period);
      assert.equal((await decrypt(periodKey, nonce, base64urlDecode(wrap.key))).length, 16);
    }
  }
  assert.equal(new Set(wrapNonces).size, 4, "two items at two periods derive four nonces");
  const sealed = issuerBlockOf(page, ISSUER_NAME).sealed;
  for (const { key: envelope } of [
    ...sealed.contentKeys,
    ...sealed.periodKeys.filter((record) => record.accessGroup === "premium"),
  ]) {
    assert.equal(base64urlDecode(/** @type {string} */ (envelope)).length, 97);
  }
  const encode = (/** @type {Uint8Array} */ bytes) => Buffer.from(bytes).toString("base64url");
  const keyAndRenderDraws = draws.filter((draw) => draw.length === 16).map(encode);
  assert.equal(keyAndRenderDraws.length, 3, "one render id and two independent content keys");
  assert.equal(new Set(keyAndRenderDraws).size, 3, "each item gets distinct fresh key bytes");
  const nonceDraws = draws.filter((draw) => draw.length === 12).map(encode);
  assert.equal(nonceDraws.length, 0, "ordinary envelopes and period wraps draw no nonce");
  assert.equal(draws.length, 3, "the render consumes only its id and two content keys");
});

describe("The whole-render composition is the render base already made", () => {
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

  test("the two roles named explicitly render what the world's defaults render", async () => {
    const { sealerConfig } = await world();
    const plain = await render(new Sealer(/** @type {any} */ (sealerConfig())));
    const composed = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            contentKeyWrapStrategy: ordinaryContentKeyWrap,
            issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
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

    const { bytes } = sealerContentRepresentations("<p>bodytext</p>");
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
      Object.hasOwn(contentRecordOf(expected, "bodytext"), "contentEncodings"),
      false,
      "legacy strings declare no additional representation layer",
    );
    assert.equal(
      Object.hasOwn(contentRecordOf(actual, "bodytext"), "contentEncodings"),
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
        {
          name: "bodytext",
          value: sealerContentRepresentations("<p>bodytext</p>").bytes,
          accessGroups: ["premium"],
        },
      ],
    });

    const { layered } = sealerContentRepresentations("<p>bodytext</p>");
    const declared = [...layered.contentEncodings];
    const sealer = new Sealer(/** @type {any} */ (sealerConfig()));
    sealer.resource(RESOURCE_ID, { section: "politics" });
    sealer.content("bodytext", layered, { accessGroups: ["premium"] });
    layered.bytes.fill(0);
    layered.contentEncodings.reverse();
    layered.contentEncodings.push("late");
    const sealed = await sealer.seal();
    const actual = JSON.parse(
      JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
    );

    assert.deepEqual(contentRecordOf(actual, "bodytext").contentEncodings, declared);
    const { contentEncodings: layers, ...actualRecord } = contentRecordOf(actual, "bodytext");
    assert.deepEqual(actualRecord, contentRecordOf(expected, "bodytext"));
    assertSameCiphertext(
      actual.sealedContent.bodytext,
      expected.sealedContent.bodytext,
      "base encrypted the supplied descriptor bytes unchanged despite its declared layers",
    );
    assert.deepEqual(actual.issuerData, expected.issuerData);
    assert.equal(payloadOf(actual.resourceJWT), payloadOf(expected.resourceJWT));
    assert.deepEqual(layers, declared);
  });

  test("an explicit representation with no layers preserves the legacy render", async () => {
    const { sealerConfig } = await world();
    const expected = await render(new Sealer(/** @type {any} */ (sealerConfig())));

    const sealer = new Sealer(/** @type {any} */ (sealerConfig()));
    sealer.resource(RESOURCE_ID, { section: "politics" });
    sealer.content("bodytext", sealerContentRepresentations("<p>bodytext</p>").unlayered, {
      accessGroups: ["premium"],
    });
    const sealed = await sealer.seal();
    const actual = JSON.parse(
      JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
    );

    assert.equal(Object.hasOwn(contentRecordOf(actual, "bodytext"), "contentEncodings"), false);
    const { resourceJWT: expectedJwt, ...expectedRest } = expected;
    const { resourceJWT: actualJwt, ...actualRest } = actual;
    assert.equal(JSON.stringify(actualRest), JSON.stringify(expectedRest));
    assert.equal(payloadOf(actualJwt), payloadOf(expectedJwt));
  });

  // Portable twins of the three cases above: each renders the origin case's
  // item through the factory twice on one stream, once as the string and once
  // in the representation under test. Changing a value after content() tests
  // the Sealer's snapshot, which a bridge cannot reach: it copies the
  // arguments at the call. That half stays in the direct cases.
  portableSealerDescriptorsTest(
    "through the Sealer factory, byte input seals what UTF-8 string input seals",
    async () => {
      const { string, bytes } = sealerContentRepresentations(sealerOriginRender().content[0].value);
      const expected = await renderItemThroughFactory(string);
      const actual = await renderItemThroughFactory(bytes);

      for (const rendered of [expected, actual]) {
        for (const record of rendered.contentData) {
          assert.equal(Object.hasOwn(record, "contentEncodings"), false);
        }
      }
      assert.deepEqual(await comparableRender(actual), await comparableRender(expected));
    },
  );

  portableSealerDescriptorsTest(
    "through the Sealer factory, a descriptor's layers reach the wire in order and base seals its bytes unchanged",
    async () => {
      const { string, layered } = sealerContentRepresentations(
        sealerOriginRender().content[0].value,
      );
      const declared = [...layered.contentEncodings];
      const expected = await renderItemThroughFactory(string);
      const actual = await renderItemThroughFactory(layered);

      const [name] = contentNamesOn(expected);
      assert.deepEqual(contentNamesOn(actual), [name]);
      const { contentEncodings: layers, ...record } = contentRecordOf(actual, name);
      assert.deepEqual(layers, declared);
      assert.deepEqual(record, contentRecordOf(expected, name));
      assertSameCiphertext(
        actual.sealedContent[name],
        expected.sealedContent[name],
        "base encrypted the descriptor bytes unchanged despite its declared layers",
      );
      const {
        contentData: actualData,
        sealedContent: actualSealed,
        ...actualRest
      } = await comparableRender(actual);
      const {
        contentData: expectedData,
        sealedContent: expectedSealed,
        ...expectedRest
      } = await comparableRender(expected);
      assert.deepEqual(actualRest, expectedRest);
    },
  );

  portableSealerDescriptorsTest(
    "through the Sealer factory, a descriptor with no layers renders what the string renders",
    async () => {
      const { string, unlayered } = sealerContentRepresentations(
        sealerOriginRender().content[0].value,
      );
      const expected = await renderItemThroughFactory(string);
      const actual = await renderItemThroughFactory(unlayered);

      for (const record of actual.contentData) {
        assert.equal(Object.hasOwn(record, "contentEncodings"), false);
      }
      assert.deepEqual(await comparableRender(actual), await comparableRender(expected));
    },
  );

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
    assert.deepEqual(issuerNamesOn(three), [ISSUER_NAME, FALLBACK_ISSUER_NAME, THIRD_ISSUER_NAME]);
  });

  portableSealerIssuersTest(
    "through the Sealer factory, an RSA-OAEP issuer beside an ECDH one changes no shared entry and opens to the same keys",
    async () => {
      // Two renders of one page through the factory, on the same stream: the
      // first with the ECDH issuer alone, the second with an RSA-OAEP issuer
      // after it. The reference reads the stream in this order: render id, the
      // content key of each item. ECDH envelopes use implicit zero nonces.
      // A period wrap derives its nonce from its coordinate and draws nothing.
      // An RSA-OAEP envelope takes its padding
      // randomness from the platform and draws nothing, so the second issuer
      // leaves every shared entry where the first render put it.
      /** @param {boolean} withRsaIssuer */
      const renderPage = async (withRsaIssuer) => {
        const sealer = await sealerForRender(sealerIssuersSetup(withRsaIssuer));
        const { resource, content } = sealerIssuersRender();
        sealer.resource(resource.resourceId, resource.data);
        for (const item of content) {
          sealer.content(item.name, item.value, item.contentType, {
            accessGroups: item.accessGroups,
          });
        }
        const rendered = await sealer.seal();
        return JSON.parse(
          JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
        );
      };
      const one = await renderPage(false);
      const two = await renderPage(true);

      assert.equal(JSON.stringify(two.contentData), JSON.stringify(one.contentData));
      assert.equal(JSON.stringify(two.sealedContent), JSON.stringify(one.sealedContent));
      assert.deepEqual(issuerNamesOn(two), [ISSUER_NAME, FALLBACK_ISSUER_NAME]);

      // The expected values come from Node's Buffer and WebCrypto, so no call
      // here reaches the test target.
      const setup = sealerIssuersSetup(true);
      const stream = setup.randomStream;
      const periodKeys = setup.fixedPeriodKeys.premium;
      /** @param {number} from @param {number} to */
      const drawn = (from, to) => Buffer.from(stream.subarray(from, to)).toString("base64url");
      /** @param {string} text */
      const bytesOf = (text) => new Uint8Array(Buffer.from(text, "base64url"));
      /** @param {Uint8Array} bytes */
      const text = (bytes) => Buffer.from(bytes).toString("base64url");
      const renderId = two.resource.renderId;
      assert.equal(renderId, drawn(0, 16));
      const items = [
        { name: "bodytext", key: drawn(16, 32) },
        { name: "sidebar", key: drawn(32, 48) },
      ];
      const periods = /** @type {const} */ (["251023T1400", "251023T1500"]);

      const offset = 48;
      for (const item of items) {
        assert.equal(Object.hasOwn(contentRecordOf(two, item.name), "nonce"), false);
        const contentKey = await crypto.subtle.importKey(
          "raw",
          bytesOf(item.key),
          { name: "AES-GCM" },
          false,
          ["decrypt"],
        );
        await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: new Uint8Array(12),
            additionalData: contentAadOctets(two, item.name),
          },
          contentKey,
          bytesOf(two.sealedContent[item.name]),
        );
        const entries = wrapsOf(two, item.name, "premium");
        assert.deepEqual(
          entries.map((/** @type {any} */ e) => e.period),
          periods,
        );
        for (const entry of entries) {
          assert.deepEqual(Object.keys(entry).sort(), ["accessGroup", "key", "period"]);
          const nonce = contentKeyWrapNonceOctets({
            renderId,
            contentName: item.name,
            accessGroup: "premium",
            t: entry.period,
          });
          const periodKey = await crypto.subtle.importKey(
            "raw",
            periodKeys[/** @type {"251023T1400" | "251023T1500"} */ (entry.period)],
            { name: "AES-GCM" },
            false,
            ["decrypt"],
          );
          const wrapped = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: nonce },
            periodKey,
            bytesOf(entry.key),
          );
          assert.equal(
            text(new Uint8Array(wrapped)),
            item.key,
            `the ${item.name} ${entry.period} wrap opens to that item's content key`,
          );
        }
      }

      // The ECDH issuer's envelopes carry no nonce and independently open
      // to the drawn content keys and fixed period keys.
      const ecdhBlock = issuerBlockOf(two, ISSUER_NAME).sealed;
      const ecdh = {
        contentKeys: contentKeyMap(ecdhBlock.contentKeys),
        periodKeys: periodKeyMap(ecdhBlock.periodKeys),
      };
      for (const item of items) {
        assert.equal(bytesOf(ecdh.contentKeys[item.name]).length, 97);
        const opened = await openEcdhEnvelope(
          ecdh.contentKeys[item.name],
          `dca-bind-key-envelope|c|${renderId}|${item.name}`,
          TEST_ISSUER_PRIVATE_KEY_PKCS8,
        );
        assert.equal(text(opened), item.key);
      }
      for (const t of periods) {
        assert.equal(bytesOf(ecdh.periodKeys.premium[t]).length, 97);
        const opened = await openEcdhEnvelope(
          ecdh.periodKeys.premium[t],
          `dca-bind-key-envelope|p|${renderId}|premium|${t}`,
          TEST_ISSUER_PRIVATE_KEY_PKCS8,
        );
        assert.equal(text(opened), text(periodKeys[t]));
      }
      assert.equal(offset, stream.length, "the render reads the stream to its last byte");

      // The RSA-OAEP issuer's envelopes are one 2048-bit block each, and open
      // under its private key to the same keys at the same coordinates.
      const rsaBlock = issuerBlockOf(two, FALLBACK_ISSUER_NAME).sealed;
      const rsa = {
        contentKeys: contentKeyMap(rsaBlock.contentKeys),
        periodKeys: periodKeyMap(rsaBlock.periodKeys),
      };
      assert.deepEqual(Object.keys(rsa.contentKeys), ["bodytext", "sidebar"]);
      assert.deepEqual(Object.keys(rsa.periodKeys.premium), periods);
      for (const item of items) {
        assert.equal(rsa.contentKeys[item.name].length, 342);
        const opened = await openRsaEnvelope(
          rsa.contentKeys[item.name],
          `dca-bind-key-envelope|c|${renderId}|${item.name}`,
          TEST_RSA_ISSUER_PRIVATE_KEY_PKCS8,
        );
        assert.equal(text(opened), item.key);
      }
      for (const t of periods) {
        assert.equal(rsa.periodKeys.premium[t].length, 342);
        const opened = await openRsaEnvelope(
          rsa.periodKeys.premium[t],
          `dca-bind-key-envelope|p|${renderId}|premium|${t}`,
          TEST_RSA_ISSUER_PRIVATE_KEY_PKCS8,
        );
        assert.equal(text(opened), text(periodKeys[t]));
      }
    },
  );
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
    /** @type {any[]} */
    const wraps = [];
    let aadCalls = 0;
    const strategy = {
      aad: (/** @type {any} */ coordinate) => {
        aadCalls += 1;
        return utf8Encode(
          `probe|${coordinate.renderId}|${coordinate.contentName}|${coordinate.accessGroup}|${coordinate.t}`,
        );
      },
      entry: (/** @type {any} */ wrap) => {
        wraps.push({ ...wrap });
        return { ...wrap, probe: "probe-v1" };
      },
    };
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            contentKeyWrapStrategy: strategy,
            issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
          })
        ),
      ),
    );

    const entries = wrapsOf(page, "bodytext", "premium");
    assert.deepEqual(
      entries.map((/** @type {any} */ entry) => entry.probe),
      ["probe-v1", "probe-v1"],
    );
    assert.deepEqual(
      entries.map((/** @type {any} */ entry) => entry.period),
      PERIODS,
    );
    assert.deepEqual(
      wraps.map((wrap) => Object.keys(wrap).sort()),
      [
        ["key", "t"],
        ["key", "t"],
      ],
      "the strategy receives no nonce to write",
    );
    assert.equal(aadCalls, 2, "the selected aad is asked once per wrap");

    const entry = entries[0];
    const coordinate = {
      renderId: page.resource.renderId,
      contentName: "bodytext",
      accessGroup: "premium",
      t: entry.period,
    };
    const aad = strategy.aad(coordinate);
    const periodKey = await fixedPeriodKeySupply().derive("premium", entry.period);
    const wrapped = base64urlDecode(entry.key);
    await assert.rejects(
      decrypt(periodKey, contentKeyWrapNonceOctets(coordinate), wrapped),
      "the entry does not open under the ordinary transcript",
    );
    await assert.rejects(
      decrypt(periodKey, contentKeyWrapNonceOctets(coordinate), wrapped, aad),
      "the selected aad is part of the nonce transcript, not only of GCM",
    );
    const contentKey = await decrypt(
      periodKey,
      contentKeyWrapNonceOctets({ ...coordinate, aad }),
      wrapped,
      aad,
    );
    assert.equal(contentKey.length, 16);
  });

  test("a strategy aad that is not bytes is refused before a wrap is written", async () => {
    const { sealerConfig } = await world();
    for (const aad of [() => "probe", () => [1, 2], () => Promise.resolve(new Uint8Array(1))]) {
      await assert.rejects(
        render(
          new Sealer(
            /** @type {any} */ (
              sealerConfig({
                contentKeyWrapStrategy: { aad, entry: (/** @type {any} */ wrap) => wrap },
              })
            ),
          ),
        ),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
  });

  test("the aad bytes the strategy returned seal the wrap, even if it changes them later", async () => {
    const { sealerConfig } = await world();
    const original = Uint8Array.of(1, 2, 3);
    const strategy = {
      aad: () => {
        const aad = Uint8Array.from(original);
        // The strategy still owns the buffer: it changes it while the nonce digest is pending.
        queueMicrotask(() => aad.fill(9));
        return aad;
      },
      entry: (/** @type {any} */ wrap) => wrap,
    };
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            contentKeyWrapStrategy: strategy,
            issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
          })
        ),
      ),
    );
    for (const entry of wrapsOf(page, "bodytext", "premium")) {
      const coordinate = {
        renderId: page.resource.renderId,
        contentName: "bodytext",
        accessGroup: "premium",
        t: entry.period,
        aad: original,
      };
      const contentKey = await decrypt(
        await fixedPeriodKeySupply().derive("premium", entry.period),
        contentKeyWrapNonceOctets(coordinate),
        base64urlDecode(entry.key),
        original,
      );
      assert.equal(contentKey.length, 16, entry.period);
    }
  });

  test("a plan requiring another wrap than the render selected is refused", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const other = { aad: () => undefined, entry: (/** @type {any} */ wrap) => wrap };
    const { config, counts } = watched(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_NAME), issuerConfig(FALLBACK_ISSUER_NAME)],
        contentKeyWrapStrategy: ordinaryContentKeyWrap,
        issuerSupplyPlanFor: wholeWith((/** @type {any} */ issuer) =>
          issuer.issuerName === FALLBACK_ISSUER_NAME ? { contentKeyWrap: other } : {},
        ),
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
            issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) => {
              strategy.aad = () => utf8Encode("swapped");
              strategy.entry = (/** @type {any} */ wrap) => ({ ...wrap, probe: "swapped" });
              return wholeRenderIssuerSupplyPlan(issuer, render);
            },
          })
        ),
      ),
    );

    const entries = wrapsOf(page, "bodytext", "premium");
    assert.deepEqual(
      entries.map((/** @type {any} */ entry) => entry.probe),
      ["selected", "selected"],
    );
    const entry = entries[0];
    const periodKey = await fixedPeriodKeySupply().derive("premium", entry.period);
    const contentKey = await decrypt(
      periodKey,
      contentKeyWrapNonceOctets({
        renderId: page.resource.renderId,
        contentName: "bodytext",
        accessGroup: "premium",
        t: entry.period,
      }),
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
      (/** @type {any} */ wrap) => ({ key: wrap.key }),
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

  test("an entry missing t or key is refused rather than replaced", async () => {
    const { sealerConfig } = await world();
    const cases = [
      ["t", (/** @type {any} */ wrap) => ({ key: wrap.key })],
      ["key", (/** @type {any} */ wrap) => ({ t: wrap.t })],
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

  test("an entry that names its own accessGroup or period is refused: the Sealer writes the coordinate", async () => {
    // The wire record is `{accessGroup, period, ...entry}`. An entry member
    // with either name would collide with the coordinate the Sealer writes,
    // so the strategy may not supply one, not even the same value.
    const { sealerConfig } = await world();
    const cases = [
      ["accessGroup", (/** @type {any} */ wrap) => ({ ...wrap, accessGroup: "premium" })],
      ["period", (/** @type {any} */ wrap) => ({ ...wrap, period: wrap.t })],
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
          assert.match(error.message, new RegExp(`leaves ${member} to the Sealer`));
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
      issuerSupplyPlanFor: wholeWith((/** @type {any} */ issuer) =>
        issuer.issuerName === FALLBACK_ISSUER_NAME ? { contentKeyWrap: other } : {},
      ),
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
        "supplied groups outside a list",
        wholeWith({ suppliedAccessGroups: "premium" }),
        "bad_config",
        /supplied accessGroups .* are a list/,
      ],
      [
        "an unknown supplied group",
        wholeWith({ suppliedAccessGroups: ["unwrapped"] }),
        "bad_config",
        /is supplied "unwrapped", which this render wraps nothing under/,
      ],
      [
        "reachable names outside a list",
        wholeWith({ reachableContentNames: "bodytext" }),
        "bad_config",
        /reachable contentNames .* are a list/,
      ],
      [
        "extra issuer members outside an object",
        wholeWith({ issuerMembers: [] }),
        "bad_config",
        /extra issuer members .* are an object/,
      ],
      [
        "period delivery outside an object",
        wholeWith({ periodKeyDelivery: [] }),
        "bad_config",
        /period-key delivery .* is an object/,
      ],
      [
        "period delivery outside a typed set",
        wholeWith({ periodKeyDelivery: { premium: "chain-keys" } }),
        "bad_config",
        /is \[period-keys\], \[chain-keys\]/,
      ],
      [
        "duplicate period delivery",
        wholeWith({ periodKeyDelivery: { premium: ["chain-keys", "chain-keys"] } }),
        "bad_config",
        /is \[period-keys\], \[chain-keys\]/,
      ],
      [
        "delivery for an unsupplied group",
        wholeWith({
          suppliedAccessGroups: ["premium"],
          periodKeyDelivery: { free: ["period-keys"] },
        }),
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
              contentKeyNames: [],
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
    assert.deepEqual(
      Object.keys(periodKeyMap(issuerBlockOf(page, ISSUER_NAME).sealed.periodKeys)),
      ["premium", "free"],
    );

    const plan = normalizedIssuerSupplyPlan(
      ISSUER_NAME,
      {
        contentKeyNames: [],
        suppliedAccessGroups: ["premium"],
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
    assert.deepEqual(plan.periodKeyDelivery.premium, ["period-keys"]);
    assert.equal(plan.periodKeyDeliveryDeclared, false);
  });

  test("the planned groups, content-key records and extra members reach the block", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            issuers: [issuerConfig(ISSUER_NAME), issuerConfig(FALLBACK_ISSUER_NAME)],
            contentKeyWrapStrategy: ordinaryContentKeyWrap,
            issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) =>
              issuer.issuerName === ISSUER_NAME
                ? {
                    suppliedAccessGroups: ["premium"],
                    contentKeyNames: [],
                    reachableContentNames: ["bodytext"],
                    issuerMembers: { probe: ["probe-v1"] },
                  }
                : wholeRenderIssuerSupplyPlan(issuer, render),
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

    const planned = issuerBlockOf(page, ISSUER_NAME);
    assert.deepEqual(planned.probe, ["probe-v1"]);
    assert.deepEqual(Object.keys(planned), ["issuerName", "probe", "sealed", "keyId"]);
    assert.equal(Object.hasOwn(planned.sealed, "contentKeys"), false);
    assert.deepEqual(Object.keys(periodKeyMap(planned.sealed.periodKeys)), ["premium"]);

    const whole = issuerBlockOf(page, FALLBACK_ISSUER_NAME);
    assert.equal(Object.hasOwn(whole, "probe"), false);
    assert.deepEqual(Object.keys(contentKeyMap(whole.sealed.contentKeys)), ["bodytext", "sidebar"]);
    assert.deepEqual(Object.keys(periodKeyMap(whole.sealed.periodKeys)), ["premium", "free"]);
  });

  test("an extra member cannot overwrite a member base owns", async () => {
    const { sealerConfig } = await world();
    for (const name of ["issuerName", "sealed", "unlockUrl", "keyId"]) {
      await assert.rejects(
        render(
          new Sealer(
            /** @type {any} */ (
              sealerConfig({
                contentKeyWrapStrategy: ordinaryContentKeyWrap,
                issuerSupplyPlanFor: wholeWith({ issuerMembers: { [name]: "taken over" } }),
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
        issuerSupplyPlanFor: wholeWith({ reachableContentNames: ["footnote"] }),
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
          contentKeyNames: [],
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
          contentKeyNames: [],
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

  test("issuer routes are complete without publisher endpoint configuration", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const rendered = await render(
      new Sealer(sealerConfig({ issuers: [issuerConfig(ISSUER_NAME)] })),
    );
    assert.equal(Object.hasOwn(issuerBlockOf(rendered, ISSUER_NAME), "unlockUrl"), false);
    assert.ok(contentKeyMap(issuerBlockOf(rendered, ISSUER_NAME).sealed.contentKeys).bodytext);
  });

  test("an issuer with an empty unlockUrl beside a usable route still publishes", async () => {
    // The empty-endpoint issuer keeps its configured scope: here it holds the
    // group's wraps, which a client holding that period key can still use,
    // while the usable issuer carries the item's complete route.
    const { issuerConfig, sealerConfig } = await world();
    const rendered = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            issuers: [
              { ...issuerConfig(ISSUER_NAME), unlockUrl: "" },
              issuerConfig(FALLBACK_ISSUER_NAME),
            ],
            issuerSupplyPlanFor: (/** @type {any} */ issuer) =>
              issuer.issuerName === ISSUER_NAME
                ? { contentKeyNames: [], suppliedAccessGroups: ["premium"] }
                : { contentKeyNames: ["bodytext"], suppliedAccessGroups: [] },
          })
        ),
      ),
    );

    assert.equal(Object.hasOwn(issuerBlockOf(rendered, ISSUER_NAME), "unlockUrl"), false);
    assert.deepEqual(Object.keys(issuerBlockOf(rendered, ISSUER_NAME).sealed), ["periodKeys"]);
    assert.deepEqual(
      Object.keys(contentKeyMap(issuerBlockOf(rendered, FALLBACK_ISSUER_NAME).sealed.contentKeys)),
      ["bodytext"],
    );
    assert.deepEqual(
      wrapsOf(rendered, "bodytext", "premium").map((/** @type {any} */ entry) => entry.period),
      PERIODS,
    );
  });

  test("an ungrouped item beside a grouped one still needs its item-key route before render work", async () => {
    for (const [label, accessGroups] of [
      ["omitted", undefined],
      ["empty", []],
    ]) {
      const { sealerConfig } = await world();
      const { config, counts } = watched(
        sealerConfig({
          contentKeyWrapStrategy: ordinaryContentKeyWrap,
          issuerSupplyPlanFor: () => ({
            suppliedAccessGroups: ["premium"],
            contentKeyNames: ["bodytext"],
          }),
        }),
      );

      await assert.rejects(
        render(new Sealer(/** @type {any} */ (config)), {
          items: [
            { name: "bodytext", accessGroups: ["premium"] },
            { name: "sidebar", accessGroups: /** @type {any} */ (accessGroups) },
          ],
        }),
        (/** @type {any} */ error) => {
          assert.equal(error.code, "bad_config", label);
          assert.match(
            error.message,
            /no complete issuer route for protected content "sidebar"/,
            label,
          );
          return true;
        },
        label,
      );
      assert.deepEqual(counts, { random: 0, plan: 0, derive: 0, seal: 0, sign: 0 }, label);
    }
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
                ? { suppliedAccessGroups: ["premium"], contentKeyNames: [] }
                : { suppliedAccessGroups: ["free"], contentKeyNames: [] },
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

    assert.deepEqual(
      Object.keys(periodKeyMap(issuerBlockOf(page, ISSUER_NAME).sealed.periodKeys)),
      ["premium"],
    );
    assert.equal(Object.hasOwn(issuerBlockOf(page, ISSUER_NAME).sealed, "contentKeys"), false);
    assert.deepEqual(
      Object.keys(periodKeyMap(issuerBlockOf(page, FALLBACK_ISSUER_NAME).sealed.periodKeys)),
      ["free"],
    );
    assert.equal(
      Object.hasOwn(issuerBlockOf(page, FALLBACK_ISSUER_NAME).sealed, "contentKeys"),
      false,
    );
  });

  test("a content-key-only render whose one plan selects no content-key name refuses", async () => {
    const { sealerConfig } = await world();
    const sourceConfig = sealerConfig({
      issuerSupplyPlanFor: () => ({ contentKeyNames: [], suppliedAccessGroups: [] }),
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
                contentKeyNames: [],
                reachableContentNames: ["bodytext"],
              }
            : { suppliedAccessGroups: ["free"], contentKeyNames: ["bodytext", "sidebar"] };
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
      assert.equal(Object.hasOwn(issuerBlockOf(page, ISSUER_NAME).sealed, "contentKeys"), false);
      assert.deepEqual(
        Object.keys(periodKeyMap(issuerBlockOf(page, ISSUER_NAME).sealed.periodKeys)),
        ["premium"],
      );
      assert.deepEqual(
        Object.keys(contentKeyMap(issuerBlockOf(page, FALLBACK_ISSUER_NAME).sealed.contentKeys)),
        ["bodytext", "sidebar"],
      );
      assert.deepEqual(
        Object.keys(periodKeyMap(issuerBlockOf(page, FALLBACK_ISSUER_NAME).sealed.periodKeys)),
        ["free"],
      );
    }
    assert.deepEqual(issuerNamesOn(forward), [ISSUER_NAME, FALLBACK_ISSUER_NAME]);
    assert.deepEqual(issuerNamesOn(reversed), [FALLBACK_ISSUER_NAME, ISSUER_NAME]);
  });
});

/**
 * The declared family plan, as base's optional `familyPlan` seam hands it over.
 * Every case below starts from this and changes the one member under test, so a
 * refusal is about that member and never about a missing required one.
 *
 * @param {object} [overrides]
 */
function declaredPeriodKeyPlan(overrides = {}) {
  return {
    periods: ["251023T1415", "251023T1430"],
    periodKeyAt: async () => new Uint8Array(16).fill(7),
    ...overrides,
  };
}

/** @param {object} [chainOverrides] */
function declaredChainPlan(chainOverrides = {}) {
  return declaredPeriodKeyPlan({
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
        () => declaredPeriodKeyPlan({ chainWindows: 2 }),
        "unsupported_option",
        /a period family plan has no chainWindows yet/,
      ],
      [
        "a plan that acquires no period key",
        () => ({ periods: ["251023T1415"] }),
        "bad_config",
        /period family plan for "premium" acquires a period key at each label/,
      ],
      [
        "planned periods outside a list",
        () => declaredPeriodKeyPlan({ periods: "251023T1415" }),
        "bad_config",
        /periods for accessGroup "premium" is a nonempty list of unique binding-safe labels/,
      ],
      [
        "an empty period list",
        () => declaredPeriodKeyPlan({ periods: [] }),
        "bad_config",
        /periods for accessGroup "premium"/,
      ],
      [
        "a repeated planned period",
        () => declaredPeriodKeyPlan({ periods: ["251023T1415", "251023T1415"] }),
        "bad_config",
        /periods for accessGroup "premium"/,
      ],
      [
        "a planned period carrying the aad join",
        () => declaredPeriodKeyPlan({ periods: ["251023T1415|251023T1430"] }),
        "bad_config",
        /periods for accessGroup "premium"/,
      ],
      [
        "a chain plan that is not an object",
        () => declaredPeriodKeyPlan({ chain: "dca-profile-chain-keys" }),
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
        // spec-profile--chain-keys.md Bounds: maxChainMembersPerFamily is 2.
        "a third supplied capability in one family",
        () =>
          declaredChainPlan({
            suppliedTs: ["251023T1145", "251023T2345", "251024T1145"],
          }),
        "bad_config",
        /the chain plan for "premium" supplies at most 2 capabilities/,
      ],
      [
        // spec-profile--chain-keys.md 11.2-11.3: an issuer refuses the whole family
        // when two members share one stationary window. 12:15 and 14:15 sit in
        // the 12:00-24:00 window of a two-chains-per-day geometry.
        "two supplied positions in one window",
        () => declaredChainPlan({ suppliedTs: ["251023T1215", "251023T1415"] }),
        "bad_config",
        /the chain plan for "premium" supplies one position per window; "251023T1215" and "251023T1415" share one/,
      ],
      [
        "two supplied positions in one window, given latest first",
        () => declaredChainPlan({ suppliedTs: ["251023T2345", "251023T1200"] }),
        "bad_config",
        /the chain plan for "premium" supplies one position per window; "251023T2345" and "251023T1200" share one/,
      ],
      [
        "a supplied chain label off the geometry's grid",
        () => declaredChainPlan({ suppliedTs: ["251023T1420"] }),
        "bad_config",
        /chain source "251023T1420" for "premium" is a real aligned UTC coordinate/,
      ],
      [
        "a supplied chain label on no calendar day",
        () => declaredChainPlan({ suppliedTs: ["250230T1415"] }),
        "bad_config",
        /chain source "250230T1415" for "premium" is a real aligned UTC coordinate/,
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

  test("a supplied label outside the period-label grammar is refused before any material is drawn", async () => {
    const { sealerConfig } = await world();
    const cases = [
      ["a dashed date with an hour", () => declaredPeriodKeyPlan({ periods: ["2025-10-23T14"] })],
      ["a label without minutes", () => declaredPeriodKeyPlan({ periods: ["251023T14"] })],
      [
        "a lowercase separator beside a canonical label",
        () => declaredPeriodKeyPlan({ periods: ["251023T1415", "251023t1430"] }),
      ],
      [
        "a chain label without its separator",
        () => declaredChainPlan({ suppliedTs: ["2510231415"] }),
      ],
    ];

    for (const [label, planFor] of cases) {
      const { config, counts } = watched(
        sealerConfig({
          contentKeyWrapStrategy: ordinaryContentKeyWrap,
          periodKeySupply: planningSupply(/** @type {any} */ (planFor)),
        }),
      );
      await assert.rejects(
        render(new Sealer(/** @type {any} */ (config))),
        (/** @type {any} */ error) => {
          assert.equal(error.code, "bad_config", label);
          assert.match(error.message, /accessGroup "premium" .* each spelled YYMMDDTHHMM/, label);
          return true;
        },
        /** @type {string} */ (label),
      );
      assert.deepEqual(counts, { random: 0, plan: 1, derive: 0, seal: 0, sign: 0 }, label);
    }
  });

  test("canonical supplied labels are admitted and wrapped at exactly those labels", async () => {
    const { sealerConfig } = await world();
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            contentKeyWrapStrategy: ordinaryContentKeyWrap,
            periodKeySupply: planningSupply(() => declaredChainPlan()),
            issuerSupplyPlanFor: wholeWith({
              periodKeyDelivery: { premium: ["period-keys", "chain-keys"] },
            }),
          })
        ),
      ),
    );

    assert.deepEqual(
      wrapsOf(page, "bodytext", "premium").map((/** @type {any} */ entry) => entry.period),
      ["251023T1415", "251023T1430"],
    );
    const sealed = issuerBlockOf(page, ISSUER_NAME).sealed;
    assert.deepEqual(Object.keys(periodKeyMap(sealed.periodKeys).premium), [
      "251023T1415",
      "251023T1430",
    ]);
    assert.deepEqual(Object.keys(periodKeyMap(sealed.chainKeys, "cutoff").premium), [
      "251023T1415",
    ]);
  });

  test("a chain delivery no supply can serve refuses before any material is drawn", async () => {
    const { sealerConfig } = await world();
    const cases = [
      [
        // Without a supply the render wraps nothing and its item names no
        // group, so the plan's group is refused before its chain choice or
        // any supplier is asked.
        "chain delivery on a publisher with no supply at all",
        { periodKeySupply: undefined },
        /is supplied "premium", which this render wraps nothing under/,
        0,
        [],
      ],
      [
        "chain delivery on a family the plan gave no chain route",
        { periodKeySupply: planningSupply(() => declaredPeriodKeyPlan()) },
        /issuer chain delivery for accessGroup "premium" has no configured chain family route/,
        1,
        ["premium"],
      ],
    ];

    for (const [label, supplyConfig, message, plan, accessGroups] of cases) {
      const { config, counts } = watched(
        sealerConfig({
          contentKeyWrapStrategy: ordinaryContentKeyWrap,
          period: { length: 15, slots: 2 },
          issuerSupplyPlanFor: () => ({
            contentKeyNames: ["bodytext"],
            suppliedAccessGroups: ["premium"],
            periodKeyDelivery: { premium: ["chain-keys"] },
          }),
          .../** @type {object} */ (supplyConfig),
        }),
      );
      await assert.rejects(
        render(new Sealer(/** @type {any} */ (config)), {
          items: [{ name: "bodytext", accessGroups: /** @type {string[]} */ (accessGroups) }],
        }),
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
    // spec-profile--chain-keys.md Bounds: maxChainMembersPerMessage is 16.
    // Eight two-member families and one one-member family ask for exactly
    // seventeen; the adjacent eight-family case below admits sixteen.
    const { sealerConfig } = await world();
    const { config, counts } = watched(
      sealerConfig({
        contentKeyWrapStrategy: ordinaryContentKeyWrap,
        periodKeySupply: planningSupply((accessGroup) =>
          declaredChainPlan({
            suppliedTs: accessGroup === "fam_i" ? ["251023T2345"] : ["251023T1145", "251023T2345"],
          }),
        ),
        issuerSupplyPlanFor: wholeWith({
          periodKeyDelivery: Object.fromEntries(
            NINE_FAMILIES.map((group) => [group, ["chain-keys"]]),
          ),
        }),
      }),
    );

    await assert.rejects(
      render(new Sealer(/** @type {any} */ (config)), {
        items: [{ name: "bodytext", accessGroups: NINE_FAMILIES }],
      }),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_config");
        assert.match(error.message, /one issuer supply contains at most 16 chain keys/);
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
    const { sealerConfig, issuerConfig } = await world();
    const eight = NINE_FAMILIES.slice(0, 8);
    const page = await render(
      new Sealer(
        /** @type {any} */ (
          sealerConfig({
            // One item-key route plus 16 chain entries needs an endpoint
            // onboarded above the reference's 16-entry assumption.
            issuers: [{ ...issuerConfig(ISSUER_NAME), limits: { maxEntries: 17 } }],
            contentKeyWrapStrategy: ordinaryContentKeyWrap,
            periodKeySupply: planningSupply(() =>
              declaredChainPlan({
                suppliedTs: ["251023T1145", "251023T2345"],
              }),
            ),
            issuerSupplyPlanFor: wholeWith({
              periodKeyDelivery: Object.fromEntries(eight.map((group) => [group, ["chain-keys"]])),
            }),
          })
        ),
      ),
      { items: [{ name: "bodytext", accessGroups: eight }] },
    );

    const sealed = issuerBlockOf(page, ISSUER_NAME).sealed;
    assert.deepEqual(Object.keys(periodKeyMap(sealed.chainKeys, "cutoff")), eight);
    assert.deepEqual(Object.keys(periodKeyMap(sealed.chainKeys, "cutoff").fam_a), [
      "251023T1145",
      "251023T2345",
    ]);
  });

  test("a supplied key of the wrong width is refused at the coordinate that produced it", async () => {
    const { sealerConfig } = await world();
    const cases = [
      [
        "a period key short of the period-key width",
        {
          periodKeySupply: planningSupply(() =>
            declaredPeriodKeyPlan({ periodKeyAt: async () => new Uint8Array(31) }),
          ),
        },
        {},
        /periodKey for accessGroup "premium" at "251023T1415" is 16 bytes/,
      ],
      [
        "a chain capability short of the period-key width",
        {
          periodKeySupply: planningSupply(() =>
            declaredChainPlan({
              suppliedTs: ["251023T1430"],
              capabilityAt: async () => new Uint8Array(31),
            }),
          ),
        },
        { issuerSupplyPlanFor: wholeWith({ periodKeyDelivery: { premium: ["chain-keys"] } }) },
        /chainKey for accessGroup "premium" at "251023T1430" is 16 bytes/,
      ],
    ];

    for (const [label, supplyConfig, planConfig, message] of cases) {
      const { config, counts } = watched(
        sealerConfig({
          contentKeyWrapStrategy: ordinaryContentKeyWrap,
          period: { length: 15, slots: 2 },
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

// Each issuer block carries only the scope the publisher selected for it: the
// content-key route for the named content names, and the period-key
// route for the named access groups (docs/spec--core-protocol.md, section 2.1).
// Every protected item still needs one complete issuer route across the blocks
// (section 9). The assertions below read the actual sealed sections and then
// open them with the issuer's private key, so "reaches" means the issuer can
// decrypt that item, not that a map member is present. A period-key route
// reaches every item the publisher wrapped under that group, whatever the
// content-key selections say.

/** bodytext and teaser are wrapped under premium, sidebar under free. */
const SCOPE_ITEMS = [
  { name: "bodytext", accessGroups: ["premium"] },
  { name: "teaser", accessGroups: ["premium"] },
  { name: "sidebar", accessGroups: ["free"] },
];

/**
 * A factory setup with two issuers on the one test key, so a test opens either
 * block with the same private key.
 *
 * @param {Record<string, unknown>} scope - the setup members that select scope
 */
function scopeSetup(scope) {
  return {
    origin: ORIGIN,
    signingKid: SIGNING_KID,
    issuers: [ISSUER_NAME, FALLBACK_ISSUER_NAME].map((issuerName) => ({
      issuerName,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
    })),
    fixedInstant: new Date(AT),
    fixedPeriodKeys: {
      premium: { [PERIODS[0]]: periodKey(0xa1), [PERIODS[1]]: periodKey(0xa2) },
      free: { [PERIODS[0]]: periodKey(0xb1), [PERIODS[1]]: periodKey(0xb2) },
    },
    testKeyDocuments: {
      signingKeys: { [SIGNING_KID]: TEST_SIGNING_KEY_PKCS8 },
      issuerPublicKeys: { [KEY_ID]: TEST_ISSUER_PUBLIC_KEY_SPKI },
    },
    ...scope,
  };
}

/**
 * @param {Record<string, { contentKeyNames: string[], suppliedAccessGroups: string[] }>} plans
 * @returns {(issuer: { issuerName: string }) => object}
 */
function plannedBy(plans) {
  return (issuer) => plans[issuer.issuerName];
}

/**
 * @param {any} sealer
 * @param {{ name: string, accessGroups: string[] }[]} [items]
 * @returns {Promise<any>}
 */
async function renderScoped(sealer, items = SCOPE_ITEMS) {
  sealer.resource(RESOURCE_ID, { section: "politics" });
  for (const item of items) {
    sealer.content(item.name, `<p>${item.name}</p>`, CONTENT_TYPE, {
      accessGroups: item.accessGroups,
    });
  }
  const sealed = await sealer.seal();
  return JSON.parse(JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }));
}

/**
 * What one issuer block carries, by section: the content names of its
 * content-key records and, per group, the labels of its period-key and
 * chain-key records.
 *
 * @param {any} page
 * @param {string} issuerName
 */
function sectionsOf(page, issuerName) {
  const sealed = issuerBlockOf(page, issuerName).sealed;
  /** @param {Record<string, Record<string, string>>|undefined} section */
  const labels = (section) =>
    section === undefined
      ? undefined
      : Object.fromEntries(
          Object.entries(section).map(([group, byT]) => [group, Object.keys(byT)]),
        );
  return {
    contentKeys:
      sealed.contentKeys === undefined ? undefined : Object.keys(contentKeyMap(sealed.contentKeys)),
    periodKeys: labels(periodKeyMap(sealed.periodKeys)),
    chainKeys: labels(periodKeyMap(sealed.chainKeys, "cutoff")),
  };
}

/**
 * The scope assertion every case uses. It compares the whole block, so a block
 * that carries one extra name, group or section fails it.
 *
 * @param {any} page
 * @param {string} issuerName
 * @param {{ contentKeys?: string[], periodKeys?: Record<string, string[]> }} expected
 */
function assertScope(page, issuerName, expected) {
  assert.deepEqual(
    sectionsOf(page, issuerName),
    {
      contentKeys: expected.contentKeys,
      periodKeys: expected.periodKeys,
      chainKeys: undefined,
    },
    `the scope of issuer "${issuerName}"`,
  );
}

/** @param {string} text */
const scopeBytesOf = (text) => new Uint8Array(Buffer.from(text, "base64url"));

/**
 * @param {Uint8Array} key @param {string} nonce @param {string} ciphertext
 * @param {Uint8Array} [aad]
 */
async function gcmOpen(key, nonce, ciphertext, aad) {
  const cryptoKey = await globalThis.crypto.subtle.importKey("raw", key, "AES-GCM", false, [
    "decrypt",
  ]);
  return new Uint8Array(
    await globalThis.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: scopeBytesOf(nonce),
        ...(aad === undefined ? {} : { additionalData: aad }),
      },
      cryptoKey,
      scopeBytesOf(ciphertext),
    ),
  );
}

/**
 * @param {any} page @param {string} contentName @param {Uint8Array} contentKey
 * @returns {Promise<string>}
 */
async function plaintext(page, contentName, contentKey) {
  const opened = await gcmOpen(
    contentKey,
    "AAAAAAAAAAAAAAAA",
    page.sealedContent[contentName],
    contentAadOctets(page, contentName),
  );
  return new TextDecoder().decode(opened);
}

/**
 * The content names one issuer can decrypt from its own block: each sealed
 * content key it opens, and each item whose wrap under a group it holds a
 * period key for. Every route is opened to the item's plaintext.
 *
 * @param {any} page
 * @param {string} issuerName
 * @returns {Promise<string[]>}
 */
async function reachOf(page, issuerName) {
  const renderId = page.resource.renderId;
  const sealed = issuerBlockOf(page, issuerName)?.sealed ?? {};
  /** @type {Set<string>} */
  const reached = new Set();

  for (const { contentName, key: envelope } of sealed.contentKeys ?? []) {
    const contentKey = await openEcdhEnvelope(
      envelope,
      `dca-bind-key-envelope|c|${renderId}|${contentName}`,
      TEST_ISSUER_PRIVATE_KEY_PKCS8,
    );
    assert.equal(await plaintext(page, contentName, contentKey), `<p>${contentName}</p>`);
    reached.add(contentName);
  }

  for (const { accessGroup, period: t, key: envelope } of sealed.periodKeys ?? []) {
    const key = await openEcdhEnvelope(
      envelope,
      `dca-bind-key-envelope|p|${renderId}|${accessGroup}|${t}`,
      TEST_ISSUER_PRIVATE_KEY_PKCS8,
    );
    for (const contentName of contentNamesOn(page)) {
      const wrap = wrapsOf(page, contentName, accessGroup).find(
        (/** @type {any} */ entry) => entry.period === t,
      );
      if (wrap === undefined) continue;
      const nonce = contentKeyWrapNonceOctets({ renderId, contentName, accessGroup, t });
      const contentKey = await gcmOpen(key, Buffer.from(nonce).toString("base64url"), wrap.key);
      assert.equal(await plaintext(page, contentName, contentKey), `<p>${contentName}</p>`);
      reached.add(contentName);
    }
  }
  return [...reached].sort();
}

/**
 * A Sealer on native keys whose every draw, period-key ask and seal is counted,
 * so a refusal can show it produced nothing.
 *
 * @param {Record<string, unknown>} options
 */
async function watchedScopeSealer(options) {
  const counts = { random: 0, derive: 0, seal: 0 };
  const signing = await signingKeypair();
  const issuers = [];
  for (const issuerName of [ISSUER_NAME, FALLBACK_ISSUER_NAME]) {
    const pair = await issuerKeypair();
    issuers.push({
      issuerName,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      publicKey: pair.publicKey,
    });
  }
  const random = seededRandom(20251023);
  const config = {
    origin: ORIGIN,
    clock: { now: () => new Date(AT) },
    random: {
      bytes: (/** @type {number} */ n) => {
        counts.random += 1;
        return random.bytes(n);
      },
    },
    signingKeys: { [SIGNING_KID]: signing.privateKey },
    signingKid: SIGNING_KID,
    periodKeySupply: {
      derive: async () => {
        counts.derive += 1;
        return new Uint8Array(16);
      },
    },
    keySealing: {
      seal: async () => {
        counts.seal += 1;
        return "sealed";
      },
    },
    issuers,
    ...options,
  };
  return { config, counts };
}

/**
 * @param {Record<string, unknown>} options
 * @param {RegExp} message
 * @param {string} [label]
 * @param {{ name: string, accessGroups?: string[] }[]} [items]
 */
async function assertRefusedBeforeOutput(
  options,
  message,
  label = String(message),
  items = SCOPE_ITEMS,
) {
  const { config, counts } = await watchedScopeSealer(options);
  if (config.periodKeySupply === undefined) delete (/** @type {any} */ (config).periodKeySupply);
  await assert.rejects(
    renderScoped(new Sealer(/** @type {any} */ (config)), /** @type {any} */ (items)),
    (/** @type {any} */ error) => {
      assert.equal(error.code, "bad_config", label);
      assert.match(error.message, message, label);
      return true;
    },
    label,
  );
  assert.deepEqual(counts, { random: 0, derive: 0, seal: 0 }, label);
}

describe("Each issuer block carries only its selected scope", () => {
  test("an assigned period wrap remains valid when issuer selects only the item key", async () => {
    const page = await renderScoped(
      await sealerForRender(
        scopeSetup({
          issuerSupplyPlanFor: plannedBy({
            [ISSUER_NAME]: { contentKeyNames: ["bodytext"], suppliedAccessGroups: [] },
            [FALLBACK_ISSUER_NAME]: { contentKeyNames: [], suppliedAccessGroups: [] },
          }),
        }),
      ),
      [{ name: "bodytext", accessGroups: ["premium"] }],
    );

    assert.deepEqual(wrapGroupsOn(page, "bodytext"), ["premium"]);
    assertScope(page, ISSUER_NAME, { contentKeys: ["bodytext"] });
    assert.equal(issuerNamesOn(page).includes(FALLBACK_ISSUER_NAME), false);
    assert.deepEqual(await reachOf(page, ISSUER_NAME), ["bodytext"]);
  });

  test("a grouped and an ungrouped item in one render each keep exactly their own route", async () => {
    for (const [label, accessGroups] of [
      ["omitted", undefined],
      ["empty", []],
    ]) {
      const page = await renderScoped(
        await sealerForRender(
          scopeSetup({
            issuerSupplyPlanFor: plannedBy({
              [ISSUER_NAME]: { contentKeyNames: ["sidebar"], suppliedAccessGroups: ["premium"] },
              [FALLBACK_ISSUER_NAME]: { contentKeyNames: [], suppliedAccessGroups: [] },
            }),
          }),
        ),
        [
          { name: "bodytext", accessGroups: ["premium"] },
          { name: "teaser", accessGroups: ["premium"] },
          { name: "sidebar", accessGroups: /** @type {any} */ (accessGroups) },
        ],
      );

      assert.deepEqual(wrapGroupsOn(page, "bodytext"), ["premium"], label);
      assert.deepEqual(wrapGroupsOn(page, "teaser"), ["premium"], label);
      assert.equal(Object.hasOwn(contentRecordOf(page, "sidebar"), "keys"), false, label);
      assertScope(page, ISSUER_NAME, {
        contentKeys: ["sidebar"],
        periodKeys: { premium: PERIODS },
      });
      assert.equal(issuerNamesOn(page).includes(FALLBACK_ISSUER_NAME), false, label);
      // The grouped items open through the premium wraps, the ungrouped one
      // through its own sealed item key, all from the one issuer block.
      assert.deepEqual(await reachOf(page, ISSUER_NAME), ["bodytext", "sidebar", "teaser"], label);
    }
  });

  test("a content-key-only issuer and a period-only issuer each reach only what they were given", async () => {
    const page = await renderScoped(
      await sealerForRender(
        scopeSetup({
          issuerSupplyPlanFor: plannedBy({
            [ISSUER_NAME]: { contentKeyNames: ["sidebar"], suppliedAccessGroups: [] },
            [FALLBACK_ISSUER_NAME]: { contentKeyNames: [], suppliedAccessGroups: ["premium"] },
          }),
        }),
      ),
    );

    assertScope(page, ISSUER_NAME, { contentKeys: ["sidebar"] });
    assertScope(page, FALLBACK_ISSUER_NAME, { periodKeys: { premium: PERIODS } });
    assert.deepEqual(await reachOf(page, ISSUER_NAME), ["sidebar"]);
    assert.deepEqual(await reachOf(page, FALLBACK_ISSUER_NAME), ["bodytext", "teaser"]);
  });

  test("a period-key route reaches every item wrapped under its group, whatever the content-key selections", async () => {
    const page = await renderScoped(
      await sealerForRender(
        scopeSetup({
          issuerSupplyPlanFor: plannedBy({
            [ISSUER_NAME]: {
              contentKeyNames: ["sidebar", "bodytext"],
              suppliedAccessGroups: [],
            },
            [FALLBACK_ISSUER_NAME]: { contentKeyNames: [], suppliedAccessGroups: ["premium"] },
          }),
        }),
      ),
    );

    // Render order, not selection order, so two issuers read one order.
    assertScope(page, ISSUER_NAME, { contentKeys: ["bodytext", "sidebar"] });
    assertScope(page, FALLBACK_ISSUER_NAME, { periodKeys: { premium: PERIODS } });
    // The bodytext content key sealed to the first issuer does not narrow the
    // second issuer's premium reach, and teaser is in no content-key selection
    // at all.
    assert.deepEqual(await reachOf(page, ISSUER_NAME), ["bodytext", "sidebar"]);
    assert.deepEqual(await reachOf(page, FALLBACK_ISSUER_NAME), ["bodytext", "teaser"]);
  });

  test("two issuers whose scopes differ in both kinds carry exactly their own sections", async () => {
    const page = await renderScoped(
      await sealerForRender(
        scopeSetup({
          issuerSupplyPlanFor: plannedBy({
            [ISSUER_NAME]: { contentKeyNames: ["teaser"], suppliedAccessGroups: ["free"] },
            [FALLBACK_ISSUER_NAME]: {
              contentKeyNames: ["sidebar"],
              suppliedAccessGroups: ["premium"],
            },
          }),
        }),
      ),
    );

    assertScope(page, ISSUER_NAME, { contentKeys: ["teaser"], periodKeys: { free: PERIODS } });
    assertScope(page, FALLBACK_ISSUER_NAME, {
      contentKeys: ["sidebar"],
      periodKeys: { premium: PERIODS },
    });
    assert.deepEqual(await reachOf(page, ISSUER_NAME), ["sidebar", "teaser"]);
    assert.deepEqual(await reachOf(page, FALLBACK_ISSUER_NAME), ["bodytext", "sidebar", "teaser"]);
  });

  test("an issuer whose standing scope meets nothing in this render gets nothing while its sibling keeps the complete route", async () => {
    /** @type {Record<string, { contentKeyNames: string[], accessGroups: string[] }>} */
    const standing = {
      [ISSUER_NAME]: { contentKeyNames: ["footnote"], accessGroups: ["archive"] },
      [FALLBACK_ISSUER_NAME]: {
        contentKeyNames: ["bodytext", "sidebar"],
        accessGroups: ["premium"],
      },
    };
    // The publisher intersects each standing entrustment with this render's
    // names and groups before it asks the Sealer; the first issuer's
    // intersection is empty in both kinds.
    const page = await renderScoped(
      await sealerForRender(
        scopeSetup({
          issuerSupplyPlanFor: (
            /** @type {{ issuerName: string }} */ issuer,
            /** @type {{ accessGroups: string[], contentNames: string[] }} */ render,
          ) => ({
            contentKeyNames: standing[issuer.issuerName].contentKeyNames.filter((name) =>
              render.contentNames.includes(name),
            ),
            suppliedAccessGroups: standing[issuer.issuerName].accessGroups.filter((group) =>
              render.accessGroups.includes(group),
            ),
          }),
        }),
      ),
    );

    assert.equal(issuerNamesOn(page).includes(ISSUER_NAME), false);
    assert.deepEqual(await reachOf(page, ISSUER_NAME), []);
    assertScope(page, FALLBACK_ISSUER_NAME, {
      contentKeys: ["bodytext", "sidebar"],
      periodKeys: { premium: PERIODS },
    });
    assert.deepEqual(await reachOf(page, FALLBACK_ISSUER_NAME), ["bodytext", "sidebar", "teaser"]);
  });

  test("the scope assertion fails an overbroad block and passes the selected one", async () => {
    const selected = {
      [ISSUER_NAME]: { contentKeyNames: ["sidebar"], suppliedAccessGroups: [] },
      [FALLBACK_ISSUER_NAME]: { contentKeyNames: [], suppliedAccessGroups: ["premium"] },
    };
    // The old default handed every issuer every name and every group. Named
    // explicitly here, it is the overbroad result the assertion must catch.
    const overbroad = await renderScoped(
      await sealerForRender(scopeSetup({ issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan })),
    );
    assert.throws(
      () => assertScope(overbroad, ISSUER_NAME, { contentKeys: ["sidebar"] }),
      assert.AssertionError,
    );
    assert.notDeepEqual(await reachOf(overbroad, ISSUER_NAME), ["sidebar"]);

    const scoped = await renderScoped(
      await sealerForRender(scopeSetup({ issuerSupplyPlanFor: plannedBy(selected) })),
    );
    assertScope(scoped, ISSUER_NAME, { contentKeys: ["sidebar"] });
    assert.deepEqual(await reachOf(scoped, ISSUER_NAME), ["sidebar"]);
  });

  test("the factory takes the same selections as plain data per issuer", async () => {
    const page = await renderScoped(
      await sealerForRender(
        scopeSetup({
          issuerSupplyPlans: {
            [ISSUER_NAME]: { contentKeyNames: ["sidebar"], suppliedAccessGroups: [] },
            [FALLBACK_ISSUER_NAME]: { contentKeyNames: [], suppliedAccessGroups: ["premium"] },
          },
        }),
      ),
    );
    assertScope(page, ISSUER_NAME, { contentKeys: ["sidebar"] });
    assertScope(page, FALLBACK_ISSUER_NAME, { periodKeys: { premium: PERIODS } });
  });
});

describe("A selection is refused before the render produces anything", () => {
  test("a Sealer without a planner is refused at construction", async () => {
    const { config } = await watchedScopeSealer({});
    assert.throws(
      () => new Sealer(/** @type {any} */ (config)),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_config");
        assert.match(error.message, /issuerSupplyPlanFor/);
        return true;
      },
    );
  });

  test("a missing or malformed selection is refused, never read as every name", async () => {
    /** @type {[string, object, RegExp][]} */
    const cases = [
      ["an empty plan", {}, /no accessGroup selection/],
      [
        "no content-key selection",
        { suppliedAccessGroups: ["premium"] },
        /no content-key selection/,
      ],
      ["no group selection", { contentKeyNames: ["bodytext"] }, /no accessGroup selection/],
      [
        "content-key names outside a list",
        { contentKeyNames: "bodytext", suppliedAccessGroups: [] },
        /contentKeyNames .* are a list/,
      ],
      [
        "a repeated content-key name",
        { contentKeyNames: ["bodytext", "bodytext"], suppliedAccessGroups: [] },
        /selects content-key name "bodytext" twice/,
      ],
      [
        "a repeated group",
        { contentKeyNames: [], suppliedAccessGroups: ["premium", "premium"] },
        /is supplied "premium" twice/,
      ],
    ];
    for (const [label, plan, message] of cases) {
      await assertRefusedBeforeOutput({ issuerSupplyPlanFor: () => plan }, message, label);
    }
  });

  test("a name or group this render does not carry is refused", async () => {
    await assertRefusedBeforeOutput(
      {
        issuerSupplyPlanFor: () => ({
          contentKeyNames: ["bodytext", "sidebar", "teaser", "footnote"],
          suppliedAccessGroups: [],
        }),
      },
      /selects content-key name "footnote", which this render does not carry/,
    );
    await assertRefusedBeforeOutput(
      {
        issuerSupplyPlanFor: () => ({
          contentKeyNames: ["bodytext", "sidebar", "teaser"],
          suppliedAccessGroups: ["archive"],
        }),
      },
      /is supplied "archive", which this render wraps nothing under/,
    );
  });

  test("no item is emitted without a complete issuer route", async () => {
    await assertRefusedBeforeOutput(
      {
        issuerSupplyPlanFor: plannedBy({
          [ISSUER_NAME]: { contentKeyNames: ["sidebar"], suppliedAccessGroups: [] },
          [FALLBACK_ISSUER_NAME]: { contentKeyNames: ["teaser"], suppliedAccessGroups: [] },
        }),
      },
      /no complete issuer route for protected content "bodytext"/,
    );
    // Without a period-key supply the render wraps nothing, so every item
    // needs a content-key route.
    await assertRefusedBeforeOutput(
      {
        periodKeySupply: undefined,
        issuerSupplyPlanFor: () => ({ contentKeyNames: ["sidebar"], suppliedAccessGroups: [] }),
      },
      /no complete issuer route for protected content "bodytext"/,
      "a content-key-only render",
      SCOPE_ITEMS.map(({ name }) => ({ name })),
    );
  });

  test("a named group with no period-key supply is refused, not silently dropped", async () => {
    // Every item has a content-key route here, so the only fault is the
    // wraps the groups ask for and nothing can make.
    await assertRefusedBeforeOutput(
      {
        periodKeySupply: undefined,
        issuerSupplyPlanFor: () => ({
          contentKeyNames: ["bodytext", "teaser", "sidebar"],
          suppliedAccessGroups: [],
        }),
      },
      /content "bodytext" names accessGroups/,
    );
  });
});

test("supplier callback additions belong to the next render's captured item set", async () => {
  const signing = await signingKeypair();
  let sealer;
  let added = false;
  const supply = {
    derive: async () => new Uint8Array(16).fill(3),
    familyPlan: () => ({
      periods: ["251023T1400"],
      periodKeyAt: async () => {
        if (!added) {
          added = true;
          sealer.content("late", "<p>Late</p>", "text/html", { accessGroups: ["premium"] });
        }
        return new Uint8Array(16).fill(3);
      },
    }),
  };
  sealer = new Sealer({
    origin: ORIGIN,
    clock: new Clock(AT),
    random: seededRandom(42),
    signingKeys: { [SIGNING_KID]: signing.privateKey },
    periodKeySupply: supply,
    issuers: [{ issuerName: ISSUER_NAME, keyId: KEY_ID, algorithm: "rsa-oaep", publicKey: {} }],
    issuerSupplyPlanFor: (issuer, render) => ({
      ...wholeRenderIssuerSupplyPlan(issuer, render),
      suppliedAccessGroups: [],
    }),
    keySealing: { seal: async () => "sealed" },
  });
  sealer.resource(RESOURCE_ID, {});
  sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });
  const first = await sealer.seal();
  assert.deepEqual(contentNamesOn(first.dcaData), ["bodytext"]);
  assert.deepEqual(Object.keys(first.sealedContent), ["bodytext"]);
  assert.deepEqual(
    Object.keys(contentKeyMap(issuerBlockOf(first.dcaData, ISSUER_NAME).sealed.contentKeys)),
    ["bodytext"],
  );
  const second = await sealer.seal();
  assert.deepEqual(contentNamesOn(second.dcaData), ["bodytext", "late"]);
  assert.deepEqual(Object.keys(second.sealedContent), ["bodytext", "late"]);
  assert.deepEqual(
    Object.keys(contentKeyMap(issuerBlockOf(second.dcaData, ISSUER_NAME).sealed.contentKeys)),
    ["bodytext", "late"],
  );
});

test("an ordinary random supply seals only selected period sources and refuses malformed selectors before work", async () => {
  const { sealerConfig } = await world();
  const source = randomPeriodKeySupply({ random: seededRandom(73) });
  for (const [selection, valid] of [
    [{ premium: [PERIODS[1]] }, true],
    [{ premium: ["251023T1600"] }, false],
    [{ premium: [PERIODS[0], PERIODS[0]] }, false],
    [[], false],
  ]) {
    const calls = [];
    const { config, counts } = watched(
      sealerConfig({
        periodKeySupply: {
          derive: async (group, t) => {
            calls.push([group, t]);
            return source.derive(group, t);
          },
        },
        issuerSupplyPlanFor: wholeWith({ periodKeySourceTs: selection }),
      }),
    );
    const sealer = new Sealer(config);
    if (valid) {
      const page = await render(sealer, {
        items: [{ name: "bodytext", accessGroups: ["premium"] }],
      });
      assert.deepEqual(
        Object.keys(periodKeyMap(issuerBlockOf(page, ISSUER_NAME).sealed.periodKeys).premium),
        [PERIODS[1]],
      );
      assert.deepEqual(
        calls,
        PERIODS.map((t) => ["premium", t]),
        "both item wraps still get their own period material",
      );
    } else {
      await assert.rejects(
        render(sealer, { items: [{ name: "bodytext", accessGroups: ["premium"] }] }),
        { code: "bad_config" },
      );
      assert.deepEqual(calls, []);
      assert.deepEqual(counts, { random: 0, plan: 0, derive: 0, seal: 0, sign: 0 });
    }
  }
});

test("resource replacement in the clock belongs to the next seal operation", async () => {
  const { sealerConfig } = await world();
  let replaced = false;
  const sealer = new Sealer(
    sealerConfig({
      itemPreparations: [
        {
          name: "capture-witness",
          routes: () => [],
          prepare: async (input) => ({ claims: { preparedFor: input.resourceId } }),
        },
      ],
      clock: {
        now() {
          if (!replaced) {
            replaced = true;
            sealer.resource("next-resource", { edition: "next" });
          }
          return new Date(AT);
        },
      },
    }),
  );
  sealer.resource(RESOURCE_ID, { edition: "initial" });
  sealer.content("bodytext", "<p>Body</p>", CONTENT_TYPE, { accessGroups: ["premium"] });
  const initial = await sealer.seal();
  const next = await sealer.seal();
  for (const [rendered, resourceId, edition] of [
    [initial, RESOURCE_ID, "initial"],
    [next, "next-resource", "next"],
  ]) {
    assert.equal(rendered.dcaData.resource.resourceId, resourceId);
    assert.equal(rendered.dcaData.resource.preparedFor, resourceId);
    assert.deepEqual(rendered.dcaData.resource.data, { edition });
    const signed = JSON.parse(
      Buffer.from(rendered.dcaData.resourceJWT.split(".")[1], "base64url").toString("utf8"),
    );
    assert.deepEqual(signed, rendered.dcaData.resource);
  }
});

test("overlapping seals keep preparation and signed output on the same captured resource", async () => {
  const { sealerConfig } = await world();
  const entered = Promise.withResolvers();
  const resume = Promise.withResolvers();
  const preparedIds = [];
  const sealer = new Sealer(
    sealerConfig({
      itemPreparations: [
        {
          name: "capture-witness",
          routes: () => [],
          async prepare(input) {
            preparedIds.push(input.resourceId);
            if (preparedIds.length === 1) {
              entered.resolve();
              await resume.promise;
            }
            return { claims: { preparedFor: input.resourceId } };
          },
        },
      ],
    }),
  );
  sealer.resource(RESOURCE_ID, { edition: "initial" });
  sealer.content("bodytext", "<p>Body</p>", CONTENT_TYPE, { accessGroups: ["premium"] });
  const initialPending = sealer.seal();
  await entered.promise;
  sealer.resource("next-resource", { edition: "next" });
  sealer.content("late", "<p>Late</p>", CONTENT_TYPE, { accessGroups: ["premium"] });
  let next;
  try {
    next = await sealer.seal();
  } finally {
    resume.resolve();
  }
  const initial = await initialPending;
  assert.deepEqual(preparedIds, [RESOURCE_ID, "next-resource"]);
  for (const [rendered, resourceId, edition, names] of [
    [initial, RESOURCE_ID, "initial", ["bodytext"]],
    [next, "next-resource", "next", ["bodytext", "late"]],
  ]) {
    assert.equal(rendered.dcaData.resource.resourceId, resourceId);
    assert.equal(rendered.dcaData.resource.preparedFor, resourceId);
    assert.deepEqual(rendered.dcaData.resource.data, { edition });
    assert.deepEqual(Object.keys(rendered.sealedContent), names);
    const wrap = wrapsOf(rendered.dcaData, "bodytext", "premium")[0];
    const periodKey = await fixedPeriodKeySupply().derive("premium", wrap.period);
    const contentKey = await decrypt(
      periodKey,
      contentKeyWrapNonceOctets({
        renderId: rendered.dcaData.resource.renderId,
        contentName: "bodytext",
        accessGroup: "premium",
        t: wrap.period,
      }),
      base64urlDecode(wrap.key),
    );
    const opened = await decrypt(
      contentKey,
      new Uint8Array(12),
      base64urlDecode(rendered.sealedContent.bodytext),
      contentAadOctets(rendered.dcaData, "bodytext"),
    );
    assert.equal(new TextDecoder().decode(opened), "<p>Body</p>");
    const signed = JSON.parse(
      Buffer.from(rendered.dcaData.resourceJWT.split(".")[1], "base64url").toString("utf8"),
    );
    assert.deepEqual(signed, rendered.dcaData.resource);
  }
});

test("a failed seal releases its operation and the builder can seal the next resource", async () => {
  const { sealerConfig } = await world();
  const failure = new Error("preparation failed");
  let fail = true;
  const sealer = new Sealer(
    sealerConfig({
      itemPreparations: [
        {
          name: "retry-witness",
          routes: () => [],
          async prepare(input) {
            if (fail) {
              fail = false;
              throw failure;
            }
            return { claims: { preparedFor: input.resourceId } };
          },
        },
      ],
    }),
  );
  sealer.resource(RESOURCE_ID, { edition: "failed" });
  sealer.content("bodytext", "<p>Body</p>", CONTENT_TYPE, { accessGroups: ["premium"] });
  await assert.rejects(sealer.seal(), (error) => error === failure);
  sealer.resource("retry-resource", { edition: "retry" });
  const retried = await sealer.seal();
  assert.equal(retried.dcaData.resource.resourceId, "retry-resource");
  assert.equal(retried.dcaData.resource.preparedFor, "retry-resource");
  assert.deepEqual(retried.dcaData.resource.data, { edition: "retry" });
});

test("preparations isolate inherited item and issuer names across renders", async () => {
  const opening = await issuerKeypair();
  const signing = await signingKeypair();
  const member = "preparationIsolationWitness";
  const original = Object.getOwnPropertyDescriptor(Object, member);
  try {
    for (const name of ["constructor", "toString"]) {
      for (const marker of ["first-render", "second-render"]) {
        const issuerName = name;
        const sealer = new Sealer({
          origin: ORIGIN,
          clock: new Clock(AT),
          random: seededRandom(42),
          signingKeys: { signing: signing.privateKey },
          issuers: [
            { issuerName, keyId: KEY_ID, algorithm: "ecdh-p256", publicKey: opening.publicKey },
          ],
          issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
          itemPreparations: [
            {
              name: "isolated-contribution",
              routes: () => [],
              prepare: () => ({
                contentRecords: { [name]: { [member]: marker, ["__proto__"]: { marker } } },
                issuerSealed: { [issuerName]: { [member]: [marker], ["__proto__"]: { marker } } },
              }),
            },
          ],
        });
        sealer.resource(RESOURCE_ID, {});
        sealer.content(name, "body", "text/plain");
        const { dcaData } = await sealer.seal();
        assert.equal(dcaData.contentData[0][member], marker);
        assert.equal(Object.hasOwn(dcaData.contentData[0], "__proto__"), true);
        assert.deepEqual(dcaData.contentData[0]["__proto__"], { marker });
        assert.equal(Object.hasOwn(dcaData.issuerData[0].sealed, "__proto__"), true);
        assert.deepEqual(dcaData.issuerData[0].sealed["__proto__"], { marker });
        assert.deepEqual(dcaData.issuerData[0].sealed[member], [marker]);
        assert.deepEqual(Object.getOwnPropertyDescriptor(Object, member), original);
      }
    }
  } finally {
    if (original) Object.defineProperty(Object, member, original);
    else Reflect.deleteProperty(Object, member);
  }
});
