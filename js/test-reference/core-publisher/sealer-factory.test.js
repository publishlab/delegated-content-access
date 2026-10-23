// @ts-check
//
// The factory a render asks for its Sealer. Production gives it the Sealer's
// configuration and native keys, and the Sealer reads the wall clock and the
// secure random source. A repeatable test gives it a fixed instant, one random
// byte stream, fixed period keys and known key documents, and the factory
// builds the clock, the random source, the period-key supply and the keys from
// them. Either way the result is a real Sealer, a new one per call.
//
// The stream is what keeps a byte-exact test honest across ports: a render
// reads it front to back however it splits its reads, and a read past its end
// is refused instead of answered from somewhere else. A period the fixed keys
// do not list is refused the same way.

import { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../core-publisher/Sealer.js";
import { sealerForRender } from "../../core-publisher/testing/sealerFactory.js";
import { decrypt } from "../../core-shared/aead.js";
import { DcaError } from "../../core-shared/errors.js";
import {
  ACCESS_GROUP,
  ALGORITHM,
  ARTICLES,
  AT,
  CONTENT_NAME,
  CONTENT_TYPE,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  RESOURCE_ID,
  SIGNING_KID,
} from "../../demo/scenarios/fixtures.js";
import {
  issuerKeypair,
  labelStream,
  randomStream,
  signingKeypair,
  TEST_ISSUER_PUBLIC_KEY_SPKI,
  TEST_SIGNING_KEY_PKCS8,
  TEST_SIGNING_PUBLIC_KEY_SPKI,
} from "../support/keys.js";
import { portableTest, test } from "../support/portable-test.js";
import { assertRefusalCase, refusal } from "../support/refusal.js";
import {
  dynamicRefusals,
  sealerOriginSetup,
  sealerRefusalCases,
  sealerRuntimeSetup,
  typedRefusals,
} from "../support/sealerCases.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { wrapNonceOf } from "../support/contentKeyWrapNonceOctets.js";
import {
  contentNamesOn,
  contentRecordOf,
  issuerBlockOf,
  wrapsOf,
} from "../../test-lib/helpers/inspect.js";

const portableRefusalTest = portableTest("portable-sealer-refusals");
const portableDynamicRefusalTest = portableTest("portable-sealer-refusals-dynamic");
const portableRuntimeTest = portableTest("portable-sealer-runtime");
const portableOwnershipTest = portableTest("portable-sealer-ownership");

const ISSUER = {
  issuerName: ISSUER_NAME,
  keyId: KEY_ID,
  algorithm: ALGORITHM,
};

/** The two periods a render at `AT` wraps under: the current hour and the next. */
const T14 = "251023T1400";
const T15 = "251023T1500";

/** @param {object} [overrides] */
function testSetup(overrides = {}) {
  return {
    origin: ORIGIN,
    signingKid: SIGNING_KID,
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [ISSUER],
    fixedInstant: new Date(AT),
    randomStream: randomStream(1, 56),
    testKeyDocuments: {
      signingKeys: { [SIGNING_KID]: TEST_SIGNING_KEY_PKCS8 },
      issuerPublicKeys: { [KEY_ID]: TEST_ISSUER_PUBLIC_KEY_SPKI },
    },
    ...overrides,
  };
}

/**
 * The caller names the item's groups. A setup without fixed period keys holds
 * no period-key supply, so its item names none and rides its item key alone.
 *
 * @param {Sealer} sealer
 * @param {string[]} accessGroups
 */
function sealOne(sealer, accessGroups) {
  sealer.resource(RESOURCE_ID, {});
  sealer.content(CONTENT_NAME, ARTICLES.A, CONTENT_TYPE, { accessGroups });
  return sealer.seal();
}

/** @param {Uint8Array} bytes */
const base64url = (bytes) => Buffer.from(bytes).toString("base64url");

/** @param {string} pem */
function der(pem) {
  const body = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
  return Buffer.from(body, "base64");
}

describe("The Sealer factory", () => {
  test("test setup builds a real Sealer on the fixed instant, the random stream and the known keys", async () => {
    const sealer = await sealerForRender(testSetup());
    assert.ok(sealer instanceof Sealer);

    const { dcaData } = await sealOne(sealer, []);
    const stream = randomStream(1, 56);

    assert.equal(dcaData.resource.issuedAt, new Date(AT).toISOString());
    assert.equal(dcaData.resource.renderId, base64url(stream.subarray(0, 16)));
    assert.equal(Object.hasOwn(contentRecordOf(dcaData, CONTENT_NAME), "nonce"), false);
    assert.equal(issuerBlockOf(dcaData, ISSUER_NAME).keyId, KEY_ID);

    // The signing key imported from the PKCS#8 document signs what the public
    // half of the same key pair verifies.
    const [header, payload, signature] = dcaData.resourceJWT.split(".");
    const publicKey = await crypto.subtle.importKey(
      "spki",
      der(TEST_SIGNING_PUBLIC_KEY_SPKI),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      Buffer.from(signature, "base64url"),
      Buffer.from(`${header}.${payload}`),
    );
    assert.equal(verified, true);
  });

  portableOwnershipTest("each call owns its Sealer, render state and random stream", async () => {
    const setup = sealerOriginSetup(AT, "sealer-ownership");
    const first = await sealerForRender(setup);
    const second = await sealerForRender(setup);
    assert.notEqual(first, second);

    // Interleave both objects before sealing either: per-render mutable state
    // and the callback's stream cursor must belong to their own instance.
    assert.equal(await first.resource(`${RESOURCE_ID}-first`, {}), first);
    assert.equal(await second.resource(`${RESOURCE_ID}-second`, {}), second);
    assert.equal(await first.content(CONTENT_NAME, ARTICLES.A, CONTENT_TYPE), first);
    assert.equal(await second.content(CONTENT_NAME, ARTICLES.B, "text/html"), second);
    const one = await first.seal();
    const two = await second.seal();
    for (const { dcaData } of [one, two]) {
      assert.equal(dcaData.resource.issuedAt, new Date(AT).toISOString());
      assert.equal(dcaData.resource.renderId, base64url(setup.randomStream.subarray(0, 16)));
      assert.deepEqual(contentNamesOn(dcaData), [CONTENT_NAME]);
    }
    assert.equal(one.dcaData.resource.resourceId, `${RESOURCE_ID}-first`);
    assert.equal(two.dcaData.resource.resourceId, `${RESOURCE_ID}-second`);
    assert.equal(contentRecordOf(one.dcaData, CONTENT_NAME).contentType, CONTENT_TYPE);
    assert.equal(contentRecordOf(two.dcaData, CONTENT_NAME).contentType, "text/html");
  });

  test("without test setup the Sealer reads the wall clock and draws secure random bytes", async () => {
    const signing = await signingKeypair();
    const issuerKeys = await issuerKeypair();
    const setup = {
      origin: ORIGIN,
      signingKid: SIGNING_KID,
      signingKeys: { [SIGNING_KID]: signing.privateKey },
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [{ ...ISSUER, publicKey: issuerKeys.publicKey }],
    };
    const before = Date.now();
    const one = await sealOne(await sealerForRender(setup), []);
    const two = await sealOne(await sealerForRender(setup), []);
    const after = Date.now();

    const issuedAt = Date.parse(one.dcaData.resource.issuedAt);
    assert.ok(issuedAt >= before - 1000 && issuedAt <= after, "the render is stamped now");
    assert.notEqual(one.dcaData.resource.renderId, two.dcaData.resource.renderId);
  });

  portableRuntimeTest(
    "through the Sealer factory, a setup without a fixed instant or a random stream reads the wall clock and draws secure random bytes",
    async () => {
      // Only what holds for any wall clock and secure random source: the
      // render is stamped between the reads of this host's clock around it,
      // and two renders draw different render ids and content keys. The
      // test target runs on this host and reads the same clock. A second of
      // slack each side covers a port that rounds or cuts the milliseconds.
      const before = Date.now();
      const one = await sealOne(await sealerForRender(sealerRuntimeSetup()), []);
      const two = await sealOne(await sealerForRender(sealerRuntimeSetup()), []);
      const after = Date.now();

      for (const { dcaData } of [one, two]) {
        const issuedAt = Date.parse(dcaData.resource.issuedAt);
        assert.ok(
          issuedAt >= before - 1000 && issuedAt <= after + 1000,
          `the render is stamped now, not ${dcaData.resource.issuedAt}`,
        );
      }
      assert.notEqual(one.dcaData.resource.renderId, two.dcaData.resource.renderId);
      assert.notEqual(one.sealedContent[CONTENT_NAME], two.sealedContent[CONTENT_NAME]);
    },
  );

  test("a read past the end of the random stream is refused", async () => {
    // A render draws its render ID (16 bytes), then its content key (16). The
    // ordinary ECDH envelope draws nothing: its IV is the implicit zero IV.
    const short = await sealerForRender(testSetup({ randomStream: randomStream(1, 30) }));
    await assert.rejects(sealOne(short, []), {
      code: "bad_config",
      message: "the random stream has 14 bytes left, asked for 16",
    });

    // 32 bytes are exactly one render: it seals, and the next render's first
    // draw finds the stream used up.
    const exact = await sealerForRender(testSetup({ randomStream: randomStream(1, 32) }));
    await sealOne(exact, []);
    await assert.rejects(exact.seal(), {
      code: "bad_config",
      message: "the random stream has 0 bytes left, asked for 16",
    });
  });

  test("a random stream is bytes", async () => {
    await assert.rejects(sealerForRender(testSetup({ randomStream: [1, 2, 3] })), {
      code: "bad_config",
      message: "a random stream is bytes",
    });
  });

  test("fixed period keys supply the periods the render wraps under", async () => {
    const stream = randomStream(1, 104);
    const periodKeys = {
      [T14]: new Uint8Array(16).fill(0xa1),
      [T15]: new Uint8Array(16).fill(0xa2),
    };
    const sealer = await sealerForRender(
      testSetup({ randomStream: stream, fixedPeriodKeys: { [ACCESS_GROUP]: periodKeys } }),
    );

    const { dcaData } = await sealOne(sealer, [ACCESS_GROUP]);
    const entries = wrapsOf(dcaData, CONTENT_NAME, ACCESS_GROUP);
    assert.deepEqual(
      entries.map((/** @type {any} */ entry) => entry.period),
      [T14, T15],
    );
    for (const entry of entries) {
      const contentKey = await decrypt(
        periodKeys[entry.period],
        wrapNonceOf(dcaData, CONTENT_NAME, ACCESS_GROUP, entry.period),
        Buffer.from(entry.key, "base64url"),
      );
      assert.deepEqual(new Uint8Array(contentKey), stream.subarray(16, 32));
    }
  });

  test("a period the fixed keys do not list is refused", async () => {
    const sealer = await sealerForRender(
      testSetup({
        randomStream: randomStream(1, 104),
        fixedPeriodKeys: { [ACCESS_GROUP]: { [T14]: new Uint8Array(16).fill(0xa1) } },
      }),
    );

    await assert.rejects(sealOne(sealer, [ACCESS_GROUP]), {
      code: "bad_config",
      message: `no fixed period key for ${ACCESS_GROUP} at ${T15}`,
    });
  });

  test("fixed period keys are records of bytes by access group and period", async () => {
    for (const fixedPeriodKeys of [
      [],
      { [ACCESS_GROUP]: [] },
      { [ACCESS_GROUP]: { [T14]: "key" } },
    ]) {
      await assert.rejects(
        sealerForRender(testSetup({ fixedPeriodKeys })),
        {
          code: "bad_config",
          message: "fixed period keys are records of bytes by access group and period",
        },
        JSON.stringify(fixedPeriodKeys),
      );
    }
  });

  test("period keys come from a supply or from fixed test keys, never both", async () => {
    const periodKeySupply = { derive: async () => new Uint8Array(16) };
    await assert.rejects(
      sealerForRender(
        testSetup({
          periodKeySupply,
          fixedPeriodKeys: { [ACCESS_GROUP]: { [T14]: new Uint8Array(16) } },
        }),
      ),
      {
        code: "bad_config",
        message: "period keys come from a supply or from fixed test keys, not both",
      },
    );
  });

  test("the factory builds the clock and the random source itself", async () => {
    for (const name of ["clock", "random"]) {
      await assert.rejects(sealerForRender(testSetup({ [name]: {} })), {
        code: "bad_config",
        message: `the Sealer factory builds the ${name}; the setup holds none`,
      });
    }
  });

  test("a key comes from a native key or a test document, never both", async () => {
    const signing = await signingKeypair();
    await assert.rejects(
      sealerForRender(testSetup({ signingKeys: { [SIGNING_KID]: signing.privateKey } })),
      { code: "bad_config" },
    );
    const issuerKeys = await issuerKeypair();
    await assert.rejects(
      sealerForRender(testSetup({ issuers: [{ ...ISSUER, publicKey: issuerKeys.publicKey }] })),
      { code: "bad_config" },
    );
  });

  test("a test key document that is not the expected PEM is refused", async () => {
    for (const document of [
      "",
      TEST_ISSUER_PUBLIC_KEY_SPKI,
      "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
    ]) {
      await assert.rejects(
        sealerForRender(
          testSetup({
            testKeyDocuments: {
              signingKeys: { [SIGNING_KID]: document },
              issuerPublicKeys: { [KEY_ID]: TEST_ISSUER_PUBLIC_KEY_SPKI },
            },
          }),
        ),
        { code: "bad_config" },
        JSON.stringify(document),
      );
    }
  });

  // Portable twins cover a read past the end of the stream, a period the
  // fixed keys do not list, a key document that is not the expected PEM, and
  // a fixed period key of the wrong width. The dynamic twin covers the setup
  // a typed port cannot receive: a random stream or fixed period keys that
  // are lists, a clock or random source in the setup, a supply beside fixed
  // period keys, and a key beside its key document. The cases live in
  // test-reference/support/sealerCases.js, which the refusal record reads too.
  portableRefusalTest(
    "through the Sealer factory, test setup the render cannot use is refused",
    async () => {
      for (const refused of typedRefusals(sealerRefusalCases().factory)) {
        await assertRefusalCase(sealerForRender, refused);
      }
    },
  );

  portableDynamicRefusalTest(
    "through the Sealer factory, test setup of another JSON kind, or a member the factory builds, is refused",
    async () => {
      for (const refused of dynamicRefusals(sealerRefusalCases().factory)) {
        await assertRefusalCase(sealerForRender, refused);
      }
    },
  );

  // Each group runs its typed cases, its dynamic cases or both, by the portable
  // tests of sealer-origin.test.js, sealer-options.test.js and this file. A
  // case marked into a half no test runs would run nowhere.
  test("every refusal case falls in a half of its group that a portable test runs", () => {
    const cases = sealerRefusalCases();
    for (const group of ["origin", "http", "seal"]) {
      assert.deepEqual(dynamicRefusals(cases[group]), [], `${group} has no dynamic case`);
    }
    assert.deepEqual(typedRefusals(cases.names), [], "names has no typed case");
    for (const group of ["content", "config", "factory"]) {
      assert.ok(typedRefusals(cases[group]).length > 0, `${group} has typed cases`);
      assert.ok(dynamicRefusals(cases[group]).length > 0, `${group} has dynamic cases`);
    }
    assert.deepEqual(Object.keys(cases), [
      "origin",
      "http",
      "names",
      "content",
      "factory",
      "config",
      "seal",
    ]);
  });

  // Through a test bridge, a refusal the adapter sends without an error type
  // arrives as a plain Error carrying the adapter's code. The check the
  // portable cases use must fail it, so an adapter cannot pass a case by
  // naming the code itself.
  test("the portable refusal check fails a plain Error that carries the case's code", () => {
    const message = /^a random stream is bytes$/;
    assert.equal(refusal("bad_config", message)(dcaError("a random stream is bytes")), true);
    const plain = Object.assign(new Error("a random stream is bytes"), { code: "bad_config" });
    assert.throws(() => refusal("bad_config")(plain), assert.AssertionError);
    assert.throws(() => refusal("bad_config", message)(plain), assert.AssertionError);
    assert.throws(
      () => refusal("bad_config")(new DcaError("unsupported_option", "a random stream is bytes")),
      assert.AssertionError,
    );
  });

  // How a port splits its reads decides both numbers in the message, so the
  // portable case pins the code and leaves the numbers open. "a read past the
  // end of the random stream is refused" above pins this reference's own.
  test("the portable stream-exhaustion case leaves the draw numbers to the port", () => {
    const exhausted = sealerRefusalCases().factory.find(
      ({ name }) => name === "a read past the end of the random stream",
    );
    assert.ok(exhausted?.message, "the case exists and names a message");
    const check = refusal(exhausted.code, exhausted.message);
    for (const text of [
      "the random stream has 6 bytes left, asked for 12",
      "the random stream has 2 bytes left, asked for 16",
    ])
      assert.equal(check(dcaError(text)), true, text);
    assert.throws(() => check(dcaError("a random stream is bytes")), assert.AssertionError);
  });
});

// A labelled stream names its case instead of its first byte. Block i of the
// stream is SHA-256 over the label's UTF-8 bytes and i as a 4-byte big-endian
// counter. The expected bytes come from `sha256sum`, not from the helper.
describe("A labelled random stream", () => {
  test("expands its label with SHA-256 and a counter, to the length asked for", () => {
    const hex = (/** @type {Uint8Array} */ bytes) => Buffer.from(bytes).toString("hex");
    assert.equal(
      hex(labelStream("period-key-wire", 40)),
      "079bd825698b5c5226c501647a2c51eb7ed3ec2f73a247359b58ea405343c419" + "08d8472a579182d3",
    );
    assert.equal(labelStream("period-key-wire", 0).length, 0);
    assert.equal(
      hex(labelStream("period-key-wire", 20)),
      hex(labelStream("period-key-wire", 40).subarray(0, 20)),
      "a shorter stream is a prefix of a longer one",
    );
    assert.notEqual(hex(labelStream("sealer-origin", 16)), hex(labelStream("sealer-origin-2", 16)));
  });
});

/** @param {string} message */
function dcaError(message) {
  return new DcaError("bad_config", message);
}
