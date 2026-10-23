// @ts-check
//
// The publisher's delivery origin, from the config name that carries it to the
// bytes it lands in. One render is delivered from one origin, so the Sealer
// takes it once and signs it as `resourceJWT.origin`. That signed value is what
// an issuer compares the observed HTTP `Origin` against.
//
// These tests catch two ways the origin goes wrong. A Sealer that took a second
// spelling of its own host would sign a coordinate no browser reports, so every
// delivery from it is refused at admission, and one that signed nothing would
// leave the issuer with no value to compare the observed header with at all.

import { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../core-publisher/Sealer.js";
import { sealerForRender } from "../../core-publisher/testing/sealerFactory.js";
import { Clock } from "../../demo/actors/Clock.js";
import { decodeCompactJwt } from "../../core-shared/compactJwt.js";
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
import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
import { openEcdhEnvelope } from "../support/ecdhEnvelope.js";
import {
  issuerKeypair,
  labelStream,
  seededRandom,
  signingKeypair,
  TEST_ISSUER_PRIVATE_KEY_PKCS8,
  TEST_SIGNING_PUBLIC_KEY_SPKI,
} from "../support/keys.js";
import { assertRefusalCase } from "../support/refusal.js";
import {
  sealerAdmittedOrigins,
  sealerOriginRender,
  sealerOriginSetup,
  sealerRefusalCases,
  typedRefusals,
} from "../support/sealerCases.js";
import { portableTest, test } from "../support/portable-test.js";
import { assertSignedOrigin } from "../support/signedOrigin.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { contentAadOctets } from "../support/contentAadOctets.js";
import { contentKeyMap } from "../support/namedRecords.js";
import { contentNamesOn, contentRecordOf, issuerBlockOf } from "../../test-lib/helpers/inspect.js";

const portableSealerTest = portableTest("portable-sealer-origin");
const portableRefusalTest = portableTest("portable-sealer-refusals");

/**
 * One publisher over one issuer, enough of a render to reach `seal()`.
 *
 * @param {object} [overrides]
 */
async function sealerWith(overrides = {}) {
  const signing = await signingKeypair();
  const issuerKeys = await issuerKeypair();

  const config = {
    origin: ORIGIN,
    clock: new Clock(AT),
    random: seededRandom(20251023),
    signingKeys: { [SIGNING_KID]: signing.privateKey },
    signingKid: SIGNING_KID,
    periodKeySupply: randomPeriodKeySupply(),
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        publicKey: issuerKeys.publicKey,
      },
    ],
    ...overrides,
  };
  return { config, issuerKeys, signing };
}

/** @param {Uint8Array} bytes */
const base64url = (bytes) => Buffer.from(bytes).toString("base64url");

/**
 * @param {object} config
 */
async function render(config) {
  const sealer = new Sealer(/** @type {any} */ (config));
  sealer.resource(RESOURCE_ID, {});
  sealer.content(CONTENT_NAME, ARTICLES.A, CONTENT_TYPE, { accessGroups: [ACCESS_GROUP] });
  return sealer.seal();
}

/**
 * The origin case's render through the Sealer factory, with `change` laid
 * over its setup.
 *
 * @param {object} change
 */
async function renderThroughFactory(change) {
  const publisher = await sealerForRender({ ...sealerOriginSetup(AT, "sealer-origin"), ...change });
  const { resource, content } = sealerOriginRender();
  publisher.resource(resource.resourceId, resource.data);
  for (const item of content) {
    publisher.content(item.name, item.value, item.contentType, {
      accessGroups: item.accessGroups,
    });
  }
  return publisher.seal();
}

describe("The publisher signs one delivery origin", () => {
  portableSealerTest("the origin it was configured with is the one it signs", async () => {
    const { dcaData } = await renderThroughFactory({});

    await assertSignedOrigin(dcaData.resourceJWT, ORIGIN, TEST_SIGNING_PUBLIC_KEY_SPKI);
    // The issuer block names the key the setup configured for its issuer.
    assert.equal(issuerBlockOf(dcaData, ISSUER_NAME).keyId, KEY_ID);
  });

  portableSealerTest(
    "two renders in one process keep their own time, draws and content",
    async () => {
      // A long-running process builds a Sealer per render. Two renders whose
      // calls interleave must not see each other's clock, random draws or
      // collected items.
      /** @param {string} contentName */
      const scope = (contentName) => ({
        issuerSupplyPlans: {
          [ISSUER_NAME]: { contentKeyNames: [contentName], suppliedAccessGroups: [] },
        },
      });
      const first = await sealerForRender({
        ...sealerOriginSetup("2025-10-23T14:20:00Z", "sealer-origin"),
        ...scope("first"),
      });
      const second = await sealerForRender({
        ...sealerOriginSetup("2025-11-02T08:05:00Z", "sealer-origin-second"),
        ...scope("second"),
      });
      first.resource("first-resource", {});
      second.resource("second-resource", {});
      // The origin setup holds no period-key supply, so each item names no
      // group and opens through its item key alone.
      first.content("first", ARTICLES.A, CONTENT_TYPE, { accessGroups: [] });
      second.content("second", ARTICLES.A, CONTENT_TYPE, { accessGroups: [] });
      const secondSealed = await second.seal();
      const firstSealed = await first.seal();

      for (const [sealed, instant, label, resourceId, contentName] of /** @type {const} */ ([
        [firstSealed, "2025-10-23T14:20:00.000Z", "sealer-origin", "first-resource", "first"],
        [
          secondSealed,
          "2025-11-02T08:05:00.000Z",
          "sealer-origin-second",
          "second-resource",
          "second",
        ],
      ])) {
        const { resource, resourceJWT } = sealed.dcaData;
        // The reference draws the render id and content key in that order.
        // Content and ordinary ECDH envelopes use implicit zero nonces.
        const stream = labelStream(label, 32);
        const renderId = stream.subarray(0, 16);
        const contentKeyBytes = stream.subarray(16, 32);
        const contentNonce = new Uint8Array(12);
        await assertSignedOrigin(resourceJWT, ORIGIN, TEST_SIGNING_PUBLIC_KEY_SPKI);
        assert.equal(resource.issuedAt, instant);
        assert.equal(resource.renderId, base64url(renderId));
        assert.equal(resource.resourceId, resourceId);
        assert.deepEqual(contentNamesOn(sealed.dcaData), [contentName]);
        assert.equal(Object.hasOwn(contentRecordOf(sealed.dcaData, contentName), "nonce"), false);
        const contentKey = await crypto.subtle.importKey(
          "raw",
          contentKeyBytes,
          { name: "AES-GCM" },
          false,
          ["decrypt"],
        );
        const plaintext = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: contentNonce,
            additionalData: contentAadOctets(sealed.dcaData, contentName),
          },
          contentKey,
          Buffer.from(sealed.sealedContent[contentName], "base64url"),
        );
        assert.equal(new TextDecoder().decode(plaintext), ARTICLES.A);
        const envelope = contentKeyMap(
          issuerBlockOf(sealed.dcaData, ISSUER_NAME).sealed.contentKeys,
        )[contentName];
        assert.equal(Buffer.from(envelope, "base64url").length, 97);
        // The issuer opens the envelope at its coordinate to the drawn content key.
        const opened = await openEcdhEnvelope(
          envelope,
          `dca-bind-key-envelope|c|${resource.renderId}|${contentName}`,
          TEST_ISSUER_PRIVATE_KEY_PKCS8,
        );
        assert.equal(base64url(opened), base64url(contentKeyBytes));
      }
    },
  );

  test("an origin that is missing or not canonical is refused at construction", async () => {
    const { config } = await sealerWith();
    const { origin, ...without } = config;

    assert.throws(
      () => new Sealer(/** @type {any} */ (without)),
      (/** @type {any} */ error) => error.code === "bad_config",
      "a render with no origin has nothing for an issuer to admit it at",
    );

    for (const value of [
      "www.news-site.example",
      "HTTPS://www.news-site.example",
      "https://www.news-site.example/",
      "https://www.news-site.example:443",
      "https://www.news-site.example/news",
      "https://www.news-site.example|x",
      "https://[2001:DB8::1]",
      "https://[fe80::1%25eth0]",
      "https://[2001:db8::1",
    ]) {
      assert.throws(
        () => new Sealer(/** @type {any} */ ({ ...config, origin: value })),
        (/** @type {any} */ error) => error.code === "bad_config",
        `${JSON.stringify(value)} is not the canonical origin the issuer compares byte for byte`,
      );
    }
  });

  portableRefusalTest(
    "through the Sealer factory, an origin that is missing or not canonical is refused",
    async () => {
      for (const refused of typedRefusals(sealerRefusalCases().origin)) {
        await assertRefusalCase(sealerForRender, refused);
      }
    },
  );

  test("a canonical IPv6 literal is a delivery origin like any other", async () => {
    // The publisher signs the bracketed literal the browser will report,
    // port and all. The mapped literal is hexadecimal here for the same
    // reason it is in the header: the URL serializer has no dotted form.
    const { config } = await sealerWith();

    for (const value of sealerAdmittedOrigins().ipv6) {
      const { dcaData } = await render({ ...config, origin: value });

      assert.equal(decodeCompactJwt(dcaData.resourceJWT).payload.origin, value);
    }
  });

  portableSealerTest(
    "through the Sealer factory, a canonical IPv6 literal is signed as given",
    async () => {
      for (const origin of sealerAdmittedOrigins().ipv6) {
        const { dcaData } = await renderThroughFactory({ origin });

        await assertSignedOrigin(dcaData.resourceJWT, origin, TEST_SIGNING_PUBLIC_KEY_SPKI);
      }
    },
  );
});

describe("http is the development profile, and only for a localhost host", () => {
  test("an http origin is refused when the profile was not asked for", async () => {
    const { config } = await sealerWith();

    for (const value of [
      "http://publisher.example",
      "http://localhost:8080",
      "http://www-default.localhost",
    ]) {
      assert.throws(
        () => new Sealer(/** @type {any} */ ({ ...config, origin: value })),
        (/** @type {any} */ error) => error.code === "bad_config",
        `${JSON.stringify(value)} is a render over http, which a publisher signs under the profile alone`,
      );
    }
  });

  test("the profile admits http for a localhost host and for nothing else", async () => {
    const { config } = await sealerWith();

    assert.throws(
      () =>
        new Sealer(
          /** @type {any} */ ({
            ...config,
            origin: "http://publisher.example",
            developmentHttpOrigin: true,
          }),
        ),
      (/** @type {any} */ error) => error.code === "bad_config",
      "a deployment running the profile still cannot sign http for a public host",
    );

    assert.throws(
      () =>
        new Sealer(
          /** @type {any} */ ({
            ...config,
            origin: "http://[::1]:8080",
            developmentHttpOrigin: true,
          }),
        ),
      (/** @type {any} */ error) => error.code === "bad_config",
      "the profile host set is localhost, names under it and 127.0.0.1, and holds no literal",
    );

    for (const value of sealerAdmittedOrigins().developmentHttp) {
      const { dcaData } = await render({ ...config, origin: value, developmentHttpOrigin: true });

      assert.equal(decodeCompactJwt(dcaData.resourceJWT).payload.origin, value);
    }
  });

  portableSealerTest(
    "through the Sealer factory, the profile admits http for a localhost host",
    async () => {
      for (const origin of sealerAdmittedOrigins().developmentHttp) {
        const { dcaData } = await renderThroughFactory({ origin, developmentHttpOrigin: true });

        await assertSignedOrigin(dcaData.resourceJWT, origin, TEST_SIGNING_PUBLIC_KEY_SPKI);
      }
    },
  );

  portableRefusalTest(
    "through the Sealer factory, http is refused without the profile, and for a non-localhost host with it",
    async () => {
      for (const refused of typedRefusals(sealerRefusalCases().http)) {
        await assertRefusalCase(sealerForRender, refused);
      }
    },
  );

  test("an https origin signs the same with the profile on as with it off", async () => {
    const { config } = await sealerWith();
    const off = await render(config);
    const on = await render({ ...config, developmentHttpOrigin: true });

    assert.equal(decodeCompactJwt(off.dcaData.resourceJWT).payload.origin, ORIGIN);
    assert.equal(decodeCompactJwt(on.dcaData.resourceJWT).payload.origin, ORIGIN);
  });

  portableSealerTest(
    "through the Sealer factory, an https origin signs the same with the profile on as with it off",
    async () => {
      const off = await renderThroughFactory({});
      const on = await renderThroughFactory({ developmentHttpOrigin: true });

      await assertSignedOrigin(off.dcaData.resourceJWT, ORIGIN, TEST_SIGNING_PUBLIC_KEY_SPKI);
      await assertSignedOrigin(on.dcaData.resourceJWT, ORIGIN, TEST_SIGNING_PUBLIC_KEY_SPKI);
    },
  );
});
