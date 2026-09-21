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

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../core-publisher/Sealer.js";
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
  UNLOCK_URL,
} from "../../demo/scenarios/fixtures.js";
import { exactPeriodKeySupply } from "../../demo/support/exactPeriodKeySupply.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../support/keys.js";

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
    periodKeySupply: exactPeriodKeySupply(),
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        publicKey: issuerKeys.publicKey,
        unlockUrl: UNLOCK_URL,
      },
    ],
    ...overrides,
  };
  return { config, issuerKeys, signing };
}

/**
 * @param {object} config
 */
async function render(config) {
  const sealer = new Sealer(/** @type {any} */ (config));
  sealer.resource(RESOURCE_ID, {});
  sealer.content(CONTENT_NAME, ARTICLES.A, CONTENT_TYPE, { accessGroups: [ACCESS_GROUP] });
  return sealer.seal();
}

describe("The publisher signs one delivery origin", () => {
  test("the origin it was configured with is the one it signs", async () => {
    const { config } = await sealerWith();
    const { dcaData } = await render(config);

    assert.equal(decodeCompactJwt(dcaData.resourceJWT).payload.origin, ORIGIN);
  });

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

  test("a canonical IPv6 literal is a delivery origin like any other", async () => {
    // The publisher signs the bracketed literal the browser will report,
    // port and all. The mapped literal is hexadecimal here for the same
    // reason it is in the header: the URL serializer has no dotted form.
    const { config } = await sealerWith();

    for (const value of [
      "https://[2001:db8::1]",
      "https://[2001:db8::1]:8443",
      "https://[::ffff:7f00:1]",
    ]) {
      const { dcaData } = await render({ ...config, origin: value });

      assert.equal(decodeCompactJwt(dcaData.resourceJWT).payload.origin, value);
    }
  });
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

    for (const value of [
      "http://localhost:8080",
      "http://www-default.localhost",
      "http://127.0.0.1:8000",
    ]) {
      const { dcaData } = await render({ ...config, origin: value, developmentHttpOrigin: true });

      assert.equal(decodeCompactJwt(dcaData.resourceJWT).payload.origin, value);
    }
  });

  test("an https origin signs the same with the profile on as with it off", async () => {
    const { config } = await sealerWith();
    const off = await render(config);
    const on = await render({ ...config, developmentHttpOrigin: true });

    assert.equal(decodeCompactJwt(off.dcaData.resourceJWT).payload.origin, ORIGIN);
    assert.equal(decodeCompactJwt(on.dcaData.resourceJWT).payload.origin, ORIGIN);
  });
});
