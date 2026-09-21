// @ts-check
//
// What a render looks like with and without the extension selected. The three
// deployment claims of the prototype contract live here: an unlisted issuer is
// untouched, a listed one carries the marker and no direct map, and a listed
// issuer that cannot reach one of its grantable items fails the render closed.

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { decrypt } from "../../../core-shared/aead.js";
import { base64urlDecode } from "../../../core-shared/codec.js";
import { keyMaterialInPlay, leaks } from "../../../test-lib/helpers/keyMaterialLeaks.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import {
  EXTENSION_NAME,
  OMISSION_BIND_VERSION,
  omissionBindAad,
} from "../core-shared/omissionBind.js";
import {
  AT,
  ISSUER_A,
  ISSUER_B,
  PERIODS,
  ephemeralPool,
  render,
  world,
} from "../test-lib/world.js";

/**
 * Count every operation an issuer-supply refusal must precede.
 *
 * @param {any} source
 */
function watched(source) {
  const counts = { random: 0, derive: 0, seal: 0, sign: 0 };
  const config = {
    ...source,
    random: {
      bytes(n) {
        counts.random += 1;
        return source.random.bytes(n);
      },
    },
    periodKeySupply: {
      derive(accessGroup, t) {
        counts.derive += 1;
        return source.periodKeySupply.derive(accessGroup, t);
      },
    },
    keySealing: {
      async seal() {
        counts.seal += 1;
        return "sealed";
      },
    },
    signingKeys: Object.fromEntries(
      Object.entries(source.signingKeys).map(([kid, key]) => [
        kid,
        new Proxy(/** @type {object} */ (key), {
          get(target, name, receiver) {
            counts.sign += 1;
            return Reflect.get(target, name, receiver);
          },
        }),
      ]),
    ),
  };
  return { config, counts };
}

test("an unlisted issuer renders byte-identically to the base sealer", async () => {
  const { issuerConfig, sealerConfig } = await world();
  const providers = await ephemeralPool();

  const base = await render(
    new Sealer(sealerConfig({ issuers: [issuerConfig(ISSUER_A)], ephemeralKeyPairs: providers() })),
    { items: ["bodytext", "sidebar"] },
  );
  const composed = await render(
    new OmittingSealer(
      sealerConfig({ issuers: [issuerConfig(ISSUER_A)], ephemeralKeyPairs: providers() }),
    ),
    { items: ["bodytext", "sidebar"] },
  );

  // Every byte but the signature. ECDSA draws its own nonce inside WebCrypto,
  // which the injected `random` does not reach, so two signatures over one
  // payload differ by construction. The payload under them is compared
  // instead, decoded from the token both renders carry.
  const { resourceJWT: baseJwt, ...baseRest } = base;
  const { resourceJWT: composedJwt, ...composedRest } = composed;
  assert.equal(JSON.stringify(composedRest), JSON.stringify(baseRest));
  assert.equal(payloadOf(composedJwt), payloadOf(baseJwt));
});

/** @param {string} token @returns {string} the compact JWT's header and payload */
function payloadOf(token) {
  return token.split(".").slice(0, 2).join(".");
}

test("a listed issuer carries the marker and no direct map; an unlisted one in the same render keeps its own", async () => {
  const { issuerConfig, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] }), issuerConfig(ISSUER_B)],
      }),
    ),
    { items: ["bodytext", "note"] },
  );

  assert.deepEqual(page.issuerData[ISSUER_A].extensions, [EXTENSION_NAME]);
  assert.equal(Object.hasOwn(page.issuerData[ISSUER_A].sealed, "contentKeys"), false);
  assert.deepEqual(Object.keys(page.issuerData[ISSUER_A].sealed.periodKeys.premium), PERIODS);

  assert.equal(Object.hasOwn(page.issuerData[ISSUER_B], "extensions"), false);
  assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.contentKeys), ["bodytext", "note"]);
});

test("a serialized bound render carries none of its exact or content-key material", async () => {
  const { issuerConfig, periodKeySupply, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
  );

  const material = await keyMaterialInPlay(page, periodKeySupply, {
    additionalDataFor: ({ contentName, accessGroup, value }) =>
      omissionBindAad({
        renderId: page.resource.renderId,
        contentName,
        accessGroup,
        t: value.t,
      }),
  });
  assert.deepEqual(
    material.map(({ label }) => label),
    [
      `the periodKey for premium/${PERIODS[0]}`,
      "the contentKey for bodytext",
      `the periodKey for premium/${PERIODS[1]}`,
    ],
  );
  assert.deepEqual(leaks(JSON.stringify(page), material), []);
});

test("two omission configurations cannot collapse under one issuer name", async () => {
  const { issuerConfig, sealerConfig } = await world();

  assert.throws(
    () =>
      new OmittingSealer(
        sealerConfig({
          issuers: [
            issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] }),
            issuerConfig(ISSUER_A),
          ],
        }),
      ),
    (/** @type {any} */ error) => {
      assert.equal(error.code, "bad_config");
      assert.equal(error.message, `issuerName "${ISSUER_A}" is configured more than once`);
      return true;
    },
  );
});

test("a bound entry names the binding it was wrapped under and opens only with that aad", async () => {
  const { issuerConfig, periodKeySupply, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
  );

  const entries = page.contentData.bodytext.keys.premium;
  assert.deepEqual(
    entries.map((/** @type {any} */ entry) => entry.bind),
    [OMISSION_BIND_VERSION, OMISSION_BIND_VERSION],
  );

  const entry = entries[0];
  const periodKey = await periodKeySupply.derive("premium", entry.t);
  const nonce = base64urlDecode(entry.nonce);
  const wrapped = base64urlDecode(entry.key);

  await assert.rejects(
    decrypt(periodKey, nonce, wrapped),
    "an unbound open of a bound entry fails",
  );
  const contentKey = await decrypt(
    periodKey,
    nonce,
    wrapped,
    omissionBindAad({
      renderId: page.resource.renderId,
      contentName: "bodytext",
      accessGroup: "premium",
      t: entry.t,
    }),
  );
  assert.equal(contentKey.length, 16);
});

test("a listed issuer whose period material covers no group of a grantable item fails the render closed", async () => {
  const { issuerConfig, sealerConfig } = await world();

  const observed = watched(
    sealerConfig({
      issuers: [
        issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME], accessGroups: ["premium"] }),
      ],
    }),
  );

  await assert.rejects(
    render(new OmittingSealer(observed.config), { items: ["bodytext", "sidebar"] }),
    (/** @type {any} */ error) => {
      assert.equal(error.code, "bad_config");
      assert.match(error.message, /must reach "sidebar"/);
      return true;
    },
  );
  assert.deepEqual(observed.counts, { random: 0, derive: 0, seal: 0, sign: 0 });

  // The same render is fine once the uncovered item is outside what this
  // issuer is asked to grant and another issuer supplies the route.
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [
          issuerConfig(ISSUER_A, {
            extensions: [EXTENSION_NAME],
            accessGroups: ["premium"],
            grantable: ["bodytext"],
          }),
          issuerConfig(ISSUER_B),
        ],
      }),
    ),
    { items: ["bodytext", "sidebar"] },
  );
  assert.deepEqual(Object.keys(page.issuerData[ISSUER_A].sealed.periodKeys), ["premium"]);
  assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.contentKeys), [
    "bodytext",
    "sidebar",
  ]);
});

test("an active omission issuer without period supply refuses before base render work", async () => {
  const { issuerConfig, sealerConfig } = await world();
  const observed = watched(
    sealerConfig({
      issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
    }),
  );
  delete observed.config.periodKeySupply;

  assert.throws(
    () => new OmittingSealer(observed.config),
    (/** @type {any} */ error) => {
      assert.equal(error.code, "bad_config");
      assert.match(error.message, /has no periodKeySupply to route through/);
      return true;
    },
  );
  assert.deepEqual(observed.counts, { random: 0, derive: 0, seal: 0, sign: 0 });
});

test("a render at a stated instant carries the two periods its bound entries are labelled with", async () => {
  const { issuerConfig, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        at: AT,
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
  );

  assert.deepEqual(
    page.contentData.bodytext.keys.premium.map((/** @type {any} */ entry) => entry.t),
    PERIODS,
  );
});
