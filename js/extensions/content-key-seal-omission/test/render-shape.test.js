// @ts-check
//
// What a render looks like with and without the extension selected. The three
// deployment claims of the prototype contract live here: an unlisted issuer is
// untouched, a listed one carries the marker and no `contentKeys` map, and a
// listed issuer that cannot reach one of its grantable items fails the render
// closed.

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { decrypt } from "../../../core-shared/aead.js";
import { base64urlDecode } from "../../../core-shared/codec.js";
import { recordsByName } from "../../../core-shared--client-publisher/deliveryRecords.js";
import { keyMaterialInPlay, leaks } from "../../../test-lib/helpers/keyMaterialLeaks.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import {
  EXTENSION_NAME,
  OMISSION_BIND_IDENTIFIER,
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
import { contentKeyWrapNonceOctets } from "../../../test-reference/support/contentKeyWrapNonceOctets.js";

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

/**
 * One named record of a page collection, looked up the way a reader does.
 *
 * @param {unknown} collection
 * @param {string} member - the identity field, such as `issuerName`
 * @param {string} name
 * @returns {any}
 */
function recordOf(collection, member, name) {
  return recordsByName(collection, member, () => true)?.get(name);
}

/**
 * The distinct values of one field across records, in first-seen order.
 *
 * @param {any[]} records
 * @param {string} member
 * @returns {unknown[]}
 */
function distinct(records, member) {
  return [...new Set(records.map((record) => record[member]))];
}

/** @param {string} token @returns {string} the compact JWT's header and payload */
function payloadOf(token) {
  return token.split(".").slice(0, 2).join(".");
}

test("a listed issuer has the marker and no contentKeys map; an unlisted one in the render keeps its own", async () => {
  const { issuerConfig, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] }), issuerConfig(ISSUER_B)],
      }),
    ),
    { items: ["bodytext", "note"] },
  );

  const listed = recordOf(page.issuerData, "issuerName", ISSUER_A);
  const unlisted = recordOf(page.issuerData, "issuerName", ISSUER_B);
  assert.deepEqual(listed.extensions, [EXTENSION_NAME]);
  assert.equal(Object.hasOwn(listed.sealed, "contentKeys"), false);
  assert.deepEqual(
    listed.sealed.periodKeys
      .filter((/** @type {any} */ record) => record.accessGroup === "premium")
      .map((/** @type {any} */ record) => record.period),
    PERIODS,
  );

  assert.equal(Object.hasOwn(unlisted, "extensions"), false);
  assert.deepEqual(
    unlisted.sealed.contentKeys.map((/** @type {any} */ record) => record.contentName),
    ["bodytext", "note"],
  );
});

test("a serialized bound render carries none of its period-key or content-key material", async () => {
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
        t: value.period,
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

  const entries = recordOf(page.contentData, "contentName", "bodytext").keys.filter(
    (/** @type {any} */ entry) => entry.accessGroup === "premium",
  );
  assert.deepEqual(
    entries.map((/** @type {any} */ entry) => entry.bind),
    [OMISSION_BIND_IDENTIFIER, OMISSION_BIND_IDENTIFIER],
  );

  const entry = entries[0];
  const periodKey = await periodKeySupply.derive("premium", entry.period);
  const coordinate = {
    renderId: page.resource.renderId,
    contentName: "bodytext",
    accessGroup: "premium",
    t: entry.period,
  };
  const aad = omissionBindAad(coordinate);
  const wrapped = base64urlDecode(entry.key);

  await assert.rejects(
    decrypt(periodKey, contentKeyWrapNonceOctets({ ...coordinate, aad }), wrapped),
    "the bound nonce with missing GCM AAD fails",
  );
  await assert.rejects(
    decrypt(periodKey, contentKeyWrapNonceOctets(coordinate), wrapped, aad),
    "the ordinary nonce with correct GCM AAD fails",
  );
  const contentKey = await decrypt(
    periodKey,
    contentKeyWrapNonceOctets({ ...coordinate, aad }),
    wrapped,
    aad,
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
  assert.deepEqual(
    distinct(recordOf(page.issuerData, "issuerName", ISSUER_A).sealed.periodKeys, "accessGroup"),
    ["premium"],
  );
  assert.deepEqual(
    distinct(recordOf(page.issuerData, "issuerName", ISSUER_B).sealed.contentKeys, "contentName"),
    ["bodytext", "sidebar"],
  );
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
    recordOf(page.contentData, "contentName", "bodytext")
      .keys.filter((/** @type {any} */ entry) => entry.accessGroup === "premium")
      .map((/** @type {any} */ entry) => entry.period),
    PERIODS,
  );
});
