// @ts-check

// Composition coverage for two independently removable extensions. This test
// lives outside either extension so neither package imports its sibling.

import test from "node:test";
import assert from "node:assert/strict";

import { Client } from "../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import { actorWorld } from "../demo/scenarios/world.js";
import { keyDerivationSecret } from "../demo/scenarios/fixtures.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { base64urlEncode, utf8Decode } from "../core-shared/codec.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";
import { KeyDelivery } from "../adapter-issuer/KeyDelivery.js";
import { chainKeyRequestBuilderFactory } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import * as rsaProfile from "../extensions/client-bound-transport/rsaOaep.js";
import * as ecdhProfile from "../extensions/client-bound-transport/ecdhP256.js";
import { clientBoundKeyCapability } from "../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  CONTENT_NAME,
  ISSUER_NAME as PRIMARY,
  UNLOCK_URL as PRIMARY_UNLOCK,
} from "../demo/scenarios/fixtures.js";
import { issuerBlockOf, recordNamed } from "../test-lib/helpers/inspect.js";

const PUBLISHER_ORIGIN = "https://www.news-site.example";
const CHAIN_GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

function chainPeriodKeySupply() {
  return periodFamilySupply({
    families: {
      [ACCESS_GROUP]: periodFamilyGeneration({
        keyDerivationSecret: keyDerivationSecret(7),
        geometry: CHAIN_GEOMETRY,
      }),
    },
    chainWindows: 2,
  });
}

async function clientKeys() {
  const pair = /** @type {CryptoKeyPair} */ (
    await globalThis.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
      "deriveKey",
    ])
  );
  return {
    privateKey: pair.privateKey,
    publicKey: await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey),
  };
}

test("a synthetic chain marker leaves a client-bound period-key handle in the ordinary period-key cache", async () => {
  const stage = await actorWorld({
    transportMode: "client-bound",
    clientBoundProfile: ecdhProfile,
    period: { length: 15, slots: 1 },
    periodKeySupply: chainPeriodKeySupply(),
  });
  const periodKeyCache = new PeriodKeyCache();
  const chainCache = new ChainKeyCache();
  const client = new Client({
    publisherOrigin: PUBLISHER_ORIGIN,
    cache: periodKeyCache,
    chainCache,
    chainKeyProfile: referenceChainKeyProfile,
    clientBoundKeyCapability: clientBoundKeyCapability(await clientKeys(), ecdhProfile),
  });

  const markChainEnabled = (page) => {
    const sealed = issuerBlockOf(page, PRIMARY).sealed;
    const accessGroup = sealed.periodKeys[0].accessGroup;
    sealed.chainKeys = [
      { accessGroup, cutoff: "251023T2345", key: "AQ" },
      { accessGroup, cutoff: "251024T1145", key: "Ag" },
    ];
    page.periodGeometry = {
      accessGroups: {
        [accessGroup]: { chainsPerDay: 2, periodMinutes: 15 },
      },
    };
  };

  const pageA = (await stage.render("A")).asJson();
  markChainEnabled(pageA);
  const dataA = client.parse(pageA);
  const request = client.buildRequest(dataA, PRIMARY, [CONTENT_NAME]);
  const answer = await stage.network.post(PRIMARY_UNLOCK, request, { origin: PUBLISHER_ORIGIN });
  assert.equal(answer.status, 200);
  assert.equal(answer.body.transport.method, ecdhProfile.METHOD);
  await client.applyResponse(dataA, PRIMARY, answer.body, request);

  assert.equal(
    (await periodKeyCache.entries()).length,
    1,
    "received period-key handles stay in the ordinary period-key family",
  );
  assert.deepEqual(
    chainCache.entries(),
    [],
    "no issuer-returned period-key handle enters the chain partition",
  );

  const pageB = (await stage.render("B")).asJson();
  markChainEnabled(pageB);
  const dataB = client.parse(pageB);
  const contentKey = await client.contentKeyFor(dataB, CONTENT_NAME);
  assert.ok(
    contentKey instanceof globalThis.CryptoKey,
    "the period-key handle opens another handle",
  );
  assert.equal(contentKey.extractable, false);
  assert.deepEqual([...contentKey.usages], ["decrypt"]);
  assert.equal(
    utf8Decode(await client.decrypt(dataB, CONTENT_NAME, client.extract(pageB, CONTENT_NAME))),
    ARTICLES.B,
  );
  assert.equal(stage.network.stats()[PRIMARY_UNLOCK].attempts, 1, "B needed no second unlock");
});

test("a chain section beside transport is classified before mixed key entries reject the representation", async () => {
  const stage = await actorWorld({
    transportMode: "client-bound",
    clientBoundProfile: ecdhProfile,
    period: { length: 15, slots: 1 },
    periodKeySupply: chainPeriodKeySupply(),
  });
  const periodKeyCache = new PeriodKeyCache();
  const chainCache = new ChainKeyCache();
  const client = new Client({
    publisherOrigin: PUBLISHER_ORIGIN,
    cache: periodKeyCache,
    chainCache,
    chainKeyProfile: referenceChainKeyProfile,
    clientBoundKeyCapability: clientBoundKeyCapability(await clientKeys(), ecdhProfile),
  });

  const page = (await stage.render("A")).asJson();
  const data = client.parse(page);
  const request = client.buildRequest(data, PRIMARY, [CONTENT_NAME]);
  const answer = await stage.network.post(PRIMARY_UNLOCK, request, { origin: PUBLISHER_ORIGIN });
  assert.equal(answer.body.transport.method, ecdhProfile.METHOD);
  const wrapped = (answer.body.keys.periodKeys ?? []).filter(
    (record) => record.accessGroup === ACCESS_GROUP,
  );
  assert.equal(
    wrapped.length > 0,
    true,
    "the composition delivers at least one wrapped period key",
  );

  // One response carrying all three: a malformed chain coordinate beside a
  // valid wrapped period key of a supported section and a content key of
  // another.
  const mixed = structuredClone(answer.body);
  mixed.keys.chainKeys = [
    {
      accessGroup: ACCESS_GROUP,
      cutoff: "251023T2345",
      key: base64urlEncode(new Uint8Array(16).fill(3)),
    },
  ];
  mixed.periodGeometry = { chainsPerDay: 2, periodMinutes: 15 };
  mixed.keys.contentKeys = [
    { contentName: CONTENT_NAME, key: base64urlEncode(new Uint8Array(16).fill(5)) },
  ];

  const applied = await client.applyResponse(page, PRIMARY, mixed, request);

  assert.deepEqual(
    applied.issues,
    [{ section: "response", code: "invalid_transport" }],
    "mixed supported key entries reject the representation before chain coordinate admission",
  );
  assert.equal(applied.accepted, 0, "response-scope rejection retains no earlier wrapped sibling");
  assert.deepEqual(
    chainCache.entries(),
    [],
    "no chain key is retained beside client-bound transport",
  );
  assert.equal(
    (await client.contentKeyFor(data, CONTENT_NAME)) instanceof Uint8Array,
    false,
    "the content key is not held",
  );
});

// Publisher envelopes are relay material here. KeyDelivery supplies real
// recipient ciphertext, so these cases isolate response admission and opening.
async function chainResponseFixture(profile) {
  const stage = await actorWorld({
    period: { length: 15, slots: 1 },
    periodKeySupply: chainPeriodKeySupply(),
  });
  const pair =
    profile === ecdhProfile
      ? await clientKeys()
      : await (async () => {
          const keys = /** @type {CryptoKeyPair} */ (
            await globalThis.crypto.subtle.generateKey(
              {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
              },
              false,
              ["unwrapKey", "decrypt"],
            )
          );
          return {
            privateKey: keys.privateKey,
            publicKey: await globalThis.crypto.subtle.exportKey("jwk", keys.publicKey),
          };
        })();
  const capability = clientBoundKeyCapability(pair, profile);
  const calls = { agreements: 0, opens: 0, periodKeyWrites: 0, chainWrites: 0 };
  const periodKeyCache = new PeriodKeyCache();
  const chainCache = new ChainKeyCache();
  const periodKeyPut = periodKeyCache.put.bind(periodKeyCache);
  const chainPut = chainCache.put.bind(chainCache);
  periodKeyCache.put = async (...args) => {
    calls.periodKeyWrites++;
    await periodKeyPut(...args);
  };
  chainCache.put = async (...args) => {
    calls.chainWrites++;
    await chainPut(...args);
  };
  const client = new Client({
    publisherOrigin: PUBLISHER_ORIGIN,
    cache: periodKeyCache,
    chainCache,
    chainKeyProfile: referenceChainKeyProfile,
    requestBuilderFactory: chainKeyRequestBuilderFactory,
    clientBoundKeyCapability: {
      publicKey: capability.publicKey,
      assertCanOpenChainKeys: () => capability.assertCanOpenChainKeys(),
      async openDeliveredKeys(transport) {
        calls.agreements++;
        const opener = await capability.openDeliveredKeys(transport);
        return {
          async open(...args) {
            calls.opens++;
            return opener.open(...args);
          },
        };
      },
    },
  });
  const rawPage = (await stage.render("A")).asJson();
  issuerBlockOf(rawPage, PRIMARY).sealed.chainKeys = [
    { accessGroup: ACCESS_GROUP, cutoff: "251023T1145", key: "AQ" },
    { accessGroup: ACCESS_GROUP, cutoff: "251023T2345", key: "Ag" },
  ];
  rawPage.periodGeometry = { chainsPerDay: 2, periodMinutes: 15 };
  const page = client.parse(rawPage);
  const request = client.buildRequest(page, PRIMARY, [CONTENT_NAME]);
  const delivery = new KeyDelivery({
    profile,
    random: { bytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)) },
  });
  const view = await delivery.preflight("client-bound", new DcaRequest(request));
  const response = await delivery.prepare(
    {
      keys: {
        chainKeys: [
          {
            accessGroup: ACCESS_GROUP,
            cutoff: "251023T1100",
            key: base64urlEncode(new Uint8Array(16).fill(6)),
          },
          {
            accessGroup: ACCESS_GROUP,
            cutoff: "251023T1400",
            key: base64urlEncode(new Uint8Array(16).fill(7)),
          },
        ],
      },
    },
    view,
  );
  return { client, page, request, response, calls, periodKeyCache, chainCache };
}

for (const profile of [ecdhProfile, rsaProfile]) {
  test(`${profile.METHOD} refuses invalid captured request geometry and unsolicited cutoffs before opening or writing`, async () => {
    for (const variant of [
      "invalid geometry",
      "different geometry",
      "unsolicited window",
      "above supplied ceiling",
    ]) {
      const fixture = await chainResponseFixture(profile);
      const { response, client, page, request, calls } = fixture;
      // Use one wrapped chain key so a valid sibling cannot mask private-key work.
      const wrapped = recordNamed(response.keys.chainKeys, "cutoff", "251023T1400").key;
      response.keys.chainKeys = [
        { accessGroup: ACCESS_GROUP, cutoff: "251023T1400", key: wrapped },
      ];
      if (variant === "invalid geometry")
        request.periodGeometry = { ...CHAIN_GEOMETRY, periodMinutes: 7 };
      if (variant === "different geometry") request.periodGeometry = { periodMinutes: 15 };
      if (variant === "unsolicited window")
        response.keys.chainKeys = [
          { accessGroup: ACCESS_GROUP, cutoff: "251024T1400", key: wrapped },
        ];
      if (variant === "above supplied ceiling") {
        // The request ceiling is positioned below the returned cutoff, within
        // the same window. Rebuild the association from the actual relay.
        const rawPage = structuredClone(page);
        issuerBlockOf(rawPage, PRIMARY).sealed.chainKeys = [
          { accessGroup: ACCESS_GROUP, cutoff: "251023T1300", key: "Aw" },
        ];
        const limited = client.parse(rawPage);
        const limitedRequest = client.buildRequest(limited, PRIMARY, [CONTENT_NAME]);
        const result = await client.applyResponse(limited, PRIMARY, response, limitedRequest);
        assert.equal(result.accepted, 0, variant);
        assert.ok(
          result.issues.some((issue) => issue.section === "chainKeys"),
          variant,
        );
      } else {
        const result = await client.applyResponse(page, PRIMARY, response, request);
        assert.equal(result.accepted, 0, variant);
        assert.ok(
          result.issues.some((issue) => issue.section === "chainKeys"),
          variant,
        );
      }
      assert.deepEqual(
        calls,
        { agreements: 0, opens: 0, periodKeyWrites: 0, chainWrites: 0 },
        variant,
      );
      assert.deepEqual(fixture.chainCache.entries(), [], variant);
      assert.deepEqual(await fixture.periodKeyCache.entries(), [], variant);
    }
  });

  test(`${profile.METHOD} retains a valid chain sibling beside a malformed, tampered, or wrong-width chain key`, async () => {
    for (const variant of ["malformed", "tampered", "wrong width"]) {
      const { client, page, request, response, calls, chainCache } =
        await chainResponseFixture(profile);
      const wrapped = recordNamed(response.keys.chainKeys, "cutoff", "251023T1400").key;
      if (variant === "wrong width") {
        // Bypass KeyDelivery's issuer width guard deliberately: the receiver
        // must also refuse authenticated material of the wrong chain width.
        const { subtle } = globalThis.crypto;
        // Both carriers bind the chain-key kind context of
        // docs/spec--response-binding.md section 6, so only the width differs
        // from an honest chainKeys entry.
        const chainKeyContext = Uint8Array.from([
          ...new TextEncoder().encode("dca-bind-client-bound-key-kind"),
          0,
          ...new TextEncoder().encode("chainKey"),
        ]);
        let wrap;
        if (profile === rsaProfile) {
          const { kty, n, e } = request.clientPublicKey;
          const publicKey = await subtle.importKey(
            "jwk",
            { kty, n, e },
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"],
          );
          wrap = async (bytes) => ({
            key: base64urlEncode(
              new Uint8Array(
                await subtle.encrypt(
                  { name: "RSA-OAEP", label: chainKeyContext },
                  publicKey,
                  bytes,
                ),
              ),
            ),
          });
          response.transport = { method: profile.METHOD };
        } else {
          const ephemeral = /** @type {CryptoKeyPair} */ (
            await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
          );
          const peer = await subtle.importKey(
            "jwk",
            request.clientPublicKey,
            { name: "ECDH", namedCurve: "P-256" },
            false,
            [],
          );
          const material = await subtle.deriveKey(
            { name: "ECDH", public: peer },
            ephemeral.privateKey,
            "HKDF",
            false,
            ["deriveKey"],
          );
          const aes = await subtle.deriveKey(
            {
              name: "HKDF",
              hash: "SHA-256",
              salt: new Uint8Array(0),
              info: new TextEncoder().encode("dca-derivation-client-bound-transport"),
            },
            material,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt"],
          );
          wrap = async (bytes) => {
            const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
            return {
              key: base64urlEncode(
                new Uint8Array(
                  await subtle.encrypt(
                    { name: "AES-GCM", iv: nonce, additionalData: chainKeyContext },
                    aes,
                    bytes,
                  ),
                ),
              ),
              nonce: base64urlEncode(nonce),
            };
          };
          const { kty, crv, x, y } = await subtle.exportKey("jwk", ephemeral.publicKey);
          response.transport = {
            method: profile.METHOD,
            publicKey: { kty, crv, x, y },
          };
        }
        response.keys.chainKeys = [
          {
            accessGroup: ACCESS_GROUP,
            cutoff: "251023T1100",
            key: await wrap(new Uint8Array(16).fill(6)),
          },
          {
            accessGroup: ACCESS_GROUP,
            cutoff: "251023T1400",
            key: await wrap(new Uint8Array(17).fill(7)),
          },
        ];
      } else if (variant === "malformed") wrapped.key = "%%%";
      else wrapped.key = (wrapped.key[0] === "A" ? "B" : "A") + wrapped.key.slice(1);
      const result = await client.applyResponse(page, PRIMARY, response, request);
      assert.equal(result.accepted, 1, variant);
      assert.deepEqual(result.issues, [{ section: "chainKeys", code: "malformed_key" }], variant);
      assert.equal(calls.chainWrites, 1, variant);
      assert.equal(calls.periodKeyWrites, 0, variant);
      const retained = chainCache.entries();
      assert.equal(retained.length, 1, variant);
      assert.equal(retained[0].t, "251023T1100", variant);
    }
  });
}
