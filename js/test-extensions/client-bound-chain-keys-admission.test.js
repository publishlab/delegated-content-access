// @ts-check
//
// Composition coverage for client-bound transport selection with a
// chain-key grant. The response keeps its chain geometry unwrapped, while
// the one chain key travels through the selected client-bound method.

import test from "node:test";
import assert from "node:assert/strict";
import { hkdfSync } from "node:crypto";
import { base64urlDecode, base64urlEncode } from "../core-shared/codec.js";

import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import * as clientBoundEcdh from "../extensions/client-bound-transport/ecdhP256.js";
import * as clientBoundRsa from "../extensions/client-bound-transport/rsaOaep.js";
import { clientBoundKeyCapability } from "../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";
import { Sealer } from "../core-publisher/Sealer.js";
import { Client } from "../test-lib/harnesses/client.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { chainKeyRequestBuilderFactory } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { Random } from "../demo/actors/Random.js";
import { Clock } from "../demo/actors/Clock.js";
import { Network } from "../demo/actors/Network.js";
import { IssuerServer } from "../demo/actors/IssuerServer.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import { openingKeysOver, PublisherRegistrations } from "../demo/support/PublisherRegistrations.js";
import { wholeRenderIssuerSupplyPlan } from "../core-publisher/issuerSupplyPlan.js";
import { recordNamed, wrapsOf } from "../test-lib/helpers/inspect.js";

const { subtle } = globalThis.crypto;

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const DOMAIN = "www.news-site.example";
const AT = "2025-10-23T14:20:00Z";

const PUB = `https://${DOMAIN}`;
const PERIOD_SECRET = new Uint8Array(32).fill(7);
const ARTICLE_A = "<p>The council voted 7-2 to rezone the harbour.</p>";
const ARTICLE_B = "<p>The ferry timetable changes on Monday.</p>";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

/**
 * The premium family's chain-key records in one response, in wire order.
 *
 * @param {any} body
 * @returns {any[]}
 */
const premiumChains = (body) =>
  (body.keys.chainKeys ?? []).filter(
    (/** @type {any} */ record) => record.accessGroup === "premium",
  );

/**
 * @returns {Promise<{ keyStore: object, publisherRegistration: object, render: (resourceId: string, value: string) => Promise<any> }>}
 */
async function world({
  chainItemSlots = 1,
  periodKeySupply = periodFamilySupply({
    families: {
      premium: periodFamilyGeneration({ keyDerivationSecret: PERIOD_SECRET, geometry: GEOMETRY }),
    },
    chainWindows: 2,
    chainItemSlots,
  }),
} = {}) {
  const issuerKeys = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const signingKeys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);

  let seed = 1;

  /**
   * @param {string} resourceId
   * @param {string} value
   */
  async function render(resourceId, value, at = AT) {
    const sealer = new Sealer({
      origin: PUB,
      clock: new Clock(at),
      random: new Random({ seed: seed++ }),
      signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
      periodKeySupply,
      issuerSupplyPlanFor: (issuer, render) => ({
        ...wholeRenderIssuerSupplyPlan(issuer, render),
        contentKeyNames: [],
        periodKeyDelivery: { premium: ["chain-keys"] },
      }),
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: "ecdh-p256",
          publicKey: issuerKeys.publicKey,
        },
      ],
    });

    sealer.resource(resourceId, { section: "politics" });
    sealer.content("bodytext", value, "text/html", { accessGroups: ["premium"] });

    const rendered = await sealer.seal();
    return JSON.parse(
      JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
    );
  }

  const keyStore = {
    /**
     * @param {string} issuerName
     * @param {string} keyId
     */
    get(issuerName, keyId) {
      if (issuerName !== ISSUER_NAME || keyId !== KEY_ID) return undefined;
      return { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey };
    },
  };

  const publisherRegistration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]),
    },
  ]).get(SIGNING_KID);

  return { keyStore, publisherRegistration, render };
}

async function clientKeysFor(profile) {
  const params =
    profile === clientBoundEcdh
      ? { name: "ECDH", namedCurve: "P-256" }
      : {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        };
  const usages = profile === clientBoundEcdh ? ["deriveKey"] : ["unwrapKey", "decrypt"];
  const pair = /** @type {CryptoKeyPair} */ (await subtle.generateKey(params, false, usages));
  return {
    privateKey: pair.privateKey,
    publicKey: await subtle.exportKey("jwk", pair.publicKey),
  };
}

// Independent Node HKDF computation of the fixed family's period key at one
// position of the 12:00 window: 0 is 251023T1200, 9 is 251023T1415.
// docs/spec-profile--chain-keys.md sections 6.4–6.5 fix these context octets:
// domain, length-prefixed construction/group, geometry, window start, position.
/** @param {number} periodPosition */
function expectedPeriodKey(periodPosition) {
  const info = Buffer.concat([
    Buffer.from([0, 0, 27]),
    Buffer.from("dca-construction-chain-keys"),
    Buffer.from([0, 7]),
    Buffer.from("premium"),
    Buffer.alloc(10),
  ]);
  const tail = info.length - 10;
  info.writeUInt16BE(2, tail);
  info.writeUInt16BE(15, tail + 2);
  info.writeUInt32BE(Date.UTC(2025, 9, 23, 12) / 60000, tail + 4);
  const derive = (domain, position, input) => {
    info[0] = domain;
    info.writeUInt16BE(position, tail + 8);
    return new Uint8Array(hkdfSync("sha256", input, Buffer.alloc(0), info, 16));
  };
  let chainKey = derive(1, 47, PERIOD_SECRET);
  for (let position = 46; position >= periodPosition; position--) {
    chainKey = derive(2, position, chainKey);
  }
  return derive(3, periodPosition, chainKey);
}

test("IssuerServer admits a fixed client-bound chain composition", async () => {
  const source = await world();
  const clock = new Clock(AT);
  const network = new Network({ clock });

  assert.doesNotThrow(
    () =>
      new IssuerServer({
        clock,
        network,
        random: new Random({ seed: 1 }),
        issuerName: ISSUER_NAME,
        unlockUrl: "https://api.example.com/unlock",
        keyStore: source.keyStore,
        publisherRegistrations: new PublisherRegistrations([source.publisherRegistration]),
        accessPolicy: new AllowAllPolicy(),
        periodGrantKind: "chain-keys",
        chainKeyProfile: referenceChainKeyProfile,
        transportMode: "client-bound",
        clientBoundProfile: clientBoundEcdh,
      }),
  );
});

test("ECDH and RSA chain-only delivery opens the cutoff item and excludes later items", async () => {
  const profiles = [
    ["ECDH-P256", clientBoundEcdh],
    ["RSA-OAEP", clientBoundRsa],
  ];
  for (const [method, profile] of profiles) {
    const source = await world({ chainItemSlots: 2 });
    const clock = new Clock(AT);
    const network = new Network({ clock });
    new IssuerServer({
      clock,
      network,
      random: new Random({ seed: 1 }),
      issuerName: ISSUER_NAME,
      unlockUrl: "https://api.example.com/unlock",
      keyStore: source.keyStore,
      publisherRegistrations: new PublisherRegistrations([source.publisherRegistration]),
      accessPolicy: {
        decide(_claims, requested) {
          return {
            contentNames: [],
            periodGrants: requested.accessGroups.map((accessGroup) => ({
              accessGroup,
              futurePeriodCount: 1,
              authorizePeriod: () => true,
            })),
          };
        },
      },
      periodGrantKind: "chain-keys",
      chainKeyProfile: referenceChainKeyProfile,
      transportMode: "client-bound",
      clientBoundProfile: profile,
    });
    const capability = clientBoundKeyCapability(await clientKeysFor(profile), profile);
    const chainCache = new ChainKeyCache();
    const client = new Client({
      publisherOrigin: PUB,
      chainCache,
      chainKeyProfile: referenceChainKeyProfile,
      requestBuilderFactory: chainKeyRequestBuilderFactory,
      clientBoundKeyCapability: capability,
    });
    const rendered = await source.render("123456", ARTICLE_A);
    const page = client.parse(rendered);
    const request = client.buildRequest(page, ISSUER_NAME, ["bodytext"]);

    assert.deepEqual(request.sealed.contentKeys ?? [], [], method);
    assert.deepEqual(request.sealed.periodKeys ?? [], [], method);
    const answer = await network.post("https://api.example.com/unlock", request, { origin: PUB });
    answer.body = JSON.parse(JSON.stringify(answer.body));
    assert.equal(answer.status, 200, method);
    assert.equal(answer.body.transport.method, method);
    const chainKeyCount = premiumChains(answer.body).length;
    assert.deepEqual(
      premiumChains(answer.body).map((record) => record.cutoff),
      ["251023T1430"],
      method,
    );
    assert.deepEqual(answer.body.keys.contentKeys ?? [], [], method);
    assert.deepEqual(answer.body.keys.periodKeys ?? [], [], method);
    assert.equal(Object.hasOwn(answer.body, "periodGeometry"), false, method);
    const firstChain = recordNamed(premiumChains(answer.body), "cutoff", "251023T1430")?.key;
    assert.ok(
      firstChain,
      `${method} returns the latest independently authorized article/future cutoff`,
    );
    assert.deepEqual(
      Object.keys(firstChain).sort(),
      method === "ECDH-P256" ? ["key", "nonce"] : ["key"],
      method,
    );
    assert.equal(base64urlDecode(firstChain.key).length, method === "ECDH-P256" ? 32 : 256, method);
    if (method === "ECDH-P256") assert.equal(base64urlDecode(firstChain.nonce).length, 12, method);
    const chainKey = await (
      await capability.openDeliveredKeys(answer.body.transport)
    ).open(firstChain, [], "chainKey");
    assert.equal(chainKey?.length, 16, method);

    const applied = await client.applyResponse(page, ISSUER_NAME, answer.body, request);
    assert.deepEqual(applied.issues, [], method);
    assert.equal(applied.accepted, chainKeyCount, method);
    const context = { publisher: PUB, issuerName: ISSUER_NAME, ...GEOMETRY };
    assert.deepEqual(
      await chainCache.candidates("premium", "251023T1430", context),
      [expectedPeriodKey(10)],
      method,
    );
    assert.equal(
      new TextDecoder().decode(
        await client.decrypt(page, "bodytext", rendered.sealedContent.bodytext),
      ),
      ARTICLE_A,
      method,
    );

    const later = await source.render("later", ARTICLE_A, "2025-10-23T14:45:00Z");
    const laterPage = client.parse(later);
    assert.deepEqual(await chainCache.candidates("premium", "251023T1445", context), [], method);
    assert.equal(await client.contentKeyFor(laterPage, "bodytext"), null, method);
    await assert.rejects(client.decrypt(laterPage, "bodytext", later.sealedContent.bodytext), {
      code: "no_key",
    });

    const wrongRecipient = clientBoundKeyCapability(await clientKeysFor(profile), profile);
    const wrongOpener = await wrongRecipient.openDeliveredKeys(answer.body.transport);
    await assert.rejects(wrongOpener.open(firstChain, [], "chainKey"), { code: "unwrap_failed" });

    const tampered = JSON.parse(JSON.stringify(answer.body));
    for (const { key: wrapped } of premiumChains(tampered)) {
      const bytes = base64urlDecode(wrapped.key);
      bytes[0] ^= 1;
      wrapped.key = base64urlEncode(bytes);
    }
    const rejectedCache = new ChainKeyCache();
    const rejectedClient = new Client({
      publisherOrigin: PUB,
      chainCache: rejectedCache,
      chainKeyProfile: referenceChainKeyProfile,
      requestBuilderFactory: chainKeyRequestBuilderFactory,
      clientBoundKeyCapability: capability,
    });
    const rejectedPage = rejectedClient.parse(rendered);
    const rejectedRequest = rejectedClient.buildRequest(rejectedPage, ISSUER_NAME, ["bodytext"]);
    const rejected = await rejectedClient.applyResponse(
      rejectedPage,
      ISSUER_NAME,
      tampered,
      rejectedRequest,
    );
    assert.equal(rejected.accepted, 0, method);
    assert.equal(rejected.issues.length, chainKeyCount, method);
    assert.ok(
      rejected.issues.every((issue) => issue.code === "malformed_key"),
      method,
    );
    assert.deepEqual(rejectedCache.entries(), [], method);
    assert.equal(await rejectedClient.contentKeyFor(rejectedPage, "bodytext"), null, method);
  }
});

// The response carries one chain key at the 14:30 cutoff and no content key
// or period key. The earlier item is wrapped only at 12:00 and 12:15 and
// never reaches the issuer, so the client opens it only by stepping the
// delivered chain key back from position 10 and deriving the period key there.
// A client that derives the period key straight from the delivered chain key
// still opens the cutoff item, but not this one. Both renders come from one family
// generation, so the earlier wraps sit in the delivered chain's reach
// (docs/spec-profile--chain-keys.md section 5.2).
test("ECDH and RSA client-bound chain key opens an earlier item by derivation alone", async () => {
  const profiles = [
    ["ECDH-P256", clientBoundEcdh],
    ["RSA-OAEP", clientBoundRsa],
  ];
  for (const [method, profile] of profiles) {
    const source = await world({ chainItemSlots: 2 });
    const clock = new Clock(AT);
    const network = new Network({ clock });
    new IssuerServer({
      clock,
      network,
      random: new Random({ seed: 1 }),
      issuerName: ISSUER_NAME,
      unlockUrl: "https://api.example.com/unlock",
      keyStore: source.keyStore,
      publisherRegistrations: new PublisherRegistrations([source.publisherRegistration]),
      accessPolicy: {
        decide(_claims, requested) {
          return {
            contentNames: [],
            periodGrants: requested.accessGroups.map((accessGroup) => ({
              accessGroup,
              futurePeriodCount: 1,
              authorizePeriod: () => true,
            })),
          };
        },
      },
      periodGrantKind: "chain-keys",
      chainKeyProfile: referenceChainKeyProfile,
      transportMode: "client-bound",
      clientBoundProfile: profile,
    });
    const chainCache = new ChainKeyCache();
    const client = new Client({
      publisherOrigin: PUB,
      chainCache,
      chainKeyProfile: referenceChainKeyProfile,
      requestBuilderFactory: chainKeyRequestBuilderFactory,
      clientBoundKeyCapability: clientBoundKeyCapability(await clientKeysFor(profile), profile),
    });
    const current = await source.render("123456", ARTICLE_A);
    const earlier = await source.render("earlier", ARTICLE_B, "2025-10-23T12:05:00Z");
    assert.deepEqual(
      wrapsOf(earlier, "bodytext", "premium").map((entry) => entry.period),
      ["251023T1200", "251023T1215"],
      method,
    );

    const page = client.parse(current);
    const request = client.buildRequest(page, ISSUER_NAME, ["bodytext"]);
    const answer = await network.post("https://api.example.com/unlock", request, { origin: PUB });
    answer.body = JSON.parse(JSON.stringify(answer.body));
    assert.equal(answer.status, 200, method);
    assert.equal(answer.body.transport.method, method);
    assert.deepEqual(answer.body.keys.contentKeys ?? [], [], method);
    assert.deepEqual(answer.body.keys.periodKeys ?? [], [], method);
    assert.deepEqual(
      premiumChains(answer.body).map((record) => record.cutoff),
      ["251023T1430"],
      method,
    );
    const applied = await client.applyResponse(page, ISSUER_NAME, answer.body, request);
    assert.deepEqual(applied.issues, [], method);

    const earlierPage = client.parse(earlier);
    assert.equal(
      new TextDecoder().decode(
        await client.decrypt(earlierPage, "bodytext", earlier.sealedContent.bodytext),
      ),
      ARTICLE_B,
      method,
    );
    assert.equal(network.stats()["https://api.example.com/unlock"].attempts, 1, method);
    const context = { publisher: PUB, issuerName: ISSUER_NAME, ...GEOMETRY };
    assert.deepEqual(
      await chainCache.candidates("premium", "251023T1200", context),
      [expectedPeriodKey(0)],
      method,
    );
  }
});
