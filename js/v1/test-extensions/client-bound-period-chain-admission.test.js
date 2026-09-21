// @ts-check
//
// Composition coverage for dynamic client-bound transport selection with a
// period-chain grant. This unsupported combination must be rejected before
// transport preflight, response-cache lookup or issuer private-key lookup.

import test from "node:test";
import assert from "node:assert/strict";

import { periodFamilyGeneration } from "../extensions/period-chain/core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../extensions/period-chain/core-publisher/periodFamilySupply.js";
import { referencePeriodChainProfile } from "../extensions/period-chain/referenceProfile.js";
import * as clientBoundEcdh from "../extensions/client-bound-transport/ecdhP256.js";
import { KeyDelivery } from "../adapter-issuer/KeyDelivery.js";
import { Sealer } from "../core-publisher/Sealer.js";
import { Client } from "../test-lib/harnesses/client.js";
import { Random } from "../demo/actors/Random.js";
import { Clock } from "../demo/actors/Clock.js";
import { Network } from "../demo/actors/Network.js";
import { IssuerServer } from "../demo/actors/IssuerServer.js";
import { IssuerResponseCache } from "../demo/actors/issuer/IssuerResponseCache.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import { openingKeysOver, PublisherRegistrations } from "../demo/support/PublisherRegistrations.js";

const { subtle } = globalThis.crypto;

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const DOMAIN = "www.news-site.example";
const AT = "2025-10-23T14:20:00Z";

const PUB = `https://${DOMAIN}`;
const PERIOD_SECRET = new Uint8Array(32).fill(7);
const ARTICLE_A = "<p>The council voted 7-2 to rezone the harbour.</p>";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

/**
 * @returns {Promise<{ keyStore: object, publisherRegistration: object, render: (resourceId: string, value: string) => Promise<any> }>}
 */
async function world({
  periodKeySupply = periodFamilySupply({
    families: {
      premium: periodFamilyGeneration({ keyDerivationSecret: PERIOD_SECRET, geometry: GEOMETRY }),
    },
    chainWindows: 2,
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
      issuerSupplyPlanFor: () => ({ periodKeyDelivery: { premium: ["chain"] } }),
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: "ECDH-P256",
          publicKey: issuerKeys.publicKey,
          unlockUrl: "https://api.example.com/unlock",
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
      return { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey };
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

test("IssuerServer refuses a fixed client-bound chain composition at construction", async () => {
  const source = await world();
  const clock = new Clock(AT);
  const network = new Network({ clock });

  assert.throws(
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
        periodGrantKind: "chain",
        periodChainProfile: referencePeriodChainProfile,
        transportMode: "client-bound",
        clientBoundProfile: clientBoundEcdh,
      }),
    (/** @type {any} */ error) =>
      error.code === "bad_config" && /chain grants need direct transport/.test(error.message),
  );
});

test("IssuerServer rejects a dynamic client-bound chain selection before private or cache work", async () => {
  const source = await world();
  let keyLookups = 0;
  let preflights = 0;
  let cacheReads = 0;
  const originalPreflight = KeyDelivery.prototype.preflight;
  const originalCacheGet = IssuerResponseCache.prototype.get;
  KeyDelivery.prototype.preflight = async function (...args) {
    preflights++;
    return originalPreflight.apply(this, /** @type {any} */ (args));
  };
  IssuerResponseCache.prototype.get = function (...args) {
    cacheReads++;
    return originalCacheGet.apply(this, /** @type {any} */ (args));
  };
  const keyStore = {
    get(...args) {
      keyLookups++;
      return source.keyStore.get(...args);
    },
  };
  try {
    const clock = new Clock(AT);
    const network = new Network({ clock });
    new IssuerServer({
      clock,
      network,
      random: new Random({ seed: 1 }),
      issuerName: ISSUER_NAME,
      unlockUrl: "https://api.example.com/unlock",
      keyStore,
      publisherRegistrations: new PublisherRegistrations([source.publisherRegistration]),
      accessPolicy: new AllowAllPolicy(),
      periodGrantKind: "chain",
      periodChainProfile: referencePeriodChainProfile,
      transportPolicy: {
        modeFor() {
          return "client-bound";
        },
      },
      clientBoundProfile: clientBoundEcdh,
    });
    const client = new Client({ publisherOrigin: PUB });
    const page = client.parse(await source.render("123456", ARTICLE_A));

    const answer = await network.post(
      "https://api.example.com/unlock",
      client.buildRequest(page, ISSUER_NAME, ["bodytext"]),
      { origin: PUB },
    );

    assert.deepEqual(answer, {
      status: 500,
      body: { error: "internal_error", issuerName: ISSUER_NAME },
    });
    assert.equal(
      preflights,
      0,
      "the unsupported composition is rejected before transport preflight",
    );
    assert.equal(cacheReads, 0, "and before response-cache lookup");
    assert.equal(keyLookups, 0, "and before key lookup or unseal");
  } finally {
    KeyDelivery.prototype.preflight = originalPreflight;
    IssuerResponseCache.prototype.get = originalCacheGet;
  }
});
