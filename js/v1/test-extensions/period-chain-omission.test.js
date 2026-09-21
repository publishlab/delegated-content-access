// @ts-check
//
// One issuer selecting both optional extensions at once.
//
// This is the composition the two were designed for and neither can reach
// alone. The publisher omits this issuer's direct `sealed.contentKeys` and
// seals it period chains instead; the client forwards its bound candidates; the
// issuer answers the granted period family as chain cutoffs, and answers the
// omitted content key by unwrapping a candidate under an exact leaf its own
// chain capability derived. The ordinary engine carries no extension protocol
// and each extension carries its own engine, so the deployment that selects
// both is written out in `support/PeriodChainOmissionIssuerEngine.js` beside
// this file: it verifies once, decides once, and opens under one key authority.
//
// Neither extension imports the other. The chain half reaches the omission half
// only as an injected `exactPeriodLeaves`, wired here, which is why this test
// lives in neutral territory rather than inside either extension.

import test from "node:test";
import assert from "node:assert/strict";

import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { DcaData } from "../core-client/DcaData.js";
import { openContent } from "../core-client/openContent.js";
import { base64urlDecode, utf8Decode } from "../core-shared/codec.js";
import { openingKeysOver, PublisherRegistrations } from "../demo/support/PublisherRegistrations.js";
import { periodFamilyGeneration } from "../extensions/period-chain/core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../extensions/period-chain/core-publisher/periodFamilySupply.js";
import { referencePeriodChainProfile } from "../extensions/period-chain/referenceProfile.js";
import { OmittingSealer } from "../extensions/content-key-seal-omission/core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../extensions/content-key-seal-omission/core-client/OmissionRequestBuilder.js";
import { PeriodChainRequestBuilder } from "../extensions/period-chain/core-client/PeriodChainRequestBuilder.js";
import { omissionIssuerEngine } from "../extensions/content-key-seal-omission/core-issuer/omissionIssuerEngine.js";
import { PeriodChainOmissionIssuerEngine } from "./support/PeriodChainOmissionIssuerEngine.js";
import { EXTENSION_NAME } from "../extensions/content-key-seal-omission/core-shared/omissionBind.js";

const { subtle } = globalThis.crypto;

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const PUB = "https://www.news-site.example";
const AT = "2025-10-23T14:20:00Z";
const GROUP = "premium";
const NAME = "bodytext";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

/** The extension root secret behind the issuer's own chain capability. */
const PERIOD_SECRET = new Uint8Array(32).fill(7);

/**
 * A publisher that omits this issuer's direct map and supplies period chains,
 * and the issuer that holds the same chain capability.
 */
async function world() {
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const generation = periodFamilyGeneration({
    keyDerivationSecret: PERIOD_SECRET,
    geometry: GEOMETRY,
  });
  const periodKeySupply = periodFamilySupply({
    families: { [GROUP]: generation },
    chainWindows: 2,
  });

  const sealer = new OmittingSealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 1 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply,
    issuerSupplyPlanFor: () => ({ periodKeyDelivery: { [GROUP]: ["chain"] } }),
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ECDH-P256",
        publicKey: issuerKeys.publicKey,
        unlockUrl: "https://api.example.com/unlock",
        extensions: [EXTENSION_NAME],
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(NAME, ARTICLE, "text/html", { accessGroups: [GROUP] });
  const sealed = await sealer.seal();
  const page = JSON.parse(
    JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
  );

  const keyStore = {
    /** @param {string} name @param {string} keyId */
    get: (name, keyId) =>
      name === ISSUER_NAME && keyId === KEY_ID
        ? { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey }
        : undefined,
  };
  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]),
    },
  ]).get(SIGNING_KID);

  return { generation, page, registration };
}

/**
 * The policy both sources read: base's `contentNames` and `periodGrants`, and
 * the omission extension's own `sourceGrants` beside them.
 */
const policy = {
  /** @param {any} claims @param {{ contentNames: string[], accessGroups: string[] }} requested */
  decide(claims, requested) {
    void claims;
    return {
      contentNames: requested.contentNames,
      periodGrants: requested.accessGroups.map((accessGroup) => ({ accessGroup, periodCount: 2 })),
      sourceGrants: requested.accessGroups.map((accessGroup) => ({ accessGroup, periodCount: 2 })),
    };
  },
};

/** @param {any} result */
function chainEntries(result) {
  assert.equal(result.capabilities.length, 1);
  const [capability] = result.capabilities;
  assert.equal(capability.kind, "period-chain");
  assert.equal(capability.accessGroup, GROUP);
  return capability.entries;
}

test("one issuer answers period chains and an omitted content key from its own chain leaf", async () => {
  const { generation, page, registration } = await world();

  const request = new PeriodChainRequestBuilder({
    innerBuilder: new OmissionRequestBuilder(),
  }).build(new DcaData(page, { publisherOrigin: PUB }), ISSUER_NAME, [NAME]);
  // The request's own sealed exact period material is dropped, so the only
  // source left for the bound candidate is the issuer's chain capability.
  // The request still presents the chain family this issuer grants from.
  const document = request.toObject();
  delete document.sealed.periodKeys;

  /** @type {[string, string][]} */
  const asked = [];
  // One issuer's capability, held for the publisher registration this request
  // authenticates against and selected by it.
  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const exactPeriodLeaves = new WeakMap();
  exactPeriodLeaves.set(registration, (accessGroup, t) => {
    asked.push([accessGroup, t]);
    return generation.periodKey(accessGroup, t);
  });

  const engine = new PeriodChainOmissionIssuerEngine({
    accessPolicy: policy,
    clock: new Clock(AT),
    exactPeriodLeaves,
  });

  const result = await engine.unlock(request, registration);

  // The chain half: the granted family comes back as chain cutoffs.
  assert.ok(Object.keys(chainEntries(result)).length > 0);

  // The omission half: the item the publisher sealed no direct key for.
  assert.deepEqual(Object.keys(result.contentKeys), [NAME]);
  assert.deepEqual(result.errors, {});

  // And the exact leaf the omission source opened its candidate under is no
  // part of the answer. A period leaf used as a source is not a grant.
  assert.deepEqual(result.periodKeys, {});
  assert.equal(asked.length > 0, true, "the omission half asked this registration's own leaf view");

  const record = page.contentData[NAME];
  const plaintext = await openContent(
    base64urlDecode(result.contentKeys[NAME]),
    NAME,
    record.nonce,
    page.sealedContent[NAME],
    record.aad,
  );
  assert.equal(utf8Decode(plaintext), ARTICLE);
});

test("either extension alone answers only its own half of that composition", async () => {
  const { generation, page, registration } = await world();
  const request = new PeriodChainRequestBuilder({
    innerBuilder: new OmissionRequestBuilder(),
  }).build(new DcaData(page, { publisherOrigin: PUB }), ISSUER_NAME, [NAME]);
  delete request.toObject().sealed.periodKeys;

  const chainOnly = referencePeriodChainProfile.issuerEngineFor({
    accessPolicy: policy,
    clock: new Clock(AT),
  });
  const chained = await chainOnly.unlock(request, registration);
  assert.ok(Object.keys(chainEntries(chained)).length > 0);
  assert.deepEqual(chained.contentKeys, {}, "the chain half opens no omitted content key");

  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const leaves = new WeakMap();
  leaves.set(registration, (accessGroup, t) => generation.periodKey(accessGroup, t));
  const omissionOnly = omissionIssuerEngine({ accessPolicy: policy, exactPeriodLeaves: leaves });
  const omitted = await omissionOnly.unlock(request, registration);
  assert.deepEqual(Object.keys(omitted.contentKeys), [NAME]);
  assert.deepEqual(omitted.capabilities, [], "the omission half returns no chain capability");
});
