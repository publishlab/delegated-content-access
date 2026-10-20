// @ts-check
//
// One issuer selecting both optional extensions at once.
//
// This is the composition the two were designed for and neither can reach
// alone. The publisher omits this issuer's `sealed.contentKeys` and
// seals it chain keys instead; the client forwards its bound candidates; the
// issuer answers the granted period family as chain cutoffs, and answers the
// omitted content key by unwrapping a candidate under a period key its own
// chain capability derived. The ordinary engine carries no extension protocol
// and each extension carries its own engine, so the deployment that selects
// both is written out in `support/ChainKeyOmissionIssuerEngine.js` beside
// this file: it verifies once, decides once, and opens under one key authority.
//
// Neither extension imports the other. The chain half reaches the omission half
// only as an injected `periodKeyLookup`, wired here, which is why this test
// lives in neutral territory rather than inside either extension.

import test from "node:test";
import assert from "node:assert/strict";

import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { DcaData } from "../core-client/DcaData.js";
import { createDeliveryClient } from "../integration-client/createDeliveryClient.js";
import { createIssuerCore } from "../integration-issuer/createIssuerCore.js";
import { chainKeyIssuerEngine } from "../extensions/chain-keys/core-issuer/chainKeyIssuerEngine.js";
import { omissionContentKeyResolverFactory } from "../extensions/content-key-seal-omission/core-client/BoundContentKeyResolver.js";
import { openContent } from "../core-client/openContent.js";
import { contentAadOctets } from "../test-reference/support/contentAadOctets.js";
import { base64urlDecode, utf8Decode } from "../core-shared/codec.js";
import { openingKeysOver, PublisherRegistrations } from "../demo/support/PublisherRegistrations.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import { OmittingSealer } from "../extensions/content-key-seal-omission/core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../extensions/content-key-seal-omission/core-client/OmissionRequestBuilder.js";
import { ChainKeyRequestBuilder } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { omissionIssuerEngine } from "../extensions/content-key-seal-omission/core-issuer/omissionIssuerEngine.js";
import { ChainKeyOmissionIssuerEngine } from "./support/ChainKeyOmissionIssuerEngine.js";
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
 * A publisher that omits this issuer's `contentKeys` map and supplies chain keys,
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
    issuerSupplyPlanFor: () => ({
      suppliedAccessGroups: [GROUP],
      periodKeyDelivery: { [GROUP]: ["chain-keys"] },
    }),
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,

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
        ? { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey }
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
/** @param {string[]} sourceLabels */
function policyFor(sourceLabels) {
  return {
    /** @param {any} claims @param {{ contentNames: string[], accessGroups: string[] }} requested */
    decide(claims, requested) {
      void claims;
      return {
        contentNames: requested.contentNames,
        periodGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          futurePeriodCount: 2,
          authorizePeriod: () => true,
        })),
        sourceGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          periods: sourceLabels,
        })),
      };
    },
  };
}

/** @param {any} result */
function chainEntries(result) {
  assert.equal(result.capabilities.length, 1);
  const [capability] = result.capabilities;
  assert.equal(capability.kind, "chain-keys");
  assert.equal(capability.accessGroup, GROUP);
  return capability.entries;
}

test("one issuer answers chain keys and an omitted content key from its own chain-derived period key", async () => {
  const { generation, page, registration } = await world();
  const dcaPage = new DcaData(page, { publisherOrigin: PUB });
  const accessPolicy = policyFor(dcaPage.sealedEntriesFor(NAME, GROUP).map((entry) => entry.t));

  const request = new ChainKeyRequestBuilder({
    innerBuilder: new OmissionRequestBuilder(),
  }).build(dcaPage, ISSUER_NAME, [NAME]);
  // The request's own sealed period keys are dropped, so the only
  // source left for the bound candidate is the issuer's chain capability.
  // The request still presents the chain family this issuer grants from.
  const document = request.toObject();
  delete document.sealed.periodKeys;

  /** @type {[string, string][]} */
  const asked = [];
  // One issuer's capability, held for the publisher registration this request
  // authenticates against and selected by it.
  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const periodKeyLookup = new WeakMap();
  periodKeyLookup.set(registration, (accessGroup, t) => {
    asked.push([accessGroup, t]);
    return generation.periodKey(accessGroup, t);
  });

  const engine = new ChainKeyOmissionIssuerEngine({
    operatingIssuerNames: [ISSUER_NAME],
    accessPolicy,
    clock: new Clock(AT),
    periodKeyLookup,
  });

  const result = await engine.unlock(request, registration);

  // The chain half: the granted family comes back as chain cutoffs.
  assert.ok(Object.keys(chainEntries(result)).length > 0);

  // The omission half: the item the publisher sealed no content key for.
  assert.deepEqual(Object.keys(result.contentKeys), [NAME]);
  assert.deepEqual(result.errors, {});

  // And the period key the omission source opened its candidate under is no
  // part of the answer. A period key used as a source is not a grant.
  assert.deepEqual(result.periodKeys, {});
  assert.equal(
    asked.length > 0,
    true,
    "the omission half asked this registration's own period-key lookup",
  );

  const plaintext = await openContent(
    base64urlDecode(result.contentKeys[NAME]),
    NAME,
    page.sealedContent[NAME],
    contentAadOctets(page, NAME),
  );
  assert.equal(utf8Decode(plaintext), ARTICLE);
});

test("either extension alone answers only its own half of that composition", async () => {
  const { generation, page, registration } = await world();
  const dcaPage = new DcaData(page, { publisherOrigin: PUB });
  const accessPolicy = policyFor(dcaPage.sealedEntriesFor(NAME, GROUP).map((entry) => entry.t));
  const request = new ChainKeyRequestBuilder({
    innerBuilder: new OmissionRequestBuilder(),
  }).build(dcaPage, ISSUER_NAME, [NAME]);
  delete request.toObject().sealed.periodKeys;

  const chainOnly = referenceChainKeyProfile.issuerEngineFor({
    operatingIssuerNames: [ISSUER_NAME],
    accessPolicy,
    clock: new Clock(AT),
  });
  const chained = await chainOnly.unlock(request, registration);
  assert.ok(Object.keys(chainEntries(chained)).length > 0);
  assert.deepEqual(chained.contentKeys, {}, "the chain half opens no omitted content key");

  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const periodKeyLookup = new WeakMap();
  periodKeyLookup.set(registration, (accessGroup, t) => generation.periodKey(accessGroup, t));
  const basePolicy = {
    decide(claims, requested) {
      return {
        ...accessPolicy.decide(claims, requested),
        periodGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          periods: requested.periodCoordinates[accessGroup] ?? [],
        })),
      };
    },
  };
  const omissionOnly = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_NAME],
    accessPolicy: basePolicy,
    periodKeyLookup,
  });
  const omitted = await omissionOnly.unlock(request, registration);
  assert.deepEqual(Object.keys(omitted.contentKeys), [NAME]);
  assert.deepEqual(omitted.capabilities, [], "the omission half returns no chain capability");
});

test("an omission issuer narrowed to one group drops the other groups' chain delivery", async () => {
  // The stock chain-keys planner shape selects chain delivery for every render
  // group. An issuer deployed for premium alone, active or inactive, seals the
  // premium chain and nothing for free; an unrestricted issuer beside it gives
  // the free item its route.
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const family = (/** @type {number} */ fill) =>
    periodFamilyGeneration({
      keyDerivationSecret: new Uint8Array(32).fill(fill),
      geometry: GEOMETRY,
    });
  for (const extensions of [[EXTENSION_NAME], []]) {
    const sealer = new OmittingSealer({
      origin: PUB,
      clock: new Clock(AT),
      random: new Random({ seed: 1 }),
      signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
      periodKeySupply: periodFamilySupply({
        families: { [GROUP]: family(7), free: family(8) },
        chainWindows: 1,
      }),
      issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ planned) => ({
        contentKeyNames: [],
        suppliedAccessGroups: planned.accessGroups,
        periodKeyDelivery: Object.fromEntries(
          planned.accessGroups.map((/** @type {string} */ group) => [group, ["chain-keys"]]),
        ),
      }),
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: "ecdh-p256",
          publicKey: issuerKeys.publicKey,
          extensions,
          grantable: [NAME],
          accessGroups: [GROUP],
        },
        {
          issuerName: "free_desk",
          keyId: KEY_ID,
          algorithm: "ecdh-p256",
          publicKey: issuerKeys.publicKey,
        },
      ],
    });
    sealer.resource("123456", { section: "politics" });
    sealer.content(NAME, ARTICLE, "text/html", { accessGroups: [GROUP] });
    sealer.content("teaser", "<p>teaser</p>", "text/html", { accessGroups: ["free"] });
    const { dcaData } = await sealer.seal();
    const label = extensions.length ? "active" : "inactive";
    const sealed = dcaData.issuerData[ISSUER_NAME].sealed;
    assert.deepEqual(Object.keys(sealed.chainKeys), [GROUP], label);
    assert.equal(Object.hasOwn(sealed, "periodKeys"), false, label);
    assert.deepEqual(
      Object.keys(dcaData.issuerData.free_desk.sealed.chainKeys),
      [GROUP, "free"],
      label,
    );
  }
});

test("omission outside a chain relay preserves projected period-key admission", async () => {
  const { page, registration } = await world();
  const { sealedContent, ...delivery } = page;
  const issuer = createIssuerCore({
    engine: chainKeyIssuerEngine({
      operatingIssuerNames: [ISSUER_NAME],
      accessPolicy: policyFor([]),
      clock: new Clock(AT),
      representation: "period-keys",
    }),
    periodKeyInput: true,
  });
  // A base inner builder adds no coordinate admission; omission must not invent one.
  assert.equal(typeof new OmissionRequestBuilder().acceptsPeriodKeyResponseCoordinate, "undefined");
  const exchanges = [];
  const client = createDeliveryClient({
    reader: {
      dcaData: delivery,
      publisherOrigin: PUB,
      extract: (name) => sealedContent[name] ?? null,
    },
    issuerName: ISSUER_NAME,
    unlockUrl: "https://issuer.example/unlock",
    requestBuilderFactory: (options) =>
      new OmissionRequestBuilder({
        innerBuilder: new ChainKeyRequestBuilder(options),
      }),
    resolverFactory: omissionContentKeyResolverFactory,
    transport: {
      async post(_url, request) {
        const result = await issuer.endpoint.handleDocument(JSON.stringify(request), registration);
        assert.equal(result.response.status, 200);
        assert.ok(Object.keys(result.response.body.keys.periodKeys[GROUP]).length);
        exchanges.push(request);
        return { ...result.response, contentType: "application/json" };
      },
    },
  });
  assert.equal(utf8Decode((await client.open(NAME)).bytes), ARTICLE);
  assert.equal(exchanges.length, 1);
  assert.equal(
    exchanges[0].sealed.periodKeys,
    undefined,
    "the issuer had to project from chain-only supply",
  );
  assert.ok(Object.keys(exchanges[0].sealed.chainKeys[GROUP]).length);
  assert.ok(exchanges[0].boundCandidates[NAME].length);
  assert.equal(utf8Decode((await client.openLocal(NAME)).bytes), ARTICLE);
});
