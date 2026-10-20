// @ts-check
//
// The two carrier corrections this file drives, and the precedence it pins.
// A chain-selecting issuer refuses a malformed request collection or an
// invalid access-group name for the whole request, the way base refuses a
// malformed coordinate, while every narrower chain scope stays per family. A
// chain client admits a returned family only under the pair the request it sent
// resolved for that family. An unsupported chain section beside `transport` is
// classified before the remaining sections are judged.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { parseDcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { chainKeyIssuerEngine } from "../core-issuer/chainKeyIssuerEngine.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;
const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const GROUP = "premium";
const OTHER = "archive";
const NAME = "bodytext";
const AT = "2025-10-23T14:20:00Z";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const TERMINAL_T = "251023T2345";
const KEY = base64urlEncode(new Uint8Array(16).fill(3));

/** @param {number} futurePeriodCount @param {boolean} content */
function policy(futurePeriodCount, content = true, authorizePeriod = () => true) {
  return {
    decide(/** @type {any} */ _claims, /** @type {any} */ requested) {
      return {
        contentNames: content ? requested.contentNames : [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
          accessGroup,
          futurePeriodCount,
          authorizePeriod,
        })),
      };
    },
  };
}

/** One sealed chain page, its registration, and a relay client for it. */
async function world() {
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: GEOMETRY,
  });
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: periodFamilySupply({ families: { [GROUP]: generation }, chainWindows: 2 }),
    issuerSupplyPlanFor: (issuer, render) => ({
      ...wholeRenderIssuerSupplyPlan(issuer, render),
      periodKeyDelivery: { [GROUP]: ["chain-keys"] },
    }),
    issuers: [
      {
        issuerName: ISSUER,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(NAME, ARTICLE, "text/html", { accessGroups: [GROUP] });
  const rendered = await sealer.seal();
  const page = JSON.parse(
    JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
  );
  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(
        {
          get: (/** @type {string} */ issuerName, /** @type {string} */ keyId) =>
            issuerName === ISSUER && keyId === KEY_ID
              ? { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey }
              : undefined,
        },
        [{ issuerName: ISSUER, keyId: KEY_ID }],
      ),
    },
  ]).get(SIGNING_KID);
  const client = new Client({
    publisherOrigin: PUB,
    cache: new PeriodKeyCache(),
    requestBuilderFactory: (/** @type {any} */ options) => new ChainKeyRequestBuilder(options),
  });
  return { client, generation, page, registration };
}

/** The relayed request document, ready for one edit before it is parsed. */
function documentFor(client, page) {
  return client.buildRequest(client.parse(page), ISSUER, [NAME]);
}

/** @param {object} document */
function requestOf(document) {
  return parseDcaRequest(JSON.stringify(document));
}

/** A registration that counts every opening-key lookup made through it. */
function counting(registration) {
  const lookups = { count: 0 };
  return {
    counted: {
      ...registration,
      openingKeys: {
        get(/** @type {any[]} */ ...args) {
          lookups.count++;
          return registration.openingKeys.get(...args);
        },
      },
    },
    lookups,
  };
}

describe("request admission when the issuer selected the chain-key extension", () => {
  for (const malformed of [null, [], "bad"]) {
    test(`a malformed chain collection ${JSON.stringify(malformed)} refuses the whole request`, async () => {
      const { client, page, registration } = await world();
      const document = documentFor(client, page);
      document.sealed.chainKeys = malformed;
      const { counted, lookups } = counting(registration);
      const engine = chainKeyIssuerEngine({
        operatingIssuerNames: [ISSUER],
        accessPolicy: policy(2),
        clock: new Clock(AT),
      });

      await assert.rejects(
        engine.unlock(requestOf(document), counted),
        (/** @type {any} */ error) => error.code === "binding_failed",
      );
      assert.equal(lookups.count, 0, "the refusal precedes opening-key lookup");
    });
  }

  test("an invalid access-group member name refuses the whole request", async () => {
    const { client, page, registration } = await world();
    const document = documentFor(client, page);
    document.sealed.chainKeys = {
      "2bad": document.sealed.chainKeys[GROUP],
      [GROUP]: document.sealed.chainKeys[GROUP],
    };
    const { counted, lookups } = counting(registration);
    const engine = chainKeyIssuerEngine({
      operatingIssuerNames: [ISSUER],
      accessPolicy: policy(2),
      clock: new Clock(AT),
    });

    await assert.rejects(
      engine.unlock(requestOf(document), counted),
      (/** @type {any} */ error) => error.code === "binding_failed",
    );
    assert.equal(lookups.count, 0, "a sibling family cannot carry the request past the name rule");
  });

  test("an invalid full periodGeometry accessGroups map refuses before policy and opening lookup", async () => {
    const { client, page, registration } = await world();
    const document = documentFor(client, page);
    document.periodGeometry.accessGroups = JSON.parse(
      '{"premium":{"chainsPerDay":2,"periodMinutes":15},"2invalid":{"chainsPerDay":1,"periodMinutes":30}}',
    );
    const { counted, lookups } = counting(registration);
    let policyCalls = 0;
    const accessPolicy = {
      decide: (...args) => {
        policyCalls++;
        return policy(2).decide(...args);
      },
    };
    const engine = chainKeyIssuerEngine({
      operatingIssuerNames: [ISSUER],
      accessPolicy,
      clock: new Clock(AT),
    });

    await assert.rejects(
      engine.unlock(requestOf(document), counted),
      (/** @type {any} */ error) => error.code === "binding_failed",
    );
    assert.equal(policyCalls, 0);
    assert.equal(lookups.count, 0);
  });

  test("the refusal reaches the wire as a malformed base coordinate does", async () => {
    const { client, page, registration } = await world();
    const document = documentFor(client, page);
    document.sealed.chainKeys = "bad";
    const engine = chainKeyIssuerEngine({
      operatingIssuerNames: [ISSUER],
      accessPolicy: policy(2),
      clock: new Clock(AT),
    });
    const endpoint = new UnlockEndpoint(new IssuerProcessor(engine));

    const answer = await endpoint.handleRequest({ request: requestOf(document), registration });

    assert.deepEqual(answer, {
      response: { status: 400, body: { error: "binding_failed" } },
      policyData: undefined,
      code: "binding_failed",
    });
  });

  test("a base issuer ignores both malformed chain members", async () => {
    const { client, page, registration } = await world();
    for (const malformed of [null, [], "bad"]) {
      const document = documentFor(client, page);
      document.sealed.chainKeys = malformed;
      const result = await new IssuerEngine({
        operatingIssuerNames: [ISSUER],
        accessPolicy: policy(2),
      }).unlock(requestOf(document), registration);
      assert.deepEqual(Object.keys(result.contentKeys), [NAME]);
      assert.deepEqual(result.errors, {});
    }

    const named = documentFor(client, page);
    named.sealed.chainKeys = { "2bad": named.sealed.chainKeys[GROUP] };
    const result = await new IssuerEngine({
      operatingIssuerNames: [ISSUER],
      accessPolicy: policy(2),
    }).unlock(requestOf(named), registration);
    assert.deepEqual(Object.keys(result.contentKeys), [NAME]);
    assert.deepEqual(result.errors, {});
  });
});

describe("local chain failures keep their narrower scope under a selecting issuer", () => {
  test("a noncanonical sealed member and valid same-window sibling void the family", async () => {
    const { client, page, registration } = await world();
    const document = documentFor(client, page);
    for (const t of Object.keys(document.sealed.chainKeys[GROUP])) {
      if (t !== TERMINAL_T) delete document.sealed.chainKeys[GROUP][t];
    }
    document.sealed.chainKeys[GROUP]["251023T2330"] = "AQ==";
    const engine = chainKeyIssuerEngine({
      operatingIssuerNames: [ISSUER],
      accessPolicy: policy(2),
      clock: new Clock(AT),
    });

    const result = await engine.unlock(requestOf(document), registration);

    assert.deepEqual(Object.keys(result.periodKeys), []);
    assert.deepEqual(result.errors, {});
  });

  const LOCAL = [
    {
      name: "a non-object family",
      spoil: (/** @type {any} */ document) => {
        document.sealed.chainKeys[OTHER] = "nope";
      },
    },
    {
      name: "an off-grid label",
      spoil: (/** @type {any} */ document) => {
        document.sealed.chainKeys[OTHER] = { "251023T1410": KEY };
      },
    },
    {
      name: "a non-string chain key",
      spoil: (/** @type {any} */ document) => {
        document.sealed.chainKeys[OTHER] = { [TERMINAL_T]: { key: KEY } };
      },
    },
  ];

  for (const { name, spoil } of LOCAL) {
    test(`${name} answers silently while its sibling family is answered`, async () => {
      const { client, generation, page, registration } = await world();
      const document = documentFor(client, page);
      spoil(document);
      const engine = chainKeyIssuerEngine({
        operatingIssuerNames: [ISSUER],
        accessPolicy: policy(2),
        clock: new Clock(AT),
      });

      const result = await engine.unlock(requestOf(document), registration);

      assert.deepEqual(Object.keys(result.contentKeys), [NAME]);
      assert.deepEqual(Object.keys(result.periodKeys), [GROUP]);
      assert.deepEqual(Object.keys(result.periodKeys[GROUP]), ["251023T1415", "251023T1430"]);
      for (const t of Object.keys(result.periodKeys[GROUP])) {
        assert.equal(
          result.periodKeys[GROUP][t],
          base64urlEncode(await generation.periodKey(GROUP, t)),
        );
      }
      assert.deepEqual(
        Object.keys(result.errors),
        name === "a non-string chain key" ? [`${OTHER}|${TERMINAL_T}`] : [],
      );
    });
  }
});

/** A page with no wrapped content: these cases judge what is filed, not what opens. */
function clientPage(renderId) {
  return new DcaData(
    {
      version: "1",
      resourceJWT: `e30.${base64urlEncode(utf8Encode(JSON.stringify({ renderId })))}.c2lnbmF0dXJl`,
      issuerData: {
        [ISSUER]: { keyId: KEY_ID, unlockUrl: "https://api.example/unlock", sealed: {} },
      },
      contentData: {},
    },
    { publisherOrigin: PUB },
  );
}

/** The request document the client sent, in the shape `PageLoad` holds it. */
function chainRequest(periodGeometry = GEOMETRY, families = { [GROUP]: { [TERMINAL_T]: KEY } }) {
  return { sealed: { contentKeys: {}, chainKeys: families }, periodGeometry };
}

/** A chain response carrying one cutoff per named family. */
function chainResponse(periodGeometry = GEOMETRY, families = { [GROUP]: { [TERMINAL_T]: KEY } }) {
  return { keys: { chainKeys: families }, periodGeometry };
}

/** A resolver over a chain cache that records what reaches it. */
function filingResolver() {
  /** @type {any[][]} */
  const filed = [];
  const resolver = new ContentKeyResolver({
    chainCache: {
      put(/** @type {any[]} */ ...args) {
        filed.push(args);
      },
      candidates: () => [],
    },
    chainKeyProfile: explicitChainKeyClientProfile,
  });
  return { filed, resolver };
}

/** Apply a focused fixture response under the exact request document it models. */
function applyAssociatedResponse(resolver, page, issuerName, response, request) {
  if (request === undefined) return resolver.applyResponse(page, issuerName, response);
  const document = {
    version: page.version,
    issuerName,
    resourceJWT: page.resourceJWT,
    keyId: page.keyIdFor(issuerName),
    ...request,
  };
  return resolver.applyResponse(
    page,
    issuerName,
    response,
    new ResponseAssociation(page, issuerName, document),
  );
}

test("chain errors require a valid presented source label under resolved request geometry", async () => {
  const valid = filingResolver().resolver;
  const validPage = clientPage("render-valid-chain-error");
  assert.deepEqual(
    await applyAssociatedResponse(
      valid,
      validPage,
      ISSUER,
      {
        keys: { contentKeys: {} },
        errors: { [`${GROUP}|${TERMINAL_T}`]: { error: "unseal_failed" } },
      },
      chainRequest(),
    ),
    {
      accepted: 0,
      errors: [{ coordinate: `${GROUP}|${TERMINAL_T}`, error: "unseal_failed" }],
      issues: [],
    },
  );

  const invalid = filingResolver().resolver;
  const invalidPage = clientPage("render-invalid-chain-error");
  const offGrid = "251023T1417";
  assert.deepEqual(
    await applyAssociatedResponse(
      invalid,
      invalidPage,
      ISSUER,
      {
        keys: { contentKeys: {} },
        errors: { [`${GROUP}|${offGrid}`]: { error: "unseal_failed" } },
      },
      chainRequest(GEOMETRY, { [GROUP]: { [offGrid]: KEY } }),
    ),
    {
      accepted: 0,
      errors: [],
      issues: [{ section: "errors", code: "malformed_error" }],
    },
  );
});

describe("a chain response is admitted under the pair its request resolved", () => {
  test("response geometry metadata cannot override the captured request pair", async () => {
    const { filed, resolver } = filingResolver();

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-pair-differs"),
      ISSUER,
      chainResponse({ chainsPerDay: 4, periodMinutes: 5 }),
      chainRequest(),
    );

    assert.deepEqual(applied, { accepted: 1, errors: [], issues: [] });
    assert.equal(filed.length, 1);
    assert.equal(filed[0][3].chainsPerDay, GEOMETRY.chainsPerDay);
    assert.equal(filed[0][3].periodMinutes, GEOMETRY.periodMinutes);
  });

  test("a family the request never presented files no cutoff", async () => {
    const { filed, resolver } = filingResolver();

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-family-unasked"),
      ISSUER,
      chainResponse(),
      chainRequest(GEOMETRY, { [OTHER]: { [TERMINAL_T]: KEY } }),
    );

    assert.deepEqual(applied, {
      accepted: 0,
      errors: [],
      issues: [{ section: "chainKeys", code: "malformed_key" }],
    });
    assert.deepEqual(filed, []);
  });

  test("a chain response with no request context files no cutoff", async () => {
    const { filed, resolver } = filingResolver();

    await assert.rejects(
      () =>
        applyAssociatedResponse(resolver, clientPage("render-no-request"), ISSUER, chainResponse()),
      (error) => error.code === "bad_config",
    );
    assert.deepEqual(filed, []);
  });

  test("semantic member order keeps one shared geometry pair", async () => {
    const { filed, resolver } = filingResolver();
    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-placement"),
      ISSUER,
      chainResponse({ periodMinutes: GEOMETRY.periodMinutes, chainsPerDay: GEOMETRY.chainsPerDay }),
      chainRequest(GEOMETRY),
    );
    assert.deepEqual(applied, { accepted: 1, errors: [], issues: [] });
    assert.deepEqual(
      filed.map(([accessGroup, cutoffT]) => [accessGroup, cutoffT]),
      [[GROUP, TERMINAL_T]],
    );
  });

  test("a cutoff at or below a presented source position in its window is admitted", async () => {
    const { filed, resolver } = filingResolver();

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-cutoff-reachable"),
      ISSUER,
      chainResponse(GEOMETRY, { [GROUP]: { "251023T1415": KEY } }),
      chainRequest(GEOMETRY, { [GROUP]: { "251023T1430": KEY } }),
    );

    assert.deepEqual(applied, { accepted: 1, errors: [], issues: [] });
    assert.deepEqual(
      filed.map(([accessGroup, cutoffT]) => [accessGroup, cutoffT]),
      [[GROUP, "251023T1415"]],
    );
  });

  for (const outside of [
    {
      name: "above its presented source position",
      requestT: "251023T1415",
      responseT: "251023T1430",
    },
    {
      name: "in a window the request did not present",
      requestT: "251023T1145",
      responseT: "251023T1215",
    },
  ]) {
    test(`a cutoff ${outside.name} files no chain key`, async () => {
      const { filed, resolver } = filingResolver();

      const applied = await applyAssociatedResponse(
        resolver,
        clientPage(`render-cutoff-${outside.responseT}`),
        ISSUER,
        chainResponse(GEOMETRY, { [GROUP]: { [outside.responseT]: KEY } }),
        chainRequest(GEOMETRY, { [GROUP]: { [outside.requestT]: KEY } }),
      );

      assert.deepEqual(applied, {
        accepted: 0,
        errors: [],
        issues: [{ section: "chainKeys", code: "malformed_key" }],
      });
      assert.deepEqual(filed, []);
    });
  }

  test("a projected period-key response files without response geometry", async () => {
    /** @type {any[][]} */
    const periodKeysFiled = [];
    const resolver = new ContentKeyResolver({
      cache: {
        put(/** @type {any[]} */ ...args) {
          periodKeysFiled.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
      chainCache: {
        put: () => assert.fail("a period key never enters the chain-key partition"),
        candidates: () => [],
      },
      chainKeyProfile: explicitChainKeyClientProfile,
    });

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-projected-period-keys"),
      ISSUER,
      { keys: { periodKeys: { [GROUP]: { "251023T1415": KEY, "251023T1430": KEY } } } },
      chainRequest(),
    );

    assert.deepEqual(applied, { accepted: 2, errors: [], issues: [] });
    assert.deepEqual(
      periodKeysFiled.map((args) => args[1]),
      ["251023T1415", "251023T1430"],
    );
  });

  test("projected period keys outside the presented chain reach are not filed", async () => {
    /** @type {any[][]} */
    const periodKeysFiled = [];
    const resolver = new ContentKeyResolver({
      cache: {
        put(/** @type {any[]} */ ...args) {
          periodKeysFiled.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
      chainCache: { put: () => {}, candidates: () => [] },
      chainKeyProfile: explicitChainKeyClientProfile,
    });

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-projected-period-keys-outside"),
      ISSUER,
      {
        keys: {
          periodKeys: {
            [GROUP]: {
              "251023T1430": KEY,
              "251023T1145": KEY,
            },
          },
        },
      },
      chainRequest(GEOMETRY, { [GROUP]: { "251023T1415": KEY } }),
    );

    assert.deepEqual(applied, {
      accepted: 0,
      errors: [],
      issues: [
        { section: "periodKeys", code: "unsolicited_coordinate" },
        { section: "periodKeys", code: "unsolicited_coordinate" },
      ],
    });
    assert.deepEqual(periodKeysFiled, []);
  });

  test("a period-key coordinate the request presents remains admissible outside chain reach", async () => {
    /** @type {any[][]} */
    const periodKeysFiled = [];
    const resolver = new ContentKeyResolver({
      cache: {
        put(/** @type {any[]} */ ...args) {
          periodKeysFiled.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
      chainCache: { put: () => {}, candidates: () => [] },
      chainKeyProfile: explicitChainKeyClientProfile,
    });
    const periodKeyT = "251023T1215";
    const request = chainRequest(GEOMETRY, { [GROUP]: { "251023T1145": KEY } });
    request.sealed.periodKeys = { [GROUP]: { [periodKeyT]: KEY } };

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-presented-period-key"),
      ISSUER,
      { keys: { periodKeys: { [GROUP]: { [periodKeyT]: KEY } } } },
      request,
    );

    assert.deepEqual(applied, { accepted: 1, errors: [], issues: [] });
    assert.deepEqual(
      periodKeysFiled.map((args) => args[1]),
      [periodKeyT],
    );
  });
});

describe("chain keys share the one response representation", () => {
  test("a chain key in direct representation beside client-bound siblings rejects the whole response", async () => {
    /** @type {any[][]} */
    const periodKeysFiled = [];
    /** @type {any[][]} */
    const chainKeysFiled = [];
    const handle = new Uint8Array(16).fill(11);
    const resolver = new ContentKeyResolver({
      cache: {
        put(/** @type {any[]} */ ...args) {
          periodKeysFiled.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
      chainCache: {
        put(/** @type {any[]} */ ...args) {
          chainKeysFiled.push(args);
        },
        candidates: () => [],
      },
      chainKeyProfile: explicitChainKeyClientProfile,
      // A chain client that also accepts direct delivery reaches the
      // transport gate itself, rather than the earlier gate a client
      // without a chain cache or without direct fallback stops at.
      clientBoundKeyCapability: {
        assertCanOpenChainKeys() {},
        openDeliveredKeys: async (/** @type {any} */ transport) =>
          transport?.method === "ECDH-P256"
            ? {
                open: async (_value, usages, keyKind) =>
                  keyKind === "chainKey"
                    ? handle
                    : globalThis.crypto.subtle.importKey("raw", handle, "AES-GCM", false, usages),
              }
            : null,
      },
      acceptDirectFallback: true,
      persistRawPeriodKeys: true,
    });

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-chain-beside-transport"),
      ISSUER,
      {
        transport: { method: "ECDH-P256" },
        keys: {
          chainKeys: { [GROUP]: { [TERMINAL_T]: KEY } },
          periodKeys: { [GROUP]: { "251023T1415": { key: KEY } } },
          contentKeys: { [NAME]: { key: KEY } },
        },
        periodGeometry: { ...GEOMETRY },
      },
      {
        ...chainRequest(),
        clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" },
        sealed: {
          ...chainRequest().sealed,
          contentKeys: { [NAME]: KEY },
        },
      },
    );

    assert.deepEqual(applied, {
      accepted: 0,
      errors: [],
      issues: [{ code: "invalid_transport", section: "response" }],
    });
    assert.deepEqual(chainKeysFiled, [], "the chain key in direct representation is never filed");
    assert.deepEqual(periodKeysFiled, [], "the whole response is refused before sibling writes");

    const control = await applyAssociatedResponse(
      resolver,
      clientPage("render-consistent-bound-response"),
      ISSUER,
      {
        transport: { method: "ECDH-P256" },
        keys: {
          chainKeys: { [GROUP]: { [TERMINAL_T]: { key: KEY } } },
          periodKeys: { [GROUP]: { "251023T1415": { key: KEY } } },
          contentKeys: { [NAME]: { key: KEY } },
        },
      },
      {
        ...chainRequest(),
        clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" },
        sealed: { ...chainRequest().sealed, contentKeys: { [NAME]: KEY } },
      },
    );
    assert.deepEqual(control, { accepted: 3, errors: [], issues: [] });
    assert.equal(chainKeysFiled.length, 1, "the matching wrapped chain reaches retention");
    assert.equal(
      periodKeysFiled.length,
      1,
      "the matching wrapped period sibling reaches retention",
    );
  });
});
