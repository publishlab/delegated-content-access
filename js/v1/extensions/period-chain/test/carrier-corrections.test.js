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
import { PeriodChainCache } from "../core-client/PeriodChainCache.js";
import { PeriodChainRequestBuilder } from "../core-client/PeriodChainRequestBuilder.js";
import { periodChainIssuerEngine } from "../core-issuer/periodChainIssuerEngine.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { explicitPeriodChainClientProfile } from "../referenceProfile.js";

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
const STATE = base64urlEncode(new Uint8Array(16).fill(3));

/** @param {number} periodCount @param {boolean} content */
function policy(periodCount, content = true) {
  return {
    decide(/** @type {any} */ _claims, /** @type {any} */ requested) {
      return {
        contentNames: content ? requested.contentNames : [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
          accessGroup,
          periodCount,
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
    issuerSupplyPlanFor: () => ({ periodKeyDelivery: { [GROUP]: ["chain"] } }),
    issuers: [
      {
        issuerName: ISSUER,
        keyId: KEY_ID,
        algorithm: "ECDH-P256",
        publicKey: issuerKeys.publicKey,
        unlockUrl: "https://api.example.com/unlock",
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
              ? { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey }
              : undefined,
        },
        [{ issuerName: ISSUER, keyId: KEY_ID }],
      ),
    },
  ]).get(SIGNING_KID);
  const client = new Client({
    publisherOrigin: PUB,
    cache: new PeriodKeyCache(),
    requestBuilderFactory: (/** @type {any} */ options) => new PeriodChainRequestBuilder(options),
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

describe("request admission when the issuer selected the period-chain extension", () => {
  for (const malformed of [null, [], "bad"]) {
    test(`a malformed chain collection ${JSON.stringify(malformed)} refuses the whole request`, async () => {
      const { client, page, registration } = await world();
      const document = documentFor(client, page);
      document.sealed.periodChainKeys = malformed;
      const { counted, lookups } = counting(registration);
      const engine = periodChainIssuerEngine({ accessPolicy: policy(2), clock: new Clock(AT) });

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
    document.sealed.periodChainKeys = {
      "2bad": document.sealed.periodChainKeys[GROUP],
      [GROUP]: document.sealed.periodChainKeys[GROUP],
    };
    const { counted, lookups } = counting(registration);
    const engine = periodChainIssuerEngine({ accessPolicy: policy(2), clock: new Clock(AT) });

    await assert.rejects(
      engine.unlock(requestOf(document), counted),
      (/** @type {any} */ error) => error.code === "binding_failed",
    );
    assert.equal(lookups.count, 0, "a sibling family cannot carry the request past the name rule");
  });

  test("the refusal reaches the wire as a malformed base coordinate does", async () => {
    const { client, page, registration } = await world();
    const document = documentFor(client, page);
    document.sealed.periodChainKeys = "bad";
    const engine = periodChainIssuerEngine({ accessPolicy: policy(2), clock: new Clock(AT) });
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
      document.sealed.periodChainKeys = malformed;
      const result = await new IssuerEngine({ accessPolicy: policy(2) }).unlock(
        requestOf(document),
        registration,
      );
      assert.deepEqual(Object.keys(result.contentKeys), [NAME]);
      assert.deepEqual(result.errors, {});
    }

    const named = documentFor(client, page);
    named.sealed.periodChainKeys = { "2bad": named.sealed.periodChainKeys[GROUP] };
    const result = await new IssuerEngine({ accessPolicy: policy(2) }).unlock(
      requestOf(named),
      registration,
    );
    assert.deepEqual(Object.keys(result.contentKeys), [NAME]);
    assert.deepEqual(result.errors, {});
  });
});

describe("local chain failures keep their narrower scope under a selecting issuer", () => {
  const LOCAL = [
    {
      name: "a non-object family",
      spoil: (/** @type {any} */ document) => {
        document.sealed.periodChainKeys[OTHER] = "nope";
      },
    },
    {
      name: "a partial geometry override",
      spoil: (/** @type {any} */ document) => {
        document.sealed.periodChainKeys[OTHER] = { [TERMINAL_T]: STATE };
        document.periodChain = { ...GEOMETRY, accessGroups: { [OTHER]: { chainsPerDay: 2 } } };
      },
    },
    {
      name: "an off-grid label",
      spoil: (/** @type {any} */ document) => {
        document.sealed.periodChainKeys[OTHER] = { "251023T1410": STATE };
      },
    },
    {
      name: "a non-string leaf",
      spoil: (/** @type {any} */ document) => {
        document.sealed.periodChainKeys[OTHER] = { [TERMINAL_T]: { key: STATE } };
      },
    },
  ];

  for (const { name, spoil } of LOCAL) {
    test(`${name} answers silently while its sibling family is answered`, async () => {
      const { client, generation, page, registration } = await world();
      const document = documentFor(client, page);
      spoil(document);
      const engine = periodChainIssuerEngine({ accessPolicy: policy(2), clock: new Clock(AT) });

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
      assert.deepEqual(result.errors, {}, "a family the reader refused reports no coordinate");
    });
  }
});

/** A page with no wrapped content: these cases judge what is filed, not what opens. */
function clientPage(renderId) {
  return new DcaData(
    {
      version: "1",
      resourceJWT: `e30.${base64urlEncode(utf8Encode(JSON.stringify({ renderId })))}.x`,
      issuerData: {
        [ISSUER]: { keyId: KEY_ID, unlockUrl: "https://api.example/unlock", sealed: {} },
      },
      contentData: {},
    },
    { publisherOrigin: PUB },
  );
}

/** The request document the client sent, in the shape `PageLoad` holds it. */
function chainRequest(periodChain = GEOMETRY, families = { [GROUP]: { [TERMINAL_T]: STATE } }) {
  return { sealed: { contentKeys: {}, periodChainKeys: families }, periodChain };
}

/** A chain response carrying one cutoff per named family. */
function chainResponse(periodChain = GEOMETRY, families = { [GROUP]: { [TERMINAL_T]: STATE } }) {
  return { keys: { periodChainKeys: families }, periodChain };
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
    periodChainProfile: explicitPeriodChainClientProfile,
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
      chainRequest(GEOMETRY, { [GROUP]: { [offGrid]: STATE } }),
    ),
    {
      accepted: 0,
      errors: [],
      issues: [{ section: "errors", code: "malformed_error" }],
    },
  );
});

describe("a chain response is admitted under the pair its request resolved", () => {
  test("a response pair the request never asked for files no cutoff", async () => {
    const { filed, resolver } = filingResolver();

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-pair-differs"),
      ISSUER,
      chainResponse({ chainsPerDay: 4, periodMinutes: 5 }),
      chainRequest(),
    );

    assert.deepEqual(applied, {
      accepted: 0,
      errors: [],
      issues: [{ section: "periodChainKeys", code: "malformed_key" }],
    });
    assert.deepEqual(filed, [], "the differing pair is refused before retention");
  });

  test("a family the request never presented files no cutoff", async () => {
    const { filed, resolver } = filingResolver();

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-family-unasked"),
      ISSUER,
      chainResponse(),
      chainRequest(GEOMETRY, { [OTHER]: { [TERMINAL_T]: STATE } }),
    );

    assert.deepEqual(applied, {
      accepted: 0,
      errors: [],
      issues: [{ section: "periodChainKeys", code: "malformed_key" }],
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

  test("equivalent geometry placement is one pair", async () => {
    const override = { accessGroups: { [GROUP]: { ...GEOMETRY } } };
    const placements = [
      {
        name: "a response override against a request default",
        request: GEOMETRY,
        response: override,
      },
      {
        name: "a response default against a request override",
        request: override,
        response: GEOMETRY,
      },
    ];

    for (const { name, request, response } of placements) {
      const { filed, resolver } = filingResolver();

      const applied = await applyAssociatedResponse(
        resolver,
        clientPage(`render-placement-${filed.length}`),
        ISSUER,
        chainResponse(response),
        chainRequest(request),
      );

      assert.deepEqual(applied, { accepted: 1, errors: [], issues: [] }, name);
      assert.deepEqual(
        filed.map(([accessGroup, cutoffT]) => [accessGroup, cutoffT]),
        [[GROUP, TERMINAL_T]],
      );
      assert.deepEqual(
        { chainsPerDay: filed[0][3].chainsPerDay, periodMinutes: filed[0][3].periodMinutes },
        { ...GEOMETRY },
        "the pair both sides resolved is what the cutoff is filed under",
      );
    }
  });

  test("a cutoff at or below a presented source position in its window is admitted", async () => {
    const { filed, resolver } = filingResolver();

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-cutoff-reachable"),
      ISSUER,
      chainResponse(GEOMETRY, { [GROUP]: { "251023T1415": STATE } }),
      chainRequest(GEOMETRY, { [GROUP]: { "251023T1430": STATE } }),
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
    test(`a cutoff ${outside.name} files no state`, async () => {
      const { filed, resolver } = filingResolver();

      const applied = await applyAssociatedResponse(
        resolver,
        clientPage(`render-cutoff-${outside.responseT}`),
        ISSUER,
        chainResponse(GEOMETRY, { [GROUP]: { [outside.responseT]: STATE } }),
        chainRequest(GEOMETRY, { [GROUP]: { [outside.requestT]: STATE } }),
      );

      assert.deepEqual(applied, {
        accepted: 0,
        errors: [],
        issues: [{ section: "periodChainKeys", code: "malformed_key" }],
      });
      assert.deepEqual(filed, []);
    });
  }

  test("a projected exact response files without response geometry", async () => {
    /** @type {any[][]} */
    const exact = [];
    const resolver = new ContentKeyResolver({
      cache: {
        put(/** @type {any[]} */ ...args) {
          exact.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
      chainCache: {
        put: () => assert.fail("an exact leaf never enters the chain partition"),
        candidates: () => [],
      },
      periodChainProfile: explicitPeriodChainClientProfile,
    });

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-projected-exact"),
      ISSUER,
      { keys: { periodKeys: { [GROUP]: { "251023T1415": STATE, "251023T1430": STATE } } } },
      chainRequest(),
    );

    assert.deepEqual(applied, { accepted: 2, errors: [], issues: [] });
    assert.deepEqual(
      exact.map((args) => args[1]),
      ["251023T1415", "251023T1430"],
    );
  });

  test("projected exact leaves outside the presented chain reach are not filed", async () => {
    /** @type {any[][]} */
    const exact = [];
    const resolver = new ContentKeyResolver({
      cache: {
        put(/** @type {any[]} */ ...args) {
          exact.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
      chainCache: { put: () => {}, candidates: () => [] },
      periodChainProfile: explicitPeriodChainClientProfile,
    });

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-projected-exact-outside"),
      ISSUER,
      {
        keys: {
          periodKeys: {
            [GROUP]: {
              "251023T1430": STATE,
              "251023T1145": STATE,
            },
          },
        },
      },
      chainRequest(GEOMETRY, { [GROUP]: { "251023T1415": STATE } }),
    );

    assert.deepEqual(applied, {
      accepted: 0,
      errors: [],
      issues: [
        { section: "periodKeys", code: "unsolicited_coordinate" },
        { section: "periodKeys", code: "unsolicited_coordinate" },
      ],
    });
    assert.deepEqual(exact, []);
  });

  test("an exact coordinate presented directly remains admissible outside chain reach", async () => {
    /** @type {any[][]} */
    const exact = [];
    const resolver = new ContentKeyResolver({
      cache: {
        put(/** @type {any[]} */ ...args) {
          exact.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
      chainCache: { put: () => {}, candidates: () => [] },
      periodChainProfile: explicitPeriodChainClientProfile,
    });
    const directT = "251023T1215";
    const request = chainRequest(GEOMETRY, { [GROUP]: { "251023T1145": STATE } });
    request.sealed.periodKeys = { [GROUP]: { [directT]: STATE } };

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-presented-exact"),
      ISSUER,
      { keys: { periodKeys: { [GROUP]: { [directT]: STATE } } } },
      request,
    );

    assert.deepEqual(applied, { accepted: 1, errors: [], issues: [] });
    assert.deepEqual(
      exact.map((args) => args[1]),
      [directT],
    );
  });
});

describe("an unsupported chain section is classified before the remaining sections are judged", () => {
  test("a chain section beside transport is unsupported while wrapped siblings are consumed", async () => {
    /** @type {any[][]} */
    const exact = [];
    /** @type {any[][]} */
    const chain = [];
    const handle = new Uint8Array(16).fill(11);
    const resolver = new ContentKeyResolver({
      cache: {
        put(/** @type {any[]} */ ...args) {
          exact.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
      chainCache: {
        put(/** @type {any[]} */ ...args) {
          chain.push(args);
        },
        candidates: () => [],
      },
      periodChainProfile: explicitPeriodChainClientProfile,
      // A chain client that also accepts direct delivery reaches the
      // transport gate itself, rather than the earlier gate a client
      // without a chain cache or without direct fallback stops at.
      clientBoundKeyCapability: {
        openDeliveredKeys: async (/** @type {any} */ transport) =>
          transport?.mode === "client-bound" ? { open: async () => handle } : null,
      },
      acceptDirectFallback: true,
      persistRawPeriodKeys: true,
    });

    const applied = await applyAssociatedResponse(
      resolver,
      clientPage("render-chain-beside-transport"),
      ISSUER,
      {
        transport: { mode: "client-bound", method: "ECDH-P256" },
        keys: {
          periodChainKeys: { [GROUP]: { [TERMINAL_T]: STATE } },
          periodKeys: { [GROUP]: { "251023T1415": { key: STATE } } },
          contentKeys: { [NAME]: { key: STATE } },
        },
        periodChain: { ...GEOMETRY },
      },
      {
        ...chainRequest(),
        clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" },
        sealed: {
          ...chainRequest().sealed,
          contentKeys: { [NAME]: STATE },
        },
      },
    );

    assert.deepEqual(applied, {
      accepted: 2,
      errors: [],
      issues: [{ section: "periodChainKeys", code: "unsupported_section" }],
    });
    assert.deepEqual(chain, [], "the chain section is refused before any leaf of it is opened");
    assert.deepEqual(
      exact.map((args) => args[1]),
      ["251023T1415"],
      "the wrapped supported sibling is consumed beside it",
    );
  });
});
