// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { parseDcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlEncode, utf8Decode } from "../../../core-shared/codec.js";
import { bindValue } from "../../../core-shared--publisher-issuer/bind.js";
import { seal as sealKey } from "../../../core-shared--publisher-issuer/keySealing.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { chainKeyIssuerEngine } from "../core-issuer/chainKeyIssuerEngine.js";
import { chainKeyCapabilitySource } from "../core-issuer/chainKeyCapabilitySource.js";
import { chainKeyRequestInput } from "../core-issuer/chainKeyRequestInput.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;
const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const GROUP = "premium";
const NAME = "bodytext";
const AT = "2025-10-23T14:20:00Z";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

function policy(futurePeriodCount, content = false, authorizePeriod = () => true) {
  return {
    decide(_claims, requested) {
      return {
        contentNames: content ? requested.contentNames : [],
        periodGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          futurePeriodCount,
          authorizePeriod,
        })),
      };
    },
  };
}

async function world(chainItemSlots = 1) {
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
  const supply = periodFamilySupply({
    families: { [GROUP]: generation },
    chainWindows: 2,
    chainItemSlots,
  });
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: supply,
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
          get: (issuerName, keyId) =>
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
    chainKeyProfile: explicitChainKeyClientProfile,
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
  });
  return { client, generation, issuerKeys, page, registration };
}

function requestFor(client, page) {
  return parseDcaRequest(JSON.stringify(client.buildRequest(client.parse(page), ISSUER, [NAME])));
}

test("one explicit member projects period keys for a relay-only client", async () => {
  const { client, generation, page, registration } = await world();
  const chainFamily = page.issuerData[ISSUER].sealed.chainKeys[GROUP];
  const first = Object.keys(chainFamily).sort()[0];
  page.issuerData[ISSUER].sealed.chainKeys[GROUP] = { [first]: chainFamily[first] };

  const clientData = client.parse(page);
  const request = parseDcaRequest(JSON.stringify(client.buildRequest(clientData, ISSUER, [NAME])));
  const engine = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: policy(2),
    clock: new Clock(AT),
  });
  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.capabilities, []);
  assert.deepEqual(result.errors, {});
  assert.deepEqual(Object.keys(result.periodKeys[GROUP]), ["251023T1415", "251023T1430"]);
  for (const t of Object.keys(result.periodKeys[GROUP])) {
    assert.equal(
      result.periodKeys[GROUP][t],
      base64urlEncode(await generation.periodKey(GROUP, t)),
    );
  }

  const globalContext = structuredClone(request.toObject());
  globalContext.periodGeometry = { ...GEOMETRY };
  const sameResolved = await engine.unlock(
    parseDcaRequest(JSON.stringify(globalContext)),
    registration,
    {},
    { capturedAtMs: Date.parse(AT) },
  );
  assert.deepEqual(
    sameResolved.periodKeys,
    result.periodKeys,
    "the same shared pair remains authenticated",
  );

  const answer = await new UnlockEndpoint(
    new IssuerProcessor(engine, { periodKeyInput: true }),
  ).handleRequest({
    request,
    registration,
  });
  assert.equal(answer.response.status, 200);
  assert.equal(answer.response.body.keys.chainKeys, undefined);
  await client.applyResponse(clientData, ISSUER, answer.response.body);
  assert.equal(
    utf8Decode(await client.decrypt(clientData, NAME, client.extract(page, NAME))),
    ARTICLE,
  );
});

test("later period-key projection includes explicit article targets without widening other coordinates", async () => {
  const { client, page, registration } = await world(2);
  const clientData = client.parse(page);
  const request = parseDcaRequest(JSON.stringify(client.buildRequest(clientData, ISSUER, [NAME])));
  const engine = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: policy(2),
    clock: new Clock("2025-10-23T14:50:00Z"),
  });
  const result = await engine.unlock(request, registration);
  assert.deepEqual(Object.keys(result.periodKeys[GROUP]), [
    "251023T1415",
    "251023T1430",
    "251023T1445",
    "251023T1500",
  ]);

  const answer = await new UnlockEndpoint(
    new IssuerProcessor(engine, { periodKeyInput: true }),
  ).handleRequest({ request, registration });
  assert.equal(answer.response.status, 200);
  await client.applyResponse(clientData, ISSUER, answer.response.body);
  assert.equal(
    utf8Decode(await client.decrypt(clientData, NAME, client.extract(page, NAME))),
    ARTICLE,
  );
});

test("one subterminal member is valid and clamps the projected reach", async () => {
  const { client, generation, issuerKeys, page, registration } = await world();
  const t = "251023T1430";
  const capability = await generation.chainCapability(GROUP, t);
  page.issuerData[ISSUER].sealed.chainKeys[GROUP] = {
    [t]: await sealKey(capability.key, issuerKeys.publicKey, "ecdh-p256", {
      random: new Random({ seed: 99 }),
      binding: {
        renderId: page.resource.renderId,
        accessGroup: GROUP,
        suppliedT: t,
        chainKey: true,
        ...GEOMETRY,
      },
    }),
  };

  const result = await chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: policy(20),
    clock: new Clock(AT),
  }).unlock(requestFor(client, page), registration);
  assert.deepEqual(Object.keys(result.periodKeys[GROUP]), ["251023T1415", "251023T1430"]);
  assert.deepEqual(result.errors, {});
});

test("a valid high-byte chainsPerDay stays intact through BIND and issuer projection", async () => {
  const { client, issuerKeys, page, registration } = await world();
  // 288 (0x120) divides the 1440-minute day. Its five-minute window admits
  // one-minute periods and five positions, within the shared 288-position cap.
  const geometry = Object.freeze({ chainsPerDay: 288, periodMinutes: 1 });
  const t = "251023T1420";
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(19),
    geometry,
  });
  const capability = await generation.chainCapability(GROUP, t);
  const binding = {
    renderId: page.resource.renderId,
    accessGroup: GROUP,
    suppliedT: t,
    chainKey: true,
    ...geometry,
  };

  assert.equal(
    bindValue(binding),
    `dca-bind-key-envelope|pc|${page.resource.renderId}|${GROUP}|${t}|288|1`,
    "the valid high byte is represented by its full decimal value",
  );
  const sealed = await sealKey(capability.key, issuerKeys.publicKey, "ecdh-p256", {
    random: new Random({ seed: 109 }),
    binding,
  });
  const requestDocument = structuredClone(requestFor(client, page).toObject());
  requestDocument.periodGeometry = geometry;
  requestDocument.requestedPeriodKeys = { [GROUP]: [t] };
  requestDocument.sealed.chainKeys = { [GROUP]: { [t]: sealed } };
  const request = parseDcaRequest(JSON.stringify(requestDocument));

  const result = await chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: policy(1),
    clock: new Clock(AT),
  }).unlock(request, registration);
  assert.deepEqual(Object.keys(result.periodKeys[GROUP]), [t]);
  assert.equal(result.periodKeys[GROUP][t], base64urlEncode(await generation.periodKey(GROUP, t)));
  assert.deepEqual(result.errors, {});
});

test("a malformed shared geometry pair is rejected before opening a key", async () => {
  const { client, page } = await world();
  page.periodGeometry = { ...GEOMETRY, accessGroups: { [GROUP]: GEOMETRY } };
  const request = new DcaRequest({
    ...client.buildRequest(client.parse(page), ISSUER, [NAME]),
    periodGeometry: page.periodGeometry,
  });
  assert.throws(
    () => chainKeyRequestInput(request),
    (error) => error.code === "binding_failed",
  );
});

test("a present malformed chain collection refuses the whole request beside period keys", () => {
  for (const malformed of [null, [], "bad", 5, true]) {
    const request = new DcaRequest({
      periodGeometry: GEOMETRY,
      sealed: {
        periodKeys: { [GROUP]: { "251023T1415": "sealed-period-key" } },
        chainKeys: malformed,
      },
    });
    assert.throws(
      () => chainKeyRequestInput(request),
      (/** @type {any} */ error) => error.code === "binding_failed",
      "a collection that is not a map is a structural refusal of the request",
    );
    assert.throws(
      () =>
        chainKeyCapabilitySource().selection(request, { capturedAtMs: Date.parse(AT) }, [
          { accessGroup: GROUP, futurePeriodCount: 1, authorizePeriod: () => true },
        ]),
      (/** @type {any} */ error) => error.code === "binding_failed",
      "so the period-key section beside it never answers as a fallback",
    );
  }
});

test("geometry substitution fails the chain BIND while an independent content sibling answers", async () => {
  const { client, generation, issuerKeys, page, registration } = await world();
  const first = "251023T1430";
  const capability = await generation.chainCapability(GROUP, first);
  page.issuerData[ISSUER].sealed.chainKeys[GROUP] = {
    [first]: await sealKey(capability.key, issuerKeys.publicKey, "ecdh-p256", {
      random: new Random({ seed: 100 }),
      binding: {
        renderId: page.resource.renderId,
        accessGroup: GROUP,
        suppliedT: first,
        chainKey: true,
        ...GEOMETRY,
      },
    }),
  };
  page.periodGeometry = { chainsPerDay: 4, periodMinutes: 15 };

  const result = await chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: policy(2, true),
    clock: new Clock(AT),
  }).unlock(requestFor(client, page), registration);
  assert.deepEqual(Object.keys(result.contentKeys), [NAME]);
  assert.deepEqual(result.periodKeys, {});
  assert.deepEqual(result.errors, {
    [`${GROUP}|${first}`]: { error: "unseal_failed", message: "sealed value could not be opened" },
  });
});

test("duplicate-window and message-limit collections are invalid before opening", async () => {
  const { client, page } = await world();
  const request = client.buildRequest(client.parse(page), ISSUER, [NAME]);
  const family = request.sealed.chainKeys[GROUP];
  const first = Object.keys(family).sort()[0];
  request.sealed.chainKeys[GROUP] = {
    [first]: family[first],
    "251023T2330": family[first],
  };
  assert.equal(
    chainKeyRequestInput(parseDcaRequest(JSON.stringify(request))).family(GROUP).kind,
    "invalid",
  );

  request.sealed.chainKeys = Object.fromEntries(
    Array.from({ length: 17 }, (_, index) => [`g${index}`, { [first]: family[first] }]),
  );
  const input = chainKeyRequestInput(parseDcaRequest(JSON.stringify(request)));
  assert.ok(input.presented.every((accessGroup) => input.family(accessGroup).kind === "invalid"));
});

test("one policy horizon crosses the stationary UTC window with the next supplied member", async () => {
  const { client, generation, page, registration } = await world(2);
  const at = "2025-10-23T23:50:00Z";
  const result = await chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: policy(2),
    clock: new Clock(at),
  }).unlock(requestFor(client, page), registration);

  assert.deepEqual(Object.keys(result.periodKeys[GROUP]), [
    "251023T1415",
    "251023T1430",
    "251023T2345",
    "251024T0000",
  ]);
  for (const t of Object.keys(result.periodKeys[GROUP])) {
    assert.equal(
      result.periodKeys[GROUP][t],
      base64urlEncode(await generation.periodKey(GROUP, t)),
    );
  }
});

test("the final profile coordinate is retained when policy reach extends beyond 2099", () => {
  const request = new DcaRequest({
    periodGeometry: GEOMETRY,
    sealed: { chainKeys: { [GROUP]: { "991231T2345": "last" } } },
  });
  const grant = { accessGroup: GROUP, futurePeriodCount: 2, authorizePeriod: () => true };
  const select = chainKeyCapabilitySource().selection(
    request,
    { capturedAtMs: Date.parse("2099-12-31T23:50:00Z") },
    [grant],
  );
  const answer = select(GROUP, 2, grant);
  assert.ok("selected" in answer);
  if (!("selected" in answer)) return;
  assert.deepEqual(
    answer.selected.map((entry) => entry.targetTs),
    [["991231T2345"]],
  );
});

test("period-key projection selection obeys the per-family and response ceilings", () => {
  const request = new DcaRequest({
    periodGeometry: { chainsPerDay: 1, periodMinutes: 5 },
    sealed: {
      chainKeys: {
        premium: { "251023T2355": "AQ", "251024T2355": "Ag" },
        archive: { "251023T2355": "Aw", "251024T2355": "BA" },
      },
    },
  });
  const grants = ["premium", "archive"].map((accessGroup) => ({
    accessGroup,
    futurePeriodCount: 1000,
    authorizePeriod: () => true,
  }));
  const select = chainKeyCapabilitySource().selection(
    request,
    { capturedAtMs: Date.parse("2025-10-23T00:00:00Z") },
    grants,
  );
  const premium = select("premium", 1000, grants[0]);
  const archive = select("archive", 1000, grants[1]);
  assert.ok("selected" in premium && "selected" in archive);
  if (!("selected" in premium) || !("selected" in archive)) return;
  const count = (answer) =>
    answer.selected.reduce((total, entry) => total + entry.targetTs.length, 0);
  assert.equal(count(archive), 288);
  assert.equal(count(premium), 224);
});
