// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { parseDcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlDecode, base64urlEncode, utf8Decode } from "../../../core-shared/codec.js";
import { seal as sealKey } from "../../../core-shared--publisher-issuer/keySealing.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { PeriodChainRequestBuilder } from "../core-client/PeriodChainRequestBuilder.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { periodChainIssuerEngine } from "../core-issuer/periodChainIssuerEngine.js";
import { periodChainCapabilitySource } from "../core-issuer/periodChainCapabilitySource.js";
import { periodChainRequestInput } from "../core-issuer/periodChainRequestInput.js";
import { explicitPeriodChainClientProfile } from "../referenceProfile.js";

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

function policy(periodCount, content = false) {
  return {
    decide(_claims, requested) {
      return {
        contentNames: content ? requested.contentNames : [],
        periodGrants: requested.accessGroups.map((accessGroup) => ({ accessGroup, periodCount })),
      };
    },
  };
}

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
  const supply = periodFamilySupply({ families: { [GROUP]: generation }, chainWindows: 2 });
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: supply,
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
          get: (issuerName, keyId) =>
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
    periodChainProfile: explicitPeriodChainClientProfile,
    requestBuilderFactory: (options) => new PeriodChainRequestBuilder(options),
  });
  return { client, generation, issuerKeys, page, registration };
}

function requestFor(client, page) {
  return parseDcaRequest(JSON.stringify(client.buildRequest(client.parse(page), ISSUER, [NAME])));
}

test("one explicit member projects frozen leaves for a relay-only client", async () => {
  const { client, generation, page, registration } = await world();
  const chainFamily = page.issuerData[ISSUER].sealed.periodChainKeys[GROUP];
  const first = Object.keys(chainFamily).sort()[0];
  page.issuerData[ISSUER].sealed.periodChainKeys[GROUP] = { [first]: chainFamily[first] };

  const clientData = client.parse(page);
  const request = parseDcaRequest(JSON.stringify(client.buildRequest(clientData, ISSUER, [NAME])));
  const engine = periodChainIssuerEngine({ accessPolicy: policy(2), clock: new Clock(AT) });
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
  globalContext.periodChain = { ...GEOMETRY };
  const sameResolved = await engine.unlock(
    parseDcaRequest(JSON.stringify(globalContext)),
    registration,
    {},
    { capturedAtMs: Date.parse(AT) },
  );
  assert.deepEqual(
    sameResolved.periodKeys,
    result.periodKeys,
    "default and family-override placement resolve to the same authenticated geometry",
  );

  const answer = await new UnlockEndpoint(
    new IssuerProcessor(engine, { exactPeriodInput: true }),
  ).handleRequest({
    request,
    registration,
  });
  assert.equal(answer.response.status, 200);
  assert.equal(answer.response.body.keys.periodChainKeys, undefined);
  await client.applyResponse(clientData, ISSUER, answer.response.body);
  assert.equal(
    utf8Decode(await client.decrypt(clientData, NAME, client.extract(page, NAME))),
    ARTICLE,
  );
});

test("one subterminal member is valid and clamps the projected reach", async () => {
  const { client, generation, issuerKeys, page, registration } = await world();
  const t = "251023T1430";
  const state = await generation.chainCapability(GROUP, t);
  page.issuerData[ISSUER].sealed.periodChainKeys[GROUP] = {
    [t]: await sealKey(state.key, issuerKeys.publicKey, "ECDH-P256", {
      random: new Random({ seed: 99 }),
      binding: {
        renderId: page.resource.renderId,
        accessGroup: GROUP,
        suppliedT: t,
        periodChain: true,
        ...GEOMETRY,
      },
    }),
  };

  const result = await periodChainIssuerEngine({
    accessPolicy: policy(20),
    clock: new Clock(AT),
  }).unlock(requestFor(client, page), registration);
  assert.deepEqual(Object.keys(result.periodKeys[GROUP]), ["251023T1415", "251023T1430"]);
  assert.deepEqual(result.errors, {});
});

test("an applicable malformed override never inherits the document pair or opens a key", async () => {
  const { client, page, registration } = await world();
  page.periodChain = {
    ...GEOMETRY,
    accessGroups: { [GROUP]: { chainsPerDay: 2 } },
  };
  const request = requestFor(client, page);
  const input = periodChainRequestInput(request);
  assert.equal(input.family(GROUP).kind, "invalid");

  let lookups = 0;
  const counted = {
    ...registration,
    openingKeys: {
      get(...args) {
        lookups++;
        return registration.openingKeys.get(...args);
      },
    },
  };
  await assert.rejects(
    periodChainIssuerEngine({ accessPolicy: policy(2), clock: new Clock(AT) }).unlock(
      request,
      counted,
    ),
    (/** @type {any} */ error) => error.code === "denied",
  );
  assert.equal(lookups, 0);
});

test("a present malformed chain collection refuses the whole request beside exact keys", () => {
  for (const malformed of [null, [], "bad"]) {
    const request = new DcaRequest({
      periodChain: GEOMETRY,
      sealed: {
        periodKeys: { [GROUP]: { "251023T1415": "exact" } },
        periodChainKeys: malformed,
      },
    });
    assert.throws(
      () => periodChainRequestInput(request),
      (/** @type {any} */ error) => error.code === "binding_failed",
      "a collection that is not a map is a structural refusal of the request",
    );
    assert.throws(
      () => periodChainCapabilitySource().selection(request, { capturedAtMs: Date.parse(AT) }),
      (/** @type {any} */ error) => error.code === "binding_failed",
      "so the exact section beside it never answers as a fallback",
    );
  }
});

test("geometry substitution fails the chain BIND while an independent content sibling answers", async () => {
  const { client, generation, issuerKeys, page, registration } = await world();
  const first = "251023T1430";
  const state = await generation.chainCapability(GROUP, first);
  page.issuerData[ISSUER].sealed.periodChainKeys[GROUP] = {
    [first]: await sealKey(state.key, issuerKeys.publicKey, "ECDH-P256", {
      random: new Random({ seed: 100 }),
      binding: {
        renderId: page.resource.renderId,
        accessGroup: GROUP,
        suppliedT: first,
        periodChain: true,
        ...GEOMETRY,
      },
    }),
  };
  page.periodChain = { chainsPerDay: 4, periodMinutes: 15 };

  const result = await periodChainIssuerEngine({
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
  const family = request.sealed.periodChainKeys[GROUP];
  const first = Object.keys(family).sort()[0];
  request.sealed.periodChainKeys[GROUP] = {
    [first]: family[first],
    "251023T2330": family[first],
  };
  assert.equal(
    periodChainRequestInput(parseDcaRequest(JSON.stringify(request))).family(GROUP).kind,
    "invalid",
  );

  request.sealed.periodChainKeys = Object.fromEntries(
    Array.from({ length: 17 }, (_, index) => [`g${index}`, { [first]: family[first] }]),
  );
  const input = periodChainRequestInput(parseDcaRequest(JSON.stringify(request)));
  assert.ok(input.presented.every((accessGroup) => input.family(accessGroup).kind === "invalid"));
});

test("one policy horizon crosses the stationary UTC window with the next supplied member", async () => {
  const { client, generation, page, registration } = await world();
  const at = "2025-10-23T23:50:00Z";
  const result = await periodChainIssuerEngine({
    accessPolicy: policy(2),
    clock: new Clock(at),
  }).unlock(requestFor(client, page), registration);

  assert.deepEqual(Object.keys(result.periodKeys[GROUP]), ["251023T2345", "251024T0000"]);
  for (const t of Object.keys(result.periodKeys[GROUP])) {
    assert.equal(
      result.periodKeys[GROUP][t],
      base64urlEncode(await generation.periodKey(GROUP, t)),
    );
  }
});

test("the final profile coordinate is retained when policy reach extends beyond 2099", () => {
  const request = new DcaRequest({
    periodChain: GEOMETRY,
    sealed: { periodChainKeys: { [GROUP]: { "991231T2345": "last" } } },
  });
  const select = periodChainCapabilitySource().selection(request, {
    capturedAtMs: Date.parse("2099-12-31T23:50:00Z"),
  });
  const answer = select(GROUP, 2);
  assert.ok("selected" in answer);
  if (!("selected" in answer)) return;
  assert.deepEqual(
    answer.selected.map((entry) => entry.targetTs),
    [["991231T2345"]],
  );
});

test("exact projection selection obeys the per-family and response ceilings", () => {
  const request = new DcaRequest({
    periodChain: { chainsPerDay: 1, periodMinutes: 5 },
    sealed: {
      periodChainKeys: {
        premium: { "251023T2355": "a", "251024T2355": "b" },
        archive: { "251023T2355": "c", "251024T2355": "d" },
      },
    },
  });
  const select = periodChainCapabilitySource().selection(request, {
    capturedAtMs: Date.parse("2025-10-23T00:00:00Z"),
  });
  const premium = select("premium", 1000);
  const archive = select("archive", 1000);
  assert.ok("selected" in premium && "selected" in archive);
  if (!("selected" in premium) || !("selected" in archive)) return;
  const count = (answer) =>
    answer.selected.reduce((total, entry) => total + entry.targetTs.length, 0);
  assert.equal(count(premium), 288);
  assert.equal(count(archive), 224);
});
