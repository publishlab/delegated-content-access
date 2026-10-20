import test from "node:test";
import assert from "node:assert/strict";
import { createPublisher } from "../integration-publisher/createPublisher.js";
import { createIssuerCore } from "../integration-issuer/createIssuerCore.js";
import { createDeliveryClient } from "../integration-client/createDeliveryClient.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilyContribution } from "../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import { chainKeyRequestBuilderFactory } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { contentGroupsProfile } from "../extensions/content-groups/referenceProfile.js";
import {
  world,
  CHAIN,
  GEOMETRY,
  SECRET,
  T12,
  T18,
  PUBLISHER,
  UNLOCK,
} from "../extensions/content-groups/test/_lib/world.js";

const AT = "2026-10-14T14:20:00Z";
const routes = [
  { issuerName: "issuerA", unlockUrl: UNLOCK },
  { issuerName: "issuerB", unlockUrl: UNLOCK, independent: true },
];
const items = [
  { name: "bodytext", value: "stock body", contentType: "text/plain", accessGroups: ["premium"] },
  {
    name: "sportsNews",
    value: "group body",
    contentType: "text/plain",
    contentGroups: ["premium"],
  },
  { name: "headline", value: "bought headline", contentType: "text/plain" },
  { name: "lockedAd", value: "denied ad", contentType: "text/plain" },
];
const text = async (client, name) => new TextDecoder().decode((await client.openLocal(name)).bytes);

async function setup({ failA = false } = {}) {
  const keys = await world({ issuers: ["issuerA", "issuerB"] });
  const publisher = createPublisher(
    {
      origin: PUBLISHER,
      clock: { now: () => new Date(AT) },
      random: { bytes: (n) => crypto.getRandomValues(new Uint8Array(n)) },
      signingKeys: { p1: keys.signing.privateKey },
      issuers: ["issuerA", "issuerB"].map((issuerName) => ({
        issuerName,
        keyId: `${issuerName}-k1`,
        algorithm: "ecdh-p256",
        publicKey: keys.opening[issuerName].publicKey,
      })),
      issuerSupplyPlanFor: (issuer, page) =>
        issuer.issuerName === "issuerA"
          ? {
              contentKeyNames: [],
              suppliedAccessGroups: [...page.accessGroups],
              periodKeyDelivery: { premium: ["chain-keys"] },
            }
          : {
              contentKeyNames: ["bodytext", "headline", "lockedAd"],
              suppliedAccessGroups: [],
            },
    },
    periodFamilyContribution({
      families: {
        premium: periodFamilyGeneration({
          keyDerivationSecret: new Uint8Array(32).fill(7),
          geometry: GEOMETRY,
        }),
      },
      chainWindows: 2,
    }),
    contentGroupsProfile.publisherContribution({
      retainedSecret: SECRET,
      periodGeometry: GEOMETRY,
      issuerSeedWindows: { issuerB: { sportsNews: [T12] } },
      chain: CHAIN,
    }),
  );
  const coreA = createIssuerCore({
    engine: referenceChainKeyProfile.issuerEngineFor({
      operatingIssuerNames: ["issuerA"],
      accessPolicy: {
        decide: (_claims, requested) => ({
          contentNames: [],
          periodGrants: requested.accessGroups.map((accessGroup) => ({
            accessGroup,
            futurePeriodCount: 2,
            authorizePeriod: () => true,
          })),
        }),
      },
    }),
  });
  const coreB = createIssuerCore(
    {
      operatingIssuerNames: ["issuerB"],
      accessPolicy: {
        decide: (_claims, requested) => ({
          contentNames: requested.contentNames.filter(
            (n) => n === "headline" || (failA && n === "bodytext"),
          ),
        }),
      },
    },
    contentGroupsProfile.issuerContribution({
      chain: CHAIN,
      policy: {
        decide: (input) => ({
          grants: Object.entries(input.contentGroups).flatMap(([contentName, entry]) =>
            entry.groups.map((group) => ({
              kind: "chain",
              contentName,
              group,
              windowStart: T12,
              cutoffT: T18,
            })),
          ),
          authorizePeriod: () => true,
        }),
      },
    }),
  );
  const sent = [],
    responses = [];
  const transport = {
    async post(_url, request) {
      const wire = JSON.parse(JSON.stringify(request));
      sent.push(wire);
      if (failA && wire.issuerName === "issuerA")
        return { status: 503, contentType: "application/json", body: {} };
      const core = wire.issuerName === "issuerA" ? coreA : coreB;
      const result = await core.endpoint.handleDocument(
        JSON.stringify(wire),
        keys.registration,
        {},
        Date.parse(AT),
      );
      const body = JSON.parse(JSON.stringify(result.response.body));
      responses.push({ issuer: wire.issuerName, body, status: result.response.status });
      return { status: result.response.status, body, contentType: "application/json" };
    },
  };
  const bundle = contentGroupsProfile.client({
    chain: CHAIN,
    createPeriodKeyCache: (c) => new PeriodKeyCache(c),
    createChainKeyCache: (c) => new ChainKeyCache(c),
  });
  const caches = { cache: new PeriodKeyCache(), chainCache: new ChainKeyCache() };
  async function client(resourceId) {
    const rendered = await publisher.publish({ resourceId, data: {}, items });
    return createDeliveryClient({
      reader: {
        dcaData: rendered.dcaData,
        publisherOrigin: PUBLISHER,
        extract: (n) => rendered.sealedContent[n],
      },
      issuerName: "issuerA",
      unlockUrl: UNLOCK,
      transport,
      ...caches,
      chainKeyProfile: referenceChainKeyProfile,
      relayPeriodKeys: true,
      requestBuilderFactory: (options) =>
        bundle.requestBuilderFactory({ innerBuilder: chainKeyRequestBuilderFactory(options) }),
      recoverySources: bundle.composeOptions.recoverySources,
      responseSections: bundle.composeOptions.responseSections,
    });
  }
  return { client, sent, responses };
}

test("separate issuers: stock and content-group chains open, scopes project, held keys reuse", async () => {
  const w = await setup();
  const first = await w.client("one");
  const walk = await first.unlockRoutes(
    items.map((i) => i.name),
    routes,
  );
  assert.deepEqual(walk.missing, ["lockedAd"]);
  for (const item of items.slice(0, 3)) assert.equal(await text(first, item.name), item.value);
  await assert.rejects(first.openLocal("lockedAd"), { code: "no_key" });
  assert.deepEqual(
    w.sent.map((r) => r.issuerName),
    ["issuerA", "issuerB"],
  );
  assert.equal(w.sent[0].sealed.contentWindowSeeds, undefined);
  assert.equal(w.sent[0].requestedContentGroups, undefined);
  assert.deepEqual(Object.keys(w.sent[0].sealed.chainKeys), ["premium"]);
  assert.equal(w.sent[1].sealed.chainKeys, undefined);
  assert.equal(w.sent[1].sealed.contentKeys.bodytext, undefined);
  assert.deepEqual(Object.keys(w.sent[1].sealed.contentWindowSeeds), ["sportsNews"]);
  assert.equal(w.responses[0].body.contentGroups, undefined);
  assert.equal(w.responses[1].body.keys.chainKeys, undefined);
  assert.ok(w.responses.every((r) => r.body.periodGeometry === undefined));
  const later = await w.client("two");
  const before = w.sent.length;
  assert.deepEqual((await later.unlockRoutes(["bodytext", "sportsNews"], routes)).missing, []);
  assert.equal(await text(later, "bodytext"), "stock body");
  assert.equal(await text(later, "sportsNews"), "group body");
  assert.equal(
    w.sent.length,
    before,
    "both held chain families open the new render without a request",
  );
});

test("separate issuers: a failed stock route preserves independent item fallback and group reuse", async () => {
  const w = await setup({ failA: true });
  const first = await w.client("fallback-one");
  const walk = await first.unlockRoutes(["bodytext", "sportsNews", "headline"], routes);
  assert.deepEqual(walk.missing, []);
  assert.equal(w.sent.length, 2);
  assert.ok(w.sent[1].sealed.contentKeys.bodytext);
  for (const item of items.slice(0, 3)) assert.equal(await text(first, item.name), item.value);
  const later = await w.client("fallback-two");
  await assert.rejects(
    later.openLocal("bodytext"),
    { code: "no_key" },
    "an item key never becomes a stock family grant",
  );
  const before = w.sent.length;
  assert.equal(await text(later, "sportsNews"), "group body");
  assert.equal(w.sent.length, before);
  assert.deepEqual((await later.unlockRoutes(["bodytext"], routes)).missing, []);
  assert.equal(await text(later, "bodytext"), "stock body");
  assert.equal(w.sent.length, before + 2, "new render needs fresh item fallback");
});

test("separate issuers: an omitted sibling section authorizes no conditional route", async () => {
  const w = await setup();
  const first = await w.client("conditional");
  const conditional = routes.map(({ independent, ...route }) => route);
  const walk = await first.unlockRoutes(["bodytext", "sportsNews", "headline"], conditional);
  assert.deepEqual(walk.missing, ["sportsNews", "headline"]);
  assert.deepEqual(
    w.sent.map((r) => r.issuerName),
    ["issuerA"],
  );
  assert.equal(await text(first, "bodytext"), "stock body");
  await assert.rejects(first.openLocal("sportsNews"), { code: "no_key" });
  assert.deepEqual((await first.unlockRoutes(["sportsNews", "headline"], routes)).missing, []);
  assert.deepEqual(
    w.sent.map((r) => r.issuerName),
    ["issuerA", "issuerB"],
  );
  assert.equal(await text(first, "sportsNews"), "group body");
  assert.equal(await text(first, "headline"), "bought headline");
});
