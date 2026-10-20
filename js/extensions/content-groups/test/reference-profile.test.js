// @ts-check
//
// The selected composition `contentGroupsProfile` supplies every role's
// content-groups member: the publisher and issuer contributions, the client
// bundle with its request builder, response consumer and recovery source, and
// the response sections and kinds the client-bound transport needs. This file
// stays inside the extension: base roles, the base period-key cache and a
// recording chain-key cache exercise host substitution. A separate exchange
// omits construction overrides and uses the stock chain-key cache to prove
// the normal publisher, issuer and client defaults compose.

import test from "node:test";
import assert from "node:assert/strict";

import { contentGroupsProfile } from "../referenceProfile.js";
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { createDeliveryClient } from "../../../integration-client/createDeliveryClient.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { JsonDeliveryReader } from "../../../adapter-client/JsonDeliveryReader.js";
import { writeJsonDelivery } from "../../../adapter-publisher/writeJsonDelivery.js";
import { unlockThroughAdmission } from "../../../test-lib/harnesses/unlockThroughAdmission.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import { CONTRACT } from "../core-shared/construction.js";
import { KIND_DESCRIPTORS, RESPONSE_SECTIONS } from "../core-shared--client-issuer/request.js";
import { ContentGroupRequestBuilder } from "../core-client/ContentGroupRequestBuilder.js";
import { ChainKeyCache } from "../../chain-keys/core-client/ChainKeyCache.js";
import { DERIVING_CHAIN } from "./_lib/derivingChainPort.js";

const subtle = globalThis.crypto.subtle;
const ORIGIN = "https://news.example";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
const SECRET = Uint8Array.from({ length: 32 }, (_, i) => i);
// 14:20 renders at period T1400 in the window that starts at T1200.
const AT = "2026-10-14T14:20:00Z";
const W12 = "261014T1200";
const T14 = "261014T1400";
const UNLOCK = "https://issuer.example/unlock";
const random = {
  bytes: (/** @type {number} */ n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
};

/** A chain-key cache that records what the bundle asks of it and holds nothing. */
function recordingChainCache() {
  const seen = { config: /** @type {any} */ (null), puts: /** @type {any[]} */ ([]), cleared: 0 };
  return {
    seen,
    /** @param {object} config */
    create(config) {
      seen.config = config;
      return {
        /** @param {any[]} args */
        async put(...args) {
          seen.puts.push(args);
        },
        async candidates() {
          return [];
        },
        async promote() {},
        async attempted() {},
        async clearReaderContext() {
          seen.cleared++;
        },
      };
    },
  };
}

/** One publisher, one issuer and one rendered page with two connector items and an ordinary one. */
/** @param {{stock?: boolean, grants?: any[]}} [options] */
async function world({ stock = false, grants } = {}) {
  const signing = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const opening = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const publisher = createPublisher(
    /** @type {any} */ ({
      origin: ORIGIN,
      clock: { now: () => new Date(AT) },
      random,
      signingKeys: { p1: signing.privateKey },
      issuers: [
        {
          issuerName: "issuerA",
          keyId: "a1",
          algorithm: "ecdh-p256",
          publicKey: opening.publicKey,
        },
      ],
      issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ render) => ({
        contentKeyNames: render.contentNames.filter((/** @type {string} */ n) => n === "purchase"),
        suppliedAccessGroups: [],
      }),
    }),
    contentGroupsProfile.publisherContribution({
      retainedSecret: SECRET,
      periodGeometry: GEOMETRY,
      issuerSeedWindows: { issuerA: { bodytext: [W12], headline: [W12] } },
      ...(stock ? {} : { chain: DERIVING_CHAIN }),
    }),
  );
  const render = await publisher.publish({
    resourceId: "story1",
    data: {},
    items: [
      {
        name: "bodytext",
        value: "body text",
        contentType: "text/plain",
        contentGroups: ["politics", "sports"],
      },
      {
        name: "headline",
        value: "head line",
        contentType: "text/plain",
        contentGroups: ["politics"],
      },
      { name: "purchase", value: "buy", contentType: "text/plain" },
    ],
  });
  const registration = {
    kid: "p1",
    publicKey: signing.publicKey,
    openingKeys: {
      get: (/** @type {string} */ issuerName) =>
        issuerName === "issuerA"
          ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
          : undefined,
    },
  };
  /** @type {any[]} */
  const decisions = [];
  const { processor, endpoint } = createIssuerCore(
    {
      operatingIssuerNames: ["issuerA"],
      accessPolicy: {
        decide: (/** @type {any} */ _c, /** @type {any} */ r) => ({ contentNames: r.contentNames }),
      },
    },
    contentGroupsProfile.issuerContribution({
      ...(stock ? {} : { chain: DERIVING_CHAIN }),
      policy: {
        decide(/** @type {any} */ input) {
          decisions.push(input);
          return {
            grants: grants ?? [
              { kind: "period", contentName: "headline", group: "politics", t: T14 },
              { kind: "item", contentName: "bodytext" },
            ],
            authorizePeriod: () => true,
          };
        },
      },
    }),
  );
  const transport = {
    /** @param {string} _url @param {object} request */
    async post(_url, request) {
      const { status, body } = await unlockThroughAdmission(
        processor,
        endpoint,
        JSON.stringify(request),
        /** @type {any} */ (registration),
      );
      return { status, contentType: "application/json", body: JSON.parse(JSON.stringify(body)) };
    },
  };
  return { render, transport, decisions };
}

test("the profile names its contract and hands each role its member", () => {
  assert.equal(contentGroupsProfile.profile, "dca-profile-content-groups");
  assert.equal(contentGroupsProfile.construction, CONTRACT.construction);
  assert.equal(contentGroupsProfile.responseSections, RESPONSE_SECTIONS);
  assert.equal(contentGroupsProfile.kindDescriptors, KIND_DESCRIPTORS);
  assert.ok(Object.isFrozen(contentGroupsProfile));
  for (const name of ["publisherContribution", "issuerContribution", "client"])
    assert.equal(typeof (/** @type {any} */ (contentGroupsProfile)[name]), "function", name);
});

test("client-bound members carry every content-group section and refuse a kind set without both kinds", () => {
  const settled = Object.freeze({ ...KIND_DESCRIPTORS, otherKind: { width: 16, open: "raw" } });
  const delivery = contentGroupsProfile.keyDeliveryMembers(settled);
  assert.equal(delivery.composedSections, RESPONSE_SECTIONS);
  assert.equal(delivery.composedKinds, settled);
  assert.deepEqual(contentGroupsProfile.capabilityOptions(settled), { composedKinds: settled });
  const [period, chain] = [CONTRACT.keyKinds.periodKey, CONTRACT.keyKinds.chainKey];
  for (const bad of [
    undefined,
    Object.freeze({}),
    Object.freeze({ [period]: KIND_DESCRIPTORS[period] }),
    Object.freeze({ ...KIND_DESCRIPTORS, [chain]: { width: 16, open: "aesHandle" } }),
    { ...KIND_DESCRIPTORS },
  ]) {
    assert.throws(
      () => contentGroupsProfile.keyDeliveryMembers(/** @type {any} */ (bad)),
      { code: "bad_config" },
      JSON.stringify(bad),
    );
    assert.throws(
      () => contentGroupsProfile.capabilityOptions(/** @type {any} */ (bad)),
      { code: "bad_config" },
      JSON.stringify(bad),
    );
  }
});

test("the client bundle builds dedicated caches and the members composeClient takes", async () => {
  const chainCache = recordingChainCache();
  /** @type {any[]} */
  const periodConfigs = [];
  const bundle = contentGroupsProfile.client({
    chain: DERIVING_CHAIN,
    limits: { maxCachedWindows: 8 },
    narrowing: { requestedContentKeys: { bodytext: "sports" } },
    createPeriodKeyCache: (config) => {
      periodConfigs.push(config);
      return new PeriodKeyCache(config);
    },
    createChainKeyCache: chainCache.create,
  });
  assert.deepEqual(periodConfigs, [{ entryKind: CONTRACT.keyKinds.periodKey, maxEntries: 8 }]);
  assert.equal(chainCache.seen.config.entryKind, CONTRACT.keyKinds.chainKey);
  assert.equal(chainCache.seen.config.periodView, "none");
  const { requestBuilderFactory, recoverySources, responseSections } = bundle.composeOptions;
  assert.deepEqual(Object.keys(bundle.composeOptions).sort(), [
    "recoverySources",
    "requestBuilderFactory",
    "responseSections",
  ]);
  assert.deepEqual(recoverySources, [bundle.recoverySource]);
  assert.deepEqual(responseSections, [bundle.responseInput]);
  assert.equal(bundle.responseInput.name, "contentGroups");
  assert.equal(typeof bundle.responseInput.clearReaderContext, "function");
  assert.ok(requestBuilderFactory({ relayPeriodKeys: true }) instanceof ContentGroupRequestBuilder);
  assert.throws(
    () => contentGroupsProfile.client({ chain: DERIVING_CHAIN, createPeriodKeyCache: () => ({}) }),
    { code: "bad_config" },
  );
});

test("a direct exchange publishes, unlocks and opens through the composed delivery client", async () => {
  const { render, transport, decisions } = await world();
  const chainCache = recordingChainCache();
  const bundle = contentGroupsProfile.client({
    chain: DERIVING_CHAIN,
    narrowing: { requestedContentKeys: { bodytext: "sports" } },
    createPeriodKeyCache: (config) => new PeriodKeyCache(config),
    createChainKeyCache: chainCache.create,
  });
  const client = createDeliveryClient({
    reader: new JsonDeliveryReader(writeJsonDelivery(render), { publisherOrigin: ORIGIN }),
    issuerName: "issuerA",
    unlockUrl: UNLOCK,
    transport,
    ...bundle.composeOptions,
  });
  const walk = await client.unlockRoutes(
    ["bodytext", "headline", "purchase"],
    [{ issuerName: "issuerA", unlockUrl: UNLOCK }],
  );
  assert.deepEqual(walk.missing, []);
  assert.equal(decisions.length, 1);
  assert.deepEqual(decisions[0].items, ["bodytext"]);
  for (const [name, text] of [
    ["bodytext", "body text"],
    ["headline", "head line"],
    ["purchase", "buy"],
  ])
    assert.equal(utf8Decode((await client.openLocal(name)).bytes), text, name);

  await client.clearReaderContext();
  assert.equal(chainCache.seen.cleared, 1, "reset reaches the dedicated chain-key cache");
  await assert.rejects(client.openLocal("bodytext"), "reset drops the held item key");
  await assert.rejects(
    client.openLocal("headline"),
    "reset empties the dedicated period-key cache",
  );
});

test("stock chain defaults publish, grant and retain keys through the real client caches", async () => {
  const { render, transport, decisions } = await world({
    stock: true,
    grants: [
      { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T14 },
      { kind: "period", contentName: "headline", group: "politics", t: T14 },
    ],
  });
  const bundle = contentGroupsProfile.client({
    createPeriodKeyCache: (config) => new PeriodKeyCache(config),
    createChainKeyCache: (config) => new ChainKeyCache(config),
  });
  const client = createDeliveryClient({
    reader: new JsonDeliveryReader(writeJsonDelivery(render), { publisherOrigin: ORIGIN }),
    issuerName: "issuerA",
    unlockUrl: UNLOCK,
    transport,
    ...bundle.composeOptions,
  });
  const names = ["bodytext", "headline", "purchase"];
  const walk = await client.unlockRoutes(names, [{ issuerName: "issuerA", unlockUrl: UNLOCK }]);
  assert.deepEqual(walk.missing, []);
  assert.equal(decisions.length, 1);
  assert.equal(
    bundle.chainKeyCache.entries().length,
    1,
    "actual stock chain cache retains the grant",
  );
  assert.equal(
    (await bundle.periodKeyCache.entries()).length,
    1,
    "dedicated period cache retains its grant",
  );
  for (const [name, text] of [
    ["bodytext", "body text"],
    ["headline", "head line"],
    ["purchase", "buy"],
  ]) {
    assert.equal(utf8Decode((await client.openLocal(name)).bytes), text, name);
  }
  assert.equal(decisions.length, 1, "local openings reuse the granted keys");
});
