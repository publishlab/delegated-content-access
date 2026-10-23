// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { chainKeyIssuerEngine } from "../core-issuer/chainKeyIssuerEngine.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";
import {
  contentKeyMap,
  errorMap,
  keyAt,
  notDeliveredMap,
  periodKeyMap,
  setKeyAt,
} from "../../../test-reference/support/namedRecords.js";
import { cutoffsOf } from "./world.js";

const ORIGIN = "https://news.example";
const ISSUER = "subscription_service";
const KID = "sign-1";
const KEY_ID = "open-1";
const GROUP = "premium";
const AT = "2025-10-23T14:20:00Z";

/**
 * One sealed chain-key route and the serialized request a chain-capable client
 * builds for it. `mixed` also seals the item content key beside the chain section.
 */
async function chainRoute({ mixed = false, periodOnly = false, seed = 7, keys } = {}) {
  const signing =
    keys?.signing ??
    /** @type {CryptoKeyPair} */ (
      await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
        "sign",
        "verify",
      ])
    );
  const opening =
    keys?.opening ??
    /** @type {CryptoKeyPair} */ (
      await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
    );
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const sealer = new Sealer({
    origin: ORIGIN,
    clock: new Clock(AT),
    random: new Random({ seed }),
    signingKeys: { [KID]: signing.privateKey },
    periodKeySupply: periodFamilySupply({ families: { [GROUP]: generation }, chainWindows: 2 }),
    issuerSupplyPlanFor: (issuer, render) => ({
      ...wholeRenderIssuerSupplyPlan(issuer, render),
      ...(mixed ? {} : { contentKeyNames: [] }),
      periodKeyDelivery: { [GROUP]: [periodOnly ? "period-keys" : "chain-keys"] },
    }),
    issuers: [
      {
        issuerName: ISSUER,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: opening.publicKey,
      },
    ],
  });
  sealer.resource("article-1", {});
  sealer.content("bodytext", "secret article", "text/plain", { accessGroups: [GROUP] });
  const render = await sealer.seal();
  const page = JSON.parse(
    JSON.stringify({ ...render.dcaData, sealedContent: render.sealedContent }),
  );
  const client = new Client({
    publisherOrigin: ORIGIN,
    cache: new PeriodKeyCache(),
    chainKeyProfile: explicitChainKeyClientProfile,
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
  });
  const dcaData = client.parse(page);
  const request = client.buildRequest(dcaData, ISSUER, ["bodytext"]);
  const document = JSON.stringify(request);
  const registration = {
    kid: KID,
    publicKey: signing.publicKey,
    openingKeys: {
      get: (issuerName, keyId) =>
        issuerName === ISSUER && keyId === KEY_ID
          ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
          : undefined,
    },
  };
  const policy = {
    decide: (_claims, requested) => ({
      contentNames: requested.contentNames,
      periodGrants: requested.accessGroups.map((accessGroup) => ({
        accessGroup,
        futurePeriodCount: 2,
        authorizePeriod: () => true,
      })),
    }),
  };
  return {
    document,
    registration,
    policy,
    page,
    dcaData,
    client,
    request,
    keys: { signing, opening },
  };
}

test("the supported issuer entry processes a selected chain-key route", async () => {
  const { document, registration, policy } = await chainRoute();
  const selected = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: policy,
    clock: new Clock(AT),
  });
  const core = createIssuerCore({
    engine: selected,
    selectedExtensions: selected.selectedExtensions,
    capabilityEncoders: selected.capabilityEncoders,
  });
  const result = await core.endpoint.handleDocument(document, registration, {}, Date.parse(AT));
  assert.equal(result.response.status, 200);
  assert.deepEqual(Object.keys(periodKeyMap(result.response.body.keys.periodKeys)[GROUP]), [
    "251023T1415",
    "251023T1430",
  ]);
  assert.equal(result.response.body.keys.chainKeys, undefined);
});

test("the issuer refuses another render's chain envelope and preserves an honest content sibling", async () => {
  const own = await chainRoute({ mixed: true });
  const other = await chainRoute({ mixed: true, seed: 8, keys: own.keys });
  assert.notEqual(own.page.resource.renderId, other.page.resource.renderId);

  const copiedRequest = structuredClone(own.request);
  const t = cutoffsOf(copiedRequest.sealed.chainKeys, GROUP).sort()[0];
  setKeyAt(
    copiedRequest.sealed.chainKeys,
    { accessGroup: GROUP, cutoff: t },
    keyAt(other.request.sealed.chainKeys, { accessGroup: GROUP, cutoff: t }),
  );

  const engine = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: own.policy,
    clock: new Clock(AT),
    representation: "chain-keys",
  });
  const core = createIssuerCore({
    engine,
    selectedExtensions: engine.selectedExtensions,
    capabilityEncoders: engine.capabilityEncoders,
  });

  const sameRender = await core.endpoint.handleDocument(
    own.document,
    own.registration,
    {},
    Date.parse(AT),
  );
  assert.equal(sameRender.response.status, 200);
  assert.ok(cutoffsOf(sameRender.response.body.keys.chainKeys, GROUP).length > 0);
  await own.client.applyResponse(own.dcaData, ISSUER, sameRender.response.body, own.request);
  assert.equal(
    utf8Decode(
      await own.client.decrypt(own.dcaData, "bodytext", own.client.extract(own.page, "bodytext")),
    ),
    "secret article",
  );

  const copied = await core.endpoint.handleDocument(
    JSON.stringify(copiedRequest),
    own.registration,
    {},
    Date.parse(AT),
  );
  assert.equal(copied.response.status, 200);
  assert.deepEqual(errorMap(copied.response.body.errors)[`${GROUP}|${t}`], {
    error: "unseal_failed",
    message: "sealed value could not be opened",
  });
  assert.deepEqual(
    cutoffsOf(copied.response.body.keys.chainKeys, GROUP),
    [],
    "no chain key answers for the family whose envelope failed",
  );
  assert.deepEqual(Object.keys(contentKeyMap(copied.response.body.keys.contentKeys)), ["bodytext"]);

  const copiedClient = new Client({
    publisherOrigin: ORIGIN,
    chainKeyProfile: explicitChainKeyClientProfile,
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
  });
  const copiedData = copiedClient.parse(own.page);
  await copiedClient.applyResponse(copiedData, ISSUER, copied.response.body, copiedRequest);
  assert.equal(
    utf8Decode(
      await copiedClient.decrypt(
        copiedData,
        "bodytext",
        copiedClient.extract(own.page, "bodytext"),
      ),
    ),
    "secret article",
  );
});

test("an injected chain engine alone composes the processor selections it declares", async () => {
  // Period-key projection: the chain section must count as a coordinate.
  const chainOnly = await chainRoute();
  const projecting = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: chainOnly.policy,
    clock: new Clock(AT),
  });
  const projected = await createIssuerCore({ engine: projecting }).endpoint.handleDocument(
    chainOnly.document,
    chainOnly.registration,
    {},
    Date.parse(AT),
  );
  assert.equal(projected.response.status, 200, JSON.stringify(projected.response.body));
  assert.deepEqual(Object.keys(periodKeyMap(projected.response.body.keys.periodKeys)[GROUP]), [
    "251023T1415",
    "251023T1430",
  ]);

  // Chain-key representation: the result also needs the engine's encoder, and
  // the item content key beside the chain section still reaches the reader.
  const mixed = await chainRoute({ mixed: true });
  const delivering = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: mixed.policy,
    clock: new Clock(AT),
    representation: "chain-keys",
  });
  const delivered = await createIssuerCore({ engine: delivering }).endpoint.handleDocument(
    mixed.document,
    mixed.registration,
    {},
    Date.parse(AT),
  );
  assert.equal(delivered.response.status, 200, JSON.stringify(delivered.response.body));
  assert.ok(keyAt(delivered.response.body.keys.contentKeys, { contentName: "bodytext" }));
  assert.ok(cutoffsOf(delivered.response.body.keys.chainKeys, GROUP).length > 0);
});

test("explicit host selections stay, but one that drops the chain engine's route is refused", async () => {
  const { policy } = await chainRoute();
  const engine = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: policy,
    clock: new Clock(AT),
    representation: "chain-keys",
  });
  const own = () => ({});
  const kept = createIssuerCore({
    engine,
    selectedExtensions: ["chain-keys"],
    capabilityEncoders: { "chain-keys": own },
  });
  assert.ok(kept.processor);
  for (const omitted of [{ selectedExtensions: [] }, { capabilityEncoders: {} }]) {
    assert.throws(
      () => createIssuerCore({ engine, ...omitted }),
      (/** @type {any} */ error) => error.code === "bad_config",
      JSON.stringify(omitted),
    );
  }
  // The period-key projection declares no encoder, so an empty host map fits.
  const projecting = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: policy,
    clock: new Clock(AT),
  });
  assert.ok(createIssuerCore({ engine: projecting, capabilityEncoders: {} }).processor);
});

test("the chain issuer forwards its captured pure version guard to admission", () => {
  const versions = ["2"];
  const engine = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    supportedVersions: versions,
    accessPolicy: {
      decide() {
        throw new Error("policy reached");
      },
    },
  });
  const core = createIssuerCore({ engine });
  versions.push("1");
  const input = {
    version: "2",
    issuerName: ISSUER,
    keyId: KEY_ID,
    sealed: { contentKeys: [{ contentName: "bodytext", key: "blob" }] },
  };
  assert.equal(core.processor.admit(new DcaRequest(input)).kind, "admitted");
  assert.deepEqual(
    core.processor.admit(new DcaRequest({ ...input, version: "1", sealed: { contentKeys: 7 } })),
    { kind: "failure", code: "bad_version" },
  );
});

test("the chain engine forwards notDeliveredReport; default none and invalid-source silence stay", async () => {
  // The request names an old coordinate whose window it supplies no chain
  // member for. Policy authorizes only that coordinate and the item content
  // key, so the content key opens on its own and the family is authorized but
  // unavailable (chain keys guide, "Missing old source").
  const OLD = "251023T0400";
  const route = await chainRoute({ mixed: true });
  const missingOld = JSON.parse(route.document);
  missingOld.requestedPeriodKeys = [{ accessGroup: GROUP, periods: [OLD] }];
  // Two members in one window make the family invalid; that is silence, not a report.
  const invalid = JSON.parse(JSON.stringify(missingOld));
  invalid.sealed.chainKeys.push({
    accessGroup: GROUP,
    cutoff: "251023T2330",
    key: keyAt(invalid.sealed.chainKeys, { accessGroup: GROUP, cutoff: "251023T2345" }),
  });
  const policy = {
    decide: (/** @type {any} */ _claims, /** @type {any} */ requested) => ({
      contentNames: requested.contentNames,
      periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
        accessGroup,
        futurePeriodCount: 0,
        authorizePeriod: (/** @type {string} */ t) => t === OLD,
      })),
    }),
  };
  for (const representation of /** @type {const} */ (["period-keys", "chain-keys"])) {
    /** @param {any} [disclosure] @param {any} document */
    const answer = async (disclosure, document) => {
      const engine = chainKeyIssuerEngine({
        operatingIssuerNames: [ISSUER],
        accessPolicy: policy,
        clock: new Clock(AT),
        representation,
        ...disclosure,
      });
      const result = await createIssuerCore({ engine }).endpoint.handleDocument(
        JSON.stringify(document),
        route.registration,
        {},
        Date.parse(AT),
      );
      assert.equal(
        result.response.status,
        200,
        `${representation} ${JSON.stringify(result.response.body)}`,
      );
      assert.ok(
        keyAt(result.response.body.keys.contentKeys, { contentName: "bodytext" }),
        representation,
      );
      if (document !== missingOld) {
        assert.deepEqual(
          result.response.body.keys.periodKeys ?? [],
          [],
          "invalid family yields no period key",
        );
        assert.deepEqual(
          result.response.body.keys.chainKeys ?? [],
          [],
          "invalid family yields no chain key",
        );
      }
      return result.response.body.notDelivered;
    };
    assert.deepEqual(
      notDeliveredMap(await answer({ notDeliveredReport: "partial" }, missingOld)),
      { [GROUP]: { reason: "unavailable" } },
      representation,
    );
    assert.equal(await answer(undefined, missingOld), undefined, `${representation} default none`);
    for (const [order, document] of [
      ["forward", invalid],
      [
        "reverse",
        {
          ...invalid,
          sealed: {
            ...invalid.sealed,
            chainKeys: [...invalid.sealed.chainKeys].reverse(),
          },
        },
      ],
    ]) {
      assert.equal(
        await answer({ notDeliveredReport: "partial" }, document),
        undefined,
        `${representation} invalid ${order}: no unavailable report can activate conditional fallback`,
      );
    }
  }
  assert.throws(
    () =>
      chainKeyIssuerEngine({
        operatingIssuerNames: [ISSUER],
        accessPolicy: policy,
        notDeliveredReport: /** @type {any} */ ("all"),
      }),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
});

test("an independent chain-horizon grant on a preactivation period-only article has no chain supply", async () => {
  const route = await chainRoute({ mixed: true, periodOnly: true });
  const request = JSON.parse(route.document);
  assert.equal(request.sealed.chainKeys, undefined);
  assert.ok(
    request.sealed.periodKeys.some((/** @type {any} */ record) => record.accessGroup === GROUP),
  );
  const engine = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    clock: new Clock(AT),
    representation: "chain-keys",
    notDeliveredReport: "partial",
    accessPolicy: {
      decide(_claims, requested) {
        return {
          contentNames: requested.contentNames,
          periodGrants: [{ accessGroup: GROUP, futurePeriodCount: 1, authorizePeriod: () => true }],
        };
      },
    },
  });
  const { response } = await createIssuerCore({ engine }).endpoint.handleDocument(
    route.document,
    route.registration,
  );
  assert.equal(response.status, 200);
  assert.ok(
    keyAt(response.body.keys.contentKeys, { contentName: "bodytext" }),
    "the independent item grant survives",
  );
  assert.deepEqual(response.body.keys.chainKeys ?? [], []);
  assert.deepEqual(
    response.body.keys.periodKeys ?? [],
    [],
    "a horizon grant does not turn into an explicit ordinary grant",
  );
  assert.equal(
    response.body.notDelivered,
    undefined,
    "ordinary-only supply cannot establish unavailable for a chain-horizon response",
  );
});
