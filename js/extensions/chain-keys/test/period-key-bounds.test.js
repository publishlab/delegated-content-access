// @ts-check
//
// The two period-key ceilings at their exact edges: 288 period keys for one
// family and 512 across one response, and what happens to the period key after
// each.
//
// Both ceilings clamp rather than refuse, unlike the 2/3 and 16/17 member
// cases in chain-carrier-reader.test.js and sealer-composition.test.js. A
// family asked for 289 period keys is answered with 288, and a family whose
// period keys would begin after the 512th is dropped from the response document
// with no `errors` entry beside it. The cases below assert that behavior as it
// stands; neither ceiling has a refusal to assert and nothing here proposes one.
//
// Elsewhere and not repeated here: the ordinary 288-and-224 composition of the
// two ceilings sits in issuer-explicit-geometry.test.js, and the per-window
// geometry refusal that makes a 289-position window unreachable in the first
// place sits in test-reference/core-shared/geometry-bounds.test.js.

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { DcaRequest, parseDcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
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
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import {
  errorMap,
  notDeliveredMap,
  periodKeyMap,
} from "../../../test-reference/support/namedRecords.js";

const { subtle } = globalThis.crypto;
const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const NAME = "bodytext";
const AT = "2025-10-23T00:00:00Z";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";

/** The only pair that fills a window to the 288-position ceiling: 1440 / 1 / 5. */
const FULL = Object.freeze({ chainsPerDay: 1, periodMinutes: 5 });

/** Three identically provisioned families, in the order the render lists them. */
const GROUPS = Object.freeze(["premium", "archive", "legacy"]);

/** @param {any} answer */
function periodKeysSelected(answer) {
  assert.ok("selected" in answer, "the selection answered with coordinates");
  return answer.selected.reduce(
    (/** @type {number} */ total, /** @type {any} */ entry) => total + entry.targetTs.length,
    0,
  );
}

/** @param {any} answer */
function lastSelected(answer) {
  const members = answer.selected;
  return members[members.length - 1].targetTs.at(-1);
}

/**
 * One family of two supplied window terminals, asked for a future horizon.
 * Selection bounds labels; invocation-time projection accounts for actual
 * candidates and shared response room after envelope opening.
 *
 * @param {number} futurePeriodCount
 */
function selectionFor(futurePeriodCount) {
  const request = new DcaRequest({
    periodGeometry: FULL,
    sealed: {
      chainKeys: [
        { accessGroup: "premium", cutoff: "251023T2355", key: "AQ" },
        { accessGroup: "premium", cutoff: "251024T2355", key: "Ag" },
      ],
    },
  });
  const grant = { accessGroup: "premium", futurePeriodCount, authorizePeriod: () => true };
  const select = chainKeyCapabilitySource().selection(request, { capturedAtMs: Date.parse(AT) }, [
    grant,
  ]);
  return select("premium", futurePeriodCount, grant);
}

/**
 * The three-family publisher render, its registration and the wire-shaped
 * request a relay-only client posts for it.
 */
async function world(chainItemSlots = 1) {
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const families = Object.fromEntries(
    GROUPS.map((group, index) => [
      group,
      periodFamilyGeneration({
        keyDerivationSecret: new Uint8Array(32).fill(7 + index),
        geometry: FULL,
      }),
    ]),
  );
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: periodFamilySupply({ families, chainWindows: 2, chainItemSlots }),
    issuerSupplyPlanFor: (issuer, render) => ({
      ...wholeRenderIssuerSupplyPlan(issuer, render),
      periodKeyDelivery: Object.fromEntries(GROUPS.map((group) => [group, ["chain-keys"]])),
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
  sealer.content(NAME, ARTICLE, "text/html", { accessGroups: [...GROUPS] });
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
    requestBuilderFactory: (/** @type {object} */ options) => new ChainKeyRequestBuilder(options),
  });
  const request = parseDcaRequest(
    JSON.stringify(client.buildRequest(client.parse(page), ISSUER, [NAME])),
  );
  return { registration, request };
}

test("one family asked for 289 period keys is answered with 288, and one asked for 287 with 287", () => {
  assert.equal(
    periodKeysSelected(selectionFor(287)),
    287,
    "below the ceiling the ask is what arrives",
  );
  assert.equal(
    periodKeysSelected(selectionFor(288)),
    288,
    "at the ceiling the ask is what arrives",
  );
  assert.equal(
    periodKeysSelected(selectionFor(289)),
    288,
    "the 289th period key of one family is clamped away",
  );
  assert.equal(
    periodKeysSelected(selectionFor(1000)),
    288,
    "and every larger ask lands on the same 288",
  );

  assert.equal(
    lastSelected(selectionFor(288)),
    "251023T2355",
    "the 288th period key is the window terminal",
  );
  assert.equal(
    lastSelected(selectionFor(289)),
    "251023T2355",
    "and the clamped ask stops on that same terminal rather than reaching the next supplied window",
  );
});

test("an admitted family missing authorized current supply reports unavailable", () => {
  const source = chainKeyCapabilitySource();
  const grant = { accessGroup: "premium", futurePeriodCount: 1, authorizePeriod: () => true };
  const currentMiss = source.selection(
    new DcaRequest({
      periodGeometry: FULL,
      sealed: { chainKeys: [{ accessGroup: "premium", cutoff: "251024T2355", key: "AQ" }] },
    }),
    { capturedAtMs: Date.parse(AT) },
    [grant],
  );
  assert.deepEqual(currentMiss("premium", 1, grant), { unavailable: "unavailable" });

  const invalidMember = source.selection(
    new DcaRequest({
      periodGeometry: FULL,
      sealed: {
        chainKeys: [{ accessGroup: "premium", cutoff: "251023T2355", key: { malformed: true } }],
      },
    }),
    { capturedAtMs: Date.parse(AT) },
    [grant],
  );
  // A malformed value is not missing supply. Its member still serves the
  // authorized current period, and the opening step answers that supplied
  // coordinate with unseal_failed (authorized-malformed-chain-member.test.js).
  assert.deepEqual(invalidMember("premium", 1, grant), {
    selected: [
      {
        t: "251023T2355",
        chainKey: true,
        chainsPerDay: FULL.chainsPerDay,
        periodMinutes: FULL.periodMinutes,
        targetTs: ["251023T0000"],
        articleTs: [],
        futureTs: ["251023T0000"],
      },
    ],
  });
});

test("all sourceable future selections reach actual candidate accounting", () => {
  const source = chainKeyCapabilitySource();
  const grants = ["premium", "archive", "legacy"].map((accessGroup) => ({
    accessGroup,
    futurePeriodCount: 600,
    authorizePeriod: () => true,
  }));
  const select = source.selection(
    new DcaRequest({
      periodGeometry: FULL,
      sealed: {
        chainKeys: [
          { accessGroup: "premium", cutoff: "251023T2355", key: "AQ" },
          { accessGroup: "premium", cutoff: "251024T2355", key: "Ag" },
          { accessGroup: "archive", cutoff: "251023T2355", key: "Aw" },
          { accessGroup: "archive", cutoff: "251024T2355", key: "BA" },
          { accessGroup: "legacy", cutoff: "251023T2355", key: "BQ" },
          { accessGroup: "legacy", cutoff: "251024T2355", key: "Bg" },
        ],
      },
    }),
    { capturedAtMs: Date.parse(AT) },
    grants,
  );
  assert.ok("selected" in select("archive", 600, grants[1]));
  assert.ok("selected" in select("legacy", 600, grants[2]));
  assert.ok("selected" in select("premium", 600, grants[0]));
});

test("article targets have priority and future output uses alphabetical remaining capacity", async () => {
  const { registration, request } = await world(2);
  const engine = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy: {
      decide: (/** @type {any} */ unusedClaims, /** @type {any} */ requested) => ({
        contentNames: [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
          accessGroup,
          futurePeriodCount: 600,
          authorizePeriod: () => true,
        })),
      }),
    },
    clock: new Clock(AT),
  });
  const endpoint = new UnlockEndpoint(
    new IssuerProcessor(engine, {
      capabilityEncoders: engine.capabilityEncoders,
      selectedExtensions: engine.selectedExtensions,
    }),
  );

  const answer = await endpoint.handleRequest({
    request,
    registration,
    capturedAtMs: Date.parse(AT),
  });

  assert.equal(answer.response.status, 200, "three families asking 600 period keys each is a 200");
  const periodKeys = periodKeyMap(answer.response.body.keys.periodKeys);
  const requested = request.toObject().requestedPeriodKeys;
  assert.deepEqual(Object.keys(periodKeys).sort(), ["archive", "legacy", "premium"]);
  for (const { accessGroup, periods } of requested) {
    for (const t of periods) {
      assert.equal(
        Object.hasOwn(periodKeys[accessGroup], t),
        true,
        `${accessGroup}|${t}: every explicit article target precedes future output`,
      );
    }
  }
  assert.equal(
    Object.keys(periodKeys.archive).length,
    288,
    "alphabetically first fills its family",
  );
  assert.equal(Object.keys(periodKeys.legacy).length, 222, "next group consumes remaining room");
  assert.equal(Object.keys(periodKeys.premium).length, 2, "last group retains its article targets");
  assert.equal(
    Object.values(periodKeys).reduce(
      (/** @type {number} */ total, /** @type {any} */ family) =>
        total + Object.keys(family).length,
      0,
    ),
    512,
    "all 512 response slots are used after article-target priority is satisfied",
  );
  assert.equal(
    answer.response.body.errors,
    undefined,
    "capacity omission does not add an errors member",
  );
});

test("unavailable distinguishes authorized missing article supply from denial and form incompatibility", () => {
  const request = new DcaRequest({
    periodGeometry: FULL,
    requestedPeriodKeys: [{ accessGroup: "premium", periods: ["251022T0000"] }],
    sealed: { chainKeys: [{ accessGroup: "premium", cutoff: "251024T2355", key: "AQ" }] },
  });
  for (const permitted of [true, false]) {
    const grant = {
      accessGroup: "premium",
      futurePeriodCount: 0,
      authorizePeriod: () => permitted,
    };
    const select = chainKeyCapabilitySource().selection(request, { capturedAtMs: Date.parse(AT) }, [
      grant,
    ]);
    assert.deepEqual(select("premium", 0, grant), {
      unavailable: permitted ? "unavailable" : "denied",
    });
  }
  const incompatible = new DcaRequest({
    periodGeometry: FULL,
    requestedPeriodKeys: [{ accessGroup: "premium", periods: ["251023T0010"] }],
    sealed: { chainKeys: [{ accessGroup: "premium", cutoff: "251023T2355", key: "Ag" }] },
  });
  const grant = {
    accessGroup: "premium",
    futurePeriodCount: 0,
    authorizePeriod: (t) => t === "251023T0010",
  };
  const select = chainKeyCapabilitySource({ representation: "chain-keys" }).selection(
    incompatible,
    { capturedAtMs: Date.parse(AT) },
    [grant],
  );
  assert.deepEqual(
    select("premium", 0, grant),
    { unavailable: true },
    "a forbidden prefix is not missing supply",
  );
});

test("issuer reports future-only unavailable without article hints and independently denies policy", async () => {
  const { registration, request } = await world();
  const document = request.toObject();
  delete document.requestedPeriodKeys;
  document.sealed = { chainKeys: [{ accessGroup: "premium", cutoff: "251022T2355", key: "AQ" }] };
  for (const permitted of [true, false]) {
    const engine = new IssuerEngine({
      operatingIssuerNames: [ISSUER],
      notDeliveredReport: "complete",
      periodCapabilitySource: chainKeyCapabilitySource(),
      accessPolicy: {
        decide: () => ({
          contentNames: [],
          periodGrants: [
            { accessGroup: "premium", futurePeriodCount: 1, authorizePeriod: () => permitted },
          ],
        }),
      },
    });
    const result = await engine.unlock(
      new DcaRequest(document),
      registration,
      {},
      { capturedAtMs: Date.parse(AT) },
    );
    assert.deepEqual(notDeliveredMap(result.notDelivered), {
      premium: { reason: permitted ? "unavailable" : "denied" },
    });
    assert.deepEqual(result.periodKeys, []);
    assert.deepEqual(result.errors, []);
  }
});

test("issuer reports older authorized missing supply but leaves opening failure as a coordinate error", async () => {
  const { registration, request } = await world();
  for (const target of ["251022T0000", "251024T0000"]) {
    const document = request.toObject();
    document.requestedPeriodKeys = [{ accessGroup: "premium", periods: [target] }];
    document.sealed = { chainKeys: [{ accessGroup: "premium", cutoff: "251024T2355", key: "Ag" }] };
    const engine = new IssuerEngine({
      operatingIssuerNames: [ISSUER],
      notDeliveredReport: "complete",
      periodCapabilitySource: chainKeyCapabilitySource(),
      accessPolicy: {
        decide: () => ({
          contentNames: [],
          periodGrants: [
            { accessGroup: "premium", futurePeriodCount: 0, authorizePeriod: () => true },
          ],
        }),
      },
    });
    const result = await engine.unlock(
      new DcaRequest(document),
      registration,
      {},
      { capturedAtMs: Date.parse(AT) },
    );
    if (target === "251022T0000") {
      assert.deepEqual(notDeliveredMap(result.notDelivered), {
        premium: { reason: "unavailable" },
      });
      assert.deepEqual(result.errors, []);
    } else {
      assert.deepEqual(result.notDelivered, []);
      assert.equal(errorMap(result.errors)["premium|251024T2355"].error, "unseal_failed");
    }
    assert.deepEqual(result.periodKeys, []);
  }
});
