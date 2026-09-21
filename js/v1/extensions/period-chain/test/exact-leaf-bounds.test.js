// @ts-check
//
// The two exact-leaf ceilings at their exact edges: 288 leaves for one family
// and 512 across one response, and what happens to the leaf after each.
//
// Both ceilings clamp rather than refuse, unlike the 2/3 and 16/17 member
// cases in chain-carrier-reader.test.js and sealer-composition.test.js. A
// family asked for 289 leaves is answered with 288, and a family whose leaves
// would begin after the 512th is dropped from the response document with no
// `errors` entry beside it. The cases below
// assert that behavior as it stands; neither ceiling has a refusal to assert
// and nothing here proposes one.
//
// Elsewhere and not repeated here: the ordinary 288-and-224 composition of the
// two ceilings sits in issuer-explicit-geometry.test.js, and the per-window
// geometry refusal that makes a 289-position window unreachable in the first
// place sits in test-reference/core-shared/geometry-bounds.test.js.

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
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
import { PeriodChainRequestBuilder } from "../core-client/PeriodChainRequestBuilder.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { periodChainIssuerEngine } from "../core-issuer/periodChainIssuerEngine.js";
import { periodChainCapabilitySource } from "../core-issuer/periodChainCapabilitySource.js";

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
function leavesSelected(answer) {
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
 * One family of two supplied window terminals, asked for `periodCount` leaves.
 * A fresh source each time, because one `selection` accumulates the response
 * room it has already spent.
 *
 * @param {number} periodCount
 */
function selectionFor(periodCount) {
  const request = new DcaRequest({
    periodChain: FULL,
    sealed: { periodChainKeys: { premium: { "251023T2355": "a", "251024T2355": "b" } } },
  });
  const select = periodChainCapabilitySource().selection(request, { capturedAtMs: Date.parse(AT) });
  return select("premium", periodCount);
}

/**
 * The three-family publisher render, its registration and the wire-shaped
 * request a relay-only client posts for it.
 */
async function world() {
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
    periodKeySupply: periodFamilySupply({ families, chainWindows: 2 }),
    issuerSupplyPlanFor: () => ({
      periodKeyDelivery: Object.fromEntries(GROUPS.map((group) => [group, ["chain"]])),
    }),
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
    requestBuilderFactory: (/** @type {object} */ options) =>
      new PeriodChainRequestBuilder(options),
  });
  const request = parseDcaRequest(
    JSON.stringify(client.buildRequest(client.parse(page), ISSUER, [NAME])),
  );
  return { registration, request };
}

test("one family asked for 289 exact leaves is answered with 288, and one asked for 287 with 287", () => {
  assert.equal(leavesSelected(selectionFor(287)), 287, "below the ceiling the ask is what arrives");
  assert.equal(leavesSelected(selectionFor(288)), 288, "at the ceiling the ask is what arrives");
  assert.equal(
    leavesSelected(selectionFor(289)),
    288,
    "the 289th leaf of one family is clamped away",
  );
  assert.equal(
    leavesSelected(selectionFor(1000)),
    288,
    "and every larger ask lands on the same 288",
  );

  assert.equal(
    lastSelected(selectionFor(288)),
    "251023T2355",
    "the 288th leaf is the window terminal",
  );
  assert.equal(
    lastSelected(selectionFor(289)),
    "251023T2355",
    "and the clamped ask stops on that same terminal rather than reaching the next supplied window",
  );
});

test("the 513th exact leaf of one response is omitted with its family, and no errors entry accompanies it", async () => {
  const { registration, request } = await world();
  const engine = periodChainIssuerEngine({
    accessPolicy: {
      decide: (/** @type {any} */ unusedClaims, /** @type {any} */ requested) => ({
        contentNames: [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
          accessGroup,
          periodCount: 600,
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

  assert.equal(answer.response.status, 200, "three families asking 600 leaves each is a 200");
  const periodKeys = answer.response.body.keys.periodKeys;
  assert.deepEqual(
    Object.keys(periodKeys),
    ["premium", "archive"],
    "the third family is simply not in the document",
  );
  assert.equal(
    Object.keys(periodKeys.premium).length,
    288,
    "the first family fills its own ceiling",
  );
  assert.equal(
    Object.keys(periodKeys.archive).length,
    224,
    "the second takes the room that is left",
  );
  assert.equal(
    Object.values(periodKeys).reduce(
      (/** @type {number} */ total, /** @type {any} */ family) =>
        total + Object.keys(family).length,
      0,
    ),
    512,
    "the 512th leaf arrives and the 513th does not",
  );
  assert.equal(
    answer.response.body.errors,
    undefined,
    "and the omitted family reports nothing: the response carries no errors member at all",
  );
});
