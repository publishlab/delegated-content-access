// @ts-check
//
// A supplied chain member whose label is canonical and on its family's grid,
// but whose sealed value is not a canonical binary string, still names the
// coordinate `accessGroup|suppliedT`. Core Section 7.1 gives that entry
// `unseal_failed` once the request and the coordinate are authorized, and
// forbids decoding or opening it. The cases below hold the malformed value
// beside the control every other unopenable value gets, a canonical string
// that does not open, and check that:
//
// - an authorized target served by the malformed member reports
//   `unseal_failed` at the supplied coordinate, not a family-level
//   `notDelivered`;
// - the source never hands the malformed value to the opener;
// - valid members, sibling families and the base content section keep their
//   answers;
// - a denied target never reaches the value, so a bad value and a good one
//   answer the same;
// - an off-grid supplied label and an off-grid desired hint keep their own
//   scopes, and a family whose only member is malformed stays an admitted
//   family rather than becoming invalid.

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
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
import { chainKeyCapabilitySource } from "../core-issuer/chainKeyCapabilitySource.js";
import { chainKeyRequestInput } from "../core-issuer/chainKeyRequestInput.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;
const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const NAME = "bodytext";
const AT = "2025-10-23T00:00:00Z";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";

/** One window per day of 5-minute periods; the sealer supplies 251023T2355 and 251024T2355. */
const FULL = Object.freeze({ chainsPerDay: 1, periodMinutes: 5 });
const GROUPS = Object.freeze(["premium", "archive"]);

/** The control: canonical binary-string spelling whose bytes do not open. */
const CANONICAL_UNOPENABLE = "Ag";

/** Values the carrier reader refuses as a sealed entry, each with its reason. */
const MALFORMED = Object.freeze([
  ["noncanonical padded spelling", "Ag=="],
  ["nonzero unused bits", "Ah"],
  ["non-string object", { malformed: true }],
  ["number", 7],
  ["null", null],
]);

/**
 * A two-family render sealed for one issuer with chain-key supply only, its
 * registration, and the request a relay-only client posts for it.
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
    issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) => ({
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
  return { registration, document: request.toObject() };
}

/** @type {Promise<{ registration: any, document: any }>|null} */
let shared = null;

/** One sealed render serves every case; each case edits a deep copy of its request. */
async function sharedWorld() {
  shared ??= world();
  const { registration, document } = await shared;
  return { registration, document: structuredClone(document) };
}

/**
 * Unlock one edited request under a policy that grants `contentNames` and an
 * independent period authorizer for each listed family.
 *
 * @param {object} options
 * @param {(document: any) => void} options.edit
 * @param {string[]} [options.contentNames]
 * @param {Record<string, (t: string) => boolean>} options.authorize
 * @param {number} [options.futurePeriodCount]
 */
async function unlockEdited({ edit, contentNames = [], authorize, futurePeriodCount = 0 }) {
  const { registration, document } = await sharedWorld();
  edit(document);
  const engine = new IssuerEngine({
    operatingIssuerNames: [ISSUER],
    notDeliveredReport: "complete",
    periodCapabilitySource: chainKeyCapabilitySource(),
    accessPolicy: {
      decide: () => ({
        contentNames,
        periodGrants: Object.entries(authorize).map(([accessGroup, authorizePeriod]) => ({
          accessGroup,
          futurePeriodCount,
          authorizePeriod,
        })),
      }),
    },
  });
  return engine.unlock(
    new DcaRequest(document),
    registration,
    {},
    { capturedAtMs: Date.parse(AT) },
  );
}

/** @param {any} result */
function reported(result) {
  return {
    periodKeys: result.periodKeys,
    errors: result.errors,
    notDelivered: result.notDelivered,
  };
}

/** @param {any} errors */
function errorCodes(errors) {
  return Object.fromEntries(
    Object.entries(errors).map(([coordinate, entry]) => [coordinate, entry.error]),
  );
}

for (const [name, value] of [
  ["control, canonical but unopenable", CANONICAL_UNOPENABLE],
  ...MALFORMED,
]) {
  test(`an authorized chain member with a ${name} value reports unseal_failed at its supplied coordinate`, async () => {
    const result = await unlockEdited({
      edit(document) {
        document.requestedPeriodKeys = { premium: ["251024T0000"] };
        document.sealed.chainKeys = { premium: { "251024T2355": value } };
      },
      authorize: { premium: () => true },
    });
    assert.deepEqual(result.periodKeys, {});
    assert.deepEqual(
      result.notDelivered,
      {},
      "a supplied member is no family-level unavailability",
    );
    assert.deepEqual(errorCodes(result.errors), { "premium|251024T2355": "unseal_failed" });
  });
}

test("an authorized malformed member on the future horizon reports unseal_failed too", async () => {
  const result = await unlockEdited({
    edit(document) {
      document.sealed.chainKeys = { premium: { "251023T2355": { malformed: true } } };
    },
    authorize: { premium: () => true },
    futurePeriodCount: 1,
  });
  assert.deepEqual(result.periodKeys, {});
  assert.deepEqual(result.notDelivered, {});
  assert.deepEqual(errorCodes(result.errors), { "premium|251023T2355": "unseal_failed" });
});

test("valid members, a sibling family and the content key keep their answers beside a malformed member", async () => {
  const result = await unlockEdited({
    edit(document) {
      assert.equal(
        typeof document.sealed.contentKeys?.[NAME],
        "string",
        "the render seals the content key",
      );
      document.sealed.chainKeys.premium["251024T2355"] = "Ag==";
      document.requestedPeriodKeys = {
        premium: ["251023T0000", "251024T0000"],
        archive: ["251024T0000"],
      };
    },
    contentNames: [NAME],
    authorize: { premium: () => true, archive: () => true },
  });
  assert.equal(typeof result.contentKeys[NAME], "string", "the base content section is answered");
  assert.deepEqual(Object.keys(result.periodKeys.premium), ["251023T0000"]);
  assert.deepEqual(Object.keys(result.periodKeys.archive), ["251024T0000"]);
  assert.deepEqual(errorCodes(result.errors), { "premium|251024T2355": "unseal_failed" });
  assert.deepEqual(result.notDelivered, {});
});

test("a denied target never reaches the value: a malformed member answers like a canonical one", async () => {
  /** @param {unknown} value */
  const deniedWith = (value) =>
    unlockEdited({
      edit(document) {
        document.sealed.chainKeys = { premium: { "251024T2355": value } };
        document.requestedPeriodKeys = { premium: ["251024T0000"] };
      },
      authorize: { premium: (t) => !t.startsWith("251024") },
    });
  const canonical = reported(await deniedWith(CANONICAL_UNOPENABLE));
  assert.deepEqual(canonical.errors, {});
  assert.deepEqual(canonical.notDelivered, { premium: { reason: "denied" } });
  for (const [, value] of MALFORMED) {
    assert.deepEqual(reported(await deniedWith(value)), canonical);
  }
});

test("an off-grid supplied label keeps its member-skip scope whatever its value", async () => {
  const result = await unlockEdited({
    edit(document) {
      document.sealed.chainKeys = { premium: { "251024T2357": { malformed: true } } };
      document.requestedPeriodKeys = { premium: ["251024T0000"] };
    },
    authorize: { premium: () => true },
  });
  assert.deepEqual(result.errors, {}, "an off-grid label names no supplied coordinate");
  assert.deepEqual(result.notDelivered, {}, "rejected labels establish no valid supply");
});

test("a family whose only member is malformed stays admitted, so an off-grid hint fails the whole request", async () => {
  const request = new DcaRequest({
    periodGeometry: FULL,
    sealed: { chainKeys: { premium: { "251024T2355": "Ag==" } } },
  });
  const family = chainKeyRequestInput(request).family("premium");
  assert.equal(family.kind, "valid", "filtering a malformed member does not invalidate its family");
  assert.deepEqual(family.members, []);
  assert.deepEqual(
    family.malformedMembers.map((/** @type {any} */ member) => member.t),
    ["251024T2355"],
  );
  assert.ok(
    family.malformedMembers.every((/** @type {any} */ member) => !Object.hasOwn(member, "sealed")),
    "the reader carries no malformed value onward",
  );

  await assert.rejects(
    unlockEdited({
      edit(document) {
        document.sealed.chainKeys = { premium: { "251024T2355": "Ag==" } };
        document.requestedPeriodKeys = { premium: ["251024T0001"] };
      },
      authorize: { premium: () => true },
    }),
    (/** @type {any} */ error) => error.code === "binding_failed",
  );
});

/**
 * The source alone, with an opener that records what it is handed and answers
 * 16 bytes for anything.
 *
 * @param {'period-keys'|'chain-keys'} representation
 * @param {Record<string, unknown>} premium
 * @param {string[]} hints
 */
async function representedBySource(representation, premium, hints) {
  const request = new DcaRequest({
    periodGeometry: FULL,
    sealed: { chainKeys: { premium } },
    requestedPeriodKeys: { premium: hints },
  });
  const source = chainKeyCapabilitySource({ representation });
  const grant = { accessGroup: "premium", futurePeriodCount: 0, authorizePeriod: () => true };
  const answer = source.selection(request, { capturedAtMs: Date.parse(AT) }, [grant])(
    "premium",
    0,
    grant,
  );
  assert.ok("selected" in answer, JSON.stringify(answer));
  /** @type {{ sealed: unknown, suppliedT: unknown }[]} */
  const opened = [];
  const represent = source.capabilities(
    {
      request,
      open: async (sealed, coordinate) => {
        opened.push({ sealed, suppliedT: /** @type {any} */ (coordinate).suppliedT });
        return { bytes: new Uint8Array(16).fill(9) };
      },
    },
    { capturedAtMs: Date.parse(AT) },
  );
  const represented = await represent("premium", answer.selected);
  return { selected: answer.selected, represented, opened };
}

for (const representation of /** @type {const} */ (["period-keys", "chain-keys"])) {
  test(`${representation}: the source answers a malformed member without handing its value to the opener`, async () => {
    const { represented, opened } = await representedBySource(
      representation,
      { "251023T2355": "AQ", "251024T2355": "Ag==" },
      ["251023T0000", "251024T0000"],
    );
    assert.deepEqual(opened, [{ sealed: "AQ", suppliedT: "251023T2355" }]);
    const failed = represented.periods.filter((period) => "error" in period);
    assert.deepEqual(
      failed.map((period) => [period.t, /** @type {any} */ (period).error.error]),
      [["251024T2355", "unseal_failed"]],
    );
    assert.ok(
      represented.periods.some((period) => "bytes" in period),
      "the valid member is still represented",
    );
  });
}

test("two positioned members in one window void the family before opening either value", () => {
  const request = new DcaRequest({
    periodGeometry: FULL,
    sealed: { chainKeys: { premium: { "251024T1200": "AQ", "251024T2355": { malformed: true } } } },
    requestedPeriodKeys: { premium: ["251024T0000", "251024T1300"] },
  });
  const grant = { accessGroup: "premium", futurePeriodCount: 0, authorizePeriod: () => true };
  const source = chainKeyCapabilitySource({ representation: "period-keys" });
  const answer = source.selection(request, { capturedAtMs: Date.parse(AT) }, [grant])(
    "premium",
    0,
    grant,
  );
  assert.deepEqual(answer, { unavailable: true });
});
