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

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";
import { chainKeyCapabilityEncoderFor } from "../core-issuer/chainKeyCapabilityEncoder.js";
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
import {
  errorMap,
  keyAt,
  periodKeyMap,
  setKeyAt,
} from "../../../test-reference/support/namedRecords.js";
import { chainKeyRecords } from "./world.js";

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
  return { registration, document: request.toObject(), page };
}

/** @type {Promise<{ registration: any, document: any, page: any }>|null} */
let shared = null;

/** One sealed render serves every case; each case edits a deep copy of its request. */
async function sharedWorld() {
  shared ??= world();
  const { registration, document, page } = await shared;
  return { registration, document: structuredClone(document), page };
}

/**
 * Unlock one edited request under a policy that grants `contentNames` and an
 * independent period authorizer for each listed family.
 *
 * @param {object} options
 * @param {(document: any) => void} options.edit
 * @param {string[]} [options.contentNames]
 * @param {Record<string, (t: string) => boolean>} options.authorize
 * @param {'period-keys'|'chain-keys'} [options.representation]
 * @param {(context: any) => void} [options.capture]
 * @param {number} [options.futurePeriodCount]
 */
async function unlockEdited({
  edit,
  contentNames = [],
  authorize,
  futurePeriodCount = 0,
  representation = "period-keys",
  capture,
}) {
  const { registration, document, page } = await sharedWorld();
  edit(document);
  capture?.({ document, page });
  const engine = new IssuerEngine({
    operatingIssuerNames: [ISSUER],
    notDeliveredReport: "complete",
    periodCapabilitySource: chainKeyCapabilitySource({ representation }),
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
    Object.entries(errorMap(errors)).map(([coordinate, entry]) => [coordinate, entry.error]),
  );
}

for (const [name, value] of [
  ["control, canonical but unopenable", CANONICAL_UNOPENABLE],
  ...MALFORMED,
]) {
  test(`an authorized chain member with a ${name} value reports unseal_failed at its supplied coordinate`, async () => {
    const result = await unlockEdited({
      edit(document) {
        document.requestedPeriodKeys = [{ accessGroup: "premium", periods: ["251024T0000"] }];
        document.sealed.chainKeys = chainKeyRecords({ premium: { "251024T2355": value } });
      },
      authorize: { premium: () => true },
    });
    assert.deepEqual(result.periodKeys, []);
    assert.deepEqual(
      result.notDelivered,
      [],
      "a supplied member is no family-level unavailability",
    );
    assert.deepEqual(errorCodes(result.errors), { "premium|251024T2355": "unseal_failed" });
  });
}

test("an authorized malformed member on the future horizon reports unseal_failed too", async () => {
  const result = await unlockEdited({
    edit(document) {
      document.sealed.chainKeys = chainKeyRecords({
        premium: { "251023T2355": { malformed: true } },
      });
    },
    authorize: { premium: () => true },
    futurePeriodCount: 1,
  });
  assert.deepEqual(result.periodKeys, []);
  assert.deepEqual(result.notDelivered, []);
  assert.deepEqual(errorCodes(result.errors), { "premium|251023T2355": "unseal_failed" });
});

test("valid members, a sibling family and the content key keep their answers beside a malformed member", async () => {
  const result = await unlockEdited({
    edit(document) {
      assert.equal(
        typeof keyAt(document.sealed.contentKeys, { contentName: NAME }),
        "string",
        "the render seals the content key",
      );
      setKeyAt(
        document.sealed.chainKeys,
        { accessGroup: "premium", cutoff: "251024T2355" },
        "Ag==",
      );
      document.requestedPeriodKeys = [
        { accessGroup: "premium", periods: ["251023T0000", "251024T0000"] },
        { accessGroup: "archive", periods: ["251024T0000"] },
      ];
    },
    contentNames: [NAME],
    authorize: { premium: () => true, archive: () => true },
  });
  assert.equal(
    typeof keyAt(result.contentKeys, { contentName: NAME }),
    "string",
    "the base content section is answered",
  );
  assert.deepEqual(Object.keys(periodKeyMap(result.periodKeys).premium), ["251023T0000"]);
  assert.deepEqual(Object.keys(periodKeyMap(result.periodKeys).archive), ["251024T0000"]);
  assert.deepEqual(errorCodes(result.errors), { "premium|251024T2355": "unseal_failed" });
  assert.deepEqual(result.notDelivered, []);
});

test("a denied target never reaches the value: a malformed member answers like a canonical one", async () => {
  /** @param {unknown} value */
  const deniedWith = (value) =>
    unlockEdited({
      edit(document) {
        document.sealed.chainKeys = chainKeyRecords({ premium: { "251024T2355": value } });
        document.requestedPeriodKeys = [{ accessGroup: "premium", periods: ["251024T0000"] }];
      },
      authorize: { premium: (t) => !t.startsWith("251024") },
    });
  const canonical = reported(await deniedWith(CANONICAL_UNOPENABLE));
  assert.deepEqual(canonical.errors, []);
  assert.deepEqual(canonical.notDelivered, [{ accessGroup: "premium", reason: "denied" }]);
  for (const [, value] of MALFORMED) {
    assert.deepEqual(reported(await deniedWith(value)), canonical);
  }
});

test("an off-grid supplied label keeps its member-skip scope whatever its value", async () => {
  const result = await unlockEdited({
    edit(document) {
      document.sealed.chainKeys = chainKeyRecords({
        premium: { "251024T2357": { malformed: true } },
      });
      document.requestedPeriodKeys = [{ accessGroup: "premium", periods: ["251024T0000"] }];
    },
    authorize: { premium: () => true },
  });
  assert.deepEqual(result.errors, [], "an off-grid label names no supplied coordinate");
  assert.deepEqual(result.notDelivered, [], "rejected labels establish no valid supply");
});

test("a family whose only member is malformed stays admitted, so an off-grid hint fails the whole request", async () => {
  const request = new DcaRequest({
    periodGeometry: FULL,
    sealed: { chainKeys: [{ accessGroup: "premium", cutoff: "251024T2355", key: "Ag==" }] },
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
        document.sealed.chainKeys = chainKeyRecords({ premium: { "251024T2355": "Ag==" } });
        document.requestedPeriodKeys = [{ accessGroup: "premium", periods: ["251024T0001"] }];
      },
      authorize: { premium: () => true },
    }),
    (/** @type {any} */ error) => error.code === "binding_failed",
  );
});

/**
 * Rival records at one cutoff: the render's own envelope for premium at
 * 251024T2355 and a wrong but admissible one, the render's envelope for
 * 251023T2355, which is canonical and opens under no BIND at the later cutoff.
 * Both are candidate members, so the issuer opens each and answers from the
 * one that opens.
 *
 * @param {(working: string, wrong: string) => string[]} candidates
 */
function rivalsAtOneCutoff(candidates) {
  return unlockEdited({
    edit(document) {
      const working = keyAt(document.sealed.chainKeys, {
        accessGroup: "premium",
        cutoff: "251024T2355",
      });
      const wrong = keyAt(document.sealed.chainKeys, {
        accessGroup: "premium",
        cutoff: "251023T2355",
      });
      document.sealed.chainKeys = candidates(working, wrong).map((key) => ({
        accessGroup: "premium",
        cutoff: "251024T2355",
        key,
      }));
      document.requestedPeriodKeys = [{ accessGroup: "premium", periods: ["251024T0000"] }];
    },
    authorize: { premium: () => true },
  });
}

for (const [order, candidates] of /** @type {const} */ ([
  ["wrong first", (/** @type {string} */ working, /** @type {string} */ wrong) => [wrong, working]],
  [
    "working first",
    (/** @type {string} */ working, /** @type {string} */ wrong) => [working, wrong],
  ],
])) {
  test(`a working candidate beside a wrong rival at one cutoff answers with no error, ${order}`, async () => {
    const alone = await rivalsAtOneCutoff((working) => [working]);
    const result = await rivalsAtOneCutoff(candidates);
    assert.deepEqual(Object.keys(periodKeyMap(result.periodKeys).premium), ["251024T0000"]);
    assert.deepEqual(result.periodKeys, alone.periodKeys, "the working candidate's key answers");
    assert.deepEqual(result.errors, [], "a failed rival is no error while another opened");
    assert.deepEqual(result.notDelivered, []);
  });
}

test("a cutoff where every rival candidate fails reports one unseal_failed entry", async () => {
  const result = await rivalsAtOneCutoff((_working, wrong) => [wrong, CANONICAL_UNOPENABLE]);
  assert.deepEqual(result.periodKeys, []);
  assert.equal(result.errors.length, 1, "one entry for the cutoff, not one per candidate");
  assert.deepEqual(errorCodes(result.errors), { "premium|251024T2355": "unseal_failed" });
  assert.deepEqual(result.notDelivered, []);
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
    sealed: { chainKeys: chainKeyRecords({ premium }) },
    requestedPeriodKeys: [{ accessGroup: "premium", periods: hints }],
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
      periodKeyCount: 0,
      selectedCapabilities: [{ accessGroup: "premium", selected: answer.selected }],
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
    sealed: {
      chainKeys: [
        { accessGroup: "premium", cutoff: "251024T1200", key: "AQ" },
        { accessGroup: "premium", cutoff: "251024T2355", key: { malformed: true } },
      ],
    },
    requestedPeriodKeys: [{ accessGroup: "premium", periods: ["251024T0000", "251024T1300"] }],
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

/**
 * Two twelve-hour windows, with an independently controlled opening result.
 * This exercises source selection and production without trusting an envelope
 * failure to stand in for the family's valid-supply classification.
 * @param {'period-keys'|'chain-keys'} representation
 * @param {{ first?: string, hints?: string[], now?: string, future?: number,
 *   authorize?: (t: string) => boolean, rival?: boolean, second?: boolean }} [options]
 */
async function horizonSource(
  representation,
  {
    first = "AQ",
    hints = [],
    now = "2025-10-14T10:00:00Z",
    future = 5,
    authorize = () => true,
    rival = false,
    second = true,
  } = {},
) {
  const request = new DcaRequest({
    periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
    sealed: {
      chainKeys: [
        { accessGroup: "premium", cutoff: "251014T1100", key: first },
        ...(rival ? [{ accessGroup: "premium", cutoff: "251014T1100", key: "Aw" }] : []),
        ...(second ? [{ accessGroup: "premium", cutoff: "251014T2300", key: "Ag" }] : []),
      ],
    },
    requestedPeriodKeys: hints.length ? [{ accessGroup: "premium", periods: hints }] : undefined,
  });
  const source = chainKeyCapabilitySource({ representation });
  const grant = { accessGroup: "premium", futurePeriodCount: future, authorizePeriod: authorize };
  const invocation = { capturedAtMs: Date.parse(now) };
  const answer = source.selection(request, invocation, [grant])("premium", 0, grant);
  if (!("selected" in answer)) return { answer, periods: [], opened: [] };
  const opened = [];
  const produce = source.capabilities(
    {
      request,
      periodKeyCount: 0,
      selectedCapabilities: [{ accessGroup: "premium", selected: answer.selected }],
      open: async (sealed, coordinate) => {
        opened.push(/** @type {any} */ (coordinate).suppliedT);
        return sealed === "AQ"
          ? { error: { error: "unseal_failed", message: "fixture opening failed" } }
          : { bytes: new Uint8Array(16).fill(9) };
      },
    },
    invocation,
  );
  const result = await produce("premium", answer.selected);
  return { answer, periods: "periods" in result ? result.periods : [], opened };
}

for (const representation of /** @type {const} */ (["period-keys", "chain-keys"])) {
  for (const first of ["AQ", "Ag=="]) {
    test(`${representation}: a failed current window stops optional production (${first})`, async () => {
      const result = await horizonSource(representation, { first });
      assert.deepEqual(
        result.periods.map((p) => [p.t, "error" in p]),
        [["251014T1100", true]],
      );
      assert.equal(result.opened.includes("251014T2300"), false);
    });

    test(`${representation}: a later article survives a failed horizon without extending it (${first})`, async () => {
      const result = await horizonSource(representation, { first, hints: ["251014T1200"] });
      assert.deepEqual(
        result.periods.filter((p) => "bytes" in p).map((p) => p.t),
        ["251014T1200"],
      );
      assert.deepEqual(
        result.periods.filter((p) => "error" in p).map((p) => p.t),
        ["251014T1100"],
      );
    });
  }

  test(`${representation}: a successful rival keeps the consecutive horizon open`, async () => {
    const result = await horizonSource(representation, { rival: true, second: false, future: 2 });
    assert.deepEqual(
      result.periods.filter((p) => "error" in p),
      [],
    );
    assert.deepEqual(
      result.periods.map((p) => p.t),
      representation === "period-keys" ? ["251014T1000", "251014T1100"] : ["251014T1100"],
    );
  });

  test(`${representation}: malformed-only supply cannot establish an unavailable report`, async () => {
    const result = await horizonSource(representation, {
      first: "Ag==",
      second: false,
      now: "2025-10-14T15:00:00Z",
      future: 1,
    });
    assert.deepEqual(result.answer, { unavailable: true });
  });

  test(`${representation}: valid supply can establish an independently authorized unavailable report`, async () => {
    const result = await horizonSource(representation, {
      first: "Ag",
      second: false,
      now: "2025-10-14T15:00:00Z",
      future: 1,
    });
    assert.deepEqual(result.answer, { unavailable: "unavailable" });
  });
}

test("a filtered chain target does not hide a separate authorized unsupplied article", async () => {
  // Move the only valid member to the second window: the malformed first
  // window reaches no older-day article. The second window's denied prefix
  // filters its current target without invalidating the independent article.
  const result = await horizonSource("chain-keys", {
    first: "Ag==",
    hints: ["251013T0900"],
    now: "2025-10-14T15:00:00Z",
    future: 1,
    authorize: (t) => t === "251013T0900" || t >= "251014T1300",
  });
  assert.deepEqual(result.answer, { unavailable: "unavailable" });
});

test("chain prefix incompatibility alone establishes no unavailable report", async () => {
  const result = await horizonSource("chain-keys", {
    now: "2025-10-14T15:00:00Z",
    future: 1,
    authorize: (t) => t >= "251014T1300",
  });
  assert.deepEqual(result.answer, { unavailable: true });
});

for (const [name, value] of [
  ["canonical but unopenable key", CANONICAL_UNOPENABLE],
  ["noncanonical key", "Ag=="],
  ["missing key", undefined],
  ["non-string key", { malformed: true }],
]) {
  test(`an actual issuer error for a positioned ${name} is admitted and conflicts with a family report`, async (t) => {
    let context;
    const responses = [];
    for (const representation of /** @type {const} */ (["period-keys", "chain-keys"])) {
      const result = await unlockEdited({
        edit(document) {
          document.sealed.chainKeys = document.sealed.chainKeys.filter(
            (record) => record.cutoff === "251024T2355",
          );
          const member = document.sealed.chainKeys.find(
            (record) => record.accessGroup === "premium",
          );
          if (value === undefined) delete member.key;
          else member.key = value;
          document.requestedPeriodKeys = GROUPS.map((accessGroup) => ({
            accessGroup,
            periods: ["251024T0000"],
          }));
        },
        contentNames: [NAME],
        authorize: { premium: () => true, archive: () => true },
        representation,
        capture: (captured) => {
          context = captured;
        },
      });
      assert.deepEqual(errorCodes(result.errors), { "premium|251024T2355": "unseal_failed" });
      const keys = { contentKeys: result.contentKeys, periodKeys: result.periodKeys };
      if (representation === "chain-keys") {
        const encode = chainKeyCapabilityEncoderFor();
        keys.chainKeys = result.capabilities.flatMap((capability) => {
          const encoded = encode(capability);
          return encoded.entries.map(({ t, key }) => ({
            accessGroup: encoded.accessGroup,
            cutoff: t,
            key,
          }));
        });
      }
      responses.push({ keys, errors: result.errors });
    }
    const page = new DcaData(context.page, { publisherOrigin: PUB });
    const association = new ResponseAssociation(page, ISSUER, context.document);
    const apply = async (response) => {
      const periodWrites = [];
      const chainWrites = [];
      const resolver = new ContentKeyResolver({
        cache: {
          put: (...args) => periodWrites.push(args),
          candidatesAt: () => [],
          attempted: async () => {},
        },
        chainCache: { put: (...args) => chainWrites.push(args), candidates: () => [] },
        chainKeyProfile: explicitChainKeyClientProfile,
      });
      const application = await resolver.applyResponse(page, ISSUER, response, association);
      return { application, periodWrites, chainWrites, resolver };
    };
    for (const [index, response] of responses.entries()) {
      await t.test(
        `${index === 0 ? "period-key" : "chain-key"} delivery admits the source error`,
        async () => {
          const { application } = await apply(response);
          assert.equal(application.accepted, 2, "the content and valid archive key are accepted");
          assert.deepEqual(application.errors, response.errors);
          assert.deepEqual(application.issues, []);
        },
      );
    }
    const mixed = {
      keys: { ...responses[0].keys, chainKeys: responses[1].keys.chainKeys },
      errors: responses[0].errors,
      notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
    };
    await t.test("a contradictory family report refuses both stock key sections", async () => {
      const { application, periodWrites, chainWrites, resolver } = await apply(mixed);
      assert.equal(application.accepted, 1);
      assert.deepEqual(application.issues, [
        { section: "notDelivered", code: "malformed_response" },
      ]);
      assert.deepEqual(periodWrites, [], "a malformed report prevents every stock period write");
      assert.deepEqual(chainWrites, [], "a malformed report prevents every stock chain write");
      assert.deepEqual(application.errors, mixed.errors);
      assert.ok(await resolver.contentKeyFor(page, NAME), "the independent content key survives");
    });
  });
}
