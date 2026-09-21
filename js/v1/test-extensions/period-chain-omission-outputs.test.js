// @ts-check
//
// What one issuer selecting both extensions answers, pinned byte by byte.
//
// The composition beside this file is under research, so this test fixes its
// inputs and takes every expected value from outside the modules under test:
// the cutoff state from the neutral `dca-period-chain-v1` fixture, the content
// key from the article it opens. A change of composition that changes an
// answer shows up here rather than in a shape assertion that still passes.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { DcaData } from "../core-client/DcaData.js";
import { openContent } from "../core-client/openContent.js";
import { base64urlDecode, base64urlEncode, utf8Decode } from "../core-shared/codec.js";
import { openingKeysOver, PublisherRegistrations } from "../demo/support/PublisherRegistrations.js";
import { periodFamilyGeneration } from "../extensions/period-chain/core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../extensions/period-chain/core-publisher/periodFamilySupply.js";
import { OmittingSealer } from "../extensions/content-key-seal-omission/core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../extensions/content-key-seal-omission/core-client/OmissionRequestBuilder.js";
import { PeriodChainRequestBuilder } from "../extensions/period-chain/core-client/PeriodChainRequestBuilder.js";
import { PeriodChainOmissionIssuerEngine } from "./support/PeriodChainOmissionIssuerEngine.js";
import { EXTENSION_NAME } from "../extensions/content-key-seal-omission/core-shared/omissionBind.js";

const { subtle } = globalThis.crypto;

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const PUB = "https://www.news-site.example";
const AT = "2025-10-23T14:20:00Z";
const GROUP = "premium";
const NAME = "bodytext";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

/** The chain root secret behind both the render and every expectation below. */
const PERIOD_SECRET = new Uint8Array(32).fill(7);

const VECTORS = JSON.parse(
  readFileSync(
    new URL(
      "../extensions/period-chain/test/fixtures/dca-period-chain-v1.vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

// The vector set states its lifecycle before a byte of it is used: a set
// without `setIdentity`, `status` and `semanticWidths` is ambiguous about which
// width it records, and this loader does not accept one.
assert.equal(VECTORS.setIdentity, "dca-period-chain-v1");
assert.equal(VECTORS.status, "canonical-16");
assert.equal(VECTORS.semanticWidths.chainState, 16);
assert.equal(VECTORS.semanticWidths.exactLeaf, 16);
assert.equal(VECTORS.semanticWidths.exactWrapAlgorithm, "AES-128-GCM");
const C1 = VECTORS.cases.find((/** @type {any} */ entry) => entry.id === "c1");

/**
 * A policy naming its counts: base's content names and period grants, and the
 * omission extension's own `sourceGrants` beside them.
 *
 * @param {number} periodCount
 */
function policyGranting(periodCount) {
  return {
    /** @param {any} claims @param {{ contentNames: string[], accessGroups: string[] }} requested */
    decide(claims, requested) {
      void claims;
      return {
        contentNames: requested.contentNames,
        periodGrants: requested.accessGroups.map((accessGroup) => ({ accessGroup, periodCount })),
        sourceGrants: requested.accessGroups.map((accessGroup) => ({ accessGroup, periodCount })),
        policyData: { plan: "monthly" },
      };
    },
  };
}

/** A publisher omitting this issuer's direct map, and the issuer holding the same chain supply. */
async function world() {
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const generation = periodFamilyGeneration({
    keyDerivationSecret: PERIOD_SECRET,
    geometry: GEOMETRY,
  });
  const supply = periodFamilySupply({ families: { [GROUP]: generation }, chainWindows: 2 });

  const sealer = new OmittingSealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 1 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: supply,
    issuerSupplyPlanFor: () => ({ periodKeyDelivery: { [GROUP]: ["exact", "chain"] } }),
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ECDH-P256",
        publicKey: issuerKeys.publicKey,
        unlockUrl: "https://api.example.com/unlock",
        extensions: [EXTENSION_NAME],
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(NAME, ARTICLE, "text/html", { accessGroups: [GROUP] });
  const sealed = await sealer.seal();
  const page = JSON.parse(
    JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
  );

  const keyStore = {
    /** @param {string} name @param {string} keyId */
    get: (name, keyId) =>
      name === ISSUER_NAME && keyId === KEY_ID
        ? { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey }
        : undefined,
  };
  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]),
    },
  ]).get(SIGNING_KID);

  return { generation, page, registration };
}

/**
 * The request this client sends. Most composition tests drop the sealed exact
 * material so the bound candidate has only the issuer's held capability to
 * open under; one keeps it to prove chain-required output does not hide
 * material from the independent content-key route.
 *
 * @param {any} page
 * @param {{ keepExact?: boolean }} [options]
 */
function requestFor(page, { keepExact = false } = {}) {
  const request = new PeriodChainRequestBuilder({
    innerBuilder: new OmissionRequestBuilder({ relayExactPeriod: true }),
  }).build(new DcaData(page, { publisherOrigin: PUB }), ISSUER_NAME, [NAME]);
  const document = request.toObject();
  if (!keepExact) delete document.sealed.periodKeys;
  return request;
}

/**
 * The cutoff bytes read from the neutral fixture. A positioned chain state is
 * a fact of the family, the window and the coordinate, so the terminal the
 * issuer walked from is implied by the label.
 *
 * @param {string} cutoffT
 */
function cutoffKey(cutoffT) {
  const state = C1.cutoffStates[cutoffT];
  assert.ok(state, `the fixture records the chain state at ${cutoffT}`);
  return state;
}

test("the fixture family these bytes are pinned to is the family this publisher seals with", () => {
  assert.equal(
    [...PERIOD_SECRET].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
    C1.secretHex,
    "the render and the fixture share one family secret",
  );
  assert.equal(C1.accessGroup, GROUP);
  assert.equal(C1.chainsPerDay, GEOMETRY.chainsPerDay);
  assert.equal(C1.periodMinutes, GEOMETRY.periodMinutes);
});

/**
 * @param {any} registration
 * @param {any} generation
 * @param {object} [config]
 */
function combinedEngine(registration, generation, config = {}) {
  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const exactPeriodLeaves = new WeakMap();
  exactPeriodLeaves.set(registration, (accessGroup, t) => generation.periodKey(accessGroup, t));
  return new PeriodChainOmissionIssuerEngine({
    accessPolicy: policyGranting(2),
    clock: new Clock(AT),
    exactPeriodLeaves,
    ...config,
  });
}

/** @param {any} result */
function chainEntries(result) {
  assert.equal(result.capabilities.length, 1);
  const [capability] = result.capabilities;
  assert.equal(capability.kind, "period-chain");
  assert.equal(capability.accessGroup, GROUP);
  return capability.entries;
}

test("both halves answer in one unlock: the chain cutoff and the omitted content key", async () => {
  const { generation, page, registration } = await world();
  const engine = combinedEngine(registration, generation);

  const result = await engine.unlock(requestFor(page), registration);

  assert.deepEqual(chainEntries(result), {
    "251023T1430": cutoffKey("251023T1430"),
  });
  assert.deepEqual(result.errors, {});
  assert.deepEqual(result.policyData, { plan: "monthly" });
  assert.deepEqual(result.periodKeys, {}, "the leaf a candidate opened under is not a grant");

  const record = page.contentData[NAME];
  const plaintext = await openContent(
    base64urlDecode(result.contentKeys[NAME]),
    NAME,
    record.nonce,
    page.sealedContent[NAME],
    record.aad,
  );
  assert.equal(utf8Decode(plaintext), ARTICLE);
});

test("the application instant selects the chain start for the combined issuer too", async () => {
  const { generation, page, registration } = await world();
  let clockReads = 0;
  const engine = combinedEngine(registration, generation, {
    clock: {
      now() {
        clockReads++;
        return new Date(AT);
      },
    },
  });

  const result = await engine.unlock(
    requestFor(page),
    registration,
    {},
    new Date("2025-10-23T16:20:00Z"),
  );

  assert.deepEqual(chainEntries(result), {
    "251023T1630": cutoffKey("251023T1630"),
  });
  assert.deepEqual(Object.keys(result.contentKeys), [NAME]);
  assert.equal(clockReads, 0, "an application-owned instant leaves the injected clock unread");
});

test("a registration with no leaf view held reaches no content key, and the chain half still answers", async () => {
  const { generation, page, registration } = await world();
  const engine = new PeriodChainOmissionIssuerEngine({
    accessPolicy: policyGranting(2),
    clock: new Clock(AT),
    exactPeriodLeaves: new WeakMap(),
  });

  const result = await engine.unlock(requestFor(page), registration);

  assert.deepEqual(result.contentKeys, {}, "no capability is selected for this registration");
  assert.deepEqual(chainEntries(result), {
    "251023T1430": cutoffKey("251023T1430"),
  });
});

test("chain-required output leaves sealed exact material available to the omission route", async () => {
  const { generation, page, registration } = await world();
  const engine = new PeriodChainOmissionIssuerEngine({
    accessPolicy: policyGranting(2),
    clock: new Clock(AT),
    exactPeriodLeaves: new WeakMap(),
  });

  // Exact period keys are not an output route in this composition. They are
  // still one internal candidate the independently granted omission route
  // may open, so selecting chain-required period output must not erase them
  // from the shared admitted request.
  const result = await engine.unlock(requestFor(page, { keepExact: true }), registration);

  assert.deepEqual(result.periodKeys, {}, "no exact period capability is returned");
  assert.deepEqual(chainEntries(result), {
    "251023T1430": cutoffKey("251023T1430"),
  });
  assert.deepEqual(result.errors, {});

  const record = page.contentData[NAME];
  const plaintext = await openContent(
    base64urlDecode(result.contentKeys[NAME]),
    NAME,
    record.nonce,
    page.sealedContent[NAME],
    record.aad,
  );
  assert.equal(utf8Decode(plaintext), ARTICLE);
});

test("a policy granting nothing refuses the combined request whole", async () => {
  const { generation, page, registration } = await world();
  let openingLookups = 0;
  let leafSelections = 0;
  let leafCalls = 0;
  const countedRegistration = {
    ...registration,
    openingKeys: {
      get(issuerName, keyId) {
        openingLookups++;
        return registration.openingKeys.get(issuerName, keyId);
      },
    },
  };
  const exactPeriodLeaves = {
    get(selected) {
      leafSelections++;
      assert.equal(selected, countedRegistration);
      return async (accessGroup, t) => {
        leafCalls++;
        return generation.periodKey(accessGroup, t);
      };
    },
  };
  const engine = combinedEngine(countedRegistration, generation, {
    accessPolicy: { decide: () => ({ contentNames: [], periodGrants: [] }) },
    exactPeriodLeaves,
  });

  await assert.rejects(
    engine.unlock(requestFor(page), countedRegistration),
    (/** @type {any} */ error) => error.code === "denied",
  );
  assert.deepEqual(
    { openingLookups, leafSelections, leafCalls },
    { openingLookups: 0, leafSelections: 0, leafCalls: 0 },
    "complete denial precedes both extensions' key paths",
  );

  const allowed = await combinedEngine(countedRegistration, generation, {
    exactPeriodLeaves,
  }).unlock(requestFor(page), countedRegistration);

  assert.deepEqual(
    Object.keys(allowed.contentKeys),
    [NAME],
    "the same counted source answers when granted",
  );
  assert.deepEqual(
    { openingLookups, leafSelections, leafCalls },
    { openingLookups: 1, leafSelections: 1, leafCalls: 1 },
    "the counters observe reachable key paths",
  );
});
