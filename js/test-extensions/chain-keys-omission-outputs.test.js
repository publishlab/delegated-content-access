// @ts-check
//
// What one issuer selecting both extensions answers, pinned byte by byte.
//
// The composition beside this file is under research, so this test fixes its
// inputs and takes every expected value from outside the modules under test:
// the cutoff chain key from the neutral `dca-profile-chain-keys` fixture, the content
// key from the article it opens. A change of composition that changes an
// answer shows up here rather than in a shape assertion that still passes.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { DcaData } from "../core-client/DcaData.js";
import { openContent } from "../core-client/openContent.js";
import { contentAadOctets } from "../test-reference/support/contentAadOctets.js";
import { base64urlDecode, utf8Decode } from "../core-shared/codec.js";
import { openingKeysOver, PublisherRegistrations } from "../demo/support/PublisherRegistrations.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { OmittingSealer } from "../extensions/content-key-seal-omission/core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../extensions/content-key-seal-omission/core-client/OmissionRequestBuilder.js";
import { ChainKeyRequestBuilder } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { ChainKeyOmissionIssuerEngine } from "./support/ChainKeyOmissionIssuerEngine.js";
import { EXTENSION_NAME } from "../extensions/content-key-seal-omission/core-shared/omissionBind.js";

const { subtle } = globalThis.crypto;

/**
 * The ciphertext a page carries for one item, read from its
 * `[{contentName, content}]` records.
 *
 * @param {any[]} sealedContent
 * @param {string} contentName
 * @returns {string|null}
 */
function ciphertextOf(sealedContent, contentName) {
  return (
    sealedContent.find((/** @type {any} */ record) => record.contentName === contentName)
      ?.content ?? null
  );
}

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
      "../extensions/chain-keys/test/fixtures/dca-profile-chain-keys.vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

// The vector set states its lifecycle before a byte of it is used: a set
// without `setIdentity`, `status` and `semanticWidths` is ambiguous about which
// width it records, and this loader does not accept one.
assert.equal(VECTORS.setIdentity, "dca-profile-chain-keys");
assert.equal(VECTORS.status, "canonical-16");
assert.equal(VECTORS.semanticWidths.chainKey, 16);
assert.equal(VECTORS.semanticWidths.periodKey, 16);
assert.equal(VECTORS.semanticWidths.periodKeyWrapAlgorithm, "AES-128-GCM");
const C1 = VECTORS.cases.find((/** @type {any} */ entry) => entry.id === "c1");

/**
 * A policy naming its chain horizon and explicit auxiliary source labels: base's content names and period grants, and the
 * omission extension's own `sourceGrants` beside them.
 *
 * @param {number} periodCount
 * @param {string[]} sourcePeriods
 */
function policyGranting(periodCount, sourcePeriods) {
  return {
    /** @param {any} claims @param {{ contentNames: string[], accessGroups: string[] }} requested */
    decide(claims, requested) {
      void claims;
      return {
        contentNames: requested.contentNames,
        periodGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          futurePeriodCount: periodCount,
          authorizePeriod: () => periodCount > 0,
        })),
        sourceGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          periods: sourcePeriods,
        })),
        policyData: { plan: "monthly" },
      };
    },
  };
}

/** A publisher omitting this issuer's `contentKeys` map, and the issuer holding the same chain supply. */
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
    issuerSupplyPlanFor: () => ({
      suppliedAccessGroups: [GROUP],
      periodKeyDelivery: { [GROUP]: ["period-keys", "chain-keys"] },
    }),
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,

        extensions: [EXTENSION_NAME],
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(NAME, ARTICLE, "text/html", { accessGroups: [GROUP] });
  const sealed = await sealer.seal();
  const page = JSON.parse(
    JSON.stringify({
      ...sealed.dcaData,
      // The page carries ciphertexts as named records; the sealer hands a map.
      sealedContent: Object.entries(sealed.sealedContent).map(([contentName, content]) => ({
        contentName,
        content,
      })),
    }),
  );

  const keyStore = {
    /** @param {string} name @param {string} keyId */
    get: (name, keyId) =>
      name === ISSUER_NAME && keyId === KEY_ID
        ? { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey }
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
 * The request this client sends. Most composition tests drop the sealed period
 * keys so the bound candidate has only the issuer's held capability to open
 * under; one keeps them to prove chain-required output does not hide them
 * from the independent content-key route.
 *
 * @param {any} page
 * @param {{ keepPeriodKeys?: boolean }} [options]
 */
function requestFor(page, { keepPeriodKeys = false } = {}) {
  const request = new ChainKeyRequestBuilder({
    innerBuilder: new OmissionRequestBuilder({ relayPeriodKeys: true }),
  }).build(new DcaData(page, { publisherOrigin: PUB }), ISSUER_NAME, [NAME]);
  const document = request.toObject();
  if (!keepPeriodKeys) delete document.sealed.periodKeys;
  return request;
}

/**
 * The cutoff bytes read from the neutral fixture. A positioned chain key is
 * a fact of the family, the window and the coordinate, so the terminal the
 * issuer walked from is implied by the label.
 *
 * @param {string} cutoffT
 */
function cutoffKey(cutoffT) {
  const chainKey = C1.cutoffChainKeys[cutoffT];
  assert.ok(chainKey, `the fixture records the chain key at ${cutoffT}`);
  return chainKey;
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
 * @param {string[]} sourcePeriods
 * @param {object} [config]
 */
function combinedEngine(registration, generation, sourcePeriods, config = {}) {
  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const periodKeyLookup = new WeakMap();
  periodKeyLookup.set(registration, (accessGroup, t) => generation.periodKey(accessGroup, t));
  return new ChainKeyOmissionIssuerEngine({
    accessPolicy: policyGranting(2, sourcePeriods),
    operatingIssuerNames: [ISSUER_NAME],
    clock: new Clock(AT),
    periodKeyLookup,
    ...config,
  });
}

/**
 * The content names a result delivers keys for, one per record.
 *
 * @param {any} result
 */
function contentNames(result) {
  return result.contentKeys.map((/** @type {any} */ record) => record.contentName);
}

/**
 * The key a result delivers for `NAME`.
 *
 * @param {any} result
 */
function contentKey(result) {
  const record = result.contentKeys.find((/** @type {any} */ entry) => entry.contentName === NAME);
  assert.ok(record, `the result delivers a content key for ${NAME}`);
  return record.key;
}

/**
 * The capability's chain entries as the candidate set at each cutoff `t`.
 * Several entries may share one `t` as rival candidates, so each cutoff maps to
 * its sorted distinct keys, and entry order means nothing.
 * @param {any} result
 * @returns {Record<string, string[]>}
 */
function chainEntries(result) {
  assert.equal(result.capabilities.length, 1);
  const [capability] = result.capabilities;
  assert.equal(capability.kind, "chain-keys");
  assert.equal(capability.accessGroup, GROUP);
  assert.ok(Array.isArray(capability.entries), "chain entries are records");
  /** @type {Record<string, string[]>} */
  const candidates = {};
  for (const { t, key } of capability.entries) {
    const keys = (candidates[t] ??= []);
    if (!keys.includes(key)) keys.push(key);
  }
  for (const keys of Object.values(candidates)) keys.sort();
  return candidates;
}

test("both halves answer in one unlock: the chain cutoff and the omitted content key", async () => {
  const { generation, page, registration } = await world();
  const sourcePeriods = new DcaData(page, { publisherOrigin: PUB })
    .sealedEntriesFor(NAME, GROUP)
    .map(({ t }) => t);
  const engine = combinedEngine(registration, generation, sourcePeriods);

  const result = await engine.unlock(requestFor(page), registration);

  assert.deepEqual(chainEntries(result), {
    "251023T1430": [cutoffKey("251023T1430")],
  });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.policyData, { plan: "monthly" });
  assert.deepEqual(result.periodKeys, [], "the period key a candidate opened under is not a grant");

  const plaintext = await openContent(
    base64urlDecode(contentKey(result)),
    NAME,
    ciphertextOf(page.sealedContent, NAME),
    contentAadOctets(page, NAME),
  );
  assert.equal(utf8Decode(plaintext), ARTICLE);
});

test("the application instant selects the chain start for the combined issuer too", async () => {
  const { generation, page, registration } = await world();
  const sourcePeriods = new DcaData(page, { publisherOrigin: PUB })
    .sealedEntriesFor(NAME, GROUP)
    .map(({ t }) => t);
  let clockReads = 0;
  const engine = combinedEngine(registration, generation, sourcePeriods, {
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
    "251023T1630": [cutoffKey("251023T1630")],
  });
  assert.deepEqual(contentNames(result), [NAME]);
  assert.equal(clockReads, 0, "an application-owned instant leaves the injected clock unread");
});

test("a registration with no period-key lookup held reaches no content key, and the chain half still answers", async () => {
  const { page, registration } = await world();
  const sourcePeriods = new DcaData(page, { publisherOrigin: PUB })
    .sealedEntriesFor(NAME, GROUP)
    .map(({ t }) => t);
  const engine = new ChainKeyOmissionIssuerEngine({
    accessPolicy: policyGranting(2, sourcePeriods),
    operatingIssuerNames: [ISSUER_NAME],
    clock: new Clock(AT),
    periodKeyLookup: new WeakMap(),
  });

  const result = await engine.unlock(requestFor(page), registration);

  assert.deepEqual(result.contentKeys, [], "no capability is selected for this registration");
  assert.deepEqual(chainEntries(result), {
    "251023T1430": [cutoffKey("251023T1430")],
  });
});

test("chain-required output leaves sealed period keys available to the omission route", async () => {
  const { page, registration } = await world();
  const sourcePeriods = new DcaData(page, { publisherOrigin: PUB })
    .sealedEntriesFor(NAME, GROUP)
    .map(({ t }) => t);
  const engine = new ChainKeyOmissionIssuerEngine({
    accessPolicy: policyGranting(2, sourcePeriods),
    operatingIssuerNames: [ISSUER_NAME],
    clock: new Clock(AT),
    periodKeyLookup: new WeakMap(),
  });

  // Period keys are not an output route in this composition. They are
  // still one internal candidate the independently granted omission route
  // may open, so selecting chain-required period output must not erase them
  // from the shared admitted request.
  const result = await engine.unlock(requestFor(page, { keepPeriodKeys: true }), registration);

  assert.deepEqual(result.periodKeys, [], "no period-key capability is returned");
  assert.deepEqual(chainEntries(result), {
    "251023T1430": [cutoffKey("251023T1430")],
  });
  assert.deepEqual(result.errors, []);

  const plaintext = await openContent(
    base64urlDecode(contentKey(result)),
    NAME,
    ciphertextOf(page.sealedContent, NAME),
    contentAadOctets(page, NAME),
  );
  assert.equal(utf8Decode(plaintext), ARTICLE);
});

test("a policy granting nothing refuses the combined request whole", async () => {
  const { generation, page, registration } = await world();
  const sourcePeriods = new DcaData(page, { publisherOrigin: PUB })
    .sealedEntriesFor(NAME, GROUP)
    .map(({ t }) => t);
  let openingLookups = 0;
  let lookupSelections = 0;
  let periodKeyCalls = 0;
  const countedRegistration = {
    ...registration,
    openingKeys: {
      get(issuerName, keyId) {
        openingLookups++;
        return registration.openingKeys.get(issuerName, keyId);
      },
    },
  };
  const periodKeyLookup = {
    get(selected) {
      lookupSelections++;
      assert.equal(selected, countedRegistration);
      return async (accessGroup, t) => {
        periodKeyCalls++;
        return generation.periodKey(accessGroup, t);
      };
    },
  };
  const engine = combinedEngine(countedRegistration, generation, sourcePeriods, {
    accessPolicy: { decide: () => ({ contentNames: [], periodGrants: [] }) },
    periodKeyLookup,
  });

  await assert.rejects(
    engine.unlock(requestFor(page), countedRegistration),
    (/** @type {any} */ error) => error.code === "denied",
  );
  assert.deepEqual(
    { openingLookups, lookupSelections, periodKeyCalls },
    { openingLookups: 0, lookupSelections: 0, periodKeyCalls: 0 },
    "complete denial precedes both extensions' key paths",
  );

  const allowed = await combinedEngine(countedRegistration, generation, sourcePeriods, {
    periodKeyLookup,
  }).unlock(requestFor(page), countedRegistration);

  assert.deepEqual(contentNames(allowed), [NAME], "the same counted source answers when granted");
  assert.deepEqual(
    { openingLookups, lookupSelections, periodKeyCalls },
    { openingLookups: 1, lookupSelections: 1, periodKeyCalls: 1 },
    "the counters observe reachable key paths",
  );
});
