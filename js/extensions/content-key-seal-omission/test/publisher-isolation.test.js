// @ts-check
//
// Two registered publishers, one issuer, and the copied-candidate case.
//
// Publisher A and publisher B have their own signing keys, their own delivery
// origins, their own registrations and their own issuer opening keysets. Each
// has period material of its own that the issuer holds as a long-lived
// capability. Nothing in a render says whose material opens it: both spell the
// same access group and the same period labels, and both renderIds and both
// bound candidates travel in public pages.
//
// So B copies A's bound candidate and A's renderId, and signs that renderId in
// a valid resource token of its own. Everything B presents authenticates: the
// signature is B's, the registration is B's, the renderId under it is the one
// the candidate was wrapped against. One thing still separates B from A's
// content key: which period-key material the issuer reaches for. The issuer
// selects that from application state keyed by the registration the token
// verified against. B's registration selects B's period keys; A's period keys
// are unreachable from B's request however the request is spelled.
//
// The separate control below covers the honest case: each publisher opens its
// own item through its own material, and the two content keys differ.

import test from "node:test";
import assert from "node:assert/strict";

import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { decodePayload, sign } from "../../../core-shared--publisher-issuer/jwt.js";
import { randomPeriodKeySupply } from "../../../demo/support/randomPeriodKeySupply.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import { AT, ISSUER_A, KEY_ID, contentOnlyPolicy, render } from "../test-lib/world.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;

/**
 * The period labels of the candidates a request forwards for one content name.
 *
 * @param {any} request
 * @param {string} contentName
 */
function candidatePeriods(request, contentName) {
  return request
    .toObject()
    .boundCandidates.filter((/** @type {any} */ record) => record.contentName === contentName)
    .map((/** @type {any} */ { period }) => period);
}

/**
 * The content names an unlock delivers keys for, one per record.
 *
 * @param {any[]} contentKeys
 */
function deliveredNames(contentKeys) {
  return contentKeys.map(({ contentName }) => contentName);
}

/**
 * The key an unlock delivers at one content name.
 *
 * @param {any[]} contentKeys
 * @param {string} contentName
 */
function keyAt(contentKeys, contentName) {
  return contentKeys.find((record) => record.contentName === contentName)?.key;
}

/**
 * The error record an unlock reports at one coordinate.
 *
 * @param {any[]} errors
 * @param {string} coordinate
 */
function errorAt(errors, coordinate) {
  return errors.find((record) => record.coordinate === coordinate);
}

/**
 * One registered publisher: its signing key, its own issuer opening keyset, its
 * own period material, one active render and the request a client builds from
 * it. Two of these share nothing but the issuer name and the keyId label.
 *
 * @param {{ origin: string, kid: string, seed: number }} identity
 */
async function publisher({ origin, kid, seed }) {
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const periodKeySupply = randomPeriodKeySupply({ random: new Random({ seed }) });

  const keyStore = {
    /** @param {string} name @param {string} keyId */
    get: (name, keyId) =>
      name === ISSUER_A && keyId === KEY_ID
        ? { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey }
        : undefined,
  };
  const registration = new PublisherRegistrations([
    {
      kid,
      publicKey: signingKeys.publicKey,
      origin,
      openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER_A, keyId: KEY_ID }]),
    },
  ]).get(kid);

  const page = await render(
    new OmittingSealer({
      origin,
      clock: new Clock(AT),
      random: new Random({ seed: seed + 100 }),
      signingKeys: { [kid]: signingKeys.privateKey },
      periodKeySupply,
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: ISSUER_A,
          keyId: KEY_ID,
          algorithm: "ecdh-p256",
          publicKey: issuerKeys.publicKey,

          extensions: [EXTENSION_NAME],
        },
      ],
    }),
    { items: ["bodytext"] },
  );

  const request = new OmissionRequestBuilder({ relayPeriodKeys: true }).build(
    new DcaData(page, { publisherOrigin: origin }),
    ISSUER_A,
    ["bodytext"],
  );

  // This case turns on the issuer's long-lived capability, so the request's
  // own sealed period material is dropped and only a period key can answer.
  delete request.toObject().sealed.periodKeys;

  return { origin, kid, signingKeys, registration, periodKeySupply, page, request };
}

/**
 * The issuer application: two registered publishers, the period keys it holds
 * for each, and one engine over them. The period-key views live in a `WeakMap`
 * keyed by the registration object the application itself constructed, so
 * selecting one needs that object and nothing a request can spell.
 */
async function issuerApplication() {
  const a = await publisher({
    origin: "https://www.news-site.example",
    kid: "sign-a-2025-10",
    seed: 11,
  });
  const b = await publisher({
    origin: "https://www.other-site.example",
    kid: "sign-b-2025-10",
    seed: 12,
  });

  /** @type {{ publisher: string, accessGroup: string, t: string }[]} */
  const asked = [];
  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const periodKeyLookup = new WeakMap();
  for (const [label, owner] of [
    ["A", a],
    ["B", b],
  ]) {
    periodKeyLookup.set(
      /** @type {any} */ (owner).registration,
      (/** @type {string} */ accessGroup, /** @type {string} */ t) => {
        asked.push({ publisher: /** @type {string} */ (label), accessGroup, t });
        return /** @type {any} */ (owner).periodKeySupply.derive(accessGroup, t);
      },
    );
  }

  const sourcePeriods = candidatePeriods(a.request, "bodytext");

  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: contentOnlyPolicy(["bodytext"], {
      sourceGrants: [{ accessGroup: "premium", periods: sourcePeriods }],
    }),
    periodKeyLookup,
  });

  return { a, b, asked, engine };
}

test("each publisher opens its own item through its own period-key material", async () => {
  const { a, b, asked, engine } = await issuerApplication();

  const mine = await engine.unlock(a.request, a.registration);
  const theirs = await engine.unlock(b.request, b.registration);

  assert.deepEqual(deliveredNames(mine.contentKeys), ["bodytext"]);
  assert.deepEqual(deliveredNames(theirs.contentKeys), ["bodytext"]);
  assert.deepEqual(mine.errors, []);
  assert.deepEqual(theirs.errors, []);

  // Different material, so "the same key came back" cannot pass for "the
  // partition held".
  assert.notEqual(keyAt(mine.contentKeys, "bodytext"), keyAt(theirs.contentKeys, "bodytext"));

  // Each unlock reached exactly its own publisher's period keys.
  assert.deepEqual([...new Set(asked.map(({ publisher: name }) => name))].sort(), ["A", "B"]);
});

test("a publisher signing another publisher's renderId over its copied candidate gets no key", async () => {
  const { a, b, asked, engine } = await issuerApplication();

  const honest = await engine.unlock(a.request, a.registration);
  assert.deepEqual(
    deliveredNames(honest.contentKeys),
    ["bodytext"],
    "A's period key is in this issuer application and does open A's candidate",
  );
  asked.length = 0;

  // B's request, carrying A's public bound candidate and A's public renderId,
  // signed by B under B's own registration. Base passes every check it makes.
  const document = b.request.toObject();
  document.boundCandidates = JSON.parse(JSON.stringify(a.request.toObject().boundCandidates));
  const copiedClaims = decodePayload(a.request.resourceJWT);
  document.resourceJWT = await sign(
    { ...copiedClaims, origin: b.origin },
    b.signingKeys.privateKey,
    { kid: b.kid },
  );

  const result = await engine.unlock(b.request, b.registration);

  assert.deepEqual(result.contentKeys, [], "no content key of A's comes back to B");
  assert.equal(errorAt(result.errors, "bodytext")?.error, "unseal_failed");
  assert.deepEqual(result.periodKeys, []);

  // B's registration selects B's capability. A's period keys are held by the
  // same issuer application and were never asked for this request.
  assert.deepEqual(asked, [
    { publisher: "B", accessGroup: "premium", t: "251023T1400" },
    { publisher: "B", accessGroup: "premium", t: "251023T1500" },
  ]);
});

test("a publisher registration with no period-key capability is a miss and reaches no other publisher", async () => {
  const { a, b } = await issuerApplication();

  // Application state that holds A's period keys alone. B is registered and
  // verifies, and there is no global source under the selection to fall back
  // to.
  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const periodKeyLookup = new WeakMap();
  periodKeyLookup.set(a.registration, (accessGroup, t) => a.periodKeySupply.derive(accessGroup, t));
  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: contentOnlyPolicy(["bodytext"], {
      sourceGrants: [
        {
          accessGroup: "premium",
          periods: candidatePeriods(a.request, "bodytext"),
        },
      ],
    }),
    periodKeyLookup,
  });

  const result = await engine.unlock(b.request, b.registration);

  assert.deepEqual(result.contentKeys, []);
  assert.equal(errorAt(result.errors, "bodytext")?.error, "unseal_failed");
});
