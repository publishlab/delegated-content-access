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
// content key: which leaf material the issuer reaches for. The issuer selects
// that from application state keyed by the registration the token verified
// against. B's registration selects B's leaves; A's leaves are unreachable from
// B's request however the request is spelled.
//
// The separate control below covers the honest case: each publisher opens its
// own item through its own material, and the two content keys differ.

import test from "node:test";
import assert from "node:assert/strict";

import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { decodePayload, sign } from "../../../core-shared--publisher-issuer/jwt.js";
import { exactPeriodKeySupply } from "../../../demo/support/exactPeriodKeySupply.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import { AT, ISSUER_A, KEY_ID, contentOnlyPolicy, render } from "../test-lib/world.js";

const { subtle } = globalThis.crypto;

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
  const periodKeySupply = exactPeriodKeySupply({ random: new Random({ seed }) });

  const keyStore = {
    /** @param {string} name @param {string} keyId */
    get: (name, keyId) =>
      name === ISSUER_A && keyId === KEY_ID
        ? { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey }
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
      issuers: [
        {
          issuerName: ISSUER_A,
          keyId: KEY_ID,
          algorithm: "ECDH-P256",
          publicKey: issuerKeys.publicKey,
          unlockUrl: `https://${ISSUER_A}.example.com/unlock`,
          extensions: [EXTENSION_NAME],
        },
      ],
    }),
    { items: ["bodytext"] },
  );

  const request = new OmissionRequestBuilder({ relayExactPeriod: true }).build(
    new DcaData(page, { publisherOrigin: origin }),
    ISSUER_A,
    ["bodytext"],
  );

  // This case turns on the issuer's long-lived capability, so the request's
  // own sealed period material is dropped and only a leaf can answer.
  delete request.toObject().sealed.periodKeys;

  return { origin, kid, signingKeys, registration, periodKeySupply, page, request };
}

/**
 * The issuer application: two registered publishers, the leaves it holds for
 * each, and one engine over them. The leaf views live in a `WeakMap` keyed by
 * the registration object the application itself constructed, so selecting one
 * needs that object and nothing a request can spell.
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
  const exactPeriodLeaves = new WeakMap();
  for (const [label, owner] of [
    ["A", a],
    ["B", b],
  ]) {
    exactPeriodLeaves.set(
      /** @type {any} */ (owner).registration,
      (/** @type {string} */ accessGroup, /** @type {string} */ t) => {
        asked.push({ publisher: /** @type {string} */ (label), accessGroup, t });
        return /** @type {any} */ (owner).periodKeySupply.derive(accessGroup, t);
      },
    );
  }

  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["bodytext"]),
    exactPeriodLeaves,
  });

  return { a, b, asked, engine };
}

test("each publisher opens its own item through its own leaf material", async () => {
  const { a, b, asked, engine } = await issuerApplication();

  const mine = await engine.unlock(a.request, a.registration);
  const theirs = await engine.unlock(b.request, b.registration);

  assert.deepEqual(Object.keys(mine.contentKeys), ["bodytext"]);
  assert.deepEqual(Object.keys(theirs.contentKeys), ["bodytext"]);
  assert.deepEqual(mine.errors, {});
  assert.deepEqual(theirs.errors, {});

  // Different material, so "the same key came back" cannot pass for "the
  // partition held".
  assert.notEqual(mine.contentKeys.bodytext, theirs.contentKeys.bodytext);

  // Each unlock reached exactly its own publisher's leaves.
  assert.deepEqual([...new Set(asked.map(({ publisher: name }) => name))].sort(), ["A", "B"]);
});

test("a publisher signing another publisher's renderId over its copied candidate gets no key", async () => {
  const { a, b, asked, engine } = await issuerApplication();

  const honest = await engine.unlock(a.request, a.registration);
  assert.deepEqual(
    Object.keys(honest.contentKeys),
    ["bodytext"],
    "A's leaf is in this issuer application and does open A's candidate",
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

  assert.deepEqual(result.contentKeys, {}, "no content key of A's comes back to B");
  assert.equal(result.errors.bodytext.error, "unseal_failed");
  assert.deepEqual(result.periodKeys, {});

  // B's registration selects B's capability. A's leaves are held by the same
  // issuer application and were never asked for this request.
  assert.deepEqual(asked, [
    { publisher: "B", accessGroup: "premium", t: "251023T14" },
    { publisher: "B", accessGroup: "premium", t: "251023T15" },
  ]);
});

test("a publisher registration with no leaf capability is a miss and reaches no other publisher", async () => {
  const { a, b } = await issuerApplication();

  // Application state that holds A's leaves alone. B is registered and
  // verifies, and there is no global source under the selection to fall back
  // to.
  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const exactPeriodLeaves = new WeakMap();
  exactPeriodLeaves.set(a.registration, (accessGroup, t) =>
    a.periodKeySupply.derive(accessGroup, t),
  );
  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["bodytext"]),
    exactPeriodLeaves,
  });

  const result = await engine.unlock(b.request, b.registration);

  assert.deepEqual(result.contentKeys, {});
  assert.equal(result.errors.bodytext.error, "unseal_failed");
});
