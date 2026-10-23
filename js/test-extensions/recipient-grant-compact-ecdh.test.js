// @ts-check
//
// A recipient-grant issuer whose opening key also permits compact ECDH. The
// operator enables compact on one key entry with
// `envelopes: ["ecdh-p256", "compact-ecdh"]`, and that one entry backs the grant
// endpoint. The grant endpoint takes the compact issuer contribution, so an
// ordinary and a compact delivery to that key both open for the grant holder.
// Two extensions take part, so this test lives with the compositions.

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../core-publisher/Sealer.js";
import { composePublisherConfig } from "../core-publisher/publisherComposition.js";
import { wholeRenderIssuerSupplyPlan } from "../core-publisher/issuerSupplyPlan.js";
import { utf8Decode } from "../core-shared/codec.js";
import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { Client } from "../test-lib/harnesses/client.js";
import { issuerKeypair, signingKeypair } from "../test-reference/support/keys.js";
import { createRecipientGrantIssuer } from "../extensions/recipient-grant/issuer.js";
import { compactEcdhPublisherContribution } from "../extensions/compact-ecdh/core-publisher/keySealing.js";
import { compactEcdhIssuerContribution } from "../extensions/compact-ecdh/core-issuer/procedure.js";
import { COMPACT_ECDH } from "../extensions/compact-ecdh/core-shared--publisher-issuer/selector.js";

const ORIGIN = "https://publisher.example";
const ISSUER = "issuer_a";
const BODY = "bodytext";
const SIDE = "sidebar";
const TEXT = "The paid article body.";
const NOW = Date.parse("2025-10-23T14:20:00Z");

/**
 * One render to one issuer key, with the issuer block compact-selected or not,
 * and the single key entry that permits both procedures.
 *
 * @param {boolean} compact
 */
async function render(compact) {
  const signing = await signingKeypair();
  const pair = await issuerKeypair("ecdh-p256");
  const base = {
    origin: ORIGIN,
    clock: new Clock("2025-10-23T14:20:00Z"),
    random: new Random({ seed: compact ? 22 : 23 }),
    signingKeys: { signing: signing.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER,
        keyId: "k",
        algorithm: "ecdh-p256",
        publicKey: pair.publicKey,
        ...(compact ? { envelope: COMPACT_ECDH } : {}),
      },
    ],
  };
  const sealer = new Sealer(
    composePublisherConfig(base, compactEcdhPublisherContribution()).config,
  );
  sealer.resource("123456", {});
  sealer.content(BODY, TEXT, "text/plain");
  sealer.content(SIDE, "The sidebar.", "text/plain");
  const rendered = await sealer.seal();
  const client = new Client({ publisherOrigin: ORIGIN, relayPeriodKeys: false });
  const page = client.parse({ ...rendered.dcaData, sealedContent: rendered.sealedContent });
  const entry = {
    algorithm: "ecdh-p256",
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    envelopes: ["ecdh-p256", COMPACT_ECDH],
  };
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    origin: ORIGIN,
    registrationId: "pub-1",
    origins: [ORIGIN],
    openingKeys: { get: () => entry },
  };
  return { client, page, registration, ciphertext: rendered.sealedContent[BODY] };
}

function grantIssuer(now = () => NOW) {
  return createRecipientGrantIssuer(
    {
      operatingIssuerNames: [ISSUER],
      issuerId: "issuer-a",
      grants: {
        get: () => ({
          purpose: "recipient-unlock",
          issuerId: "issuer-a",
          publisherRegistrationId: "pub-1",
          resourceId: "123456",
          contentNames: [BODY],
          notBeforeMs: NOW - 1000,
          expiresAtMs: NOW + 60000,
          revoked: false,
        }),
      },
      accessPolicy: {
        decide: (_claims, requested) => ({
          contentNames: requested.contentNames,
          periodGrants: [],
        }),
      },
      now,
    },
    compactEcdhIssuerContribution(),
  );
}

test("one key entry permitting both procedures serves ordinary and compact grant deliveries", async () => {
  const issuer = grantIssuer();
  for (const compact of [false, true]) {
    const { client, page, registration, ciphertext } = await render(compact);
    const request = client.buildRequest(page, ISSUER, [BODY, SIDE]);
    assert.equal(request.envelope, compact ? COMPACT_ECDH : undefined, `compact=${compact}`);
    const answer = await issuer.unlock({
      document: JSON.stringify(request),
      registration,
      authorization: "Bearer ref",
      observedOrigin: ORIGIN,
    });
    assert.equal(answer.status, 200, `compact=${compact} ${JSON.stringify(answer.body)}`);
    assert.equal(answer.body.errors, undefined, `compact=${compact}`);
    assert.deepEqual(Object.keys(answer.body.keys), ["contentKeys"], `compact=${compact}`);
    assert.deepEqual(
      answer.body.keys.contentKeys.map((/** @type {any} */ record) => record.contentName),
      [BODY],
      `compact=${compact}: the grant names bodytext only`,
    );
    await client.applyResponse(page, ISSUER, answer.body);
    assert.equal(utf8Decode(await client.decrypt(page, BODY, ciphertext)), TEXT);
    assert.equal(await client.contentKeyFor(page, SIDE), null, `compact=${compact}`);
  }
});

test("compact grant expiry refuses fresh acquisition while previously held item capability still opens", async () => {
  let instant = NOW;
  const issuer = grantIssuer(() => instant);
  const { client, page, registration, ciphertext } = await render(true);
  let openingReads = 0;
  const opening = registration.openingKeys.get;
  registration.openingKeys.get = () => {
    openingReads++;
    return opening();
  };
  const request = client.buildRequest(page, ISSUER, [BODY]);
  assert.equal(request.envelope, COMPACT_ECDH);
  const exchange = (request) =>
    issuer.unlock({
      document: JSON.stringify(request),
      registration,
      authorization: "Bearer ref",
      observedOrigin: ORIGIN,
    });
  const admitted = await exchange(request);
  assert.equal(admitted.status, 200);
  await client.applyResponse(page, ISSUER, JSON.parse(JSON.stringify(admitted.body)));
  assert.equal(utf8Decode(await client.decrypt(page, BODY, ciphertext)), TEXT);
  assert.equal(openingReads, 1);

  instant = NOW + 60000; // Exact expiry, with the same grant record and issuer.
  const successor = new Client({ publisherOrigin: ORIGIN, relayPeriodKeys: false });
  const nextRequest = successor.buildRequest(page, ISSUER, [BODY]);
  assert.equal(nextRequest.envelope, COMPACT_ECDH);
  const refused = await exchange(nextRequest);
  assert.equal(refused.status, 401);
  assert.equal(refused.body.keys, undefined);
  assert.equal(openingReads, 1, "expiry refuses before opening the compact envelope again");
  assert.equal(await successor.contentKeyFor(page, BODY), null);
  assert.equal(
    utf8Decode(await client.decrypt(page, BODY, ciphertext)),
    TEXT,
    "expiry stops future grants and does not revoke delivered capability",
  );
});
