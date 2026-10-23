// Experiment-owned integration tests; setup follows compact-ecdh/test/exchange.test.js.
import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { composePublisherConfig } from "../../../core-publisher/publisherComposition.js";
import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { issuerBlockOf, recordNamed } from "../../../test-lib/helpers/inspect.js";
import { unlockThroughAdmission } from "../../../test-lib/harnesses/unlockThroughAdmission.js";
import { issuerKeypair, signingKeypair } from "../../../test-reference/support/keys.js";
import { nonceFreeEnvelopePublisherContribution } from "../core-publisher/keySealing.js";
import { nonceFreeEnvelopeIssuerContribution } from "../core-issuer/procedure.js";
import { NONCE_FREE_ENVELOPE } from "../core-shared--publisher-issuer/envelope.js";

const ORIGIN = "https://publisher.example";
const EXPERIMENTAL = "experimental";
const ORDINARY = "ordinary";
const BODY = "body";
const TEXT = "The authorized original content.";
const contentRecord = (records) => recordNamed(records, "contentName", BODY);
const errorAt = (body) => recordNamed(body.errors, "coordinate", BODY);

async function world() {
  const signing = await signingKeypair();
  const experimentalPair = await issuerKeypair("ecdh-p256");
  const ordinaryPair = await issuerKeypair("ecdh-p256");
  /** @type {Record<string, any>} */
  const entries = {
    [`${EXPERIMENTAL}/k`]: {
      algorithm: "ecdh-p256",
      privateKey: experimentalPair.privateKey,
      publicKey: experimentalPair.publicKey,
      envelopes: ["ecdh-p256", NONCE_FREE_ENVELOPE],
    },
    [`${ORDINARY}/k`]: { algorithm: "ecdh-p256", privateKey: ordinaryPair.privateKey },
  };
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    origin: ORIGIN,
    openingKeys: {
      get: (/** @type {string} */ i, /** @type {string} */ k) => entries[`${i}/${k}`],
    },
  };
  const core = createIssuerCore(
    { operatingIssuerNames: [EXPERIMENTAL, ORDINARY], accessPolicy: new AllowAllPolicy() },
    nonceFreeEnvelopeIssuerContribution(),
  );

  /** @param {{ experimentalSelected?: boolean, seed?: number }} [options] */
  async function render({ experimentalSelected = true, seed = 1 } = {}) {
    const base = {
      origin: ORIGIN,
      clock: new Clock("2025-10-23T14:20:00Z"),
      random: new Random({ seed }),
      signingKeys: { signing: signing.privateKey },
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: EXPERIMENTAL,
          keyId: "k",
          algorithm: "ecdh-p256",
          publicKey: experimentalPair.publicKey,
          ...(experimentalSelected ? { envelope: NONCE_FREE_ENVELOPE } : {}),
        },
        {
          issuerName: ORDINARY,
          keyId: "k",
          algorithm: "ecdh-p256",
          publicKey: ordinaryPair.publicKey,
        },
      ],
    };
    const sealer = new Sealer(
      composePublisherConfig(base, nonceFreeEnvelopePublisherContribution()).config,
    );
    sealer.resource("resource", {});
    sealer.content(BODY, TEXT, "text/plain");
    const rendered = await sealer.seal();
    const client = new Client({ publisherOrigin: ORIGIN });
    const page = client.parse({ ...rendered.dcaData, sealedContent: rendered.sealedContent });
    return { rendered, client, page, ciphertext: rendered.sealedContent[BODY] };
  }

  /** @param {any} request */
  const unlock = (request) =>
    unlockThroughAdmission(core.processor, core.endpoint, request, registration);

  return { entries, render, unlock };
}

/**
 * @param {Awaited<ReturnType<typeof world>>} w
 * @param {Awaited<ReturnType<Awaited<ReturnType<typeof world>>["render"]>>} r
 * @param {string} issuer
 */
async function readThrough(w, r, issuer) {
  const request = r.client.buildRequest(r.page, issuer, [BODY]);
  const { status, body } = await w.unlock(request);
  assert.equal(status, 200, issuer);
  assert.equal(body.errors, undefined, issuer);
  await r.client.applyResponse(r.page, issuer, body);
  return new TextDecoder().decode(await r.client.decrypt(r.page, BODY, r.ciphertext));
}

describe("nonce-free envelope contribution exchange", () => {
  test("publisher, client relay and issuer procedures deliver a usable content key", async () => {
    const w = await world();
    const r = await w.render();
    const candidate = issuerBlockOf(r.rendered.dcaData, EXPERIMENTAL);
    assert.equal(candidate.envelope, NONCE_FREE_ENVELOPE);
    assert.equal(binaryStringBytes(contentRecord(candidate.sealed.contentKeys).key)?.length, 97);
    assert.equal(
      binaryStringBytes(
        contentRecord(issuerBlockOf(r.rendered.dcaData, ORDINARY).sealed.contentKeys).key,
      )?.length,
      97,
    );
    assert.equal(await readThrough(w, r, EXPERIMENTAL), TEXT);
    assert.equal(await readThrough(w, await w.render({ seed: 2 }), ORDINARY), TEXT);
  });

  test("ordinary selection opens the adopted carrier, unknown selection and unpermitted experiment refuse", async () => {
    const w = await world();
    const r = await w.render();
    const request = r.client.buildRequest(r.page, EXPERIMENTAL, [BODY]);
    const { envelope: _removed, ...stripped } = request;
    // Ordinary core adopted the same carrier and BIND; removing the prototype
    // selector now names that ordinary procedure, rather than a layout fallback.
    const ordinary = await w.unlock(stripped);
    assert.equal(ordinary.status, 200);
    assert.equal(ordinary.body.errors, undefined);
    assert.ok(contentRecord(ordinary.body.keys.contentKeys)?.key);
    await r.client.applyResponse(r.page, EXPERIMENTAL, ordinary.body);
    assert.equal(
      new TextDecoder().decode(await r.client.decrypt(r.page, BODY, r.ciphertext)),
      TEXT,
    );

    const unknown = await w.unlock({ ...request, envelope: "unknown-experiment" });
    assert.equal(contentRecord(unknown.body.keys?.contentKeys), undefined);
    assert.ok(errorAt(unknown.body));
    delete w.entries[`${EXPERIMENTAL}/k`].envelopes;
    const { body } = await w.unlock(request);
    assert.equal(contentRecord(body.keys?.contentKeys), undefined);
    assert.ok(errorAt(body));
  });

  test("a same-coordinate blob sealed for another recipient is refused", async () => {
    const w = await world();
    const r = await w.render();
    assert.equal(
      await readThrough(w, r, ORDINARY),
      TEXT,
      "the source recipient opens its own envelope",
    );
    const request = r.client.buildRequest(r.page, EXPERIMENTAL, [BODY]);
    contentRecord(request.sealed.contentKeys).key = contentRecord(
      issuerBlockOf(r.rendered.dcaData, ORDINARY).sealed.contentKeys,
    ).key;
    const { status, body } = await w.unlock(request);
    assert.equal(status, 200);
    assert.equal(contentRecord(body.keys?.contentKeys), undefined);
    assert.ok(errorAt(body));
  });

  test("a blob copied from another render fails at the issuer's reconstructed BIND", async () => {
    const w = await world();
    const original = await w.render({ seed: 11 });
    const other = await w.render({ seed: 12 });
    const request = other.client.buildRequest(other.page, EXPERIMENTAL, [BODY]);
    const copied = original.client.buildRequest(original.page, EXPERIMENTAL, [BODY]);
    contentRecord(request.sealed.contentKeys).key = contentRecord(copied.sealed.contentKeys).key;
    const { status, body } = await w.unlock(request);
    assert.equal(status, 200);
    assert.equal(contentRecord(body.keys?.contentKeys), undefined);
    assert.ok(errorAt(body));
  });
});
