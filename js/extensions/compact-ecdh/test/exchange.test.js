// @ts-check
//
// The whole compact-ECDH path through the reference roles: a composed publisher
// seals to one issuer with the compact procedure and to another ordinarily, the
// client relays each block's selector, and a composed issuer opens each with
// the procedure its request selects and its key entry permits
// (docs/spec-profile--compact-ecdh.md Sections 2, 3 and 5).

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
import { unlockThroughAdmission } from "../../../test-lib/harnesses/unlockThroughAdmission.js";
import { issuerKeypair, signingKeypair } from "../../../test-reference/support/keys.js";
import { compactEcdhPublisherContribution } from "../core-publisher/keySealing.js";
import { compactEcdhIssuerContribution } from "../core-issuer/procedure.js";
import { COMPACT_ECDH } from "../core-shared--publisher-issuer/selector.js";

const ORIGIN = "https://publisher.example";
const COMPACT = "compact";
const ORDINARY = "ordinary";
const BODY = "body";
const TEXT = "The authorized original content.";

async function world() {
  const signing = await signingKeypair();
  const compactPair = await issuerKeypair("ecdh-p256");
  const ordinaryPair = await issuerKeypair("ecdh-p256");
  /** @type {Record<string, any>} */
  const entries = {
    [`${COMPACT}/k`]: {
      algorithm: "ecdh-p256",
      privateKey: compactPair.privateKey,
      publicKey: compactPair.publicKey,
      envelopes: ["ecdh-p256", COMPACT_ECDH],
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
    { operatingIssuerNames: [COMPACT, ORDINARY], accessPolicy: new AllowAllPolicy() },
    compactEcdhIssuerContribution(),
  );

  /** @param {{ compactSelected?: boolean, seed?: number }} [options] */
  async function render({ compactSelected = true, seed = 1 } = {}) {
    const base = {
      origin: ORIGIN,
      clock: new Clock("2025-10-23T14:20:00Z"),
      random: new Random({ seed }),
      signingKeys: { signing: signing.privateKey },
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: COMPACT,
          keyId: "k",
          algorithm: "ecdh-p256",
          publicKey: compactPair.publicKey,
          ...(compactSelected ? { envelope: COMPACT_ECDH } : {}),
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
      composePublisherConfig(base, compactEcdhPublisherContribution()).config,
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

describe("compact-ECDH exchange", () => {
  test("one delivery carries a compact block and an ordinary block, and each opens", async () => {
    const w = await world();
    const r = await w.render();
    const compact = r.rendered.dcaData.issuerData[COMPACT];
    const ordinary = r.rendered.dcaData.issuerData[ORDINARY];
    assert.equal(compact.envelope, COMPACT_ECDH);
    assert.equal(Object.hasOwn(ordinary, "envelope"), false);
    assert.equal(compact.sealed.contentKeys[BODY].length, 87, "65 octets, unpadded base64url");
    assert.equal(binaryStringBytes(compact.sealed.contentKeys[BODY])?.length, 65);
    assert.equal(binaryStringBytes(ordinary.sealed.contentKeys[BODY])?.length, 109);
    assert.equal(await readThrough(w, r, COMPACT), TEXT);
    assert.equal(await readThrough(w, await w.render({ seed: 2 }), ORDINARY), TEXT);
  });

  test("one key pair and keyId serve a cached ordinary delivery and a compact one", async () => {
    const w = await world();
    const older = await w.render({ compactSelected: false, seed: 3 });
    assert.equal(Object.hasOwn(older.rendered.dcaData.issuerData[COMPACT], "envelope"), false);
    assert.equal(await readThrough(w, older, COMPACT), TEXT);
    assert.equal(await readThrough(w, await w.render({ seed: 4 }), COMPACT), TEXT);
  });

  test("a key entry that permits only compact-ecdh opens no cached ordinary delivery", async () => {
    const w = await world();
    w.entries[`${COMPACT}/k`].envelopes = [COMPACT_ECDH];
    const older = await w.render({ compactSelected: false, seed: 3 });
    const request = older.client.buildRequest(older.page, COMPACT, [BODY]);
    const { status, body } = await w.unlock(request);
    assert.equal(status, 200);
    assert.equal(body.keys?.contentKeys?.[BODY], undefined);
    assert.ok(body.errors?.[BODY]);
    assert.equal(await readThrough(w, await w.render({ seed: 4 }), COMPACT), TEXT);
  });

  test("a key entry that does not permit compact-ecdh opens no compact blob", async () => {
    const w = await world();
    delete w.entries[`${COMPACT}/k`].envelopes;
    const r = await w.render();
    const { status, body } = await w.unlock(r.client.buildRequest(r.page, COMPACT, [BODY]));
    assert.equal(status, 200);
    assert.equal(body.keys?.contentKeys?.[BODY], undefined);
    assert.ok(body.errors?.[BODY]);
  });

  test("a removed, inserted, changed or copied selector opens nothing", async () => {
    const w = await world();
    const compactRender = await w.render();
    const ordinaryRender = await w.render({ compactSelected: false, seed: 5 });
    const compactRequest = compactRender.client.buildRequest(compactRender.page, COMPACT, [BODY]);
    const ordinaryRequest = ordinaryRender.client.buildRequest(ordinaryRender.page, COMPACT, [
      BODY,
    ]);
    const otherIssuer = compactRender.client.buildRequest(compactRender.page, ORDINARY, [BODY]);
    const { envelope: _removed, ...stripped } = compactRequest;
    for (const [label, request] of [
      ["removed", stripped],
      ["inserted", { ...ordinaryRequest, envelope: COMPACT_ECDH }],
      ["changed", { ...compactRequest, envelope: "compact-ecdh-vX" }],
      ["copied to the ordinary issuer", { ...otherIssuer, envelope: COMPACT_ECDH }],
    ]) {
      const { status, body } = await w.unlock(request);
      assert.equal(status, 200, label);
      assert.equal(body.keys?.contentKeys?.[BODY], undefined, label);
      assert.ok(body.errors?.[BODY], label);
    }
  });

  test("an issuer entry permitting compact-ecdh without its public key is an issuer fault", async () => {
    const w = await world();
    delete w.entries[`${COMPACT}/k`].publicKey;
    const r = await w.render();
    const { status } = await w.unlock(r.client.buildRequest(r.page, COMPACT, [BODY]));
    assert.equal(status, 500);
  });

  test("an issuer key entry off P-256 permitting compact-ecdh is an issuer fault", async () => {
    const w = await world();
    const r = await w.render();
    const request = r.client.buildRequest(r.page, COMPACT, [BODY]);
    const rsa = await issuerKeypair("rsa-oaep");
    const p384 = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, false, [
      "deriveBits",
    ]);
    for (const [label, entry] of [
      ["RSA", { algorithm: "rsa-oaep", ...rsa, envelopes: ["rsa-oaep", COMPACT_ECDH] }],
      ["P-384", { algorithm: "ecdh-p256", ...p384, envelopes: [COMPACT_ECDH] }],
    ]) {
      w.entries[`${COMPACT}/k`] = entry;
      const { status, body } = await w.unlock(request);
      assert.equal(status, 500, String(label));
      assert.equal(body.keys, undefined, String(label));
    }
  });

  test("an RSA entry permitting compact-ecdh is refused where the issuer reads it", async () => {
    // The request omits `envelope`, so it never selects compact-ecdh. The
    // procedure opens under ECDH P-256 keys only, and the issuer refuses the
    // entry before any envelope opens.
    const w = await world();
    const r = await w.render({ compactSelected: false });
    const request = r.client.buildRequest(r.page, COMPACT, [BODY]);
    assert.equal(request.envelope, undefined);
    const rsa = await issuerKeypair("rsa-oaep");
    w.entries[`${COMPACT}/k`] = {
      algorithm: "rsa-oaep",
      ...rsa,
      envelopes: ["rsa-oaep", COMPACT_ECDH],
    };
    const { status, body } = await w.unlock(request);
    assert.equal(status, 500);
    assert.equal(body.keys, undefined);
  });

  test("the publisher refuses a compact selection for an RSA issuer key", async () => {
    const signing = await signingKeypair();
    const rsa = await issuerKeypair("rsa-oaep");
    const base = {
      origin: ORIGIN,
      clock: new Clock("2025-10-23T14:20:00Z"),
      random: new Random({ seed: 6 }),
      signingKeys: { signing: signing.privateKey },
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: COMPACT,
          keyId: "k",
          algorithm: "rsa-oaep",
          publicKey: rsa.publicKey,
          envelope: COMPACT_ECDH,
        },
      ],
    };
    const sealer = new Sealer(
      composePublisherConfig(base, compactEcdhPublisherContribution()).config,
    );
    sealer.resource("resource", {});
    sealer.content(BODY, TEXT, "text/plain");
    await assert.rejects(() => sealer.seal(), { code: "bad_config" });

    // A P-256 key registered under another procedure is still not an
    // ecdh-p256 registration: the issuer opens it with that other procedure.
    const p256 = await issuerKeypair("ecdh-p256");
    const misregistered = {
      ...base,
      random: new Random({ seed: 7 }),
      issuers: [{ ...base.issuers[0], publicKey: p256.publicKey }],
    };
    const second = new Sealer(
      composePublisherConfig(misregistered, compactEcdhPublisherContribution()).config,
    );
    second.resource("resource", {});
    second.content(BODY, TEXT, "text/plain");
    await assert.rejects(() => second.seal(), { code: "bad_config" });
  });
});

test("period keys in a compact block are compact envelopes the issuer opens", async () => {
  const { randomPeriodKeySupply } = await import("../../../demo/support/randomPeriodKeySupply.js");
  const { DcaData } = await import("../../../core-client/DcaData.js");
  const { DcaRequestBuilder } = await import("../../../core-client/DcaRequestBuilder.js");
  const signing = await signingKeypair();
  const pair = await issuerKeypair("ecdh-p256");
  const base = {
    origin: ORIGIN,
    clock: new Clock("2025-10-23T14:20:00Z"),
    random: new Random({ seed: 8 }),
    signingKeys: { signing: signing.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    periodKeySupply: randomPeriodKeySupply(),
    issuers: [
      {
        issuerName: COMPACT,
        keyId: "k",
        algorithm: "ecdh-p256",
        publicKey: pair.publicKey,
        envelope: COMPACT_ECDH,
      },
    ],
  };
  const sealer = new Sealer(
    composePublisherConfig(base, compactEcdhPublisherContribution()).config,
  );
  sealer.resource("resource", {});
  sealer.content(BODY, TEXT, "text/plain", { accessGroups: ["premium"] });
  const { dcaData } = await sealer.seal();
  const periods = dcaData.issuerData[COMPACT].sealed.periodKeys.premium;
  assert.ok(Object.keys(periods).length > 0);
  for (const blob of Object.values(periods)) assert.equal(binaryStringBytes(blob)?.length, 65);

  const core = createIssuerCore(
    {
      operatingIssuerNames: [COMPACT],
      accessPolicy: new AllowAllPolicy(),
      periodKeyInput: true,
    },
    compactEcdhIssuerContribution(),
  );
  const entry = {
    algorithm: "ecdh-p256",
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    envelopes: [COMPACT_ECDH],
  };
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    origin: ORIGIN,
    openingKeys: { get: () => entry },
  };
  const request = new DcaRequestBuilder({ relayPeriodKeys: true })
    .build(new DcaData(dcaData), COMPACT, [BODY])
    .toObject();
  assert.equal(request.envelope, COMPACT_ECDH);
  const { status, body } = await unlockThroughAdmission(
    core.processor,
    core.endpoint,
    request,
    registration,
  );
  assert.equal(status, 200);
  assert.equal(body.errors, undefined);
  assert.ok(Object.keys(body.keys?.periodKeys?.premium ?? {}).length > 0, JSON.stringify(body));
});

test("a compact blob copied to another item's coordinate opens nothing", async () => {
  const signing = await signingKeypair();
  const pair = await issuerKeypair("ecdh-p256");
  const base = {
    origin: ORIGIN,
    clock: new Clock("2025-10-23T14:20:00Z"),
    random: new Random({ seed: 13 }),
    signingKeys: { signing: signing.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: COMPACT,
        keyId: "k",
        algorithm: "ecdh-p256",
        publicKey: pair.publicKey,
        envelope: COMPACT_ECDH,
      },
    ],
  };
  const sealer = new Sealer(
    composePublisherConfig(base, compactEcdhPublisherContribution()).config,
  );
  sealer.resource("resource", {});
  sealer.content(BODY, TEXT, "text/plain");
  sealer.content("summary", "Short.", "text/plain");
  const rendered = await sealer.seal();
  const client = new Client({ publisherOrigin: ORIGIN });
  const page = client.parse({ ...rendered.dcaData, sealedContent: rendered.sealedContent });
  const request = client.buildRequest(page, COMPACT, [BODY, "summary"]);
  const keys = request.sealed.contentKeys;
  const swapped = {
    ...request,
    sealed: { ...request.sealed, contentKeys: { [BODY]: keys.summary, summary: keys[BODY] } },
  };
  const core = createIssuerCore(
    { operatingIssuerNames: [COMPACT], accessPolicy: new AllowAllPolicy() },
    compactEcdhIssuerContribution(),
  );
  const entry = {
    algorithm: "ecdh-p256",
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    envelopes: [COMPACT_ECDH],
  };
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    origin: ORIGIN,
    openingKeys: { get: () => entry },
  };
  const unlock = (/** @type {any} */ sent) =>
    unlockThroughAdmission(core.processor, core.endpoint, sent, registration);
  const honest = await unlock(request);
  assert.equal(honest.body.errors, undefined);
  const { status, body } = await unlock(swapped);
  assert.equal(status, 200);
  assert.equal(body.keys?.contentKeys?.[BODY], undefined);
  assert.equal(body.keys?.contentKeys?.summary, undefined);
  assert.ok(body.errors?.[BODY] && body.errors?.summary);
});
