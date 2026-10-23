// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { createRecipientGrantIssuer } from "../issuer.js";
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { issuerKeypair, signingKeypair } from "../../../test-reference/support/keys.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import { requestFor } from "../../../test-lib/harnesses/issuer-endpoint.js";
import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import {
  world,
  ARTICLE_GROUP,
  BODYTEXT,
  PREMIUM,
  ISSUER_NAME,
  PUBLISHER_ORIGIN,
} from "../../../test-lib/fixtures/endpoint-hardening-world.js";
import { sealedContentOf } from "../../../test-lib/helpers/inspect.js";
import { keyAt } from "../../../test-reference/support/namedRecords.js";

const NOW = Date.parse("2025-10-23T14:20:00Z");
const REFERENCE = "opaque-issuer-reference";

function grant(overrides = {}) {
  return {
    purpose: "recipient-unlock",
    issuerId: "issuer-a",
    publisherRegistrationId: "publisher-one",
    resourceId: "123456",
    contentNames: [BODYTEXT],
    notBeforeMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000,
    revoked: false,
    ...overrides,
  };
}

async function fixture(
  overrides = {},
  denyCurrentPolicy = false,
  operatingIssuerNames = [ISSUER_NAME],
  issuerOptions = {},
) {
  const w = await world();
  const page = await w.render();
  const calls = { lookup: 0, policy: 0, opening: 0 };
  const registration = {
    ...w.publisherRegistration,
    registrationId: "publisher-one",
    origins: [PUBLISHER_ORIGIN],
    openingKeys: {
      async get(...args) {
        calls.opening++;
        return w.publisherRegistration.openingKeys.get(...args);
      },
    },
  };
  const policy = {
    decide(_claims, requested) {
      calls.policy++;
      return { contentNames: denyCurrentPolicy ? [] : requested.contentNames, periodGrants: [] };
    },
  };
  const issuer = createRecipientGrantIssuer({
    ...issuerOptions,
    operatingIssuerNames,
    issuerId: "issuer-a",
    grants: {
      get() {
        calls.lookup++;
        return grant(overrides);
      },
    },
    accessPolicy: policy,
    now: () => NOW,
  });
  const request = (names = [BODYTEXT]) => {
    const contentKeyOnly = JSON.parse(JSON.stringify(requestFor(page, ISSUER_NAME, names)));
    delete contentKeyOnly.sealed.periodKeys;
    delete contentKeyOnly.sealed.chainKeys;
    return JSON.stringify(contentKeyOnly);
  };
  const unlock = (input = {}) =>
    issuer.unlock({
      document: request(),
      registration,
      authorization: `Bearer ${REFERENCE}`,
      observedOrigin: PUBLISHER_ORIGIN,
      ...input,
    });
  return { w, page, calls, issuer, registration, request, unlock };
}

test("recipient grant opens only an admitted current-render named item", async () => {
  const { unlock, calls } = await fixture();
  const answer = await unlock();
  assert.equal(answer.status, 200);
  assert.ok(keyAt(answer.body.keys.contentKeys, { contentName: BODYTEXT }));
  assert.equal(answer.body.keys.periodKeys, undefined);
  assert.equal(answer.body.keys.chainKeys, undefined);
  assert.deepEqual(calls, { lookup: 1, policy: 1, opening: 1 });
  const nonBrowser = await unlock({ observedOrigin: undefined });
  assert.equal(nonBrowser.status, 200);
  assert.ok(keyAt(nonBrowser.body.keys.contentKeys, { contentName: BODYTEXT }));
  assert.deepEqual(calls, { lookup: 2, policy: 2, opening: 2 });
});

test("explicit nonfinite or nonnumeric capture instants refuse before grant lookup", async () => {
  const { unlock, calls } = await fixture();
  for (const capturedAtMs of [null, "123", NaN, Infinity, -Infinity]) {
    await assert.rejects(unlock({ capturedAtMs }), { code: "bad_config" });
  }
  assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });
});

test("a valid recipient grant cannot override current policy denial", async () => {
  const { unlock, calls } = await fixture({}, true);
  const answer = await unlock();
  assert.equal(answer.status, 401);
  assert.equal(answer.body.keys, undefined);
  assert.deepEqual(calls, { lookup: 1, policy: 1, opening: 0 });
});

test("publisher and Origin admission precede grant lookup", async () => {
  const { unlock, calls, request, registration } = await fixture();
  const wrongOrigin = await unlock({ observedOrigin: "https://other.example" });
  assert.equal(wrongOrigin.status, 400);
  assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });
  const excludedOrigin = await unlock({
    registration: { ...registration, origins: ["https://other.example"] },
  });
  assert.equal(excludedOrigin.status, 400);
  assert.equal(excludedOrigin.body.keys, undefined);
  assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });

  const changed = JSON.parse(request());
  changed.resourceJWT += "x";
  const wrongSignature = await unlock({ document: JSON.stringify(changed) });
  assert.equal(wrongSignature.status, 400);
  assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });
});

test("wrong audience, publisher, resource, expiry and revocation refuse before policy or key", async () => {
  for (const bad of [
    { issuerId: "issuer-b" },
    { publisherRegistrationId: "other" },
    { resourceId: "other" },
    { expiresAtMs: NOW },
    { notBeforeMs: NOW + 1 },
    { revoked: true },
    { purpose: "issuance" },
  ]) {
    const { unlock, calls } = await fixture(bad);
    const answer = await unlock();
    assert.equal(answer.status, 401, JSON.stringify(bad));
    assert.equal(answer.body.keys, undefined);
    assert.equal(calls.lookup, 1);
    assert.equal(calls.policy, 0);
    assert.equal(calls.opening, 0);
  }
});

test("scope intersects presented names and current issuer policy", async () => {
  const { unlock, calls, request } = await fixture();
  const mixed = await unlock({ document: request([BODYTEXT, PREMIUM]) });
  assert.equal(mixed.status, 200);
  assert.ok(keyAt(mixed.body.keys.contentKeys, { contentName: BODYTEXT }));
  assert.equal(keyAt(mixed.body.keys.contentKeys, { contentName: PREMIUM }), undefined);
  assert.equal(calls.opening, 1);

  const ungranted = await unlock({ document: request([PREMIUM]) });
  assert.equal(ungranted.status, 401);
  assert.equal(calls.opening, 1);
});

test("an issuer contribution adds envelope procedures only, never another grant mechanism", () => {
  const config = {
    operatingIssuerNames: [ISSUER_NAME],
    issuerId: "issuer-a",
    grants: { get: () => null },
    accessPolicy: { decide: () => ({}) },
    now: () => NOW,
  };
  const procedures = { "invented-procedure": async () => new Uint8Array(16) };
  assert.ok(
    createRecipientGrantIssuer(config, { name: "invented", envelopeProcedures: procedures }),
  );

  // A response section source would answer a second key family beside the
  // item keys, and a coordinate reading or bound would change what the grant
  // endpoint admits. The item-only grant scope admits none of them.
  const source = {
    name: "wider",
    members: ["widerKeys"],
    envelopeOpeners: {},
    presented: () => true,
    respond: async () => ({ widerKeys: {} }),
  };
  const sections = [{ path: ["widerKeys"], depth: 1, keyKind: "contentKey" }];
  for (const widening of [
    { name: "wider", responseSectionSource: source, responseSections: sections },
    { name: "wider", responseSectionSource: source },
    { name: "wider", responseSections: sections },
    { name: "wider", extensionCoordinate: () => true },
    { name: "wider", requestBounds: [] },
    { name: "invented", envelopeProcedures: procedures, extensionCoordinate: () => true },
    { envelopeProcedures: procedures },
    null,
  ]) {
    assert.throws(
      () => createRecipientGrantIssuer(config, /** @type {any} */ (widening)),
      { code: "bad_config" },
      JSON.stringify(widening && Object.keys(widening)),
    );
  }
});

test("period input and invalid header are whole-request refusals", async () => {
  const { unlock, calls, request } = await fixture();
  const malformed = await unlock({ authorization: ["Bearer one", "Bearer two"] });
  assert.equal(malformed.status, 401);
  // An empty record array is a present section: presence alone refuses.
  for (const section of ["periodKeys", "chainKeys"]) {
    const candidate = JSON.parse(request());
    candidate.sealed[section] = [];
    const answer = await unlock({ document: JSON.stringify(candidate) });
    assert.equal(answer.status, 400, section);
  }
  for (const section of ["periodGeometry", "chainGeometry", "requestedPeriodKeys"]) {
    const candidate = JSON.parse(request());
    candidate[section] = section === "requestedPeriodKeys" ? [] : {};
    const answer = await unlock({ document: JSON.stringify(candidate) });
    assert.equal(answer.status, 400, section);
  }
  assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });
});

test("chain-key input is a whole-request refusal before grant lookup", async () => {
  const { unlock, calls, request, page } = await fixture();
  // A chain-key relay adds explicit geometry and one positioned sealed chain
  // key per access group. The blob is a real issuer envelope from this render.
  const relayed = JSON.parse(JSON.stringify(requestFor(page, ISSUER_NAME, [BODYTEXT])));
  const { key: periodEnvelope } = relayed.sealed.periodKeys.find(
    (/** @type {any} */ record) => record.accessGroup === ARTICLE_GROUP,
  );
  const chain = JSON.parse(request());
  chain.periodGeometry = { chainsPerDay: 2, periodMinutes: 15 };
  chain.sealed.chainKeys = [
    { accessGroup: ARTICLE_GROUP, cutoff: "251023T2345", key: periodEnvelope },
  ];
  const document = JSON.stringify(chain);
  // The base processor admits these bytes, so the refusal below is the grant
  // rule and not byte parsing.
  const { processor } = createIssuerCore({
    operatingIssuerNames: [ISSUER_NAME],
    accessPolicy: { decide: () => ({}) },
  });
  assert.equal(processor.admit(document).kind, "admitted");

  const answer = await unlock({ document });
  assert.equal(answer.status, 400);
  assert.deepEqual(answer.body, { error: "binding_failed" });
  assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });

  // The same signed request without the chain member opens under this grant.
  const plain = await unlock();
  assert.equal(plain.status, 200);
  assert.deepEqual(calls, { lookup: 1, policy: 1, opening: 1 });
});

test("grant presentation checks the one admitted request value, so one initial BOM opens like base", async () => {
  const { unlock, calls, request, issuer, registration } = await fixture();
  // Base admission ignores exactly one initial U+FEFF (data format Section 2);
  // the grant rule must read that same parsed value, not reparse the bytes.
  const bom = await unlock({ document: `\uFEFF${request()}` });
  assert.equal(bom.status, 200);
  assert.ok(keyAt(bom.body.keys.contentKeys, { contentName: BODYTEXT }));
  assert.deepEqual(calls, { lookup: 1, policy: 1, opening: 1 });

  const browser = issuer.browserHttp((origin) => origin === PUBLISHER_ORIGIN);
  const viaHttp = await browser.handle({
    method: "POST",
    contentType: "application/json",
    origin: PUBLISHER_ORIGIN,
    body: `\uFEFF${request()}`,
    authorization: `Bearer ${REFERENCE}`,
    hostContext: { registration },
  });
  assert.equal(viaHttp.status, 200);
  assert.deepEqual(calls, { lookup: 2, policy: 2, opening: 2 });

  // Two BOMs stay a parse refusal, and a BOM does not hide an explicit empty
  // forbidden member from the presence check.
  const doubled = await unlock({ document: `\uFEFF\uFEFF${request()}` });
  assert.equal(doubled.status, 400);
  for (const [where, section] of [
    ["sealed", "periodKeys"],
    ["sealed", "chainKeys"],
    ["top", "periodGeometry"],
    ["top", "chainGeometry"],
    ["top", "requestedPeriodKeys"],
  ]) {
    const candidate = JSON.parse(request());
    // Carriers are empty record arrays and geometries empty objects: each is
    // present and well formed, so only the presence check can refuse it.
    (where === "sealed" ? candidate.sealed : candidate)[section] = section.endsWith("Keys")
      ? []
      : {};
    const answer = await unlock({ document: `\uFEFF${JSON.stringify(candidate)}` });
    assert.deepEqual(answer, { status: 400, body: { error: "binding_failed" } }, section);
  }
  assert.deepEqual(calls, { lookup: 2, policy: 2, opening: 2 });
});

test("browser composition verifies signed origin before CORS and grant lookup", async () => {
  const { issuer, registration, request, calls } = await fixture();
  const browser = issuer.browserHttp((origin) => origin === PUBLISHER_ORIGIN);
  const preflight = await browser.handle({ method: "OPTIONS", origin: PUBLISHER_ORIGIN });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers["access-control-allow-headers"], "content-type, authorization");
  assert.equal(preflight.headers["access-control-allow-credentials"], undefined);

  for (const [origin, selectedRegistration] of [
    ["https://other.example", registration],
    ["https://other.example", { ...registration, origins: undefined }],
    [PUBLISHER_ORIGIN, { ...registration, origins: ["https://other.example"] }],
  ]) {
    const bad = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin,
      body: request(),
      authorization: `Bearer ${REFERENCE}`,
      hostContext: { registration: selectedRegistration },
    });
    assert.equal(bad.status, 400);
    assert.equal(bad.headers["access-control-allow-origin"], undefined);
    assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });
  }

  const good = await browser.handle({
    method: "POST",
    contentType: "application/json",
    origin: PUBLISHER_ORIGIN,
    body: request(),
    authorization: `Bearer ${REFERENCE}`,
    hostContext: { registration },
  });
  assert.equal(good.status, 200);
  assert.equal(good.headers["access-control-allow-origin"], PUBLISHER_ORIGIN);
  assert.deepEqual(calls, { lookup: 1, policy: 1, opening: 1 });
});

test("direct and browser grants reuse their request's verified publisher claims", async (t) => {
  const { unlock, issuer, registration, request, calls } = await fixture();
  const verification = t.mock.method(crypto.subtle, "verify");
  assert.equal(
    (await unlock({ verification: { resource: { resourceId: "forged" } } })).status,
    200,
  );
  assert.equal(
    verification.mock.callCount(),
    1,
    "direct grant ignores supplied claims and verifies once",
  );
  const answer = await issuer
    .browserHttp(() => true)
    .handle({
      method: "POST",
      contentType: "application/json",
      origin: PUBLISHER_ORIGIN,
      body: request(),
      authorization: `Bearer ${REFERENCE}`,
      hostContext: { registration },
    });
  assert.equal(answer.status, 200);
  assert.equal(verification.mock.callCount(), 2, "browser admission hands off its verification");
  assert.deepEqual(calls, { lookup: 2, policy: 2, opening: 2 });
});

test("public grant calls cannot replace signed resource claims with supplied verification", async () => {
  const { unlock, calls } = await fixture({ resourceId: "grant-only-resource" });
  const answer = await unlock({
    verification: { resource: { resourceId: "grant-only-resource", origin: PUBLISHER_ORIGIN } },
  });
  assert.equal(answer.status, 401);
  assert.equal(answer.body.keys, undefined);
  assert.deepEqual(calls, { lookup: 1, policy: 0, opening: 0 });
});

test("recipient-grant uniform disclosure covers direct and browser refusals", async () => {
  const { unlock, issuer, registration, request, calls } = await fixture({}, false, [ISSUER_NAME], {
    errorDetail: "uniform",
  });
  assert.deepEqual(await unlock({ document: "{" }), {
    status: 400,
    body: { error: "rejected" },
  });
  const browser = issuer.browserHttp(() => true);
  const answer = await browser.handle({
    method: "POST",
    contentType: "application/json",
    origin: "https://other.example",
    body: request(),
    authorization: `Bearer ${REFERENCE}`,
    hostContext: { registration },
  });
  assert.equal(answer.status, 400);
  assert.deepEqual(answer.body, { error: "rejected" });
  const missingBearer = await browser.handle({
    method: "POST",
    contentType: "application/json",
    origin: PUBLISHER_ORIGIN,
    body: request(),
    hostContext: { registration },
  });
  assert.equal(missingBearer.status, 401);
  assert.deepEqual(missingBearer.body, { error: "rejected" });
  assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });
});

test("a live grant survives signing-key rotation inside one registration but refuses another registration", async () => {
  const opening = await issuerKeypair();
  const oldSigning = await signingKeypair();
  const newSigning = await signingKeypair();
  const calls = { lookup: 0, policy: 0, opening: 0 };
  const issuer = createRecipientGrantIssuer({
    operatingIssuerNames: [ISSUER_NAME],
    issuerId: "issuer-a",
    grants: {
      get: () => {
        calls.lookup++;
        return grant();
      },
    },
    accessPolicy: {
      decide: (_claims, requested) => {
        calls.policy++;
        return { contentNames: requested.contentNames, periodGrants: [] };
      },
    },
    now: () => NOW,
  });
  const openingKeys = {
    get() {
      calls.opening++;
      return { algorithm: "ecdh-p256", privateKey: opening.privateKey };
    },
  };
  async function attempt(kid, signing, registrationId, value) {
    const publisher = createPublisher({
      origin: PUBLISHER_ORIGIN,
      clock: { now: () => new Date(NOW) },
      random: { bytes: (n) => crypto.getRandomValues(new Uint8Array(n)) },
      signingKeys: { [kid]: signing.privateKey },
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: "opening-key",
          algorithm: "ecdh-p256",
          publicKey: opening.publicKey,
        },
      ],
      issuerSupplyPlanFor: (_issuer, render) => ({
        contentKeyNames: render.contentNames,
        suppliedAccessGroups: [],
      }),
    });
    const render = await publisher.publish({
      resourceId: "123456",
      data: {},
      items: [{ name: BODYTEXT, value, contentType: "text/plain", accessGroups: [] }],
    });
    const document = JSON.stringify(
      new DcaRequestBuilder()
        .build(new DcaData(render.dcaData, { publisherOrigin: PUBLISHER_ORIGIN }), ISSUER_NAME, [
          BODYTEXT,
        ])
        .toObject(),
    );
    return issuer.unlock({
      document,
      registration: { registrationId, kid, publicKey: signing.publicKey, openingKeys },
      authorization: `Bearer ${REFERENCE}`,
      observedOrigin: PUBLISHER_ORIGIN,
    });
  }

  const before = await attempt("old-signing", oldSigning, "publisher-one", "first render");
  assert.equal(before.status, 200);
  const after = await attempt("new-signing", newSigning, "publisher-one", "later render");
  assert.equal(after.status, 200);
  assert.deepEqual(calls, { lookup: 2, policy: 2, opening: 2 });

  const other = await attempt("new-signing", newSigning, "publisher-two", "other registration");
  assert.equal(other.status, 401);
  assert.deepEqual(calls, { lookup: 3, policy: 2, opening: 2 });
  const missing = await attempt("new-signing", newSigning, "", "missing identity");
  assert.equal(missing.status, 400);
  assert.deepEqual(calls, { lookup: 3, policy: 2, opening: 2 });
});

test("selected bearer admits scheme case and spaces but refuses combined or parameter credentials", async () => {
  for (const authorization of [`bearer ${REFERENCE}`, `bEaReR   ${REFERENCE}`]) {
    const { unlock, calls } = await fixture();
    assert.equal((await unlock({ authorization })).status, 200);
    assert.equal(calls.lookup, 1);
  }
  for (const authorization of [
    "Bearer a:b",
    "Bearer a=b",
    "Bearer a,b",
    "Bearer token=abc",
    "Bearer a b",
    "Bearer a\n",
    "Bearer\ta",
    "Basic a",
    "Bearer ",
    ["Bearer a", "Bearer b"],
  ]) {
    const { unlock, calls } = await fixture();
    assert.equal((await unlock({ authorization })).status, 401);
    assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });
  }
});

test("a registration key of the wrong kind is the issuer's fault, not the request's bad_signature", async () => {
  const { unlock, calls, registration, issuer, request } = await fixture();
  const raw = await crypto.subtle.exportKey("raw", registration.publicKey);
  const ecdh = await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [],
  );
  await assert.rejects(unlock({ registration: { ...registration, publicKey: ecdh } }), {
    code: "bad_config",
  });
  await assert.rejects(unlock({ registration: { ...registration, openingKeys: {} } }), {
    code: "bad_config",
  });
  assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });

  // Through the browser composition the same fault is an owned 5xx without CORS.
  const browser = issuer.browserHttp((origin) => origin === PUBLISHER_ORIGIN);
  const viaHttp = await browser.handle({
    method: "POST",
    contentType: "application/json",
    origin: PUBLISHER_ORIGIN,
    body: request(),
    authorization: `Bearer ${REFERENCE}`,
    hostContext: { registration: { ...registration, publicKey: ecdh } },
  });
  assert.equal(viaHttp.status, 500);
  assert.equal(viaHttp.headers["access-control-allow-origin"], undefined);
  assert.equal(viaHttp.headers["cache-control"], "no-store");
  assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });

  // A right-kind key that did not sign stays the request's refusal.
  const stranger = await signingKeypair();
  const answer = await unlock({ registration: { ...registration, publicKey: stranger.publicKey } });
  assert.deepEqual(answer, { status: 400, body: { error: "bad_signature" } });
  const invalidSignature = await browser.handle({
    method: "POST",
    contentType: "application/json",
    origin: PUBLISHER_ORIGIN,
    body: request(),
    authorization: `Bearer ${REFERENCE}`,
    hostContext: { registration: { ...registration, publicKey: stranger.publicKey } },
  });
  assert.equal(invalidSignature.status, 400);
  assert.deepEqual(invalidSignature.body, { error: "bad_signature" });
  assert.equal(invalidSignature.headers["access-control-allow-origin"], undefined);
  assert.deepEqual(calls, { lookup: 0, policy: 0, opening: 0 });
});

test("signed resource A controls grant scope despite an unsigned diagnostic resource B", async () => {
  const resourceB = "other-resource";
  const refused = await fixture({ resourceId: resourceB });
  const request = JSON.parse(refused.request());
  request.resource = { ...refused.page.resource, resourceId: resourceB };
  const answer = await refused.unlock({ document: JSON.stringify(request) });
  assert.equal(answer.status, 401);
  assert.equal(answer.body.keys, undefined);
  assert.deepEqual(refused.calls, { lookup: 1, policy: 0, opening: 0 });

  const allowed = await fixture();
  const client = new Client({ publisherOrigin: PUBLISHER_ORIGIN, relayPeriodKeys: false });
  const page = client.parse(allowed.page);
  const control = client.buildRequest(page, ISSUER_NAME, [BODYTEXT]);
  control.resource = { ...allowed.page.resource, resourceId: resourceB };
  const admitted = await allowed.unlock({ document: JSON.stringify(control) });
  assert.equal(admitted.status, 200);
  await client.applyResponse(page, ISSUER_NAME, JSON.parse(JSON.stringify(admitted.body)));
  assert.equal(
    utf8Decode(await client.decrypt(page, BODYTEXT, sealedContentOf(allowed.page, BODYTEXT))),
    "<p>The council voted 7-2 to rezone the harbour.</p>",
  );
  assert.deepEqual(allowed.calls, { lookup: 1, policy: 1, opening: 1 });
});

test("an admitted unsigned issuer alias cannot select a different grant audience", async () => {
  const otherIssuer = "issuer-b";
  const configured = await fixture({ issuerId: otherIssuer }, false, [ISSUER_NAME, otherIssuer]);
  const request = JSON.parse(configured.request());
  request.issuerName = otherIssuer;
  const answer = await configured.unlock({ document: JSON.stringify(request) });
  assert.equal(answer.status, 401);
  assert.equal(answer.body.keys, undefined);
  assert.deepEqual(configured.calls, { lookup: 1, policy: 0, opening: 0 });
});

test("opaque records admit only content names without imposing signed-form array bounds", async () => {
  for (const badName of ["bad|name", "bad name", "bad\nname", "x".repeat(65)]) {
    const { unlock, calls } = await fixture({ contentNames: [BODYTEXT, badName] });
    assert.equal((await unlock()).status, 401);
    assert.deepEqual(calls, { lookup: 1, policy: 0, opening: 0 });
  }
  for (const contentNames of [
    [BODYTEXT, BODYTEXT],
    [BODYTEXT, ...Array.from({ length: 64 }, (_, i) => `other${i}`)],
  ]) {
    const { unlock, calls } = await fixture({ contentNames });
    const answer = await unlock();
    assert.equal(answer.status, 200, "opaque store encoding and set size remain local");
    assert.ok(keyAt(answer.body.keys.contentKeys, { contentName: BODYTEXT }));
    assert.deepEqual(calls, { lookup: 1, policy: 1, opening: 1 });
  }
});
