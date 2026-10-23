// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { Sealer } from "../../core-publisher/Sealer.js";
import { assertIssuerRequestBudget } from "../../core-publisher/issuerRequestBudget.js";
import { utf8Encode } from "../../core-shared/codec.js";
import { requestLimits } from "../../core-shared/requestLimits.js";
import { requestEntryCounts } from "../../core-shared/requestLimits.js";
import { DcaData } from "../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../core-client/DcaRequestBuilder.js";
import { world, BODYTEXT } from "../../test-lib/fixtures/wire-policy-world.js";
import { ISSUER_NAME } from "../../demo/scenarios/fixtures.js";

const ISSUER = "issuer_a";

/**
 * @param {{ items?: string[], periodKeys?: string[], chainKeys?: string[], keyId?: string }} [options]
 */
function delivery({ items = ["body"], periodKeys = [], chainKeys = [], keyId = "key" } = {}) {
  return {
    version: "1",
    resourceJWT: "signed.resource.token",
    contentData: items.map((contentName) => ({
      contentName,
      keys: [{ accessGroup: "premium", period: "t", key: "wrap" }],
    })),
    issuerData: [
      {
        issuerName: ISSUER,
        keyId,
        sealed: {
          contentKeys: items.map((contentName) => ({ contentName, key: "envelope" })),
          ...(periodKeys.length
            ? { periodKeys: periodKeys.map((period) => record("period", period)) }
            : {}),
          ...(chainKeys.length
            ? { chainKeys: chainKeys.map((cutoff) => record("cutoff", cutoff)) }
            : {}),
        },
      },
    ],
  };
}

/**
 * @param {'period'|'cutoff'} field
 * @param {string} label
 * @param {string} [accessGroup]
 */
function record(field, label, accessGroup = "premium") {
  return { accessGroup, [field]: label, key: "envelope" };
}

function issuer(limits = {}, clientRequestExtraBytes) {
  return {
    issuerName: ISSUER,
    limits: requestLimits(limits),
    clientRequestExtraBytes,
  };
}

/** @param {number} count @param {string} prefix */
function labels(count, prefix) {
  return Array.from({ length: count }, (_, index) => `${prefix}${index}`);
}

test("four period entries fit the reference group cap; five do not", () => {
  assert.doesNotThrow(() =>
    assertIssuerRequestBudget(delivery({ periodKeys: labels(4, "t") }), issuer()),
  );
  assert.throws(
    () => assertIssuerRequestBudget(delivery({ periodKeys: labels(5, "t") }), issuer()),
    {
      code: "bad_config",
      message: /maxEntriesPerGroup/,
    },
  );
  assert.doesNotThrow(() =>
    assertIssuerRequestBudget(
      delivery({ periodKeys: labels(5, "t") }),
      issuer({ maxEntriesPerGroup: 5 }),
    ),
  );
});

test("sixteen item envelopes fit; the seventeenth needs a higher onboarded endpoint cap", () => {
  const names = Array.from({ length: 17 }, (_, index) => `item${index}`);
  assert.doesNotThrow(() =>
    assertIssuerRequestBudget(delivery({ items: names.slice(0, 16) }), issuer()),
  );
  assert.throws(() => assertIssuerRequestBudget(delivery({ items: names }), issuer()), {
    code: "bad_config",
    message: /maxEntries/,
  });
  assert.doesNotThrow(() =>
    assertIssuerRequestBudget(delivery({ items: names }), issuer({ maxEntries: 17 })),
  );
});

test("period and chain entries share one group cap; unused groups do not enter the conservative request", () => {
  const candidate = delivery({ periodKeys: labels(2, "p"), chainKeys: labels(2, "c") });
  const sealed = /** @type {any} */ (candidate.issuerData[0].sealed);
  sealed.periodKeys.push(...labels(100, "u").map((label) => record("period", label, "unused")));
  assert.doesNotThrow(() => assertIssuerRequestBudget(candidate, issuer()));
  sealed.chainKeys.push(record("cutoff", "c2"));
  assert.throws(() => assertIssuerRequestBudget(candidate, issuer()), {
    code: "bad_config",
    message: /maxEntriesPerGroup/,
  });
});

test("rival records at one coordinate each count toward the raw caps", () => {
  // Repeated records are candidate alternatives, and every one of them is
  // relayed and opened, so the caps count them before any copy is dropped.
  assert.doesNotThrow(() =>
    assertIssuerRequestBudget(delivery({ periodKeys: ["t0", "t0", "t0", "t0"] }), issuer()),
  );
  assert.throws(
    () =>
      assertIssuerRequestBudget(delivery({ periodKeys: ["t0", "t0", "t0", "t0", "t0"] }), issuer()),
    { code: "bad_config", message: /maxEntriesPerGroup/ },
  );
  assert.deepEqual(
    requestEntryCounts({
      contentKeys: [
        { contentName: "body", key: "a" },
        { contentName: "body", key: "a" },
      ],
      periodKeys: [record("period", "t0"), record("period", "t0"), "not a record"],
      chainKeys: [record("cutoff", "c0", "other")],
    }),
    {
      entries: 6,
      groups: new Map([
        ["premium", 2],
        ["other", 1],
      ]),
    },
  );
});

test("UTF-8 request bytes and explicit client overhead are checked at the exact boundary", () => {
  const candidate = delivery({ keyId: "clé" });
  const block = candidate.issuerData[0];
  const document = {
    version: candidate.version,
    issuerName: ISSUER,
    resourceJWT: candidate.resourceJWT,
    keyId: block.keyId,
    sealed: { contentKeys: block.sealed.contentKeys },
  };
  const length = utf8Encode(JSON.stringify(document)).length;
  assert.ok(length > JSON.stringify(document).length);
  assert.doesNotThrow(() =>
    assertIssuerRequestBudget(candidate, issuer({ maxBodyBytes: length + 2 }, 2)),
  );
  assert.throws(
    () => assertIssuerRequestBudget(candidate, issuer({ maxBodyBytes: length + 1 }, 2)),
    {
      code: "bad_config",
      message: /maxBodyBytes/,
    },
  );
  assert.doesNotThrow(() => assertIssuerRequestBudget(candidate, issuer({ maxBodyBytes: length })));
});

test("the relayed envelope selector counts toward the request bytes", () => {
  const candidate = delivery();
  const block = /** @type {any} */ (candidate.issuerData[0]);
  block.envelope = "compact-ecdh";
  const document = {
    version: candidate.version,
    issuerName: ISSUER,
    resourceJWT: candidate.resourceJWT,
    keyId: block.keyId,
    envelope: block.envelope,
    sealed: { contentKeys: block.sealed.contentKeys },
  };
  const length = utf8Encode(JSON.stringify(document)).length;
  assert.doesNotThrow(() => assertIssuerRequestBudget(candidate, issuer({ maxBodyBytes: length })));
  assert.throws(() => assertIssuerRequestBudget(candidate, issuer({ maxBodyBytes: length - 1 })), {
    code: "bad_config",
    message: /maxBodyBytes/,
  });
});

test("publisher budget matches the real base request builder's UTF-8 bytes", async () => {
  const fixture = await world();
  const { dcaData } = await fixture.render();
  const page = new DcaData(dcaData);
  const base = new DcaRequestBuilder({ relayPeriodKeys: true })
    .build(page, ISSUER_NAME, [BODYTEXT.name])
    .toObject();
  assert.equal(requestEntryCounts(base.sealed).entries, 3);
  assert.equal(requestEntryCounts(base.sealed).groups.get("premium"), 2);
  const fullBytes = utf8Encode(JSON.stringify(base)).length;
  const extraBytes = 32;
  const limits = { maxEntries: 3, maxEntriesPerGroup: 2 };
  assert.doesNotThrow(() =>
    assertIssuerRequestBudget(dcaData, {
      issuerName: ISSUER_NAME,
      limits: requestLimits({ ...limits, maxBodyBytes: fullBytes + 32 }),
      clientRequestExtraBytes: extraBytes,
    }),
  );
  assert.throws(
    () =>
      assertIssuerRequestBudget(dcaData, {
        issuerName: ISSUER_NAME,
        limits: requestLimits({ ...limits, maxBodyBytes: fullBytes + 31 }),
        clientRequestExtraBytes: extraBytes,
      }),
    { code: "bad_config", message: /maxBodyBytes/ },
  );
  assert.throws(
    () =>
      assertIssuerRequestBudget(dcaData, {
        issuerName: ISSUER_NAME,
        limits: requestLimits({ ...limits, maxEntriesPerGroup: 1, maxBodyBytes: fullBytes + 32 }),
        clientRequestExtraBytes: extraBytes,
      }),
    { code: "bad_config", message: /maxEntriesPerGroup/ },
  );
});

test("Sealer refuses an over-limit complete publication before returning it", async () => {
  const publisher = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const opening = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const config = {
    origin: "https://publisher.example",
    clock: { now: () => new Date("2025-10-23T14:20:00Z") },
    random: { bytes: (count) => crypto.getRandomValues(new Uint8Array(count)) },
    signingKeys: { publisher: publisher.privateKey },
    issuers: [
      {
        issuerName: ISSUER,
        keyId: "key",
        algorithm: "ecdh-p256",
        publicKey: opening.publicKey,

        limits: { maxEntries: 1 },
      },
    ],
    issuerSupplyPlanFor: () => ({ contentKeyNames: ["first", "second"], suppliedAccessGroups: [] }),
  };
  const sealer = new Sealer(config);
  sealer.resource("123456", {});
  sealer.content("first", "first", "text/plain");
  sealer.content("second", "second", "text/plain");
  await assert.rejects(() => sealer.seal(), { code: "bad_config", message: /maxEntries/ });
});

test("Sealer counts a selected preparation's request relay over the assembled delivery", async () => {
  const publisher = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const opening = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  /** @type {[any, string][]} */
  const seen = [];
  /** @param {number} bytes */
  const config = (bytes) => ({
    origin: "https://publisher.example",
    clock: { now: () => new Date("2025-10-23T14:20:00Z") },
    random: {
      bytes: (/** @type {number} */ count) => crypto.getRandomValues(new Uint8Array(count)),
    },
    signingKeys: { publisher: publisher.privateKey },
    issuers: [
      { issuerName: ISSUER, keyId: "key", algorithm: "ecdh-p256", publicKey: opening.publicKey },
    ],
    issuerSupplyPlanFor: () => ({ contentKeyNames: ["first"], suppliedAccessGroups: [] }),
    itemPreparations: [
      {
        name: "relaying",
        routes: () => [],
        prepare: async () => ({}),
        requestRelay: (/** @type {any} */ page, /** @type {string} */ issuerName) => {
          seen.push([page, issuerName]);
          return { sealed: { relayed: { first: "x".repeat(bytes) } }, members: { hint: "y" } };
        },
      },
    ],
  });
  /** @param {number} bytes */
  const seal = (bytes) =>
    new Sealer(/** @type {any} */ (config(bytes)))
      .resource("123456", {})
      .content("first", "first", "text/plain")
      .seal();
  const { dcaData } = await seal(16);
  assert.deepEqual(seen.at(-1)?.[0], dcaData);
  assert.notEqual(seen.at(-1)?.[0], dcaData);
  assert.equal(seen.at(-1)?.[1], ISSUER);
  await assert.rejects(() => seal(65536), { code: "bad_config", message: /maxBodyBytes/ });
});
