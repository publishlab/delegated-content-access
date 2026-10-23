// @ts-check
//
// Several sealed records at one coordinate. The request carries each record as
// its own source candidate (data-format Section 2.3): the issuer authorizes the
// coordinate once, opens every distinct envelope at it, and answers every
// distinct key that opened. A candidate that does not open costs nothing while
// a sibling at the same coordinate opens. Raw records count toward the
// request limits before any dedupe.
//
// An invented envelope procedure stands in for the ordinary opener, so a test
// can write an envelope that opens to chosen bytes: the blob is the
// base64url key itself, and the blob "shut" fails to open the way a wrong
// envelope does.

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { DcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import { base64urlDecode, base64urlEncode } from "../../core-shared/codec.js";
import { DcaError } from "../../core-shared/errors.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";

const ORIGIN = "https://publisher.example";
const NAME = "issuer";
const BODY = "body";
const SUMMARY = "summary";
const GROUP = "premium";
const T0 = "251023T1400";
const PROCEDURE = "invented-procedure";

/** A 16-byte key whose every byte is `fill`, as the wire spells it. */
const keyOf = (/** @type {number} */ fill) => base64urlEncode(new Uint8Array(16).fill(fill));
const KEY_A = keyOf(1);
const KEY_B = keyOf(2);
const SHUT = "shut";

/**
 * One render, an engine whose invented procedure opens a blob to the bytes it
 * spells, and the request members a client would send for that render.
 *
 * @param {{ decide?: (requested: any) => any }} [setup]
 */
async function world(setup = {}) {
  const signing = await signingKeypair();
  const pair = await issuerKeypair("ecdh-p256");
  /** @type {unknown[]} */
  const opened = [];
  const policy = {
    calls: 0,
    /** @param {any} claims @param {any} requested */
    decide(claims, requested) {
      void claims;
      this.calls++;
      return (
        setup.decide?.(requested) ?? {
          contentNames: [...requested.contentNames],
          periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
            accessGroup,
            periods: [...(requested.periodCoordinates[accessGroup] ?? [])],
          })),
        }
      );
    },
  };
  const engine = new IssuerEngine({
    operatingIssuerNames: [NAME],
    accessPolicy: policy,
    envelopeProcedures: {
      [PROCEDURE]: async (/** @type {unknown} */ sealed) => {
        opened.push(sealed);
        if (sealed === SHUT) throw new DcaError("unseal_failed", "does not open");
        return base64urlDecode(/** @type {string} */ (sealed));
      },
    },
  });
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    origin: ORIGIN,
    openingKeys: {
      get: (/** @type {string} */ issuerName) =>
        issuerName === NAME
          ? { algorithm: "ecdh-p256", privateKey: pair.privateKey, envelopes: [PROCEDURE] }
          : undefined,
    },
  };
  const sealer = new Sealer({
    origin: ORIGIN,
    clock: new Clock("2025-10-23T14:20:00Z"),
    random: new Random({ seed: 5 }),
    signingKeys: { signing: signing.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [{ issuerName: NAME, keyId: "k", algorithm: "ecdh-p256", publicKey: pair.publicKey }],
  });
  sealer.resource("resource", {});
  sealer.content(BODY, "text", "text/plain");
  sealer.content(SUMMARY, "short", "text/plain");
  const { dcaData } = await sealer.seal();

  /** @param {any} sealed */
  const document = (sealed) => ({
    version: "1",
    issuerName: NAME,
    keyId: "k",
    resourceJWT: dcaData.resourceJWT,
    envelope: PROCEDURE,
    sealed,
  });
  return {
    policy,
    opened,
    document,
    /** @param {any} sealed */
    unlock: (sealed) => engine.unlock(new DcaRequest(document(sealed)), registration),
  };
}

test("every distinct key that opens at one name goes out, under one policy call", async () => {
  const { policy, opened, unlock } = await world();
  const result = await unlock({
    contentKeys: [
      { contentName: BODY, key: KEY_A },
      { contentName: BODY, key: KEY_B },
      { contentName: BODY, key: KEY_A },
    ],
  });

  assert.deepEqual(result.contentKeys, [
    { contentName: BODY, key: KEY_A },
    { contentName: BODY, key: KEY_B },
  ]);
  assert.deepEqual(result.errors, []);
  assert.equal(policy.calls, 1, "rivals at one name are one logical grant");
  assert.deepEqual(opened, [KEY_A, KEY_B], "an identical record is one candidate, opened once");
});

test("a candidate that does not open beside one that does leaves no error, in either order", async () => {
  for (const records of [
    [SHUT, KEY_A],
    [KEY_A, SHUT],
  ]) {
    const { unlock } = await world();
    const result = await unlock({
      contentKeys: records.map((key) => ({ contentName: BODY, key })),
    });
    assert.deepEqual(result.contentKeys, [{ contentName: BODY, key: KEY_A }], String(records));
    assert.deepEqual(result.errors, [], String(records));
  }
});

test("a name whose every candidate fails answers one error at its coordinate", async () => {
  const { unlock } = await world();
  const result = await unlock({
    contentKeys: [
      { contentName: BODY, key: SHUT },
      { contentName: BODY, key: 7 },
      { contentName: SUMMARY, key: KEY_A },
    ],
  });

  assert.deepEqual(result.contentKeys, [{ contentName: SUMMARY, key: KEY_A }]);
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0].coordinate, BODY);
  assert.equal(result.errors[0].error, "unseal_failed");
});

test("a denied name's envelopes are never read, whichever records sit beside them", async () => {
  /** @type {string[]} */
  const reads = [];
  const watched = (/** @type {string} */ contentName, /** @type {string} */ key) =>
    new Proxy(
      { contentName, key },
      {
        get(target, name, receiver) {
          if (name === "key") reads.push(target.contentName);
          return Reflect.get(target, name, receiver);
        },
      },
    );
  const { unlock } = await world({ decide: () => ({ contentNames: [BODY] }) });
  const result = await unlock({
    contentKeys: [watched(SUMMARY, KEY_B), watched(BODY, KEY_A), watched(SUMMARY, KEY_A)],
  });

  assert.deepEqual(result.contentKeys, [{ contentName: BODY, key: KEY_A }]);
  assert.deepEqual(
    [...new Set(reads)],
    [BODY],
    "the engine reads names to present them and envelopes only where granted",
  );
});

test("rival period-key records at one label open as rival candidates", async () => {
  for (const keys of [
    [SHUT, KEY_A, KEY_B],
    [KEY_B, SHUT, KEY_A],
  ]) {
    const { policy, unlock } = await world();
    const result = await unlock({
      contentKeys: [],
      periodKeys: keys.map((key) => ({ accessGroup: GROUP, period: T0, key })),
    });

    const expected = keys
      .filter((key) => key !== SHUT)
      .map((key) => ({ accessGroup: GROUP, period: T0, key }));
    assert.deepEqual(result.periodKeys, expected, String(keys));
    assert.deepEqual(result.errors, [], String(keys));
    assert.equal(policy.calls, 1);
  }
});

test("raw records count toward the entry cap before any dedupe", () => {
  const processor = new IssuerProcessor(
    {
      checkOperatingIssuerName() {},
      async unlock() {
        throw new Error("unreachable");
      },
    },
    { limits: { maxEntries: 2 } },
  );
  const sealed = {
    contentKeys: [
      { contentName: BODY, key: KEY_A },
      { contentName: BODY, key: KEY_A },
      { contentName: BODY, key: KEY_A },
    ],
  };
  assert.deepEqual(
    processor.admit(JSON.stringify({ version: "1", issuerName: NAME, keyId: "k", sealed })),
    { kind: "failure", code: "too_many_entries" },
  );
});
