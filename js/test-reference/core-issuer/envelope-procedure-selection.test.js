// @ts-check
//
// The engine picks the envelope procedure for one unlock in one place. The
// trusted key entry's optional `envelopes` is an allowlist; absent, it permits
// only the ordinary procedure the entry registers as `algorithm`. An absent
// `envelope` request member selects that ordinary procedure, which the
// allowlist must still permit. A present member selects an extension's
// procedure only when the engine was given an opener under that name and the
// allowlist names it; anything else opens nothing at every coordinate. No case
// falls back to the ordinary procedure: the blobs here are valid ordinary
// envelopes, so a fallback would hand out their keys. An allowlist the engine
// cannot honour is an issuer fault, never a per-item refusal. The same one
// choice governs a response section source's envelopes: a source without an
// opener under the selected procedure opens nothing there.
//
// Base tests cannot import an extension, so an invented procedure stands in
// for the compact-ECDH opener.

import test from "node:test";
import assert from "node:assert/strict";
import { Sealer } from "../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { base64urlEncode, utf8Decode, utf8Encode } from "../../core-shared/codec.js";
import { decrypt, encrypt } from "../../core-shared/aead.js";
import { deriveAesGcmKey, generateEcdhKeyPair } from "../../core-shared/cryptoProvider.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";
import { contentKeyMap, errorMap } from "../support/namedRecords.js";

const ORIGIN = "https://publisher.example";
const NAME = "issuer";
const BODY = "body";
const PROCEDURE = "invented-procedure";
const ORDINARY = "ecdh-p256";
const OPENED = Uint8Array.from({ length: 16 }, (_, i) => i + 1);

/**
 * @param {{ envelopes?: unknown, procedures?: Record<string, any>|undefined, algorithm?: unknown,
 *   source?: any }} [setup]
 */
async function world(setup = {}) {
  // An `envelopes` key given as undefined means an entry without the member.
  const envelopes = Object.hasOwn(setup, "envelopes") ? setup.envelopes : [ORDINARY, PROCEDURE];
  const procedures = setup.procedures;
  const signing = await signingKeypair();
  const pair = await issuerKeypair("ecdh-p256");
  /** @type {{ sealed: unknown, key: any, aad: Uint8Array }[]} */
  const calls = [];
  const opener = async (
    /** @type {unknown} */ sealed,
    /** @type {any} */ key,
    /** @type {Uint8Array} */ aad,
  ) => {
    calls.push({ sealed, key, aad });
    return OPENED;
  };
  const engine = new IssuerEngine({
    operatingIssuerNames: [NAME],
    accessPolicy: new AllowAllPolicy(),
    ...(procedures === undefined ? { envelopeProcedures: { [PROCEDURE]: opener } } : procedures),
    ...(setup.source === undefined ? {} : { responseSectionSources: [setup.source] }),
  });
  const processor = new IssuerProcessor(engine, {
    periodKeyInput: false,
    ...(setup.source === undefined
      ? {}
      : {
          selectedExtensions: [setup.source.name],
          extensionCoordinates: { [setup.source.name]: setup.source.presented },
        }),
  });
  const endpoint = new UnlockEndpoint(processor);
  const entry = {
    algorithm: Object.hasOwn(setup, "algorithm") ? setup.algorithm : ORDINARY,
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    ...(envelopes === undefined ? {} : { envelopes }),
  };
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    origin: ORIGIN,
    openingKeys: {
      get: (/** @type {string} */ issuerName) => (issuerName === NAME ? entry : undefined),
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
  const rendered = await sealer.seal();
  const client = new Client({ publisherOrigin: ORIGIN });
  const page = client.parse({ ...rendered.dcaData, sealedContent: rendered.sealedContent });
  const request = client.buildRequest(page, NAME, [BODY]);
  return {
    calls,
    pair,
    /**
     * @param {unknown} [envelope] - omitted when undefined
     * @param {Record<string, unknown>} [members] - further request members
     */
    unlock: (envelope, members = {}) => {
      const sent = { ...structuredClone(request), ...members };
      if (envelope !== undefined) sent.envelope = envelope;
      return unlockThroughAdmission(processor, endpoint, sent, registration);
    },
  };
}

test("an absent envelope member opens with the ordinary procedure the entry permits", async () => {
  for (const envelopes of [undefined, [ORDINARY], [ORDINARY, PROCEDURE], [PROCEDURE, ORDINARY]]) {
    const { calls, unlock } = await world({ envelopes });
    const { status, body } = await unlock();
    assert.equal(status, 200, String(envelopes));
    assert.equal(errorMap(body.errors), undefined, String(envelopes));
    assert.equal(typeof contentKeyMap(body.keys?.contentKeys)?.[BODY], "string", String(envelopes));
    assert.equal(calls.length, 0, "the selected opener runs only when the request selects it");
  }
});

test("an entry that permits only the extension procedure refuses an absent member", async () => {
  const { calls, unlock } = await world({ envelopes: [PROCEDURE] });
  const { status, body } = await unlock();
  assert.equal(status, 200);
  assert.equal(
    contentKeyMap(body.keys?.contentKeys)?.[BODY],
    undefined,
    "a valid ordinary envelope stays shut",
  );
  assert.ok(errorMap(body.errors)?.[BODY]);
  assert.equal(calls.length, 0);
});

test("a permitted selected procedure opens under the BIND octets and the key pair", async () => {
  for (const envelopes of [[PROCEDURE], [ORDINARY, PROCEDURE]]) {
    const { calls, pair, unlock } = await world({ envelopes });
    const { status, body } = await unlock(PROCEDURE);
    assert.equal(status, 200);
    assert.equal(errorMap(body.errors), undefined);
    assert.equal(contentKeyMap(body.keys.contentKeys)[BODY], base64urlEncode(OPENED));
    assert.equal(calls.length, 1);
    assert.equal(typeof calls[0].sealed, "string");
    assert.equal(calls[0].key.privateKey, pair.privateKey);
    assert.equal(calls[0].key.publicKey, pair.publicKey);
    const bind = utf8Decode(calls[0].aad);
    assert.match(bind, /^dca-bind-key-envelope\|/);
    assert.ok(bind.split("|").includes(BODY), "the binding names the coordinate");
  }
});

test("a selected procedure the key entry does not permit opens nothing", async () => {
  for (const envelopes of [undefined, [ORDINARY]]) {
    const { calls, unlock } = await world({ envelopes });
    const { status, body } = await unlock(PROCEDURE);
    assert.equal(status, 200, String(envelopes));
    assert.equal(
      contentKeyMap(body.keys?.contentKeys)?.[BODY],
      undefined,
      "no fallback to the ordinary procedure",
    );
    assert.ok(errorMap(body.errors)?.[BODY], String(envelopes));
    assert.equal(calls.length, 0);
  }
});

test("an allowlist the engine cannot honour is an issuer fault on every request", async () => {
  const cases = [
    { envelopes: null },
    { envelopes: PROCEDURE },
    { envelopes: [] },
    { envelopes: [7] },
    { envelopes: [PROCEDURE, PROCEDURE] },
    { envelopes: [ORDINARY, ORDINARY] },
    { envelopes: ["other"] },
    { envelopes: ["rsa-oaep"], note: "another key type's ordinary procedure" },
    { envelopes: [PROCEDURE], procedures: {}, note: "no opener in this engine" },
  ];
  for (const setup of cases) {
    const { calls, unlock } = await world(setup);
    for (const envelope of [undefined, PROCEDURE]) {
      const { status, body } = await unlock(envelope);
      const label = `${JSON.stringify(setup)} ${envelope}`;
      assert.equal(status, 500, label);
      assert.equal(body.keys, undefined, label);
    }
    assert.equal(calls.length, 0);
  }
});

test("a held entry's algorithm is a base procedure, never an extension procedure name", async () => {
  // An entry registering the extension procedure as its ordinary one would
  // open extension envelopes for a request that carries no selector, so a
  // stripped selector would still reach the extension procedure. The entry is
  // the issuer's fault on every request, with or without an allowlist.
  const declared = {
    envelopeProcedures: { [PROCEDURE]: { open: async () => OPENED, keyAlgorithms: [PROCEDURE] } },
  };
  for (const setup of [
    { algorithm: PROCEDURE, envelopes: undefined },
    { algorithm: PROCEDURE, envelopes: [PROCEDURE] },
    { algorithm: PROCEDURE, envelopes: undefined, procedures: declared },
    { algorithm: "other", envelopes: undefined },
    { algorithm: undefined, envelopes: undefined },
    { algorithm: "ECDH-P256", envelopes: undefined },
  ]) {
    const { calls, unlock } = await world(setup);
    for (const envelope of [undefined, PROCEDURE]) {
      const { status, body } = await unlock(envelope);
      const label = `${JSON.stringify(setup)} ${envelope}`;
      assert.equal(status, 500, label);
      assert.equal(body.keys, undefined, label);
    }
    assert.equal(calls.length, 0, JSON.stringify(setup));
  }
});

test("a procedure that declares its key types refuses an entry of another type at setup", async () => {
  // The entry is ECDH P-256. A procedure declared for RSA keys only cannot
  // use it, so the entry is refused before any request selects the procedure:
  // the request that omits `envelope` and would open ordinarily gets 500 too.
  const declared = (/** @type {string[]} */ keyAlgorithms) => ({
    envelopeProcedures: { [PROCEDURE]: { open: async () => OPENED, keyAlgorithms } },
  });
  const refused = await world({ procedures: declared(["rsa-oaep"]) });
  for (const envelope of [undefined, PROCEDURE]) {
    const { status, body } = await refused.unlock(envelope);
    assert.equal(status, 500, String(envelope));
    assert.equal(body.keys, undefined, String(envelope));
  }
  const fitting = await world({ procedures: declared(["rsa-oaep", "ecdh-p256"]) });
  const { status, body } = await fitting.unlock(PROCEDURE);
  assert.equal(status, 200);
  assert.equal(contentKeyMap(body.keys.contentKeys)[BODY], base64urlEncode(OPENED));
});

test("a malformed or unknown envelope member opens nothing and never falls back", async () => {
  for (const envelope of ["", "ecdh-p256", "other", 7, null, { x: 1 }]) {
    const { calls, unlock } = await world();
    const { status, body } = await unlock(envelope);
    assert.equal(status, 200, JSON.stringify(envelope));
    assert.equal(
      contentKeyMap(body.keys?.contentKeys)?.[BODY],
      undefined,
      JSON.stringify(envelope),
    );
    assert.ok(errorMap(body.errors)?.[BODY], JSON.stringify(envelope));
    assert.equal(calls.length, 0);
  }
});

test("an opener failure is the ordinary per-item refusal", async () => {
  const failing = async () => {
    const { DcaError } = await import("../../core-shared/errors.js");
    throw new DcaError("unseal_failed", "no");
  };
  const short = async () => new Uint8Array(15);
  for (const opener of [failing, short]) {
    const { unlock } = await world({ procedures: { envelopeProcedures: { [PROCEDURE]: opener } } });
    const { status, body } = await unlock(PROCEDURE);
    assert.equal(status, 200);
    assert.equal(contentKeyMap(body.keys?.contentKeys)?.[BODY], undefined);
    assert.ok(errorMap(body.errors)?.[BODY]);
  }
});

test("the engine refuses a procedure table it cannot use", () => {
  const base = { operatingIssuerNames: [NAME], accessPolicy: new AllowAllPolicy() };
  for (const envelopeProcedures of [
    null,
    [],
    { [PROCEDURE]: "not a function" },
    { "ecdh-p256": async () => OPENED },
    { "rsa-oaep": async () => OPENED },
    { [PROCEDURE]: { open: "not a function", keyAlgorithms: [ORDINARY] } },
    { [PROCEDURE]: { open: async () => OPENED } },
    { [PROCEDURE]: { open: async () => OPENED, keyAlgorithms: [] } },
    { [PROCEDURE]: { open: async () => OPENED, keyAlgorithms: ORDINARY } },
    { [PROCEDURE]: { open: async () => OPENED, keyAlgorithms: [7] } },
  ]) {
    assert.throws(() => new IssuerEngine({ ...base, envelopeProcedures }), { code: "bad_config" });
  }
});

test("prototype-looking procedure names stay own members with their declared key types", async () => {
  for (const declared of [undefined, [ORDINARY], ["rsa-oaep"]]) {
    const name = "__proto__";
    const open = async () => OPENED;
    const procedure = declared === undefined ? open : { open, keyAlgorithms: declared };
    const { unlock } = await world({
      envelopes: [ORDINARY, name],
      procedures: { envelopeProcedures: { [name]: procedure } },
    });
    const { status, body } = await unlock(name);
    if (declared?.[0] === "rsa-oaep") {
      assert.equal(status, 500);
      assert.equal(body.keys, undefined);
    } else {
      assert.equal(status, 200);
      assert.equal(contentKeyMap(body.keys?.contentKeys)?.[BODY], base64urlEncode(OPENED));
    }
  }
});

/** An ordinary-shaped ECDH AES-GCM seal of 32 bytes under `aad` that `ordinaryOpener` opens. */
async function sourceEnvelope(/** @type {CryptoKey} */ publicKey, /** @type {Uint8Array} */ aad) {
  const ephemeral = await generateEcdhKeyPair("P-256");
  const point = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const key = await deriveAesGcmKey(publicKey, ephemeral.privateKey);
  const body = await encrypt(key, new Uint8Array(12), new Uint8Array(32).fill(9), aad, 32);
  return base64urlEncode(new Uint8Array([...point, ...body]));
}

/** @type {(sealed: unknown, privateKey: CryptoKey, aad: Uint8Array) => Promise<Uint8Array>} */
async function ordinaryOpener(sealed, privateKey, aad) {
  const bytes = Buffer.from(/** @type {string} */ (sealed), "base64url");
  const point = await crypto.subtle.importKey(
    "raw",
    bytes.subarray(0, 65),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const key = await deriveAesGcmKey(point, privateKey);
  return decrypt(key, new Uint8Array(12), bytes.subarray(65), aad, 32);
}

test("a selected extension procedure gives a section source no ordinary opener to fall back to", async () => {
  // The procedure the unlock selects applies to section-source envelopes as
  // well. This source brings an opener for the ordinary procedure only, and
  // its envelope is a valid one under this key, so a fallback to that opener
  // would hand the source the sealed bytes under a procedure the request did
  // not select.
  const aad = utf8Encode("source-aad");
  let ordinaryOpens = 0;
  const source = {
    name: "fake",
    members: ["fakeSection"],
    envelopeOpeners: {
      [ORDINARY]: async (/** @type {[unknown, CryptoKey, Uint8Array]} */ ...args) => {
        ordinaryOpens++;
        return ordinaryOpener(...args);
      },
    },
    presented: (/** @type {any} */ request) => Object.hasOwn(request.toObject(), "fakeAsk"),
    async respond(/** @type {any} */ unlock) {
      const sealed = unlock.request.toObject().fakeAsk.envelope;
      const opened = await unlock.openAuxiliary(sealed, { aad });
      return {
        fakeSection: { opened: "bytes" in opened ? opened.bytes.length : opened.error.error },
      };
    },
  };
  const { calls, pair, unlock } = await world({ source });
  const fakeAsk = { envelope: await sourceEnvelope(pair.publicKey, aad) };

  // Control: without a selector the ordinary procedure opens the source's envelope.
  const ordinary = await unlock(undefined, { fakeAsk });
  assert.equal(ordinary.status, 200);
  assert.deepEqual(ordinary.body.fakeSection, { opened: 32 });
  assert.equal(ordinaryOpens, 1);
  assert.equal(calls.length, 0);

  // The request selects the extension procedure the entry permits. It opens the
  // base coordinate; the source has no opener under it, so its envelope stays shut.
  const selected = await unlock(PROCEDURE, { fakeAsk });
  assert.equal(selected.status, 200);
  assert.equal(contentKeyMap(selected.body.keys.contentKeys)[BODY], base64urlEncode(OPENED));
  assert.deepEqual(selected.body.fakeSection, { opened: "unseal_failed" });
  assert.equal(ordinaryOpens, 1, "the ordinary opener is not a fallback");
  assert.equal(calls.length, 1, "the extension procedure opened the base coordinate only");
});
