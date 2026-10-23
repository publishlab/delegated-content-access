// @ts-check
//
// An issuer contribution may bring envelope procedures, which createIssuerCore
// hands to the base engine. The engine still decides which one an unlock runs
// (see ../core-issuer/envelope-procedure-selection.test.js); this file checks
// only the composition: the procedure arrives, two owners of one name refuse,
// and an injected engine cannot silently drop it.

import test from "node:test";
import assert from "node:assert/strict";
import { Sealer } from "../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { createIssuerCore } from "../../integration-issuer/createIssuerCore.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { base64urlEncode } from "../../core-shared/codec.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";

const ORIGIN = "https://publisher.example";
const NAME = "issuer";
const BODY = "body";
const PROCEDURE = "invented-procedure";
const OPENED = Uint8Array.from({ length: 16 }, (_, i) => 16 - i);
const opener = async () => OPENED;

test("a contribution's envelope procedure reaches the base engine", async () => {
  const signing = await signingKeypair();
  const pair = await issuerKeypair("ecdh-p256");
  const core = createIssuerCore(
    { operatingIssuerNames: [NAME], accessPolicy: new AllowAllPolicy() },
    { name: "invented-envelope", envelopeProcedures: { [PROCEDURE]: opener } },
  );
  const entry = {
    algorithm: "ecdh-p256",
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    envelopes: [PROCEDURE],
  };
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    origin: ORIGIN,
    openingKeys: { get: () => entry },
  };
  const sealer = new Sealer({
    origin: ORIGIN,
    clock: new Clock("2025-10-23T14:20:00Z"),
    random: new Random({ seed: 9 }),
    signingKeys: { signing: signing.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [{ issuerName: NAME, keyId: "k", algorithm: "ecdh-p256", publicKey: pair.publicKey }],
  });
  sealer.resource("resource", {});
  sealer.content(BODY, "text", "text/plain");
  const rendered = await sealer.seal();
  const client = new Client({ publisherOrigin: ORIGIN });
  const page = client.parse({ ...rendered.dcaData, sealedContent: rendered.sealedContent });
  const request = { ...client.buildRequest(page, NAME, [BODY]), envelope: PROCEDURE };
  const { status, body } = await unlockThroughAdmission(
    core.processor,
    core.endpoint,
    request,
    registration,
  );
  assert.equal(status, 200);
  assert.deepEqual(body.keys.contentKeys, [{ contentName: BODY, key: base64urlEncode(OPENED) }]);
});

test("two owners of one procedure name refuse", () => {
  const base = { operatingIssuerNames: [NAME], accessPolicy: new AllowAllPolicy() };
  assert.throws(
    () =>
      createIssuerCore(
        { ...base, envelopeProcedures: { [PROCEDURE]: opener } },
        { name: "second", envelopeProcedures: { [PROCEDURE]: opener } },
      ),
    { code: "bad_config" },
  );
  assert.throws(
    () =>
      createIssuerCore(
        base,
        { name: "first", envelopeProcedures: { [PROCEDURE]: opener } },
        { name: "second", envelopeProcedures: { [PROCEDURE]: opener } },
      ),
    { code: "bad_config" },
  );
});

test("a contribution's procedures cannot ride on an injected engine", () => {
  const engine = { unlock: async () => ({}), checkOperatingIssuerName: () => {} };
  assert.throws(
    () =>
      createIssuerCore(
        { engine: /** @type {any} */ (engine) },
        { name: "invented-envelope", envelopeProcedures: { [PROCEDURE]: opener } },
      ),
    { code: "bad_config" },
  );
});

test("a contribution's procedure table must be a map of openers", () => {
  const base = { operatingIssuerNames: [NAME], accessPolicy: new AllowAllPolicy() };
  for (const envelopeProcedures of [null, [], "x"]) {
    assert.throws(
      () =>
        createIssuerCore(base, {
          name: "bad",
          envelopeProcedures: /** @type {any} */ (envelopeProcedures),
        }),
      { code: "bad_config" },
    );
  }
});
