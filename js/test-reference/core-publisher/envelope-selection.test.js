// @ts-check
//
// A configured issuer may select an extension envelope procedure with
// `envelope`. The Sealer then hands that name to the key sealing on every seal
// for the issuer and writes it into the issuer block beside `keyId`, so the
// client relays it and the issuer selects the same procedure. Base never seals
// such a procedure itself: the core key sealing has none, so selecting one
// without a key sealing that implements it is a configuration fault. An item
// preparation that seals its own fields into a selecting issuer's block must
// declare that procedure; otherwise the block would mix procedures, which the
// compact-ECDH profile forbids (docs/spec-profile--compact-ecdh.md Section 3.1).
// The rule holds per block and per preparation: another block may use another
// procedure, and one preparation's declaration covers only its own fields.
//
// Base tests cannot import an extension, so an invented procedure stands in.

import test from "node:test";
import assert from "node:assert/strict";
import { Sealer } from "../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { composePublisherConfig } from "../../core-publisher/publisherComposition.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";

const ORIGIN = "https://publisher.example";
const PROCEDURE = "invented-procedure";

async function setup() {
  const signing = await signingKeypair();
  const pair = await issuerKeypair("ecdh-p256");
  /** @type {{ algorithm: string, options: any }[]} */
  const calls = [];
  const keySealing = {
    seal: async (
      /** @type {Uint8Array} */ _key,
      /** @type {CryptoKey} */ _pk,
      /** @type {string} */ algorithm,
      /** @type {any} */ options,
    ) => {
      calls.push({ algorithm, options });
      return "AQ";
    },
  };
  /** @param {Record<string, unknown>} [extra] */
  const issuer = (name, extra = {}) => ({
    issuerName: name,
    keyId: `${name}-key`,
    algorithm: "ecdh-p256",
    publicKey: pair.publicKey,
    ...extra,
  });
  const base = {
    origin: ORIGIN,
    clock: new Clock("2025-10-23T14:20:00Z"),
    random: new Random({ seed: 11 }),
    signingKeys: { signing: signing.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
  };
  return { calls, keySealing, issuer, base };
}

/** @param {Sealer} sealer */
async function render(sealer) {
  sealer.resource("resource", {});
  sealer.content("body", "text", "text/plain");
  return (await sealer.seal()).dcaData;
}

test("a selected procedure reaches the key sealing and the issuer block", async () => {
  const { calls, keySealing, issuer, base } = await setup();
  const sealer = new Sealer({
    ...base,
    keySealing,
    issuers: [issuer("compact", { envelope: PROCEDURE }), issuer("ordinary")],
  });
  const data = await render(sealer);
  assert.equal(data.issuerData.compact.envelope, PROCEDURE);
  assert.equal(data.issuerData.compact.keyId, "compact-key");
  assert.equal(Object.hasOwn(data.issuerData.ordinary, "envelope"), false);
  const byIssuer = calls.map((call) => call.options.envelope);
  assert.deepEqual(byIssuer, [PROCEDURE, undefined]);
  assert.equal(Object.hasOwn(calls[1].options, "envelope"), false, "no member for the default");
});

test("the core key sealing cannot seal a selected procedure", async () => {
  const { issuer, base } = await setup();
  assert.throws(
    () => new Sealer({ ...base, issuers: [issuer("compact", { envelope: PROCEDURE })] }),
    { code: "bad_config" },
  );
});

test("an envelope selector names an extension procedure", async () => {
  const { keySealing, issuer, base } = await setup();
  for (const envelope of ["", 7, null, "ecdh-p256", "rsa-oaep"]) {
    assert.throws(
      () => new Sealer({ ...base, keySealing, issuers: [issuer("compact", { envelope })] }),
      { code: "bad_config" },
      JSON.stringify(envelope),
    );
  }
});

/**
 * An item preparation that seals `member` into the named issuer blocks.
 *
 * @param {string} name
 * @param {string[]} issuerNames
 * @param {string[]} [envelopes]
 */
function sealingPreparation(name, issuerNames, envelopes) {
  return {
    name,
    routes: () => [],
    prepare: async () => ({
      issuerSealed: Object.fromEntries(
        issuerNames.map((issuerName) => [issuerName, { [name]: 1 }]),
      ),
    }),
    ...(envelopes === undefined ? {} : { envelopes }),
  };
}

/** @param {string} preparation */
const undeclaredIn = (preparation) => (/** @type {any} */ error) =>
  error.code === "bad_config" &&
  error.message ===
    `issuer "compact" selects ${PROCEDURE}, which the item preparation ${preparation} does not seal under`;

test("an item preparation declares the procedure of every block it seals into", async () => {
  const { keySealing, issuer, base } = await setup();
  const issuers = [issuer("compact", { envelope: PROCEDURE }), issuer("ordinary")];
  /** @param {any[]} itemPreparations */
  const sealer = (itemPreparations) =>
    new Sealer({ ...base, keySealing, issuers, itemPreparations });

  await assert.rejects(
    render(sealer([sealingPreparation("prep", ["compact"])])),
    undeclaredIn("prep"),
  );
  await assert.rejects(
    render(sealer([sealingPreparation("prep", ["compact"], ["other"])])),
    undeclaredIn("prep"),
  );
  const declared = await render(sealer([sealingPreparation("prep", ["compact"], [PROCEDURE])]));
  assert.equal(declared.issuerData.compact.envelope, PROCEDURE);
  assert.equal(declared.issuerData.compact.sealed.prep, 1);

  // A preparation that seals nothing into the selecting block needs no
  // declaration, whether it seals into another block or into none.
  const beside = await render(sealer([sealingPreparation("prep", ["ordinary"])]));
  assert.equal(beside.issuerData.ordinary.sealed.prep, 1);
  assert.equal(Object.hasOwn(beside.issuerData.compact.sealed, "prep"), false);
  assert.equal(beside.issuerData.compact.envelope, PROCEDURE);
  const none = await render(sealer([sealingPreparation("prep", [])]));
  assert.equal(none.issuerData.compact.envelope, PROCEDURE);
});

test("a compatible preparation in a block does not cover an incompatible one beside it", async () => {
  const { keySealing, issuer, base } = await setup();
  const issuers = [issuer("compact", { envelope: PROCEDURE }), issuer("ordinary")];
  const compatible = sealingPreparation("compatible", ["compact"], [PROCEDURE]);
  const incompatible = sealingPreparation("incompatible", ["compact", "ordinary"]);
  for (const itemPreparations of [
    [compatible, incompatible],
    [incompatible, compatible],
  ]) {
    await assert.rejects(
      render(new Sealer({ ...base, keySealing, issuers, itemPreparations })),
      undeclaredIn("incompatible"),
      itemPreparations.map((preparation) => preparation.name).join(", "),
    );
  }
  // The same pair renders once the incompatible one stays out of the block.
  const apart = await render(
    new Sealer({
      ...base,
      keySealing,
      issuers,
      itemPreparations: [compatible, sealingPreparation("incompatible", ["ordinary"])],
    }),
  );
  assert.equal(apart.issuerData.compact.sealed.compatible, 1);
  assert.equal(Object.hasOwn(apart.issuerData.compact.sealed, "incompatible"), false);
  assert.equal(apart.issuerData.ordinary.sealed.incompatible, 1);
});

test("composition keeps a preparation's declared procedures", async () => {
  const { keySealing, issuer, base } = await setup();
  const contribution = (/** @type {string[]|undefined} */ envelopes) => ({
    name: "prep",
    itemPreparation: sealingPreparation("prep", ["compact"], envelopes),
  });
  const sealing = { name: "sealing", keySealing };
  const issuers = [issuer("compact", { envelope: PROCEDURE })];
  const composed = composePublisherConfig({ ...base, issuers }, sealing, contribution([PROCEDURE]));
  assert.equal((await render(new Sealer(composed.config))).issuerData.compact.envelope, PROCEDURE);
  const undeclared = composePublisherConfig({ ...base, issuers }, sealing, contribution(undefined));
  await assert.rejects(render(new Sealer(undeclared.config)), undeclaredIn("prep"));
  assert.throws(
    () =>
      composePublisherConfig({ ...base, issuers }, sealing, contribution(/** @type {any} */ ("x"))),
    { code: "bad_config" },
  );
});
