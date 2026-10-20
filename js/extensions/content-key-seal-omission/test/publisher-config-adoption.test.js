// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { checkedIssuerSupplyPlanner } from "../../../core-publisher/issuerSupplyPlan.js";
import { validatePublisherConfig } from "../../../core-publisher/publisherConfig.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { omissionSealing } from "../core-publisher/omissionSealing.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";

const ISSUER = Object.freeze({
  issuerName: "issuer_a",
  keyId: "key-1",
  algorithm: "rsa-oaep",
  publicKey: Object.freeze({}),
});

function configFor(issuer = ISSUER) {
  return {
    origin: "https://publisher.example",
    clock: {
      now() {
        throw new Error("clock called during admission");
      },
    },
    random: {
      bytes() {
        throw new Error("random called during admission");
      },
    },
    signingKeys: { signing: {} },
    periodKeySupply: {
      derive() {
        throw new Error("derive called during admission");
      },
    },
    keySealing: {
      seal() {
        throw new Error("seal called during admission");
      },
    },
    issuerSupplyPlanFor() {
      throw new Error("planner called during admission");
    },
    issuers: [issuer],
  };
}

function refusal(call) {
  try {
    call();
  } catch (error) {
    return { code: error?.code, message: error?.message };
  }
  assert.fail("expected a typed refusal");
}

test("omission admission keeps extension and runtime constructor refusals identical", () => {
  const cases = [
    { ...ISSUER, surprise: true },
    { ...ISSUER, extensions: ["unknown-extension"] },
    { ...ISSUER, extensions: [EXTENSION_NAME], accessGroups: ["bad|group"] },
  ];

  for (const issuer of cases) {
    const config = configFor(issuer);
    assert.deepEqual(
      refusal(() => omissionSealing(config)),
      refusal(() => new OmittingSealer(config)),
    );
  }

  const activeWithoutSupply = configFor({ ...ISSUER, extensions: [EXTENSION_NAME] });
  delete activeWithoutSupply.periodKeySupply;
  assert.deepEqual(
    refusal(() => omissionSealing(activeWithoutSupply)),
    refusal(() => new OmittingSealer(activeWithoutSupply)),
  );
});

test("omission projection reaches the unchanged base validator", () => {
  const config = configFor();
  config.origin = "http://publisher.example";
  const projected = { ...config, ...omissionSealing(config) };

  assert.deepEqual(
    refusal(() => validatePublisherConfig(projected)),
    refusal(() => new OmittingSealer(config)),
  );
});

test("active and inactive omission configuration performs no operational work or mutation", () => {
  for (const issuer of [
    ISSUER,
    Object.freeze({ ...ISSUER, extensions: Object.freeze([EXTENSION_NAME]) }),
  ]) {
    const issuers = Object.freeze([issuer]);
    const config = Object.freeze({ ...configFor(issuer), issuers });
    const before = [...Object.keys(issuer)];

    const projected = omissionSealing(config);
    new OmittingSealer(config);

    assert.deepEqual(Object.keys(issuer), before);
    assert.equal(config.issuers, issuers);
    assert.equal(typeof projected.issuerSupplyPlanFor, "function");
  }
});

test("a planner that is not callable is refused with base's refusal, where the composition is built", () => {
  const config = { ...configFor(), issuerSupplyPlanFor: {} };

  const composed = refusal(() => omissionSealing(config));

  // The refusal stands at composition time, before a Sealer exists and long
  // before a render asks anyone for a plan. Nothing operational was reached,
  // because this configuration's clock, randomness and key sealing throw.
  assert.equal(composed.code, "bad_config");
  // The plan seam's own check produces this refusal, so the wrapper cannot
  // drift into a second text for the same case.
  assert.deepEqual(
    composed,
    refusal(() => checkedIssuerSupplyPlanner(config.issuerSupplyPlanFor)),
  );
  assert.deepEqual(
    composed,
    refusal(() => new OmittingSealer(config)),
  );
});
