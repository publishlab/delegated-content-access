// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { validatePublisherConfig } from "../../../core-publisher/publisherConfig.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import {
  CHAIN_KEY_CONSTRUCTION,
  chainKeyConstructionProfile,
} from "../core-shared/chainKeyConstruction.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";

function refusal(call) {
  try {
    call();
  } catch (error) {
    return { code: error?.code, message: error?.message };
  }
  assert.fail("expected a typed refusal");
}

function watchedGeneration(geometry, calls) {
  return Object.freeze({
    geometry: Object.freeze(geometry),
    constructionProfile: chainKeyConstructionProfile(CHAIN_KEY_CONSTRUCTION),
    coordinateFor() {
      calls.push("coordinateFor");
      throw new Error("coordinate called during admission");
    },
    periodKey() {
      calls.push("periodKey");
      throw new Error("periodKey called during admission");
    },
    chainCapability() {
      calls.push("chainCapability");
      throw new Error("chain called during admission");
    },
  });
}

function baseConfig(periodKeySupply) {
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
    periodKeySupply,
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: "issuer_a",
        keyId: "key-1",
        algorithm: "rsa-oaep",
        publicKey: {},
      },
    ],
  };
}

test("chain-key construction refuses its own configuration before derivation exists", () => {
  const keyDerivationSecret = new Uint8Array(32);
  assert.equal(
    refusal(() =>
      periodFamilyGeneration({
        keyDerivationSecret,
        geometry: { chainsPerDay: 7, periodMinutes: 15 },
      }),
    ).code,
    "bad_config",
  );
  assert.equal(
    refusal(() =>
      periodFamilyGeneration({
        keyDerivationSecret: new Uint8Array(31),
        geometry: { chainsPerDay: 2, periodMinutes: 15 },
      }),
    ).code,
    "bad_config",
  );
  assert.equal(
    refusal(() => periodFamilySupply({ families: {}, chainWindows: 5 })).code,
    "bad_config",
  );
  assert.equal(
    refusal(() =>
      periodFamilySupply({
        families: { premium: {} },
        chainWindows: 2,
      }),
    ).code,
    "bad_config",
  );
});

test("valid mixed-family supply and Sealer admission invoke no operational method", () => {
  const calls = [];
  const families = Object.freeze({
    premium: watchedGeneration({ chainsPerDay: 2, periodMinutes: 15 }, calls),
    archive: watchedGeneration({ chainsPerDay: 2, periodMinutes: 60 }, calls),
  });
  const periodKeySupply = Object.freeze({
    derive() {
      calls.push("derive");
      throw new Error("derive called during admission");
    },
  });
  const config = Object.freeze({ periodKeySupply, families, chainWindows: 2 });

  const supply = periodFamilySupply(config);
  new Sealer(baseConfig(supply));

  assert.deepEqual(calls, []);
  assert.equal(config.families, families);
  assert.equal(supply.familyPlan instanceof Function, true);
});

test("a composed period-family supply still receives unchanged base validation", () => {
  const supply = periodFamilySupply({
    families: {
      premium: watchedGeneration({ chainsPerDay: 2, periodMinutes: 15 }, []),
    },
    chainWindows: 2,
  });
  const config = baseConfig(supply);
  config.origin = "http://publisher.example";

  assert.deepEqual(
    refusal(() => validatePublisherConfig(config)),
    refusal(() => new Sealer(config)),
  );
});

test("the two reference generation geometries remain admitted without deriving", () => {
  const keyDerivationSecret = new Uint8Array(32).fill(7);
  const fine = periodFamilyGeneration({
    keyDerivationSecret,
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const hourly = periodFamilyGeneration({
    keyDerivationSecret,
    geometry: { chainsPerDay: 2, periodMinutes: 60 },
  });

  assert.deepEqual(fine.geometry, {
    chainsPerDay: 2,
    periodMinutes: 15,
    windowMinutes: 720,
    positionsPerWindow: 48,
  });
  assert.deepEqual(hourly.geometry, {
    chainsPerDay: 2,
    periodMinutes: 60,
    windowMinutes: 720,
    positionsPerWindow: 12,
  });
});

test("real mixed generation geometries reach Sealer admission without derivation", () => {
  const keyDerivationSecret = new Uint8Array(32).fill(7);
  const families = {
    premium: periodFamilyGeneration({
      keyDerivationSecret,
      geometry: { chainsPerDay: 2, periodMinutes: 15 },
    }),
    archive: periodFamilyGeneration({
      keyDerivationSecret,
      geometry: { chainsPerDay: 2, periodMinutes: 60 },
    }),
  };
  const deriveBits = globalThis.crypto.subtle.deriveBits;
  let calls = 0;
  globalThis.crypto.subtle.deriveBits = function trap() {
    calls++;
    throw new Error("deriveBits called during admission");
  };
  try {
    const supply = periodFamilySupply({ families, chainWindows: 2 });
    new Sealer(baseConfig(supply));
  } finally {
    globalThis.crypto.subtle.deriveBits = deriveBits;
  }
  assert.equal(calls, 0);
});
