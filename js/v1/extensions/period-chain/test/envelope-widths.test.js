// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";

test("canonical period-chain leaves and state are 16 bytes while the key-derivation secret remains 32 bytes", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  assert.equal((await generation.periodKey("premium", "251023T1415")).length, 16);
  assert.equal((await generation.chainCapability("premium", "251023T2345")).key.length, 16);
  assert.throws(
    () =>
      periodFamilyGeneration({
        keyDerivationSecret: new Uint8Array(24),
        geometry: { chainsPerDay: 2, periodMinutes: 15 },
      }),
    /exactly 32 key-derivation-secret bytes/,
  );
});
