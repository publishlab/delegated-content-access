// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";

test("the issuer-facing family generation exposes canonical 16-byte period-key and chain-key material", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  assert.equal((await generation.periodKey("premium", "251023T1415")).length, 16);
  assert.equal((await generation.chainCapability("premium", "251023T2345")).key.length, 16);
});
