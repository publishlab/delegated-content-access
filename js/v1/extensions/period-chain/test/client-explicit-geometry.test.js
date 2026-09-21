// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { PeriodChainCache } from "../core-client/PeriodChainCache.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";

const geometry = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const context = Object.freeze({ publisher: "https://publisher.example", ...geometry });

test("the client cache files and derives only canonical 16-byte positioned state", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry,
  });
  const terminalT = "251023T2345";
  const targetT = "251023T1415";
  const cache = new PeriodChainCache();
  await cache.put(
    "premium",
    terminalT,
    (await generation.chainCapability("premium", terminalT)).key,
    context,
  );
  assert.deepEqual(await cache.candidates("premium", targetT, context), [
    await generation.periodKey("premium", targetT),
  ]);
  for (const width of [15, 17, 24, 32]) {
    await assert.rejects(
      cache.put("premium", terminalT, new Uint8Array(width), context),
      (error) => error.code === "bad_key" && /16 key bytes/.test(error.message),
    );
  }
});
