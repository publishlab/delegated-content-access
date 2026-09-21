// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { PeriodChainCache } from "../core-client/PeriodChainCache.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { PERIOD_CHAIN_CONSTRUCTION } from "../core-shared/periodChainConstruction.js";

const geometry = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const context = Object.freeze({ publisher: "https://publisher.example", ...geometry });

test("one canonical family supplies a 16-byte terminal and exact leaf to the client cache", async () => {
  const keyDerivationSecret = new Uint8Array(32).fill(7);
  const generation = periodFamilyGeneration({ keyDerivationSecret, geometry });
  assert.equal(generation.constructionProfile.constructionId, PERIOD_CHAIN_CONSTRUCTION);
  assert.equal(generation.constructionProfile.stateBytes, 16);

  const terminalT = "251023T2345";
  const targetT = "251023T1415";
  const capability = await generation.chainCapability("premium", terminalT);
  assert.equal(capability.key.length, 16);
  const cache = new PeriodChainCache();
  await cache.put("premium", terminalT, capability.key, context);
  const candidates = await cache.candidates("premium", targetT, context);
  assert.deepEqual(candidates, [await generation.periodKey("premium", targetT)]);
  assert.equal(candidates[0].length, 16);
  const entries = cache.entries();
  assert.deepEqual(
    entries.map(({ t, kind }) => ({ t, kind })),
    [
      { t: terminalT, kind: "chain" },
      { t: targetT, kind: "exact" },
    ],
    "cache bookkeeping exposes coordinates and capability kind, not retained-input bytes",
  );
  assert.ok(entries.every((entry) => !Object.hasOwn(entry, "key")));
  assert.equal(
    JSON.stringify({ generation, cache: entries }).includes("keyDerivationSecret"),
    false,
  );
  assert.equal(
    JSON.stringify({ generation, cache: entries }).includes(
      JSON.stringify([...keyDerivationSecret]),
    ),
    false,
  );
});
