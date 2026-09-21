// @ts-check
// Sibling to base suite: js/v1/test/key-attempt-runners.test.js

import test from "node:test";
import assert from "node:assert/strict";

import { runDirectPeriodChainTrace } from "../../../demo/browser/key-attempt-runners.js";
import { keyDerivationSecret } from "../../../demo/scenarios/fixtures.js";
import { PeriodChainCache } from "../core-client/PeriodChainCache.js";
import { PeriodChainRequestBuilder } from "../core-client/PeriodChainRequestBuilder.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { referencePeriodChainProfile } from "../referenceProfile.js";

const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

const CHAIN_SETUP = Object.freeze({
  at: "2025-10-23T14:20:00Z",
  seed: 1,
  period: Object.freeze({ length: 60, slots: 2 }),
  transportMode: "direct",
  fallback: false,
  primaryOffline: false,
  periodGrantKind: "chain",
  periodChainStrategy: "retain",
});

test("the chain runner records sealed terminal artifacts, wire labels, and a real cached-chain open", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: keyDerivationSecret(),
    geometry: GEOMETRY,
  });
  const trace = await runDirectPeriodChainTrace(CHAIN_SETUP, {
    periodKeySupply: periodFamilySupply({ families: { premium: generation }, chainWindows: 2 }),
    periodChainProfile: referencePeriodChainProfile,
    periodChainCacheFactory: (options) => new PeriodChainCache(options),
    requestBuilderFactory: (options) => new PeriodChainRequestBuilder(options),
  });
  const renderA = trace.steps.find((step) => step.kind === "render" && step.label === "A");
  const unlockA = trace.steps.find((step) => step.kind === "unlock" && step.label === "A");
  const advance = trace.steps.find((step) => step.kind === "advance");
  const openB = trace.steps.find((step) => step.kind === "open" && step.label === "B");

  assert.equal(trace.world.periodGrantKind, "chain");
  assert.equal(trace.world.periodChainStrategy, "retain");
  assert.deepEqual(Object.keys(renderA.publisherSealedTerminalKeys.premium), [
    "251023T2345",
    "251024T1145",
  ]);
  assert.ok(
    Object.values(renderA.publisherSealedTerminalKeys.premium).every(
      (blob) => typeof blob === "string" && blob.length > 0,
    ),
    "the publisher observation keeps its actual sealed terminal blobs",
  );
  assert.deepEqual(unlockA.wire.request.periodChainKeyCoordinates, [
    { accessGroup: "premium", t: ["251023T2345", "251024T1145"] },
  ]);
  assert.deepEqual(
    advance,
    {
      kind: "advance",
      from: "2025-10-23T14:20:00.000Z",
      to: "2025-10-23T15:10:00.000Z",
    },
    "B's observed chain-cache origin follows the runner's recorded clock transition",
  );
  assert.deepEqual(
    unlockA.wire.response,
    {
      contentKeyNames: ["bodytext"],
      periodKeyCoordinates: [],
      periodChainKeyCoordinates: [{ accessGroup: "premium", t: ["251023T2345", "251024T1145"] }],
      counts: { contentKeys: 1, periodKeys: 0, periodChainKeys: 2 },
    },
    "the direct response retains labels/counts, not returned chain-key bytes",
  );
  assert.deepEqual(openB.resolutionOrigin, {
    contentName: "bodytext",
    kind: "cached-period-chain-key",
    accessGroup: "premium",
    t: "251023T1500",
  });
  assert.deepEqual(
    openB.origin,
    {
      contentName: "bodytext",
      kind: "held-content-key",
    },
    "the content key recovered during resolution is the one the open consumes",
  );
  assert.equal(openB.opened, true);
  assert.equal(openB.error, null);
  assert.equal(
    JSON.stringify(trace).includes('"root"'),
    false,
    "no unobserved root or derivation stage is claimed",
  );
});
