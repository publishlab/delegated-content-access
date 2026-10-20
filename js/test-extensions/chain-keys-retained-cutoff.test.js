// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { base64urlEncode } from "../core-shared/codec.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";

const GROUP = "premium";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const CONTEXT = Object.freeze({ publisher: "https://publisher.example", ...GEOMETRY });
const WIDER = "251023T2000";
const NARROWER = "251023T1500";
const BETWEEN = "251023T1800";

test("a re-delivered lower cutoff of the held family leaves the wider chain key serving the gap", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(17),
    geometry: GEOMETRY,
  });
  const cache = new ChainKeyCache({ strategy: "retain" });
  await cache.put(GROUP, WIDER, (await generation.chainCapability(GROUP, WIDER)).key, CONTEXT);
  await cache.put(
    GROUP,
    NARROWER,
    (await generation.chainCapability(GROUP, NARROWER)).key,
    CONTEXT,
  );

  assert.deepEqual(
    cache
      .entries()
      .filter(({ kind }) => kind === "chain-key")
      .map(({ t }) => t),
    [WIDER],
    "the narrower re-delivery is absorbed by the wider retained chain key",
  );
  const expected = base64urlEncode(await generation.periodKey(GROUP, BETWEEN));
  assert.deepEqual(
    (await cache.candidates(GROUP, BETWEEN, CONTEXT)).map(base64urlEncode),
    [expected],
    "the position between the two cutoffs still derives from the wider chain key",
  );
});
