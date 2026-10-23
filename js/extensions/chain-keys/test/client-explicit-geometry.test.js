// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { base64urlEncode } from "../../../core-shared/codec.js";
import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";

const geometry = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const context = Object.freeze({ publisher: "https://publisher.example", ...geometry });

test("the chain profile admits period-key output at a coordinate covered by a chain request", () => {
  const request = {
    sealed: {
      chainKeys: [
        {
          accessGroup: "premium",
          cutoff: "251023T1400",
          key: base64urlEncode(new Uint8Array(16).fill(7)),
        },
      ],
    },
    periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
  };

  assert.equal(
    explicitChainKeyClientProfile.acceptsPeriodKeyResponseCoordinate(
      "premium",
      "251023T1400",
      request,
    ),
    true,
  );
  assert.equal(
    explicitChainKeyClientProfile.acceptsPeriodKeyResponseCoordinate("premium", "251023T1415", {
      ...request,
      sealed: { chainKeys: [] },
    }),
    false,
    "an unpresented family has no chain-key reach",
  );
});

test("the client cache files and derives only canonical 16-byte positioned chain keys", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry,
  });
  const terminalT = "251023T2345";
  const targetT = "251023T1415";
  const cache = new ChainKeyCache();
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

test("chain response geometry comes only from the captured request, never response metadata", () => {
  const request = Object.freeze({
    periodGeometry: geometry,
    sealed: {
      chainKeys: [
        {
          accessGroup: "premium",
          cutoff: "251023T1400",
          key: base64urlEncode(new Uint8Array(16).fill(7)),
        },
      ],
    },
  });
  const response = {
    keys: {
      chainKeys: [
        {
          accessGroup: "premium",
          cutoff: "251023T1400",
          key: base64urlEncode(new Uint8Array(16).fill(8)),
        },
      ],
    },
  };
  const parameters = (answer, asked = request) =>
    explicitChainKeyClientProfile.parametersForResponse(
      answer,
      null,
      "premium",
      asked,
      "251023T1400",
    );
  assert.deepEqual(parameters(response), {
    ...geometry,
    windowMinutes: 720,
    positionsPerWindow: 48,
  });
  assert.deepEqual(
    parameters({ ...response, periodGeometry: { chainsPerDay: 4, periodMinutes: 30 } }),
    { ...geometry, windowMinutes: 720, positionsPerWindow: 48 },
  );
  assert.equal(parameters(response, { ...request, periodGeometry: undefined }), null);
  assert.equal(parameters(response, { ...request, periodGeometry: { periodMinutes: 15 } }), null);
  assert.equal(
    explicitChainKeyClientProfile.parametersForResponse(
      response,
      null,
      "premium",
      request,
      "251023T1415",
    ),
    null,
  );
});
