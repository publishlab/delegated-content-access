// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";
import { base64urlDecode, base64urlEncode } from "../core-shared/codec.js";
import { chainKeyCapabilitySource } from "../extensions/chain-keys/core-issuer/chainKeyCapabilitySource.js";
import { chainKeyCapabilityEncoderFor } from "../extensions/chain-keys/core-issuer/chainKeyCapabilityEncoder.js";
import { requireChainRepresentation } from "../extensions/chain-keys/core-issuer/chainKeyIssuerEngine.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import {
  periodKeysFromChainKey,
  resolveChainGeometry,
  settleChainGeometry,
} from "../extensions/chain-keys/core-shared/chainKeyConstruction.js";
const GEOMETRY = { chainsPerDay: 2, periodMinutes: 15 };
const NOW = { capturedAtMs: Date.parse("2025-10-23T14:20:00Z") };

/** @param {{ cutoff: string, key: string }[]} family @param {string[]} targets */
function request(family, targets = []) {
  return new DcaRequest({
    sealed: {
      contentKeys: [],
      chainKeys: family.map(({ cutoff, key }) => ({ accessGroup: "premium", cutoff, key })),
    },
    periodGeometry: GEOMETRY,
    ...(targets.length
      ? { requestedPeriodKeys: [{ accessGroup: "premium", periods: targets }] }
      : {}),
  });
}

test("off-grid-only supply establishes no authorized-unavailable condition, even for an article target", () => {
  const grant = { accessGroup: "premium", futurePeriodCount: 1, authorizePeriod: () => true };
  for (const targets of [[], ["251023T1415"]]) {
    const answer = chainKeyCapabilitySource().selection(
      request([{ cutoff: "251023T1407", key: "AQ" }], targets),
      NOW,
      [grant],
    )("premium");
    assert.deepEqual(answer, { unavailable: true });
    assert.equal(Object.hasOwn(answer, "authorizedUnavailable"), false);
  }
});

test("period projection rechecks authorization after an admitted article target", () => {
  const targets = ["251023T1415", "251023T1430", "251023T1500"];
  const grant = {
    accessGroup: "premium",
    futurePeriodCount: 0,
    authorizePeriod: (t) => t === targets[0],
  };
  const answer = chainKeyCapabilitySource({ representation: "period-keys" }).selection(
    request([{ cutoff: "251023T2345", key: "AQ" }], targets),
    NOW,
    [grant],
  )("premium");
  assert.deepEqual(
    answer.selected.flatMap((member) => member.targetTs),
    [targets[0]],
  );
});

test("reference composition refuses conflicting construction and output representation pins", () => {
  const config = {
    operatingIssuerNames: ["issuer"],
    accessPolicy: { decide: async () => ({}) },
    clock: { now: () => new Date(NOW.capturedAtMs) },
  };
  for (const factory of [
    referenceChainKeyProfile.familyGenerationFor,
    referenceChainKeyProfile.issuerEngineFor,
    referenceChainKeyProfile.explicitIssuerEngineFor,
  ])
    assert.throws(() => factory({ ...config, construction: "invented" }), { code: "bad_config" });
  assert.throws(
    () => referenceChainKeyProfile.issuerEngineFor({ ...config, representation: "period-keys" }),
    { code: "bad_config" },
  );
  assert.throws(
    () =>
      referenceChainKeyProfile.explicitIssuerEngineFor({ ...config, representation: "chain-keys" }),
    { code: "bad_config" },
  );
  assert.doesNotThrow(() =>
    referenceChainKeyProfile.issuerEngineFor({ ...config, representation: "chain-keys" }),
  );
  assert.doesNotThrow(() =>
    referenceChainKeyProfile.explicitIssuerEngineFor({ ...config, representation: "period-keys" }),
  );
});

test("projection below a supplied terminal returns exactly the cutoff prefix's recorded bytes", async () => {
  const fixture = JSON.parse(
    readFileSync(
      new URL(
        "../extensions/chain-keys/test/fixtures/dca-profile-chain-keys.vectors.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ).cases.find((row) => row.id === "c1");
  const rows = await periodKeysFromChainKey({
    chainKey: base64urlDecode(fixture.rootChainKey),
    accessGroup: "premium",
    suppliedT: "251023T2345",
    cutoffT: "251023T1430",
    geometry: GEOMETRY,
  });
  assert.equal(rows.length, 11);
  assert.equal(rows[10].t, "251023T1430");
  assert.deepEqual(
    rows.map((row) => base64urlEncode(row.key)),
    fixture.expansion.slice(0, 11),
  );
});

test("wire geometry refuses string typed numbers rather than coercing them", () => {
  for (const geometry of [
    { chainsPerDay: "2", periodMinutes: 15 },
    { chainsPerDay: 2, periodMinutes: "15" },
  ]) {
    assert.equal(resolveChainGeometry(geometry, "premium"), null);
    assert.throws(() => settleChainGeometry(geometry), { code: "bad_config" });
  }
});

test("construction labels use UTC in a native non-UTC process", () => {
  const url = new URL(
    "../extensions/chain-keys/core-shared/chainKeyConstruction.js",
    import.meta.url,
  ).href;
  const script = `import assert from 'node:assert/strict'; import {chainKeyLabelAt,chainKeyCoordinate} from ${JSON.stringify(url)}; const minute=Date.parse('2025-10-26T01:30:00Z')/60000; assert.equal(chainKeyLabelAt(minute),'251026T0130'); assert.equal(chainKeyCoordinate('251026T0130',{chainsPerDay:2,periodMinutes:15}).position,6);`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    env: { ...process.env, TZ: "Europe/Oslo" },
    encoding: "utf8",
  });
  assert.equal(child.status, 0, child.stderr);
});

test("encoder refuses a same-window cutoff above its supplied capability", () => {
  const encode = chainKeyCapabilityEncoderFor();
  assert.throws(
    () =>
      encode({
        kind: "chain-keys",
        accessGroup: "premium",
        entries: [{ t: "251023T1500", key: base64urlEncode(new Uint8Array(16)) }],
        interpretation: {
          geometry: GEOMETRY,
          selections: [{ suppliedT: "251023T1415", cutoffT: "251023T1500" }],
        },
      }),
    /backward cutoff/,
  );
});

test("independent horizon miss never falls through to the ordinary sorted-label grant", () => {
  const source = { selection: () => () => ({ miss: true }), capabilities: async function* () {} };
  const select = requireChainRepresentation(source).selection(request([]), NOW, []);
  assert.deepEqual(select("premium", 1, { authorizePeriod: () => true }), { unavailable: true });
  assert.deepEqual(select("premium", 1, {}), { miss: true });
});
