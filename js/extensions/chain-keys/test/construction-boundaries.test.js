// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import {
  chainKeyCoordinatePrimitive,
  chainKeyLabelPrimitive,
  chainKeyRootPrimitive,
  chainKeyStepPrimitive,
  chainKeyLeafPrimitive,
  chainKeyFromChainKey,
  periodKeyFromChainKey,
  periodKeysFromChainKey,
  settleChainGeometry,
} from "../core-shared/chainKeyConstruction.js";

const GEOMETRY = { chainsPerDay: 2, periodMinutes: 15 };
const SECRET = new Uint8Array(32).fill(7);
const GROUP = "premium";

test("canonical primitives refuse a period-aligned start inside a stationary window", async () => {
  const { windowStart } = chainKeyCoordinatePrimitive({ t: "251023T0000", ...GEOMETRY });
  const input = { ...GEOMETRY, windowStart, position: 0 };
  const root = { ...GEOMETRY, windowStart, accessGroup: GROUP, keyDerivationSecret: SECRET };
  const terminal = await chainKeyRootPrimitive(root);
  const atZero = await chainKeyFromChainKey({
    chainKey: terminal,
    accessGroup: GROUP,
    suppliedT: "251023T1145",
    targetT: "251023T0000",
    geometry: settleChainGeometry(GEOMETRY),
  });
  const atOne = await chainKeyFromChainKey({
    chainKey: terminal,
    accessGroup: GROUP,
    suppliedT: "251023T1145",
    targetT: "251023T0015",
    geometry: settleChainGeometry(GEOMETRY),
  });
  assert.equal(chainKeyLabelPrimitive(input), "251023T0000");
  assert.equal(terminal.length, 16);
  const leaf = { ...input, accessGroup: GROUP, chainKey: atZero };
  assert.deepEqual(
    await chainKeyLeafPrimitive(leaf),
    await periodKeyFromChainKey({
      chainKey: atZero,
      accessGroup: GROUP,
      t: "251023T0000",
      geometry: settleChainGeometry(GEOMETRY),
    }),
  );
  assert.deepEqual(
    await chainKeyStepPrimitive({ ...leaf, chainKey: atOne }),
    atZero,
    "Step position zero is valid and derives the canonical preceding key",
  );

  // Adding one whole period preserves the period grid but is not a window start.
  // An off-period input would be rejected earlier and miss this round-trip guard.
  const windowStartInside = windowStart + GEOMETRY.periodMinutes;
  assert.throws(() => chainKeyLabelPrimitive({ ...input, windowStart: windowStartInside }), {
    code: "bad_config",
  });
  for (const operation of [
    () => chainKeyRootPrimitive({ ...root, windowStart: windowStartInside }),
    () => chainKeyStepPrimitive({ ...leaf, windowStart: windowStartInside }),
    () => chainKeyLeafPrimitive({ ...leaf, windowStart: windowStartInside }),
  ]) {
    await assert.rejects(operation, { code: "bad_config" });
  }
});

test("period projection refuses another window even when its cutoff position is lower", async () => {
  const geometry = settleChainGeometry(GEOMETRY);
  const { windowStart } = chainKeyCoordinatePrimitive({ t: "251023T1145", ...GEOMETRY });
  const chainKey = await chainKeyRootPrimitive({
    ...GEOMETRY,
    windowStart,
    accessGroup: GROUP,
    keyDerivationSecret: SECRET,
  });
  const input = { chainKey, accessGroup: GROUP, suppliedT: "251023T1145", geometry };
  const valid = await periodKeysFromChainKey({ ...input, cutoffT: "251023T0045" });
  assert.deepEqual(
    valid.map(({ t }) => t),
    ["251023T0000", "251023T0015", "251023T0030", "251023T0045"],
  );
  for (const entry of valid) {
    const positioned = await chainKeyFromChainKey({ ...input, targetT: entry.t });
    assert.deepEqual(
      entry.key,
      await periodKeyFromChainKey({
        chainKey: positioned,
        accessGroup: GROUP,
        t: entry.t,
        geometry,
      }),
    );
  }
  for (const cutoffT of ["251022T1245", "251023T1245"]) {
    const cutoff = chainKeyCoordinatePrimitive({ t: cutoffT, ...GEOMETRY });
    assert.notEqual(cutoff.windowStart, windowStart);
    assert.equal(cutoff.position, 3, "the forward-position refusal cannot hide a window error");
    await assert.rejects(periodKeysFromChainKey({ ...input, cutoffT }), { code: "bad_config" });
  }
});

test("canonical coordinates reject calendar aliases instead of normalizing their fields", () => {
  for (const t of ["000229T0000", "240229T0000", "991231T2345"]) {
    const coordinate = chainKeyCoordinatePrimitive({ t, ...GEOMETRY });
    assert.equal(chainKeyLabelPrimitive({ ...coordinate, ...GEOMETRY }), t);
  }
  for (const t of [
    "251023T2400",
    "251032T0000",
    "250229T0000",
    "251023T1260",
    "251323T0000",
    "250023T0000",
    "251000T0000",
    "251023T2360",
  ]) {
    assert.throws(() => chainKeyCoordinatePrimitive({ t, ...GEOMETRY }), { code: "bad_config" });
  }
});
