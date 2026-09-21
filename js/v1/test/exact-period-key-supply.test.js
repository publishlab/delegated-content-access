import test from "node:test";
import assert from "node:assert/strict";

import { exactPeriodKeySupply } from "../demo/support/exactPeriodKeySupply.js";
import { Random } from "../demo/actors/Random.js";

test("exact period keys are stable per nested coordinate and independent elsewhere", async () => {
  const supply = exactPeriodKeySupply({ random: new Random({ seed: 41 }) });
  const first = await supply.derive("premium", "251023T14");
  assert.equal(first.length, 16);
  assert.deepEqual(await supply.derive("premium", "251023T14"), first);
  assert.notDeepEqual(await supply.derive("premium", "251023T15"), first);
  assert.notDeepEqual(await supply.derive("subscriber", "251023T14"), first);
});

test("exact period keys copy configured and returned bytes defensively", async () => {
  const configured = new Uint8Array(16).fill(9);
  const supply = exactPeriodKeySupply({ keys: { premium: { now: configured } } });
  configured.fill(3);

  const returned = await supply.derive("premium", "now");
  assert.deepEqual(returned, new Uint8Array(16).fill(9));
  returned.fill(7);
  assert.deepEqual(await supply.derive("premium", "now"), new Uint8Array(16).fill(9));
});

test("accessGroup and t delimiters cannot collide in the nested registry", async () => {
  const supply = exactPeriodKeySupply({ random: new Random({ seed: 43 }) });
  const left = await supply.derive("a|b", "c");
  const right = await supply.derive("a", "b|c");
  assert.notDeepEqual(left, right);
});

test("a supply produces canonical 16-byte leaves", async () => {
  const supply = exactPeriodKeySupply({ random: new Random({ seed: 45 }) });
  assert.deepEqual(Object.keys(supply), ["derive"]);
  assert.equal((await supply.derive("premium", "251023T14")).length, 16);
});

test("a configured noncanonical key width is refused", () => {
  assert.throws(
    () =>
      exactPeriodKeySupply({
        keys: { premium: { now: new Uint8Array(24).fill(9) } },
      }),
    (/** @type {any} */ error) =>
      error.code === "bad_config" &&
      /exact period keys must be 16-byte Uint8Arrays/.test(error.message),
  );
});

test("the removed profile selector is refused", () => {
  assert.throws(
    () => exactPeriodKeySupply({ exactProfile: "dca-v1-exact-period-24" }),
    (/** @type {any} */ error) => error.code === "unsupported_option",
  );
});
