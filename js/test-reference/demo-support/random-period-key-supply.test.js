import test from "node:test";
import assert from "node:assert/strict";

import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
import { Random } from "../../demo/actors/Random.js";

test("period keys are stable per nested coordinate and independent elsewhere", async () => {
  const supply = randomPeriodKeySupply({ random: new Random({ seed: 41 }) });
  const first = await supply.derive("premium", "251023T1400");
  assert.equal(first.length, 16);
  assert.deepEqual(await supply.derive("premium", "251023T1400"), first);
  assert.notDeepEqual(await supply.derive("premium", "251023T1500"), first);
  assert.notDeepEqual(await supply.derive("subscriber", "251023T1400"), first);
});

test("period keys copy configured and returned bytes defensively", async () => {
  const configured = new Uint8Array(16).fill(9);
  const supply = randomPeriodKeySupply({ keys: { premium: { now: configured } } });
  configured.fill(3);

  const returned = await supply.derive("premium", "now");
  assert.deepEqual(returned, new Uint8Array(16).fill(9));
  returned.fill(7);
  assert.deepEqual(await supply.derive("premium", "now"), new Uint8Array(16).fill(9));
});

test("accessGroup and t delimiters cannot collide in the nested registry", async () => {
  const supply = randomPeriodKeySupply({ random: new Random({ seed: 43 }) });
  const left = await supply.derive("a|b", "c");
  const right = await supply.derive("a", "b|c");
  assert.notDeepEqual(left, right);
});

test("a supply produces canonical 16-byte period keys", async () => {
  const supply = randomPeriodKeySupply({ random: new Random({ seed: 45 }) });
  assert.deepEqual(Object.keys(supply), ["derive"]);
  assert.equal((await supply.derive("premium", "251023T1400")).length, 16);
});

test("a configured noncanonical key width is refused", () => {
  assert.throws(
    () =>
      randomPeriodKeySupply({
        keys: { premium: { now: new Uint8Array(24).fill(9) } },
      }),
    (/** @type {any} */ error) =>
      error.code === "bad_config" && /period keys must be 16-byte Uint8Arrays/.test(error.message),
  );
});

test("an unknown option is refused", () => {
  assert.throws(
    () => randomPeriodKeySupply({ inventedSelector: "dca-profile-period-keys-invented" }),
    (/** @type {any} */ error) => error.code === "unsupported_option",
  );
});
