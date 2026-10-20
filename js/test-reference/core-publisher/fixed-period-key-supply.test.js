// @ts-check
//
// The strict fixed period-key supply the test Sealer factory composes. It
// answers the coordinates its table lists and refuses every other one, so a
// render that asks for an unexpected period fails instead of wrapping under a
// key nobody chose.

import test from "node:test";
import assert from "node:assert/strict";

import { fixedPeriodKeySupply } from "../../core-publisher/testing/fixedPeriodKeySupply.js";

const T14 = "251023T1400";
const T15 = "251023T1500";

test("a listed coordinate answers its key, as a new copy each time", async () => {
  const key = new Uint8Array(16).fill(0xa1);
  const supply = fixedPeriodKeySupply({ premium: { [T14]: key } });
  key.fill(0);

  const first = await supply.derive("premium", T14);
  assert.deepEqual(first, new Uint8Array(16).fill(0xa1), "the table holds a copy of the key");
  first.fill(0);
  assert.deepEqual(
    await supply.derive("premium", T14),
    new Uint8Array(16).fill(0xa1),
    "a caller that changes an answer does not change the table",
  );
});

test("an unlisted period or access group is refused with bad_config", async () => {
  const supply = fixedPeriodKeySupply({ premium: { [T14]: new Uint8Array(16) } });
  await assert.rejects(supply.derive("premium", T15), {
    code: "bad_config",
    message: `no fixed period key for premium at ${T15}`,
  });
  await assert.rejects(supply.derive("sport", T14), {
    code: "bad_config",
    message: `no fixed period key for sport at ${T14}`,
  });
});

test("the table is records of bytes by access group and period", () => {
  for (const keys of [null, [], "keys", { premium: [] }, { premium: { [T14]: "key" } }]) {
    assert.throws(
      () => fixedPeriodKeySupply(keys),
      {
        code: "bad_config",
        message: "fixed period keys are records of bytes by access group and period",
      },
      JSON.stringify(keys),
    );
  }
});
