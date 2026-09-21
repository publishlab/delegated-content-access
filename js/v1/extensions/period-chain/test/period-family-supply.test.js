// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";

const SECRET = new Uint8Array(32).fill(7);

/**
 * A refusal matcher that reads the typed code the port maps on as well as the
 * wording. A message-only matcher passes while the code goes wrong.
 *
 * @param {RegExp} message
 * @param {string} [code]
 */
function refusalOf(message, code = "bad_config") {
  return (/** @type {any} */ error) => {
    assert.equal(error.name, "DcaError");
    assert.equal(error.code, code);
    assert.match(error.message, message);
    return true;
  };
}
const AT = new Date("2025-10-23T14:20:00Z");
// Ten minutes into the second-to-last position of the 12:00-24:00 stationary window.
const NEAR_WINDOW_END = new Date("2025-10-23T23:40:00Z");

test("family supply keeps base exact fallback separate from fixed-label chain-family planning", async () => {
  const calls = [];
  const exactSupply = {
    async derive(accessGroup, t) {
      calls.push([accessGroup, t]);
      return new Uint8Array(16).fill(t.length);
    },
  };
  const premium = periodFamilyGeneration({
    keyDerivationSecret: SECRET,
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({ exactSupply, families: { premium }, chainWindows: 2 });

  const ordinary = supply.familyPlan("archive", AT, { length: 60, slots: 2 });
  assert.deepEqual(ordinary.periods, ["251023T14", "251023T15"]);
  assert.equal("chain" in ordinary, false);
  assert.deepEqual(await ordinary.exactAt("251023T14"), new Uint8Array(16).fill(9));
  assert.deepEqual(calls, [["archive", "251023T14"]]);

  const chain = supply.familyPlan("premium", AT, { length: 60, slots: 2 });
  assert.deepEqual(
    chain.periods,
    ["251023T1415", "251023T1430"],
    "slots survive; base hourly geometry does not",
  );
  assert.deepEqual(chain.chain.geometry, { chainsPerDay: 2, periodMinutes: 15 });
  assert.deepEqual(chain.chain.suppliedTs, ["251023T2345", "251024T1145"]);
  assert.deepEqual(
    await chain.exactAt("251023T1415"),
    await premium.periodKey("premium", "251023T1415"),
  );
  assert.deepEqual(
    await chain.chain.capabilityAt("251023T2345"),
    (await premium.chainCapability("premium", "251023T2345")).key,
  );
  assert.deepEqual(
    await supply.derive("premium", "251023T1415"),
    await chain.exactAt("251023T1415"),
  );

  const leaf = await chain.exactAt("251023T1415");
  leaf.fill(0);
  assert.notDeepEqual(leaf, await chain.exactAt("251023T1415"), "all outward key bytes are copies");
  // The refusal is per coordinate, so each one is asserted beside the
  // planned coordinate the same handle still answers.
  await assert.rejects(chain.exactAt("251023T1445"), refusalOf(/planned coordinate/));
  assert.deepEqual(
    await chain.exactAt("251023T1430"),
    await premium.periodKey("premium", "251023T1430"),
  );
  await assert.rejects(chain.chain.capabilityAt("251023T1415"), refusalOf(/planned coordinate/));
  assert.deepEqual(
    await chain.chain.capabilityAt("251024T1145"),
    (await premium.chainCapability("premium", "251024T1145")).key,
  );
});

test("family supply accepts own frozen generation handles only", () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: SECRET,
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const inherited = Object.create({ premium: generation });
  const supply = periodFamilySupply({ families: inherited, chainWindows: 2 });
  assert.throws(() => supply.familyPlan("premium", AT, { slots: 1 }), refusalOf(/no exact source/));
  // The supply plans that same generation under an own key, so the refusal
  // turns on where the name sits rather than on the handle.
  assert.deepEqual(
    periodFamilySupply({ families: { premium: generation }, chainWindows: 2 }).familyPlan(
      "premium",
      AT,
      {
        slots: 1,
      },
    ).periods,
    ["251023T1415"],
  );
  assert.throws(
    () => periodFamilySupply({ families: { premium: { ...generation } }, chainWindows: 2 }),
    refusalOf(/frozen periodFamilyGeneration handle/),
  );

  // The bound is inclusive at both ends, so each refusal is asserted beside
  // the neighbouring value the supply accepts.
  for (const chainWindows of [0, 3]) {
    assert.throws(
      () => periodFamilySupply({ families: {}, chainWindows }),
      refusalOf(/chainWindows is from 1 through 2/),
      `chainWindows ${chainWindows} is outside the bound`,
    );
  }
  for (const chainWindows of [1, 2]) {
    assert.deepEqual(
      periodFamilySupply({ families: { premium: generation }, chainWindows }).familyPlan(
        "premium",
        AT,
        {
          slots: 1,
        },
      ).chain.suppliedTs.length,
      chainWindows,
      `chainWindows ${chainWindows} is inside the bound and supplies that many window terminals`,
    );
  }
});

test("a chain family refuses a plan wrapping a period no supplied capability reaches", () => {
  const premium = periodFamilyGeneration({
    keyDerivationSecret: SECRET,
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({ families: { premium }, chainWindows: 1 });

  // The geometry fact the plan has to respect: four 15-minute slots from
  // 23:30 run past the only terminal a one-window supply carries.
  assert.notEqual(
    premium.coordinateFor("251024T0015").windowStart,
    premium.coordinateFor("251023T2345").windowStart,
    "the fourth planned period sits in the window after the only supplied terminal",
  );

  assert.throws(
    () => supply.familyPlan("premium", NEAR_WINDOW_END, { length: 60, slots: 4 }),
    (error) => {
      assert.equal(error.code, "bad_config");
      assert.match(error.message, /no supplied period-chain capability reaches/);
      return true;
    },
  );
});

test("the supplied window boundary is the exact edge a chain family plan may reach", () => {
  const premium = periodFamilyGeneration({
    keyDerivationSecret: SECRET,
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const oneWindow = periodFamilySupply({ families: { premium }, chainWindows: 1 });

  const upToTerminal = oneWindow.familyPlan("premium", NEAR_WINDOW_END, { length: 60, slots: 2 });
  assert.deepEqual(upToTerminal.periods, ["251023T2330", "251023T2345"]);
  assert.deepEqual(
    upToTerminal.chain.suppliedTs,
    ["251023T2345"],
    "the last planned period is the terminal of the only supplied window",
  );

  assert.throws(
    () => oneWindow.familyPlan("premium", NEAR_WINDOW_END, { length: 60, slots: 3 }),
    (error) => {
      assert.equal(error.code, "bad_config");
      assert.match(
        error.message,
        /wraps period 251024T0000 .*no supplied period-chain capability reaches/s,
      );
      return true;
    },
    "the first period of the next window is one period too far",
  );

  const twoWindows = periodFamilySupply({ families: { premium }, chainWindows: 2 });
  const crossing = twoWindows.familyPlan("premium", NEAR_WINDOW_END, { length: 60, slots: 3 });
  assert.deepEqual(crossing.periods, ["251023T2330", "251023T2345", "251024T0000"]);
  assert.deepEqual(
    crossing.chain.suppliedTs,
    ["251023T2345", "251024T1145"],
    "the explicit second window carries the terminal that reaches the crossing period",
  );
});

function generationAnswering(coordinateFor) {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: SECRET,
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  return Object.freeze({
    geometry: generation.geometry,
    constructionProfile: generation.constructionProfile,
    coordinateFor,
    periodKey: (accessGroup, t) => generation.periodKey(accessGroup, t),
    chainCapability: (accessGroup, t) => generation.chainCapability(accessGroup, t),
  });
}

test("a chain family refuses a generation answering a planned period with no coordinate", () => {
  const premium = generationAnswering(() => undefined);
  const supply = periodFamilySupply({ families: { premium }, chainWindows: 1 });

  assert.throws(
    () => supply.familyPlan("premium", NEAR_WINDOW_END, { length: 60, slots: 4 }),
    (error) => {
      assert.equal(error.code, "bad_config");
      assert.match(error.message, /no usable coordinate for period 251023T2330/);
      return true;
    },
  );
});

test("a chain family refuses a coordinate carrying no window start over accepting the under-reaching plan", () => {
  const premium = generationAnswering((t) => ({ t }));
  const supply = periodFamilySupply({ families: { premium }, chainWindows: 1 });

  // This case reuses the 2/15 geometry, 23:40 instant, four slots and single
  // window the reach test refuses. A coordinate without a window start
  // compares every planned window equal to every supplied one, so the
  // refusal has to come first.
  assert.throws(
    () => supply.familyPlan("premium", NEAR_WINDOW_END, { length: 60, slots: 4 }),
    (error) => {
      assert.equal(error.code, "bad_config");
      assert.match(error.message, /no usable coordinate for period 251023T2330/);
      return true;
    },
  );
});

test("a canonical family plans 16-byte leaves and state", async () => {
  const premium = periodFamilyGeneration({
    keyDerivationSecret: SECRET,
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({ families: { premium }, chainWindows: 2 });
  const plan = supply.familyPlan("premium", AT, { length: 60, slots: 2 });

  assert.equal((await plan.exactAt(plan.periods[0])).length, 16);
});

test("an exactSupply admits 16-byte leaves and refuses other widths", async () => {
  const canonical = periodFamilySupply({
    exactSupply: { derive: async () => new Uint8Array(16).fill(4) },
    families: {},
    chainWindows: 2,
  });
  const plan = canonical.familyPlan("archive", AT, { length: 60, slots: 2 });
  assert.equal((await plan.exactAt(plan.periods[0])).length, 16);

  const mismatched = periodFamilySupply({
    exactSupply: { derive: async () => new Uint8Array(32).fill(4) },
    families: {},
    chainWindows: 2,
  });
  const wrong = mismatched.familyPlan("archive", AT, { length: 60, slots: 2 });
  await assert.rejects(
    wrong.exactAt(wrong.periods[0]),
    refusalOf(/a period-family exactSupply returns 16 exact-key bytes/),
  );
});

test("an exactSupply naming an unknown profile is refused at construction", () => {
  assert.throws(
    () =>
      periodFamilySupply({
        exactSupply: { exactProfile: true, derive: async () => new Uint8Array(16) },
        families: {},
        chainWindows: 2,
      }),
    refusalOf(/has no width profile selector/, "unsupported_option"),
  );
});

test("a generation whose capability is 32 bytes is refused", async () => {
  const premium = periodFamilyGeneration({
    keyDerivationSecret: SECRET,
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const widened = Object.freeze({
    ...premium,
    chainCapability: async (/** @type {string} */ _group, /** @type {string} */ t) =>
      Object.freeze({
        t,
        key: new Uint8Array(32).fill(1),
      }),
  });
  const supply = periodFamilySupply({ families: { premium: widened }, chainWindows: 2 });
  const plan = supply.familyPlan("premium", AT, { length: 60, slots: 2 });
  await assert.rejects(
    plan.chain.capabilityAt(plan.chain.suppliedTs[0]),
    refusalOf(/a period-family generation returns its planned 16-byte capability/),
  );
});

test("a generation cannot invent or relabel its canonical construction profile", () => {
  const premium = periodFamilyGeneration({
    keyDerivationSecret: SECRET,
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const unknown = Object.freeze({
    ...premium,
    constructionProfile: Object.freeze({
      ...premium.constructionProfile,
      constructionId: "dca-period-chain-invented-v1",
    }),
  });
  assert.throws(
    () => periodFamilySupply({ families: { premium: unknown }, chainWindows: 2 }),
    refusalOf(/there is no period-chain construction profile/, "unsupported_option"),
  );

  const mismatched = Object.freeze({
    ...premium,
    constructionProfile: Object.freeze({
      ...premium.constructionProfile,
      stateBytes: 32,
    }),
  });
  assert.throws(
    () => periodFamilySupply({ families: { premium: mismatched }, chainWindows: 2 }),
    refusalOf(/carries the registered paired widths/),
  );
});
