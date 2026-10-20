// @ts-check
//
// The chain-key supply as a publisher contribution. `periodFamilyContribution`
// takes the same closed configuration as `periodFamilySupply` and claims the
// period-key supply seam with its result, so the chain bytes are the supply's.
// The render compares against a record written once from a plain Sealer with
// the supply nested by hand, before composition existed (`fixtures/`).

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { composePublisherConfig } from "../../../core-publisher/publisherComposition.js";
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import {
  periodFamilyContribution,
  periodFamilySupply,
} from "../core-publisher/periodFamilySupply.js";
import {
  assertRendersRecord,
  recordedPublisherWorld,
} from "../../../test-lib/fixtures/publisher-composition-world.js";

const CHAIN_SUPPLY = JSON.parse(
  readFileSync(
    new URL("./fixtures/publisher-composition--chain-supply.json", import.meta.url),
    "utf8",
  ),
);

/**
 * The recorded chain family, as `periodFamilySupply` takes it.
 *
 * @param {any} chain - a record's `input.chain`
 * @param {{ derive: Function }} periodKeySupply
 */
function familyConfig(chain, periodKeySupply) {
  return {
    periodKeySupply: /** @type {any} */ (periodKeySupply),
    families: Object.fromEntries(
      chain.groups.map((/** @type {string} */ group) => [
        group,
        periodFamilyGeneration({
          keyDerivationSecret: Buffer.from(chain.keyDerivationSecret, "base64url"),
          geometry: chain.geometry,
        }),
      ]),
    ),
    chainWindows: chain.chainWindows,
    // This recorded composition deliberately exercises two item alternatives.
    chainItemSlots: 2,
  };
}

/** @param {() => unknown} call */
function refusal(call) {
  try {
    call();
  } catch (error) {
    return { code: /** @type {any} */ (error)?.code, message: /** @type {any} */ (error)?.message };
  }
  return assert.fail("expected a typed refusal");
}

describe("The chain-key contribution", () => {
  test("createPublisher and the composed Sealer render the hand-nested record", async () => {
    const world = await recordedPublisherWorld(CHAIN_SUPPLY.input);
    const family = familyConfig(CHAIN_SUPPLY.input.chain, world.periodKeySupply);

    await assertRendersRecord(
      await createPublisher(world.config(), periodFamilyContribution(family)).publish(
        world.article(),
      ),
      CHAIN_SUPPLY,
    );
    const composed = composePublisherConfig(world.config(), periodFamilyContribution(family));
    assert.equal(composed.owners.periodKeySupply, "chain-keys");
    await assertRendersRecord(await world.sealed(new Sealer(composed.config)), CHAIN_SUPPLY);
  });

  test("the contribution carries the supply and claims nothing else", async () => {
    const world = await recordedPublisherWorld(CHAIN_SUPPLY.input);
    const contribution = periodFamilyContribution(
      familyConfig(CHAIN_SUPPLY.input.chain, world.periodKeySupply),
    );

    assert.deepEqual(Object.keys(contribution), ["name", "periodKeySupply"]);
    assert.equal(contribution.name, "chain-keys");
    assert.deepEqual(Object.keys(contribution.periodKeySupply), ["derive", "familyPlan"]);
  });

  test("a base periodKeySupply beside it is a second owner, refused before any supply call", async () => {
    const world = await recordedPublisherWorld(CHAIN_SUPPLY.input);
    let derives = 0;
    const counting = {
      derive: (/** @type {string} */ group, /** @type {string} */ t) => {
        derives++;
        return world.periodKeySupply.derive(group, t);
      },
    };
    const config = { ...world.config(), periodKeySupply: counting };
    const contribution = periodFamilyContribution(familyConfig(CHAIN_SUPPLY.input.chain, counting));
    const expected = {
      code: "bad_config",
      message: "periodKeySupply has two owners: the base configuration and chain-keys",
    };

    assert.deepEqual(
      refusal(() => createPublisher(config, contribution)),
      expected,
    );
    assert.deepEqual(
      refusal(() => composePublisherConfig(config, contribution)),
      expected,
    );
    assert.equal(derives, 0);
  });

  test("it refuses what periodFamilySupply refuses, with the same refusal", () => {
    for (const config of [
      { families: {}, chainWindows: 2, surprise: true },
      { families: {} },
      { families: {}, chainWindows: 0 },
    ]) {
      assert.deepEqual(
        refusal(() => periodFamilyContribution(/** @type {any} */ (config))),
        refusal(() => periodFamilySupply(/** @type {any} */ (config))),
      );
    }
  });
});
