// @ts-check
//
// Omission as a publisher contribution: `omissionContribution(config)` through
// `createPublisher` and `composePublisherConfig`, and `OmittingSealer` over the
// same composition. The renders compare against records written once from
// `OmittingSealer` as it stood before composition existed (`fixtures/`).

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import { composePublisherConfig } from "../../../core-publisher/publisherComposition.js";
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { omissionContribution, omissionSealing } from "../core-publisher/omissionSealing.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import {
  assertRendersRecord,
  recordedPublisherWorld,
  testAadContentKeyWrap,
} from "../../../test-lib/fixtures/publisher-composition-world.js";
import { ARTICLE, ISSUER_A, world } from "../test-lib/world.js";

/** @param {string} name */
function record(name) {
  return JSON.parse(
    readFileSync(
      new URL(`./fixtures/publisher-composition--${name}.json`, import.meta.url),
      "utf8",
    ),
  );
}

const RECORDS = {
  active: record("omission-active"),
  inactive: record("omission-inactive"),
  mixed: record("omission-mixed"),
};
const INACTIVE_TEST_AAD = record("omission-inactive-test-aad");

/** @param {() => unknown} call */
function refusal(call) {
  try {
    call();
  } catch (error) {
    return { code: /** @type {any} */ (error)?.code, message: /** @type {any} */ (error)?.message };
  }
  return assert.fail("expected a typed refusal");
}

describe("Omission renders through the composed path", () => {
  for (const [label, recorded] of Object.entries(RECORDS)) {
    test(`${label}: createPublisher, the composed Sealer and OmittingSealer render the record`, async () => {
      const world = await recordedPublisherWorld(recorded.input);

      let config = world.config();
      await assertRendersRecord(
        await createPublisher(config, omissionContribution(config)).publish(world.article()),
        recorded,
      );
      config = world.config();
      await assertRendersRecord(
        await world.sealed(
          new Sealer(composePublisherConfig(config, omissionContribution(config)).config),
        ),
        recorded,
      );
      await assertRendersRecord(await world.sealed(new OmittingSealer(world.config())), recorded);
      config = world.config();
      await assertRendersRecord(
        await world.sealed(
          new Sealer(/** @type {any} */ ({ ...config, ...omissionSealing(config) })),
        ),
        recorded,
      );
    });
  }

  test("inactive omission keeps the base contentKeyWrapStrategy", async () => {
    const world = await recordedPublisherWorld(INACTIVE_TEST_AAD.input);
    const config = world.config();
    const contribution = omissionContribution(config);

    assert.equal(Object.hasOwn(contribution, "contentKeyWrapStrategy"), false);
    assert.equal(Object.hasOwn(contribution, "requiredSeams"), false);
    const composed = composePublisherConfig(config, contribution);
    assert.equal(composed.owners.contentKeyWrapStrategy, "base");
    assert.equal(composed.config.contentKeyWrapStrategy, testAadContentKeyWrap);
    await assertRendersRecord(
      await createPublisher(config, contribution).publish(world.article()),
      INACTIVE_TEST_AAD,
    );
    await assertRendersRecord(
      await world.sealed(new OmittingSealer(world.config())),
      INACTIVE_TEST_AAD,
    );
  });

  test("active omission beside a base contentKeyWrapStrategy is refused at construction", async () => {
    const world = await recordedPublisherWorld(RECORDS.active.input);
    const config = world.config();
    const counts = { random: 0, clock: 0, seal: 0, derive: 0, planner: 0, wrap: 0 };
    const { random, clock, keySealing, periodKeySupply, issuerSupplyPlanFor } = config;
    Object.assign(config, {
      random: { bytes: (/** @type {number} */ n) => (counts.random++, random.bytes(n)) },
      clock: { now: () => (counts.clock++, clock.now()) },
      keySealing: {
        seal: (/** @type {any[]} */ ...args) => (counts.seal++, keySealing.seal(...args)),
      },
      periodKeySupply: {
        derive: (/** @type {string} */ group, /** @type {string} */ t) => (
          counts.derive++,
          periodKeySupply.derive(group, t)
        ),
      },
      issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) => (
        counts.planner++,
        issuerSupplyPlanFor(issuer, render)
      ),
      contentKeyWrapStrategy: {
        aad: () => (counts.wrap++, undefined),
        entry: (/** @type {any} */ wrap) => (counts.wrap++, wrap),
      },
    });
    const expected = {
      code: "bad_config",
      message:
        "contentKeyWrapStrategy has two owners: the base configuration and content-key-seal-omission",
    };

    assert.deepEqual(
      refusal(() => createPublisher(config, omissionContribution(config))),
      expected,
    );
    assert.deepEqual(
      refusal(() => new OmittingSealer(config)),
      expected,
    );
    assert.deepEqual(counts, { random: 0, clock: 0, seal: 0, derive: 0, planner: 0, wrap: 0 });
  });

  test("an active issuer with no period-key supply anywhere is refused", async () => {
    const world = await recordedPublisherWorld(RECORDS.active.input);
    const config = world.config({ basePeriodKeySupply: false });

    assert.deepEqual(
      refusal(() => createPublisher(config, omissionContribution(config))),
      {
        code: "bad_config",
        message: `${EXTENSION_NAME} needs periodKeySupply, and this render has no periodKeySupply to route through`,
      },
    );
  });
});

describe("Omission's issuer members on the real entry", () => {
  test("a misspelled accessGroups is refused", async () => {
    const world = await recordedPublisherWorld(RECORDS.mixed.input);
    const config = world.config();
    const { accessGroups, ...rest } = config.issuers[0];
    config.issuers[0] = { ...rest, accessGroup: accessGroups };
    const expected = {
      code: "unsupported_option",
      message: "an issuer entry has no accessGroup yet, and will not pretend to",
    };

    assert.deepEqual(
      refusal(() => createPublisher(config, omissionContribution(config))),
      expected,
    );
    assert.deepEqual(
      refusal(() => new OmittingSealer(config)),
      expected,
    );
  });

  test("an active issuer's members are the contribution's, not base's", async () => {
    const world = await recordedPublisherWorld(RECORDS.mixed.input);
    const contribution = omissionContribution(world.config());

    assert.equal(contribution.name, EXTENSION_NAME);
    assert.deepEqual(contribution.issuerConfigMembers, ["extensions", "grantable", "accessGroups"]);
    assert.deepEqual(contribution.requiredSeams, ["periodKeySupply"]);
    assert.equal(typeof contribution.issuerSupplyPlanWrapper, "function");
  });

  for (const [label, extra, message] of /** @type {const} */ ([
    ["limits", { limits: { maxEntries: 1 } }, `issuer ${ISSUER_A} publication exceeds maxEntries`],
    [
      "clientRequestExtraBytes",
      { clientRequestExtraBytes: 70000 },
      `issuer ${ISSUER_A} publication exceeds maxBodyBytes`,
    ],
  ])) {
    test(`${label} reaches base's request budget through createPublisher, active and inactive`, async () => {
      for (const recorded of [RECORDS.inactive, RECORDS.mixed]) {
        const world = await recordedPublisherWorld(recorded.input);
        const config = world.config();
        Object.assign(config.issuers[0], extra);

        await assert.rejects(
          createPublisher(config, omissionContribution(config)).publish(world.article()),
          { code: "bad_config", message },
        );
      }
    });
  }
});

describe("OmittingSealer keeps base issuer members", () => {
  /** @type {[string, object][]} */
  const members = [
    ["limits", { limits: { maxEntries: 1 } }],
    ["clientRequestExtraBytes", { clientRequestExtraBytes: 70000 }],
  ];

  for (const [label, extra] of members) {
    test(`${label} on an inactive and an active issuer reaches base's request budget`, async () => {
      const { issuerConfig, sealerConfig } = await world();
      for (const omission of [{}, { extensions: [EXTENSION_NAME] }]) {
        const config = sealerConfig({
          issuers: [issuerConfig(ISSUER_A, { ...omission, ...extra })],
        });
        const base = new Sealer(/** @type {any} */ ({ ...config, ...omissionSealing(config) }));
        const wrapped = new OmittingSealer(config);
        for (const sealer of [base, wrapped]) {
          sealer.resource("123456", { section: "politics" });
          sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: ["premium"] });
          sealer.content("note", ARTICLE, "text/html", { accessGroups: ["premium"] });
        }
        const expected = await base.seal().then(
          () => assert.fail("base sealed past the configured budget"),
          (error) => ({ code: error.code, message: error.message }),
        );
        await assert.rejects(wrapped.seal(), expected);
      }
    });
  }
});

describe("Omission snapshots its configuration", () => {
  test("editing an extensions list after composition neither activates nor deactivates", async () => {
    for (const [recorded, edit] of /** @type {const} */ ([
      [RECORDS.inactive, (/** @type {string[]} */ list) => list.push(EXTENSION_NAME)],
      [RECORDS.mixed, (/** @type {string[]} */ list) => list.splice(0, list.length)],
    ])) {
      const world = await recordedPublisherWorld(recorded.input);
      // Each consumer gets its own configuration, and so its own seeded Random.
      /** @type {((config: any) => () => Promise<any>)[]} */
      const consumers = [
        (config) => {
          const composed = composePublisherConfig(config, omissionContribution(config));
          return () => world.sealed(new Sealer(composed.config));
        },
        (config) => {
          const publisher = createPublisher(config, omissionContribution(config));
          return () => publisher.publish(world.article());
        },
        (config) => {
          const sealer = new OmittingSealer(config);
          return () => world.sealed(sealer);
        },
      ];
      for (const consumer of consumers) {
        const config = world.config();
        config.issuers[0].extensions ??= [];
        const rendered = consumer(config);
        edit(config.issuers[0].extensions);
        config.issuers[0].accessGroups?.push("free");
        await assertRendersRecord(await rendered(), recorded);
      }
    }
  });
});

describe("An issuer the contribution never saw", () => {
  /**
   * Wraps every collaborator that draws, derives or seals, so a test can show
   * a refusal came before any of them ran.
   *
   * @param {Record<string, any>} config
   */
  function counted(config) {
    const counts = { random: 0, seal: 0, derive: 0 };
    const { random, keySealing, periodKeySupply } = config;
    Object.assign(config, {
      random: { bytes: (/** @type {number} */ n) => (counts.random++, random.bytes(n)) },
      keySealing: {
        seal: (/** @type {any[]} */ ...args) => (counts.seal++, keySealing.seal(...args)),
      },
      periodKeySupply: {
        derive: (/** @type {string} */ group, /** @type {string} */ t) => (
          counts.derive++,
          periodKeySupply.derive(group, t)
        ),
      },
    });
    return counts;
  }

  /**
   * Each publisher route over one base configuration and one contribution.
   *
   * @param {any} world
   * @param {Record<string, any>} config
   * @param {any} contribution
   */
  function routes(world, config, contribution) {
    return [
      () => createPublisher(config, contribution).publish(world.article()),
      () => world.sealed(new Sealer(composePublisherConfig(config, contribution).config)),
    ];
  }

  test("an issuer added after the contribution was built is refused before any draw", async () => {
    const world = await recordedPublisherWorld(RECORDS.mixed.input);
    for (const route of [0, 1]) {
      const config = world.config();
      const contribution = omissionContribution(config);
      config.issuers.push({
        ...config.issuers[1],
        issuerName: "issuer_c",
        extensions: [EXTENSION_NAME],
        accessGroups: ["free"],
      });
      const counts = counted(config);

      await assert.rejects(routes(world, config, contribution)[route](), {
        code: "bad_config",
        message: `issuer "issuer_c" was not configured when ${EXTENSION_NAME} was selected`,
      });
      assert.deepEqual(counts, { random: 0, seal: 0, derive: 0 });
    }
  });

  test("a contribution built from another issuer list is refused before any draw", async () => {
    const world = await recordedPublisherWorld(RECORDS.inactive.input);
    for (const route of [0, 1]) {
      const contribution = omissionContribution(world.config());
      const config = world.config();
      config.issuers[1] = {
        ...config.issuers[1],
        issuerName: "issuer_c",
        extensions: [EXTENSION_NAME],
        accessGroups: ["free"],
      };
      const counts = counted(config);

      await assert.rejects(routes(world, config, contribution)[route](), {
        code: "bad_config",
        message: `issuer "issuer_c" was not configured when ${EXTENSION_NAME} was selected`,
      });
      assert.deepEqual(counts, { random: 0, seal: 0, derive: 0 });
    }
  });
});

test("the omission publisher budgets the support signal and bound candidates it asks clients to send", async () => {
  const w = await recordedPublisherWorld(RECORDS.active.input);
  const page = await w.sealed(new OmittingSealer(w.config()));
  const issuerName = Object.keys(page.dcaData.issuerData)[0];
  const document = new OmissionRequestBuilder({ relayPeriodKeys: true })
    .build(new DcaData(page.dcaData), issuerName, Object.keys(page.dcaData.contentData))
    .toObject();
  assert.ok(Object.keys(document.boundCandidates).length > 0);
  const bytes = new TextEncoder().encode(JSON.stringify(document)).length;
  for (const atLimit of [false, true]) {
    for (const path of ["entry", "composed", "convenience", "spread"]) {
      const config = w.config();
      config.issuers[0].limits = { maxBodyBytes: bytes - (atLimit ? 0 : 1) };
      const render =
        path === "entry"
          ? createPublisher(config, omissionContribution(config)).publish(w.article())
          : w.sealed(
              path === "convenience"
                ? new OmittingSealer(config)
                : new Sealer(
                    /** @type {any} */ (
                      path === "spread"
                        ? { ...config, ...omissionSealing(config) }
                        : composePublisherConfig(config, omissionContribution(config)).config
                    ),
                  ),
            );
      if (atLimit) await render;
      else await assert.rejects(render, { code: "bad_config" }, path);
    }
  }
});

test("a render without bound wraps budgets the support signal only, as its client sends", async () => {
  const w = await recordedPublisherWorld(RECORDS.inactive.input);
  const page = await w.sealed(new OmittingSealer(w.config()));
  const issuerName = Object.keys(page.dcaData.issuerData)[0];
  const document = new OmissionRequestBuilder({ relayPeriodKeys: true })
    .build(new DcaData(page.dcaData), issuerName, Object.keys(page.dcaData.contentData))
    .toObject();
  assert.equal(Object.hasOwn(document, "boundCandidates"), false);
  const bytes = new TextEncoder().encode(JSON.stringify(document)).length;
  for (const atLimit of [false, true]) {
    const config = w.config();
    config.issuers[0].limits = { maxBodyBytes: bytes - (atLimit ? 0 : 1) };
    const render = createPublisher(config, omissionContribution(config)).publish(w.article());
    if (atLimit) await render;
    else await assert.rejects(render, { code: "bad_config" });
  }
});
