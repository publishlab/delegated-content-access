// @ts-check
//
// Publisher composition: base configuration plus a list of contributions, each
// claiming the seams it owns. Every contribution here is synthetic, so this
// file runs with `extensions/` removed.
//
// The renders compare against records written once from the publisher as it
// stood before composition existed (`fixtures/`), never against a second call
// through the composed path.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Sealer } from "../../core-publisher/Sealer.js";
import { composePublisherConfig } from "../../core-publisher/publisherComposition.js";
import { ISSUER_CONFIG_MEMBERS } from "../../core-publisher/publisherConfig.js";
import { checkedIssuerSupplyPlanner } from "../../core-publisher/issuerSupplyPlan.js";
import { createPublisher } from "../../integration-publisher/createPublisher.js";
import {
  assertRendersRecord,
  recordedPublisherWorld,
  testAadContentKeyWrap,
} from "../../test-lib/fixtures/publisher-composition-world.js";

/** @param {string} name */
function record(name) {
  return JSON.parse(
    readFileSync(
      new URL(`./fixtures/publisher-composition--${name}.json`, import.meta.url),
      "utf8",
    ),
  );
}

const BASELINE = record("baseline");
const BASELINE_TEST_AAD = record("baseline-test-aad");

const SEAMS = /** @type {const} */ (["contentKeyWrapStrategy", "keySealing", "periodKeySupply"]);

/**
 * A base configuration whose every collaborator counts its calls, so a test
 * can show that composition asked none of them anything.
 */
function counted() {
  /** @type {Record<string, number>} */
  const counts = {
    random: 0,
    clock: 0,
    keySealing: 0,
    periodKeySupply: 0,
    contentKeyWrapStrategy: 0,
    planner: 0,
    wrapper: 0,
  };
  const seams = {
    contentKeyWrapStrategy: () => ({
      aad() {
        counts.contentKeyWrapStrategy++;
        return undefined;
      },
      entry() {
        counts.contentKeyWrapStrategy++;
        return {};
      },
    }),
    keySealing: () => ({
      seal() {
        counts.keySealing++;
        return "";
      },
    }),
    periodKeySupply: () => ({
      derive() {
        counts.periodKeySupply++;
        return new Uint8Array(16);
      },
    }),
  };
  /** @type {Record<string, any>} */
  const config = {
    origin: "https://publisher.example",
    clock: {
      now() {
        counts.clock++;
        return new Date("2025-10-23T14:20:00Z");
      },
    },
    random: {
      bytes(/** @type {number} */ n) {
        counts.random++;
        return new Uint8Array(n);
      },
    },
    signingKeys: { signing: /** @type {any} */ ({}) },
    issuerSupplyPlanFor() {
      counts.planner++;
      return { contentKeyNames: [], suppliedAccessGroups: [] };
    },
    issuers: [
      {
        issuerName: "issuer_a",
        keyId: "key-1",
        algorithm: "ecdh-p256",
        publicKey: {},
      },
    ],
  };
  const wrapper = (/** @type {Function} */ inner, /** @type {any} */ issuer, render) => {
    counts.wrapper++;
    return inner(issuer, render);
  };
  return { config, counts, seams, wrapper };
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

/** @param {unknown} value */
function isPlainRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const ZERO = {
  random: 0,
  clock: 0,
  keySealing: 0,
  periodKeySupply: 0,
  contentKeyWrapStrategy: 0,
  planner: 0,
  wrapper: 0,
};

describe("Seam owners", () => {
  for (const seam of SEAMS) {
    test(`${seam}: the base configuration and a contribution are two owners`, () => {
      const { config, counts, seams, wrapper } = counted();
      config[seam] = seams[seam]();
      const contribution = {
        name: "alpha",
        [seam]: seams[seam](),
        issuerSupplyPlanWrapper: wrapper,
      };

      assert.deepEqual(
        refusal(() => composePublisherConfig(config, contribution)),
        {
          code: "bad_config",
          message: `${seam} has two owners: the base configuration and alpha`,
        },
      );
      assert.deepEqual(counts, ZERO);
    });

    test(`${seam}: two contributions are two owners`, () => {
      const { config, counts, seams, wrapper } = counted();
      const alpha = { name: "alpha", [seam]: seams[seam](), issuerSupplyPlanWrapper: wrapper };
      const beta = { name: "beta", [seam]: seams[seam](), issuerSupplyPlanWrapper: wrapper };

      assert.deepEqual(
        refusal(() => composePublisherConfig(config, alpha, beta)),
        { code: "bad_config", message: `${seam} has two owners: alpha and beta` },
      );
      assert.deepEqual(counts, ZERO);
    });

    test(`${seam}: one object passed by two owners still has two owners`, () => {
      const { config, counts, seams } = counted();
      const shared = seams[seam]();
      config[seam] = shared;

      assert.deepEqual(
        refusal(() => composePublisherConfig(config, { name: "alpha", [seam]: shared })),
        {
          code: "bad_config",
          message: `${seam} has two owners: the base configuration and alpha`,
        },
      );
      delete config[seam];
      assert.deepEqual(
        refusal(() =>
          composePublisherConfig(
            config,
            { name: "alpha", [seam]: shared },
            { name: "beta", [seam]: shared },
          ),
        ),
        { code: "bad_config", message: `${seam} has two owners: alpha and beta` },
      );
      assert.deepEqual(counts, ZERO);
    });
  }

  test("a core default is a fallback, not an owner", () => {
    const { config, seams } = counted();
    const supply = seams.periodKeySupply();
    config.periodKeySupply = undefined;
    const composed = composePublisherConfig(config, { name: "alpha", periodKeySupply: supply });

    assert.deepEqual(composed.owners, {
      contentKeyWrapStrategy: null,
      keySealing: null,
      periodKeySupply: "alpha",
    });
    assert.equal(composed.config.periodKeySupply, supply);
    assert.equal(Object.hasOwn(composed.config, "contentKeyWrapStrategy"), false);
    assert.equal(Object.hasOwn(composed.config, "keySealing"), false);
  });

  test("an explicit base selection owns its seam", () => {
    const { config, seams } = counted();
    config.keySealing = seams.keySealing();
    const composed = composePublisherConfig(config, { name: "alpha" });

    assert.equal(composed.owners.keySealing, "base");
    assert.equal(composed.config.keySealing, config.keySealing);
  });

  test("createPublisher refuses two owners when it is built, before any publish", () => {
    const { config, counts, seams, wrapper } = counted();
    const alpha = {
      name: "alpha",
      contentKeyWrapStrategy: seams.contentKeyWrapStrategy(),
      issuerSupplyPlanWrapper: wrapper,
    };
    const beta = {
      name: "beta",
      contentKeyWrapStrategy: seams.contentKeyWrapStrategy(),
      issuerSupplyPlanWrapper: wrapper,
    };

    assert.deepEqual(
      refusal(() => createPublisher(/** @type {any} */ (config), alpha, beta)),
      { code: "bad_config", message: "contentKeyWrapStrategy has two owners: alpha and beta" },
    );
    config.keySealing = seams.keySealing();
    assert.deepEqual(
      refusal(() =>
        createPublisher(/** @type {any} */ (config), {
          name: "alpha",
          keySealing: seams.keySealing(),
        }),
      ),
      {
        code: "bad_config",
        message: "keySealing has two owners: the base configuration and alpha",
      },
    );
    assert.deepEqual(counts, ZERO);
  });
});

describe("The selected planner", () => {
  test("a contribution cannot replace the planner", () => {
    const { config, counts } = counted();
    const contribution = { name: "alpha", issuerSupplyPlanFor: config.issuerSupplyPlanFor };

    assert.deepEqual(
      refusal(() => composePublisherConfig(config, contribution)),
      {
        code: "unsupported_option",
        message: "a publisher contribution has no issuerSupplyPlanFor yet, and will not pretend to",
      },
    );
    assert.deepEqual(counts, ZERO);
  });

  test("a wrapper cannot hide an invalid base planner", () => {
    const { config, counts, wrapper } = counted();
    config.issuerSupplyPlanFor = {};

    assert.deepEqual(
      refusal(() =>
        composePublisherConfig(config, { name: "alpha", issuerSupplyPlanWrapper: wrapper }),
      ),
      refusal(() => checkedIssuerSupplyPlanner({})),
    );
    delete config.issuerSupplyPlanFor;
    assert.deepEqual(
      refusal(() =>
        composePublisherConfig(config, { name: "alpha", issuerSupplyPlanWrapper: wrapper }),
      ),
      refusal(() => checkedIssuerSupplyPlanner(undefined)),
    );
    assert.deepEqual(counts, ZERO);
  });

  test("wrappers nest in list order: the last one is outermost", async () => {
    const world = await recordedPublisherWorld(BASELINE.input);
    const config = world.config();
    const basePlanner = config.issuerSupplyPlanFor;
    /** @type {string[]} */
    const trace = [];
    const fromA = new WeakSet();
    config.issuerSupplyPlanFor = (/** @type {any} */ issuer, /** @type {any} */ render) => {
      trace.push("base");
      return basePlanner(issuer, render);
    };
    /** @param {string} name */
    const tracing = (name) => ({
      name,
      issuerSupplyPlanWrapper: (/** @type {Function} */ inner, issuer, render) => {
        trace.push(`${name} enter`);
        const plan = inner(issuer, render);
        if (name === "B") assert.ok(fromA.has(plan), "B is handed the plan A returned");
        trace.push(`${name} exit`);
        const own = { ...plan };
        if (name === "A") fromA.add(own);
        return own;
      },
    });

    const composed = composePublisherConfig(config, tracing("A"), tracing("B"));
    assert.deepEqual(composed.plannerOrder, ["A", "B"]);
    assert.deepEqual(trace, [], "composition calls no wrapper");

    await assertRendersRecord(await world.sealed(new Sealer(composed.config)), BASELINE);
    const once = ["B enter", "A enter", "base", "A exit", "B exit"];
    assert.deepEqual(trace, [...once, ...once], "one nesting per issuer");
  });
});

describe("Renders through the composed path", () => {
  test("no contribution: createPublisher and the composed Sealer render the recorded baseline", async () => {
    const world = await recordedPublisherWorld(BASELINE.input);

    await assertRendersRecord(
      await createPublisher(world.config()).publish(world.article()),
      BASELINE,
    );
    await assertRendersRecord(
      await createPublisher(world.config(), { name: "empty" }).publish(world.article()),
      BASELINE,
    );
    await assertRendersRecord(
      await world.sealed(new Sealer(composePublisherConfig(world.config()).config)),
      BASELINE,
    );
  });

  test("an inactive contribution leaves the base contentKeyWrapStrategy in place", async () => {
    const world = await recordedPublisherWorld(BASELINE_TEST_AAD.input);
    const inactive = {
      name: "inactive",
      issuerConfigMembers: ["inactiveTier"],
      issuerSupplyPlanWrapper: (/** @type {Function} */ inner, issuer, render) =>
        inner(issuer, render),
    };

    const composed = composePublisherConfig(world.config(), inactive);
    assert.equal(composed.owners.contentKeyWrapStrategy, "base");
    assert.equal(composed.config.contentKeyWrapStrategy, testAadContentKeyWrap);
    await assertRendersRecord(await world.sealed(new Sealer(composed.config)), BASELINE_TEST_AAD);
    await assertRendersRecord(
      await createPublisher(world.config(), inactive).publish(world.article()),
      BASELINE_TEST_AAD,
    );
  });

  test("the result is frozen, and so are its config and owners", () => {
    const { config } = counted();
    const composed = composePublisherConfig(config, { name: "alpha" });

    for (const value of [composed, composed.config, composed.owners, composed.plannerOrder]) {
      assert.ok(Object.isFrozen(value));
    }
    assert.deepEqual(Object.keys(composed), ["config", "owners", "plannerOrder"]);
  });
});

describe("Issuer config members", () => {
  test("base names its issuer config members once", () => {
    assert.deepEqual(ISSUER_CONFIG_MEMBERS, [
      "issuerName",
      "keyId",
      "algorithm",
      "publicKey",
      "limits",
      "maxChainMembersPerMessage",
      "clientRequestExtraBytes",
      "envelope",
    ]);
    assert.ok(Object.isFrozen(ISSUER_CONFIG_MEMBERS));
  });

  test("a declared member passes, and neither the planner nor the Sealer sees it", async () => {
    const world = await recordedPublisherWorld(BASELINE.input);
    const config = world.config();
    for (const issuer of config.issuers) issuer.alphaTier = "gold";
    const basePlanner = config.issuerSupplyPlanFor;
    /** @type {string[][]} */
    const seen = [];
    config.issuerSupplyPlanFor = (/** @type {any} */ issuer, /** @type {any} */ render) => {
      seen.push(Object.keys(issuer));
      return basePlanner(issuer, render);
    };
    const alpha = {
      name: "alpha",
      issuerConfigMembers: ["alphaTier"],
      issuerSupplyPlanWrapper: (
        /** @type {Function} */ inner,
        /** @type {any} */ issuer,
        render,
      ) => {
        seen.push(Object.keys(issuer));
        return inner(issuer, render);
      },
    };

    const composed = composePublisherConfig(config, alpha);
    for (const issuer of composed.config.issuers) {
      assert.equal(Object.hasOwn(issuer, "alphaTier"), false);
    }
    await assertRendersRecord(await world.sealed(new Sealer(composed.config)), BASELINE);
    assert.equal(seen.length, 4);
    for (const keys of seen) assert.equal(keys.includes("alphaTier"), false);
    const fresh = world.config();
    for (const issuer of fresh.issuers) issuer.alphaTier = "gold";
    await assertRendersRecord(
      await createPublisher(fresh, alpha).publish(world.article()),
      BASELINE,
    );
  });

  test("an undeclared member is refused on the composed path", () => {
    const { config, counts } = counted();
    config.issuers[0].alphaTier = "gold";

    for (const contributions of [[], [{ name: "beta", issuerConfigMembers: ["betaTier"] }]]) {
      assert.deepEqual(
        refusal(() => composePublisherConfig(config, ...contributions)),
        {
          code: "unsupported_option",
          message: "an issuer entry has no alphaTier yet, and will not pretend to",
        },
      );
    }
    config.issuers[0] = { ...config.issuers[0], kdf: "HKDF" };
    delete config.issuers[0].alphaTier;
    assert.deepEqual(
      refusal(() => composePublisherConfig(config, { name: "alpha" })),
      {
        code: "unsupported_option",
        message: "an issuer entry has no kdf yet, and will not pretend to",
      },
    );
    assert.deepEqual(counts, ZERO);
  });

  test("a contribution cannot redefine a base member", () => {
    const { config } = counted();
    for (const member of ["limits", "issuerName"]) {
      assert.deepEqual(
        refusal(() =>
          composePublisherConfig(config, { name: "alpha", issuerConfigMembers: [member] }),
        ),
        {
          code: "bad_config",
          message: `alpha declares the issuer member ${member}, which base defines`,
        },
      );
    }
  });

  test("two contributions cannot declare one member", () => {
    const { config } = counted();
    assert.deepEqual(
      refusal(() =>
        composePublisherConfig(
          config,
          { name: "alpha", issuerConfigMembers: ["tier"] },
          { name: "beta", issuerConfigMembers: ["tier"] },
        ),
      ),
      { code: "bad_config", message: "the issuer member tier is declared by alpha and by beta" },
    );
  });

  for (const [label, extra, message] of /** @type {const} */ ([
    ["limits", { limits: { maxEntries: 1 } }, "issuer issuer_a publication exceeds maxEntries"],
    [
      "clientRequestExtraBytes",
      { clientRequestExtraBytes: 70000 },
      "issuer issuer_a publication exceeds maxBodyBytes",
    ],
  ])) {
    test(`${label} reaches the request budget on the composed path`, async () => {
      const world = await recordedPublisherWorld(BASELINE.input);
      // Each consumer gets its own configuration, and so its own seeded Random.
      const config = () => {
        const fresh = world.config();
        Object.assign(fresh.issuers[0], extra);
        return fresh;
      };
      const alpha = { name: "alpha", issuerConfigMembers: ["alphaTier"] };

      await assert.rejects(createPublisher(config(), alpha).publish(world.article()), {
        code: "bad_config",
        message,
      });
      await assert.rejects(
        world.sealed(new Sealer(composePublisherConfig(config(), alpha).config)),
        {
          code: "bad_config",
          message,
        },
      );
    });
  }

  test("an absent base member stays absent on the entry the Sealer receives", () => {
    const { config } = counted();
    const composed = composePublisherConfig(config, { name: "alpha" });

    assert.deepEqual(Object.keys(composed.config.issuers[0]), Object.keys(config.issuers[0]));
    for (const member of ["limits", "clientRequestExtraBytes"]) {
      assert.equal(Object.hasOwn(composed.config.issuers[0], member), false);
    }
  });
});

describe("Composition snapshots its inputs", () => {
  test("mutating the base, an issuer record or a claimed list afterwards changes no render", async () => {
    const world = await recordedPublisherWorld(BASELINE.input);
    /** @param {Record<string, any>} config @param {{ issuerConfigMembers: string[] }} alpha */
    const mutate = (config, alpha) => {
      config.contentKeyWrapStrategy = testAadContentKeyWrap;
      config.issuers[0].keyId = "changed";
      config.issuers[0].surprise = true;
      config.issuers.pop();
      alpha.issuerConfigMembers.length = 0;
    };
    // Each consumer gets its own configuration, and so its own seeded Random.
    const inputs = () => {
      const config = world.config();
      for (const issuer of config.issuers) issuer.alphaTier = "gold";
      return { config, alpha: { name: "alpha", issuerConfigMembers: ["alphaTier"] } };
    };

    const first = inputs();
    const composed = composePublisherConfig(first.config, first.alpha);
    mutate(first.config, first.alpha);
    assert.equal(composed.owners.contentKeyWrapStrategy, null);
    await assertRendersRecord(await world.sealed(new Sealer(composed.config)), BASELINE);

    const second = inputs();
    const publisher = createPublisher(second.config, second.alpha);
    mutate(second.config, second.alpha);
    await assertRendersRecord(await publisher.publish(world.article()), BASELINE);
  });

  test("a refusal stands on the values given at composition", () => {
    const { config, seams } = counted();
    const alpha = { name: "alpha", issuerConfigMembers: ["tier"] };
    const composed = composePublisherConfig(config, alpha);
    alpha.issuerConfigMembers.push("limits");
    config.keySealing = seams.keySealing();

    assert.equal(composed.owners.keySealing, null);
    assert.equal(Object.hasOwn(composed.config, "keySealing"), false);
  });

  for (const [label, contributions] of /** @type {const} */ ([
    ["no contribution", []],
    ["one contribution", [{ name: "alpha" }]],
  ])) {
    test(`${label}: a later Sealer reads the period and signing keys given at composition`, async () => {
      const world = await recordedPublisherWorld(BASELINE.input);
      const config = world.config();
      config.period = { length: 60, slots: 2 };
      const composed = composePublisherConfig(config, ...contributions);
      config.period.slots = 3;
      delete config.signingKeys[BASELINE.input.signingKid];

      await assertRendersRecord(await world.sealed(new Sealer(composed.config)), BASELINE);
    });

    test(`${label}: a later Sealer keeps the issuer limits given at composition`, async () => {
      const world = await recordedPublisherWorld(BASELINE.input);
      const config = world.config();
      config.issuers[0].limits = { maxEntries: 1 };
      const composed = composePublisherConfig(config, ...contributions);
      config.issuers[0].limits.maxEntries = 100;

      await assert.rejects(world.sealed(new Sealer(composed.config)), {
        code: "bad_config",
        message: "issuer issuer_a publication exceeds maxEntries",
      });
    });
  }

  test("the returned period, signing keys and issuer limits are frozen copies", () => {
    const { config } = counted();
    config.period = { length: 60, slots: 2 };
    config.issuers[0].limits = { maxEntries: 1 };
    const composed = composePublisherConfig(config, { name: "alpha" });
    const [issuer] = composed.config.issuers;

    for (const value of [composed.config.period, composed.config.signingKeys, issuer.limits]) {
      assert.ok(Object.isFrozen(value));
    }
    assert.notEqual(composed.config.period, config.period);
    assert.notEqual(composed.config.signingKeys, config.signingKeys);
    assert.notEqual(issuer.limits, config.issuers[0].limits);
    assert.throws(() => {
      issuer.limits.maxEntries = 100;
    }, TypeError);
    assert.deepEqual(issuer.limits, { maxEntries: 1 });
    // Keys and collaborators are what the host handed over, not copies.
    assert.equal(composed.config.signingKeys.signing, config.signingKeys.signing);
    assert.equal(issuer.publicKey, config.issuers[0].publicKey);
    for (const name of ["clock", "random"]) assert.equal(composed.config[name], config[name]);
  });

  test("absent, undefined and malformed nested members reach the Sealer as given", () => {
    /** @param {() => unknown} call */
    const outcome = (call) => {
      try {
        call();
        return "accepted";
      } catch (error) {
        return {
          code: /** @type {any} */ (error)?.code,
          message: /** @type {any} */ (error)?.message,
        };
      }
    };
    // Admission finds a named kid by own membership, enumerable or not.
    const hiddenKid = { other: {} };
    Object.defineProperty(hiddenKid, "signing", { value: {}, enumerable: false });
    /** @type {[string, (config: Record<string, any>) => void][]} */
    const cases = [
      ["limits undefined", (config) => (config.issuers[0].limits = undefined)],
      ["limits null", (config) => (config.issuers[0].limits = null)],
      ["limits a list", (config) => (config.issuers[0].limits = [1])],
      ["limits a string", (config) => (config.issuers[0].limits = "small")],
      ["limits zero", (config) => (config.issuers[0].limits = { maxEntries: 0 })],
      ["limits unknown", (config) => (config.issuers[0].limits = { maxGroups: 1 })],
      ["period undefined", (config) => (config.period = undefined)],
      ["period null", (config) => (config.period = null)],
      ["period zero", (config) => (config.period = { length: 0 })],
      ["signing keys null", (config) => (config.signingKeys = null)],
      ["signing keys empty", (config) => (config.signingKeys = {})],
      ["signing keys a list", (config) => (config.signingKeys = ["signing"])],
      [
        "signing key not enumerable",
        (config) => Object.assign(config, { signingKeys: hiddenKid, signingKid: "signing" }),
      ],
    ];
    for (const [label, edit] of cases) {
      const plain = counted().config;
      edit(plain);
      const base = counted().config;
      edit(base);
      const composed = composePublisherConfig(base, { name: "alpha" }).config;

      assert.deepEqual(
        outcome(() => new Sealer(/** @type {any} */ (composed))),
        outcome(() => new Sealer(/** @type {any} */ (plain))),
        label,
      );
      for (const [given, kept] of [
        [base, composed],
        [base.issuers[0], composed.issuers[0]],
      ]) {
        for (const member of ["period", "signingKeys", "limits"]) {
          assert.equal(
            Object.hasOwn(kept, member),
            Object.hasOwn(given, member),
            `${label}: ${member}`,
          );
          if (!isPlainRecord(given[member])) assert.equal(kept[member], given[member], label);
        }
      }
    }
  });
});

describe("The contribution record", () => {
  test("an unknown member is refused", () => {
    const { config } = counted();
    assert.deepEqual(
      refusal(() => composePublisherConfig(config, { name: "alpha", surprise: true })),
      {
        code: "unsupported_option",
        message: "a publisher contribution has no surprise yet, and will not pretend to",
      },
    );
  });

  test("a member present as undefined is refused", () => {
    const { config } = counted();
    assert.deepEqual(
      refusal(() => composePublisherConfig(config, { name: "alpha", keySealing: undefined })),
      {
        code: "bad_config",
        message: "a publisher contribution omits keySealing instead of setting it to undefined",
      },
    );
  });

  test("names are nonempty, unique and not base", () => {
    const { config } = counted();
    for (const contributions of [[{ name: "" }], [{}], [{ name: 7 }], [{ name: "base" }]]) {
      assert.equal(
        refusal(() => composePublisherConfig(config, .../** @type {any[]} */ (contributions))).code,
        "bad_config",
      );
    }
    assert.deepEqual(
      refusal(() => composePublisherConfig(config, { name: "alpha" }, { name: "alpha" })),
      { code: "bad_config", message: 'the publisher contribution "alpha" is listed twice' },
    );
  });

  test("a required seam nobody owns is refused", () => {
    const { config, counts } = counted();
    assert.deepEqual(
      refusal(() =>
        composePublisherConfig(config, { name: "alpha", requiredSeams: ["periodKeySupply"] }),
      ),
      {
        code: "bad_config",
        message:
          "alpha needs periodKeySupply, and this render has no periodKeySupply to route through",
      },
    );
    assert.deepEqual(counts, ZERO);
  });

  test("a required seam another owner holds is met", () => {
    const { config, seams } = counted();
    const composed = composePublisherConfig(
      config,
      { name: "alpha", requiredSeams: ["periodKeySupply"] },
      { name: "beta", periodKeySupply: seams.periodKeySupply() },
    );
    assert.equal(composed.owners.periodKeySupply, "beta");
  });

  test("a contribution is a record", () => {
    const { config } = counted();
    for (const contribution of [null, [], "alpha"]) {
      assert.equal(
        refusal(() => composePublisherConfig(config, /** @type {any} */ (contribution))).code,
        "bad_config",
      );
    }
  });
});

describe("Plain Sealer admission", () => {
  test("a plain Sealer and a createPublisher with no contribution still accept an unknown issuer member", () => {
    const { config } = counted();
    config.issuers[0].surprise = true;

    assert.doesNotThrow(() => new Sealer(/** @type {any} */ (config)));
    assert.doesNotThrow(() => createPublisher(/** @type {any} */ (config)));
  });
});

describe("A contributed page geometry", () => {
  /**
   * A render with one premium item under the given supply, beside a synthetic
   * contribution that routes nothing and writes `geometry` as its page member.
   *
   * @param {any} periodKeySupply
   * @param {any} geometry
   * @param {any} [periodKeyDelivery]
   */
  async function sealedWith(periodKeySupply, geometry, periodKeyDelivery) {
    const signing = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    const opening = await globalThis.crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    const { config } = composePublisherConfig(
      /** @type {any} */ ({
        origin: "https://publisher.example",
        clock: { now: () => new Date("2026-10-14T12:20:00Z") },
        random: { bytes: (/** @type {number} */ n) => new Uint8Array(n).fill(3) },
        signingKeys: { k1: signing.privateKey },
        periodKeySupply,
        issuers: [
          {
            issuerName: "issuer_a",
            keyId: "a1",
            algorithm: "ecdh-p256",
            publicKey: opening.publicKey,
          },
        ],
        issuerSupplyPlanFor: () => ({
          contentKeyNames: [],
          suppliedAccessGroups: ["premium"],
          ...(periodKeyDelivery ? { periodKeyDelivery } : {}),
        }),
      }),
      {
        name: "page-geometry-probe",
        itemPreparation: {
          routes: () => [],
          prepare: async () => ({ pageMembers: { periodGeometry: geometry } }),
        },
      },
    );
    const sealer = new Sealer(/** @type {any} */ (config));
    sealer.resource("story1", {});
    sealer.content("body", "x", "text/plain", { accessGroups: ["premium"] });
    return (await sealer.seal()).dcaData;
  }

  const plainSupply = { derive: async () => new Uint8Array(16).fill(5) };
  /** A chain family delivered as period keys only keeps geometry for retained chain opening. */
  const chainFamilySupply = {
    derive: async () => new Uint8Array(16).fill(5),
    familyPlan: () => ({
      periods: ["261014T1215"],
      periodKeyAt: async () => new Uint8Array(16).fill(7),
      chain: {
        geometry: { chainsPerDay: 2, periodMinutes: 15 },
        suppliedTs: ["261014T1215"],
        capabilityAt: async () => new Uint8Array(16).fill(9),
      },
    }),
  };

  test("the shared publisher grid admits a compatible contributed complete pair", async () => {
    const plain = await sealedWith(plainSupply, { chainsPerDay: 2, periodMinutes: 60 });
    assert.deepEqual(plain.periodGeometry, { chainsPerDay: 2, periodMinutes: 60 });
    const chain = await sealedWith(
      chainFamilySupply,
      { periodMinutes: 15, chainsPerDay: 2 },
      {
        premium: ["period-keys"],
      },
    );
    assert.deepEqual(chain.periodGeometry, { periodMinutes: 15, chainsPerDay: 2 });
  });

  test("the shared publisher grid refuses other minutes, a partial pair or an unknown member", async () => {
    for (const geometry of [
      { chainsPerDay: 2, periodMinutes: 30 },
      { periodMinutes: 30 },
      { chainsPerDay: 2, periodMinutes: 60, chainCount: 1 },
      [2, 60],
    ]) {
      await assert.rejects(
        sealedWith(plainSupply, geometry),
        (/** @type {any} */ error) =>
          error.code === "bad_config" &&
          /one periodGeometry applies to the page/.test(error.message),
        JSON.stringify(geometry),
      );
    }
  });

  test("a complete base pair still refuses a contributed pair that differs in either member", async () => {
    const delivery = { premium: ["period-keys", "chain-keys"] };
    assert.deepEqual(
      (await sealedWith(chainFamilySupply, { chainsPerDay: 2, periodMinutes: 15 }, delivery))
        .periodGeometry,
      { chainsPerDay: 2, periodMinutes: 15 },
    );
    for (const geometry of [
      { chainsPerDay: 4, periodMinutes: 15 },
      { chainsPerDay: 2, periodMinutes: 30 },
      { periodMinutes: 15 },
    ]) {
      await assert.rejects(
        sealedWith(chainFamilySupply, geometry, delivery),
        /one periodGeometry applies to the page/,
        JSON.stringify(geometry),
      );
    }
  });
});
