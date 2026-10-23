// @ts-check
//
// OmittingSealer takes what a base Sealer takes. Each case below hands the
// wrapper and base the same input and expects the same render or the same
// refusal; only the issuer members and the wrap this extension owns may differ.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { ordinaryContentKeyWrap } from "../../../core-publisher/contentKeyWrap.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { omissionSealing } from "../core-publisher/omissionSealing.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import { ARTICLE, ISSUER_A, ISSUER_B, ephemeralPool, world } from "../test-lib/world.js";

/** @param {any} sealed @returns {any} */
function wire(sealed) {
  const { resourceJWT, ...rest } = sealed.dcaData;
  return {
    // ECDSA draws its own nonce inside WebCrypto, so only the signed part compares.
    jwt: resourceJWT.split(".").slice(0, 2).join("."),
    rest: JSON.stringify(rest),
    sealedContent: JSON.stringify(sealed.sealedContent),
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

/** @param {any} config @returns {{ config: any, draws: () => number }} */
function counting(config) {
  let draws = 0;
  return {
    config: {
      ...config,
      random: {
        /** @param {number} n */
        bytes(n) {
          draws += 1;
          return config.random.bytes(n);
        },
      },
      periodKeySupply: {
        /** @param {string} accessGroup @param {string} t */
        derive(accessGroup, t) {
          draws += 1;
          return config.periodKeySupply.derive(accessGroup, t);
        },
      },
    },
    draws: () => draws,
  };
}

const DESCRIPTOR = Object.freeze({
  bytes: new TextEncoder().encode(ARTICLE),
  contentType: "text/html",
  contentEncodings: Object.freeze(["gzip"]),
});

describe("OmittingSealer content() forwards every base calling form", () => {
  const premium = { accessGroups: ["premium"] };
  // A form without options wraps under no group, so the active issuer is told
  // to reach no item, and base's route check still has a route to accept.
  /** @type {[string, boolean, (sealer: any) => void][]} */
  const forms = [
    ["descriptor with options", true, (s) => s.content("bodytext", DESCRIPTOR, premium)],
    ["descriptor without options", false, (s) => s.content("bodytext", DESCRIPTOR)],
    [
      "legacy string with options",
      true,
      (s) => s.content("bodytext", ARTICLE, "text/html", premium),
    ],
    ["legacy string without options", false, (s) => s.content("bodytext", ARTICLE, "text/html")],
    [
      "legacy bytes with options",
      true,
      (s) => s.content("bodytext", DESCRIPTOR.bytes, "text/html", premium),
    ],
  ];

  for (const [label, grouped, add] of forms) {
    test(`${label}: the wrapper renders what base renders under the same roles`, async () => {
      const { issuerConfig, sealerConfig } = await world();
      const providers = await ephemeralPool();
      const issuers = [
        issuerConfig(ISSUER_A, {
          extensions: [EXTENSION_NAME],
          ...(grouped ? {} : { grantable: [] }),
        }),
        issuerConfig(ISSUER_B),
      ];

      const wrapped = new OmittingSealer(sealerConfig({ issuers, ephemeralKeyPairs: providers() }));
      const baseConfig = sealerConfig({ issuers, ephemeralKeyPairs: providers() });
      const base = new Sealer(
        /** @type {any} */ ({ ...baseConfig, ...omissionSealing(baseConfig) }),
      );
      for (const sealer of [wrapped, base]) {
        sealer.resource("123456", { section: "politics" });
        add(sealer);
      }

      assert.deepEqual(wire(await wrapped.seal()), wire(await base.seal()));
    });
  }

  test("a descriptor with a fourth argument gets base's refusal", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const config = sealerConfig({
      issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
    });
    const options = { accessGroups: ["premium"] };

    assert.deepEqual(
      refusal(() => new OmittingSealer(config).content("bodytext", DESCRIPTOR, options, options)),
      refusal(() =>
        new Sealer(/** @type {any} */ ({ ...config, ...omissionSealing(config) })).content(
          "bodytext",
          DESCRIPTOR,
          options,
          options,
        ),
      ),
    );
  });
});

describe("One owner for the render's content-key wrap", () => {
  const callerWrap = Object.freeze({
    aad: () => undefined,
    /** @param {{ t: string, key: string }} wrap */
    entry: ({ t, key }) => ({ t, key, caller: "selected" }),
  });

  test("an inactive composition keeps the caller's strategy and renders what base renders", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const providers = await ephemeralPool();
    /** @param {any} config */
    const withCallerWrap = (config) => ({ ...config, contentKeyWrapStrategy: callerWrap });
    const issuers = [issuerConfig(ISSUER_A)];

    const wrapped = new OmittingSealer(
      withCallerWrap(sealerConfig({ issuers, ephemeralKeyPairs: providers() })),
    );
    const base = new Sealer(
      /** @type {any} */ (
        withCallerWrap(sealerConfig({ issuers, ephemeralKeyPairs: providers() }))
      ),
    );
    for (const sealer of [wrapped, base]) {
      sealer.resource("123456", { section: "politics" });
      sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: ["premium"] });
    }

    const rendered = await wrapped.seal();
    const bodytext = rendered.dcaData.contentData.find(
      (/** @type {any} */ record) => record.contentName === "bodytext",
    );
    const premiumWraps = bodytext.keys.filter(
      (/** @type {any} */ entry) => entry.accessGroup === "premium",
    );
    assert.equal(premiumWraps[0].caller, "selected");
    assert.deepEqual(wire(rendered), wire(await base.seal()));
  });

  test("an active composition refuses a caller's strategy before any entropy", async () => {
    const { issuerConfig, sealerConfig } = await world();
    for (const strategy of [callerWrap, ordinaryContentKeyWrap]) {
      const { config, draws } = counting({
        ...sealerConfig({ issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })] }),
        contentKeyWrapStrategy: strategy,
      });

      const composed = refusal(() => omissionSealing(config));
      assert.equal(composed.code, "bad_config");
      assert.deepEqual(
        refusal(() => new OmittingSealer(config)),
        composed,
      );
      assert.equal(draws(), 0);
    }
  });

  test("an active issuer's inner plan naming another wrap is refused before any entropy", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const { config, draws } = counting({
      ...sealerConfig({ issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })] }),
      issuerSupplyPlanFor: () => ({
        suppliedAccessGroups: ["premium"],
        contentKeyWrap: ordinaryContentKeyWrap,
      }),
    });
    const sealer = new OmittingSealer(config);
    sealer.resource("123456", { section: "politics" });
    sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: ["premium"] });

    await assert.rejects(sealer.seal(), { code: "bad_config" });
    assert.equal(draws(), 0);
  });
});
