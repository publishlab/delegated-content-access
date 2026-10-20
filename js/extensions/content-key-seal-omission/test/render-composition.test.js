// @ts-check
//
// This extension composes the two publisher roles. `omissionSealing` reads the
// per-issuer deployment configuration and answers the base issuer entries plus
// the two roles a Sealer takes: the render's content-key wrap and the
// per-issuer supply plan.
// `OmittingSealer` is that composition around a base Sealer, so a base Sealer
// handed the same roles renders the same bytes.
//
// Activation reaches furthest in the mixed render: one issuer listing the
// extension makes the whole render carry the bound wrap, including for the
// readers of an inactive issuer in the same page.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { omissionSealing } from "../core-publisher/omissionSealing.js";
import { EXTENSION_NAME, OMISSION_BIND_IDENTIFIER } from "../core-shared/omissionBind.js";
import { ISSUER_A, ISSUER_B, PERIODS, ephemeralPool, render, world } from "../test-lib/world.js";

/** @param {string} token @returns {string} the compact JWT's header and payload */
function payloadOf(token) {
  return token.split(".").slice(0, 2).join(".");
}

/** @param {any} left @param {any} right */
function assertSameRender(left, right) {
  const { resourceJWT: leftJwt, ...leftRest } = left;
  const { resourceJWT: rightJwt, ...rightRest } = right;
  assert.equal(JSON.stringify(leftRest), JSON.stringify(rightRest));
  assert.equal(payloadOf(leftJwt), payloadOf(rightJwt));
}

describe("The composition is what the extension publishes", () => {
  test("a base Sealer given the two roles renders what OmittingSealer renders", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const providers = await ephemeralPool();
    const issuers = [
      issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] }),
      issuerConfig(ISSUER_B),
    ];

    const composed = await render(
      new OmittingSealer(sealerConfig({ issuers, ephemeralKeyPairs: providers() })),
      {
        items: ["bodytext", "sidebar"],
      },
    );

    const config = sealerConfig({ issuers, ephemeralKeyPairs: providers() });
    const selected = omissionSealing(config);
    assert.equal(typeof selected.issuerSupplyPlanFor, "function");
    assert.equal(typeof selected.contentKeyWrapStrategy.aad, "function");
    assert.equal(typeof selected.contentKeyWrapStrategy.entry, "function");
    // The base entries carry none of this extension's per-issuer members.
    assert.deepEqual(
      selected.issuers.map((/** @type {any} */ issuer) => Object.keys(issuer)),
      [
        ["issuerName", "keyId", "algorithm", "publicKey"],
        ["issuerName", "keyId", "algorithm", "publicKey"],
      ],
    );

    const base = await render(new Sealer(/** @type {any} */ ({ ...config, ...selected })), {
      items: ["bodytext", "sidebar"],
    });
    assertSameRender(base, composed);
  });

  test("one active issuer binds the shared wrap for the inactive one beside it", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const page = await render(
      new OmittingSealer(
        sealerConfig({
          issuers: [
            issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] }),
            issuerConfig(ISSUER_B),
          ],
        }),
      ),
      { items: ["bodytext", "sidebar"] },
    );

    for (const [contentName, accessGroup] of [
      ["bodytext", "premium"],
      ["sidebar", "free"],
    ]) {
      assert.deepEqual(
        page.contentData[contentName].keys[accessGroup].map(
          (/** @type {any} */ entry) => entry.bind,
        ),
        [OMISSION_BIND_IDENTIFIER, OMISSION_BIND_IDENTIFIER],
      );
    }
    assert.equal(Object.hasOwn(page.issuerData[ISSUER_A].sealed, "contentKeys"), false);
    assert.deepEqual(Object.keys(page.issuerData[ISSUER_A].sealed.periodKeys), ["premium", "free"]);
    assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.contentKeys), [
      "bodytext",
      "sidebar",
    ]);
    assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.periodKeys), ["premium", "free"]);
    assert.equal(Object.hasOwn(page.issuerData[ISSUER_B], "extensions"), false);
  });

  test("an inactive issuer keeps the access groups it was configured for", async () => {
    const { issuerConfig, sealerConfig } = await world();
    // Inactive means the ordinary `contentKeys` map and no marker. The issuer's
    // own configuration is still read: an issuer deployed for premium alone
    // covers premium alone, whichever route the render's other issuers take.
    const page = await render(
      new OmittingSealer(
        sealerConfig({
          issuers: [
            issuerConfig(ISSUER_A, {
              extensions: [EXTENSION_NAME],
              accessGroups: ["premium"],
              grantable: ["bodytext"],
            }),
            issuerConfig(ISSUER_B, { accessGroups: ["premium"] }),
          ],
        }),
      ),
      { items: ["bodytext", "sidebar"] },
    );

    assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.periodKeys), ["premium"]);
    assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.contentKeys), [
      "bodytext",
      "sidebar",
    ]);
    assert.deepEqual(Object.keys(page.issuerData[ISSUER_A].sealed.periodKeys), ["premium"]);
  });

  test("an all-inactive render keeps each issuer access-group restriction", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const page = await render(
      new OmittingSealer(
        sealerConfig({
          issuers: [issuerConfig(ISSUER_A, { accessGroups: ["premium"] }), issuerConfig(ISSUER_B)],
        }),
      ),
      { items: ["bodytext", "sidebar"] },
    );

    assert.deepEqual(Object.keys(page.issuerData[ISSUER_A].sealed.periodKeys), ["premium"]);
    assert.deepEqual(Object.keys(page.issuerData[ISSUER_A].sealed.contentKeys), [
      "bodytext",
      "sidebar",
    ]);
    assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.periodKeys), ["premium", "free"]);
    assert.equal(Object.hasOwn(page.issuerData[ISSUER_A], "extensions"), false);
    assert.equal(Object.hasOwn(page.issuerData[ISSUER_B], "extensions"), false);
  });

  test("composition never widens the inner planner or either issuer restriction", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const issuers = [
      issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME], grantable: ["bodytext"] }),
      issuerConfig(ISSUER_B, { accessGroups: ["premium"] }),
    ];
    const page = await render(
      new OmittingSealer({
        ...sealerConfig({ issuers }),
        issuerSupplyPlanFor: (issuer) => ({
          contentKeyNames: ["bodytext", "sidebar"],
          suppliedAccessGroups: issuer.issuerName === ISSUER_A ? ["premium"] : ["premium", "free"],
        }),
      }),
      { items: ["bodytext", "sidebar"] },
    );

    assert.deepEqual(Object.keys(page.issuerData[ISSUER_A].sealed.periodKeys), ["premium"]);
    assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.periodKeys), ["premium"]);
  });

  test("narrowing drops the delivery and source selections of every group it removes", async () => {
    // The inner plan selects delivery and source labels for every render
    // group. An issuer deployed for premium alone, active or inactive, keeps
    // its premium selections and loses the free ones with the free group.
    const { issuerConfig, sealerConfig } = await world();
    const issuers = [
      issuerConfig(ISSUER_A, {
        extensions: [EXTENSION_NAME],
        accessGroups: ["premium"],
        grantable: ["bodytext"],
      }),
      issuerConfig(ISSUER_B, { accessGroups: ["premium"] }),
    ];
    const page = await render(
      new OmittingSealer({
        ...sealerConfig({ issuers }),
        issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ planned) => ({
          contentKeyNames: planned.contentNames,
          suppliedAccessGroups: planned.accessGroups,
          periodKeyDelivery: Object.fromEntries(
            planned.accessGroups.map((/** @type {string} */ group) => [group, ["period-keys"]]),
          ),
          periodKeySourceTs: Object.fromEntries(
            planned.accessGroups.map((/** @type {string} */ group) => [group, [PERIODS[1]]]),
          ),
        }),
      }),
      { items: ["bodytext", "sidebar"] },
    );

    for (const issuerName of [ISSUER_A, ISSUER_B]) {
      assert.deepEqual(
        Object.keys(page.issuerData[issuerName].sealed.periodKeys),
        ["premium"],
        issuerName,
      );
      // The kept source selection still applies to the kept group.
      assert.deepEqual(
        Object.keys(page.issuerData[issuerName].sealed.periodKeys.premium),
        [PERIODS[1]],
        issuerName,
      );
    }
  });

  test("narrowing leaves an inner plan's delivery selection for an unsupplied group to base's refusal", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const sealer = new OmittingSealer({
      ...sealerConfig({ issuers: [issuerConfig(ISSUER_A, { accessGroups: ["premium"] })] }),
      issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ planned) => ({
        contentKeyNames: planned.contentNames,
        suppliedAccessGroups: ["premium"],
        periodKeyDelivery: { premium: ["period-keys"], free: ["period-keys"] },
      }),
    });
    await assert.rejects(
      render(sealer, { items: ["bodytext", "sidebar"] }),
      (/** @type {any} */ error) =>
        error.code === "bad_config" && /unsupplied accessGroup "free"/.test(error.message),
    );
  });

  test("a null inner plan refuses the render before entropy or sealing", async () => {
    const { issuerConfig, sealerConfig } = await world();
    let draws = 0;
    const sealer = new OmittingSealer({
      ...sealerConfig({ issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })] }),
      random: {
        bytes() {
          draws++;
          return new Uint8Array(16);
        },
      },
      issuerSupplyPlanFor: () => null,
    });
    sealer.resource("123456", { section: "politics" });
    sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });

    await assert.rejects(
      () => sealer.seal(),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.equal(draws, 0);
  });

  test("a missing inner group selection never supplies every group", async () => {
    const { issuerConfig, sealerConfig } = await world();
    for (const extensions of [[], [EXTENSION_NAME]]) {
      let draws = 0;
      const sealer = new OmittingSealer({
        ...sealerConfig({ issuers: [issuerConfig(ISSUER_A, { extensions })] }),
        random: {
          bytes() {
            draws++;
            return new Uint8Array(16);
          },
        },
        issuerSupplyPlanFor: () => ({ contentKeyNames: ["bodytext"] }),
      });
      sealer.resource("123456", { section: "politics" });
      sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });

      await assert.rejects(
        () => sealer.seal(),
        (/** @type {any} */ error) =>
          error.code === "bad_config" && /supplies accessGroups as a list/.test(error.message),
      );
      assert.equal(draws, 0);
    }
  });

  test("an active issuer explicitly supplies no content-key names", () => {
    const { issuerSupplyPlanFor } = omissionSealing({
      issuers: [
        {
          issuerName: ISSUER_A,
          extensions: [EXTENSION_NAME],
          grantable: ["bodytext"],
        },
      ],
      periodKeySupply: {},
      issuerSupplyPlanFor: () => ({ suppliedAccessGroups: ["premium"] }),
    });
    const plan = issuerSupplyPlanFor(
      { issuerName: ISSUER_A },
      {
        accessGroups: ["premium"],
        contentNames: ["bodytext"],
      },
    );
    assert.deepEqual(plan.contentKeyNames, []);
    assert.deepEqual(plan.suppliedAccessGroups, ["premium"]);
    assert.equal(Object.hasOwn(plan, "contentKeys"), false);
  });

  test("the render with no issuer listing the extension keeps the ordinary wrap", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const page = await render(
      new OmittingSealer(
        sealerConfig({ issuers: [issuerConfig(ISSUER_A), issuerConfig(ISSUER_B)] }),
      ),
      { items: ["bodytext", "sidebar"] },
    );

    for (const [contentName, accessGroup] of [
      ["bodytext", "premium"],
      ["sidebar", "free"],
    ]) {
      for (const entry of page.contentData[contentName].keys[accessGroup]) {
        assert.deepEqual(Object.keys(entry), ["t", "nonce", "key"]);
      }
    }
  });

  test("which issuer is listed first changes no issuer block", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const active = () =>
      issuerConfig(ISSUER_A, {
        extensions: [EXTENSION_NAME],
        accessGroups: ["premium"],
        grantable: ["bodytext"],
      });
    const inactive = () => issuerConfig(ISSUER_B);
    const items = ["bodytext", "sidebar"];

    const forward = await render(
      new OmittingSealer(sealerConfig({ issuers: [active(), inactive()] })),
      { items },
    );
    const reversed = await render(
      new OmittingSealer(sealerConfig({ issuers: [inactive(), active()] })),
      { items },
    );

    for (const page of [forward, reversed]) {
      assert.deepEqual(page.issuerData[ISSUER_A].extensions, [EXTENSION_NAME]);
      assert.equal(Object.hasOwn(page.issuerData[ISSUER_A].sealed, "contentKeys"), false);
      assert.deepEqual(Object.keys(page.issuerData[ISSUER_A].sealed.periodKeys), ["premium"]);
      assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.contentKeys), items);
      assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.periodKeys), [
        "premium",
        "free",
      ]);
      for (const entry of page.contentData.sidebar.keys.free) {
        assert.equal(entry.bind, OMISSION_BIND_IDENTIFIER);
      }
    }
  });
});
