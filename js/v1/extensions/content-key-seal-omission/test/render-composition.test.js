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
import { EXTENSION_NAME, OMISSION_BIND_VERSION } from "../core-shared/omissionBind.js";
import { ISSUER_A, ISSUER_B, ephemeralPool, render, world } from "../test-lib/world.js";

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
        ["issuerName", "keyId", "algorithm", "publicKey", "unlockUrl"],
        ["issuerName", "keyId", "algorithm", "publicKey", "unlockUrl"],
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
        [OMISSION_BIND_VERSION, OMISSION_BIND_VERSION],
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
    // Inactive means the ordinary direct map and no marker. The issuer's
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
          suppliedAccessGroups: issuer.issuerName === ISSUER_A ? ["premium"] : ["premium", "free"],
        }),
      }),
      { items: ["bodytext", "sidebar"] },
    );

    assert.deepEqual(Object.keys(page.issuerData[ISSUER_A].sealed.periodKeys), ["premium"]);
    assert.deepEqual(Object.keys(page.issuerData[ISSUER_B].sealed.periodKeys), ["premium"]);
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
        assert.equal(entry.bind, OMISSION_BIND_VERSION);
      }
    }
  });
});
