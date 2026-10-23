// @ts-check
//
// The publisher integration entry accepts a selected extension's contribution
// without importing that extension into the base source slice. Omission is an
// implementation prototype; these cases exercise explicit host composition.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { ordinaryContentKeyWrap } from "../../../core-publisher/contentKeyWrap.js";
import { omissionContribution } from "../core-publisher/omissionSealing.js";
import { EXTENSION_NAME, OMISSION_BIND_IDENTIFIER } from "../core-shared/omissionBind.js";
import { ISSUER_A, ISSUER_B, ITEMS, world } from "../test-lib/world.js";

/**
 * The record in one named-record collection whose identity member is `name`.
 * A missing record fails here, as reading the old map's absent member did.
 *
 * @param {any[]} collection @param {string} member @param {string} name
 */
function recordNamed(collection, member, name) {
  const record = collection.find((entry) => entry[member] === name);
  assert.ok(record, `no record with ${member} ${name}`);
  return record;
}

/**
 * One item's wraps grouped by access group, as the old `keys` map held them.
 *
 * @param {any} dcaData @param {string} contentName
 * @returns {any[][]}
 */
function wrapGroups(dcaData, contentName) {
  /** @type {Map<string, any[]>} */
  const groups = new Map();
  for (const entry of recordNamed(dcaData.contentData, "contentName", contentName).keys) {
    groups.set(entry.accessGroup, [...(groups.get(entry.accessGroup) ?? []), entry]);
  }
  return [...groups.values()];
}

/** @param {any[]} records @returns {string[]} the content names, sorted */
function contentNamesOf(records) {
  return records.map((record) => record.contentName).sort();
}

/** @param {any[]} records @returns {string[]} the access groups covered, sorted */
function groupsOf(records) {
  return [...new Set(records.map((record) => record.accessGroup))].sort();
}

function article() {
  return {
    resourceId: "123456",
    data: { section: "politics" },
    items: ITEMS.filter((item) => ["bodytext", "sidebar"].includes(item.name)),
  };
}

describe("Explicit publisher integration composition", () => {
  test("a selected omission issuer and an ordinary issuer share one bound wrap", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const config = sealerConfig({
      issuers: [
        issuerConfig(ISSUER_A, {
          extensions: [EXTENSION_NAME],
          grantable: ["bodytext"],
          accessGroups: ["premium"],
        }),
        issuerConfig(ISSUER_B),
      ],
    });
    const { dcaData } = await createPublisher(config, omissionContribution(config)).publish(
      article(),
    );

    for (const name of ["bodytext", "sidebar"]) {
      for (const entries of wrapGroups(dcaData, name)) {
        assert.ok(entries.length > 0);
        assert.ok(entries.every((entry) => entry.bind === OMISSION_BIND_IDENTIFIER));
      }
    }
    const active = recordNamed(dcaData.issuerData, "issuerName", ISSUER_A);
    const ordinary = recordNamed(dcaData.issuerData, "issuerName", ISSUER_B);
    assert.deepEqual(active.extensions, [EXTENSION_NAME]);
    assert.equal(Object.hasOwn(active.sealed, "contentKeys"), false);
    assert.deepEqual(groupsOf(active.sealed.periodKeys), ["premium"]);
    assert.equal(Object.hasOwn(ordinary, "extensions"), false);
    assert.deepEqual(contentNamesOf(ordinary.sealed.contentKeys), ["bodytext", "sidebar"]);
  });

  test("baseline and all-inactive selection keep ordinary wrap and item envelopes", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const config = sealerConfig({ issuers: [issuerConfig(ISSUER_A)] });
    const baseline = await createPublisher(config).publish(article());
    const inactive = await createPublisher(config, omissionContribution(config)).publish(article());

    for (const render of [baseline, inactive]) {
      const issuer = recordNamed(render.dcaData.issuerData, "issuerName", ISSUER_A);
      assert.equal(Object.hasOwn(issuer, "extensions"), false);
      assert.deepEqual(contentNamesOf(issuer.sealed.contentKeys), ["bodytext", "sidebar"]);
      for (const name of ["bodytext", "sidebar"]) {
        for (const entries of wrapGroups(render.dcaData, name)) {
          assert.ok(entries.length > 0);
          assert.ok(entries.every((entry) => !Object.hasOwn(entry, "bind")));
        }
      }
    }
  });

  test("a planner requiring another wrap is refused before entropy", async () => {
    const { issuerConfig, sealerConfig } = await world();
    const config = sealerConfig({
      issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
    });
    let draws = 0;
    const publisher = createPublisher(
      {
        ...config,
        issuerSupplyPlanFor: (issuer, render) => ({
          ...config.issuerSupplyPlanFor(issuer, render),
          contentKeyWrap: ordinaryContentKeyWrap,
        }),
        random: {
          bytes(n) {
            draws++;
            return config.random.bytes(n);
          },
        },
      },
      omissionContribution(config),
    );

    await assert.rejects(publisher.publish(article()), { code: "bad_config" });
    assert.equal(draws, 0);
  });
});
