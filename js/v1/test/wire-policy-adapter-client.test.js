import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Client } from "../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { base64urlDecode } from "../core-shared/codec.js";
import { ISSUER_NAME } from "../demo/scenarios/fixtures.js";
import { requestFor } from "../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";
import { BODYTEXT, PUB, T_NOW, T_NEXT, world } from "../test-lib/fixtures/wire-policy-world.js";

/**
 * A cache that records which exact coordinates were asked for, so a test can
 * count coordinate lookups instead of reading the code.
 *
 * @param {PeriodKeyCache} cache
 */
function countingCache(cache) {
  /** @type {string[]} */
  const asked = [];
  return {
    asked,
    /**
     * @param {string} accessGroup
     * @param {string} t
     * @param {any} key
     * @param {object} [context]
     */
    put(accessGroup, t, key, context) {
      return cache.put(accessGroup, t, key, context);
    },
    /**
     * @param {string} accessGroup
     * @param {string} t
     * @param {object} [context]
     */
    candidatesAt(accessGroup, t, context) {
      asked.push(`${accessGroup}|${t}`);
      return cache.candidatesAt(accessGroup, t, context);
    },
    attempted(context) {
      return cache.attempted(context);
    },
  };
}

/**
 * The contentKey an issuer hands back for one item, as bytes. The direct path,
 * used here as the reference every other delivery of the same key is compared
 * against.
 *
 * @param {any} w - the world
 * @param {any} page
 * @param {string} contentName
 * @returns {Promise<Uint8Array>}
 */
async function contentKeyFor(w, page, contentName) {
  const { processor, endpoint, publisherRegistration } = w.endpointWith();
  const { status, body } = await unlockThroughAdmission(
    processor,
    endpoint,
    requestFor(page, ISSUER_NAME, [contentName]),
    publisherRegistration,
  );

  assert.equal(
    status,
    200,
    "the reference unlock has to succeed, or the comparison below means nothing",
  );
  return base64urlDecode(body.keys.contentKeys[contentName]);
}

describe("first-accessGroup-wins", () => {
  // The trial unwrap asks only the article's exact coordinates and stops at
  // the first one that opens an entry.

  test("the trial unwrap asks each authored coordinate, not unrelated family history", async () => {
    const w = await world();
    const { page } = await w.render({
      items: [{ ...BODYTEXT, accessGroups: ["subscriber", "premium"] }],
    });

    // Two groups, two periods each: four entries the walk could have asked
    // about, and two families it may ask about.
    assert.deepEqual(
      page.contentData.bodytext.keys.subscriber.map((/** @type {any} */ e) => e.t),
      [T_NOW, T_NEXT],
    );
    assert.deepEqual(
      page.contentData.bodytext.keys.premium.map((/** @type {any} */ e) => e.t),
      [T_NOW, T_NEXT],
    );

    const backing = new PeriodKeyCache();
    // Only the second group's key is held, so the walk has to pass through the
    // first one and keep going; a miss on a family does not end the walk.
    await backing.put("premium", T_NOW, await w.periodKeySupply.derive("premium", T_NOW), {
      publisher: PUB,
    });

    const cache = countingCache(backing);
    const unsealer = new Client({ cache: /** @type {any} */ (cache), publisherOrigin: PUB });
    const dcaData = unsealer.parse(page);

    const { covered } = await unsealer.resolve(dcaData, ["bodytext"]);
    assert.deepEqual(covered, ["bodytext"], "the second group opened it");

    assert.deepEqual(cache.asked, [
      `subscriber|${T_NOW}`,
      `subscriber|${T_NEXT}`,
      `premium|${T_NOW}`,
    ]);
    assert.equal(
      cache.asked.length,
      3,
      "the successful premium coordinate ends the walk before its sibling",
    );
  });

  test("the walk stops at the first accessGroup that unwraps, and never asks about the rest", async () => {
    const w = await world();
    const { page } = await w.render({
      items: [{ ...BODYTEXT, accessGroups: ["subscriber", "premium"] }],
    });

    const backing = new PeriodKeyCache();
    for (const accessGroup of ["subscriber", "premium"]) {
      await backing.put(accessGroup, T_NOW, await w.periodKeySupply.derive(accessGroup, T_NOW), {
        publisher: PUB,
      });
    }

    const cache = countingCache(backing);
    const unsealer = new Client({ cache: /** @type {any} */ (cache), publisherOrigin: PUB });
    const dcaData = unsealer.parse(page);

    const opened = await unsealer.contentKeyFor(dcaData, "bodytext");
    assert.ok(opened, "the first group opened it");

    assert.deepEqual(
      cache.asked,
      [`subscriber|${T_NOW}`],
      "first-accessGroup-wins: premium was never consulted",
    );

    // Both groups wrap the same contentKey, so which one won is invisible in
    // what came out. That is why the walk order is asserted on the lookups
    // rather than on the key.
    assert.deepEqual(opened, await contentKeyFor(w, page, "bodytext"));
  });
});
