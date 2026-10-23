import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Client } from "../../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { base64urlDecode, utf8Decode } from "../../core-shared/codec.js";
import { ISSUER_NAME } from "../../demo/scenarios/fixtures.js";
import { requestFor } from "../../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { BODYTEXT, PUB, T_NOW, T_NEXT, world } from "../../test-lib/fixtures/wire-policy-world.js";
import { issuerBlockOf, periodsOn, wrapGroupsOn } from "../../test-lib/helpers/inspect.js";
import { contentKeyMap, keyAt, periodKeyMap } from "../support/namedRecords.js";

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
 * The contentKey an issuer hands back for one item, as bytes. The content-key route,
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
  return base64urlDecode(keyAt(body.keys.contentKeys, { contentName }));
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
    assert.deepEqual(periodsOn(page, "bodytext", "subscriber"), [T_NOW, T_NEXT]);
    assert.deepEqual(periodsOn(page, "bodytext", "premium"), [T_NOW, T_NEXT]);

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

test("a cached slot key opens another article offering that slot even when its issuer refuses a new grant", async () => {
  const w = await world();
  const articleA = await w.render({
    resourceId: "article-A",
    items: [{ ...BODYTEXT, value: "Article A", accessGroups: ["slot-1", "slot-2"] }],
  });
  const articleB = await w.render({
    resourceId: "article-B",
    items: [{ ...BODYTEXT, value: "Article B", accessGroups: ["slot-1", "slot-2"] }],
  });
  const slotTwoOnly = await w.render({
    resourceId: "article-C",
    items: [{ ...BODYTEXT, value: "Article C", accessGroups: ["slot-2"] }],
  });

  let permitGrant = true;
  const { processor, endpoint, publisherRegistration } = w.endpointWith({
    accessPolicy: {
      decide(_claims, requested) {
        return {
          contentNames: [],
          periodGrants: permitGrant
            ? [
                {
                  accessGroup: "slot-1",
                  periods: (requested.periodCoordinates["slot-1"] ?? []).slice(0, 1),
                },
              ]
            : [],
          policyData: [],
        };
      },
    },
  });
  const client = new Client({ publisherOrigin: PUB, cache: new PeriodKeyCache() });
  const first = client.parse(articleA.page);
  const granted = await unlockThroughAdmission(
    processor,
    endpoint,
    client.buildRequest(first, ISSUER_NAME, ["bodytext"]),
    publisherRegistration,
  );
  assert.equal(granted.status, 200);
  assert.deepEqual(granted.body.keys.contentKeys, [], "no per-item content key was granted");
  const grantedPeriods = periodKeyMap(granted.body.keys.periodKeys);
  assert.deepEqual(Object.keys(grantedPeriods), ["slot-1"]);
  assert.deepEqual(Object.keys(grantedPeriods["slot-1"]), [T_NOW]);
  await client.applyResponse(first, ISSUER_NAME, granted.body);

  permitGrant = false;
  const second = client.parse(articleB.page);
  const refused = await unlockThroughAdmission(
    processor,
    endpoint,
    client.buildRequest(second, ISSUER_NAME, ["bodytext"]),
    publisherRegistration,
  );
  assert.deepEqual(
    refused.body.keys?.periodKeys ?? [],
    [],
    "the issuer returned no new period capability for article B",
  );
  assert.deepEqual((await client.resolve(second, ["bodytext"])).covered, ["bodytext"]);
  assert.equal(
    utf8Decode(await client.decrypt(second, "bodytext", client.extract(articleB.page, "bodytext"))),
    "Article B",
    "the previously granted slot-1 key opens B's different content key",
  );
  assert.deepEqual(
    (await client.resolve(client.parse(slotTwoOnly.page), ["bodytext"])).missing,
    ["bodytext"],
    "slot-1 does not open an article authored only under slot-2",
  );
});

test("each render's bodytext assignment bounds cached reach, and either assigned group opens C", async () => {
  const w = await world();
  const configuredGroups = new Set(["slot-1", "slot-2", "slot-3"]);
  const derivedGroups = new Set();
  const periodKeySupply = {
    async derive(accessGroup, t) {
      assert.ok(configuredGroups.has(accessGroup), `configured group ${accessGroup}`);
      derivedGroups.add(accessGroup);
      return w.periodKeySupply.derive(accessGroup, t);
    },
  };
  const items = {
    A: { ...BODYTEXT, value: "Article A", accessGroups: ["slot-1"] },
    B: { ...BODYTEXT, value: "Article B", accessGroups: ["slot-2"] },
    C: { ...BODYTEXT, value: "Article C", accessGroups: ["slot-1", "slot-2"] },
  };
  const [articleA, articleB, articleC] = await Promise.all(
    ["A", "B", "C"].map((id) =>
      w.render({
        resourceId: `article-${id}`,
        periodKeySupply,
        items: [items[id]],
      }),
    ),
  );

  for (const [rendered, expected] of [
    [articleA, ["slot-1"]],
    [articleB, ["slot-2"]],
    [articleC, ["slot-1", "slot-2"]],
  ]) {
    assert.deepEqual(wrapGroupsOn(rendered.page, "bodytext"), expected);
    assert.deepEqual(
      Object.keys(periodKeyMap(issuerBlockOf(rendered.page, ISSUER_NAME).sealed.periodKeys)),
      expected,
      "the configured but unassigned slot-3 has no issuer envelope either",
    );
  }
  assert.deepEqual([...derivedGroups].sort(), ["slot-1", "slot-2"]);

  let permittedGroup = "slot-1";
  let decisions = 0;
  const { processor, endpoint, publisherRegistration } = w.endpointWith({
    accessPolicy: {
      decide(_claims, requested) {
        decisions += 1;
        return {
          contentNames: [],
          periodGrants: requested.accessGroups.includes(permittedGroup)
            ? [
                {
                  accessGroup: permittedGroup,
                  periods: (requested.periodCoordinates[permittedGroup] ?? []).slice(0, 1),
                },
              ]
            : [],
          policyData: [],
        };
      },
    },
  });

  const slotOneClient = new Client({ publisherOrigin: PUB, cache: new PeriodKeyCache() });
  const pageA = slotOneClient.parse(articleA.page);
  const grantA = await unlockThroughAdmission(
    processor,
    endpoint,
    slotOneClient.buildRequest(pageA, ISSUER_NAME, ["bodytext"]),
    publisherRegistration,
  );
  assert.equal(grantA.status, 200);
  assert.deepEqual(grantA.body.keys.contentKeys, []);
  assert.deepEqual(Object.keys(periodKeyMap(grantA.body.keys.periodKeys)), ["slot-1"]);
  await slotOneClient.applyResponse(pageA, ISSUER_NAME, grantA.body);
  assert.deepEqual((await slotOneClient.resolve(pageA, ["bodytext"])).covered, ["bodytext"]);
  assert.equal(
    utf8Decode(
      await slotOneClient.decrypt(
        pageA,
        "bodytext",
        slotOneClient.extract(articleA.page, "bodytext"),
      ),
    ),
    "Article A",
  );

  const pageB = slotOneClient.parse(articleB.page);
  const deniedB = await unlockThroughAdmission(
    processor,
    endpoint,
    slotOneClient.buildRequest(pageB, ISSUER_NAME, ["bodytext"]),
    publisherRegistration,
  );
  assert.equal(deniedB.status, 401, "the slot-1 policy denies the slot-2 request");
  assert.equal(deniedB.body.keys, undefined, "the denied request carries no capability");
  assert.deepEqual((await slotOneClient.resolve(pageB, ["bodytext"])).missing, ["bodytext"]);

  const pageCFromSlotOne = slotOneClient.parse(articleC.page);
  const callsBeforeCachedC = decisions;
  assert.deepEqual((await slotOneClient.resolve(pageCFromSlotOne, ["bodytext"])).covered, [
    "bodytext",
  ]);
  assert.equal(
    decisions,
    callsBeforeCachedC,
    "the cached slot-1 key opens C without another unlock",
  );
  const slotOneContentKey = await slotOneClient.contentKeyFor(pageCFromSlotOne, "bodytext");
  assert.equal(
    utf8Decode(
      await slotOneClient.decrypt(
        pageCFromSlotOne,
        "bodytext",
        slotOneClient.extract(articleC.page, "bodytext"),
      ),
    ),
    "Article C",
  );

  permittedGroup = "slot-2";
  const slotTwoClient = new Client({ publisherOrigin: PUB, cache: new PeriodKeyCache() });
  const pageBForSlotTwo = slotTwoClient.parse(articleB.page);
  const grantB = await unlockThroughAdmission(
    processor,
    endpoint,
    slotTwoClient.buildRequest(pageBForSlotTwo, ISSUER_NAME, ["bodytext"]),
    publisherRegistration,
  );
  assert.deepEqual(Object.keys(periodKeyMap(grantB.body.keys.periodKeys)), ["slot-2"]);
  await slotTwoClient.applyResponse(pageBForSlotTwo, ISSUER_NAME, grantB.body);
  assert.deepEqual((await slotTwoClient.resolve(pageBForSlotTwo, ["bodytext"])).covered, [
    "bodytext",
  ]);
  assert.equal(
    utf8Decode(
      await slotTwoClient.decrypt(
        pageBForSlotTwo,
        "bodytext",
        slotTwoClient.extract(articleB.page, "bodytext"),
      ),
    ),
    "Article B",
  );
  const pageAFromSlotTwo = slotTwoClient.parse(articleA.page);
  assert.deepEqual(
    (await slotTwoClient.resolve(pageAFromSlotTwo, ["bodytext"])).missing,
    ["bodytext"],
    "slot-2 does not open A, which is assigned only to slot-1",
  );
  const pageCFromSlotTwo = slotTwoClient.parse(articleC.page);
  assert.deepEqual((await slotTwoClient.resolve(pageCFromSlotTwo, ["bodytext"])).covered, [
    "bodytext",
  ]);
  const slotTwoContentKey = await slotTwoClient.contentKeyFor(pageCFromSlotTwo, "bodytext");
  assert.deepEqual(slotTwoContentKey, slotOneContentKey, "both wraps open C's same contentKey");

  const unassignedCache = new PeriodKeyCache();
  await unassignedCache.put("slot-3", T_NOW, new Uint8Array(16), { publisher: PUB });
  const unassignedClient = new Client({ publisherOrigin: PUB, cache: unassignedCache });
  const pageCFromUnassignedGroup = unassignedClient.parse(articleC.page);
  assert.deepEqual(wrapGroupsOn(pageCFromUnassignedGroup, "bodytext"), ["slot-1", "slot-2"]);
  assert.equal(
    await unassignedClient.contentKeyFor(pageCFromUnassignedGroup, "bodytext"),
    null,
    "a cached unassigned slot-3 key is not a candidate for C",
  );
});

test("one sealed item serves full-group subscribers by cache and occasional readers by item key", async () => {
  const w = await world();
  const firstRender = await w.render({
    resourceId: "shared-premium-render",
    items: [{ ...BODYTEXT, value: "Shared article", accessGroups: ["premium"] }],
  });
  const secondRender = await w.render({
    resourceId: "another-premium-render",
    items: [{ ...BODYTEXT, value: "Another article", accessGroups: ["premium"] }],
  });

  const subscriberEntitlement = new Set(["premium"]);
  let subscriberDecisions = 0;
  const {
    processor: subscriberProcessor,
    endpoint: subscriberEndpoint,
    publisherRegistration,
  } = w.endpointWith({
    accessPolicy: {
      decide(_claims, requested) {
        subscriberDecisions += 1;
        return {
          // This issuer's trusted policy grants the whole premium group;
          // it has no per-article membership reconstruction step.
          contentNames: [],
          periodGrants:
            subscriberEntitlement.has("premium") && requested.accessGroups.includes("premium")
              ? [
                  {
                    accessGroup: "premium",
                    periods: (requested.periodCoordinates.premium ?? []).slice(0, 1),
                  },
                ]
              : [],
          policyData: [],
        };
      },
    },
  });
  const subscriber = new Client({ publisherOrigin: PUB, cache: new PeriodKeyCache() });
  const subscriberPage = subscriber.parse(firstRender.page);
  const subscriberGrant = await unlockThroughAdmission(
    subscriberProcessor,
    subscriberEndpoint,
    subscriber.buildRequest(subscriberPage, ISSUER_NAME, ["bodytext"]),
    publisherRegistration,
  );
  assert.deepEqual(subscriberGrant.body.keys.contentKeys, []);
  assert.deepEqual(Object.keys(periodKeyMap(subscriberGrant.body.keys.periodKeys)), ["premium"]);
  await subscriber.applyResponse(subscriberPage, ISSUER_NAME, subscriberGrant.body);
  assert.deepEqual((await subscriber.resolve(subscriberPage, ["bodytext"])).covered, ["bodytext"]);
  const subscriberContentKey = await subscriber.contentKeyFor(subscriberPage, "bodytext");
  assert.equal(
    utf8Decode(
      await subscriber.decrypt(
        subscriberPage,
        "bodytext",
        subscriber.extract(firstRender.page, "bodytext"),
      ),
    ),
    "Shared article",
    "the subscriber's period-key wrap opens the same first-render item",
  );
  const subscriberSecondPage = subscriber.parse(secondRender.page);
  assert.deepEqual(
    (await subscriber.resolve(subscriberSecondPage, ["bodytext"])).covered,
    ["bodytext"],
    "the cached full-group key opens the next render without an issuer call",
  );
  assert.equal(subscriberDecisions, 1);
  assert.equal(
    utf8Decode(
      await subscriber.decrypt(
        subscriberSecondPage,
        "bodytext",
        subscriber.extract(secondRender.page, "bodytext"),
      ),
    ),
    "Another article",
    "the trusted full-group entitlement reaches a separate render",
  );

  const occasionalResourceId = firstRender.page.resource.resourceId;
  const occasionalEntitlement = new Set([`${occasionalResourceId}|bodytext`]);
  const { processor: occasionalProcessor, endpoint: occasionalEndpoint } = w.endpointWith({
    accessPolicy: {
      decide(claims, requested) {
        return {
          // This item grant is tied to the first verified resource. It does
          // not authorize the same contentName in a later render.
          contentNames: requested.contentNames.filter((name) =>
            occasionalEntitlement.has(`${claims.resource.resourceId}|${name}`),
          ),
          periodGrants: [],
          policyData: [],
        };
      },
    },
  });
  const occasional = new Client({ publisherOrigin: PUB, cache: new PeriodKeyCache() });
  const occasionalPage = occasional.parse(firstRender.page);
  const occasionalGrant = await unlockThroughAdmission(
    occasionalProcessor,
    occasionalEndpoint,
    occasional.buildRequest(occasionalPage, ISSUER_NAME, ["bodytext"]),
    publisherRegistration,
  );
  assert.deepEqual(Object.keys(contentKeyMap(occasionalGrant.body.keys.contentKeys)), ["bodytext"]);
  assert.equal(occasionalGrant.body.keys.periodKeys, undefined);
  await occasional.applyResponse(occasionalPage, ISSUER_NAME, occasionalGrant.body);
  assert.deepEqual((await occasional.resolve(occasionalPage, ["bodytext"])).covered, ["bodytext"]);
  const occasionalContentKey = await occasional.contentKeyFor(occasionalPage, "bodytext");
  assert.deepEqual(
    occasionalContentKey,
    subscriberContentKey,
    "the item-key grant and cached period-key wrap yield the same contentKey",
  );
  assert.equal(
    utf8Decode(
      await occasional.decrypt(
        occasionalPage,
        "bodytext",
        occasional.extract(firstRender.page, "bodytext"),
      ),
    ),
    "Shared article",
  );
  const occasionalSecondPage = occasional.parse(secondRender.page);
  assert.equal(
    await occasional.contentKeyFor(occasionalSecondPage, "bodytext"),
    null,
    "the first render's item key does not open bodytext in another render",
  );
  const deniedSecondRender = await unlockThroughAdmission(
    occasionalProcessor,
    occasionalEndpoint,
    occasional.buildRequest(occasionalSecondPage, ISSUER_NAME, ["bodytext"]),
    publisherRegistration,
  );
  assert.equal(deniedSecondRender.status, 401);
  assert.equal(deniedSecondRender.body.keys, undefined);
  assert.equal(occasionalPage.resourceJWT, subscriberPage.resourceJWT);
});
