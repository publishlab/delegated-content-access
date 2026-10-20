// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";
import { Clock } from "../demo/actors/Clock.js";
import { rootFromPage } from "../demo/support/queryableRoot.js";
import { actorWorld, readArticle } from "../demo/scenarios/world.js";
import { ACCESS_GROUP, CONTENT_NAME, CONTENT_TYPE } from "../demo/scenarios/fixtures.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { chainKeyCapabilitySource } from "../extensions/chain-keys/core-issuer/chainKeyCapabilitySource.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import {
  chainGeneration,
  chainSupply,
  deliveryPlan,
  periodOnlyPolicy,
} from "../extensions/chain-keys/test/world.js";

const GEOMETRY = { chainsPerDay: 2, periodMinutes: 15 };
const WINDOW_START = "251023T1200";
const CUTOFF = "251023T1415";
const SUPPLIED = "251023T2345";
const ISSUER_NOW = "2025-10-23T14:20:00Z";

test("unit: a denied window start withholds the chain grant for a later cutoff", () => {
  const request = new DcaRequest({
    sealed: { contentKeys: {}, chainKeys: { [ACCESS_GROUP]: { [SUPPLIED]: "AQ" } } },
    periodGeometry: GEOMETRY,
    requestedPeriodKeys: { [ACCESS_GROUP]: [CUTOFF] },
  });
  const answer = chainKeyCapabilitySource({ representation: "chain-keys" }).selection(
    request,
    { capturedAtMs: Date.parse(ISSUER_NOW) },
    [
      {
        accessGroup: ACCESS_GROUP,
        futurePeriodCount: 0,
        authorizePeriod: (t) => t !== WINDOW_START,
      },
    ],
  )(ACCESS_GROUP);
  assert.equal(
    Object.hasOwn(answer, "selected"),
    false,
    `no chain grant when position 0 is denied; got ${JSON.stringify(answer)}`,
  );
});

test("end to end: the reader cannot open the denied window-start item from a cutoff grant", async () => {
  const chainCache = new ChainKeyCache({ strategy: "retain" });
  const basePlan = deliveryPlan(() => ["chain-keys"]);
  const world = await actorWorld({
    at: ISSUER_NOW,
    period: { slots: 1 },
    periodKeySupply: chainSupply(chainGeneration(7)),
    issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) => ({
      ...basePlan(issuer, render),
      contentKeyNames: [],
    }),
    accessPolicy: periodOnlyPolicy(0, (t) => t !== WINDOW_START),
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => chainCache,
    primary: { periodGrantKind: "chain-keys" },
  });
  /** @type {{ status: number, response: any }[]} */
  const exchanges = [];
  const browser = world.makeBrowser({
    network: {
      async post(
        /** @type {string} */ url,
        /** @type {any} */ request,
        /** @type {any} */ options,
      ) {
        const answer = await world.network.post(url, request, options);
        exchanges.push({
          status: answer.status,
          response: JSON.parse(JSON.stringify(answer.body)),
        });
        return answer;
      },
    },
    chainKeyStrategy: "retain",
    requestBuilderFactory: (/** @type {object} */ options) => new ChainKeyRequestBuilder(options),
  });
  const publisherClock = new Clock(ISSUER_NOW);
  const publisher = world.publisherWith({ clock: publisherClock });
  const instant = (/** @type {string} */ t) =>
    `20${t.slice(0, 2)}-${t.slice(2, 4)}-${t.slice(4, 6)}T${t.slice(7, 9)}:${t.slice(9, 11)}:00Z`;
  const renderAt = (/** @type {string} */ t) => {
    publisherClock.set(instant(t));
    return publisher.render({
      resourceId: `bulletin-${t}`,
      data: { section: "harbour" },
      items: [
        {
          name: CONTENT_NAME,
          value: `<p>Bulletin ${t}.</p>`,
          contentType: CONTENT_TYPE,
          accessGroups: [ACCESS_GROUP],
        },
      ],
    });
  };
  const atWindowStart = await renderAt(WINDOW_START);
  const atCutoff = await renderAt(CUTOFF);

  const first = await readArticle(browser, atCutoff, [CONTENT_NAME]);
  assert.equal(exchanges.length, 1);
  const chainKeys = exchanges[0].response?.keys?.chainKeys?.[ACCESS_GROUP];
  assert.equal(
    chainKeys,
    undefined,
    `the issuer must return no chain key while position 0 is denied; returned ${JSON.stringify(chainKeys)}`,
  );
  assert.equal(first.texts[CONTENT_NAME], null);

  // The denied item: whatever the first unlock left behind must not open it.
  const load = browser.load(rootFromPage(atWindowStart));
  const { missing } = await load.resolve([CONTENT_NAME]);
  const opened = await load.open(CONTENT_NAME);
  assert.deepEqual(
    missing,
    [CONTENT_NAME],
    "the window-start item is not resolved from retained material",
  );
  assert.deepEqual(
    opened,
    { bytes: null, error: "no_key" },
    "the denied window-start item stays closed",
  );
});
