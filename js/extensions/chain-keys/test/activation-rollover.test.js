// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";

import { actorWorld } from "../../../demo/scenarios/world.js";
import { rootFromPage } from "../../../demo/support/queryableRoot.js";
import { ACCESS_GROUP, CONTENT_NAME, ISSUER_NAME } from "../../../demo/scenarios/fixtures.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { base64urlEncode, utf8Decode } from "../../../core-shared/codec.js";
import { parseDcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { chainKeyIssuerEngine } from "../core-issuer/chainKeyIssuerEngine.js";
import { referenceChainKeyProfile } from "../referenceProfile.js";
import {
  candidatesOffered,
  chainBrowser,
  chainGeneration,
  chainSupply,
  coordinatesOf,
  exchangesPosted,
  deliveryPlan,
  GEOMETRY,
  periodOnlyPolicy,
  sameBytes,
} from "./world.js";

const T0 = "251023T2330";
const T1 = "251024T0000";

/** Page delivery keeps encrypted content beside DCA metadata. */
function metadataOf(page) {
  const { sealedContent, ...metadata } = page.asJson();
  assert.ok(sealedContent && typeof sealedContent === "object");
  assert.equal(Object.hasOwn(metadata, "sealedContent"), false);
  return metadata;
}

/** Save the actual serialized DCA metadata and wire documents when requested. */
async function saveArtifacts(name, documents) {
  const root = process.env.DCA_ACTIVATION_ARTIFACT_DIR;
  if (!root) return;
  await mkdir(root, { recursive: true });
  const measures = {};
  for (const [kind, document] of Object.entries(documents)) {
    if (kind.toLowerCase().includes("dcametadata")) {
      assert.equal(
        Object.hasOwn(document, "sealedContent"),
        false,
        `${kind} excludes encrypted body`,
      );
    }
    const bytes = Buffer.from(JSON.stringify(document));
    const compressed = gzipSync(bytes, { level: 6 });
    assert.deepEqual(gunzipSync(compressed), bytes, `${kind} gzip roundtrips`);
    await writeFile(join(root, `${name}-${kind}.json`), bytes);
    await writeFile(join(root, `${name}-${kind}.json.gz`), compressed);
    measures[kind] = { rawBytes: bytes.length, gzipBytes: compressed.length };
  }
  await writeFile(join(root, `${name}-measures.json`), JSON.stringify(measures, null, 2) + "\n");
}

test("optimized T1-only ordinary source serves chain and explicit T1 grants from one saved article", async () => {
  let active = false;
  let policyMode = "ordinary-current";
  const chainCache = new ChainKeyCache({ strategy: "retain" });
  const world = await actorWorld({
    at: "2025-10-23T23:40:00Z",
    period: { length: 15, slots: 3 },
    issuerSupplyPlanFor: (issuer, render) => ({
      ...wholeRenderIssuerSupplyPlan(issuer, render),
      contentKeyNames: [],
      ...(active
        ? {
            periodKeyDelivery: { [ACCESS_GROUP]: ["period-keys", "chain-keys"] },
            periodKeySourceTs: { [ACCESS_GROUP]: [T1] },
          }
        : { periodKeyDelivery: { [ACCESS_GROUP]: ["period-keys"] } }),
    }),
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => chainCache,
    primary: {
      periodGrantKind: "chain-keys",
      accessPolicy: {
        decide(_claims, requested) {
          return {
            contentNames: [],
            periodGrants: requested.accessGroups.map((accessGroup) =>
              policyMode.startsWith("chain")
                ? {
                    accessGroup,
                    futurePeriodCount: 1,
                    authorizePeriod: (t) => policyMode === "chain" || t === T1,
                  }
                : {
                    accessGroup,
                    periods: policyMode === "ordinary-next" ? [T1] : [T0],
                  },
            ),
          };
        },
      },
    },
  });
  const browser = chainBrowser(world);
  const oldPage = await world.render("A");
  assert.deepEqual(coordinatesOf(oldPage), [T0, "251023T2345", T1]);
  assert.equal(Object.hasOwn(oldPage.asJson().issuerData[ISSUER_NAME].sealed, "chainKeys"), false);
  const oldLoad = browser.load(rootFromPage(oldPage));
  assert.deepEqual(await oldLoad.resolve([CONTENT_NAME]), { covered: [], missing: [CONTENT_NAME] });
  const oldExchange = await exchangesPosted(world.network, () =>
    oldLoad.unlock({ issuerName: ISSUER_NAME }),
  );
  assert.equal(oldExchange.result.ok, true, JSON.stringify(oldExchange.exchanges));
  assert.deepEqual(Object.keys(oldExchange.exchanges[0].body.keys.periodKeys[ACCESS_GROUP]), [T0]);
  assert.match(utf8Decode((await oldLoad.open(CONTENT_NAME)).bytes), /rezone the harbour/);

  const generation = chainGeneration(17);
  active = true;
  world.publisher.rotatePeriodKeySupply(chainSupply(generation, 1, 3));
  const savedPage = await world.render("B");
  const data = savedPage.asJson();
  assert.deepEqual(coordinatesOf(savedPage), [T0, "251023T2345", T1]);
  assert.deepEqual(Object.keys(data.issuerData[ISSUER_NAME].sealed.periodKeys[ACCESS_GROUP]), [T1]);
  assert.deepEqual(Object.keys(data.issuerData[ISSUER_NAME].sealed.chainKeys[ACCESS_GROUP]), [
    "251023T2345",
  ]);
  assert.deepEqual(data.periodGeometry, GEOMETRY);

  // The optimized article supports an explicit ordinary T1 decision even
  // though its T0 ordinary source was intentionally omitted.
  policyMode = "ordinary-next";
  const nextBrowser = chainBrowser(world);
  const nextLoad = nextBrowser.load(rootFromPage(savedPage));
  await nextLoad.resolve([CONTENT_NAME]);
  const nextExchange = await exchangesPosted(world.network, () =>
    nextLoad.unlock({ issuerName: ISSUER_NAME }),
  );
  assert.equal(nextExchange.result.ok, true, JSON.stringify(nextExchange.exchanges));
  assert.deepEqual(Object.keys(nextExchange.exchanges[0].request.sealed.periodKeys[ACCESS_GROUP]), [
    T1,
  ]);
  assert.deepEqual(Object.keys(nextExchange.exchanges[0].request.sealed.chainKeys[ACCESS_GROUP]), [
    "251023T2345",
  ]);
  assert.deepEqual(Object.keys(nextExchange.exchanges[0].body.keys.periodKeys[ACCESS_GROUP]), [T1]);
  assert.match(utf8Decode((await nextLoad.open(CONTENT_NAME)).bytes), /second reading/);

  // Issuer later selects its chain input for the identical saved article.
  policyMode = "chain";
  const activeLoad = browser.load(rootFromPage(savedPage));
  const { result: resolved, offered } = await candidatesOffered(browser.cache, () =>
    activeLoad.resolve([CONTENT_NAME]),
  );
  assert.deepEqual(resolved, { covered: [], missing: [CONTENT_NAME] });
  assert.ok(offered.flat().length > 0, "the old same-coordinate period key was offered");
  const newT0 = await generation.periodKey(ACCESS_GROUP, T0);
  assert.equal(
    offered.flat().some((key) => sameBytes(key, newT0)),
    false,
  );
  const chainExchange = await exchangesPosted(world.network, () =>
    activeLoad.unlock({ issuerName: ISSUER_NAME }),
  );
  assert.equal(chainExchange.result.ok, true, JSON.stringify(chainExchange.exchanges));
  assert.deepEqual(Object.keys(chainExchange.exchanges[0].body.keys.chainKeys[ACCESS_GROUP]), [
    "251023T2345",
  ]);
  assert.match(utf8Decode((await activeLoad.open(CONTENT_NAME)).bytes), /second reading/);
  assert.match(
    utf8Decode((await browser.load(rootFromPage(oldPage)).open(CONTENT_NAME)).bytes),
    /rezone the harbour/,
  );

  // At T1 the retained prior-window chain cannot reach forward. Even though
  // the article also relays an ordinary T1 source, a chain-horizon grant does
  // not silently change representation or authorization semantics.
  world.clock.set("2025-10-24T00:05:00Z");
  policyMode = "chain-next-only";
  const freshBrowser = () =>
    world.makeBrowser({
      chainKeyStrategy: "retain",
      chainKeyCacheFactory: () => new ChainKeyCache({ strategy: "retain" }),
      requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
    });
  const chainAtT1 = freshBrowser().load(rootFromPage(savedPage));
  await chainAtT1.resolve([CONTENT_NAME]);
  const unavailable = await exchangesPosted(world.network, () =>
    chainAtT1.unlock({ issuerName: ISSUER_NAME }),
  );
  assert.equal(
    unavailable.exchanges.length,
    1,
    JSON.stringify({ result: unavailable.result, exchanges: unavailable.exchanges }),
  );
  assert.equal(unavailable.result.ok, false);
  assert.deepEqual(unavailable.exchanges[0].body.keys.periodKeys ?? {}, {});
  assert.deepEqual(unavailable.exchanges[0].body.keys.chainKeys ?? {}, {});

  // The same chain-capable issuer can choose an explicit ordinary grant for
  // T1; its enabled chain input has not disabled its period-key route.
  policyMode = "ordinary-next";
  const laterBrowser = freshBrowser();
  const ordinaryAtT1 = laterBrowser.load(rootFromPage(savedPage));
  await ordinaryAtT1.resolve([CONTENT_NAME]);
  const later = await exchangesPosted(world.network, () =>
    ordinaryAtT1.unlock({ issuerName: ISSUER_NAME }),
  );
  assert.equal(later.result.ok, true, JSON.stringify(later.exchanges));
  assert.deepEqual(Object.keys(later.exchanges[0].body.keys.periodKeys[ACCESS_GROUP]), [T1]);
  assert.equal(
    later.exchanges[0].body.keys.periodKeys[ACCESS_GROUP][T1],
    base64urlEncode(await generation.periodKey(ACCESS_GROUP, T1)),
  );
  assert.match(utf8Decode((await ordinaryAtT1.open(CONTENT_NAME)).bytes), /second reading/);
  const freshAtT1 = await world.render("C");
  assert.equal(coordinatesOf(freshAtT1)[0], T1);
  const cachedAtT1 = laterBrowser.load(rootFromPage(freshAtT1));
  assert.deepEqual(await cachedAtT1.resolve([CONTENT_NAME]), {
    covered: [CONTENT_NAME],
    missing: [],
  });
  assert.match(utf8Decode((await cachedAtT1.open(CONTENT_NAME)).bytes), /close on Friday/);
  await saveArtifacts("optimized", {
    dcaMetadata: metadataOf(savedPage),
    ordinaryRequest: nextExchange.exchanges[0].request,
    ordinaryResponse: nextExchange.exchanges[0].body,
    chainRequest: chainExchange.exchanges[0].request,
    chainResponse: chainExchange.exchanges[0].body,
    unreachableRequest: unavailable.exchanges[0].request,
    unreachableResponse: unavailable.exchanges[0].body,
  });
});

test("a granted T+6 cutoff cannot open a T+7-only article in the same stationary window", async () => {
  const t6 = "251023T0600";
  const t7 = "251023T0700";
  const world = await actorWorld({
    at: "2025-10-23T06:05:00Z",
    period: { length: 60, slots: 1 },
    periodKeySupply: chainSupply(chainGeneration(23), 1),
    issuerSupplyPlanFor: deliveryPlan(() => ["chain-keys"]),
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => new ChainKeyCache({ strategy: "retain" }),
    primary: {
      periodGrantKind: "chain-keys",
      accessPolicy: periodOnlyPolicy(1, (t) => t <= t6),
    },
  });
  const browser = chainBrowser(world);
  const article6 = await world.render("A");
  assert.deepEqual(coordinatesOf(article6), [t6]);
  const load6 = browser.load(rootFromPage(article6));
  await load6.resolve([CONTENT_NAME]);
  const granted = await exchangesPosted(world.network, () =>
    load6.unlock({ issuerName: ISSUER_NAME }),
  );
  assert.equal(granted.result.ok, true);
  assert.match(utf8Decode((await load6.open(CONTENT_NAME)).bytes), /rezone the harbour/);
  world.clock.set("2025-10-23T07:05:00Z");
  const article7 = await world.render("B");
  assert.deepEqual(coordinatesOf(article7), [t7]);
  const load7 = browser.load(rootFromPage(article7));
  assert.deepEqual(await load7.resolve([CONTENT_NAME]), { covered: [], missing: [CONTENT_NAME] });
  const denied = await load7.open(CONTENT_NAME);
  assert.equal(denied.bytes, null);
  assert.equal(denied.error, "no_key");
  const refused = await exchangesPosted(world.network, () =>
    load7.unlock({ issuerName: ISSUER_NAME }),
  );
  assert.equal(refused.result.ok, false);
  assert.deepEqual(refused.exchanges[0].body.keys?.chainKeys ?? {}, {});
});

test("full dual supply preserves an ordinary relay before the issuer selects chain grants on the saved article", async () => {
  let active = false;
  let chainGrant = false;
  const world = await actorWorld({
    at: "2025-10-23T23:40:00Z",
    period: { length: 15, slots: 3 },
    issuerSupplyPlanFor: (issuer, render) => ({
      ...wholeRenderIssuerSupplyPlan(issuer, render),
      contentKeyNames: [],
      periodKeyDelivery: {
        [ACCESS_GROUP]: active ? ["period-keys", "chain-keys"] : ["period-keys"],
      },
    }),
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => new ChainKeyCache({ strategy: "retain" }),
    primary: {
      periodGrantKind: "chain-keys",
      accessPolicy: {
        decide(_claims, requested) {
          return {
            contentNames: [],
            periodGrants: requested.accessGroups.map((accessGroup) =>
              chainGrant
                ? { accessGroup, futurePeriodCount: 1, authorizePeriod: () => true }
                : { accessGroup, periods: [T0] },
            ),
          };
        },
      },
    },
  });
  const ordinaryBrowser = world.makeBrowser();
  const oldPage = await world.render("A");
  const oldLoad = ordinaryBrowser.load(rootFromPage(oldPage));
  await oldLoad.resolve([CONTENT_NAME]);
  const old = await exchangesPosted(world.network, () =>
    oldLoad.unlock({ issuerName: ISSUER_NAME }),
  );
  assert.equal(old.result.ok, true);
  const oldT0 = ordinaryBrowser.cache.candidatesAt(ACCESS_GROUP, T0, {
    publisher: world.publisher.origin,
  });
  assert.ok((await oldT0).length > 0);

  const generation = chainGeneration(19);
  active = true;
  world.publisher.rotatePeriodKeySupply(chainSupply(generation, 1, 3));
  const savedPage = await world.render("B");
  const sealed = savedPage.asJson().issuerData[ISSUER_NAME].sealed;
  assert.deepEqual(Object.keys(sealed.periodKeys[ACCESS_GROUP]), [T0, "251023T2345", T1]);
  assert.deepEqual(Object.keys(sealed.chainKeys[ACCESS_GROUP]), ["251023T2345"]);
  const newT0 = await generation.periodKey(ACCESS_GROUP, T0);
  assert.equal(
    (await oldT0).some((key) => sameBytes(key, newT0)),
    false,
  );

  // A base request relays only ordinary source even though the saved page
  // already carries both. The old same-label candidate misses; the new T0
  // answer is cached alongside it without a flush.
  const ordinaryLoad = ordinaryBrowser.load(rootFromPage(savedPage));
  const ordinaryResolved = await ordinaryLoad.resolve([CONTENT_NAME]);
  assert.deepEqual(ordinaryResolved, { covered: [], missing: [CONTENT_NAME] });
  const ordinary = await exchangesPosted(world.network, () =>
    ordinaryLoad.unlock({ issuerName: ISSUER_NAME }),
  );
  assert.equal(ordinary.result.ok, true);
  assert.equal(Object.hasOwn(ordinary.exchanges[0].request.sealed, "chainKeys"), false);
  assert.deepEqual(Object.keys(ordinary.exchanges[0].body.keys.periodKeys[ACCESS_GROUP]), [T0]);
  assert.match(utf8Decode((await ordinaryLoad.open(CONTENT_NAME)).bytes), /second reading/);
  assert.match(
    utf8Decode((await ordinaryBrowser.load(rootFromPage(oldPage)).open(CONTENT_NAME)).bytes),
    /rezone the harbour/,
  );
  const rivalCandidates = await ordinaryBrowser.cache.candidatesAt(ACCESS_GROUP, T0, {
    publisher: world.publisher.origin,
  });
  const oldKey = (await oldT0)[0];
  assert.ok(
    rivalCandidates.some((key) => sameBytes(key, oldKey)),
    "the old candidate remains",
  );
  assert.ok(
    rivalCandidates.some((key) => sameBytes(key, newT0)),
    "the new candidate is retained at the same coordinate",
  );
  active = false;
  world.publisher.rotatePeriodKeySupply(world.periodKeySupply);
  const freshOldGenerationPage = await world.render("C");
  active = true;
  world.publisher.rotatePeriodKeySupply(chainSupply(generation, 1, 3));
  const freshOldLoad = ordinaryBrowser.load(rootFromPage(freshOldGenerationPage));
  assert.deepEqual(await freshOldLoad.resolve([CONTENT_NAME]), {
    covered: [CONTENT_NAME],
    missing: [],
  });
  assert.match(utf8Decode((await freshOldLoad.open(CONTENT_NAME)).bytes), /close on Friday/);

  chainGrant = true;
  const capable = chainBrowser(world).load(rootFromPage(savedPage));
  await capable.resolve([CONTENT_NAME]);
  const chain = await exchangesPosted(world.network, () =>
    capable.unlock({ issuerName: ISSUER_NAME }),
  );
  assert.equal(chain.result.ok, true);
  assert.deepEqual(Object.keys(chain.exchanges[0].request.sealed.chainKeys[ACCESS_GROUP]), [
    "251023T2345",
  ]);
  assert.deepEqual(Object.keys(chain.exchanges[0].body.keys.chainKeys[ACCESS_GROUP]), [
    "251023T2345",
  ]);
  assert.match(utf8Decode((await capable.open(CONTENT_NAME)).bytes), /second reading/);
  // The two engines operate on the identical signed article and registration.
  // The first consumes the ordinary serialized request without chain input;
  // the later composition consumes its chain-relaying serialized request.
  const baseRequest = parseDcaRequest(JSON.stringify(ordinary.exchanges[0].request));
  const baseResult = await new IssuerEngine({
    operatingIssuerNames: [ISSUER_NAME],
    accessPolicy: {
      decide: (_claims, requested) => ({
        contentNames: [],
        periodGrants: requested.accessGroups.map((accessGroup) => ({ accessGroup, periods: [T0] })),
      }),
    },
  }).unlock(baseRequest, world.publisherRegistration);
  assert.equal(baseResult.periodKeys[ACCESS_GROUP][T0], base64urlEncode(newT0));
  const chainRequest = parseDcaRequest(JSON.stringify(chain.exchanges[0].request));
  const chainResult = await chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER_NAME],
    clock: world.clock,
    accessPolicy: {
      decide: (_claims, requested) => ({
        contentNames: [],
        periodGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          futurePeriodCount: 1,
          authorizePeriod: () => true,
        })),
      }),
    },
  }).unlock(chainRequest, world.publisherRegistration);
  assert.equal(chainResult.periodKeys[ACCESS_GROUP][T0], base64urlEncode(newT0));
  assert.deepEqual(await ordinaryBrowser.load(rootFromPage(savedPage)).resolve([CONTENT_NAME]), {
    covered: [CONTENT_NAME],
    missing: [],
  });
  await saveArtifacts("staged", {
    randomDcaMetadata: metadataOf(oldPage),
    randomRequest: old.exchanges[0].request,
    randomResponse: old.exchanges[0].body,
    fullDualDcaMetadata: metadataOf(savedPage),
    publisherFirstRequest: ordinary.exchanges[0].request,
    publisherFirstResponse: ordinary.exchanges[0].body,
    issuerLaterRequest: chain.exchanges[0].request,
    issuerLaterResponse: chain.exchanges[0].body,
  });
});
