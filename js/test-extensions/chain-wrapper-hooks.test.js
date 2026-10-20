// Chain relay must retain another selected extension's delivery-client hooks,
// including when this issuer supplies no ordinary chain-key family to relay.
import test from "node:test";
import assert from "node:assert/strict";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { createDeliveryClient } from "../integration-client/createDeliveryClient.js";
import { ChainKeyRequestBuilder } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { contentGroupsProfile } from "../extensions/content-groups/referenceProfile.js";
import { world, item, CHAIN, UNLOCK } from "../extensions/content-groups/test/_lib/world.js";

test("chain wrapper preserves a seed-only content-group route through the real delivery walk", async () => {
  const fixture = await world();
  const published = await fixture.publish({ items: [item("story", ["premium"])] });
  const issuer = fixture.issuer();
  const bundle = contentGroupsProfile.client({
    chain: CHAIN,
    createPeriodKeyCache: (options) => new PeriodKeyCache(options),
    createChainKeyCache: (options) => new ChainKeyCache(options),
  });
  const sent = [];
  const client = createDeliveryClient({
    reader: {
      dcaData: published.page,
      publisherOrigin: published.origin,
      extract: (name) => published.sealedContent[name] ?? null,
    },
    issuerName: issuer.name,
    unlockUrl: UNLOCK,
    transport: {
      async post(_url, request) {
        sent.push(structuredClone(request));
        const { status, body } = await issuer.answer(request);
        return { status, contentType: "application/json", body };
      },
    },
    ...bundle.composeOptions,
    requestBuilderFactory: (options) =>
      new ChainKeyRequestBuilder({ innerBuilder: bundle.requestBuilderFactory(options) }),
  });
  await client.unlockRoutes(["story"], [{ issuerName: issuer.name, unlockUrl: UNLOCK }]);
  assert.equal(sent.length, 1);
  assert.ok(sent[0].sealed.contentWindowSeeds.story);
  assert.equal(sent[0].sealed.chainKeys, undefined);
  assert.equal(new TextDecoder().decode((await client.openLocal("story")).bytes), "content:story");
});
