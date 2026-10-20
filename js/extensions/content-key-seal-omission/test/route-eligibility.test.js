// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { createDeliveryClient } from "../../../integration-client/createDeliveryClient.js";
import { DeniedUnlockCache } from "../../../adapter-client/DeniedUnlockCache.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import {
  OmissionRequestBuilder,
  omissionPresentedContentNames,
} from "../core-client/OmissionRequestBuilder.js";
import { omissionContentKeyResolverFactory } from "../core-client/BoundContentKeyResolver.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import {
  ARTICLE,
  ISSUER_A,
  PERIODS,
  PUB,
  contentOnlyPolicy,
  render,
  world,
} from "../test-lib/world.js";

async function fixture({
  relayPeriodKeys = false,
  acceptDirectResponse = true,
  familyDenial = false,
} = {}) {
  const { issuerConfig, registration, sealerConfig, periodKeySupply } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
  );
  const periodKeyLookup = new WeakMap([
    [registration, (group, t) => periodKeySupply.derive(group, t)],
  ]);
  const endpoint = new UnlockEndpoint(
    new IssuerProcessor(
      omissionIssuerEngine({
        operatingIssuerNames: [ISSUER_A],
        accessPolicy: contentOnlyPolicy(["bodytext"], {
          sourceGrants: [{ accessGroup: "premium", periods: PERIODS }],
        }),
        periodKeyLookup,
      }),
      {
        periodKeyInput: true,
        selectedExtensions: [EXTENSION_NAME],
        extensionCoordinates: {
          [EXTENSION_NAME]: (request) =>
            omissionPresentedContentNames(request.toObject()).length > 0,
        },
      },
    ),
  );
  const posts = [];
  const client = createDeliveryClient({
    reader: {
      dcaData: page,
      publisherOrigin: PUB,
      extract: (name) => page.sealedContent[name] ?? null,
    },
    issuerName: ISSUER_A,
    unlockUrl: "https://issuer.example/unlock",
    relayPeriodKeys,
    acceptDirectResponse,
    persistRawPeriodKeys: relayPeriodKeys,
    denialCache: new DeniedUnlockCache({ now: () => 1000 }),
    requestBuilderFactory: (options) => new OmissionRequestBuilder(options),
    resolverFactory: omissionContentKeyResolverFactory,
    transport: {
      async post(_url, request) {
        posts.push(structuredClone(request));
        if (familyDenial && posts.length === 1)
          return {
            status: 200,
            contentType: "application/json",
            body: { keys: {}, notDelivered: { premium: { reason: "denied" } } },
          };
        const { response } = await endpoint.handleDocument(JSON.stringify(request), registration);
        return { ...response, contentType: "application/json" };
      },
    },
  });
  return { client, posts };
}

test("bound candidates alone request and open an item key using the issuer's entrusted period key", async () => {
  const { client, posts } = await fixture();
  const result = await client.unlock(["bodytext"]);
  assert.equal(result.skipped, undefined);
  assert.equal(posts.length, 1);
  assert.deepEqual(posts[0].sealed, { contentKeys: {} });
  assert.ok(posts[0].boundCandidates.bodytext.length > 0);
  assert.equal(utf8Decode((await client.openLocal("bodytext")).bytes), ARTICLE);
});

test("a strict endpoint rejects a bound-candidate-only request without a client-bound offer", async () => {
  const { client, posts } = await fixture({ acceptDirectResponse: false });
  await assert.rejects(client.unlock(["bodytext"]), { code: "bad_config" });
  assert.equal(posts.length, 0);
});

test("a family denial cannot suppress a missing omission item-key answer", async () => {
  const { client, posts } = await fixture({ relayPeriodKeys: true, familyDenial: true });
  const first = await client.unlock(["bodytext"]);
  assert.deepEqual(first.application.notDelivered, [{ accessGroup: "premium", reason: "denied" }]);
  const second = await client.unlock(["bodytext"]);
  assert.equal(second.skipped, undefined);
  assert.equal(posts.length, 2, "a family report never denies the separate item-key route");
  assert.equal(utf8Decode((await client.openLocal("bodytext")).bytes), ARTICLE);
});
