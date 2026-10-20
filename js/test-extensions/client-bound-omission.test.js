// @ts-check
//
// Neutral composition proof for two removable extensions: client-bound
// transport supplies the opaque period-key handle, while omission supplies
// the one bound-entry interpretation. Neither extension imports its sibling.

import test from "node:test";
import assert from "node:assert/strict";

import { createDeliveryClient } from "../integration-client/createDeliveryClient.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { KeyDelivery } from "../adapter-issuer/KeyDelivery.js";
import { OmissionRequestBuilder } from "../extensions/content-key-seal-omission/core-client/OmissionRequestBuilder.js";
import { omissionIssuerEngine } from "../extensions/content-key-seal-omission/core-issuer/omissionIssuerEngine.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { DcaData } from "../core-client/DcaData.js";
import { openContent } from "../core-client/openContent.js";
import { contentAadOctets } from "../test-reference/support/contentAadOctets.js";
import { utf8Decode } from "../core-shared/codec.js";
import { Random } from "../demo/actors/Random.js";
import * as ecdhProfile from "../extensions/client-bound-transport/ecdhP256.js";
import { clientBoundKeyCapability } from "../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";
import { OmittingSealer } from "../extensions/content-key-seal-omission/core-publisher/OmittingSealer.js";
import { omissionContentKeyResolverFactory } from "../extensions/content-key-seal-omission/core-client/BoundContentKeyResolver.js";
import { EXTENSION_NAME } from "../extensions/content-key-seal-omission/core-shared/omissionBind.js";
import {
  ARTICLE,
  ISSUER_A,
  PUB,
  render,
  world,
} from "../extensions/content-key-seal-omission/test-lib/world.js";

const { subtle } = globalThis.crypto;

test("an omission-bound wrap opens through a client-bound period-key handle without exporting either handle", async () => {
  const { issuerConfig, periodKeySupply, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
    { items: ["bodytext"] },
  );
  const entry = page.contentData.bodytext.keys.premium[0];
  const periodBytes = await periodKeySupply.derive("premium", entry.t);

  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
  );
  const capability = clientBoundKeyCapability(
    {
      privateKey: pair.privateKey,
      publicKey: await subtle.exportKey("jwk", pair.publicKey),
    },
    ecdhProfile,
  );
  const transport = await ecdhProfile.seal(capability.publicKey, {
    random: new Random({ seed: 404 }),
  });
  const delivered = await transport.wrap(periodBytes, "periodKey");
  const opener = await capability.openDeliveredKeys({
    ...transport.transport,
    method: ecdhProfile.METHOD,
  });
  const periodHandle = await opener.open(delivered, ["unwrapKey"], "periodKey");
  assert.ok(periodHandle instanceof globalThis.CryptoKey);
  assert.equal(periodHandle.extractable, false);
  assert.deepEqual([...periodHandle.usages], ["unwrapKey"]);

  const cache = new PeriodKeyCache();
  await cache.put("premium", entry.t, periodHandle, { publisher: PUB });
  const resolver = omissionContentKeyResolverFactory({
    cache,
    clientBoundKeyCapability: capability,
  });
  const dcaData = new DcaData(page, { publisherOrigin: PUB });

  const originalExport = subtle.exportKey;
  let exportCalls = 0;
  subtle.exportKey = function (...args) {
    exportCalls++;
    return originalExport.apply(subtle, args);
  };
  /** @type {CryptoKey|null} */
  let contentHandle = null;
  try {
    const resolved = await resolver.contentKeyWithOriginFor(dcaData, "bodytext");
    contentHandle = /** @type {CryptoKey} */ (resolved.key);
    assert.deepEqual(resolved.origin, {
      kind: "cached-period-key",
      accessGroup: "premium",
      t: entry.t,
    });
    assert.ok(
      contentHandle instanceof globalThis.CryptoKey,
      "the bound attempt preserves the handle chain",
    );
    assert.equal(contentHandle.extractable, false);
    assert.deepEqual([...contentHandle.usages], ["decrypt"]);

    assert.equal(
      utf8Decode(
        await openContent(
          contentHandle,
          "bodytext",
          page.sealedContent.bodytext,
          contentAadOctets(page, "bodytext"),
        ),
      ),
      ARTICLE,
    );
  } finally {
    subtle.exportKey = originalExport;
  }

  assert.equal(exportCalls, 0, "the successful resolve and decrypt path exports neither handle");
  await assert.rejects(() => subtle.exportKey("raw", periodHandle));
  await assert.rejects(() => subtle.exportKey("raw", /** @type {CryptoKey} */ (contentHandle)));
});

test("a real omission issuer delivers an associated client-bound period handle that opens the bound item", async () => {
  const { issuerConfig, registration, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
    { items: ["bodytext"] },
  );
  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
  );
  const capability = clientBoundKeyCapability(
    {
      privateKey: pair.privateKey,
      publicKey: await subtle.exportKey("jwk", pair.publicKey),
    },
    ecdhProfile,
  );
  let policies = 0;
  let openingLookups = 0;
  const countedRegistration = {
    ...registration,
    openingKeys: {
      get(...args) {
        openingLookups++;
        return registration.openingKeys.get(...args);
      },
    },
  };
  const processor = new IssuerProcessor(
    omissionIssuerEngine({
      operatingIssuerNames: [ISSUER_A],
      accessPolicy: {
        decide(claims, requested) {
          policies++;
          assert.equal(claims.resource.resourceId, "123456");
          return {
            contentNames: [],
            periodGrants: requested.accessGroups.map((accessGroup) => ({
              accessGroup,
              periods: requested.periodCoordinates[accessGroup],
            })),
          };
        },
      },
    }),
    { periodKeyInput: true },
  );
  const endpoint = new UnlockEndpoint(processor);
  const delivery = new KeyDelivery({ profile: ecdhProfile, random: new Random({ seed: 405 }) });
  const cache = new PeriodKeyCache();
  const { sealedContent, ...metadata } = page;
  const responses = [];
  const requests = [];
  const client = createDeliveryClient({
    reader: { dcaData: metadata, publisherOrigin: PUB, extract: (name) => sealedContent[name] },
    issuerName: ISSUER_A,
    unlockUrl: "https://issuer.example/unlock",
    relayPeriodKeys: true,
    clientBoundKeyCapability: capability,
    requestBuilderFactory: (options) => new OmissionRequestBuilder(options),
    resolverFactory: omissionContentKeyResolverFactory,
    cache,
    transport: {
      async post(_url, request) {
        const raw = JSON.stringify(request);
        requests.push(JSON.parse(raw));
        const admission = processor.admit(raw);
        assert.equal(admission.code, undefined);
        assert.ok(admission.request);
        const view = await delivery.preflight("client-bound", admission.request);
        const { response } = await endpoint.handleRequest({
          request: admission.request,
          registration: countedRegistration,
        });
        assert.equal(response.status, 200);
        const body = JSON.parse(JSON.stringify(await delivery.prepare(response.body, view)));
        responses.push(body);
        return { status: response.status, body, contentType: "application/json" };
      },
    },
  });
  const originalUnwrap = subtle.unwrapKey;
  const observedBindings = [];
  subtle.unwrapKey = function (format, wrapped, key, algorithm, ...args) {
    const aad = algorithm.additionalData;
    if (aad)
      observedBindings.push(
        utf8Decode(new Uint8Array(aad.buffer ?? aad, aad.byteOffset ?? 0, aad.byteLength)),
      );
    return originalUnwrap.call(subtle, format, wrapped, key, algorithm, ...args);
  };
  const originalExport = subtle.exportKey;
  let rawExports = 0;
  subtle.exportKey = function (format, ...args) {
    if (format === "raw") rawExports++;
    return originalExport.call(subtle, format, ...args);
  };
  try {
    const result = await client.unlock(["bodytext"]);
    assert.equal(result.status, 200);
    assert.equal(utf8Decode((await client.openLocal("bodytext")).bytes), ARTICLE);
  } finally {
    subtle.exportKey = originalExport;
    subtle.unwrapKey = originalUnwrap;
  }
  assert.equal(policies, 1);
  assert.ok(openingLookups > 0, "the registered opening-key store was consulted");
  assert.equal(rawExports, 0);
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0].clientPublicKey, capability.publicKey);
  assert.ok(
    requests[0].boundCandidates.bodytext,
    "the omission request presents its bound coordinate",
  );
  assert.deepEqual(responses[0].keys.contentKeys, {});
  assert.equal(responses[0].transport.method, ecdhProfile.METHOD);
  const entry = page.contentData.bodytext.keys.premium[0];
  const [handle] = await cache.candidatesAt("premium", entry.t, {
    publisher: PUB,
    issuerName: ISSUER_A,
  });
  const expectedBind = [
    "dca-bind-seal-omission",
    page.resource.renderId,
    "bodytext",
    "premium",
    entry.t,
  ].join("|");
  assert.ok(
    observedBindings.includes(expectedBind),
    "the opaque content-key unwrap uses its full omission coordinate",
  );
  const opener = await capability.openDeliveredKeys(responses[0].transport);
  await assert.rejects(
    () => opener.open(responses[0].keys.periodKeys.premium[entry.t], ["decrypt"], "contentKey"),
    "the delivered period key cannot be opened under the item-key context",
  );
  assert.ok(handle instanceof globalThis.CryptoKey);
  assert.equal(handle.extractable, false);
  assert.deepEqual([...handle.usages], ["unwrapKey"]);
  await assert.rejects(() => subtle.exportKey("raw", handle));
});
