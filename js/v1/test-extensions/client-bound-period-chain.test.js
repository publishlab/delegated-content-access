// @ts-check

// Composition coverage for two independently removable extensions. This test
// lives outside either extension so neither package imports its sibling.

import test from "node:test";
import assert from "node:assert/strict";

import { Client } from "../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { PeriodChainCache } from "../extensions/period-chain/core-client/PeriodChainCache.js";
import { referencePeriodChainProfile } from "../extensions/period-chain/referenceProfile.js";
import { actorWorld } from "../demo/scenarios/world.js";
import { base64urlEncode, utf8Decode } from "../core-shared/codec.js";
import * as ecdhProfile from "../extensions/client-bound-transport/ecdhP256.js";
import { clientBoundKeyCapability } from "../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  CONTENT_NAME,
  ISSUER_NAME as PRIMARY,
  UNLOCK_URL as PRIMARY_UNLOCK,
} from "../demo/scenarios/fixtures.js";

const PUBLISHER_ORIGIN = "https://www.news-site.example";

async function clientKeys() {
  const pair = /** @type {CryptoKeyPair} */ (
    await globalThis.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
      "deriveKey",
    ])
  );
  return {
    privateKey: pair.privateKey,
    publicKey: await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey),
  };
}

test("a synthetic chain marker leaves an exact client-bound handle in the ordinary exact cache", async () => {
  const stage = await actorWorld({
    transportMode: "client-bound",
    clientBoundProfile: ecdhProfile,
  });
  const exactCache = new PeriodKeyCache();
  const chainCache = new PeriodChainCache();
  const client = new Client({
    publisherOrigin: PUBLISHER_ORIGIN,
    cache: exactCache,
    chainCache,
    periodChainProfile: referencePeriodChainProfile,
    clientBoundKeyCapability: clientBoundKeyCapability(await clientKeys(), ecdhProfile),
  });

  const markChainEnabled = (page) => {
    const sealed = page.issuerData[PRIMARY].sealed;
    const accessGroup = Object.keys(sealed.periodKeys)[0];
    sealed.periodChainKeys = {
      [accessGroup]: {
        "251023T2345": "<publisher-sealed-root-1>",
        "251024T1145": "<publisher-sealed-root-2>",
      },
    };
    page.periodChain = {
      accessGroups: {
        [accessGroup]: { chainsPerDay: 2, periodMinutes: 15 },
      },
    };
  };

  const pageA = (await stage.render("A")).asJson();
  markChainEnabled(pageA);
  const dataA = client.parse(pageA);
  const request = client.buildRequest(dataA, PRIMARY, [CONTENT_NAME]);
  const answer = await stage.network.post(PRIMARY_UNLOCK, request, { origin: PUBLISHER_ORIGIN });
  assert.equal(answer.status, 200);
  assert.equal(answer.body.transport.mode, "client-bound");
  await client.applyResponse(dataA, PRIMARY, answer.body, request);

  assert.equal(
    (await exactCache.entries()).length,
    2,
    "received exact handles stay in the ordinary exact family",
  );
  assert.deepEqual(
    chainCache.entries(),
    [],
    "no issuer-returned exact handle enters the chain partition",
  );

  const pageB = (await stage.render("B")).asJson();
  markChainEnabled(pageB);
  const dataB = client.parse(pageB);
  const contentKey = await client.contentKeyFor(dataB, CONTENT_NAME);
  assert.ok(contentKey instanceof globalThis.CryptoKey, "the exact handle opens another handle");
  assert.equal(contentKey.extractable, false);
  assert.deepEqual([...contentKey.usages], ["decrypt"]);
  assert.equal(
    utf8Decode(await client.decrypt(dataB, CONTENT_NAME, client.extract(pageB, CONTENT_NAME))),
    ARTICLES.B,
  );
  assert.equal(stage.network.stats()[PRIMARY_UNLOCK].attempts, 1, "B needed no second unlock");
});

test("a chain section beside transport is classified before mixed leaves reject the representation", async () => {
  const stage = await actorWorld({
    transportMode: "client-bound",
    clientBoundProfile: ecdhProfile,
  });
  const exactCache = new PeriodKeyCache();
  const chainCache = new PeriodChainCache();
  const client = new Client({
    publisherOrigin: PUBLISHER_ORIGIN,
    cache: exactCache,
    chainCache,
    periodChainProfile: referencePeriodChainProfile,
    clientBoundKeyCapability: clientBoundKeyCapability(await clientKeys(), ecdhProfile),
  });

  const page = (await stage.render("A")).asJson();
  const data = client.parse(page);
  const request = client.buildRequest(data, PRIMARY, [CONTENT_NAME]);
  const answer = await stage.network.post(PRIMARY_UNLOCK, request, { origin: PUBLISHER_ORIGIN });
  assert.equal(answer.body.transport.mode, "client-bound");
  const wrapped = Object.keys(answer.body.keys.periodKeys[ACCESS_GROUP] ?? {});
  assert.equal(
    wrapped.length > 0,
    true,
    "the composition delivers at least one wrapped exact leaf",
  );

  // One response carrying all three: a chain section the v1 profile never
  // delivers beside `transport`, a valid wrapped leaf of a supported section,
  // and a direct leaf of another supported section.
  const mixed = structuredClone(answer.body);
  mixed.keys.periodChainKeys = {
    [ACCESS_GROUP]: { "251023T2345": base64urlEncode(new Uint8Array(16).fill(3)) },
  };
  mixed.periodChain = { chainsPerDay: 2, periodMinutes: 15 };
  mixed.keys.contentKeys = { [CONTENT_NAME]: base64urlEncode(new Uint8Array(16).fill(5)) };

  const applied = await client.applyResponse(page, PRIMARY, mixed, request);

  assert.deepEqual(
    applied.issues,
    [{ section: "periodChainKeys", code: "unsupported_section" }, { code: "invalid_transport" }],
    "the chain section is classified first, then mixed supported leaves reject the response representation",
  );
  assert.equal(applied.accepted, 0, "response-scope rejection retains no earlier wrapped sibling");
  assert.deepEqual(
    chainCache.entries(),
    [],
    "no chain state is retained beside client-bound transport",
  );
  assert.equal(
    (await client.contentKeyFor(data, CONTENT_NAME)) instanceof Uint8Array,
    false,
    "the direct content leaf is not held",
  );
});
