// @ts-check
// Sibling to base suite: js/v1/test/leak-checks.test.js
//
// The client-bound half of the placement leak requirement. The base sibling
// runs the same boundary under direct transport.

import test from "node:test";
import assert from "node:assert/strict";

import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import { deliveredKeys } from "../../../core-shared--client-issuer/responseKeys.js";
import { actorWorld } from "../../../demo/scenarios/world.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  CONTENT_NAME,
  CONTENT_TYPE,
  ISSUER_NAME,
  UNLOCK_URL,
} from "../../../demo/scenarios/fixtures.js";
import { exactPeriodKeySupply } from "../../../demo/support/exactPeriodKeySupply.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { openAndPlace } from "../../../test-lib/harnesses/openAndPlace.js";
import { keyMaterialInPlay, leaks } from "../../../test-lib/helpers/keyMaterialLeaks.js";
import * as clientBoundEcdh from "../ecdhP256.js";
import { clientBoundKeyCapability } from "../core-client/clientBoundKeyCapability.js";

const { subtle } = globalThis.crypto;
const PUBLISHER_ORIGIN = "https://www.news-site.example";
const ITEMS = [
  {
    name: CONTENT_NAME,
    value: ARTICLES.A,
    contentType: CONTENT_TYPE,
    accessGroups: [ACCESS_GROUP],
  },
  {
    name: "factbox",
    value: "Harbour plan: 14 hectares, 2031.",
    contentType: "text/plain",
    accessGroups: [ACCESS_GROUP, "staff"],
  },
];

test("the values a placement adapter is handed carry no key material, under client-bound transport", async () => {
  const stage = await actorWorld({
    periodKeySupply: exactPeriodKeySupply(),
    transportMode: "client-bound",
    clientBoundProfile: clientBoundEcdh,
  });
  const page = await stage.publisher.render({
    resourceId: "123456",
    data: { section: "politics" },
    items: ITEMS,
  });

  const keys = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveKey",
  ]);
  const clientKeys = {
    privateKey: keys.privateKey,
    publicKey: await subtle.exportKey("jwk", keys.publicKey),
  };
  const unsealer = new Client({
    cache: /** @type {any} */ (new PeriodKeyCache({})),
    publisherOrigin: PUBLISHER_ORIGIN,
    clientBoundKeyCapability: clientBoundKeyCapability(clientKeys, clientBoundEcdh),
  });

  const json = page.asJson();
  const dcaData = unsealer.parse(json);
  const names = ITEMS.map((item) => item.name);
  const { missing } = await unsealer.resolve(dcaData, names);
  const request = unsealer.buildRequest(dcaData, ISSUER_NAME, missing);
  const answer = await stage.network.post(UNLOCK_URL, request, {
    from: { who: "a reader" },
    timeout: 2 * 1000,
    origin: PUBLISHER_ORIGIN,
  });
  assert.equal(answer.status, 200, "the honest path has to work before an absence means anything");
  await unsealer.applyResponse(dcaData, ISSUER_NAME, answer.body);

  /** @type {any[][]} */
  const placements = [];
  await openAndPlace({
    page: {
      dcaData,
      extract: (/** @type {string} */ contentName) => unsealer.extract(json, contentName),
    },
    unsealer,
    contentNames: names,
    place: (/** @type {any[]} */ ...args) => {
      placements.push(args);
    },
  });

  // Every key in this body is wrapped, and the client holds a handle
  // afterwards. The seam must not be handed one of those either: unreadable
  // key material still may not be passed to page code.
  assert.equal(answer.body.transport.mode, "client-bound");
  assert.deepEqual(
    placements.map(([contentName, bytes, contentType]) => [
      contentName,
      utf8Decode(bytes),
      contentType,
    ]),
    ITEMS.map((item) => [item.name, item.value, item.contentType]),
  );

  const material = await keyMaterialInPlay(json, stage.periodKeySupply);
  assert.deepEqual(leaks(placements, material), []);
  assert.deepEqual(leaks(dcaData, material), []);

  // The direct body lights the scan up; this one must not. Every key
  // arrived wrapped for this client's keypair.
  const delivered = [...deliveredKeys(answer.body.keys)];
  assert.ok(
    delivered.length > 0,
    "a body with no keys in it would pass the scan for the wrong reason",
  );
  for (const key of delivered) {
    assert.equal(typeof key.key, "string");
    assert.equal(typeof key.nonce, "string");
  }
  assert.deepEqual(leaks(answer.body, material), []);

  // Only plaintext article bytes cross the placement seam.
  for (const [, decryptedData] of placements) {
    assert.ok(decryptedData instanceof Uint8Array);
  }
});
