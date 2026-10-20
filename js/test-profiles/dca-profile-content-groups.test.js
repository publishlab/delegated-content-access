// @ts-check
//
// The selected content-groups composition against independent vectors.
// Requested: dca-profile-content-groups. Resolved: dca-profile-baseline and
// dca-profile-content-groups; the stock chain-key derivation is composed as the
// trusted chain port, not selected as dca-profile-chain-keys.
//
// js/extensions/content-groups/test/_lib/generate-production-vectors.mjs wrote
// the fixture from node:crypto and the specifications, with no code from the
// implementation. Production code here consumes those bytes and must answer
// them: the issuer opens the fixed seed envelopes and answers the fixed request
// with the fixed response, the composed client builds the fixed request from the
// fixed publication and opens every item from the fixed response.
//
// The fixed response carries one key of each kind: a chain key for `bodytext`,
// a period key for `headline` and an item content key for `shoppingAd`, so each
// item opens only through the kind of key its policy grant returned. Issuer
// bounds, refusals and cache rules stay with the extension's focused tests.
// The tests carry no claim tags: the claim index names no content-groups duty yet.

import test from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { URL } from "node:url";

import { contentGroupsProfile } from "../extensions/content-groups/referenceProfile.js";
import {
  contentNameSeed,
  contentNameSeedAad,
  publisherNamespace,
} from "../extensions/content-groups/core-shared/construction.js";
import { openSeed } from "../extensions/content-groups/core-shared/seed-envelope.js";
import {
  chainKeyCoordinate,
  chainKeyFromChainKey,
  chainKeyLabelAt,
  periodKeyFromChainKey,
  settleChainGeometry,
} from "../extensions/chain-keys/core-shared/chainKeyConstruction.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { JsonDeliveryReader } from "../adapter-client/JsonDeliveryReader.js";
import { writeJsonDelivery } from "../adapter-publisher/writeJsonDelivery.js";
import { DcaData } from "../core-client/DcaData.js";
import { createIssuerCore } from "../integration-issuer/createIssuerCore.js";
import { createDeliveryClient } from "../integration-client/createDeliveryClient.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";
import { utf8Decode } from "../core-shared/codec.js";

const VECTORS = JSON.parse(
  readFileSync(
    new URL("../extensions/content-groups/test/fixtures/production.vectors.json", import.meta.url),
    "utf8",
  ),
);
const { inputs, expected } = VECTORS;
const subtle = globalThis.crypto.subtle;
const UNLOCK = "https://issuer.example/unlock";
const NAMES = Object.keys(inputs.items);

// The stock chain-key construction as the host's trusted chain port.
const CHAIN = Object.freeze({
  coordinate: chainKeyCoordinate,
  labelAt: chainKeyLabelAt,
  settleGeometry: settleChainGeometry,
  familyGeneration: periodFamilyGeneration,
  fromChain: chainKeyFromChainKey,
  periodFromChain: periodKeyFromChainKey,
});

const issuerPrivateKey = () =>
  subtle.importKey(
    "jwk",
    expected.issuer.privateJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );

/** A fresh copy of a JSON value from the fixture. */
const copy = (/** @type {any} */ value) => JSON.parse(JSON.stringify(value));

const hex = (/** @type {Uint8Array} */ bytes) => Buffer.from(bytes).toString("hex");

/** The real base issuer with the content-groups contribution over the stock chain port. */
async function issuer(/** @type {any[]} */ grants) {
  const publicKey = await subtle.importKey(
    "jwk",
    expected.publisher.publicJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const privateKey = await issuerPrivateKey();
  const registration = {
    kid: inputs.publisherKid,
    publicKey,
    openingKeys: {
      get: (/** @type {string} */ name) =>
        name === inputs.issuerName ? { algorithm: "ecdh-p256", privateKey } : undefined,
    },
  };
  /** @type {any[]} */
  const decisions = [];
  const { processor, endpoint } = createIssuerCore(
    {
      operatingIssuerNames: [inputs.issuerName],
      accessPolicy: {
        decide: (/** @type {any} */ _c, /** @type {any} */ r) => ({ contentNames: r.contentNames }),
      },
    },
    contentGroupsProfile.issuerContribution({
      chain: CHAIN,
      policy: {
        decide(/** @type {any} */ input) {
          decisions.push(copy({ contentGroups: input.contentGroups, items: input.items }));
          return { grants, authorizePeriod: () => true };
        },
      },
    }),
  );
  /** @param {object} request */
  const answer = (request) =>
    unlockThroughAdmission(
      processor,
      endpoint,
      JSON.stringify(request),
      /** @type {any} */ (registration),
    );
  return { answer, decisions };
}

/** The content-groups client bundle over the two real caches. */
function clientBundle() {
  return contentGroupsProfile.client({
    chain: CHAIN,
    narrowing: copy(inputs.narrowing),
    createPeriodKeyCache: (config) => new PeriodKeyCache(config),
    createChainKeyCache: (config) => new ChainKeyCache(/** @type {any} */ (config)),
  });
}

test("production opens each fixed seed envelope to the seed the vectors derive", async () => {
  assert.equal(await publisherNamespace(inputs.origin), expected.publisherNamespace);
  const privateKey = await issuerPrivateKey();
  const secret = Buffer.from(inputs.retainedSecretHex, "hex");
  for (const [contentName, envelope] of Object.entries(expected.seedEnvelopes)) {
    const binding = {
      publisher: inputs.origin,
      renderId: inputs.renderId,
      issuerName: inputs.issuerName,
      contentName,
      windowStartLabel: inputs.windowStart,
      periodGeometry: inputs.periodGeometry,
    };
    const aad = await contentNameSeedAad(binding, CHAIN);
    assert.equal(hex(aad), envelope.aadHex, `${contentName} AAD`);
    assert.equal(Buffer.from(envelope.sealed, "base64url").length, 125);
    const seed = await openSeed(envelope.sealed, privateKey, aad);
    assert.equal(hex(seed), envelope.seedHex, `${contentName} opened seed`);
    const derived = await contentNameSeed(
      Uint8Array.from(secret),
      inputs.origin,
      inputs.periodGeometry,
      contentName,
      inputs.windowStart,
      CHAIN,
    );
    assert.equal(hex(derived), envelope.seedHex, `${contentName} derived seed`);
  }
});

test("the composed request builder builds the fixed request from the fixed publication", () => {
  const builder = clientBundle().composeOptions.requestBuilderFactory({});
  const page = new DcaData(copy(expected.publication.dcaData), {
    publisherOrigin: inputs.origin,
  });
  const request = builder.build(page, inputs.issuerName, NAMES);
  assert.deepEqual(JSON.parse(JSON.stringify(request.toObject())), expected.request);
});

test("the composed issuer answers the fixed request with the fixed direct response, byte for byte", async () => {
  const { answer, decisions } = await issuer(inputs.grants);
  const { status, body } = await answer(expected.request);
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(JSON.stringify(body), JSON.stringify(expected.response));
  assert.deepEqual(decisions, [
    {
      contentGroups: Object.fromEntries(
        Object.entries(inputs.narrowing.requestedContentGroups).map(([name, groups]) => [
          name,
          { groups, windows: [inputs.windowStart] },
        ]),
      ),
      items: Object.keys(inputs.narrowing.requestedContentKeys),
    },
  ]);
});

test("a policy that grants nothing releases no key for the fixed request", async () => {
  const { answer, decisions } = await issuer([]);
  const { status, body } = await answer(expected.request);
  assert.equal(decisions.length, 1, "the policy was asked");
  // With no content-group grant and no ordinary item key, the base endpoint
  // has delivered nothing and answers its denial.
  assert.equal(status, 401);
  assert.deepEqual(body, { error: "denied" });
});

test("the composed delivery client sends the fixed request and opens every item from the fixed response", async () => {
  /** @type {any[]} */
  const sent = [];
  const transport = {
    /** @param {string} url @param {object} request */
    async post(url, request) {
      assert.equal(url, UNLOCK);
      sent.push(JSON.parse(JSON.stringify(request)));
      return {
        status: 200,
        contentType: "application/json",
        body: copy(expected.response),
      };
    },
  };
  const client = createDeliveryClient({
    reader: new JsonDeliveryReader(writeJsonDelivery(copy(expected.publication)), {
      publisherOrigin: inputs.origin,
    }),
    issuerName: inputs.issuerName,
    unlockUrl: UNLOCK,
    transport,
    ...clientBundle().composeOptions,
  });
  const walk = await client.unlockRoutes(NAMES, [
    { issuerName: inputs.issuerName, unlockUrl: UNLOCK },
  ]);
  assert.deepEqual(walk.missing, []);
  assert.deepEqual(sent, [expected.request]);
  for (const [name, { plaintext }] of Object.entries(inputs.items))
    assert.equal(utf8Decode((await client.openLocal(name)).bytes), plaintext, name);
});
