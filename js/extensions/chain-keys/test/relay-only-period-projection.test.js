// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { createDeliveryClient } from "../../../integration-client/createDeliveryClient.js";
import { JsonDeliveryReader } from "../../../adapter-client/JsonDeliveryReader.js";
import { writeJsonDelivery } from "../../../adapter-publisher/writeJsonDelivery.js";
import { base64urlEncode } from "../../../core-shared/codec.js";
import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { chainKeyIssuerEngine } from "../core-issuer/chainKeyIssuerEngine.js";
import { chainGeneration, chainSupply, deliveryPlan, periodOnlyPolicy } from "./world.js";
import { ACCESS_GROUP, AT, ISSUER_NAME } from "../../../demo/scenarios/fixtures.js";

async function world(chainKeyProfile = undefined) {
  const signing = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const opening = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const publisherOrigin = "https://news.example";
  const clock = { now: () => new Date(AT) };
  const publisher = createPublisher({
    origin: publisherOrigin,
    clock,
    random: { bytes: (size) => crypto.getRandomValues(new Uint8Array(size)) },
    signingKeys: { signing: signing.privateKey },
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: "opening",
        algorithm: "ecdh-p256",
        publicKey: opening.publicKey,
      },
    ],
    periodKeySupply: chainSupply(chainGeneration(9)),
    issuerSupplyPlanFor: deliveryPlan(() => ["chain-keys"]),
  });
  const render = await publisher.publish({
    resourceId: "relay-only",
    data: {},
    items: [
      {
        name: "bodytext",
        value: "Entitled period projection",
        contentType: "text/plain",
        accessGroups: [ACCESS_GROUP],
      },
    ],
  });
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    openingKeys: {
      get: (issuer, id) =>
        issuer === ISSUER_NAME && id === "opening"
          ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
          : undefined,
    },
  };
  const issuer = createIssuerCore({
    engine: chainKeyIssuerEngine({
      operatingIssuerNames: [ISSUER_NAME],
      accessPolicy: periodOnlyPolicy(2),
      clock,
      representation: "period-keys",
    }),
    periodKeyInput: true,
  });
  const exchanges = [];
  const client = createDeliveryClient({
    reader: new JsonDeliveryReader(writeJsonDelivery(render), { publisherOrigin }),
    issuerName: ISSUER_NAME,
    unlockUrl: "https://issuer.example/unlock",
    relayPeriodKeys: true,
    ...(chainKeyProfile === undefined ? {} : { chainKeyProfile }),
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
    transport: {
      async post(_url, request) {
        const result = await issuer.endpoint.handleDocument(JSON.stringify(request), registration);
        assert.equal(result.response.status, 200, "real issuer accepts the relay request");
        assert.ok(
          Object.keys(result.response.body.keys.periodKeys[ACCESS_GROUP]).length,
          "real issuer supplies projected period keys before client admission",
        );
        exchanges.push({ request, response: result.response });
        return {
          status: result.response.status,
          body: JSON.parse(JSON.stringify(result.response.body)),
          contentType: "application/json",
        };
      },
    },
  });
  return { client, exchanges };
}

for (const [name, profile] of [
  ["without a chain profile or cache", undefined],
  ["with the existing chain profile", explicitChainKeyClientProfile],
]) {
  test(`a relay-only client opens chain-only supply through issuer period projection ${name}`, async () => {
    const { client, exchanges } = await world(profile);
    const opened = await client.open("bodytext");
    assert.equal(new TextDecoder().decode(opened.bytes), "Entitled period projection");
    assert.equal(exchanges.length, 1);
    const [{ request, response }] = exchanges;
    assert.ok(Object.keys(request.sealed.chainKeys[ACCESS_GROUP]).length);
    assert.equal(request.sealed.periodKeys, undefined);
    assert.equal(response.status, 200);
    assert.ok(Object.keys(response.body.keys.periodKeys[ACCESS_GROUP]).length);
    assert.equal(response.body.keys.chainKeys, undefined);
    assert.equal(
      new TextDecoder().decode((await client.openLocal("bodytext")).bytes),
      "Entitled period projection",
    );
    await client.clearReaderContext();
    await assert.rejects(client.openLocal("bodytext"), { code: "no_key" });
  });
}

// Admission probes use a frozen, page-associated request and synthetic key
// bytes. They test request reach without asking an issuer to open relabelled
// envelopes; the successful cross-role case above uses untouched envelopes.
function associatedRequest(client, change = () => {}) {
  const request = structuredClone(
    client.builder.build(client.dcaData, ISSUER_NAME, ["bodytext"]).toObject(),
  );
  const envelope = Object.values(request.sealed.chainKeys[ACCESS_GROUP])[0];
  request.periodGeometry = { chainsPerDay: 2, periodMinutes: 15 };
  request.sealed.chainKeys = { [ACCESS_GROUP]: { "251023T1430": envelope } };
  delete request.requestedPeriodKeys;
  change(request);
  return { request, association: new ResponseAssociation(client.dcaData, ISSUER_NAME, request) };
}

const rejectionCases = [
  [
    "an unpresented family",
    "251023T1415",
    (request) => {
      request.sealed.chainKeys = { other: request.sealed.chainKeys[ACCESS_GROUP] };
    },
  ],
  ["a later position than the supplied cutoff", "251023T1445", () => {}],
  ["another stationary window", "251023T0015", () => {}],
  ["an off-grid period", "251023T1416", () => {}],
  ["an invalid calendar coordinate", "251023T2460", () => {}],
  [
    "missing geometry",
    "251023T1415",
    (request) => {
      delete request.periodGeometry;
    },
  ],
  [
    "a partial geometry pair",
    "251023T1415",
    (request) => {
      request.periodGeometry = { chainsPerDay: 2 };
    },
  ],
  [
    "a conflicting family grid",
    "251023T1415",
    (request) => {
      request.periodGeometry.accessGroups = {
        [ACCESS_GROUP]: { chainsPerDay: 2, periodMinutes: 60 },
      };
    },
  ],
  [
    "a malformed chain collection",
    "251023T1415",
    (request) => {
      request.sealed.chainKeys = [];
    },
  ],
  [
    "a malformed source envelope",
    "251023T1415",
    (request) => {
      request.sealed.chainKeys[ACCESS_GROUP]["251023T1430"] = {};
    },
  ],
  [
    "two source members in one window",
    "251023T1415",
    (request) => {
      request.sealed.chainKeys[ACCESS_GROUP]["251023T1445"] = "another";
    },
  ],
];

function periodResponse(t) {
  return {
    keys: { periodKeys: { [ACCESS_GROUP]: { [t]: base64urlEncode(new Uint8Array(16).fill(7)) } } },
  };
}

for (const [name, t, change] of rejectionCases) {
  test(`a relay-only client rejects projected period keys for ${name}`, async () => {
    const { client } = await world();
    const { association } = associatedRequest(client, change);
    const result = await client.resolver.applyResponse(
      client.dcaData,
      ISSUER_NAME,
      periodResponse(t),
      association,
    );
    assert.equal(result.accepted, 0);
    assert.deepEqual(result.issues, [{ section: "periodKeys", code: "unsolicited_coordinate" }]);
    assert.deepEqual(await client.cache.entries(), []);
  });
}

test("relay admission reads the frozen request rather than later caller edits", async () => {
  const { client } = await world();
  const { request, association } = associatedRequest(client);
  request.periodGeometry.periodMinutes = 60;
  request.sealed.chainKeys = {};
  const result = await client.resolver.applyResponse(
    client.dcaData,
    ISSUER_NAME,
    periodResponse("251023T1415"),
    association,
  );
  assert.equal(result.accepted, 1);
  assert.equal((await client.cache.entries()).length, 1);
  const invalid = associatedRequest(client, (request) => {
    request.sealed.chainKeys = {};
  });
  invalid.request.sealed.chainKeys = association.request.sealed.chainKeys;
  const denied = await client.resolver.applyResponse(
    client.dcaData,
    ISSUER_NAME,
    periodResponse("251023T1415"),
    invalid.association,
  );
  assert.equal(denied.accepted, 0, "later repairs cannot enlarge the frozen request's reach");
});

test("a bare resolver still requires explicit opt-in for chain-projected periods", async () => {
  const { client } = await world();
  const { association } = associatedRequest(client);
  const cache = new PeriodKeyCache();
  const bare = new ContentKeyResolver({ cache });
  const result = await bare.applyResponse(
    client.dcaData,
    ISSUER_NAME,
    periodResponse("251023T1415"),
    association,
  );
  assert.equal(result.accepted, 0);
  assert.deepEqual(await cache.entries(), []);
});

test("presented period keys retain their base admission independently of chain geometry", async () => {
  const { client } = await world();
  const t = "251023T1416";
  const { association } = associatedRequest(client, (request) => {
    delete request.periodGeometry;
    request.sealed.periodKeys = { [ACCESS_GROUP]: { [t]: "sealed period member" } };
  });
  const result = await client.resolver.applyResponse(
    client.dcaData,
    ISSUER_NAME,
    periodResponse(t),
    association,
  );
  assert.equal(result.accepted, 1);
});

test("a configured profile validator retains precedence over relay admission", async () => {
  const { client } = await world({ acceptsPeriodKeyResponseCoordinate: () => false });
  const { association } = associatedRequest(client);
  const result = await client.resolver.applyResponse(
    client.dcaData,
    ISSUER_NAME,
    periodResponse("251023T1415"),
    association,
  );
  assert.equal(result.accepted, 0);
  assert.deepEqual(await client.cache.entries(), []);
});

test("the generic resolver collaborator must answer boolean", async () => {
  const { client } = await world();
  const { association } = associatedRequest(client);
  const resolver = new ContentKeyResolver({
    cache: new PeriodKeyCache(),
    periodKeyResponseCoordinate: () => "yes",
  });
  await assert.rejects(
    resolver.applyResponse(client.dcaData, ISSUER_NAME, periodResponse("251023T1415"), association),
    { code: "bad_config" },
  );
  assert.throws(() => new ContentKeyResolver({ periodKeyResponseCoordinate: true }), {
    code: "bad_config",
  });
});
