import test from "node:test";
import assert from "node:assert/strict";
import { createDeliveryClient } from "../../integration-client/createDeliveryClient.js";
import { DcaData } from "../../core-client/DcaData.js";
import { ISSUER_NAME, UNLOCK_URL } from "../../demo/scenarios/fixtures.js";
import { world, PUB, BODYTEXT } from "../../test-lib/fixtures/wire-policy-world.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { issuerBlockOf } from "../../test-lib/helpers/inspect.js";

async function setup() {
  const fixture = await world();
  const delivered = await fixture.render();
  const issuer = fixture.endpointWith();
  const reader = {
    dcaData: delivered.dcaData,
    publisherOrigin: PUB,
    extract: (name) => delivered.sealedContent[name] ?? null,
  };
  const transport = {
    async post(_url, request) {
      const answer = await unlockThroughAdmission(
        issuer.processor,
        issuer.endpoint,
        request,
        issuer.publisherRegistration,
      );
      return { ...answer, contentType: "application/json" };
    },
  };
  return { reader, transport };
}

test("publisher emits no endpoint; every carried URL type is ignored and the host route opens content", async () => {
  const fx = await setup();
  assert.equal(Object.hasOwn(issuerBlockOf(fx.reader.dcaData, ISSUER_NAME), "unlockUrl"), false);
  for (const value of [
    undefined,
    null,
    "",
    17,
    [],
    {},
    "javascript:void(0)",
    "https://hostile.example/unlock",
  ]) {
    const reader = { ...fx.reader, dcaData: structuredClone(fx.reader.dcaData) };
    if (value !== undefined) issuerBlockOf(reader.dcaData, ISSUER_NAME).unlockUrl = value;
    const page = new DcaData(reader.dcaData, { publisherOrigin: PUB });
    assert.equal(page.hasIssuer(ISSUER_NAME), true);
    const urls = [];
    const client = createDeliveryClient({
      reader,
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      transport: {
        async post(url, request) {
          urls.push(url);
          return fx.transport.post(url, request);
        },
      },
    });
    assert.equal((await client.open(BODYTEXT.name)).contentName, BODYTEXT.name);
    assert.deepEqual(urls, [UNLOCK_URL]);
  }
});

test("wire endpoint cannot supply a missing host route; configured issuer with no material sends nothing", async () => {
  const fx = await setup();
  issuerBlockOf(fx.reader.dcaData, ISSUER_NAME).unlockUrl = "https://hostile.example/unlock";
  const posts = [];
  const transport = {
    async post(url, request) {
      posts.push(url);
      return fx.transport.post(url, request);
    },
  };
  const missing = createDeliveryClient({ reader: fx.reader, issuerName: ISSUER_NAME, transport });
  await assert.rejects(missing.open(BODYTEXT.name), { code: "bad_config" });
  const absent = createDeliveryClient({
    reader: fx.reader,
    issuerName: "absent_issuer",
    unlockUrl: UNLOCK_URL,
    transport,
  });
  await assert.rejects(absent.open(BODYTEXT.name), { code: "unknown_issuer" });
  assert.deepEqual(posts, []);
});

test("retained period capability opens with no endpoint while another client rotates endpoints without changing the delivery", async () => {
  const fx = await setup();
  const before = JSON.stringify(fx.reader.dcaData);
  const urls = [];
  const transport = {
    async post(url, request) {
      urls.push(url);
      return fx.transport.post(url, request);
    },
  };
  const first = createDeliveryClient({
    reader: fx.reader,
    issuerName: ISSUER_NAME,
    unlockUrl: UNLOCK_URL,
    transport,
    relayPeriodKeys: true,
    persistRawPeriodKeys: true,
  });
  await first.open(BODYTEXT.name);
  const local = createDeliveryClient({
    reader: fx.reader,
    issuerName: ISSUER_NAME,
    transport,
    cache: first.cache,
  });
  await local.open(BODYTEXT.name);
  assert.deepEqual(urls, [UNLOCK_URL]);
  const rotated = createDeliveryClient({
    reader: fx.reader,
    issuerName: ISSUER_NAME,
    unlockUrl: "https://new-endpoint.example/unlock",
    transport,
  });
  await rotated.open(BODYTEXT.name);
  assert.deepEqual(urls, [UNLOCK_URL, "https://new-endpoint.example/unlock"]);
  assert.equal(JSON.stringify(fx.reader.dcaData), before);
});

test("pending acquisition keeps captured endpoint, delivery, transport and host context", async () => {
  const fx = await setup();
  let release;
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  const seen = [];
  const transport = {
    async post(url, request, context) {
      seen.push({ url, context, request });
      await pending;
      return fx.transport.post(url, request);
    },
  };
  const config = {
    reader: fx.reader,
    issuerName: ISSUER_NAME,
    unlockUrl: UNLOCK_URL,
    transport,
    cacheNamespace: "publisher-account-a",
  };
  const client = createDeliveryClient(config);
  const opening = client.open(BODYTEXT.name);
  while (seen.length === 0) await new Promise((resolve) => setImmediate(resolve));
  config.unlockUrl = "https://replacement.example/unlock";
  fx.reader.publisherOrigin = "https://other-publisher.example";
  issuerBlockOf(fx.reader.dcaData, ISSUER_NAME).unlockUrl = "https://hostile.example/unlock";
  transport.post = async () => {
    throw new Error("replacement transport must not own pending response");
  };
  release();
  await opening;
  assert.equal(seen[0].url, UNLOCK_URL);
  assert.deepEqual(seen[0].context, { origin: PUB });
  assert.equal(client.dcaData.publisherOrigin, PUB);
});

test("the same issuer alias in separate trusted host contexts uses only each context's transport and retained keys", async () => {
  const fx = await setup();
  const seen = [];
  const make = (account) =>
    createDeliveryClient({
      reader: fx.reader,
      issuerName: ISSUER_NAME,
      unlockUrl: `https://${account}.issuer.example/unlock`,
      cacheNamespace: account,
      relayPeriodKeys: true,
      persistRawPeriodKeys: true,
      transport: {
        async post(url, request, context) {
          seen.push({ account, url, origin: context.origin });
          return fx.transport.post(url, request);
        },
      },
    });
  const first = make("account-a");
  const second = make("account-b");
  await first.open(BODYTEXT.name);
  await assert.rejects(second.openLocal(BODYTEXT.name), { code: "no_key" });
  await second.open(BODYTEXT.name);
  assert.deepEqual(seen, [
    { account: "account-a", url: "https://account-a.issuer.example/unlock", origin: PUB },
    { account: "account-b", url: "https://account-b.issuer.example/unlock", origin: PUB },
  ]);
});
