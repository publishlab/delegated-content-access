// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { copyManifestFiles } from "../../../tools/copyManifest.js";
import { allImportEdgesOf, closureOf } from "../../../test-base/sourceGraph.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { JsonDeliveryReader } from "../../../adapter-client/JsonDeliveryReader.js";
import { writeJsonDelivery } from "../../../adapter-publisher/writeJsonDelivery.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { chainKeyIssuerEngine } from "../core-issuer/chainKeyIssuerEngine.js";
import {
  chainKeyClientProfileFor,
  explicitChainKeyClientProfile,
} from "../core-client/chainKeyClientProfile.js";
import * as allRoles from "../referenceProfile.js";
import { chainGeneration, chainSupply, deliveryPlan, periodOnlyPolicy } from "./world.js";
import { ACCESS_GROUP, AT, ISSUER_NAME } from "../../../demo/scenarios/fixtures.js";

const SOURCE = new URL("../../../", import.meta.url);
const CLIENT_ENTRIES = [
  "integration-client/createDeliveryClient.js",
  "adapter-client/JsonDeliveryReader.js",
  "extensions/chain-keys/core-client/chainKeyClientProfile.js",
  "extensions/chain-keys/core-client/ChainKeyRequestBuilder.js",
  "extensions/chain-keys/core-client/ChainKeyCache.js",
];
const baseManifest = JSON.parse(
  readFileSync(new URL("copy-manifest--client.json", SOURCE), "utf8"),
);
const selectedFiles = copyManifestFiles(
  {
    layers: {
      ...baseManifest.layers,
      chainClient: {
        paths: [
          "extensions/chain-keys/core-client/*.js",
          "extensions/chain-keys/core-shared/*.js",
          "extensions/chain-keys/core-shared--client-issuer/*.js",
        ],
      },
    },
  },
  SOURCE,
);

test("the all-role entry preserves the client factory and singleton identities", () => {
  assert.equal(allRoles.chainKeyClientProfileFor, chainKeyClientProfileFor);
  assert.equal(allRoles.explicitChainKeyClientProfile, explicitChainKeyClientProfile);
  assert.equal(Object.isFrozen(explicitChainKeyClientProfile), true);
  assert.equal(Object.isFrozen(chainKeyClientProfileFor()), true);
  assert.throws(() => chainKeyClientProfileFor("dca-construction-chain-keys-invented"), {
    code: "unsupported_option",
  });
});

test("the selected client artifact closes without publisher, issuer or all-role composition", () => {
  const selected = new Set(selectedFiles);
  for (const entry of CLIENT_ENTRIES) {
    for (const reached of closureOf([entry], allImportEdgesOf)) {
      assert.ok(selected.has(reached), `${entry} reaches uncopied ${reached}`);
    }
  }
  for (const path of selected) {
    assert.doesNotMatch(
      path,
      /(?:^|\/)(?:core-publisher|core-issuer|core-shared--publisher-issuer|integration-publisher|integration-issuer)\//,
    );
    assert.notEqual(path, "extensions/chain-keys/referenceProfile.js");
    for (const edge of allImportEdgesOf(path)) {
      assert.ok(
        edge.specifier.startsWith("."),
        `${path} needs an external module ${edge.specifier}`,
      );
      assert.ok(selected.has(edge.target), `${path} reaches uncopied ${edge.target}`);
    }
  }
});

// The publisher and issuer run only in this parent process. The child receives
// serialized delivery/request/answer data and only the selected client source.
async function fixture() {
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
  const rendered = await publisher.publish({
    resourceId: "copied-chain-client",
    data: {},
    items: [
      {
        name: "bodytext",
        value: "Copied client opens chain-backed content",
        contentType: "text/plain",
        accessGroups: [ACCESS_GROUP],
      },
    ],
  });
  const delivery = writeJsonDelivery(rendered);
  const reader = new JsonDeliveryReader(delivery, { publisherOrigin });
  const request = new ChainKeyRequestBuilder({ relayPeriodKeys: true })
    .build(new DcaData(reader.dcaData, { publisherOrigin }), ISSUER_NAME, ["bodytext"])
    .toObject();
  const issuer = createIssuerCore({
    engine: chainKeyIssuerEngine({
      operatingIssuerNames: [ISSUER_NAME],
      accessPolicy: periodOnlyPolicy(2),
      clock,
      representation: "chain-keys",
    }),
    periodKeyInput: true,
  });
  const result = await issuer.endpoint.handleDocument(JSON.stringify(request), {
    kid: "signing",
    publicKey: signing.publicKey,
    openingKeys: {
      get: (issuerName, keyId) =>
        issuerName === ISSUER_NAME && keyId === "opening"
          ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
          : undefined,
    },
  });
  assert.equal(result.response.status, 200);
  assert.ok(Object.keys(result.response.body.keys.chainKeys[ACCESS_GROUP]).length);
  assert.deepEqual(result.response.body.keys.contentKeys ?? {}, {});
  assert.deepEqual(result.response.body.keys.periodKeys ?? {}, {});
  return {
    delivery: [...delivery],
    publisherOrigin,
    issuerName: ISSUER_NAME,
    request,
    response: result.response,
  };
}

const CHILD = `
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createDeliveryClient } from "./integration-client/createDeliveryClient.js";
import { JsonDeliveryReader } from "./adapter-client/JsonDeliveryReader.js";
import { chainKeyClientProfileFor } from "./extensions/chain-keys/core-client/chainKeyClientProfile.js";
import { ChainKeyRequestBuilder } from "./extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { ChainKeyCache } from "./extensions/chain-keys/core-client/ChainKeyCache.js";
const fixture = JSON.parse(readFileSync(0, "utf8"));
const chainCache = new ChainKeyCache({ strategy: "retain" });
let requests = 0;
const client = createDeliveryClient({
  reader: new JsonDeliveryReader(Uint8Array.from(fixture.delivery), { publisherOrigin: fixture.publisherOrigin }),
  issuerName: fixture.issuerName, unlockUrl: "https://issuer.example/unlock", relayPeriodKeys: true,
  chainCache, chainKeyProfile: chainKeyClientProfileFor(),
  requestBuilderFactory: options => new ChainKeyRequestBuilder(options),
  transport: { async post(_url, request) {
    requests++;
    assert.deepEqual(request, fixture.request, "the isolated client sends the real issuer's associated request");
    return { ...fixture.response, contentType: "application/json" };
  } },
});
const opened = await client.open("bodytext");
const local = await client.openLocal("bodytext");
assert.ok(chainCache.entries().length, "actual chain capability was retained");
await client.clearReaderContext();
await assert.rejects(client.openLocal("bodytext"), { code: "no_key" });
assert.deepEqual(chainCache.entries(), []);
process.stdout.write(JSON.stringify({ plaintext: new TextDecoder().decode(opened.bytes), local: new TextDecoder().decode(local.bytes), requests, reset: true }));
`;

test("an actual copied client artifact imports and opens a real chain response", async () => {
  const data = await fixture();
  const scratch = mkdtempSync(join(tmpdir(), "dca-chain-client-copy-"));
  try {
    for (const relative of selectedFiles) {
      const target = join(scratch, relative);
      mkdirSync(dirname(target), { recursive: true });
      cpSync(fileURLToPath(new URL(relative, SOURCE)), target);
    }
    writeFileSync(join(scratch, "package.json"), JSON.stringify({ type: "module" }));
    writeFileSync(join(scratch, "open.mjs"), CHILD);
    const result = spawnSync(process.execPath, [join(scratch, "open.mjs")], {
      cwd: scratch,
      input: JSON.stringify(data),
      encoding: "utf8",
      timeout: 30000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      plaintext: "Copied client opens chain-backed content",
      local: "Copied client opens chain-backed content",
      requests: 1,
      reset: true,
    });
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
