import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  CONTRACT,
  DEFAULT_LIMITS,
  checkedContentRecords,
  chainKeyPartition,
  contentNameSeed,
  contentNameSeedAad,
  periodKeyPartition,
  publisherNamespace,
  settleLimits,
} from "../core-shared/construction.js";
import * as constructionModule from "../core-shared/construction.js";
import * as seedEnvelopeModule from "../core-shared/seed-envelope.js";
import * as publishModule from "../core-publisher/publish.js";
import * as unlockModule from "../core-issuer/unlock.js";
import * as requestModule from "../core-shared--client-issuer/request.js";
import * as clientModule from "../core-client/client.js";
import { CHAIN } from "./_lib/chainPort.js";

// Root's production anchors, computed with Python hashlib/hmac without either
// implementation: retained secret 00..1f, origin https://news.example, name
// bodytext, 2 windows/day and 60-minute periods, window 261014T1200, item key a0..af.
const ORIGIN = "https://news.example";
const SECRET = Uint8Array.from({ length: 32 }, (_, i) => i);
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
const WINDOW = "261014T1200";
const NAMESPACE = "2d0a016473ff75fd2afa3cc1dac401896235215a4a61e06d11129ff3442837a7";
const SEED_HEX = "d9b1274900e75c2ddcf90b8015ffc87d4bd60eb8b84298d5ec9d57e26223a8f3";

/** @param {Uint8Array} bytes */
const hex = (bytes) => Buffer.from(bytes).toString("hex");

test("the contract names are the root-pinned production literals in one frozen object", () => {
  assert.ok(Object.isFrozen(CONTRACT));
  assert.equal(CONTRACT.profile, "dca-profile-content-groups");
  assert.equal(CONTRACT.construction, "dca-construction-content-groups");
  assert.equal(CONTRACT.seedSalt, "dca-construction-content-name-seeds");
  assert.equal(CONTRACT.seedInfoLabel, "content-name-window");
  assert.equal(CONTRACT.seedAadLabel, "dca-bind-content-name-seed");
  assert.equal(CONTRACT.envelopeAlgorithm, "ecdh-p256-content-name-seed");
  assert.equal(CONTRACT.itemPadSalt, "dca-construction-content-connectors");
  assert.equal(CONTRACT.itemPadLabel, "item-pad");
  assert.ok(Object.isFrozen(CONTRACT.wire));
  assert.deepEqual(CONTRACT.wire, {
    sealedSeeds: "contentWindowSeeds",
    connectors: "connectors",
    requestedContentGroups: "requestedContentGroups",
    requestedContentKeys: "requestedContentKeys",
    response: "contentGroups",
    chainKeys: "chainKeys",
    periodKeys: "periodKeys",
    contentKeys: "contentKeys",
    errors: "errors",
  });
  assert.ok(Object.isFrozen(CONTRACT.keyKinds));
  assert.deepEqual(CONTRACT.keyKinds, {
    periodKey: "contentGroupPeriodKey",
    chainKey: "contentGroupChainKey",
  });
});

test("the publisher namespace and content-name seed match root's anchors", async () => {
  assert.equal(await publisherNamespace(ORIGIN), NAMESPACE);
  const seed = await contentNameSeed(SECRET, ORIGIN, GEOMETRY, "bodytext", WINDOW, CHAIN);
  assert.equal(hex(seed), SEED_HEX);
});

test("each content name, window, geometry and publisher derives its own seed", async () => {
  const anchor = hex(await contentNameSeed(SECRET, ORIGIN, GEOMETRY, "bodytext", WINDOW, CHAIN));
  const variants = [
    [SECRET, ORIGIN, GEOMETRY, "headline", WINDOW],
    [SECRET, ORIGIN, GEOMETRY, "bodytext", "261015T0000"],
    [SECRET, ORIGIN, { chainsPerDay: 2, periodMinutes: 30 }, "bodytext", WINDOW],
    [SECRET, "https://other.example", GEOMETRY, "bodytext", WINDOW],
    [SECRET.map((b) => b ^ 1), ORIGIN, GEOMETRY, "bodytext", WINDOW],
  ];
  for (const [secret, origin, geometry, name, window] of variants) {
    const seed = await contentNameSeed(
      /** @type {Uint8Array} */ (secret),
      /** @type {string} */ (origin),
      geometry,
      /** @type {string} */ (name),
      /** @type {string} */ (window),
      CHAIN,
    );
    assert.notEqual(hex(seed), anchor);
  }
});

test("seed derivation refuses an unaligned window, a short secret and a bad content name", async () => {
  await assert.rejects(
    contentNameSeed(SECRET, ORIGIN, GEOMETRY, "bodytext", "261014T1300", CHAIN),
    /aligned start/,
  );
  await assert.rejects(
    contentNameSeed(SECRET.subarray(1), ORIGIN, GEOMETRY, "bodytext", WINDOW, CHAIN),
    /32 bytes/,
  );
  await assert.rejects(contentNameSeed(SECRET, ORIGIN, GEOMETRY, "body text", WINDOW, CHAIN));
  await assert.rejects(
    contentNameSeed(SECRET, "https://news.example/", GEOMETRY, "bodytext", WINDOW, CHAIN),
    /canonical/,
  );
});

test("the seed-envelope AAD matches the independent fixture over the content-name label", async () => {
  // Written by _lib/generate-vectors.mjs from node:crypto and literal text only.
  const vector = JSON.parse(
    await readFile(new URL("fixtures/seed-aad.json", import.meta.url), "utf8"),
  );
  const aad = await contentNameSeedAad(vector.binding, CHAIN);
  assert.equal(new TextDecoder().decode(aad), vector.expectedAadUtf8);
  assert.equal(hex(aad), vector.expectedAadHex);
  assert.match(vector.expectedAadUtf8, /^\["dca-bind-content-name-seed","2d0a0164/);
});

test("the seed-envelope AAD separates every bound coordinate", async () => {
  const binding = {
    publisher: ORIGIN,
    renderId: "AAECAwQFBgcICQoLDA0ODw",
    issuerName: "issuer",
    contentName: "bodytext",
    windowStartLabel: WINDOW,
    periodGeometry: GEOMETRY,
  };
  const anchor = hex(await contentNameSeedAad(binding, CHAIN));
  for (const changed of [
    { publisher: "https://other.example" },
    { renderId: "AQECAwQFBgcICQoLDA0ODw" },
    { issuerName: "other" },
    { contentName: "headline" },
    { windowStartLabel: "261015T0000" },
    { periodGeometry: { chainsPerDay: 2, periodMinutes: 30 } },
  ])
    assert.notEqual(hex(await contentNameSeedAad({ ...binding, ...changed }, CHAIN)), anchor);
  await assert.rejects(contentNameSeedAad({ ...binding, renderId: "short" }, CHAIN));
  await assert.rejects(contentNameSeedAad({ ...binding, windowStartLabel: "261014T1300" }, CHAIN));
});

test("settleLimits applies the annex defaults and refuses retired and unknown names", () => {
  assert.deepEqual(DEFAULT_LIMITS, {
    maxItems: 64,
    maxGroups: 1024,
    maxPeriodKeysPerContentGroup: 48,
    maxSeedWindows: 2,
    maxWindowsPerGroup: 2,
    maxResponseMembers: 2048,
    maxCachedWindows: 4096,
    maxRivalsPerWindow: 4,
    maxTrialsPerItem: 4096,
  });
  const limits = settleLimits();
  assert.ok(Object.isFrozen(limits));
  assert.deepEqual(limits, DEFAULT_LIMITS);
  assert.equal(settleLimits({ maxItems: 3 }).maxItems, 3);
  assert.equal(settleLimits({ maxGroups: 1025 }).maxResponseMembers, 2048);
  for (const name of ["maxScopes", "maxPeriodKeysPerGroup", "maxSeeds"])
    assert.throws(() => settleLimits({ [name]: 1 }), /unknown content-groups limit/);
  for (const bad of [0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1, "4"])
    assert.throws(() => settleLimits({ maxGroups: bad }), /positive safe integer/);
  assert.throws(() => settleLimits(/** @type {any} */ ([])), /trusted configuration/);
});

test("content records admit named connector maps and refuse every other carrier", () => {
  const limits = settleLimits();
  const c1 = "AAECAwQFBgcICQoLDA0ODw";
  const c2 = "EBESExQVFhcYGRobHB0eHw";
  const page = {
    contentData: {
      bodytext: { connectors: { politics: c1, sports: c2 } },
      purchase: { keys: {} },
    },
  };
  assert.deepEqual(
    { ...checkedContentRecords(page, limits) },
    {
      bodytext: [
        { group: "politics", connector: c1 },
        { group: "sports", connector: c2 },
      ],
      purchase: [],
    },
  );
  const refused = [
    { contentData: { bodytext: { connectors: {} } } },
    { contentData: { bodytext: { connectors: [c1] } } },
    { contentData: { bodytext: { connectors: { politics: null } } } },
    { contentData: { bodytext: { connectors: { politics: "AAEC" } } } },
    { contentData: { bodytext: { connectors: { "bad group": c1 } } } },
    { contentData: { bodytext: null } },
    { contentData: { "bad name": {} } },
    { contentData: [] },
    { contentGroups: ["politics"], contentData: { bodytext: {} } },
  ];
  for (const bad of refused) assert.throws(() => checkedContentRecords(bad, limits));
  const many = Object.fromEntries(Array.from({ length: 3 }, (_, i) => [`item${i}`, {}]));
  assert.throws(
    () => checkedContentRecords({ contentData: many }, settleLimits({ maxItems: 2 })),
    /contentData/,
  );
  const groups = { connectors: { a: c1, b: c1, c: c1 } };
  assert.throws(
    () => checkedContentRecords({ contentData: { x: groups } }, settleLimits({ maxGroups: 2 })),
    /maxGroups/,
  );
});

test("partitions are structured family identities, never string keys", () => {
  const chain = chainKeyPartition(ORIGIN, GEOMETRY, "bodytext", "politics");
  assert.ok(Object.isFrozen(chain) && Object.isFrozen(chain.parts));
  assert.deepEqual(chain, {
    kind: "contentGroupChainKey",
    parts: ["dca-construction-content-groups", ORIGIN, "2", "60", "bodytext", "politics"],
  });
  const period = periodKeyPartition(ORIGIN, GEOMETRY, "bodytext", "politics");
  assert.deepEqual(period, {
    kind: "contentGroupPeriodKey",
    parts: ["dca-construction-content-groups", ORIGIN, "2", "60", "bodytext", "politics"],
  });
  const variants = [
    chainKeyPartition(ORIGIN, GEOMETRY, "headline", "politics"),
    chainKeyPartition(ORIGIN, GEOMETRY, "bodytext", "sports"),
    chainKeyPartition("https://other.example", GEOMETRY, "bodytext", "politics"),
    chainKeyPartition(ORIGIN, { chainsPerDay: 2, periodMinutes: 30 }, "bodytext", "politics"),
  ];
  for (const other of variants) assert.notDeepEqual(other, chain);
  assert.throws(() => chainKeyPartition(ORIGIN, GEOMETRY, "body text", "politics"));
  assert.throws(() => periodKeyPartition(ORIGIN, GEOMETRY, "bodytext", "bad group"));
  assert.throws(() => periodKeyPartition("https://news.example/", GEOMETRY, "bodytext", "a"));
  assert.throws(() => periodKeyPartition(ORIGIN, { chainsPerDay: 0, periodMinutes: 60 }, "b", "a"));
});

test("no module exports the retired publisher-wide seed form", () => {
  const retired = {
    construction: [
      constructionModule,
      ["SEED_ID", "CONNECTOR_ID", "CONSTRUCTION", "checkedGroups", "windowSeed", "inspectMirrors"],
    ],
    seedEnvelope: [seedEnvelopeModule, ["seedAAD", "sealWindowSeed", "openWindowSeed"]],
    publish: [publishModule, ["publish"]],
    unlock: [unlockModule, ["unlock"]],
    request: [requestModule, ["buildRequest"]],
    client: [clientModule, ["createClient"]],
  };
  for (const [label, [namespace, names]] of Object.entries(retired))
    for (const name of names)
      assert.equal(Object.hasOwn(namespace, name), false, `${label}.${name}`);
});
