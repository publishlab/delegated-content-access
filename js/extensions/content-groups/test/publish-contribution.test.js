// The content-groups publisher contribution through the base `createPublisher`
// and its Sealer. Expected connectors and seeds come from the
// extension's construction functions over the test chain port, not from the
// contribution under test.
import { seedHandle } from "../core-shared--publisher-issuer/seedHandle.js";
import test from "node:test";
import assert from "node:assert/strict";
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { decrypt } from "../../../core-shared/aead.js";
import { base64urlDecode } from "../../../core-shared/codec.js";
import { decodePayload } from "../../../core-shared--publisher-issuer/jwt.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";
import { contentGroupsPublisherContribution } from "../core-publisher/publish.js";
import {
  contentNameSeed,
  contentNameSeedAad,
  itemPad,
  xor16,
} from "../core-shared/construction.js";
import { openSeed } from "../core-shared/seed-envelope.js";
import { DERIVING_CHAIN, allZeroed, recordingChain } from "./_lib/derivingChainPort.js";

const subtle = globalThis.crypto.subtle;
const ORIGIN = "https://news.example";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
const SECRET = Uint8Array.from({ length: 32 }, (_, i) => i);
// 14:20 renders at period T1400 in the window that starts at T1200.
const AT = "2026-10-14T14:20:00Z";
const T14 = "261014T1400";
const W12 = "261014T1200";
const W00 = "261015T0000";

async function world(issuerSeedWindows = {}, overrides = {}, chain = DERIVING_CHAIN, limits) {
  const signing = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const issuerA = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const issuerB = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const config = {
    origin: ORIGIN,
    clock: { now: () => new Date(AT) },
    random: {
      bytes: (/** @type {number} */ n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
    },
    signingKeys: { k1: signing.privateKey },
    issuers: [
      { issuerName: "issuerA", keyId: "a1", algorithm: "ecdh-p256", publicKey: issuerA.publicKey },
      { issuerName: "issuerB", keyId: "b1", algorithm: "ecdh-p256", publicKey: issuerB.publicKey },
    ],
    issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) => ({
      contentKeyNames:
        issuer.issuerName === "issuerB"
          ? render.contentNames.filter((/** @type {string} */ name) => name === "purchase")
          : [],
      suppliedAccessGroups: [],
    }),
    ...overrides,
  };
  const contribution = contentGroupsPublisherContribution({
    retainedSecret: SECRET,
    periodGeometry: GEOMETRY,
    issuerSeedWindows,
    chain,
    ...(limits === undefined ? {} : { limits }),
  });
  return {
    publisher: createPublisher(/** @type {any} */ (config), contribution),
    issuerA,
    issuerB,
  };
}

const ITEMS = () => [
  {
    name: "bodytext",
    value: "body",
    contentType: "text/html",
    contentGroups: ["politics", "sports"],
  },
  { name: "headline", value: "head", contentType: "text/plain", contentGroups: ["politics"] },
  { name: "purchase", value: "buy", contentType: "text/plain" },
];

/** @param {string} contentName @param {string} window */
function seedOf(contentName, window) {
  return contentNameSeed(SECRET, ORIGIN, GEOMETRY, contentName, window, DERIVING_CHAIN);
}

/** The content key a connector hides, recomputed from the seed at the render period. */
async function keyBehind(/** @type {string} */ connector, /** @type {any} */ context) {
  const { contentName, group, renderId } = context;
  const handle = seedHandle(await seedOf(contentName, W12), GEOMETRY, W12, DERIVING_CHAIN);
  const pad = await itemPad(await handle.periodKey(group, T14), { renderId, contentName });
  return xor16(base64urlDecode(connector), pad);
}

test("a real page carries connectors and per-issuer seed envelopes", async () => {
  const { publisher, issuerA, issuerB } = await world({
    issuerA: { bodytext: [W12, W00] },
    issuerB: { headline: [W12] },
  });
  const { dcaData, sealedContent } = await publisher.publish({
    resourceId: "story1",
    data: { section: "news" },
    items: ITEMS(),
  });
  const page = /** @type {any} */ (dcaData);
  const claims = decodePayload(page.resourceJWT);
  const renderId = claims.renderId;

  assert.equal(page.renderPeriod, T14);
  assert.deepEqual(page.periodGeometry, GEOMETRY);
  assert.equal(page.contentGroups, undefined);
  assert.deepEqual(Object.keys(page.contentData.bodytext.connectors), ["politics", "sports"]);
  assert.deepEqual(Object.keys(page.contentData.headline.connectors), ["politics"]);
  assert.equal(page.contentData.purchase.connectors, undefined);

  // Every connector hides the key that opens its item's body under the
  // derived content AAD.
  for (const [contentName] of [
    ["bodytext", "text/html"],
    ["headline", "text/plain"],
  ]) {
    const record = page.contentData[contentName];
    const keys = await Promise.all(
      Object.entries(record.connectors).map(([group, connector]) =>
        keyBehind(/** @type {string} */ (connector), { contentName, group, renderId }),
      ),
    );
    for (const key of keys) assert.deepEqual(key, keys[0]);
    const aad = /** @type {Uint8Array} */ (contentAadOctets(page, contentName));
    await decrypt(keys[0], new Uint8Array(12), base64urlDecode(sealedContent[contentName]), aad);
  }
  assert.equal(Object.hasOwn(claims, "contentKeyCommitments"), false);
  assert.deepEqual(claims.data, { section: "news" });

  // issuerA holds two windows of bodytext only; issuerB one window of headline
  // beside its ordinary content key for purchase.
  const sealedA = page.issuerData.issuerA.sealed;
  const sealedB = page.issuerData.issuerB.sealed;
  assert.deepEqual(Object.keys(sealedA), ["contentWindowSeeds"]);
  assert.deepEqual(Object.keys(sealedA.contentWindowSeeds), ["bodytext"]);
  assert.deepEqual(Object.keys(sealedA.contentWindowSeeds.bodytext), [W12, W00]);
  assert.deepEqual(Object.keys(sealedB), ["contentKeys", "contentWindowSeeds"]);
  assert.deepEqual(Object.keys(sealedB.contentKeys), ["purchase"]);
  assert.deepEqual(Object.keys(sealedB.contentWindowSeeds), ["headline"]);
  for (const [issuerName, keys, contentName, window] of /** @type {const} */ ([
    ["issuerA", issuerA, "bodytext", W12],
    ["issuerA", issuerA, "bodytext", W00],
    ["issuerB", issuerB, "headline", W12],
  ])) {
    const aad = await contentNameSeedAad(
      {
        publisher: ORIGIN,
        renderId,
        issuerName,
        contentName,
        windowStartLabel: window,
        periodGeometry: GEOMETRY,
      },
      DERIVING_CHAIN,
    );
    const envelope = page.issuerData[issuerName].sealed.contentWindowSeeds[contentName][window];
    assert.deepEqual(
      await openSeed(envelope, keys.privateKey, aad),
      await seedOf(contentName, window),
    );
  }
});

test("every seed copy a render hands to a handle is zeroed when publish returns", async () => {
  const recorded = recordingChain();
  const { publisher } = await world(
    { issuerA: { bodytext: [W12, W00], headline: [W12] } },
    {},
    recorded.chain,
  );
  await publisher.publish({ resourceId: "story1", data: {}, items: ITEMS() });
  assert.ok(allZeroed(recorded.secrets), "a published render left a seed copy");
});

test("a connector item with no seeded render window and no ordinary route has no route", async () => {
  // issuerA holds only the next window of bodytext, which no reader can use
  // to recover this render's key.
  const { publisher } = await world({ issuerA: { bodytext: [W00] } });
  await assert.rejects(
    publisher.publish({ resourceId: "story1", data: {}, items: [ITEMS()[0]] }),
    /no complete issuer route for protected content "bodytext"/,
  );
  // The same item with an ordinary route publishes; its connectors stay.
  const routed = await world(
    { issuerA: { bodytext: [W00] } },
    {
      issuerSupplyPlanFor: () => ({ contentKeyNames: ["bodytext"], suppliedAccessGroups: [] }),
    },
  );
  const { dcaData } = await routed.publisher.publish({
    resourceId: "story1",
    data: {},
    items: [ITEMS()[0]],
  });
  assert.ok(/** @type {any} */ (dcaData).contentData.bodytext.connectors.politics);
});

test("an issuer's promised connector routes fit maxResponseMembers; its possible choices need not", async () => {
  // Each connector item promises one key from the issuer that holds its render
  // window: a chain of one group in that window, a period key or the item key.
  // bodytext offers two groups in two windows and headline one group, six
  // possible chain choices, yet issuerA's exchange promises two members.
  const items = ITEMS().slice(0, 2);
  const windows = { issuerA: { bodytext: [W12, W00], headline: [W12] } };
  const fits = await world(windows, {}, DERIVING_CHAIN, { maxResponseMembers: 2 });
  await fits.publisher.publish({ resourceId: "story1", data: {}, items });

  let draws = 0;
  const counting = {
    random: {
      bytes: (/** @type {number} */ n) => {
        draws++;
        return globalThis.crypto.getRandomValues(new Uint8Array(n));
      },
    },
  };
  const over = await world(windows, counting, DERIVING_CHAIN, { maxResponseMembers: 1 });
  await assert.rejects(
    over.publisher.publish({ resourceId: "story1", data: {}, items }),
    /issuerA promises 2 content-group response members over maxResponseMembers 1/,
  );
  assert.equal(draws, 0);

  // A next-window seed promises nothing for this render; split across two
  // issuers, each exchange promises one member.
  const split = await world(
    { issuerA: { bodytext: [W12], headline: [W00] }, issuerB: { headline: [W12] } },
    {},
    DERIVING_CHAIN,
    { maxResponseMembers: 1 },
  );
  await split.publisher.publish({ resourceId: "story1", data: {}, items });
});

test("an ordinary-only render, even with an empty group list, carries no content-groups member", async () => {
  const { publisher } = await world({ issuerA: { bodytext: [W12] } });
  const { dcaData } = await publisher.publish({
    resourceId: "story1",
    data: {},
    items: [{ ...ITEMS()[2], contentGroups: [] }],
  });
  const page = /** @type {any} */ (dcaData);
  assert.equal(page.renderPeriod, undefined);
  assert.equal(page.periodGeometry, undefined);
  assert.equal(decodePayload(page.resourceJWT).contentKeyCommitments, undefined);
  assert.deepEqual(Object.keys(page.issuerData), ["issuerB"]);
});

test("the item's group list is copied when the render is handed over", async () => {
  const { publisher } = await world({ issuerA: { bodytext: [W12], headline: [W12] } });
  const items = ITEMS();
  const pending = publisher.publish({ resourceId: "story1", data: {}, items });
  items[0].contentGroups?.push("opinion");
  const { dcaData } = await pending;
  assert.deepEqual(Object.keys(/** @type {any} */ (dcaData).contentData.bodytext.connectors), [
    "politics",
    "sports",
  ]);
});

test("configuration and item input are refused before a render draws anything", async () => {
  const base = { retainedSecret: SECRET, periodGeometry: GEOMETRY, chain: DERIVING_CHAIN };
  for (const [label, options, pattern] of /** @type {[string, any, RegExp][]} */ ([
    ["a short secret", { retainedSecret: new Uint8Array(16) }, /retained secret/],
    ["a partial geometry", { periodGeometry: { periodMinutes: 60 } }, /geometry/],
    [
      "an unaligned window",
      { issuerSeedWindows: { issuerA: { bodytext: ["261014T1300"] } } },
      /aligned/,
    ],
    ["unordered windows", { issuerSeedWindows: { issuerA: { bodytext: [W00, W12] } } }, /ordered/],
    [
      "too many windows",
      { issuerSeedWindows: { issuerA: { bodytext: [W12, W00, "261015T1200"] } } },
      /maxSeedWindows/,
    ],
    [
      "an empty window list",
      { issuerSeedWindows: { issuerA: { bodytext: [] } } },
      /maxSeedWindows/,
    ],
    ["an unknown limit", { limits: { maxScopes: 4 } }, /maxScopes/],
    ["an invalid chain override", { chain: null }, /chain port/],
  ])) {
    assert.throws(
      () => contentGroupsPublisherContribution({ ...base, ...options }),
      pattern,
      label,
    );
  }

  let draws = 0;
  const counting = {
    random: {
      bytes: (/** @type {number} */ n) => {
        draws++;
        return globalThis.crypto.getRandomValues(new Uint8Array(n));
      },
    },
  };
  for (const [label, windows, items, pattern] of /** @type {[string, any, any[], RegExp][]} */ ([
    ["an unconfigured issuer", { issuerC: { bodytext: [W12] } }, [ITEMS()[0]], /issuerC/],
    [
      "an empty group name",
      { issuerA: { bodytext: [W12] } },
      [{ ...ITEMS()[0], contentGroups: [""] }],
      /accessGroup/,
    ],
    [
      "a duplicate group",
      { issuerA: { bodytext: [W12] } },
      [{ ...ITEMS()[0], contentGroups: ["a", "a"] }],
      /unique/,
    ],
    [
      "a group map",
      { issuerA: { bodytext: [W12] } },
      [{ ...ITEMS()[0], contentGroups: { a: 1 } }],
      /list/,
    ],
  ])) {
    const { publisher } = await world(windows, counting);
    await assert.rejects(
      publisher.publish({ resourceId: "story1", data: {}, items }),
      pattern,
      label,
    );
  }
  assert.equal(draws, 0);

  const rsa = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false,
    ["encrypt", "decrypt"],
  );
  const { publisher } = await world(
    { issuerA: { bodytext: [W12] } },
    {
      issuers: [
        { issuerName: "issuerA", keyId: "a1", algorithm: "rsa-oaep", publicKey: rsa.publicKey },
      ],
    },
  );
  await assert.rejects(
    publisher.publish({ resourceId: "story1", data: {}, items: [ITEMS()[0]] }),
    /ecdh-p256/,
  );
});
