// The base publisher's generic item-preparation seam, exercised with a fake
// contribution. Base names no content-group member: the contribution supplies
// signed claims, item record members, issuer sealed sections and page members
// before the resource is signed, and declares which items it gives a route.
import test from "node:test";
import assert from "node:assert/strict";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { composePublisherConfig } from "../../../core-publisher/publisherComposition.js";
import { decrypt } from "../../../core-shared/aead.js";
import { base64urlDecode } from "../../../core-shared/codec.js";
import { decodePayload } from "../../../core-shared--publisher-issuer/jwt.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";

const subtle = globalThis.crypto.subtle;
const ORIGIN = "https://news.example";
const AT = "2026-10-14T12:20:00Z";

async function baseConfig(overrides = {}) {
  const signing = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const issuer = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  return {
    origin: ORIGIN,
    clock: { now: () => new Date(AT) },
    random: {
      bytes: (/** @type {number} */ n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
    },
    signingKeys: { k1: signing.privateKey },
    issuers: [
      { issuerName: "issuerA", keyId: "a1", algorithm: "ecdh-p256", publicKey: issuer.publicKey },
      { issuerName: "issuerB", keyId: "b1", algorithm: "ecdh-p256", publicKey: issuer.publicKey },
    ],
    // issuerB is sealed the ordinary content key of "ordinary"; issuerA nothing.
    issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) => ({
      contentKeyNames:
        issuer.issuerName === "issuerB"
          ? render.contentNames.filter((/** @type {string} */ name) => name === "ordinary")
          : [],
      suppliedAccessGroups: [],
    }),
    ...overrides,
  };
}

/** A contribution that routes "routed" and records what it was handed. */
function fakeContribution(seen = /** @type {any[]} */ ([]), extra = {}) {
  return {
    name: "fake",
    itemPreparation: {
      routes(/** @type {any} */ render) {
        seen.push({ phase: "routes", render });
        return render.items.some((/** @type {any} */ item) => item.name === "routed")
          ? ["routed"]
          : [];
      },
      async prepare(/** @type {any} */ context) {
        const kept = Object.fromEntries(
          Object.entries(context.contentKeys).map(([name, key]) => [
            name,
            Uint8Array.from(/** @type {Uint8Array} */ (key)),
          ]),
        );
        // Zero the handed keys: they are copies, so the Sealer's stay intact.
        for (const key of Object.values(context.contentKeys))
          /** @type {Uint8Array} */ (key).fill(0);
        seen.push({ phase: "prepare", context, kept });
        return {
          claims: { fakeCommitments: { routed: "c1" } },
          contentRecords: { routed: { fakeRoutes: { g: "r1" } } },
          issuerSealed: { issuerA: { fakeSeeds: { routed: "s1" } } },
          pageMembers: { fakeRenderPeriod: "261014T1200" },
        };
      },
    },
    ...extra,
  };
}

/** @param {any} config */
function sealer(config) {
  return new Sealer(/** @type {any} */ (config));
}

test("a contribution's preparation adds claims, record members, sealed sections and page members", async () => {
  const seen = /** @type {any[]} */ ([]);
  const { config } = composePublisherConfig(await baseConfig(), fakeContribution(seen));
  const { dcaData, sealedContent } = await sealer(config)
    .resource("story1", { section: "news" })
    .content("routed", "connector only", "text/plain")
    .content("ordinary", "sealed to issuerB", "text/plain")
    .seal();

  const signed = decodePayload(dcaData.resourceJWT);
  assert.deepEqual(signed.fakeCommitments, { routed: "c1" });
  assert.deepEqual(signed.data, { section: "news" });
  assert.deepEqual(Object.keys(signed), [
    "renderId",
    "origin",
    "issuedAt",
    "resourceId",
    "data",
    "fakeCommitments",
  ]);
  assert.deepEqual(/** @type {any} */ (dcaData.contentData).routed.fakeRoutes, { g: "r1" });
  assert.equal(/** @type {any} */ (dcaData.contentData).ordinary.fakeRoutes, undefined);
  assert.deepEqual(/** @type {any} */ (dcaData.issuerData).issuerA, {
    sealed: { fakeSeeds: { routed: "s1" } },
    keyId: "a1",
  });
  assert.deepEqual(Object.keys(/** @type {any} */ (dcaData.issuerData).issuerB.sealed), [
    "contentKeys",
  ]);
  assert.equal(/** @type {any} */ (dcaData).fakeRenderPeriod, "261014T1200");
  assert.deepEqual(Object.keys(dcaData), [
    "version",
    "resource",
    "resourceJWT",
    "fakeRenderPeriod",
    "contentData",
    "issuerData",
  ]);

  // Preparation saw the render's id and the content keys that encrypted the
  // items, before the resource carrying its claims was signed.
  const { context: prepared, kept } = seen.find((entry) => entry.phase === "prepare");
  assert.equal(prepared.renderId, signed.renderId);
  assert.equal(prepared.origin, ORIGIN);
  assert.equal(prepared.resourceId, "story1");
  assert.equal(prepared.now.toISOString(), new Date(AT).toISOString());
  assert.deepEqual(
    prepared.items.map((/** @type {any} */ item) => item.name),
    ["routed", "ordinary"],
  );
  assert.deepEqual(
    prepared.issuers.map((/** @type {any} */ issuer) => [issuer.issuerName, issuer.keyId]),
    [
      ["issuerA", "a1"],
      ["issuerB", "b1"],
    ],
  );
  for (const name of ["routed", "ordinary"]) {
    const aad = /** @type {Uint8Array} */ (contentAadOctets(dcaData, name));
    const plain = await decrypt(
      kept[name],
      new Uint8Array(12),
      base64urlDecode(sealedContent[name]),
      aad,
    );
    assert.ok(plain.length > 0);
  }
  assert.ok(Object.isFrozen(prepared.items));
});

test("an item that only a contribution routes passes the route check; one no route reaches does not", async () => {
  const { config } = composePublisherConfig(await baseConfig(), fakeContribution());
  await sealer(config).resource("story1", {}).content("routed", "x", "text/plain").seal();
  await assert.rejects(
    sealer(config).resource("story1", {}).content("unrouted", "x", "text/plain").seal(),
    /no complete issuer route for protected content "unrouted"/,
  );
});

test("routes are settled before any random byte is drawn", async () => {
  let draws = 0;
  const base = await baseConfig({
    random: {
      bytes: (/** @type {number} */ n) => {
        draws++;
        return globalThis.crypto.getRandomValues(new Uint8Array(n));
      },
    },
  });
  const contribution = fakeContribution();
  contribution.itemPreparation.routes = () => {
    throw new Error("routes refused");
  };
  const { config } = composePublisherConfig(base, contribution);
  await assert.rejects(
    sealer(config).resource("story1", {}).content("routed", "x", "text/plain").seal(),
    /routes refused/,
  );
  assert.equal(draws, 0);
});

for (const [label, result, pattern] of /** @type {[string, any, RegExp][]} */ ([
  ["a base claim", { claims: { data: {} } }, /claim data/],
  ["a base record member", { contentRecords: { routed: { nonce: "x" } } }, /record member nonce/],
  ["a record of an item the render lacks", { contentRecords: { other: { a: 1 } } }, /other/],
  [
    "a base sealed member",
    { issuerSealed: { issuerA: { contentKeys: {} } } },
    /sealed member contentKeys/,
  ],
  ["an issuer the publisher lacks", { issuerSealed: { issuerC: { x: {} } } }, /issuerC/],
  ["a base page member", { pageMembers: { contentData: {} } }, /page member contentData/],
  ["an unknown result member", { other: {} }, /other/],
  ["a non-JSON claim", { claims: { when: new Date() } }, /JSON/],
])) {
  test(`a preparation result naming ${label} is refused`, async () => {
    const contribution = fakeContribution();
    contribution.itemPreparation.prepare = async () => result;
    const { config } = composePublisherConfig(await baseConfig(), contribution);
    await assert.rejects(
      sealer(config).resource("story1", {}).content("routed", "x", "text/plain").seal(),
      pattern,
    );
  });
}

test("two contributions may not add the same member", async () => {
  const one = fakeContribution();
  const two = { ...fakeContribution(), name: "fake2" };
  const { config } = composePublisherConfig(await baseConfig(), one, two);
  await assert.rejects(
    sealer(config).resource("story1", {}).content("routed", "x", "text/plain").seal(),
    /fakeCommitments/,
  );
});

test("composition refuses a malformed item preparation", async () => {
  const base = await baseConfig();
  for (const itemPreparation of [null, {}, { routes() {} }, { prepare() {} }, () => {}]) {
    assert.throws(
      () => composePublisherConfig(base, { name: "bad", itemPreparation }),
      /item preparation/,
    );
  }
});

test("a page geometry member must equal the base period geometry when both are emitted", async () => {
  const contribution = fakeContribution();
  contribution.itemPreparation.prepare = async () => ({
    pageMembers: { periodGeometry: { chainsPerDay: 2, periodMinutes: 60 } },
  });
  const { config } = composePublisherConfig(await baseConfig(), contribution);
  const { dcaData } = await sealer(config)
    .resource("story1", {})
    .content("routed", "x", "text/plain")
    .seal();
  assert.deepEqual(dcaData.periodGeometry, { chainsPerDay: 2, periodMinutes: 60 });
  assert.deepEqual(Object.keys(dcaData).slice(0, 4), [
    "version",
    "resource",
    "resourceJWT",
    "periodGeometry",
  ]);
});

test("a contributed page geometry agrees with the base one by field, not by member order", async () => {
  // Base emits {chainsPerDay, periodMinutes} for a chain family; the
  // contribution writes the same fields in reverse, or different values.
  const base = await baseConfig({
    periodKeySupply: {
      derive: async () => new Uint8Array(16).fill(5),
      familyPlan: () => ({
        periods: ["261014T1215"],
        periodKeyAt: async () => new Uint8Array(16).fill(7),
        chain: {
          geometry: { chainsPerDay: 2, periodMinutes: 15 },
          suppliedTs: ["261014T1215"],
          capabilityAt: async () => new Uint8Array(16).fill(9),
        },
      }),
    },
    issuerSupplyPlanFor: (/** @type {any} */ issuer) =>
      issuer.issuerName === "issuerB"
        ? {
            contentKeyNames: [],
            suppliedAccessGroups: ["premium"],
            periodKeyDelivery: { premium: ["period-keys", "chain-keys"] },
          }
        : { contentKeyNames: [], suppliedAccessGroups: [] },
  });
  for (const [geometry, agrees] of /** @type {[any, boolean][]} */ ([
    [{ periodMinutes: 15, chainsPerDay: 2 }, true],
    [{ chainsPerDay: 2, periodMinutes: 30 }, false],
    [{ chainsPerDay: 4, periodMinutes: 15 }, false],
    [{ periodMinutes: 15 }, false],
  ])) {
    const contribution = fakeContribution();
    contribution.itemPreparation.prepare = async () => ({
      pageMembers: { periodGeometry: geometry },
    });
    const { config } = composePublisherConfig(base, contribution);
    const sealing = sealer(config)
      .resource("story1", {})
      .content("routed", "x", "text/plain")
      .content("premium", "y", "text/plain", { accessGroups: ["premium"] })
      .seal();
    const label = JSON.stringify(geometry);
    if (agrees) {
      const { dcaData } = await sealing;
      assert.deepEqual(dcaData.periodGeometry, { chainsPerDay: 2, periodMinutes: 15 }, label);
    } else await assert.rejects(sealing, /one periodGeometry applies to the page/, label);
  }
});

test("createPublisher admits a declared item option and captures it before any await", async () => {
  const { createPublisher } = await import("../../../integration-publisher/createPublisher.js");
  const seen = /** @type {any[]} */ ([]);
  const contribution = { ...fakeContribution(seen), itemOptionMembers: ["fakeGroups"] };
  const publisher = createPublisher(/** @type {any} */ (await baseConfig()), contribution);
  const item = { name: "routed", value: "x", contentType: "text/plain", fakeGroups: ["g1"] };
  const pending = publisher.publish({ resourceId: "story1", data: {}, items: [item] });
  item.fakeGroups.push("g2");
  await pending;
  const routes = seen.find((entry) => entry.phase === "routes").render;
  const prepared = seen.find((entry) => entry.phase === "prepare").context;
  assert.deepEqual(routes.items[0].options, { fakeGroups: ["g1"] });
  assert.deepEqual(prepared.items[0].options, { fakeGroups: ["g1"] });
  assert.ok(Object.isFrozen(prepared.items[0].options.fakeGroups));

  // An option nobody declared is still refused.
  await assert.rejects(
    publisher.publish({
      resourceId: "story1",
      data: {},
      items: [{ name: "routed", value: "x", contentType: "text/plain", other: 1 }],
    }),
    /has no other/,
  );
  // A host cannot hand the composed members in directly.
  assert.throws(
    () => createPublisher(/** @type {any} */ ({ itemOptionMembers: ["fakeGroups"] })),
    /needs its own|has no itemOptionMembers/,
  );
});

test("composition refuses an item option base reads or two contributions declare", async () => {
  const base = await baseConfig();
  assert.throws(
    () => composePublisherConfig(base, { name: "bad", itemOptionMembers: ["accessGroups"] }),
    /base reads/,
  );
  assert.throws(
    () =>
      composePublisherConfig(
        base,
        { name: "one", itemOptionMembers: ["fakeGroups"] },
        { name: "two", itemOptionMembers: ["fakeGroups"] },
      ),
    /declared by one and by two/,
  );
});
