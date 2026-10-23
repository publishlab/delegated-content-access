// @ts-check
//
// The content-group request rides the base request builder. Its wire members
// follow the production annex: `sealed.contentWindowSeeds`,
// `requestedContentGroups`, `requestedContentKeys`, plus the page's
// `renderPeriod` and `periodGeometry`. `requestedContentItems` and
// `seedWindows` narrow locally and never reach the wire. The shared request
// reader refuses what the builder must never send.

import test from "node:test";
import assert from "node:assert/strict";

import { ContentGroupRequestBuilder } from "../core-client/ContentGroupRequestBuilder.js";
import { readContentGroupRequest } from "../core-shared--client-issuer/request.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { projectEligibleIdentities } from "../../../adapter-client/routeAttempts.js";
import { createDeliveryClient } from "../../../integration-client/createDeliveryClient.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { dcaError } from "../../../core-shared/errors.js";
import { issuerBlock, item } from "./_lib/records.js";

const PUB = "https://news.example";
const ISSUER = "issuer";
const W1 = "261014T1200";
const W2 = "261015T0000";
/** @param {number} n */
const b64 = (n, size = 16) => base64urlEncode(new Uint8Array(size).fill(n));
/** @param {any} value */
const json = (value) => base64urlEncode(utf8Encode(JSON.stringify(value)));
const JWT = `${json({ alg: "ES256", kid: "k1" })}.${json({ origin: PUB, renderId: b64(9) })}.c2ln`;
const C = { bodyPolitics: b64(1), bodySports: b64(2), headPolitics: b64(3) };
const ENV = { body1: b64(11, 113), body2: b64(12, 113), head1: b64(13, 113) };

function page() {
  return {
    version: "1",
    resourceJWT: JWT,
    renderPeriod: "261014T1500",
    periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
    contentData: [
      {
        contentName: "bodytext",
        contentType: "text/plain",
        nonce: b64(0, 12),
        connectors: [
          { group: "politics", connector: C.bodyPolitics },
          { group: "sports", connector: C.bodySports },
        ],
      },
      {
        contentName: "headline",
        contentType: "text/plain",
        nonce: b64(0, 12),
        connectors: [{ group: "politics", connector: C.headPolitics }],
      },
      { contentName: "purchase", contentType: "text/plain", nonce: b64(0, 12) },
    ],
    issuerData: [
      {
        issuerName: ISSUER,
        keyId: "kid",
        sealed: {
          contentKeys: [{ contentName: "purchase", key: b64(20, 109) }],
          contentWindowSeeds: [
            { contentName: "bodytext", windowStart: W1, key: ENV.body1 },
            { contentName: "bodytext", windowStart: W2, key: ENV.body2 },
            { contentName: "headline", windowStart: W1, key: ENV.head1 },
          ],
        },
      },
      {
        issuerName: "other",
        keyId: "kid2",
        sealed: { contentKeys: [{ contentName: "purchase", key: b64(21, 109) }] },
      },
    ],
  };
}

/** The seed records of one page issuer block. @param {any} p @param {string} issuerName */
const seedsOf = (p, issuerName = ISSUER) => issuerBlock(p, issuerName).sealed.contentWindowSeeds;
/** Drop one content name's seed records, or one window of them, from a page issuer block. */
const dropSeeds = (/** @type {any} */ p, /** @type {string} */ name, window = "") => {
  const block = issuerBlock(p, ISSUER);
  block.sealed.contentWindowSeeds = block.sealed.contentWindowSeeds.filter(
    (/** @type {any} */ r) => r.contentName !== name || (window !== "" && r.windowStart !== window),
  );
};
/** The distinct content names a request's seed records carry, sorted. @param {any} request */
const seedNames = (request) =>
  [
    ...new Set(request.sealed.contentWindowSeeds.map((/** @type {any} */ r) => r.contentName)),
  ].sort();
/** A record's fields in a fixed order, so field order inside a record does not count. */
const canonical = (/** @type {any} */ r) =>
  JSON.stringify(
    Object.keys(r)
      .sort()
      .map((name) => [name, r[name]]),
  );
/**
 * Assert two record collections hold the same records; array position means nothing.
 * @param {any[]} actual @param {any[]} expected @param {string} [message]
 */
const sameRecords = (actual, expected, message) =>
  assert.deepEqual(actual.map(canonical).sort(), expected.map(canonical).sort(), message);
/** @param {any} sealed @param {any} expected @param {string} [message] */
const sameSealed = (sealed, expected, message) => {
  assert.deepEqual(Object.keys(sealed).sort(), Object.keys(expected).sort(), message);
  for (const name of Object.keys(expected)) sameRecords(sealed[name], expected[name], message);
};

/** @param {Record<string, unknown>} [narrowing] @param {Record<string, number>} [limits] */
function builder(narrowing, limits) {
  return new ContentGroupRequestBuilder({
    ...(narrowing === undefined ? {} : { narrowing }),
    ...(limits === undefined ? {} : { limits }),
  });
}
/** @param {ContentGroupRequestBuilder} b @param {string[]} needed */
const built = (b, needed, issuer = ISSUER) =>
  /** @type {any} */ (b.build(new DcaData(page()), issuer, needed).toObject());

const ALL = ["bodytext", "headline", "purchase"];

test("by default the request asks every connector group of each needed name with a seed", () => {
  const request = built(builder(), ALL);
  sameSealed(request.sealed, {
    contentKeys: [{ contentName: "purchase", key: b64(20, 109) }],
    contentWindowSeeds: seedsOf(page()),
  });
  sameRecords(request.requestedContentGroups, [
    { contentName: "bodytext", groups: ["politics", "sports"] },
    { contentName: "headline", groups: ["politics"] },
  ]);
  sameRecords(request.requestedContentKeys, [
    { contentName: "bodytext", group: "politics", connector: C.bodyPolitics },
    { contentName: "headline", group: "politics", connector: C.headPolitics },
  ]);
  assert.equal(request.renderPeriod, "261014T1500");
  assert.deepEqual(request.periodGeometry, { chainsPerDay: 2, periodMinutes: 60 });
  assert.equal(Object.hasOwn(request, "requestedContentItems"), false);
  assert.equal(Object.hasOwn(request, "seedWindows"), false);
  assert.ok(readContentGroupRequest(request));
});

test("an item only needed through its ordinary route adds no content-group member", () => {
  const request = built(builder(), ["purchase"]);
  assert.deepEqual(Object.keys(request).sort(), [
    "issuerName",
    "keyId",
    "resourceJWT",
    "sealed",
    "version",
  ]);
  assert.equal(readContentGroupRequest(request), null);
  // An issuer that holds no seed relays only its ordinary envelopes.
  const other = built(builder(), ALL, "other");
  assert.deepEqual(other.sealed, { contentKeys: [{ contentName: "purchase", key: b64(21, 109) }] });
});

test("requestedContentKeys names a group locally; only the builder relays its connector", () => {
  const b = builder({ requestedContentGroups: {}, requestedContentKeys: { bodytext: "sports" } });
  const request = built(b, ALL);
  assert.deepEqual(request.requestedContentKeys, [
    { contentName: "bodytext", group: "sports", connector: C.bodySports },
  ]);
  assert.deepEqual(request.requestedContentGroups, []);
  assert.deepEqual(seedNames(request), ["bodytext"]);
  const read = readContentGroupRequest(request);
  assert.deepEqual(read?.contentKeys, { bodytext: [{ group: "sports", connector: C.bodySports }] });
  // An item-key-only request asks no period or chain keys, so it needs no raw key custody.
  assert.deepEqual(b.keyFamilies(request), { contentKeys: true, familyKeys: false });
});

test("explicit narrowing refuses an empty group list and a group outside the item's map", () => {
  for (const narrowing of [
    { requestedContentGroups: { bodytext: [] } },
    { requestedContentGroups: { bodytext: ["opinions"] } },
    { requestedContentGroups: { headline: ["sports"] } },
    { requestedContentGroups: { bodytext: ["politics", "politics"] } },
    { requestedContentKeys: { headline: "sports" } },
    { seedWindows: [W2], requestedContentGroups: { headline: ["politics"] } },
    { requestedContentGroups: [] },
    { unknownNarrowing: true },
  ])
    assert.throws(
      () => built(builder(narrowing), ALL),
      { code: "bad_config" },
      JSON.stringify(narrowing),
    );
});

test("explicit narrowing skips a name outside the attempt or without a seed here before its connector lookup", () => {
  // The README's own narrowing on a page without shoppingAd: the ordinary
  // purchase route and the default content-group routes still go out.
  const absent = built(builder({ requestedContentKeys: { shoppingAd: "sports" } }), ALL);
  assert.deepEqual(absent.sealed.contentKeys, [{ contentName: "purchase", key: b64(20, 109) }]);
  sameRecords(absent.requestedContentGroups, [
    { contentName: "bodytext", groups: ["politics", "sports"] },
    { contentName: "headline", groups: ["politics"] },
  ]);
  assert.equal(Object.hasOwn(absent, "requestedContentKeys"), false);
  const groups = built(
    builder({ requestedContentGroups: { shoppingAd: ["sports"], headline: ["politics"] } }),
    ALL,
  );
  assert.deepEqual(groups.requestedContentGroups, [
    { contentName: "headline", groups: ["politics"] },
  ]);
  assert.deepEqual(seedNames(groups), ["headline"]);
  // An issuer without a seed for a narrowed name serves the names it holds, also
  // when the attempt still needs the narrowed name: an earlier issuer may have
  // denied it, and the walk offers it here beside its ordinary siblings. The
  // connector lookup belongs to an offered route, so even a group the page
  // does not carry is skipped here.
  for (const narrowing of [
    { requestedContentGroups: { bodytext: ["politics"] } },
    { requestedContentKeys: { bodytext: "sports" } },
    { requestedContentGroups: { bodytext: ["culture"] } },
    { requestedContentKeys: { bodytext: "culture" } },
  ])
    for (const needed of [["purchase"], ["bodytext", "purchase"]]) {
      const other = built(builder(narrowing), needed, "other");
      assert.deepEqual(
        other.sealed,
        { contentKeys: [{ contentName: "purchase", key: b64(21, 109) }] },
        JSON.stringify([narrowing, needed]),
      );
      assert.equal(Object.hasOwn(other, "requestedContentGroups"), false);
      assert.equal(Object.hasOwn(other, "requestedContentKeys"), false);
    }
  // The same holds at an issuer that seeds other names but not the narrowed one.
  const unseeded = page();
  dropSeeds(unseeded, "headline");
  for (const narrowing of [
    { requestedContentGroups: { headline: ["politics"] } },
    { requestedContentKeys: { headline: "politics" } },
  ]) {
    const request = /** @type {any} */ (
      builder(narrowing).build(new DcaData(unseeded), ISSUER, ["headline", "purchase"]).toObject()
    );
    assert.deepEqual(
      request.sealed,
      { contentKeys: [{ contentName: "purchase", key: b64(20, 109) }] },
      JSON.stringify(narrowing),
    );
  }
  // An offered route still refuses a group outside the item's connector map.
  for (const narrowing of [
    { requestedContentKeys: { headline: "sports" } },
    { requestedContentGroups: { headline: ["sports"] } },
  ])
    assert.throws(
      () => built(builder(narrowing), ["headline"]),
      { code: "bad_config" },
      JSON.stringify(narrowing),
    );
  // An ordinary item has no seed at any issuer, so narrowing it selects nothing.
  const ordinary = built(builder({ requestedContentGroups: { purchase: ["politics"] } }), ALL);
  assert.deepEqual(ordinary.sealed, {
    contentKeys: [{ contentName: "purchase", key: b64(20, 109) }],
  });
  const ordinaryKey = built(builder({ requestedContentKeys: { purchase: "politics" } }), ALL);
  assert.deepEqual(ordinaryKey.sealed.contentKeys, [
    { contentName: "purchase", key: b64(20, 109) },
  ]);
  assert.equal(Object.hasOwn(ordinaryKey, "requestedContentKeys"), false);
  // A malformed issuer seed collection is unusable even with explicit
  // narrowing; ordinary routes and another issuer remain independent.
  for (const malformedSeeds of [null, {}, [null], [{ contentName: "bodytext", windowStart: W1 }]]) {
    const malformed = page();
    issuerBlock(malformed, ISSUER).sealed.contentWindowSeeds = malformedSeeds;
    for (const narrowing of [
      { requestedContentGroups: { bodytext: ["politics"] } },
      { requestedContentKeys: { bodytext: "sports" } },
      // Even a connector mismatch is irrelevant when no seed collection admits.
      { requestedContentKeys: { bodytext: "culture" } },
    ]) {
      const b = builder(narrowing);
      const ordinary = /** @type {any} */ (
        b.build(new DcaData(malformed), ISSUER, ["bodytext", "purchase"]).toObject()
      );
      assert.deepEqual(ordinary.sealed, {
        contentKeys: [{ contentName: "purchase", key: b64(20, 109) }],
      });
      assert.equal(Object.hasOwn(ordinary, "requestedContentGroups"), false);
      assert.deepEqual(b.build(new DcaData(malformed), "other", ["purchase"]).toObject().sealed, {
        contentKeys: [{ contentName: "purchase", key: b64(21, 109) }],
      });
    }
  }
  assert.doesNotThrow(() =>
    built(builder({ requestedContentKeys: { headline: "sports" } }), ["bodytext"]),
  );
});

test("a narrowing that selects no content-group route sends no content-group member", () => {
  const request = built(builder({ requestedContentGroups: {} }), ALL);
  assert.equal(Object.hasOwn(request.sealed, "contentWindowSeeds"), false);
  assert.equal(Object.hasOwn(request, "requestedContentGroups"), false);
});

test("maxItems bounds every content-name map of the narrowing and the request", () => {
  assert.throws(
    () =>
      built(
        builder(
          { requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] } },
          {
            maxItems: 1,
          },
        ),
        ALL,
      ),
    { code: "bad_config" },
  );
  assert.throws(
    () =>
      built(
        builder(
          { requestedContentKeys: { bodytext: "sports", headline: "politics" } },
          { maxItems: 1 },
        ),
        ALL,
      ),
    {
      code: "bad_config",
    },
  );
  // The page's own name map over the bound relays no content-group member.
  const request = built(builder(undefined, { maxItems: 1 }), ALL);
  assert.equal(Object.hasOwn(request, "requestedContentGroups"), false);
});

test("local narrowing selects items, windows and cutoffs without new wire members", () => {
  const request = built(
    builder({
      requestedContentItems: ["bodytext"],
      seedWindows: [W1],
      requestedChainCutoffs: { [W1]: "261014T1800" },
    }),
    ALL,
  );
  assert.deepEqual(request.sealed, {
    contentKeys: [],
    contentWindowSeeds: [{ contentName: "bodytext", windowStart: W1, key: ENV.body1 }],
  });
  assert.deepEqual(request.requestedContentGroups, [
    { contentName: "bodytext", groups: ["politics", "sports"] },
  ]);
  assert.deepEqual(request.requestedChainCutoffs, [{ windowStart: W1, cutoff: "261014T1800" }]);
  // Selection only narrows: a needed list without bodytext asks nothing of it.
  const narrowed = built(builder({ requestedContentGroups: { bodytext: ["sports"] } }), [
    "headline",
  ]);
  assert.equal(Object.hasOwn(narrowed, "requestedContentGroups"), false);
});

test("the shared reader refuses requests the builder never sends", () => {
  const good = built(builder({ requestedContentKeys: { headline: "politics" } }), [
    "bodytext",
    "headline",
  ]);
  assert.ok(readContentGroupRequest(good));
  /** @param {(r: any) => void} mutate */
  const variant = (mutate) => {
    const copy = structuredClone(good);
    mutate(copy);
    return copy;
  };
  /** @param {any} r @param {string} name */
  const groupsOf = (r, name) =>
    r.requestedContentGroups.find((/** @type {any} */ g) => g.contentName === name);
  /** @param {any} r @param {string} name */
  const keyOf = (r, name) =>
    r.requestedContentKeys.find((/** @type {any} */ k) => k.contentName === name);
  /** @param {any} r @param {string} name */
  const withoutSeeds = (r, name) =>
    (r.sealed.contentWindowSeeds = r.sealed.contentWindowSeeds.filter(
      (/** @type {any} */ seed) => seed.contentName !== name,
    ));
  const refused = [
    (/** @type {any} */ r) => (groupsOf(r, "bodytext").groups = []),
    (/** @type {any} */ r) => (groupsOf(r, "bodytext").groups = ["politics", "politics"]),
    (/** @type {any} */ r) => (groupsOf(r, "bodytext").groups = "politics"),
    (/** @type {any} */ r) => {
      r.requestedContentGroups = [];
      delete r.requestedContentKeys;
    },
    (/** @type {any} */ r) => withoutSeeds(r, "bodytext"),
    (/** @type {any} */ r) =>
      r.sealed.contentWindowSeeds.push({ contentName: "extra", windowStart: W1, key: ENV.head1 }),
    // A bodytext seed that names no window: records cannot hold an empty window map.
    (/** @type {any} */ r) => {
      withoutSeeds(r, "bodytext");
      r.sealed.contentWindowSeeds.push({
        contentName: "bodytext",
        windowStart: "",
        key: ENV.body1,
      });
    },
    (/** @type {any} */ r) => (keyOf(r, "headline").extra = 1),
    (/** @type {any} */ r) => (keyOf(r, "headline").connector = b64(1, 15)),
    (/** @type {any} */ r) =>
      (r.requestedContentKeys = r.requestedContentKeys.map((/** @type {any} */ k) =>
        k.contentName === "headline" ? "politics" : k,
      )),
    (/** @type {any} */ r) => delete r.renderPeriod,
    (/** @type {any} */ r) => (r.periodGeometry = [2, 60]),
    (/** @type {any} */ r) => (r.requestedChainCutoffs = ["261014T1800"]),
  ];
  for (const [index, mutate] of refused.entries())
    assert.throws(
      () => readContentGroupRequest(variant(mutate)),
      { code: "binding_failed" },
      String(index),
    );
  assert.throws(
    () =>
      readContentGroupRequest(
        variant((r) => {
          withoutSeeds(r, "bodytext");
          r.sealed.contentWindowSeeds.push(
            { contentName: "bodytext", windowStart: W1, key: ENV.body1 },
            { contentName: "bodytext", windowStart: W2, key: ENV.body2 },
            { contentName: "bodytext", windowStart: "261015T1200", key: ENV.body1 },
          );
        }),
      ),
    { code: "too_many_entries" },
  );
  assert.throws(
    () =>
      readContentGroupRequest(
        variant((r) => {
          r.requestedContentGroups = r.requestedContentGroups.filter(
            (/** @type {any} */ g) => g.contentName !== "headline",
          );
          r.requestedContentGroups.push({ contentName: "headline", groups: ["politics"] });
          withoutSeeds(r, "headline");
          r.sealed.contentWindowSeeds.push({
            contentName: "headline",
            windowStart: W1,
            key: ENV.head1,
          });
        }),
        { maxItems: 1 },
      ),
    { code: "too_many_entries" },
  );
});

test("the builder's projection keeps only the named route identities", () => {
  const b = builder({ requestedContentKeys: { headline: "politics" } });
  const request = built(b, ["bodytext", "headline"]);
  const projection = /** @type {any} */ (b.routeProjection);
  const routes = projection.identities(request);
  assert.equal(routes.length, 4);
  assert.deepEqual(b.keyFamilies(request), { contentKeys: true, familyKeys: true });
  const sportsOnly = routes.filter((/** @type {string} */ r) => r.includes("sports"));
  const narrowed = projectEligibleIdentities(
    request,
    { contentNames: [], accessGroups: [], routes: sportsOnly },
    projection,
  );
  assert.deepEqual(narrowed.requestedContentGroups, [
    { contentName: "bodytext", groups: ["sports"] },
  ]);
  assert.equal(Object.hasOwn(narrowed, "requestedContentKeys"), false);
  assert.deepEqual(seedNames(narrowed), ["bodytext"]);
  assert.equal(narrowed.renderPeriod, request.renderPeriod);
  assert.deepEqual(narrowed.periodGeometry, request.periodGeometry);
  assert.ok(readContentGroupRequest(narrowed));
  const itemOnly = projectEligibleIdentities(
    request,
    {
      contentNames: [],
      accessGroups: [],
      routes: routes.filter((/** @type {string} */ r) => r.includes("headline")),
    },
    projection,
  );
  assert.deepEqual(itemOnly.requestedContentGroups, [
    { contentName: "headline", groups: ["politics"] },
  ]);
  assert.deepEqual(itemOnly.requestedContentKeys, [
    { contentName: "headline", group: "politics", connector: C.headPolitics },
  ]);
  assert.equal(projection.useful(routes[0], ["purchase"]), false);
  const none = projectEligibleIdentities(
    request,
    { contentNames: [], accessGroups: [], routes: [] },
    projection,
  );
  assert.equal(Object.hasOwn(none, "requestedContentGroups"), false);
  assert.equal(Object.hasOwn(none.sealed, "contentWindowSeeds"), false);
  assert.equal(b.keyFamilies(none).familyKeys, false);
});

test("the builder wraps a supplied inner builder or base options, not both", () => {
  const inner = new DcaRequestBuilder();
  assert.ok(new ContentGroupRequestBuilder({ innerBuilder: inner }));
  assert.throws(
    () => new ContentGroupRequestBuilder({ innerBuilder: inner, relayPeriodKeys: true }),
    { code: "bad_config" },
  );
  assert.throws(() => new ContentGroupRequestBuilder({ innerBuilder: {} }), {
    code: "bad_config",
  });
  const offered = new ContentGroupRequestBuilder({
    clientPublicKey: { kty: "EC", crv: "P-256", x: "x", y: "y" },
  });
  assert.equal(
    /** @type {any} */ (offered.build(new DcaData(page()), ISSUER, ALL).toObject()).clientPublicKey
      .kty,
    "EC",
  );
});

test("a conditional retry through the delivery client replays only outstanding routes", async () => {
  /** @type {any[]} */
  const posted = [];
  const missing = new Set(ALL);
  const resolver = {
    applyResponse: async () => ({ accepted: 0, errors: [], issues: [], notDelivered: [] }),
    resolveDetailed: async (/** @type {any} */ _d, /** @type {string[]} */ n) => ({
      covered: [],
      missing: n.filter((x) => missing.has(x)),
      origins: [],
    }),
    resolveAuthenticated: async (/** @type {any} */ _d, /** @type {string[]} */ n) => ({
      missing: n.filter((x) => missing.has(x)),
    }),
    resolve: async () => [],
    contentKeyFor: async () => null,
    contentKeyWithOriginFor: async () => null,
    clearReaderContext: async () => {},
  };
  const raw = page();
  raw.issuerData.push({ ...structuredClone(issuerBlock(raw, ISSUER)), issuerName: "backup" });
  const client = createDeliveryClient({
    reader: { dcaData: raw, publisherOrigin: PUB, extract: () => b64(0, 32) },
    issuerName: ISSUER,
    transport: {
      async post(url, request) {
        posted.push(structuredClone(request));
        if (url.includes("first")) throw dcaError("timeout", "scripted");
        return { status: 200, contentType: "application/json", body: {} };
      },
    },
    requestBuilderFactory: (options) => new ContentGroupRequestBuilder(options),
    resolverFactory: () => resolver,
  });
  missing.delete("purchase");
  const walk = await client.unlockRoutes(
    ["bodytext", "headline", "purchase"],
    [
      { issuerName: ISSUER, unlockUrl: "https://first.example/u", retryOperational: true },
      { issuerName: "backup", unlockUrl: "https://second.example/u" },
    ],
  );
  assert.deepEqual(
    walk.attempts.map((a) => a.outcome),
    ["timeout", "answered"],
  );
  assert.deepEqual(posted[0].requestedContentGroups, posted[1].requestedContentGroups);
  assert.deepEqual(posted[1].sealed.contentKeys, []);
  assert.deepEqual(seedNames(posted[1]), ["bodytext", "headline"]);
});

test("default alternatives offer one item connector beside groups, but not a future-only item route", () => {
  const request = built(builder(), ["bodytext"]);
  assert.deepEqual(request.requestedContentKeys, [
    { contentName: "bodytext", group: "politics", connector: C.bodyPolitics },
  ]);
  const future = page();
  dropSeeds(future, "bodytext", W1);
  const next = /** @type {any} */ (
    builder().build(new DcaData(future), ISSUER, ["bodytext"]).toObject()
  );
  assert.equal(Object.hasOwn(next, "requestedContentKeys"), false);
  assert.deepEqual(next.requestedContentGroups, [
    { contentName: "bodytext", groups: ["politics", "sports"] },
  ]);
});

test("an unused malformed connector item does not suppress valid sibling selection", () => {
  const damaged = page();
  // An empty connector collection does not admit: an item carries one to maxGroups records.
  item(damaged, "headline").connectors = [];
  const request = /** @type {any} */ (
    builder().build(new DcaData(damaged), ISSUER, ["bodytext", "headline", "purchase"]).toObject()
  );
  assert.deepEqual(request.requestedContentGroups, [
    { contentName: "bodytext", groups: ["politics", "sports"] },
  ]);
  assert.deepEqual(request.requestedContentKeys, [
    { contentName: "bodytext", group: "politics", connector: C.bodyPolitics },
  ]);
  assert.deepEqual(seedNames(request), ["bodytext"]);
  assert.deepEqual(request.sealed.contentKeys, [{ contentName: "purchase", key: b64(20, 109) }]);
});

test("default item choice is independent of record order and respects sub-hour window boundaries", () => {
  const original = page();
  item(original, "bodytext").connectors = [
    { group: "sports", connector: C.bodySports },
    { group: "politics", connector: C.bodyPolitics },
  ];
  /** @param {any} request */
  const itemGroups = (request) =>
    request.requestedContentKeys.map((/** @type {any} */ k) => [k.contentName, k.group]);
  const first = builder().build(new DcaData(original), ISSUER, ["bodytext"]).toObject();
  assert.deepEqual(itemGroups(first), [["bodytext", "politics"]]);
  original.periodGeometry = { chainsPerDay: 5, periodMinutes: 12 };
  original.renderPeriod = "261014T1424";
  dropSeeds(original, "bodytext");
  seedsOf(original).push({ contentName: "bodytext", windowStart: "261014T1424", key: ENV.body1 });
  const subhour = /** @type {any} */ (
    builder().build(new DcaData(original), ISSUER, ["bodytext"]).toObject()
  );
  assert.deepEqual(itemGroups(subhour), [["bodytext", "politics"]]);
  assert.deepEqual(subhour.requestedContentGroups, [
    { contentName: "bodytext", groups: ["sports", "politics"] },
  ]);
  const groupOnly = built(builder({ requestedContentKeys: {} }), ["bodytext"]);
  assert.equal(Object.hasOwn(groupOnly, "requestedContentKeys"), false);
  assert.deepEqual(groupOnly.requestedContentGroups, [
    { contentName: "bodytext", groups: ["politics", "sports"] },
  ]);
});

test("wrapping a selected builder keeps its optional hooks and key families", () => {
  const inner = {
    build: () => new DcaRequestBuilder().build(new DcaData(page()), ISSUER, ["purchase"]),
    keyFamilies(request) {
      assert.equal(this, inner);
      assert.equal(request, marker);
      return { contentKeys: true, familyKeys: true };
    },
    acceptsPeriodKeyResponseCoordinate(group, t, request) {
      assert.equal(this, inner);
      return group === "premium" && t === W1 && request === marker;
    },
  };
  const marker = {};
  const wrapped = new ContentGroupRequestBuilder({ innerBuilder: inner });
  assert.deepEqual(wrapped.keyFamilies(marker), { contentKeys: true, familyKeys: true });
  assert.equal(wrapped.acceptsPeriodKeyResponseCoordinate("premium", W1, marker), true);
  assert.equal(wrapped.acceptsPeriodKeyResponseCoordinate("unasked", W1, marker), false);
  assert.equal(typeof builder().acceptsPeriodKeyResponseCoordinate, "undefined");
  assert.deepEqual(builder().keyFamilies(marker), { contentKeys: false, familyKeys: false });
});

test("default item route relays all candidates of the first group and counts raw records", () => {
  const data = page();
  data.contentData = data.contentData.slice(0, 1);
  data.issuerData[0].sealed.contentWindowSeeds = data.issuerData[0].sealed.contentWindowSeeds.slice(
    0,
    1,
  );
  data.contentData[0].connectors.push({ group: "politics", connector: b64(4) });
  const build = (maxItems) =>
    new ContentGroupRequestBuilder({ limits: { maxItems } })
      .build(new DcaData(data), ISSUER, ["bodytext"])
      .toObject();
  const request = build(2);
  sameRecords(request.requestedContentKeys, [
    { contentName: "bodytext", group: "politics", connector: C.bodyPolitics },
    { contentName: "bodytext", group: "politics", connector: b64(4) },
  ]);
  assert.throws(() => readContentGroupRequest(request, { maxItems: 1 }), {
    code: "too_many_entries",
  });
});

test("reusable cutoff narrowing projects onto selected seed windows and preserves an empty ceiling", () => {
  const b = builder({
    seedWindows: [W1],
    requestedChainCutoffs: {
      [W1]: "261014T1800",
      [W2]: "261015T0300",
      "261016T0000": "261016T0300",
    },
  });
  const selected = built(b, ["bodytext"]);
  assert.deepEqual(selected.requestedChainCutoffs, [{ windowStart: W1, cutoff: "261014T1800" }]);
  assert.ok(readContentGroupRequest(selected));
  const noIntersection = built(
    builder({
      seedWindows: [W1],
      requestedChainCutoffs: {
        [W2]: "261015T0300",
      },
    }),
    ["bodytext"],
  );
  assert.deepEqual(noIntersection.requestedChainCutoffs, []);
  assert.deepEqual(readContentGroupRequest(noIntersection)?.cutoffs, {});
  assert.equal(
    Object.hasOwn(built(builder({ seedWindows: [W1] }), ["bodytext"]), "requestedChainCutoffs"),
    false,
  );
});

test("retry route projection drops cutoff windows whose last seed-owning route was removed", () => {
  const b = builder({ requestedChainCutoffs: { [W2]: "261015T0300" } });
  const request = built(b, ["bodytext", "headline"]);
  const projection = b.routeProjection;
  const routes = projection.identities(request).filter((route) => route.includes("headline"));
  const narrowed = projectEligibleIdentities(
    request,
    { contentNames: [], accessGroups: [], routes },
    projection,
  );
  assert.deepEqual(narrowed.requestedChainCutoffs, []);
  assert.ok(readContentGroupRequest(narrowed));
});

test("an unusable seed collection leaves another issuer's valid seeded route available", () => {
  const damaged = page();
  const otherSeeds = structuredClone(seedsOf(damaged));
  issuerBlock(damaged, ISSUER).sealed.contentWindowSeeds = [null];
  issuerBlock(damaged, "other").sealed.contentWindowSeeds = otherSeeds;
  const b = builder({ requestedContentGroups: { bodytext: ["politics"] } });
  const ordinary = b.build(new DcaData(damaged), ISSUER, ["bodytext", "purchase"]).toObject();
  assert.equal(Object.hasOwn(ordinary.sealed, "contentWindowSeeds"), false);
  const other = b.build(new DcaData(damaged), "other", ["bodytext", "purchase"]).toObject();
  assert.deepEqual(other.requestedContentGroups, [
    { contentName: "bodytext", groups: ["politics"] },
  ]);
  assert.deepEqual(seedNames(other), ["bodytext"]);
  assert.ok(readContentGroupRequest(other));
  assert.throws(
    () =>
      builder({ requestedContentGroups: { bodytext: [] } }).build(new DcaData(damaged), ISSUER, [
        "bodytext",
      ]),
    { code: "bad_config" },
  );
});
