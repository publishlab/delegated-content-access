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
const ENV = { body1: b64(11, 125), body2: b64(12, 125), head1: b64(13, 125) };

function page() {
  return {
    version: "1",
    resourceJWT: JWT,
    renderPeriod: "261014T1500",
    periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
    contentData: {
      bodytext: {
        contentType: "text/plain",
        nonce: b64(0, 12),
        connectors: { politics: C.bodyPolitics, sports: C.bodySports },
      },
      headline: {
        contentType: "text/plain",
        nonce: b64(0, 12),
        connectors: { politics: C.headPolitics },
      },
      purchase: { contentType: "text/plain", nonce: b64(0, 12) },
    },
    issuerData: {
      [ISSUER]: {
        keyId: "kid",
        sealed: {
          contentKeys: { purchase: b64(20, 109) },
          contentWindowSeeds: {
            bodytext: { [W1]: ENV.body1, [W2]: ENV.body2 },
            headline: { [W1]: ENV.head1 },
          },
        },
      },
      other: { keyId: "kid2", sealed: { contentKeys: { purchase: b64(21, 109) } } },
    },
  };
}

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
  assert.deepEqual(request.sealed, {
    contentKeys: { purchase: b64(20, 109) },
    contentWindowSeeds: {
      bodytext: { [W1]: ENV.body1, [W2]: ENV.body2 },
      headline: { [W1]: ENV.head1 },
    },
  });
  assert.deepEqual(request.requestedContentGroups, {
    bodytext: ["politics", "sports"],
    headline: ["politics"],
  });
  assert.deepEqual(request.requestedContentKeys, {
    bodytext: { group: "politics", connector: C.bodyPolitics },
    headline: { group: "politics", connector: C.headPolitics },
  });
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
  assert.deepEqual(other.sealed, { contentKeys: { purchase: b64(21, 109) } });
});

test("requestedContentKeys names a group locally; only the builder relays its connector", () => {
  const b = builder({ requestedContentGroups: {}, requestedContentKeys: { bodytext: "sports" } });
  const request = built(b, ALL);
  assert.deepEqual(request.requestedContentKeys, {
    bodytext: { group: "sports", connector: C.bodySports },
  });
  assert.deepEqual(request.requestedContentGroups, {});
  assert.deepEqual(Object.keys(request.sealed.contentWindowSeeds), ["bodytext"]);
  const read = readContentGroupRequest(request);
  assert.deepEqual(read?.contentKeys, { bodytext: { group: "sports", connector: C.bodySports } });
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
  assert.deepEqual(absent.sealed.contentKeys, { purchase: b64(20, 109) });
  assert.deepEqual(absent.requestedContentGroups, {
    bodytext: ["politics", "sports"],
    headline: ["politics"],
  });
  assert.equal(Object.hasOwn(absent, "requestedContentKeys"), false);
  const groups = built(
    builder({ requestedContentGroups: { shoppingAd: ["sports"], headline: ["politics"] } }),
    ALL,
  );
  assert.deepEqual(groups.requestedContentGroups, { headline: ["politics"] });
  assert.deepEqual(Object.keys(groups.sealed.contentWindowSeeds), ["headline"]);
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
        { contentKeys: { purchase: b64(21, 109) } },
        JSON.stringify([narrowing, needed]),
      );
      assert.equal(Object.hasOwn(other, "requestedContentGroups"), false);
      assert.equal(Object.hasOwn(other, "requestedContentKeys"), false);
    }
  // The same holds at an issuer that seeds other names but not the narrowed one.
  const unseeded = page();
  delete unseeded.issuerData[ISSUER].sealed.contentWindowSeeds.headline;
  for (const narrowing of [
    { requestedContentGroups: { headline: ["politics"] } },
    { requestedContentKeys: { headline: "politics" } },
  ]) {
    const request = /** @type {any} */ (
      builder(narrowing).build(new DcaData(unseeded), ISSUER, ["headline", "purchase"]).toObject()
    );
    assert.deepEqual(
      request.sealed,
      { contentKeys: { purchase: b64(20, 109) } },
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
  assert.deepEqual(ordinary.sealed, { contentKeys: { purchase: b64(20, 109) } });
  const ordinaryKey = built(builder({ requestedContentKeys: { purchase: "politics" } }), ALL);
  assert.deepEqual(ordinaryKey.sealed.contentKeys, { purchase: b64(20, 109) });
  assert.equal(Object.hasOwn(ordinaryKey, "requestedContentKeys"), false);
  // Malformed offered seeds refuse rather than read as an issuer without a seed.
  const malformed = page();
  malformed.issuerData[ISSUER].sealed.contentWindowSeeds.bodytext = /** @type {any} */ ({});
  for (const narrowing of [
    { requestedContentGroups: { bodytext: ["politics"] } },
    { requestedContentKeys: { bodytext: "sports" } },
  ])
    assert.throws(
      () => builder(narrowing).build(new DcaData(malformed), ISSUER, ["bodytext", "purchase"]),
      { code: "bad_config" },
      JSON.stringify(narrowing),
    );
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
    contentKeys: {},
    contentWindowSeeds: { bodytext: { [W1]: ENV.body1 } },
  });
  assert.deepEqual(request.requestedContentGroups, { bodytext: ["politics", "sports"] });
  assert.deepEqual(request.requestedChainCutoffs, { [W1]: "261014T1800" });
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
  const refused = [
    (/** @type {any} */ r) => (r.requestedContentGroups.bodytext = []),
    (/** @type {any} */ r) => (r.requestedContentGroups.bodytext = ["politics", "politics"]),
    (/** @type {any} */ r) => (r.requestedContentGroups.bodytext = "politics"),
    (/** @type {any} */ r) => {
      r.requestedContentGroups = {};
      delete r.requestedContentKeys;
    },
    (/** @type {any} */ r) => delete r.sealed.contentWindowSeeds.bodytext,
    (/** @type {any} */ r) => (r.sealed.contentWindowSeeds.extra = { [W1]: ENV.head1 }),
    (/** @type {any} */ r) => (r.sealed.contentWindowSeeds.bodytext = {}),
    (/** @type {any} */ r) => (r.requestedContentKeys.headline.extra = 1),
    (/** @type {any} */ r) => (r.requestedContentKeys.headline.connector = b64(1, 15)),
    (/** @type {any} */ r) => (r.requestedContentKeys.headline = "politics"),
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
        variant(
          (r) =>
            (r.sealed.contentWindowSeeds.bodytext = {
              [W1]: ENV.body1,
              [W2]: ENV.body2,
              "261015T1200": ENV.body1,
            }),
        ),
      ),
    { code: "too_many_entries" },
  );
  assert.throws(
    () =>
      readContentGroupRequest(
        variant((r) => {
          r.requestedContentGroups.headline = ["politics"];
          r.sealed.contentWindowSeeds.headline = { [W1]: ENV.head1 };
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
  assert.deepEqual(narrowed.requestedContentGroups, { bodytext: ["sports"] });
  assert.equal(Object.hasOwn(narrowed, "requestedContentKeys"), false);
  assert.deepEqual(Object.keys(narrowed.sealed.contentWindowSeeds), ["bodytext"]);
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
  assert.deepEqual(itemOnly.requestedContentGroups, { headline: ["politics"] });
  assert.deepEqual(itemOnly.requestedContentKeys, {
    headline: { group: "politics", connector: C.headPolitics },
  });
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
  raw.issuerData.backup = structuredClone(raw.issuerData[ISSUER]);
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
  assert.deepEqual(posted[1].sealed.contentKeys, {});
  assert.deepEqual(Object.keys(posted[1].sealed.contentWindowSeeds), ["bodytext", "headline"]);
});

test("default alternatives offer one item connector beside groups, but not a future-only item route", () => {
  const request = built(builder(), ["bodytext"]);
  assert.deepEqual(request.requestedContentKeys, {
    bodytext: { group: "politics", connector: C.bodyPolitics },
  });
  const future = page();
  delete future.issuerData[ISSUER].sealed.contentWindowSeeds.bodytext[W1];
  const next = builder().build(new DcaData(future), ISSUER, ["bodytext"]).toObject();
  assert.equal(Object.hasOwn(next, "requestedContentKeys"), false);
  assert.deepEqual(next.requestedContentGroups, { bodytext: ["politics", "sports"] });
});

test("an unused malformed connector item does not suppress valid sibling selection", () => {
  const damaged = page();
  damaged.contentData.headline.connectors = {};
  const request = builder()
    .build(new DcaData(damaged), ISSUER, ["bodytext", "headline", "purchase"])
    .toObject();
  assert.deepEqual(request.requestedContentGroups, { bodytext: ["politics", "sports"] });
  assert.deepEqual(request.requestedContentKeys, {
    bodytext: { group: "politics", connector: C.bodyPolitics },
  });
  assert.deepEqual(Object.keys(request.sealed.contentWindowSeeds), ["bodytext"]);
  assert.deepEqual(request.sealed.contentKeys, { purchase: b64(20, 109) });
});

test("default item choice is independent of map order and respects sub-hour window boundaries", () => {
  const original = page();
  original.contentData.bodytext.connectors = { sports: C.bodySports, politics: C.bodyPolitics };
  const first = builder().build(new DcaData(original), ISSUER, ["bodytext"]).toObject();
  assert.equal(first.requestedContentKeys.bodytext.group, "politics");
  original.periodGeometry = { chainsPerDay: 5, periodMinutes: 12 };
  original.renderPeriod = "261014T1424";
  original.issuerData[ISSUER].sealed.contentWindowSeeds.bodytext = { "261014T1424": ENV.body1 };
  const subhour = builder().build(new DcaData(original), ISSUER, ["bodytext"]).toObject();
  assert.equal(subhour.requestedContentKeys.bodytext.group, "politics");
  assert.deepEqual(subhour.requestedContentGroups, { bodytext: ["sports", "politics"] });
  const groupOnly = built(builder({ requestedContentKeys: {} }), ["bodytext"]);
  assert.equal(Object.hasOwn(groupOnly, "requestedContentKeys"), false);
  assert.deepEqual(groupOnly.requestedContentGroups, { bodytext: ["politics", "sports"] });
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
