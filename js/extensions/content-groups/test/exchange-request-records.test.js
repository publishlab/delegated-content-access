// @ts-check
//
// The shared request reader over named records. The issuer and the client read
// a request through `readContentGroupRequest`, so these rules hold for both:
// repeated `requestedContentGroups` records union their groups, repeated
// `requestedContentKeys` records are item-route alternatives, every
// `requestedChainCutoffs` label stays for the caller to admit before it takes
// the lowest, and repeated seed records at one window are candidates. Raw
// records count against the bounds before anything merges.

import test from "node:test";
import assert from "node:assert/strict";

import { readContentGroupRequest } from "../core-shared--client-issuer/request.js";
import { base64urlEncode } from "../../../core-shared/codec.js";

const W1 = "261014T1200";
const W2 = "261015T0000";
/** @param {number} n */
const b64 = (n, size = 16) => base64urlEncode(new Uint8Array(size).fill(n));
const ENV = { body1: b64(11, 113), body2: b64(12, 113), head1: b64(13, 113), rival: b64(14, 113) };

function request() {
  return {
    version: "1",
    issuerName: "issuer",
    keyId: "kid",
    resourceJWT: "jwt",
    sealed: {
      contentKeys: [],
      contentWindowSeeds: [
        { contentName: "bodytext", windowStart: W1, key: ENV.body1 },
        { contentName: "bodytext", windowStart: W2, key: ENV.body2 },
        { contentName: "headline", windowStart: W1, key: ENV.head1 },
      ],
    },
    renderPeriod: "261014T1500",
    periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
    requestedContentGroups: [{ contentName: "bodytext", groups: ["politics", "sports"] }],
    requestedContentKeys: [{ contentName: "headline", group: "politics", connector: b64(3) }],
  };
}

/** @param {(r: any) => void} mutate */
function variant(mutate) {
  const copy = /** @type {any} */ (structuredClone(request()));
  mutate(copy);
  return copy;
}

/** @param {any} view */
function sortedView(view) {
  const sortedGroups = Object.fromEntries(
    Object.entries(view.contentGroups)
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([name, { groups, windows }]) => [
        name,
        { groups: [...groups].sort(), windows: [...windows].sort() },
      ]),
  );
  /** @param {Record<string, readonly any[]>} map */
  const sortedLists = (map) =>
    Object.fromEntries(
      Object.entries(map)
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([name, list]) => [name, [...list].map((v) => JSON.stringify(v)).sort()]),
    );
  return {
    contentGroups: sortedGroups,
    contentKeys: sortedLists(view.contentKeys),
    cutoffs: view.cutoffs === undefined ? undefined : sortedLists(view.cutoffs),
    seeds: Object.fromEntries(
      Object.entries(view.seeds)
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([name, windows]) => [name, sortedLists(/** @type {any} */ (windows))]),
    ),
  };
}

test("the reader admits named records and exposes coordinates by name", () => {
  const view = readContentGroupRequest(request());
  assert.ok(view);
  assert.deepEqual(view.contentGroups.bodytext, {
    groups: ["politics", "sports"],
    windows: [W1, W2],
  });
  assert.deepEqual(view.contentKeys.headline, [{ group: "politics", connector: b64(3) }]);
  assert.deepEqual(view.seeds.bodytext, { [W1]: [ENV.body1], [W2]: [ENV.body2] });
  assert.equal(view.cutoffs, undefined);
});

test("the former object maps are malformed requests", () => {
  for (const mutate of [
    (/** @type {any} */ r) => (r.requestedContentGroups = { bodytext: ["politics"] }),
    (/** @type {any} */ r) =>
      (r.requestedContentKeys = { headline: { group: "politics", connector: b64(3) } }),
    (/** @type {any} */ r) => (r.sealed.contentWindowSeeds = { bodytext: { [W1]: ENV.body1 } }),
    (/** @type {any} */ r) => (r.requestedChainCutoffs = { [W1]: "261014T1800" }),
  ])
    assert.throws(() => readContentGroupRequest(variant(mutate)), { code: "binding_failed" });
});

test("records refuse a missing or wrong required field and extra closed-route fields", () => {
  const refused = [
    (/** @type {any} */ r) => (r.requestedContentGroups[0].groups = []),
    (/** @type {any} */ r) => (r.requestedContentGroups[0].groups = ["politics", "politics"]),
    (/** @type {any} */ r) => delete r.requestedContentGroups[0].contentName,
    (/** @type {any} */ r) => (r.requestedContentGroups[0] = ["bodytext", ["politics"]]),
    (/** @type {any} */ r) => (r.requestedContentKeys[0].extra = 1),
    (/** @type {any} */ r) => (r.requestedContentKeys[0].connector = b64(1, 15)),
    (/** @type {any} */ r) => delete r.requestedContentKeys[0].group,
    (/** @type {any} */ r) => (r.sealed.contentWindowSeeds[0].key = 7),
    (/** @type {any} */ r) => (r.sealed.contentWindowSeeds[0].windowStart = ""),
    (/** @type {any} */ r) => (r.requestedChainCutoffs = [{ windowStart: W1 }]),
    (/** @type {any} */ r) => (r.requestedChainCutoffs = [{ windowStart: W1, cutoff: 18 }]),
  ];
  for (const [index, mutate] of refused.entries())
    assert.throws(
      () => readContentGroupRequest(variant(mutate)),
      { code: "binding_failed" },
      String(index),
    );
});

test("repeated requestedContentGroups records union their groups", () => {
  const view = readContentGroupRequest(
    variant((r) => {
      r.requestedContentGroups = [
        { contentName: "bodytext", groups: ["politics"] },
        { contentName: "bodytext", groups: ["sports", "politics"] },
      ];
    }),
  );
  assert.deepEqual(view?.contentGroups.bodytext.groups, ["politics", "sports"]);
});

test("repeated requestedContentKeys records are item-route alternatives", () => {
  const other = { contentName: "headline", group: "sports", connector: b64(4) };
  const rival = { contentName: "headline", group: "politics", connector: b64(5) };
  const view = readContentGroupRequest(
    variant((r) => r.requestedContentKeys.push(other, rival, { ...r.requestedContentKeys[0] })),
  );
  assert.deepEqual(view?.contentKeys.headline, [
    { group: "politics", connector: b64(3) },
    { group: "sports", connector: b64(4) },
    { group: "politics", connector: b64(5) },
  ]);
});

test("every requested cutoff label of a window stays for the caller to admit", () => {
  const view = readContentGroupRequest(
    variant((r) => {
      r.requestedChainCutoffs = [
        { windowStart: W1, cutoff: "261014T1800" },
        { windowStart: W1, cutoff: "261014T1400" },
        { windowStart: W1, cutoff: "261014T1800" },
      ];
    }),
  );
  assert.deepEqual(view?.cutoffs, { [W1]: ["261014T1800", "261014T1400"] });
  assert.deepEqual(
    readContentGroupRequest(variant((r) => (r.requestedChainCutoffs = [])))?.cutoffs,
    {},
  );
});

test("repeated seed records at one window are kept as candidates", () => {
  const view = readContentGroupRequest(
    variant((r) => {
      r.sealed.contentWindowSeeds = [
        { contentName: "bodytext", windowStart: W1, key: ENV.body1 },
        { contentName: "bodytext", windowStart: W1, key: ENV.rival },
        { contentName: "headline", windowStart: W1, key: ENV.head1 },
      ];
    }),
  );
  assert.deepEqual(view?.seeds.bodytext, { [W1]: [ENV.body1, ENV.rival] });
  assert.deepEqual(view?.contentGroups.bodytext.windows, [W1]);
});

test("raw records count against the bounds before they merge", () => {
  // Two identical group records still count twice toward maxItems.
  assert.throws(
    () =>
      readContentGroupRequest(
        variant((r) => {
          r.requestedContentGroups = [
            { contentName: "bodytext", groups: ["politics"] },
            { contentName: "bodytext", groups: ["politics"] },
          ];
          r.requestedContentKeys = [];
          r.sealed.contentWindowSeeds = [r.sealed.contentWindowSeeds[0]];
        }),
        { maxItems: 1 },
      ),
    { code: "too_many_entries" },
  );
  // Group entries count across the records of one content name.
  assert.throws(
    () =>
      readContentGroupRequest(
        variant((r) => {
          r.requestedContentGroups = [
            { contentName: "bodytext", groups: ["politics"] },
            { contentName: "bodytext", groups: ["politics", "sports"] },
          ];
        }),
        { maxGroups: 2 },
      ),
    { code: "too_many_entries" },
  );
  // Repeated item alternatives count toward maxItems.
  assert.throws(
    () =>
      readContentGroupRequest(
        variant((r) => {
          r.requestedContentGroups = [];
          r.requestedContentKeys.push({ ...r.requestedContentKeys[0] });
          r.sealed.contentWindowSeeds = [r.sealed.contentWindowSeeds[2]];
        }),
        { maxItems: 1 },
      ),
    { code: "too_many_entries" },
  );
  // A rival seed record counts toward maxSeedWindows like another window.
  assert.throws(
    () =>
      readContentGroupRequest(
        variant((r) =>
          r.sealed.contentWindowSeeds.push({
            contentName: "bodytext",
            windowStart: W1,
            key: ENV.body1,
          }),
        ),
      ),
    { code: "too_many_entries" },
  );
  assert.throws(
    () =>
      readContentGroupRequest(
        variant((r) => {
          r.requestedChainCutoffs = [
            { windowStart: W1, cutoff: "261014T1800" },
            { windowStart: W1, cutoff: "261014T1800" },
            { windowStart: W1, cutoff: "261014T1800" },
          ];
        }),
        { maxItems: 1 },
      ),
    { code: "too_many_entries" },
  );
});

test("record order changes no coordinate", () => {
  const forward = variant((r) => {
    r.requestedContentGroups = [
      { contentName: "bodytext", groups: ["politics"] },
      { contentName: "headline", groups: ["politics"] },
      { contentName: "bodytext", groups: ["sports"] },
    ];
    r.requestedContentKeys.push({ contentName: "bodytext", group: "sports", connector: b64(2) });
    r.requestedChainCutoffs = [
      { windowStart: W1, cutoff: "261014T1800" },
      { windowStart: W2, cutoff: "261015T0300" },
    ];
  });
  const reversed = structuredClone(forward);
  for (const list of [
    reversed.requestedContentGroups,
    reversed.requestedContentKeys,
    reversed.requestedChainCutoffs,
    reversed.sealed.contentWindowSeeds,
  ])
    list.reverse();
  for (const list of [reversed.requestedContentGroups[0].groups]) list.reverse();
  const a = readContentGroupRequest(JSON.parse(JSON.stringify(forward)));
  const b = readContentGroupRequest(JSON.parse(JSON.stringify(reversed)));
  assert.deepEqual(sortedView(a), sortedView(b));
});

test("seed, group and cutoff records ignore unknown members while retaining required own fields", () => {
  const original = request();
  const extended = variant((r) => {
    r.requestedContentGroups[0].future = { note: "ignored" };
    r.sealed.contentWindowSeeds[0].future = false;
    r.requestedChainCutoffs = [{ windowStart: W1, cutoff: "261014T1800", future: null }];
  });
  assert.deepEqual(
    readContentGroupRequest(extended)?.contentGroups,
    readContentGroupRequest(original)?.contentGroups,
  );
  assert.deepEqual(
    readContentGroupRequest(extended)?.seeds,
    readContentGroupRequest(original)?.seeds,
  );
  assert.deepEqual(readContentGroupRequest(extended)?.cutoffs, { [W1]: ["261014T1800"] });
  for (const [collection, fields] of [
    ["requestedContentGroups", ["contentName", "groups"]],
    ["seeds", ["contentName", "windowStart", "key"]],
    ["requestedChainCutoffs", ["windowStart", "cutoff"]],
  ])
    for (const field of fields) {
      const r = /** @type {any} */ (structuredClone(extended));
      const records = collection === "seeds" ? r.sealed.contentWindowSeeds : r[collection];
      const entry = records[0];
      records[0] = Object.assign(Object.create({ [field]: entry[field] }), entry);
      delete records[0][field];
      assert.throws(
        () => readContentGroupRequest(r),
        { code: "binding_failed" },
        `${collection}.${field} cannot be inherited`,
      );
    }
});

test("a requested cutoff must name a supplied seed window across the request", () => {
  assert.throws(
    () =>
      readContentGroupRequest(
        variant((r) => {
          r.requestedChainCutoffs = [
            { windowStart: W1, cutoff: "261014T1400" },
            { windowStart: "261016T0000", cutoff: "261016T0300" },
          ];
        }),
      ),
    { code: "binding_failed" },
  );
});
