// @ts-check
//
// A durable chain cache keeps a record of what it filed so `reconcile` can
// restore a write another instance lost. That record holds chain keys, so it
// stays inside the same window bounds and eviction policy as the retained
// windows: a window the cache evicted, by count or by policy, never comes back
// through `reconcile` or a reload, and the record never holds more windows than
// the bounds allow, across every family.

import test from "node:test";
import assert from "node:assert/strict";

import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";

const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
const KIND = "testChainKey";
const GROUP = "politics";
const SEED = new Uint8Array(32).fill(1);

/** @param {string} t */
async function chainKey(t) {
  return (
    await periodFamilyGeneration({ keyDerivationSecret: SEED, geometry: GEOMETRY }).chainCapability(
      GROUP,
      t,
    )
  ).key;
}

/** @param {string} name */
const scope = (name) => ({ partition: { kind: KIND, parts: [name] }, ...GEOMETRY });

/** A storage whose writes can be lost, as when another tab writes over them. */
function lossyStorage() {
  /** @type {Map<string, string>} */
  const values = new Map();
  const state = { lose: false };
  return {
    state,
    storage: {
      /** @param {string} key */
      async get(key) {
        return values.get(key);
      },
      /** @param {string} key @param {string} value */
      async set(key, value) {
        if (!state.lose) values.set(key, value);
      },
      async keys() {
        return [...values.keys()];
      },
      /** @param {string} key */
      async remove(key) {
        values.delete(key);
      },
    },
    /** @returns {string[]} the partition names the store holds, sorted */
    families() {
      return [...values.values()].map((value) => JSON.parse(value).family[1]).sort();
    },
  };
}

/** An eviction policy that expires every chain key with a cutoff before `before`. */
function expiry() {
  const state = { before: "" };
  return {
    state,
    clock: { now: () => new Date(0) },
    /** @param {{ t: string }} entry */
    evictionPolicy: (entry) => entry.t < state.before,
  };
}

/** @param {any} storage @param {ReturnType<typeof expiry>} policy */
const bounded = (storage, policy) =>
  new ChainKeyCache({
    entryKind: KIND,
    periodView: "none",
    storage,
    maxWindows: 2,
    clock: policy.clock,
    evictionPolicy: policy.evictionPolicy,
  });

test("a window the global bound evicted stays gone through reconcile and reload", async () => {
  const store = lossyStorage();
  const policy = expiry();
  const cache = bounded(store.storage, policy);
  // Filed first, so least recently accepted, but with the latest cutoff.
  await cache.put(GROUP, "261016T0600", await chainKey("261016T0600"), scope("a"));
  await cache.put(GROUP, "261014T0600", await chainKey("261014T0600"), scope("b"));
  await cache.put(GROUP, "261014T1800", await chainKey("261014T1800"), scope("c"));
  assert.deepEqual(store.families(), ["b", "c"], "the global bound evicted family a");

  // The retained windows expire, which leaves room under the bound.
  policy.state.before = "261015T0000";
  await cache.reconcile();
  assert.deepEqual(
    store.families(),
    [],
    "reconcile restores neither an expired window nor the window the bound evicted",
  );

  await store.storage.set("theme", "dark");
  const reloaded = new ChainKeyCache({
    entryKind: KIND,
    periodView: "none",
    storage: store.storage,
  });
  for (const [name, t] of [
    ["a", "261016T0500"],
    ["b", "261014T0500"],
    ["c", "261014T1500"],
  ])
    assert.deepEqual(
      await reloaded.candidates(GROUP, t, scope(name)),
      [],
      `an evicted chain key of ${name} must not come back on reload`,
    );
});

/**
 * File four families while the store loses every write. Families a and b
 * carry the later cutoffs, c and d were accepted last.
 * @param {ChainKeyCache} cache @param {ReturnType<typeof lossyStorage>} store
 */
async function fileWhileLost(cache, store) {
  store.state.lose = true;
  await cache.put(GROUP, "261016T0600", await chainKey("261016T0600"), scope("a"));
  await cache.put(GROUP, "261016T1800", await chainKey("261016T1800"), scope("b"));
  await cache.put(GROUP, "261014T0600", await chainKey("261014T0600"), scope("c"));
  await cache.put(GROUP, "261014T1800", await chainKey("261014T1800"), scope("d"));
  store.state.lose = false;
  assert.deepEqual(store.families(), [], "the store lost every write");
}

test("reconcile restores the lost writes the bound retains", async () => {
  const store = lossyStorage();
  const cache = bounded(store.storage, expiry());
  await fileWhileLost(cache, store);
  await cache.reconcile();
  assert.deepEqual(store.families(), ["c", "d"]);
});

test("the reconcile record stays inside the global bound across families", async () => {
  const store = lossyStorage();
  const policy = expiry();
  const cache = bounded(store.storage, policy);
  await fileWhileLost(cache, store);
  // The two windows the bound retains expire before any reconcile.
  policy.state.before = "261015T0000";
  await cache.reconcile();
  assert.deepEqual(
    store.families(),
    [],
    "the record held no more than the bound: families a and b must not come back",
  );
});

test("a window this instance evicted for newer stored windows leaves its record", async () => {
  const store = lossyStorage();
  const policy = expiry();
  const cache = bounded(store.storage, policy);
  const wider = new ChainKeyCache({
    entryKind: KIND,
    periodView: "none",
    storage: store.storage,
    maxWindows: 3,
  });
  await cache.put(GROUP, "261016T0600", await chainKey("261016T0600"), scope("a"));
  await wider.put(GROUP, "261014T0600", await chainKey("261014T0600"), scope("b"));
  await wider.put(GROUP, "261014T1800", await chainKey("261014T1800"), scope("c"));
  // This instance loads three windows and evicts its own, least recent one.
  await cache.candidates(GROUP, "261014T0500", scope("b"));
  assert.deepEqual(store.families(), ["b", "c"]);

  policy.state.before = "261015T0000";
  await cache.reconcile();
  assert.deepEqual(
    store.families(),
    [],
    "reconcile must not restore family a, which this instance evicted itself",
  );
});

test("a composing profile sets the per-answer member bound; the default stays the message bound", async () => {
  /** @param {ChainKeyCache} cache @param {number} members */
  const file = async (cache, members) => {
    const lease = {};
    for (let index = 0; index < members; index++)
      await cache.put(GROUP, "261014T1800", await chainKey("261014T1800"), {
        ...scope(`name${index}`),
        lease,
      });
  };
  const partitioned = (/** @type {Record<string, unknown>} */ config) =>
    new ChainKeyCache({ entryKind: KIND, periodView: "none", ...config });

  await file(partitioned({}), 16);
  await assert.rejects(
    file(partitioned({}), 17),
    (error) => /** @type {any} */ (error)?.code === "bad_key" && /member bound/.test(error.message),
  );
  await file(partitioned({ maxMembersPerMessage: 100 }), 100);
  await assert.rejects(
    file(partitioned({ maxMembersPerMessage: 100 }), 101),
    (error) => /** @type {any} */ (error)?.code === "bad_key",
  );
  assert.throws(
    () => partitioned({ maxMembersPerMessage: 0 }),
    (error) => /** @type {any} */ (error)?.code === "bad_config",
  );
});

test("a composing profile sets the per-family member bound: three windows of one family under one lease", async () => {
  const cutoffs = ["261014T0600", "261014T1800", "261015T0600"];
  /** @param {ChainKeyCache} cache */
  const fileWindows = async (cache) => {
    const lease = {};
    for (const t of cutoffs)
      await cache.put(GROUP, t, await chainKey(t), { ...scope("bodytext"), lease });
    return lease;
  };

  const cache = new ChainKeyCache({
    entryKind: KIND,
    periodView: "none",
    maxMembersPerFamily: 3,
    maxWindowsPerFamily: 3,
  });
  await cache.attempted({ lease: await fileWindows(cache) });
  for (const t of ["261014T0500", "261014T1500", "261015T0500"])
    assert.equal((await cache.candidates(GROUP, t, scope("bodytext"))).length, 1, t);

  await assert.rejects(
    fileWindows(new ChainKeyCache({ entryKind: KIND, periodView: "none" })),
    (error) => /** @type {any} */ (error)?.code === "bad_key" && /member bound/.test(error.message),
    "the default stays the chain-keys family bound",
  );
  for (const maxMembersPerFamily of [0, 1.5])
    assert.throws(
      () => new ChainKeyCache({ entryKind: KIND, periodView: "none", maxMembersPerFamily }),
      (error) => /** @type {any} */ (error)?.code === "bad_config",
    );
});

test("the per-family window bound evicts by acceptance and stays evicted after reload", async () => {
  const store = lossyStorage();
  const config = {
    entryKind: KIND,
    periodView: /** @type {const} */ ("none"),
    maxWindowsPerFamily: 2,
    maxWindows: 10,
    storage: store.storage,
  };
  const cache = new ChainKeyCache(config);
  // The first accepted window has the latest label: eviction follows acceptance.
  const cutoffs = ["261016T0600", "261014T0600", "261014T1800"];
  for (const t of cutoffs) await cache.put(GROUP, t, await chainKey(t), scope("bodytext"));
  const generation = periodFamilyGeneration({ keyDerivationSecret: SEED, geometry: GEOMETRY });
  /** @param {ChainKeyCache} view */
  const retained = async (view) => {
    assert.deepEqual(await view.candidates(GROUP, cutoffs[0], scope("bodytext")), []);
    for (const t of cutoffs.slice(1))
      assert.deepEqual(await view.candidates(GROUP, t, scope("bodytext")), [
        await generation.periodKey(GROUP, t),
      ]);
  };
  await retained(cache);
  await cache.reconcile();
  await retained(new ChainKeyCache(config));
});

test("the global window bound evicts by acceptance, not by first filing", async () => {
  const cache = new ChainKeyCache({ entryKind: KIND, periodView: "none", maxWindows: 2 });
  await cache.put(GROUP, "261014T0600", await chainKey("261014T0600"), scope("a"));
  await cache.put(GROUP, "261015T0600", await chainKey("261015T0600"), scope("b"));
  // A later acceptance in the window of a leaves b the least recently accepted.
  await cache.put(GROUP, "261014T0800", await chainKey("261014T0800"), scope("a"));
  await cache.put(GROUP, "261016T0600", await chainKey("261016T0600"), scope("c"));
  for (const [name, t, held] of [
    ["a", "261014T0500", 1],
    ["b", "261015T0500", 0],
    ["c", "261016T0500", 1],
  ])
    assert.equal((await cache.candidates(GROUP, t, scope(name))).length, held, name);
});

test("expired windows leave before a new filing applies the global bound", async () => {
  const policy = expiry();
  const cache = new ChainKeyCache({
    entryKind: KIND,
    periodView: "none",
    maxWindows: 2,
    clock: policy.clock,
    evictionPolicy: policy.evictionPolicy,
  });
  await cache.put(GROUP, "261016T0600", await chainKey("261016T0600"), scope("b"));
  await cache.put(GROUP, "261014T0600", await chainKey("261014T0600"), scope("a"));
  policy.state.before = "261015T0000";
  await cache.put(GROUP, "261016T1800", await chainKey("261016T1800"), scope("c"));
  for (const [name, t] of [
    ["b", "261016T0500"],
    ["c", "261016T1700"],
  ]) {
    assert.equal((await cache.candidates(GROUP, t, scope(name))).length, 1);
  }
});

test("namespaces and kinds over one store keep their chain keys apart", async () => {
  const store = lossyStorage();
  /** @param {Record<string, unknown>} more */
  const sharing = (more) =>
    new ChainKeyCache({ entryKind: KIND, periodView: "none", storage: store.storage, ...more });
  await sharing({ namespace: "a" }).put(
    GROUP,
    "261014T0600",
    await chainKey("261014T0600"),
    scope("x"),
  );
  await sharing({}).put(GROUP, "261014T0600", await chainKey("261014T0600"), scope("x"));
  assert.equal(
    (await sharing({ namespace: "a" }).candidates(GROUP, "261014T0500", scope("x"))).length,
    1,
  );
  assert.deepEqual(
    await sharing({ namespace: "b" }).candidates(GROUP, "261014T0500", scope("x")),
    [],
    "another logical client on the store reads none of namespace a's chain keys",
  );
  // Another kind and an ordinary cache read the same store without refusing it.
  assert.deepEqual(
    await sharing({ entryKind: "otherChainKey" }).candidates(GROUP, "261014T0500", {
      ...scope("x"),
      partition: { kind: "otherChainKey", parts: ["x"] },
    }),
    [],
  );
  const ordinary = new ChainKeyCache({ storage: store.storage });
  const publisher = { publisher: "https://publisher.example", ...GEOMETRY };
  assert.deepEqual(await ordinary.candidates(GROUP, "261014T0500", publisher), []);
});

test("reconcile never restores an older chain key subsumed by a later filing", async () => {
  const store = lossyStorage();
  const cache = new ChainKeyCache({
    entryKind: KIND,
    periodView: "none",
    storage: store.storage,
    maxRivalsPerWindow: 3,
  });
  const rival = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(2),
    geometry: GEOMETRY,
  });
  await cache.put(GROUP, "261014T0600", await chainKey("261014T0600"), scope("a"));
  await cache.put(
    GROUP,
    "261014T0900",
    (await rival.chainCapability(GROUP, "261014T0900")).key,
    scope("a"),
  );
  await cache.put(GROUP, "261014T1000", await chainKey("261014T1000"), scope("a"));
  for (const key of await store.storage.keys()) await store.storage.remove(key);
  await cache.reconcile();
  const reloaded = new ChainKeyCache({
    entryKind: KIND,
    periodView: "none",
    storage: store.storage,
  });
  assert.equal((await reloaded.candidates(GROUP, "261014T0500", scope("a"))).length, 2);
  assert.deepEqual(
    reloaded
      .entries()
      .map(({ t }) => t)
      .sort(),
    ["261014T0900", "261014T1000"],
  );
});
