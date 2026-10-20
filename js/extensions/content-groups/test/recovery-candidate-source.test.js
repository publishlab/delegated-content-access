// @ts-check
//
// Content-group connector recovery through the shared resolver. The candidate
// source reads an item's named connector routes, asks the dedicated period-key
// cache and then the dedicated chain-key cache under the item's own
// content-name partitions, pads with the page's render ID and content name,
// and XORs each connector. The resolver authenticates, bounds and holds; the
// source checks the reader after every await.
//
// This extension's tests do not import the chain-keys extension: a recording
// stand-in answers the chain-key cache's read with derived period keys. The
// real chain-key cache under these partitions is covered in test-extensions/.

import test from "node:test";
import assert from "node:assert/strict";

import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { contentGroupCandidateSource } from "../core-client/contentGroupCandidateSource.js";
import { createContentGroupClient } from "../core-client/client.js";
import {
  CONTRACT,
  chainKeyPartition,
  itemPad,
  periodKeyPartition,
  settleLimits,
  xor16,
} from "../core-shared/construction.js";
import { CHAIN } from "./_lib/chainPort.js";

const PUBLISHER = "https://news.example";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
const RENDER_ID = "AAECAwQFBgcICQoLDA0ODw";
const T = "261014T1500";
const LIMITS = settleLimits();

/** @param {number} fill */
const bytes16 = (fill) => new Uint8Array(16).fill(fill);
/** @param {Uint8Array} a @param {Uint8Array} b */
const same = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {object} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", typ: "JWT", kid: "k1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

/**
 * A page whose items carry connectors for the given content keys and period
 * keys: `routes[name] = [{group, periodKey, contentKey}]`.
 * @param {Record<string, { group: string, periodKey: Uint8Array, contentKey: Uint8Array }[]>} routes
 * @param {Record<string, unknown>} [extra] - raw content records
 */
async function page(routes, extra = {}) {
  /** @type {Record<string, any>} */
  const contentData = { ...extra };
  for (const [contentName, list] of Object.entries(routes)) {
    /** @type {Record<string, string>} */
    const connectors = {};
    for (const { group, periodKey, contentKey } of list) {
      const pad = await itemPad(periodKey, { renderId: RENDER_ID, contentName });
      connectors[group] = base64urlEncode(xor16(contentKey, pad));
    }
    contentData[contentName] = {
      contentType: "text/html",
      nonce: base64urlEncode(new Uint8Array(12)),
      connectors,
    };
  }
  return new DcaData(
    {
      version: "1",
      renderPeriod: T,
      periodGeometry: GEOMETRY,
      resourceJWT: compactJwt({ origin: PUBLISHER, renderId: RENDER_ID }),
      issuerData: { issuer: { keyId: "k1", sealed: {} } },
      contentData,
    },
    { publisherOrigin: PUBLISHER },
  );
}

/** A chain-key cache stand-in: period keys by partition JSON, and a call log. */
function chainStandIn(/** @type {Record<string, Uint8Array[]>} */ byPartition = {}) {
  const calls = /** @type {any[]} */ ([]);
  return {
    calls,
    cache: {
      /** @param {string} group @param {string} t @param {any} context */
      async candidates(group, t, context) {
        calls.push({ group, t, context });
        const keys = (byPartition[JSON.stringify(context.partition)] ?? []).slice(
          0,
          context.chainCandidateBudget.remaining,
        );
        context.chainCandidateBudget.remaining -= keys.length;
        return keys;
      },
      // The client bundle files admitted answers through put; these tests file none.
      async put() {},
      async promote() {},
      async attempted() {},
      async clearReaderContext() {},
    },
  };
}

/** @param {any} periodKeyCache @param {any} chainKeyCache @param {Record<string, number>} [limits] */
function resolverWith(periodKeyCache, chainKeyCache, limits) {
  const source = contentGroupCandidateSource({
    chain: CHAIN,
    periodKeyCache,
    chainKeyCache,
    limits: settleLimits(limits),
  });
  return new ContentKeyResolver({ recoverySources: [source] });
}

/** @param {Uint8Array} expected @param {{ count: number }} [tries] */
const opens =
  (expected, tries = { count: 0 }) =>
  async (/** @type {string} */ _name, /** @type {Uint8Array|CryptoKey} */ candidate) => {
    tries.count++;
    return candidate instanceof Uint8Array && same(candidate, expected);
  };

test("a cached content-group period key recovers the item key through its connector", async () => {
  const periodKey = bytes16(1);
  const contentKey = bytes16(9);
  const dcaData = await page({ bodytext: [{ group: "politics", periodKey, contentKey }] });
  const periodKeyCache = new PeriodKeyCache({ entryKind: CONTRACT.keyKinds.periodKey });
  await periodKeyCache.put("politics", T, periodKey, {
    partition: periodKeyPartition(PUBLISHER, GEOMETRY, "bodytext", "politics"),
  });
  const { calls, cache } = chainStandIn();
  const resolver = resolverWith(periodKeyCache, cache);

  const result = await resolver.resolveAuthenticated(dcaData, ["bodytext"], opens(contentKey));
  assert.deepEqual(result.covered, ["bodytext"]);
  assert.deepEqual(result.origins[0].origin, {
    kind: "recovered-content-key",
    route: "period-key",
    group: "politics",
    t: T,
  });
  assert.equal(calls.length, 0, "a period-key route that opens leaves the chain route unread");
  assert.deepEqual(await resolver.contentKeyFor(dcaData, "bodytext"), contentKey);
});

test("a chain route opens when no period key does, asked under the item's own partition", async () => {
  const periodKey = bytes16(2);
  const contentKey = bytes16(8);
  const dcaData = await page({
    bodytext: [
      { group: "politics", periodKey, contentKey },
      { group: "sports", periodKey: bytes16(3), contentKey },
    ],
  });
  const partition = chainKeyPartition(PUBLISHER, GEOMETRY, "bodytext", "sports");
  const { calls, cache } = chainStandIn({ [JSON.stringify(partition)]: [bytes16(3)] });
  const resolver = resolverWith(
    new PeriodKeyCache({ entryKind: CONTRACT.keyKinds.periodKey }),
    cache,
  );

  const result = await resolver.resolveAuthenticated(dcaData, ["bodytext"], opens(contentKey));
  assert.deepEqual(result.covered, ["bodytext"]);
  assert.deepEqual(result.origins[0].origin, {
    kind: "recovered-content-key",
    route: "chain-key",
    group: "sports",
    t: T,
  });
  assert.deepEqual(
    calls.map(({ group, t, context }) => [group, t, context.chainsPerDay, context.periodMinutes]),
    [
      ["politics", T, 2, 60],
      ["sports", T, 2, 60],
    ],
  );
  assert.deepEqual(calls[1].context.partition, partition);
});

test("a key cached for bodytext is never tried for headline", async () => {
  const bodytextKey = bytes16(4);
  const contentKey = bytes16(7);
  const dcaData = await page({
    bodytext: [{ group: "politics", periodKey: bodytextKey, contentKey }],
    headline: [{ group: "politics", periodKey: bytes16(5), contentKey: bytes16(6) }],
  });
  const periodKeyCache = new PeriodKeyCache({ entryKind: CONTRACT.keyKinds.periodKey });
  await periodKeyCache.put("politics", T, bodytextKey, {
    partition: periodKeyPartition(PUBLISHER, GEOMETRY, "bodytext", "politics"),
  });
  const { cache } = chainStandIn({
    [JSON.stringify(chainKeyPartition(PUBLISHER, GEOMETRY, "bodytext", "politics"))]: [bodytextKey],
  });
  const resolver = resolverWith(periodKeyCache, cache);
  const tries = { count: 0 };
  const result = await resolver.resolveAuthenticated(
    dcaData,
    ["headline"],
    opens(bytes16(6), tries),
  );
  assert.deepEqual(result.missing, ["headline"]);
  assert.equal(tries.count, 0, "a period key of bodytext must not be tried for headline");
});

test("reset while the source awaits a cache: no further cache read and no candidate", async () => {
  /** @type {(() => void)|null} */
  let release = null;
  let periodReads = 0;
  // This stand-in does not fence itself, so only the source's own check stops it.
  const periodKeyCache = {
    async candidatesAt() {
      periodReads++;
      if (periodReads === 1)
        await new Promise((resolve) => {
          release = () => resolve(undefined);
        });
      return [];
    },
    async attempted() {},
    async clearReaderContext() {},
  };
  const { calls, cache } = chainStandIn();
  const dcaData = await page({
    bodytext: [
      { group: "politics", periodKey: bytes16(1), contentKey: bytes16(2) },
      { group: "sports", periodKey: bytes16(1), contentKey: bytes16(2) },
    ],
  });
  const resolver = resolverWith(periodKeyCache, cache);
  const tries = { count: 0 };
  const pending = resolver.resolveAuthenticated(dcaData, ["bodytext"], opens(bytes16(2), tries));
  while (release === null) await new Promise((resolve) => setImmediate(resolve));
  const clearing = resolver.clearReaderContext();
  /** @type {() => void} */ (release)();
  await assert.rejects(pending, (error) => /** @type {any} */ (error)?.code === "context_retired");
  await clearing;
  assert.equal(
    periodReads + calls.length,
    1,
    "missed reset fence: the source read a cache under a retired reader",
  );
  assert.equal(tries.count, 0);
});

test("an item without an admitted connector map, geometry or publisher yields nothing", async () => {
  const { calls, cache } = chainStandIn();
  const periodKeyCache = new PeriodKeyCache({ entryKind: CONTRACT.keyKinds.periodKey });
  const dcaData = await page(
    {},
    {
      ordinary: { contentType: "text/html", nonce: base64urlEncode(new Uint8Array(12)) },
      emptyMap: {
        contentType: "text/html",
        nonce: base64urlEncode(new Uint8Array(12)),
        connectors: {},
      },
      listed: {
        contentType: "text/html",
        nonce: base64urlEncode(new Uint8Array(12)),
        connectors: [base64urlEncode(bytes16(1))],
      },
    },
  );
  const resolver = resolverWith(periodKeyCache, cache);
  const result = await resolver.resolveAuthenticated(
    dcaData,
    ["ordinary", "emptyMap", "listed", "absent"],
    async () => true,
  );
  assert.deepEqual(result.covered, []);
  assert.equal(calls.length, 0);

  const anonymous = new DcaData({
    ...dcaData.toObject(),
    contentData: (
      await page({
        bodytext: [{ group: "politics", periodKey: bytes16(1), contentKey: bytes16(2) }],
      })
    ).toObject().contentData,
  });
  assert.deepEqual(
    (await resolver.resolveAuthenticated(anonymous, ["bodytext"], async () => true)).covered,
    [],
  );
  assert.equal(calls.length, 0, "no publisher, no partition to read");
});

test("maxTrialsPerItem bounds the source's candidates", async () => {
  const contentKey = bytes16(9);
  const dcaData = await page({
    bodytext: [{ group: "politics", periodKey: bytes16(1), contentKey }],
  });
  const partition = chainKeyPartition(PUBLISHER, GEOMETRY, "bodytext", "politics");
  const { cache } = chainStandIn({
    [JSON.stringify(partition)]: [bytes16(20), bytes16(21), bytes16(1)],
  });
  const resolver = resolverWith(
    new PeriodKeyCache({ entryKind: CONTRACT.keyKinds.periodKey }),
    cache,
    { maxTrialsPerItem: 2 },
  );
  const tries = { count: 0 };
  const result = await resolver.resolveAuthenticated(
    dcaData,
    ["bodytext"],
    opens(contentKey, tries),
  );
  assert.deepEqual(result.missing, ["bodytext"]);
  assert.equal(tries.count, 2);
});

test("a period key filed under a response lease opens through that response's attempt", async () => {
  const periodKey = bytes16(1);
  const contentKey = bytes16(9);
  const dcaData = await page({ bodytext: [{ group: "politics", periodKey, contentKey }] });
  const client = createContentGroupClient({
    chain: CHAIN,
    createPeriodKeyCache: (config) => new PeriodKeyCache(config),
    createChainKeyCache: () => chainStandIn().cache,
  });
  const consumer = {
    name: "contentGroups",
    /** @param {any} section */
    keyValues: (section) => [section.periodKeys.bodytext.politics[T]],
    /** @param {any} section @param {any} context */
    async admit(section, context) {
      const opened = await context.openKey(section.periodKeys.bodytext.politics[T], {
        keyKind: CONTRACT.keyKinds.periodKey,
        raw: true,
      });
      await client.periodKeyCache.put("politics", T, opened.key, {
        partition: periodKeyPartition(PUBLISHER, GEOMETRY, "bodytext", "politics"),
        lease: context.lease,
      });
      return { accepted: 1, issues: [] };
    },
  };
  const resolver = new ContentKeyResolver({
    recoverySources: [client.recoverySource],
    responseSections: [consumer],
  });
  const { ResponseAssociation } = await import("../../../core-client/ResponseAssociation.js");
  const application = await resolver.applyResponse(
    dcaData,
    "issuer",
    {
      contentGroups: {
        periodKeys: { bodytext: { politics: { [T]: base64urlEncode(periodKey) } } },
      },
    },
    new ResponseAssociation(dcaData, "issuer", {
      version: "1",
      issuerName: "issuer",
      resourceJWT: dcaData.resourceJWT,
      keyId: "k1",
      sealed: {},
      requestedContentGroups: { bodytext: ["politics"] },
    }),
  );
  assert.equal(application.accepted, 1);
  const result = await resolver.resolveAuthenticated(
    dcaData,
    ["bodytext"],
    opens(contentKey),
    application,
  );
  assert.deepEqual(result.covered, ["bodytext"]);
});

test("the client bundle builds the two dedicated caches, the source and the kind descriptors", async () => {
  /** @type {any[]} */
  const periodConfigs = [];
  /** @type {any[]} */
  const chainConfigs = [];
  const storage = {
    get: async () => undefined,
    set: async () => {},
    keys: async () => [],
    remove: async () => {},
  };
  const { cache } = chainStandIn();
  const client = createContentGroupClient({
    chain: CHAIN,
    limits: {
      maxCachedWindows: 100,
      maxWindowsPerGroup: 3,
      maxRivalsPerWindow: 2,
      maxTrialsPerItem: 7,
      maxResponseMembers: 300,
    },
    storage,
    namespace: "reader",
    createPeriodKeyCache: (config) => {
      periodConfigs.push(config);
      return new PeriodKeyCache(config);
    },
    createChainKeyCache: (config) => {
      chainConfigs.push(config);
      return cache;
    },
  });
  assert.deepEqual(periodConfigs, [
    { entryKind: CONTRACT.keyKinds.periodKey, maxEntries: 100, storage, namespace: "reader" },
  ]);
  assert.deepEqual(chainConfigs, [
    {
      entryKind: CONTRACT.keyKinds.chainKey,
      periodView: "none",
      maxRivalsPerWindow: 2,
      maxMembersPerMessage: 300,
      maxMembersPerFamily: 3,
      maxWindowsPerFamily: 3,
      maxWindows: 100,
      storage,
      namespace: "reader",
    },
  ]);
  assert.equal(client.chainKeyCache, cache);
  assert.equal(client.recoverySource.maxTrialsPerItem, 7);
  assert.equal(client.limits.maxTrialsPerItem, 7);
  assert.deepEqual(client.keyKinds, {
    [CONTRACT.keyKinds.periodKey]: { width: 16, open: "raw" },
    [CONTRACT.keyKinds.chainKey]: { width: 16, open: "raw" },
  });
  assert.ok(Object.isFrozen(client) && Object.isFrozen(client.keyKinds));

  for (const bad of [
    { chain: null },
    { createPeriodKeyCache: undefined },
    { createChainKeyCache: "no" },
    { limits: { maxScopes: 2 } },
    { namespace: "reader" },
  ])
    assert.throws(() =>
      createContentGroupClient(
        /** @type {any} */ ({
          chain: CHAIN,
          createPeriodKeyCache: (/** @type {any} */ config) => new PeriodKeyCache(config),
          createChainKeyCache: () => cache,
          ...bad,
        }),
      ),
    );
});

test("the client bundle refuses a cache that lacks a read, put, attempted or clearReaderContext", () => {
  // A host cache that forwards only some operations would otherwise pass
  // construction and fault at the first answered open or at reset.
  /** @param {object} target @param {string} hidden */
  const without = (target, hidden) =>
    new Proxy(target, {
      get(inner, name) {
        if (name === hidden) return undefined;
        const value = Reflect.get(inner, name, inner);
        return typeof value === "function" ? value.bind(inner) : value;
      },
    });
  /** @param {{ period?: string, chain?: string, promote?: unknown }} strip */
  const build = ({ period, chain, promote }) => {
    const { cache } = chainStandIn();
    const chainCache = promote === undefined ? cache : { ...cache, promote };
    return createContentGroupClient({
      chain: CHAIN,
      createPeriodKeyCache: (config) => {
        const real = new PeriodKeyCache(config);
        return period === undefined ? real : without(real, period);
      },
      createChainKeyCache: () => (chain === undefined ? chainCache : without(chainCache, chain)),
    });
  };
  assert.ok(build({}));
  for (const period of ["candidatesAt", "put", "attempted", "clearReaderContext"])
    assert.throws(
      () => build({ period }),
      { code: "bad_config" },
      `period-key cache without ${period}`,
    );
  for (const chain of ["candidates", "put", "attempted", "clearReaderContext"])
    assert.throws(
      () => build({ chain }),
      { code: "bad_config" },
      `chain-key cache without ${chain}`,
    );
  // promote stays optional, as for the resolver's ordinary chain cache, but answers as a function.
  assert.ok(build({ chain: "promote" }));
  assert.throws(() => build({ promote: "later" }), { code: "bad_config" });
});

test("the candidate source refuses a cache it could not complete or reset", () => {
  const { cache } = chainStandIn();
  const periodKeyCache = {
    async candidatesAt() {
      return [];
    },
    async attempted() {},
    async clearReaderContext() {},
  };
  assert.ok(
    contentGroupCandidateSource({
      chain: CHAIN,
      periodKeyCache,
      chainKeyCache: cache,
      limits: LIMITS,
    }),
  );
  for (const [side, hidden] of /** @type {const} */ ([
    ["period", "attempted"],
    ["period", "clearReaderContext"],
    ["chain", "attempted"],
    ["chain", "clearReaderContext"],
  ])) {
    const stripped = { ...(side === "period" ? periodKeyCache : cache), [hidden]: undefined };
    assert.throws(
      () =>
        contentGroupCandidateSource({
          chain: CHAIN,
          periodKeyCache: side === "period" ? stripped : periodKeyCache,
          chainKeyCache: side === "chain" ? stripped : cache,
          limits: LIMITS,
        }),
      { code: "bad_config" },
      `${side} without ${hidden}`,
    );
  }
});

test("the source's reset reaches both dedicated caches", async () => {
  let cleared = 0;
  const counting = {
    async candidatesAt() {
      return [];
    },
    async attempted() {},
    async clearReaderContext() {
      cleared++;
    },
  };
  const { cache } = chainStandIn();
  const chainCache = {
    ...cache,
    async clearReaderContext() {
      cleared++;
    },
  };
  const source = contentGroupCandidateSource({
    chain: CHAIN,
    periodKeyCache: counting,
    chainKeyCache: chainCache,
    limits: LIMITS,
  });
  await new ContentKeyResolver({ recoverySources: [source] }).clearReaderContext();
  assert.equal(cleared, 2);
});

test("the candidate source forwards the obtaining lease to optional chain promotion", async () => {
  const context = { lease: {} };
  const promoted = [];
  const { cache } = chainStandIn();
  const source = contentGroupCandidateSource({
    chain: CHAIN,
    periodKeyCache: new PeriodKeyCache({ entryKind: CONTRACT.keyKinds.periodKey }),
    chainKeyCache: {
      ...cache,
      async promote(value) {
        promoted.push(value);
      },
    },
    limits: LIMITS,
  });
  await source.promote?.(context);
  assert.deepEqual(promoted, [context]);
  assert.equal(promoted[0], context);
  const { promote: _promote, ...withoutPromotion } = cache;
  await contentGroupCandidateSource({
    chain: CHAIN,
    periodKeyCache: new PeriodKeyCache({ entryKind: CONTRACT.keyKinds.periodKey }),
    chainKeyCache: withoutPromotion,
    limits: LIMITS,
  }).promote?.(context);
});

for (const hook of ["attempted", "clearReaderContext"]) {
  test(`candidate source ${hook} joins both caches and preserves a cleanup rejection`, async () => {
    for (const failingSide of ["period", "chain"]) {
      const context = { lease: {} };
      const fault = new Error(`${failingSide} cleanup failed`);
      const calls = [];
      let release = () => {};
      const gate = new Promise((resolve) => {
        release = () => resolve(undefined);
      });
      const cleanup = (side) => async (value) => {
        calls.push({ side, value });
        if (side === failingSide) throw fault;
        await gate;
      };
      const { cache } = chainStandIn();
      const source = contentGroupCandidateSource({
        chain: CHAIN,
        periodKeyCache: {
          async candidatesAt() {
            return [];
          },
          async attempted() {},
          async clearReaderContext() {},
          [hook]: cleanup("period"),
        },
        chainKeyCache: { ...cache, [hook]: cleanup("chain") },
        limits: LIMITS,
      });
      const pending =
        hook === "attempted" ? source.attempted?.(context) : source.clearReaderContext?.();
      let settled = false;
      const rejected = assert
        .rejects(pending, (error) => error === fault)
        .then(() => {
          settled = true;
        });
      assert.deepEqual(
        calls.map(({ side }) => side),
        ["period", "chain"],
      );
      if (hook === "attempted") for (const call of calls) assert.equal(call.value, context);
      await Promise.resolve();
      assert.equal(settled, false, "a rejected owner does not abandon its pending peer");
      release();
      await rejected;
    }
  });
}

test("ordinary period candidates and later chain routes share one item's finite work allowance", async () => {
  const contentKey = bytes16(9);
  const periodKey = bytes16(1);
  const dcaData = await page({ bodytext: [{ group: "politics", periodKey, contentKey }] });
  const periodKeyCache = new PeriodKeyCache({ entryKind: CONTRACT.keyKinds.periodKey });
  for (const fill of [20, 21])
    await periodKeyCache.put("politics", T, bytes16(fill), {
      partition: periodKeyPartition(PUBLISHER, GEOMETRY, "bodytext", "politics"),
    });
  const partition = chainKeyPartition(PUBLISHER, GEOMETRY, "bodytext", "politics");
  const { calls, cache } = chainStandIn({ [JSON.stringify(partition)]: [periodKey] });
  const low = resolverWith(periodKeyCache, cache, { maxTrialsPerItem: 2 });
  const trials = { count: 0 };
  assert.deepEqual(
    (await low.resolveAuthenticated(dcaData, ["bodytext"], opens(contentKey, trials))).missing,
    ["bodytext"],
  );
  assert.equal(trials.count, 2);
  assert.equal(
    calls.length,
    0,
    "exhaustion in ordinary candidates leaves chain derivation uncalled",
  );
  const enough = resolverWith(periodKeyCache, cache, { maxTrialsPerItem: 3 });
  assert.deepEqual(
    (await enough.resolveAuthenticated(dcaData, ["bodytext"], opens(contentKey))).covered,
    ["bodytext"],
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0].context.chainCandidateBudget.remaining, 0);
});
