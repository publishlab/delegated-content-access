// @ts-check
//
// What the frozen client cache costs and what it may keep: the price of
// reading one coordinate twice, the size of the derived period-key memo, and which
// named rival bound governs which candidate kind.
//
// Then the refusals and the eviction contract: which constructions and which
// public store and read shapes the cache declines, that a partitioned family
// carries its geometry, and what one injected policy sees of both logical
// period-key pools.
//
// Elsewhere and not repeated here: client-explicit-geometry.test.js covers
// partitioning by publisher, geometry and issuer, rival admission and
// subsumption, response-lease privacy and the whole resolver path.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { encrypt } from "../../../core-shared/aead.js";
import { base64urlDecode, base64urlEncode } from "../../../core-shared/codec.js";
import { attemptContentKeyWrap } from "../../../core-client/contentKeyWrapAttempt.js";
import { keyByIssuer, PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { evictAfterSixHours } from "../../../adapter-client/periodKeyEviction.js";
import { Clock } from "../../../demo/actors/Clock.js";
import {
  CHAIN_KEY_PROFILE,
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  MAX_RIVAL_CHAIN_CANDIDATES,
  MAX_RIVAL_PERIOD_KEY_CANDIDATES,
} from "../core-shared/chainKeyConstruction.js";
import { MAX_MEMOIZED_PERIOD_KEYS, ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";

const PUB = "https://publisher.example";
const GROUP = "premium";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const CONTEXT = Object.freeze({ publisher: PUB, ...GEOMETRY });
const TERMINAL_T = "251023T2345";
const TARGET_T = "251023T1415";
const VECTORS = JSON.parse(
  readFileSync(new URL("./fixtures/dca-profile-chain-keys.vectors.json", import.meta.url), "utf8"),
);

// The vector set states its lifecycle before a byte of it is used: a set
// without `setIdentity`, `status` and `semanticWidths` is ambiguous about which
// width it records, and this loader does not accept one.
assert.equal(VECTORS.setIdentity, CHAIN_KEY_PROFILE);
assert.equal(VECTORS.status, "canonical-16");
assert.equal(VECTORS.semanticWidths.chainKey, 16);
assert.equal(VECTORS.semanticWidths.periodKey, 16);
assert.equal(VECTORS.semanticWidths.periodKeyWrapAlgorithm, "AES-128-GCM");
const C1 = VECTORS.cases.find((/** @type {any} */ entry) => entry.id === "c1");

/**
 * HKDF invocations spent by one call, counted at the WebCrypto boundary the
 * construction derives through.
 *
 * @param {() => Promise<unknown>} run
 * @returns {Promise<number>}
 */
async function derivations(run) {
  const subtle = globalThis.crypto.subtle;
  const deriveBits = subtle.deriveBits;
  let count = 0;
  subtle.deriveBits = async function (/** @type {any[]} */ ...args) {
    count++;
    return deriveBits.apply(this, /** @type {any} */ (args));
  };
  try {
    await run();
  } finally {
    subtle.deriveBits = deriveBits;
  }
  return count;
}

/** @param {number} count @param {number} fill */
function rivals(count, fill) {
  return Array.from({ length: count }, (unused, index) =>
    periodFamilyGeneration({
      keyDerivationSecret: new Uint8Array(32).fill(index + fill),
      geometry: GEOMETRY,
    }),
  );
}

for (const strategy of ["retain", "expand"]) {
  test(`${strategy} walks one coordinate once and answers every repeat read from what it derived`, async () => {
    const cache = new ChainKeyCache({ strategy: /** @type {'retain'|'expand'} */ (strategy) });
    const filing = await derivations(() =>
      cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), CONTEXT),
    );

    const reads = [];
    for (let index = 0; index < 3; index++) {
      /** @type {any} */
      let answered;
      reads.push(
        await derivations(async () => {
          answered = await cache.candidates(GROUP, TARGET_T, CONTEXT);
        }),
      );
      assert.deepEqual(
        answered.map(base64urlEncode),
        [C1.periodKey],
        `read ${index} answers the vector period key`,
      );
    }

    if (strategy === "expand") {
      assert.ok(filing > 0, `expansion walks the window once while filing, spent ${filing}`);
      assert.deepEqual(reads, [0, 0, 0], "and every read is a lookup");
      return;
    }
    assert.equal(filing, 0, "retaining a chain key derives nothing while filing");
    assert.ok(reads[0] > 0, "the first read walks back to the coordinate");
    assert.deepEqual(
      reads.slice(1),
      [0, 0],
      `a memoized period key answers without walking again, spent ${reads.join()}`,
    );
  });
}

test("retain caps its derived period-key memo and leaves the chain key that rebuilds it", async () => {
  const cache = new ChainKeyCache({ strategy: "retain", maxMemoPeriodKeys: 3 });
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), CONTEXT);
  const coordinates = ["251023T1200", "251023T1215", "251023T1230", "251023T1245", "251023T1300"];

  for (const t of coordinates) {
    assert.equal((await cache.candidates(GROUP, t, CONTEXT)).length, 1, `${t} is derivable`);
  }

  assert.deepEqual(
    cache
      .entries()
      .filter(({ kind }) => kind === "period-key")
      .map(({ t }) => t)
      .sort(),
    coordinates.slice(2),
    "the memo holds the three most recently derived coordinates",
  );
  assert.equal(
    cache.entries().filter(({ kind }) => kind === "chain-key").length,
    1,
    "and the cap never reaches the retained chain key the memo came from",
  );

  assert.ok(
    (await derivations(() => cache.candidates(GROUP, coordinates[0], CONTEXT))) > 0,
    "an evicted coordinate costs its walk again",
  );
  assert.equal(
    await derivations(() => cache.candidates(GROUP, coordinates[4], CONTEXT)),
    0,
    "a memoized one does not",
  );
});

test("expand holds its derived period keys to the default ceiling without an eviction policy", async () => {
  const cache = new ChainKeyCache({ strategy: "expand" });
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: GEOMETRY,
  });
  for (const day of [
    "251020",
    "251021",
    "251022",
    "251023",
    "251024",
    "251025",
    "251026",
    "251027",
  ]) {
    for (const terminal of ["1145", "2345"]) {
      const t = `${day}T${terminal}`;
      await cache.put(GROUP, t, (await generation.chainCapability(GROUP, t)).key, CONTEXT);
    }
  }

  assert.equal(
    cache.entries().length,
    MAX_MEMOIZED_PERIOD_KEYS,
    "sixteen expanded windows reach the ceiling instead of growing to 768 period keys",
  );
});

test("expand evicts its least recently derived period key at a small ceiling", async () => {
  const cache = new ChainKeyCache({ strategy: "expand", maxMemoPeriodKeys: 4 });
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(3),
    geometry: GEOMETRY,
  });

  for (const t of ["251023T0030", "251024T0030"]) {
    await cache.put(GROUP, t, (await generation.chainCapability(GROUP, t)).key, CONTEXT);
  }

  assert.deepEqual(
    cache
      .entries()
      .map(({ t }) => t)
      .sort(),
    ["251023T0030", "251024T0000", "251024T0015", "251024T0030"],
    "the oldest coordinates of the first expansion go first",
  );
});

test("expand refiling one chain key never crowds a rival's period key out", async () => {
  const cache = new ChainKeyCache({ strategy: "expand" });
  const [rival, refiled] = rivals(2, 31);
  const file = async (/** @type {any} */ generation) =>
    cache.put(
      GROUP,
      "251023T0600",
      (await generation.chainCapability(GROUP, "251023T0600")).key,
      CONTEXT,
    );
  await file(rival);
  for (let index = 0; index < 4; index++) await file(refiled);
  assert.deepEqual(
    new Set((await cache.candidates(GROUP, "251023T0500", CONTEXT)).map(base64urlEncode)),
    new Set([
      base64urlEncode(await rival.periodKey(GROUP, "251023T0500")),
      base64urlEncode(await refiled.periodKey(GROUP, "251023T0500")),
    ]),
  );
});

test("a pending grant is tried without entering the memo", async () => {
  const cache = new ChainKeyCache();
  const lease = {};
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), { ...CONTEXT, lease });

  /** @type {any} */
  let first;
  const walked = await derivations(async () => {
    first = await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease });
  });
  assert.deepEqual(
    first.map(base64urlEncode),
    [C1.periodKey],
    "the response-private grant answers its own read",
  );
  assert.deepEqual(cache.entries(), [], "and leaves nothing behind in the shared store");
  assert.equal(
    await derivations(() => cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease })),
    walked,
    `a second read of the same coordinate walks again, spent ${walked}`,
  );
});

test("a budgeted read of a stored rival leaves the other rival for the next read", async () => {
  /** @type {Map<string, string>} */
  const values = new Map();
  const storage = {
    async get(/** @type {string} */ key) {
      return values.get(key);
    },
    async set(/** @type {string} */ key, /** @type {string} */ value) {
      values.set(key, value);
    },
    async keys() {
      return [...values.keys()];
    },
    async remove(/** @type {string} */ key) {
      values.delete(key);
    },
  };
  const cache = new ChainKeyCache({ storage });
  const generations = rivals(2, 41);
  for (const generation of generations)
    await cache.put(
      GROUP,
      TERMINAL_T,
      (await generation.chainCapability(GROUP, TERMINAL_T)).key,
      CONTEXT,
    );

  const budget = { remaining: 1 };
  const first = await cache.candidates(GROUP, TARGET_T, {
    ...CONTEXT,
    chainCandidateBudget: budget,
  });
  assert.equal(first.length, 1, "the budget walks one rival");
  // The store refresh before each read rebuilds the held rivals; each keeps its own identity.
  assert.deepEqual(
    new Set((await cache.candidates(GROUP, TARGET_T, CONTEXT)).map(base64urlEncode)),
    new Set(
      await Promise.all(
        generations.map(async (generation) =>
          base64urlEncode(await generation.periodKey(GROUP, TARGET_T)),
        ),
      ),
    ),
    "the next read walks the rival the budget left",
  );
});

test("a leased re-delivery keeps the held chain key ahead of a rival filed before attempted()", async () => {
  const cache = new ChainKeyCache({ maxRivalsPerWindow: 2 });
  const [held, crowded, later] = rivals(3, 51);
  const file = async (/** @type {any} */ generation, /** @type {string} */ t, context = {}) =>
    cache.put(GROUP, t, (await generation.chainCapability(GROUP, t)).key, {
      ...CONTEXT,
      ...context,
    });
  await file(held, "251023T1000");
  await file(crowded, "251023T1000");
  const lease = {};
  // The issuer re-delivers the held family at a lower cutoff; a rival arrives before completion.
  await file(held, "251023T0800", { lease });
  await file(later, "251023T1000");
  await cache.attempted({ lease });
  assert.deepEqual(
    new Set((await cache.candidates(GROUP, "251023T0900", CONTEXT)).map(base64urlEncode)),
    new Set([
      base64urlEncode(await held.periodKey(GROUP, "251023T0900")),
      base64urlEncode(await later.periodKey(GROUP, "251023T0900")),
    ]),
    "the re-delivered chain key still answers above its re-delivered cutoff",
  );
});

test("each named rival bound governs its own kind, and the eight-key widening lasts one read", async () => {
  const cache = new ChainKeyCache();
  const generations = rivals(8, 61);
  const periodKeyOf = (/** @type {any} */ generation) => generation.periodKey(GROUP, TARGET_T);
  const file = async (/** @type {any} */ generation) =>
    cache.put(
      GROUP,
      TERMINAL_T,
      (await generation.chainCapability(GROUP, TERMINAL_T)).key,
      CONTEXT,
    );

  for (const generation of generations.slice(0, 4)) await file(generation);
  const first = await cache.candidates(GROUP, TARGET_T, CONTEXT);
  assert.equal(
    first.length,
    MAX_RIVAL_CHAIN_CANDIDATES,
    "four retained rivals answer with four period keys",
  );

  for (const generation of generations.slice(4)) await file(generation);
  assert.equal(
    cache.entries().filter(({ kind }) => kind === "chain-key").length,
    MAX_RIVAL_CHAIN_CANDIDATES,
    "the four newest unrelated chain keys are what one partition and window retains",
  );

  /** @type {any} */
  let second;
  const walked = await derivations(async () => {
    second = await cache.candidates(GROUP, TARGET_T, CONTEXT);
  });
  assert.deepEqual(
    new Set(second.map(base64urlEncode)),
    new Set(
      await Promise.all(
        generations.map(async (generation) => base64urlEncode(await periodKeyOf(generation))),
      ),
    ),
    "the newest chain rivals are walked and the memo of each evicted one is still tried",
  );
  assert.equal(second.length, MAX_RIVAL_CHAIN_CANDIDATES + MAX_RIVAL_PERIOD_KEY_CANDIDATES);
  const chainBound = MAX_RIVAL_CHAIN_CANDIDATES * (2 * C1.N - 1);
  assert.equal(
    walked,
    MAX_RIVAL_CHAIN_CANDIDATES * 39,
    `four walks of 38 backward steps and one Leaf derivation, inside the ${chainBound} the chain bound allows`,
  );

  /** @type {any} */
  let third;
  assert.equal(
    await derivations(async () => {
      third = await cache.candidates(GROUP, TARGET_T, CONTEXT);
    }),
    0,
    "and once every retained rival has a memo, a further read walks nothing",
  );
  assert.equal(
    third.length,
    MAX_RIVAL_PERIOD_KEY_CANDIDATES,
    "the four older memos left with the chain keys that would rebuild them, so the widening held for one read",
  );
  assert.equal(
    (await cache.candidates(GROUP, TARGET_T, CONTEXT)).length,
    MAX_RIVAL_PERIOD_KEY_CANDIDATES,
    "and the reads after it answer with those same four",
  );
});

// Emergency rollover inside one window (spec-profile--chain-keys.md, 19 and
// 19.1): the replacement secret files a cutoff in the window the old
// generation already holds. The cache walks the later cutoff back to the
// earlier one and compares bytes; only equal bytes subsume. Each position order
// reaches a different branch of that comparison, so the test files both.
for (const [order, oldCutoffT, replacementCutoffT] of [
  ["later", "251023T1500", "251023T2000"],
  ["earlier", "251023T2000", "251023T1500"],
]) {
  test(`mid-window rollover keeps both generations, replacement cutoff ${order}`, async () => {
    const [old, replacement] = rivals(2, 17);
    const chainKeyOf = async (/** @type {any} */ generation, /** @type {string} */ t) =>
      (await generation.chainCapability(GROUP, t)).key;

    // Control: the old generation at both cutoffs is one family, so the
    // byte comparison collapses the pair into one retained chain key.
    const sameGeneration = new ChainKeyCache();
    await sameGeneration.put(GROUP, oldCutoffT, await chainKeyOf(old, oldCutoffT), CONTEXT);
    await sameGeneration.put(
      GROUP,
      replacementCutoffT,
      await chainKeyOf(old, replacementCutoffT),
      CONTEXT,
    );
    assert.equal(
      sameGeneration.entries().filter(({ kind }) => kind === "chain-key").length,
      1,
      "one generation at two cutoffs of one window keeps one retained chain key",
    );

    const cache = new ChainKeyCache();
    await cache.put(GROUP, oldCutoffT, await chainKeyOf(old, oldCutoffT), CONTEXT);
    await cache.put(
      GROUP,
      replacementCutoffT,
      await chainKeyOf(replacement, replacementCutoffT),
      CONTEXT,
    );
    assert.deepEqual(
      cache
        .entries()
        .filter(({ kind }) => kind === "chain-key")
        .map(({ t }) => t)
        .sort(),
      [oldCutoffT, replacementCutoffT].sort(),
      "the backward walk across secrets yields other bytes, so both chain keys stay",
    );

    const oldPeriodKey = await old.periodKey(GROUP, TARGET_T);
    const replacementPeriodKey = await replacement.periodKey(GROUP, TARGET_T);
    assert.notEqual(base64urlEncode(oldPeriodKey), base64urlEncode(replacementPeriodKey));
    const candidates = await cache.candidates(GROUP, TARGET_T, CONTEXT);
    assert.deepEqual(
      candidates.map(base64urlEncode),
      [replacementPeriodKey, oldPeriodKey].map(base64urlEncode),
      `both period keys at ${TARGET_T}, before either cutoff, newest filed first`,
    );

    // Each render wraps its own content key under its own generation's period key
    // at the same coordinate; the trial opens each wrap with one candidate.
    const nonce = new Uint8Array(12).fill(1);
    for (const { render, periodKey, contentKey } of [
      { render: "old", periodKey: oldPeriodKey, contentKey: new Uint8Array(16).fill(0x0a) },
      { render: "new", periodKey: replacementPeriodKey, contentKey: new Uint8Array(16).fill(0x0b) },
    ]) {
      const entry = {
        t: TARGET_T,
        nonce: base64urlEncode(nonce),
        key: base64urlEncode(await encrypt(periodKey, nonce, contentKey)),
      };
      const opened = [];
      for (const candidate of candidates) {
        const key = await attemptContentKeyWrap(entry, candidate);
        opened.push(key instanceof Uint8Array ? base64urlEncode(key) : key);
      }
      assert.deepEqual(
        opened,
        render === "new"
          ? [base64urlEncode(contentKey), null]
          : [null, base64urlEncode(contentKey)],
        `the ${render}-render wrap opens under its own generation's period key and no other`,
      );
    }
  });
}

test("the chain cache refuses unusable and unknown options", async (t) => {
  assert.throws(
    () =>
      new ChainKeyCache({
        storage: /** @type {any} */ ({
          get() {},
          set() {},
          keys() {
            return [];
          },
        }),
      }),
    { code: "bad_config" },
  );
  const clock = new Clock("2025-10-23T14:20:00Z");
  for (const [name, config, code, message] of [
    [
      "unknown strategy",
      { strategy: "discard" },
      "bad_config",
      'unknown chain-key cache strategy "discard"',
    ],
    [
      "invalid clock",
      { clock: {}, evictionPolicy: () => false },
      "bad_config",
      "a chain-cache clock answers now()",
    ],
    [
      "invalid eviction callback",
      { clock, evictionPolicy: true },
      "bad_config",
      "a chain-cache evictionPolicy is a callback",
    ],
    [
      "clock without eviction",
      { clock },
      "bad_config",
      "a chain-cache evictionPolicy and clock are configured together",
    ],
    [
      "eviction without clock",
      { evictionPolicy: () => false },
      "bad_config",
      "a chain-cache evictionPolicy and clock are configured together",
    ],
    ["invalid keyBy", { keyBy: "issuer" }, "bad_config", "a chain-cache keyBy is a callback"],
    [
      "fractional memo ceiling",
      { maxMemoPeriodKeys: 2.5 },
      "bad_config",
      "maxMemoPeriodKeys is a whole number of period keys, at least one; got 2.5",
    ],
    [
      "empty memo ceiling",
      { maxMemoPeriodKeys: 0 },
      "bad_config",
      "maxMemoPeriodKeys is a whole number of period keys, at least one; got 0",
    ],
    [
      "unknown option",
      { evictionPolciy: () => false },
      "unsupported_option",
      "ChainKeyCache has no evictionPolciy yet, and will not pretend to",
    ],
  ]) {
    await t.test(name, () => {
      assert.throws(() => new ChainKeyCache(/** @type {any} */ (config)), { code, message });
    });
  }

  const cache = new ChainKeyCache({
    strategy: "retain",
    clock,
    evictionPolicy: () => false,
    keyBy: keyByIssuer,
    maxMemoPeriodKeys: 8,
  });
  const context = { ...CONTEXT, issuerName: "issuer-a" };
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), context);
  assert.deepEqual(
    (await cache.candidates(GROUP, TARGET_T, context)).map(base64urlEncode),
    [C1.periodKey],
    "every dependency together still stores and reads one family",
  );
});

test("chain cache public stores and reads refuse unusable key and context shapes", async (t) => {
  const cache = new ChainKeyCache();
  const partitioned = new ChainKeyCache({ keyBy: keyByIssuer });
  const badFamily = new ChainKeyCache({ keyBy: () => "" });
  const key = base64urlDecode(C1.rootChainKey);
  for (const [name, attempt, message] of [
    [
      "short chain key",
      () => cache.put(GROUP, TERMINAL_T, new Uint8Array(31), CONTEXT),
      "a chain-key grant of this profile is 16 key bytes",
    ],
    [
      "non-byte chain key",
      () => cache.put(GROUP, TERMINAL_T, /** @type {any} */ (null), CONTEXT),
      "a chain-key grant of this profile is 16 key bytes",
    ],
    [
      "empty access group",
      () => cache.put("", TERMINAL_T, key, CONTEXT),
      "a chain cache entry needs an accessGroup",
    ],
    [
      "store without publisher",
      () => cache.put(GROUP, TERMINAL_T, key, { ...CONTEXT, publisher: undefined }),
      "a chain cache entry files under its publisher",
    ],
    [
      "read without publisher",
      () => cache.candidates(GROUP, TARGET_T, { ...CONTEXT, publisher: undefined }),
      "a chain cache entry files under its publisher",
    ],
    [
      "store without geometry",
      () => cache.put(GROUP, TERMINAL_T, key, { publisher: PUB }),
      "a chain cache entry needs explicit chainsPerDay and periodMinutes",
    ],
    [
      "read without geometry",
      () => cache.candidates(GROUP, TARGET_T, { publisher: PUB }),
      "a chain cache entry needs explicit chainsPerDay and periodMinutes",
    ],
    [
      "partitioned store without issuer",
      () => partitioned.put(GROUP, TERMINAL_T, key, CONTEXT),
      "an issuer-keyed chain cache is told which issuer granted a key",
    ],
    [
      "partitioned read without issuer",
      () => partitioned.candidates(GROUP, TARGET_T, CONTEXT),
      "an issuer-keyed chain cache is told which issuers a read accepts",
    ],
    [
      "empty composed family",
      () => badFamily.put(GROUP, TERMINAL_T, key, { ...CONTEXT, issuerName: "issuer-a" }),
      "a chain keyBy answers with the name of one family",
    ],
    [
      "non-string read issuer",
      () =>
        partitioned.candidates(GROUP, TARGET_T, {
          ...CONTEXT,
          issuerNames: /** @type {any} */ ([1]),
        }),
      "the issuers a chain-cache read accepts are names",
    ],
    [
      "store under a lease that is no object",
      () => cache.put(GROUP, TERMINAL_T, key, { ...CONTEXT, lease: "held" }),
      "a pending chain grant is filed under its response lease",
    ],
    [
      "read under a lease that is no object",
      () => cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease: null }),
      "a pending chain read names its response lease",
    ],
    [
      "read under a lease that is a string",
      () => cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease: /** @type {any} */ ("held") }),
      "a pending chain read names its response lease",
    ],
    [
      "attempt without a lease",
      () => cache.attempted({}),
      "a completed chain attempt names its response lease",
    ],
  ]) {
    await t.test(name, async () => {
      await assert.rejects(/** @type {() => Promise<unknown>} */ (attempt), {
        code: "bad_key",
        message,
      });
    });
  }

  await t.test("over-full pending response", async () => {
    const lease = {};
    const pending = new ChainKeyCache();
    for (let index = 0; index < MAX_CHAIN_MEMBERS_PER_FAMILY; index++) {
      await pending.put(GROUP, TERMINAL_T, key, { ...CONTEXT, lease });
    }
    await assert.rejects(() => pending.put(GROUP, TERMINAL_T, key, { ...CONTEXT, lease }), {
      code: "bad_key",
      message: "a pending chain response exceeds its member bound",
    });
  });

  await t.test(
    "pending response admits 16 members across families and refuses the 17th",
    async () => {
      const lease = {};
      const pending = new ChainKeyCache();
      for (let index = 0; index < MAX_CHAIN_MEMBERS_PER_MESSAGE; index++) {
        await pending.put(`g${index}`, TERMINAL_T, key, { ...CONTEXT, lease });
      }
      await assert.rejects(() => pending.put("overflow", TERMINAL_T, key, { ...CONTEXT, lease }), {
        code: "bad_key",
        message: "a pending chain response exceeds its member bound",
      });
    },
  );

  assert.deepEqual(cache.entries(), [], "refused writes leave no cache entries");
  assert.deepEqual(partitioned.entries(), []);
  assert.deepEqual(badFamily.entries(), []);

  await cache.put(GROUP, TERMINAL_T, key, CONTEXT);
  assert.deepEqual(
    (await cache.candidates(GROUP, TARGET_T, CONTEXT)).map(base64urlEncode),
    [C1.periodKey],
    "a valid store and read recover the publisher period key",
  );
});

test("a partitioned chain key answers only under the geometry it was filed under", async () => {
  const kind = "testChainKey";
  const filed = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
  const other = Object.freeze({ chainsPerDay: 1, periodMinutes: 60 });
  // Parts without geometry, so only the family identity can keep the two apart.
  const partition = { kind, parts: ["same"] };
  const cache = new ChainKeyCache({ entryKind: kind, periodView: "none" });
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(3),
    geometry: filed,
  });
  const { key } = await generation.chainCapability(GROUP, "251023T0600");
  await cache.put(GROUP, "251023T0600", key, { partition, ...filed });
  await assert.rejects(cache.periodCandidates(GROUP, "251023T0500", { partition, ...filed }), {
    code: "bad_config",
  });

  assert.deepEqual(
    await cache.candidates(GROUP, "251023T0500", { partition, ...filed }),
    [await generation.periodKey(GROUP, "251023T0500")],
    "the filed geometry derives its period key",
  );
  // Both geometries start a window at 00:00, so the window lookup alone would
  // hand this chain key to the other geometry.
  assert.deepEqual(
    await cache.candidates(GROUP, "251023T0500", { partition, ...other }),
    [],
    "another geometry is another family",
  );
});

test("the six-hour reference policy applies inside the chain pool without dropping a supplied future window", async () => {
  const clock = new Clock("2025-10-23T14:20:00Z");
  const retaining = new ChainKeyCache({ clock, evictionPolicy: evictAfterSixHours });
  const key = base64urlDecode(C1.rootChainKey);

  await retaining.put(GROUP, "251023T0745", key, CONTEXT);
  await retaining.put(GROUP, TERMINAL_T, key, CONTEXT);
  await retaining.put(GROUP, "251024T1145", key, CONTEXT);
  assert.deepEqual(
    retaining
      .entries()
      .filter(({ kind }) => kind === "chain-key")
      .map(({ t }) => t)
      .sort(),
    ["251023T2345", "251024T1145"],
    "a supplied future window is not mistaken for an old cache entry",
  );

  const expanding = new ChainKeyCache({
    strategy: "expand",
    clock,
    evictionPolicy: evictAfterSixHours,
  });
  await expanding.put(GROUP, "251023T1145", key, CONTEXT);
  const kept = expanding
    .entries()
    .map(({ t }) => t)
    .sort();
  assert.equal(kept.length, 14, "the morning window keeps the period keys inside six hours");
  assert.equal(kept[0], "251023T0830", "and the policy reads the coordinate it is handed");
  assert.equal(kept[kept.length - 1], "251023T1145");

  const reading = new ChainKeyCache({ clock, evictionPolicy: evictAfterSixHours });
  await reading.put(GROUP, "251023T1145", key, CONTEXT);
  assert.equal((await reading.candidates(GROUP, "251023T1100", CONTEXT)).length, 1);
  clock.set("2025-10-24T08:00:00Z");
  assert.deepEqual(
    await reading.candidates(GROUP, "251023T1100", CONTEXT),
    [],
    "a read applies the policy before it answers",
  );
});

test("one metadata-only eviction contract governs both logical period-key pools", async () => {
  const clock = new Clock("2025-10-23T14:20:00Z");
  /** @type {any[]} */
  const seen = [];
  const evictionPolicy = (/** @type {any} */ entry, /** @type {{ now: Date }} */ { now }) => {
    seen.push({ ...entry, now: now.toISOString() });
    return false;
  };
  const independent = new PeriodKeyCache({ clock, evictionPolicy });
  const retaining = new ChainKeyCache({ clock, evictionPolicy });
  const expanding = new ChainKeyCache({ strategy: "expand", clock, evictionPolicy });

  await independent.put(GROUP, TARGET_T, new Uint8Array(32).fill(1), { publisher: PUB });
  await retaining.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), CONTEXT);
  await retaining.candidates(GROUP, TARGET_T, CONTEXT);
  await expanding.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), CONTEXT);
  retaining.entries();
  expanding.entries();

  assert.ok(
    seen.some(({ pool, kind }) => pool === "independent" && kind === "period-key"),
    "the base pool reports a period-key coordinate",
  );
  assert.ok(
    seen.some(({ pool, kind, t }) => pool === "chain" && kind === "chain-key" && t === TERMINAL_T),
    "a retained chain key reports the cutoff it is held at",
  );
  assert.ok(
    seen.some(({ pool, kind, t }) => pool === "chain" && kind === "period-key" && t === TARGET_T),
    "a memoized period key reports its own coordinate in the chain pool",
  );
  assert.ok(
    seen.every(({ now }) => now === "2025-10-23T14:20:00.000Z"),
    "each pool reads one injected clock",
  );
  assert.ok(
    seen.every((entry) => !Object.hasOwn(entry, "key")),
    "policy sees bookkeeping, never key material",
  );
  assert.ok(
    seen.every((entry) => !Object.hasOwn(entry, "familyName")),
    "policy sees no cache-specific family encoding",
  );
  assert.deepEqual(
    new Set(seen.flatMap((entry) => Object.keys(entry))),
    new Set(["pool", "t", "kind", "now"]),
    "and nothing else at all",
  );
});

test("promotion joins one expansion and keeps the lease usable until explicit release", async () => {
  const cache = new ChainKeyCache({ strategy: "expand", maxMemoPeriodKeys: 1 });
  const lease = {};
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), { ...CONTEXT, lease });
  const subtle = crypto.subtle;
  const derive = subtle.deriveBits;
  let release = () => {};
  let entered = () => {};
  const barrier = new Promise((resolve) => {
    release = () => resolve(undefined);
  });
  const started = new Promise((resolve) => {
    entered = () => resolve(undefined);
  });
  let blocked = false;
  subtle.deriveBits = async (...args) => {
    if (!blocked) {
      blocked = true;
      entered();
      await barrier;
    }
    return derive.apply(subtle, args);
  };
  try {
    const promotion = cache.promote({ lease });
    assert.equal(cache.promote({ lease }), promotion, "repeat completion joins the same work");
    await started;
    assert.deepEqual(
      (await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease })).map(base64urlEncode),
      [C1.periodKey],
      "private capability remains usable during blocked expansion",
    );
    release();
    await promotion;
    assert.deepEqual(
      (await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease })).map(base64urlEncode),
      [C1.periodKey],
      "capacity eviction does not release the obtaining lease",
    );
    await cache.attempted({ lease });
    assert.deepEqual(
      await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease }),
      [],
      "only explicit completed attempt releases first-use material",
    );
  } finally {
    release();
    subtle.deriveBits = derive;
  }
});

for (const partial of [false, true]) {
  test(`failed expansion ${partial ? "after partial writes" : "before any write"} releases once without retry`, async () => {
    const cache = new ChainKeyCache({ strategy: "expand" });
    const lease = {};
    if (partial)
      await cache.put("first", TERMINAL_T, base64urlDecode(C1.rootChainKey), { ...CONTEXT, lease });
    await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), { ...CONTEXT, lease });
    const expected = await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease });
    const fault = new Error("expansion failed");
    const subtle = crypto.subtle;
    const derive = subtle.deriveBits;
    let failures = 0;
    subtle.deriveBits = async (...args) => {
      if (!partial || cache.entries().length > 0) {
        failures++;
        throw fault;
      }
      return derive.apply(subtle, args);
    };
    let promotion;
    let promotionFault;
    try {
      promotion = cache.promote({ lease });
      assert.equal(cache.promote({ lease }), promotion);
      await assert.rejects(promotion, (error) => {
        promotionFault = error;
        return error.cause === fault;
      });
      assert.equal(cache.promote({ lease }), promotion, "failure is joinable until release");
    } finally {
      subtle.deriveBits = derive;
    }
    assert.equal(failures, 1);
    const retained = cache.entries();
    assert.equal(retained.length > 0, partial, "already completed writes survive the fault");
    assert.deepEqual(await cache.candidates(GROUP, TARGET_T, CONTEXT), []);
    assert.deepEqual(
      await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease }),
      expected,
      "private first-use material survives failed promotion until readers release it",
    );
    await assert.rejects(
      cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), { ...CONTEXT, lease }),
      { code: "bad_key" },
      "a completing lease cannot accept more grants",
    );
    await assert.rejects(cache.attempted({ lease }), (error) => error === promotionFault);
    assert.deepEqual(cache.entries(), retained);
    assert.deepEqual(
      await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease }),
      [],
      "terminal release drops private material even when expansion failed",
    );
    await cache.promote({ lease });
    await cache.attempted({ lease });
    assert.deepEqual(cache.entries(), retained, "later completion never retries expansion");
    await assert.rejects(
      cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), { ...CONTEXT, lease }),
      { code: "bad_key" },
      "a released lease cannot be resurrected",
    );
    const fresh = {};
    await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), {
      ...CONTEXT,
      lease: fresh,
    });
    await cache.attempted({ lease: fresh });
    assert.deepEqual(
      await cache.candidates(GROUP, TARGET_T, CONTEXT),
      expected,
      "a new response can promote normally after the earlier failure",
    );
  });
}

test("failed retained-chain promotion preserves earlier writes and releases private rivals", async () => {
  const cache = new ChainKeyCache();
  const lease = {};
  await cache.put(GROUP, TARGET_T, new Uint8Array(16).fill(111), CONTEXT);
  await cache.put("first", TERMINAL_T, base64urlDecode(C1.rootChainKey), { ...CONTEXT, lease });
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), { ...CONTEXT, lease });
  const fault = new Error("subsumption failed");
  const subtle = crypto.subtle;
  const derive = subtle.deriveBits;
  let failures = 0;
  subtle.deriveBits = async () => {
    failures++;
    throw fault;
  };
  let promotionFault;
  try {
    await assert.rejects(cache.promote({ lease }), (error) => {
      promotionFault = error;
      return error.cause === fault;
    });
    await assert.rejects(cache.attempted({ lease }), (error) => error === promotionFault);
    await cache.attempted({ lease });
    assert.equal(failures, 1, "neither cleanup nor later completion retries promotion");
  } finally {
    subtle.deriveBits = derive;
  }
  assert.equal(
    cache.entries().filter(({ t }) => t === TERMINAL_T).length,
    1,
    "the first completed chain filing survives",
  );
  assert.deepEqual(
    (await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease })).map(base64urlEncode),
    (await cache.candidates(GROUP, TARGET_T, CONTEXT)).map(base64urlEncode),
    "the failed private rival was released",
  );
});

for (const strategy of ["retain", "expand"]) {
  test(`${strategy} reader reset fences delayed derivation and permits fresh filing`, async () => {
    const cache = new ChainKeyCache({ strategy });
    const oldKey = base64urlDecode(C1.rootChainKey);
    const next = periodFamilyGeneration({
      keyDerivationSecret: new Uint8Array(32).fill(92),
      geometry: GEOMETRY,
    });
    const nextKey = (await next.chainCapability(GROUP, TERMINAL_T)).key;
    const expected = await next.periodKey(GROUP, TARGET_T);
    if (strategy === "retain") await cache.put(GROUP, TERMINAL_T, oldKey, CONTEXT);
    const subtle = globalThis.crypto.subtle,
      original = subtle.deriveBits;
    let enter, release;
    const entered = new Promise((resolve) => {
      enter = resolve;
    });
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    let held = false;
    subtle.deriveBits = async function (...args) {
      if (!held) {
        held = true;
        enter();
        await gate;
      }
      return original.apply(this, args);
    };
    try {
      const old =
        strategy === "retain"
          ? cache.candidates(GROUP, TARGET_T, CONTEXT)
          : cache.put(GROUP, TERMINAL_T, oldKey, CONTEXT);
      const retired = assert.rejects(old, { code: "context_retired" });
      await entered;
      await cache.clearReaderContext();
      assert.deepEqual(cache.entries(), []);
      await cache.put(GROUP, TERMINAL_T, nextKey, CONTEXT);
      release();
      await retired;
      assert.deepEqual(await cache.candidates(GROUP, TARGET_T, CONTEXT), [expected]);
      assert.ok(cache.entries().length > 0);
      await cache.clearReaderContext();
      assert.deepEqual(cache.entries(), []);
    } finally {
      release();
      subtle.deriveBits = original;
    }
  });
}

for (const strategy of ["retain", "expand"]) {
  test(`${strategy} staged promotion cannot repopulate after reset`, async () => {
    const cache = new ChainKeyCache({ strategy });
    const lease = {};
    if (strategy === "retain")
      await cache.put(GROUP, TARGET_T, new Uint8Array(16).fill(111), CONTEXT);
    await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), { ...CONTEXT, lease });
    const subtle = crypto.subtle;
    const original = subtle.deriveBits;
    let enter, release;
    const entered = new Promise((resolve) => {
      enter = resolve;
    });
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    let paused = false;
    subtle.deriveBits = async function (...args) {
      if (!paused) {
        paused = true;
        enter();
        await gate;
      }
      return original.apply(this, args);
    };
    try {
      const old = cache.promote({ lease });
      const rejected = assert.rejects(old, { code: "context_retired" });
      await entered;
      await cache.clearReaderContext();
      assert.deepEqual(cache.entries(), []);
      release();
      await rejected;
      await cache.attempted({ lease });
      assert.deepEqual(cache.entries(), []);
      assert.deepEqual(await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease }), []);
      await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), CONTEXT);
      assert.deepEqual((await cache.candidates(GROUP, TARGET_T, CONTEXT)).map(base64urlEncode), [
        C1.periodKey,
      ]);
    } finally {
      release();
      subtle.deriveBits = original;
    }
  });
}

function resetDerivationBoundary() {
  let release;
  const promise = new Promise((resolve) => {
    release = resolve;
  });
  return { promise, release: () => release() };
}

/**
 * Pause the first deriveBits call whose HKDF info the predicate accepts.
 * @param {(info: Uint8Array) => boolean} predicate
 */
function pauseDerivation(predicate) {
  const subtle = globalThis.crypto.subtle;
  const original = subtle.deriveBits;
  const entered = resetDerivationBoundary();
  const gate = resetDerivationBoundary();
  let held = false;
  subtle.deriveBits = async function (/** @type {any[]} */ ...args) {
    if (!held && predicate(args[0].info)) {
      held = true;
      entered.release();
      await gate.promise;
    }
    return original.apply(this, /** @type {any} */ (args));
  };
  return {
    entered: entered.promise,
    release: gate.release,
    restore: () => {
      subtle.deriveBits = original;
    },
  };
}

test("a window write queued behind a paused one cannot file after reset", async () => {
  const cache = new ChainKeyCache({ strategy: "retain" });
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), CONTEXT);
  assert.equal(cache.entries().length, 1, "the old context holds a chain key");
  const pause = pauseDerivation(() => true);
  try {
    // The first put derives from the held root toward its cutoff and pauses
    // there, holding the window. The second queues behind it on that window.
    const first = cache.put(GROUP, TARGET_T, new Uint8Array(16).fill(5), CONTEXT);
    const second = cache.put(GROUP, "251023T1500", new Uint8Array(16).fill(6), CONTEXT);
    await pause.entered;
    await cache.clearReaderContext();
    assert.deepEqual(cache.entries(), []);
    pause.release();
    await assert.rejects(first, { code: "context_retired" });
    await assert.rejects(second, { code: "context_retired" });
    assert.deepEqual(cache.entries(), [], "the queued write did not file into the new context");
    assert.deepEqual(await cache.candidates(GROUP, "251023T1500", CONTEXT), []);
  } finally {
    pause.release();
    pause.restore();
  }
});

test("a period-key derivation finishing after reset cannot memoize for the new context", async () => {
  const cache = new ChainKeyCache({ strategy: "retain" });
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), CONTEXT);
  // Pause at the canonical Leaf derivation: the chain walk has finished and only the period
  // key is left to derive, which the read then memoizes.
  const pause = pauseDerivation((info) => info[0] === 0x03);
  try {
    const old = cache.candidates(GROUP, TARGET_T, CONTEXT);
    await pause.entered;
    await cache.clearReaderContext();
    assert.deepEqual(cache.entries(), []);
    pause.release();
    await assert.rejects(old, { code: "context_retired" });
    assert.deepEqual(cache.entries(), [], "no period key was memoized after reset");
    assert.deepEqual(await cache.candidates(GROUP, TARGET_T, CONTEXT), []);
  } finally {
    pause.release();
    pause.restore();
  }
});

test("an explicit finite candidate budget bounds cold chain derivations independently of retained rivals", async () => {
  const cache = new ChainKeyCache({ maxRivalsPerWindow: 5 });
  for (const generation of rivals(5, 71)) {
    await cache.put(
      GROUP,
      TERMINAL_T,
      (await generation.chainCapability(GROUP, TERMINAL_T)).key,
      CONTEXT,
    );
  }
  const budget = { remaining: 2 };
  assert.equal(
    (await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, chainCandidateBudget: budget })).length,
    2,
  );
  assert.equal(budget.remaining, 0);
  assert.equal(
    await derivations(() =>
      cache.candidates(GROUP, "251023T1400", { ...CONTEXT, chainCandidateBudget: budget }),
    ),
    0,
  );
  assert.equal((await cache.entries()).filter((entry) => entry.kind === "chain-key").length, 5);
  const larger = { remaining: 5 };
  assert.equal(
    (
      await cache.candidates(GROUP, "251023T1345", {
        ...CONTEXT,
        chainOnly: true,
        chainCandidateBudget: larger,
      })
    ).length,
    5,
  );
  assert.equal(larger.remaining, 0);
  assert.equal(
    (await cache.candidates(GROUP, "251023T1330", CONTEXT)).length,
    4,
    "raising retention does not implicitly raise the ordinary default walk bound",
  );
});

test("concurrent chain-cache reads spend one shared finite allowance before awaiting derivation", async () => {
  const cache = new ChainKeyCache({ maxRivalsPerWindow: 5 });
  for (const generation of rivals(3, 121))
    await cache.put(
      GROUP,
      TERMINAL_T,
      (await generation.chainCapability(GROUP, TERMINAL_T)).key,
      CONTEXT,
    );
  const budget = { remaining: 2 };
  const calls = await derivations(async () => {
    await Promise.all([
      cache.candidates(GROUP, TERMINAL_T, { ...CONTEXT, chainCandidateBudget: budget }),
      cache.candidates(GROUP, TERMINAL_T, { ...CONTEXT, chainCandidateBudget: budget }),
    ]);
  });
  // At the supplied terminal coordinate each candidate needs one period-key
  // derivation. Count actual work across both reads, outside fixture setup.
  assert.equal(calls, 2, "concurrent reads must not overspend the shared allowance");
  assert.equal(budget.remaining, 0);
});

test("the shared chain-work budget counts duplicate derived results across issuer partitions", async () => {
  const cache = new ChainKeyCache({ keyBy: keyByIssuer });
  const key = base64urlDecode(C1.rootChainKey);
  for (const issuerName of ["a", "b", "c"])
    await cache.put(GROUP, TERMINAL_T, key, { ...CONTEXT, issuerName });
  const budget = { remaining: 2 };
  let selected;
  const calls = await derivations(async () => {
    selected = await cache.candidates(GROUP, TERMINAL_T, {
      ...CONTEXT,
      issuerNames: ["a", "b", "c"],
      chainCandidateBudget: budget,
    });
  });
  assert.equal(selected.length, 1, "identical period bytes are returned once");
  assert.equal(calls, 2, "both attempted derivations spend work before deduplication");
  assert.equal(budget.remaining, 0);
});

test("durable retained entries do not enlarge a cold read's explicit finite budget", async () => {
  const entries = new Map();
  const storage = {
    async get(key) {
      return entries.get(key);
    },
    async set(key, value) {
      entries.set(key, value);
    },
    async keys() {
      return [...entries.keys()];
    },
    async remove(key) {
      entries.delete(key);
    },
  };
  const writer = new ChainKeyCache({ storage, maxRivalsPerWindow: 5 });
  for (const generation of rivals(5, 91))
    await writer.put(
      GROUP,
      TERMINAL_T,
      (await generation.chainCapability(GROUP, TERMINAL_T)).key,
      CONTEXT,
    );
  const reader = new ChainKeyCache({ storage, maxRivalsPerWindow: 5 });
  const budget = { remaining: 2 };
  assert.equal(
    await derivations(async () => {
      assert.equal(
        (await reader.candidates(GROUP, TERMINAL_T, { ...CONTEXT, chainCandidateBudget: budget }))
          .length,
        2,
      );
    }),
    2,
  );
  assert.equal(budget.remaining, 0);
  assert.equal((await reader.entries()).filter((entry) => entry.kind === "chain-key").length, 5);
  for (const remaining of [-1, 1.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1, "2"]) {
    await assert.rejects(
      reader.candidates(GROUP, TERMINAL_T, { ...CONTEXT, chainCandidateBudget: { remaining } }),
      { code: "bad_config" },
    );
  }
});
