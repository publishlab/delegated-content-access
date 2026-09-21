// @ts-check
//
// What the frozen client cache costs and what it may keep: the price of
// reading one coordinate twice, the size of the derived-leaf memo, and which
// named rival bound governs which candidate kind.
//
// Then the refusals and the eviction contract: which constructions and which
// public store and read shapes the cache declines, and what one injected
// policy sees of both logical period-key pools.
//
// Elsewhere and not repeated here: client-explicit-geometry.test.js covers
// partitioning by publisher, geometry and issuer, rival admission and
// subsumption, response-lease privacy and the whole resolver path.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { base64urlDecode, base64urlEncode } from "../../../core-shared/codec.js";
import { keyByIssuer, PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { evictAfterSixHours } from "../../../adapter-client/periodKeyEviction.js";
import { Clock } from "../../../demo/actors/Clock.js";
import {
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  MAX_RIVAL_CHAIN_CANDIDATES,
  MAX_RIVAL_EXACT_CANDIDATES,
} from "../core-shared/periodChainConstruction.js";
import { MAX_MEMOIZED_LEAVES, PeriodChainCache } from "../core-client/PeriodChainCache.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";

const PUB = "https://publisher.example";
const GROUP = "premium";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const CONTEXT = Object.freeze({ publisher: PUB, ...GEOMETRY });
const TERMINAL_T = "251023T2345";
const TARGET_T = "251023T1415";
const VECTORS = JSON.parse(
  readFileSync(new URL("./fixtures/dca-period-chain-v1.vectors.json", import.meta.url), "utf8"),
);

// The vector set states its lifecycle before a byte of it is used: a set
// without `setIdentity`, `status` and `semanticWidths` is ambiguous about which
// width it records, and this loader does not accept one.
assert.equal(VECTORS.setIdentity, "dca-period-chain-v1");
assert.equal(VECTORS.status, "canonical-16");
assert.equal(VECTORS.semanticWidths.chainState, 16);
assert.equal(VECTORS.semanticWidths.exactLeaf, 16);
assert.equal(VECTORS.semanticWidths.exactWrapAlgorithm, "AES-128-GCM");
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
    const cache = new PeriodChainCache({ strategy: /** @type {'retain'|'expand'} */ (strategy) });
    const filing = await derivations(() =>
      cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.terminal), CONTEXT),
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
        [C1.leaf],
        `read ${index} answers the vector leaf`,
      );
    }

    if (strategy === "expand") {
      assert.ok(filing > 0, `expansion walks the window once while filing, spent ${filing}`);
      assert.deepEqual(reads, [0, 0, 0], "and every read is a lookup");
      return;
    }
    assert.equal(filing, 0, "retaining state derives nothing while filing");
    assert.ok(reads[0] > 0, "the first read walks back to the coordinate");
    assert.deepEqual(
      reads.slice(1),
      [0, 0],
      `a memoized leaf answers without walking again, spent ${reads.join()}`,
    );
  });
}

test("retain caps its derived-leaf memo and leaves the chain state that rebuilds it", async () => {
  const cache = new PeriodChainCache({ strategy: "retain", maxMemoLeaves: 3 });
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.terminal), CONTEXT);
  const coordinates = ["251023T1200", "251023T1215", "251023T1230", "251023T1245", "251023T1300"];

  for (const t of coordinates) {
    assert.equal((await cache.candidates(GROUP, t, CONTEXT)).length, 1, `${t} is derivable`);
  }

  assert.deepEqual(
    cache
      .entries()
      .filter(({ kind }) => kind === "exact")
      .map(({ t }) => t)
      .sort(),
    coordinates.slice(2),
    "the memo holds the three most recently derived coordinates",
  );
  assert.equal(
    cache.entries().filter(({ kind }) => kind === "chain").length,
    1,
    "and the cap never reaches the retained state the memo came from",
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

test("expand holds its derived leaves to the default ceiling without an eviction policy", async () => {
  const cache = new PeriodChainCache({ strategy: "expand" });
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
    MAX_MEMOIZED_LEAVES,
    "sixteen expanded windows reach the ceiling instead of growing to 768 leaves",
  );
});

test("expand evicts its least recently derived leaf at a small ceiling", async () => {
  const cache = new PeriodChainCache({ strategy: "expand", maxMemoLeaves: 4 });
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

test("a pending grant is tried without entering the memo", async () => {
  const cache = new PeriodChainCache();
  const lease = {};
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.terminal), { ...CONTEXT, lease });

  /** @type {any} */
  let first;
  const walked = await derivations(async () => {
    first = await cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease });
  });
  assert.deepEqual(
    first.map(base64urlEncode),
    [C1.leaf],
    "the response-private grant answers its own read",
  );
  assert.deepEqual(cache.entries(), [], "and leaves nothing behind in the shared store");
  assert.equal(
    await derivations(() => cache.candidates(GROUP, TARGET_T, { ...CONTEXT, lease })),
    walked,
    `a second read of the same coordinate walks again, spent ${walked}`,
  );
});

test("each named rival bound governs its own kind, and the eight-key widening lasts one read", async () => {
  const cache = new PeriodChainCache();
  const generations = rivals(8, 61);
  const leafOf = (/** @type {any} */ generation) => generation.periodKey(GROUP, TARGET_T);
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
    "four retained rivals answer with four leaves",
  );

  for (const generation of generations.slice(4)) await file(generation);
  assert.equal(
    cache.entries().filter(({ kind }) => kind === "chain").length,
    MAX_RIVAL_CHAIN_CANDIDATES,
    "the four newest unrelated states are what one partition and window retains",
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
        generations.map(async (generation) => base64urlEncode(await leafOf(generation))),
      ),
    ),
    "the newest chain rivals are walked and the memo of each evicted one is still tried",
  );
  assert.equal(second.length, MAX_RIVAL_CHAIN_CANDIDATES + MAX_RIVAL_EXACT_CANDIDATES);
  const chainBound = MAX_RIVAL_CHAIN_CANDIDATES * (2 * C1.N - 1);
  assert.equal(
    walked,
    MAX_RIVAL_CHAIN_CANDIDATES * 39,
    `four walks of 38 backward steps and one leaf, inside the ${chainBound} the chain bound allows`,
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
    MAX_RIVAL_EXACT_CANDIDATES,
    "the four older memos left with the states that would rebuild them, so the widening held for one read",
  );
  assert.equal(
    (await cache.candidates(GROUP, TARGET_T, CONTEXT)).length,
    MAX_RIVAL_EXACT_CANDIDATES,
    "and the reads after it answer with those same four",
  );
});

test("the chain cache refuses unusable and unknown options", async (t) => {
  const clock = new Clock("2025-10-23T14:20:00Z");
  for (const [name, config, code, message] of [
    [
      "unknown strategy",
      { strategy: "discard" },
      "bad_config",
      'unknown period-chain cache strategy "discard"',
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
      { maxMemoLeaves: 2.5 },
      "bad_config",
      "maxMemoLeaves is a whole number of leaves, at least one; got 2.5",
    ],
    [
      "empty memo ceiling",
      { maxMemoLeaves: 0 },
      "bad_config",
      "maxMemoLeaves is a whole number of leaves, at least one; got 0",
    ],
    [
      "unknown option",
      { evictionPolciy: () => false },
      "unsupported_option",
      "PeriodChainCache has no evictionPolciy yet, and will not pretend to",
    ],
  ]) {
    await t.test(name, () => {
      assert.throws(() => new PeriodChainCache(/** @type {any} */ (config)), { code, message });
    });
  }

  const cache = new PeriodChainCache({
    strategy: "retain",
    clock,
    evictionPolicy: () => false,
    keyBy: keyByIssuer,
    maxMemoLeaves: 8,
  });
  const context = { ...CONTEXT, issuerName: "issuer-a" };
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.terminal), context);
  assert.deepEqual(
    (await cache.candidates(GROUP, TARGET_T, context)).map(base64urlEncode),
    [C1.leaf],
    "every dependency together still stores and reads one family",
  );
});

test("chain cache public stores and reads refuse unusable key and context shapes", async (t) => {
  const cache = new PeriodChainCache();
  const partitioned = new PeriodChainCache({ keyBy: keyByIssuer });
  const badFamily = new PeriodChainCache({ keyBy: () => "" });
  const key = base64urlDecode(C1.terminal);
  for (const [name, attempt, message] of [
    [
      "short chain key",
      () => cache.put(GROUP, TERMINAL_T, new Uint8Array(31), CONTEXT),
      "a direct period-chain grant of this profile is 16 key bytes",
    ],
    [
      "non-byte chain key",
      () => cache.put(GROUP, TERMINAL_T, /** @type {any} */ (null), CONTEXT),
      "a direct period-chain grant of this profile is 16 key bytes",
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
    const pending = new PeriodChainCache();
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
      const pending = new PeriodChainCache();
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
    [C1.leaf],
    "a valid store and read recover the publisher leaf",
  );
});

test("the six-hour reference policy applies inside the chain pool without dropping a supplied future window", async () => {
  const clock = new Clock("2025-10-23T14:20:00Z");
  const retaining = new PeriodChainCache({ clock, evictionPolicy: evictAfterSixHours });
  const key = base64urlDecode(C1.terminal);

  await retaining.put(GROUP, "251023T0745", key, CONTEXT);
  await retaining.put(GROUP, TERMINAL_T, key, CONTEXT);
  await retaining.put(GROUP, "251024T1145", key, CONTEXT);
  assert.deepEqual(
    retaining
      .entries()
      .filter(({ kind }) => kind === "chain")
      .map(({ t }) => t)
      .sort(),
    ["251023T2345", "251024T1145"],
    "a supplied future window is not mistaken for an old cache entry",
  );

  const expanding = new PeriodChainCache({
    strategy: "expand",
    clock,
    evictionPolicy: evictAfterSixHours,
  });
  await expanding.put(GROUP, "251023T1145", key, CONTEXT);
  const kept = expanding
    .entries()
    .map(({ t }) => t)
    .sort();
  assert.equal(kept.length, 14, "the morning window keeps the leaves inside six hours");
  assert.equal(kept[0], "251023T0830", "and the policy reads the coordinate it is handed");
  assert.equal(kept[kept.length - 1], "251023T1145");
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
  const retaining = new PeriodChainCache({ clock, evictionPolicy });
  const expanding = new PeriodChainCache({ strategy: "expand", clock, evictionPolicy });

  await independent.put(GROUP, TARGET_T, new Uint8Array(32).fill(1), { publisher: PUB });
  await retaining.put(GROUP, TERMINAL_T, base64urlDecode(C1.terminal), CONTEXT);
  await retaining.candidates(GROUP, TARGET_T, CONTEXT);
  await expanding.put(GROUP, TERMINAL_T, base64urlDecode(C1.terminal), CONTEXT);
  retaining.entries();
  expanding.entries();

  assert.ok(
    seen.some(({ pool, kind }) => pool === "independent" && kind === "exact"),
    "the base pool reports an exact coordinate",
  );
  assert.ok(
    seen.some(({ pool, kind, t }) => pool === "chain" && kind === "chain" && t === TERMINAL_T),
    "retained state reports the cutoff it is held at",
  );
  assert.ok(
    seen.some(({ pool, kind, t }) => pool === "chain" && kind === "exact" && t === TARGET_T),
    "a memoized leaf reports its own coordinate in the chain pool",
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
