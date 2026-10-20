//
// The cache with a store under it, and two tabs over the one store. Everything
// here follows from `Storage` being async - the read and the write of a
// read-modify-write are two turns, and another tab runs between them.
//
// Two live `PageLoad`s are two tabs, and the only thing
// they share is the `Storage` their one `Browser` owns. That is modelled here
// as two `PeriodKeyCache` instances over one `Storage`: each cache instance
// stands for a tab's in-memory view, and the store for what the browser holds.
//
// The concurrency cases inject no network, issuer or clock. The keys are bytes
// chosen by the test rather than derived, because nothing there turns on where
// a periodKey came from - only on which of them the cache still holds. The
// eviction case later injects a clock explicitly.

import test from "node:test";
import assert from "node:assert/strict";

import { PeriodKeyCache, keyByIssuer } from "../../adapter-client/PeriodKeyCache.js";
import { evictAfterSixHours } from "../../adapter-client/periodKeyEviction.js";
import { Storage } from "../../demo/actors/Storage.js";
import { Browser } from "../../demo/actors/Browser.js";
import { Network } from "../../demo/actors/Network.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { Clock } from "../../demo/actors/Clock.js";
import { encrypt } from "../../core-shared/aead.js";
import { base64urlEncode, utf8Decode, utf8Encode } from "../../core-shared/codec.js";
import {
  ACCESS_GROUP as PREMIUM,
  AT,
  FREE_ACCESS_GROUP as FREE,
  ISSUER_NAME,
  KEY_ID,
  UNLOCK_URL,
} from "../../demo/scenarios/fixtures.js";
import { held } from "../../test-lib/helpers/inspect.js";
import { periodKey } from "../support/keys.js";
import { INHERITED } from "../../test-lib/fixtures/inherited-names.js";
import { actorWorld } from "../../demo/scenarios/world.js";
import { rootFromPage } from "../../demo/support/queryableRoot.js";
import { ARTICLES, CONTENT_NAME, T_NOW } from "../../demo/scenarios/fixtures.js";

const T10 = "251023T1000";
const T11 = "251023T1100";
const T12 = "251023T1200";
const T13 = "251023T1300";
const T14 = "251023T1400";
const T15 = "251023T1500";

/** The delivery origin a resolver-driven put/read carries. */
const PUB = "https://www.news-site.example";

/**
 * The family name one put files under. Every put here is on the period-key
 * profile a caller naming none is on. The cache partitions by publisher and
 * access group.
 *
 * @param {string} accessGroup
 * @returns {string}
 */
function family(accessGroup) {
  return `${PUB}|${accessGroup}`;
}

/**
 * The coordinate `held` reports for one period of one family.
 *
 * @param {string} accessGroup
 * @param {string} t
 * @returns {string}
 */
function coordinate(accessGroup, t) {
  return `${family(accessGroup)}/${t}`;
}

/**
 * The interleaving seam. `Storage` awaits this before every operation, so a
 * test can stop one tab inside its read-modify-write gap and let the other run
 * to completion. Nothing here is timed: `hold` resolves when the operation has
 * actually reached the gate, and `release` is what lets it go on. A `setTimeout`
 * in either place would make the order a guess.
 *
 * @returns {{ gate: (call: { op: string, key?: string }) => any, hold: (predicate: (call: { op: string, key?: string }) => boolean) => Promise<void>, release: () => void }}
 */
function brake() {
  /** @type {null|((call: { op: string, key?: string }) => boolean)} */
  let waitingFor = null;
  /** @type {null|(() => void)} */
  let release = null;
  /** @type {null|(() => void)} */
  let announce = null;

  return {
    gate(call) {
      if (!waitingFor || !waitingFor(call)) return undefined;
      waitingFor = null;
      return new Promise((resolve) => {
        release = resolve;
        announce?.();
      });
    },
    hold(predicate) {
      waitingFor = predicate;
      return new Promise((resolve) => {
        announce = () => resolve();
      });
    },
    release() {
      release?.();
      release = null;
    },
  };
}

/**
 * The timers scheduled while this is running, counted on the globals a cache
 * would have to reach for to repair itself on a clock rather than on a call.
 * `turn` yields to the loop through the real `setTimeout`, so a task already
 * queued has run by the time the caller reads the store.
 *
 * @returns {{ calls: string[], turn: () => Promise<void>, stop: () => void }}
 */
function timerWatch() {
  /** @type {string[]} */
  const calls = [];
  const real = {
    setTimeout: globalThis.setTimeout,
    setInterval: globalThis.setInterval,
    setImmediate: globalThis.setImmediate,
  };

  for (const name of ["setTimeout", "setInterval", "setImmediate"]) {
    /** @type {any} */ (globalThis)[name] = /** @param {any[]} args */ (...args) => {
      calls.push(name);
      return /** @type {any} */ (real)[name](...args);
    };
  }

  return {
    calls,
    turn: () => new Promise((resolve) => real.setTimeout(resolve, 0)),
    stop() {
      for (const [name, original] of Object.entries(real)) {
        /** @type {any} */ (globalThis)[name] = original;
      }
    },
  };
}

/**
 * One tab reads, the other tab reads and writes, the first tab writes. The
 * second write is made from a snapshot taken before the first one landed, which
 * is the whole of the lost write - no timing, no races the test cannot name.
 *
 * @param {{ maxEntries?: number }} [config]
 */
async function tabs(config = {}) {
  const stop = brake();
  const storage = new Storage({ gate: stop.gate });
  const options = { storage, ...config };

  return {
    storage,
    stop,
    one: new PeriodKeyCache(options),
    two: new PeriodKeyCache(options),
  };
}

test("the storage surface localStorage and IndexedDB both fit behind", async () => {
  const storage = new Storage();

  assert.equal(await storage.get("absent"), undefined, "an unknown key is a miss, not a throw");
  assert.deepEqual(await storage.keys(), []);

  await storage.set("a", "one");
  await storage.set("b", "two");
  assert.equal(await storage.get("a"), "one");
  assert.deepEqual((await storage.keys()).sort(), ["a", "b"]);

  await storage.set("a", "again");
  assert.equal(await storage.get("a"), "again", "a set overwrites");

  await storage.remove("a");
  assert.equal(await storage.get("a"), undefined);
  assert.deepEqual(await storage.keys(), ["b"]);

  // Wire-safe values only, the rule `Network` holds a payload to. A store
  // that mangles a Uint8Array into "[object Object]" would be a bug found
  // three layers away from here.
  for (const value of [new Uint8Array(4), 7, null, undefined, { a: 1 }]) {
    await assert.rejects(
      () => storage.set("k", /** @type {any} */ (value)),
      (/** @type {any} */ err) => err.code === "bad_storage",
      `a ${typeof value} is not something a store can keep`,
    );
  }
  await assert.rejects(
    () => storage.get(/** @type {any} */ (7)),
    (/** @type {any} */ err) => err.code === "bad_storage",
  );

  // A refused call never reached the store, so it is not an operation.
  assert.deepEqual(storage.stats(), { gets: 4, sets: 3, removes: 1, keyLists: 3 });

  assert.throws(
    () => new Storage({ /** @type {any} */ quota: 10 }),
    (/** @type {any} */ err) => err.code === "unsupported_option",
  );
});

test("a storage-backed period cache types every malformed persisted family", async () => {
  const storageKey = `dca.periodKeys.${family(PREMIUM)}`;
  const malformed = [
    ["{", "invalid JSON"],
    ["[]", "a non-object family"],
    ["null", "a null family"],
    ["7", "a scalar family"],
    [JSON.stringify({ [T14]: "not-a-list" }), "a non-list period"],
    [JSON.stringify({ [T14]: 7 }), "a numeric period value"],
    [JSON.stringify({ [T14]: [7] }), "a non-string candidate"],
    [JSON.stringify({ [T14]: [null] }), "a null candidate"],
    [JSON.stringify({ [T14]: ["%%%"] }), "an undecodable candidate"],
  ];

  for (const [stored, label] of malformed) {
    const storage = new Storage();
    await storage.set(storageKey, stored);
    const cache = new PeriodKeyCache({ storage });
    await assert.rejects(
      () => cache.candidatesAt(PREMIUM, T14, { publisher: PUB }),
      (/** @type {any} */ error) => error.code === "bad_storage",
      label,
    );
  }

  const storage = new Storage();
  const cache = new PeriodKeyCache({ storage });
  const key = periodKey(14);
  await cache.put(PREMIUM, T14, key, { publisher: PUB });
  assert.deepEqual(await cache.candidatesAt(PREMIUM, T14, { publisher: PUB }), [key]);
});

test("a period cache refuses malformed scope and coordinate inputs before filing or reading", async () => {
  for (const namespace of [null, "", 42, {}]) {
    assert.throws(
      () => new PeriodKeyCache({ namespace: /** @type {any} */ (namespace) }),
      (/** @type {any} */ error) => error.code === "bad_config",
      `namespace ${JSON.stringify(namespace)} is not a logical-client name`,
    );
  }

  const cache = new PeriodKeyCache();
  for (const [accessGroup, t] of [
    [undefined, T14],
    ["", T14],
    [PREMIUM, undefined],
    [PREMIUM, ""],
  ]) {
    await assert.rejects(
      () =>
        cache.put(/** @type {any} */ (accessGroup), /** @type {any} */ (t), periodKey(14), {
          publisher: PUB,
        }),
      (/** @type {any} */ error) => error.code === "bad_key",
      "a put needs both its access-group and period coordinate",
    );
  }

  for (const publisher of [null, 42, {}]) {
    await assert.rejects(
      () => cache.candidatesAt(PREMIUM, T14, { publisher: /** @type {any} */ (publisher) }),
      (/** @type {any} */ error) => error.code === "bad_key",
      `a read publisher is a string, not ${JSON.stringify(publisher)}`,
    );
  }
});

test("every storage operation is a turn of its own, whatever the backing", async () => {
  const storage = new Storage();

  // The property the whole file rests on: no operation happens in the turn
  // it was called in. A synchronous store would land the write here, and
  // with it every write in the demo would be atomic - no tab could lose a
  // key to another, and this file would have nothing to test.
  const pending = storage.set("a", "one");
  assert.equal(storage.stats().sets, 0, "the write has not happened yet");
  await pending;
  assert.equal(storage.stats().sets, 1);
  assert.equal(await storage.get("a"), "one");
});

test("two tabs over one storage: a write is lost across the await gap, and reconcile restores it", async () => {
  const { storage, stop, one, two } = await tabs();

  // Tab one reads an empty family and is stopped before it writes.
  const reached = stop.hold(({ op }) => op === "set");
  const slow = one.put(PREMIUM, T14, periodKey(1), { publisher: PUB });
  await reached;

  // Tab two runs the whole read-modify-write while tab one holds a snapshot
  // taken before it: it reads the same empty family and writes its key.
  await two.put(PREMIUM, T15, periodKey(2), { publisher: PUB });
  assert.deepEqual(await held(two, "coordinate"), [coordinate(PREMIUM, T15)]);

  // Tab one writes its stale snapshot over the top.
  stop.release();
  await slow;

  assert.deepEqual(await held(one, "coordinate"), [coordinate(PREMIUM, T14)], "one key survives");
  assert.deepEqual(
    await held(two, "coordinate"),
    [coordinate(PREMIUM, T14)],
    "and both tabs read the same store",
  );
  assert.deepEqual(
    (await two.candidatesAt(PREMIUM, T14, { publisher: PUB })).map((/** @type {any} */ k) => k[0]),
    [1],
    "the key tab two accepted is not in the store it would trial against",
  );

  // The repair. Tab two still knows what it accepted, so what the store is
  // missing is recoverable without asking any issuer again.
  await two.reconcile();

  assert.deepEqual(
    await held(two, "coordinate"),
    [coordinate(PREMIUM, T15), coordinate(PREMIUM, T14)],
    "newest t first",
  );
  assert.deepEqual(await held(one, "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T14),
  ]);
  assert.deepEqual(
    (await one.candidatesAt(PREMIUM, T15, { publisher: PUB })).map((/** @type {any} */ k) => k[0]),
    [2],
    "and the restored key is the bytes tab two held, not a re-derivation",
  );

  assert.ok(storage.stats().sets >= 3);
});

test("one Browser gives two PageLoads distinct cache views that explicitly reconcile a lost delivery write", async () => {
  let family = 1;
  const world = await actorWorld({
    periodKeySupply: { derive: async () => periodKey(family) },
    accessPolicy: {
      decide(_claims, requested) {
        return {
          contentNames: [],
          periodGrants: requested.accessGroups.map((accessGroup) => ({
            accessGroup,
            periods: requested.periodCoordinates[accessGroup] ?? [],
          })),
          policyData: [],
        };
      },
    },
  });
  const firstPage = await world.render("A");
  family = 2;
  const secondPage = await world.render("B");
  const stop = brake();
  const storage = new Storage({ gate: stop.gate });
  /** @type {PeriodKeyCache[]} */
  const views = [];
  const browser = world.makeBrowser({
    storage,
    cacheNamespace: "one-logical-client",
    cacheFactory() {
      const view = new PeriodKeyCache({
        storage,
        namespace: "one-logical-client",
      });
      views.push(view);
      return view;
    },
  });
  const defaultCache = browser.cache;

  // Delivery has to be admitted before the host is asked for a cache view.
  assert.throws(
    () => browser.load(/** @type {any} */ ({})),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
  assert.equal(views.length, 0);
  assert.equal(browser.stats().loads, 0);

  const first = browser.load(rootFromPage(firstPage));
  const second = browser.load(rootFromPage(secondPage));
  assert.equal(views.length, 2, "the factory runs once for each real load");
  assert.notEqual(views[0], views[1]);
  assert.equal(browser.cache, defaultCache, "Browser.cache remains the default shared cache");
  assert.notEqual(views[0], browser.cache, "a host-selected view is retained by its host");

  assert.deepEqual(await first.resolve([CONTENT_NAME]), { covered: [], missing: [CONTENT_NAME] });
  assert.deepEqual(await second.resolve([CONTENT_NAME]), { covered: [], missing: [CONTENT_NAME] });

  // The first real response is held at its cache write. The second response
  // lands a later key-family candidate at the same coordinate, then the first
  // stale view overwrites it.
  const reached = stop.hold(({ op }) => op === "set");
  const firstUnlock = first.unlock();
  await reached;
  assert.equal((await second.unlock()).ok, true);
  stop.release();
  assert.equal((await firstUnlock).ok, true);
  assert.equal(browser.stats().unlocks, 2, "both loads made their own real unlock");

  assert.deepEqual(
    (await views[1].candidatesAt(PREMIUM, T_NOW, { publisher: PUB })).map((key) => key[0]),
    [1],
    "the second view accepted key family two, but its persisted candidate was lost",
  );
  // The load that obtained family two has already retained its opened
  // content key. Its cache view still sees the lost persistent candidate;
  // another load would need reconciliation to regain family two.
  assert.deepEqual(await second.resolve([CONTENT_NAME]), { covered: [CONTENT_NAME], missing: [] });

  await views[1].reconcile();
  assert.deepEqual(
    (await views[1].candidatesAt(PREMIUM, T_NOW, { publisher: PUB })).map((key) => key[0]),
    [2, 1],
    "reconciliation restores the lost candidate beside the stale one",
  );
  const opened = await second.open(CONTENT_NAME);
  assert.equal(utf8Decode(/** @type {Uint8Array} */ (opened.bytes)), ARTICLES.B);
  assert.equal(
    browser.stats().unlocks,
    2,
    "recovery reuses the restored key without another unlock",
  );
  assert.equal(
    (await views[0].candidatesAt(PREMIUM, T_NOW, { publisher: PUB })).length,
    2,
    "reconciliation retains both independently delivered candidates",
  );
});

test("two tabs writing different families do not lose each other", async () => {
  const { stop, one, two } = await tabs();

  const reached = stop.hold(({ op }) => op === "set");
  const slow = one.put(PREMIUM, T14, periodKey(1), { publisher: PUB });
  await reached;

  await two.put(FREE, T15, periodKey(2), { publisher: PUB });

  stop.release();
  await slow;

  // The store keeps one entry per family, so the gap only costs a write when
  // two tabs are inside the same family. That is what makes the lost write
  // above a property of the shape rather than of the store being one blob.
  assert.deepEqual(await held(one, "coordinate"), [
    coordinate(FREE, T15),
    coordinate(PREMIUM, T14),
  ]);
});

test("at capacity, a racing pair evicts two keys where one was intended", async () => {
  const { stop, one, two } = await tabs({ maxEntries: 3 });

  await one.put(PREMIUM, T10, periodKey(10), { publisher: PUB });
  await one.put(PREMIUM, T11, periodKey(11), { publisher: PUB });
  await one.put(FREE, T12, periodKey(12), { publisher: PUB });
  assert.equal((await one.entries()).length, 3, "full");

  // Tab one takes its snapshot: three entries, so its own put has to make
  // room. The oldest `t` is premium/T10, in a family it is not writing to.
  const reached = stop.hold(({ op }) => op === "set");
  const slow = one.put(FREE, T14, periodKey(14), { publisher: PUB });
  await reached;

  // Tab two, from the same snapshot, makes room for its key the same way and
  // picks the same victim.
  await two.put(PREMIUM, T15, periodKey(15), { publisher: PUB });
  assert.deepEqual(await held(two, "coordinate"), [
    coordinate(FREE, T12),
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T11),
  ]);

  stop.release();
  await slow;

  // Tab one's write carries its own eviction of premium/T10 - and, because
  // that eviction is in a family it is otherwise not touching, it writes
  // premium back as a family that never held T15. Tab two's put was to cost
  // exactly one key, T10, to make room for T15. It cost two: T10 went, and so
  // did the key it made room for. What is left is T11, which both tabs had
  // already decided to keep.
  assert.deepEqual(await held(one, "coordinate"), [
    coordinate(FREE, T14),
    coordinate(FREE, T12),
    coordinate(PREMIUM, T11),
  ]);

  // Done one after the other, the same two puts evict T10 and T11 and hold
  // both new keys. That is the difference the await gap makes.
  const serial = new PeriodKeyCache({ storage: new Storage(), maxEntries: 3 });
  await serial.put(PREMIUM, T10, periodKey(10), { publisher: PUB });
  await serial.put(PREMIUM, T11, periodKey(11), { publisher: PUB });
  await serial.put(FREE, T12, periodKey(12), { publisher: PUB });
  await serial.put(FREE, T14, periodKey(14), { publisher: PUB });
  await serial.put(PREMIUM, T15, periodKey(15), { publisher: PUB });
  assert.deepEqual(await held(serial, "coordinate"), [
    coordinate(FREE, T14),
    coordinate(FREE, T12),
    coordinate(PREMIUM, T15),
  ]);

  // The repair reaches this too, and pays for it: tab two's key comes back,
  // and capacity is still capacity, so the oldest `t` in the union goes to
  // make room for it. A reconcile can restore a lost key; it cannot restore
  // a cache to a size it never had.
  await two.reconcile();
  assert.deepEqual(await held(two, "coordinate"), [
    coordinate(FREE, T14),
    coordinate(FREE, T12),
    coordinate(PREMIUM, T15),
  ]);
});

test("reconcile is invoked, never timed - a second late reads the same, and twice changes nothing", async () => {
  // Every timer either cache schedules, counted on the globals it would have to
  // reach for. A cache repairing itself on a timer rather than on a call shows
  // up here as a scheduled timer, whatever delay it picked, so this does not
  // depend on waiting long enough. The watch goes up before the caches are
  // built, so a timer a constructor schedules counts too.
  const scheduled = timerWatch();
  const { storage, stop, one, two } = await tabs();

  try {
    const reached = stop.hold(({ op }) => op === "set");
    const slow = one.put(PREMIUM, T14, periodKey(1), { publisher: PUB });
    await reached;
    await two.put(PREMIUM, T15, periodKey(2), { publisher: PUB });
    stop.release();
    await slow;

    // And nothing repaired itself off a queued task either: the loop turns
    // here, so anything already queued has run before the read below.
    await scheduled.turn();
  } finally {
    scheduled.stop();
  }

  // Nothing repaired itself while the tab was doing something else. There is
  // no timer to fire, so the store stays as the race left it.
  assert.deepEqual(scheduled.calls, [], "the cache scheduled no timer");
  assert.deepEqual(
    await held(two, "coordinate"),
    [coordinate(PREMIUM, T14)],
    "the loop turned, and the key is still lost",
  );

  await two.reconcile();
  assert.deepEqual(await held(two, "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T14),
  ]);

  const after = storage.stats().sets;
  await two.reconcile();
  await two.reconcile();
  assert.equal(storage.stats().sets, after, "a second call writes nothing");
  assert.deepEqual(await held(two, "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T14),
  ]);

  // The other tab picks the repair up the same way, by being asked.
  await one.reconcile();
  assert.equal(storage.stats().sets, after, "and a tab with nothing to add writes nothing either");
  assert.deepEqual(await held(one, "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T14),
  ]);

  // Structurally: it takes nothing, so there is nothing for a scheduler to
  // pass it, and the cache holds no clock to fire one.
  assert.equal(PeriodKeyCache.prototype.reconcile.length, 0);

  // Without a store there is nothing to reconcile against, and saying so is
  // a no-op rather than a throw: the Map is both the tab's view and the whole
  // cache.
  const alone = new PeriodKeyCache();
  await alone.put(PREMIUM, T14, periodKey(1), { publisher: PUB });
  await alone.reconcile();
  assert.deepEqual(await held(alone, "coordinate"), [coordinate(PREMIUM, T14)]);
});

test("eviction is by size, oldest t first, and maxEntries + 1 coverage holds", async () => {
  for (const cache of [
    new PeriodKeyCache({ maxEntries: 3 }),
    new PeriodKeyCache({ maxEntries: 3, storage: new Storage() }),
  ]) {
    await cache.put(PREMIUM, T11, periodKey(11), { publisher: PUB });
    await cache.put(PREMIUM, T13, periodKey(13), { publisher: PUB });
    await cache.put(PREMIUM, T12, periodKey(12), { publisher: PUB });
    assert.deepEqual(await held(cache, "coordinate"), [
      coordinate(PREMIUM, T13),
      coordinate(PREMIUM, T12),
      coordinate(PREMIUM, T11),
    ]);

    // maxEntries + 1: one over, one out, and the one that goes is the
    // oldest `t` - never the arriving key, whatever order they arrived in.
    await cache.put(PREMIUM, T14, periodKey(14), { publisher: PUB });
    assert.deepEqual(await held(cache, "coordinate"), [
      coordinate(PREMIUM, T14),
      coordinate(PREMIUM, T13),
      coordinate(PREMIUM, T12),
    ]);

    // Age is not what put T11 out - being oldest at capacity is. An entry
    // older than everything held stays as long as there is room, and comes
    // straight back if it is put again.
    await cache.put(PREMIUM, T10, periodKey(10), { publisher: PUB });
    assert.deepEqual(
      await held(cache, "coordinate"),
      [coordinate(PREMIUM, T14), coordinate(PREMIUM, T13), coordinate(PREMIUM, T12)],
      "the arriving key is the oldest, so it is the one that goes",
    );

    // Across families the rule is the same: the oldest `t` anywhere.
    await cache.put(FREE, T15, periodKey(15), { publisher: PUB });
    assert.deepEqual(await held(cache, "coordinate"), [
      coordinate(FREE, T15),
      coordinate(PREMIUM, T14),
      coordinate(PREMIUM, T13),
    ]);

    // A different key at a held coordinate coexists there as a rival
    // candidate rather than overwriting the one already there - but capacity
    // counts candidates, so the second key at T14 is one over the bound. The
    // oldest `t` anywhere goes to make room: premium/T13. Coexistence is
    // promised while capacity permits it, not an exemption from capacity.
    await cache.put(PREMIUM, T14, periodKey(99), { publisher: PUB });
    assert.deepEqual(await held(cache, "coordinate"), [
      coordinate(FREE, T15),
      coordinate(PREMIUM, T14),
      coordinate(PREMIUM, T14),
    ]);
    assert.deepEqual(
      (await cache.candidatesAt(PREMIUM, T14, { publisher: PUB })).map(
        (/** @type {any} */ k) => k[0],
      ),
      [99, 14],
      "and the rival filed second is the one the trial reaches first",
    );
  }
});

test("candidate count is the bound, so rivals at one coordinate cannot overrun capacity", async () => {
  // entries() reports one row per candidate, so the size bound has to count
  // candidates too. Three non-interchangeable keys at ONE (publisher,
  // accessGroup, t) - what a run of period-key rotations delivers - would
  // coexist without limit under coordinate counting, and the bound would be
  // gone. Under candidate counting the third put is one over the two-entry
  // cap and evicts, so entries().length never exceeds maxEntries. What goes at
  // one coordinate is its oldest-filed rival: the coordinate has no second
  // label to break the tie on, and the key a rotation replaced longest ago is
  // the one the next article is least likely to need.
  for (const cache of [
    new PeriodKeyCache({ maxEntries: 2 }),
    new PeriodKeyCache({ maxEntries: 2, storage: new Storage() }),
  ]) {
    await cache.put(PREMIUM, T14, periodKey(1), { publisher: PUB });
    await cache.put(PREMIUM, T14, periodKey(2), { publisher: PUB });
    await cache.put(PREMIUM, T14, periodKey(3), { publisher: PUB });

    assert.equal(
      (await cache.entries()).length,
      2,
      "the hard invariant: entries().length <= maxEntries",
    );
    assert.deepEqual(
      await held(cache, "coordinate"),
      [coordinate(PREMIUM, T14), coordinate(PREMIUM, T14)],
      "the coordinate keeps candidates up to the bound and no further",
    );
    assert.deepEqual(
      (await cache.candidatesAt(PREMIUM, T14, { publisher: PUB })).map(
        (/** @type {any} */ k) => k[0],
      ),
      [3, 2],
      "the rival filed first is the one the coordinate gives up, and the two left are newest first",
    );
  }
});

test("under candidate counting the oldest t goes, even when a newer coordinate holds the rivals", async () => {
  // Four candidates over three coordinates: the newest period holds two rivals
  // and the older two hold one each. Coordinate counting would see three
  // coordinates at a cap of three and evict nothing; candidate counting sees
  // one too many and drops the oldest `t` anywhere - premium/T13 - whole, since
  // its candidate list empties. The rivals a rotation left never cost a period
  // the reader is in, but they still count toward the size.
  for (const cache of [
    new PeriodKeyCache({ maxEntries: 3 }),
    new PeriodKeyCache({ maxEntries: 3, storage: new Storage() }),
  ]) {
    await cache.put(PREMIUM, T15, periodKey(5), { publisher: PUB });
    await cache.put(PREMIUM, T15, periodKey(6), { publisher: PUB });
    await cache.put(PREMIUM, T13, periodKey(3), { publisher: PUB });
    assert.equal((await cache.entries()).length, 3, "three candidates, at the bound");

    await cache.put(PREMIUM, T14, periodKey(4), { publisher: PUB });
    assert.equal(
      (await cache.entries()).length,
      3,
      "still at the bound after the fourth candidate",
    );
    assert.deepEqual(
      await held(cache, "coordinate"),
      [coordinate(PREMIUM, T15), coordinate(PREMIUM, T15), coordinate(PREMIUM, T14)],
      "the oldest t went whole; the newer coordinate keeps both its rivals",
    );
    assert.deepEqual(
      (await cache.candidatesAt(PREMIUM, T14, { publisher: PUB })).map(
        (/** @type {any} */ k) => k[0],
      ),
      [4],
    );
  }
});

test("a repeated article in one period adds no entries, storage-backed too", async () => {
  const storage = new Storage();
  const cache = new PeriodKeyCache({ storage });

  // Three articles of the same period, each unlocked on its own - the dedup
  // is the cache's, not the caller's.
  for (let article = 0; article < 3; article++) {
    await cache.put(PREMIUM, T14, periodKey(14), { publisher: PUB });
    await cache.put(PREMIUM, T15, periodKey(15), { publisher: PUB });
  }

  assert.deepEqual(await held(cache, "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T14),
  ]);
  assert.deepEqual(
    await storage.keys(),
    [`dca.periodKeys.${family(PREMIUM)}`],
    "one entry per family in the store",
  );

  // And a coordinate arriving with the same bytes it already holds costs no
  // write at all, which is what makes the second article of a period free
  // rather than merely harmless.
  const sets = storage.stats().sets;
  await cache.put(PREMIUM, T14, periodKey(14), { publisher: PUB });
  assert.equal(storage.stats().sets, sets, "nothing changed, so nothing was written");

  // Different bytes at a held coordinate - a period-key rotation - coexist
  // beside the ones already there rather than overwriting them, and still add
  // no coordinate. The write happens because the family serialises differently
  // now; the store keeps one entry per family with both candidates in it, in the
  // order they were filed, and the trial reads that order back newest first.
  await cache.put(PREMIUM, T14, periodKey(42), { publisher: PUB });
  assert.equal(storage.stats().sets, sets + 1);
  assert.deepEqual(await held(cache, "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T14),
    coordinate(PREMIUM, T14),
  ]);
  assert.deepEqual(
    (await cache.candidatesAt(PREMIUM, T15, { publisher: PUB })).map(
      (/** @type {any} */ k) => k[0],
    ),
    [15],
  );
});

test("a failed trial unwrap evicts nothing", async () => {
  const storage = new Storage();
  const cache = new PeriodKeyCache({ maxEntries: 4, storage });

  // Four periods held, at capacity. The article is wrapped under the oldest
  // one, so the trial walks three misses before it hits.
  for (const [t, fill] of [
    [T10, 10],
    [T11, 11],
    [T12, 12],
    [T13, 13],
  ]) {
    await cache.put(PREMIUM, /** @type {string} */ (t), periodKey(/** @type {number} */ (fill)), {
      publisher: PUB,
    });
  }

  const contentKey = new Uint8Array(16).fill(7);
  const nonce = new Uint8Array(12).fill(3);
  const wrapped = await encrypt(periodKey(10), nonce, contentKey);

  const dcaData = {
    version: "1",
    resource: { renderId: "123456", domain: PUB },
    resourceJWT: `eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIn0.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "123456" })))}.c2lnbmF0dXJl`,
    contentData: {
      bodytext: {
        contentType: "text/html",
        nonce: base64urlEncode(nonce),
        aad: "123456|1|bodytext",
        keys: {
          [PREMIUM]: [{ t: T10, nonce: base64urlEncode(nonce), key: base64urlEncode(wrapped) }],
        },
      },
    },
    issuerData: {
      [ISSUER_NAME]: { sealed: {}, unlockUrl: UNLOCK_URL, keyId: KEY_ID },
    },
  };

  const unsealer = new Client({ cache, publisherOrigin: PUB });
  const sets = storage.stats().sets;

  const { covered } = await unsealer.resolve(dcaData, ["bodytext"]);
  assert.deepEqual(covered, ["bodytext"], "the oldest held key is the one that opens it");

  assert.deepEqual(
    await held(cache, "coordinate"),
    [
      coordinate(PREMIUM, T13),
      coordinate(PREMIUM, T12),
      coordinate(PREMIUM, T11),
      coordinate(PREMIUM, T10),
    ],
    "the three keys that missed are all still held",
  );
  assert.equal(storage.stats().sets, sets, "a read path does not write, so it cannot evict");

  // An article nothing opens is the same story: a full miss at capacity is
  // not a reason to drop anything. The next article may be what those keys
  // were cut for. This one is wrapped under a period the cache has never
  // held, so every candidate of both families is tried and every one fails.
  const foreign = base64urlEncode(await encrypt(periodKey(99), nonce, contentKey));
  const other = {
    version: "1",
    resource: { renderId: "123457", domain: PUB },
    resourceJWT: `eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIn0.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "123457" })))}.c2lnbmF0dXJl`,
    contentData: {
      bodytext: {
        contentType: "text/html",
        nonce: base64urlEncode(nonce),
        aad: "123457|1|bodytext",
        keys: {
          [PREMIUM]: [{ t: T15, nonce: base64urlEncode(nonce), key: foreign }],
          [FREE]: [{ t: T15, nonce: base64urlEncode(nonce), key: foreign }],
        },
      },
    },
    issuerData: {
      [ISSUER_NAME]: { sealed: {}, unlockUrl: UNLOCK_URL, keyId: KEY_ID },
    },
  };
  const { missing } = await unsealer.resolve(other, ["bodytext"]);
  assert.deepEqual(missing, ["bodytext"]);
  assert.equal((await cache.entries()).length, 4);
  assert.equal(storage.stats().sets, sets);
});

test("the reference policy evicts coordinates six hours behind the injected clock; a host may replace it", async () => {
  const clock = new Clock(AT);
  const storage = new Storage();
  const cache = new PeriodKeyCache({
    maxEntries: 3,
    storage,
    clock,
    evictionPolicy: evictAfterSixHours,
  });

  await cache.put(PREMIUM, T10, periodKey(10), { publisher: PUB });
  await cache.put(PREMIUM, T11, periodKey(11), { publisher: PUB });

  // Three days on, the next cache read applies the reference policy to the
  // storage-backed pool as well as the in-memory one.
  clock.advance(3 * 24 * 60 * 60 * 1000);
  await cache.candidatesAt(PREMIUM, T14, { publisher: PUB });
  await cache.entries();
  await cache.reconcile();

  assert.deepEqual(await held(cache, "coordinate"), []);

  const retained = new PeriodKeyCache({
    storage: new Storage(),
    clock,
    evictionPolicy: () => false,
  });
  await retained.put(PREMIUM, T10, periodKey(10), { publisher: PUB });
  assert.equal(
    (await retained.entries()).length,
    1,
    "the host replaces the default through one callback",
  );

  for (const options of [{ ttl: 60 }, { maxAge: 60 }, { now: () => 0 }]) {
    assert.throws(
      () => new PeriodKeyCache(options),
      (/** @type {any} */ err) => err.code === "unsupported_option",
      `${Object.keys(options)[0]} is not a thing the cache has`,
    );
  }
  assert.equal(PeriodKeyCache.prototype.put.length, 3, "accessGroup, t, key - and no now");
  assert.equal(PeriodKeyCache.prototype.candidatesAt.length, 2);

  // Capacity remains an independent hard bound.
  const bounded = new PeriodKeyCache({ maxEntries: 3 });
  for (const [t, value] of [
    [T10, 10],
    [T11, 11],
    [T12, 12],
    [T13, 13],
  ]) {
    await bounded.put(PREMIUM, t, periodKey(value), { publisher: PUB });
  }
  assert.deepEqual(await held(bounded, "coordinate"), [
    coordinate(PREMIUM, T13),
    coordinate(PREMIUM, T12),
    coordinate(PREMIUM, T11),
  ]);
});

test("the cache refuses what it still does not implement, and what it has never heard of", () => {
  // `keyBy` is implemented now and belongs to multi-issuer.test.js: whether
  // `issuerName` joins the cache key decides whether one issuer's key opens
  // another's content, which needs two issuers to be worth anything.
  for (const options of [{ storage: {} }, { storage: { get: () => undefined } }]) {
    assert.throws(
      () => new PeriodKeyCache(options),
      (/** @type {any} */ err) => err.code === "bad_config",
      "a storage that cannot answer the calls is not a storage",
    );
  }

  for (const maxEntries of [0, -1, 1.5, "4"]) {
    assert.throws(
      () => new PeriodKeyCache({ maxEntries: /** @type {any} */ (maxEntries) }),
      (/** @type {any} */ err) => err.code === "bad_config",
      `maxEntries ${maxEntries} is not a capacity`,
    );
  }
});

test("a storage-backed cache refuses key material it cannot keep", async () => {
  const key = await globalThis.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "decrypt",
  ]);

  // The one asymmetry the design names: localStorage holds strings, and a
  // client-bound grant is a handle whose bytes are not readable. That is an
  // IndexedDB adapter, not something to fail quietly halfway through a JSON
  // round-trip.
  const backed = new PeriodKeyCache({ storage: new Storage() });
  await assert.rejects(
    () => backed.put(PREMIUM, T14, key, { publisher: PUB }),
    (/** @type {any} */ err) => err.code === "bad_key",
  );

  // The plain-Map cache still takes either kind, which is what lets one
  // cache back direct and client-bound.
  const plain = new PeriodKeyCache();
  await plain.put(PREMIUM, T14, key, { publisher: PUB });
  assert.deepEqual(await plain.candidatesAt(PREMIUM, T14, { publisher: PUB }), [key]);
});

test("an inherited accessGroup is not a stored family either", async () => {
  const cache = new PeriodKeyCache({ storage: new Storage() });
  await cache.put(PREMIUM, T14, periodKey(1), { publisher: PUB });

  // `__proto__` is named here and not in the shared list: it is a setter on an
  // object literal rather than a name a read finds on the prototype, and it is
  // the one this test goes on to put a real family under.
  for (const name of [...INHERITED, "__proto__"]) {
    assert.deepEqual(
      await cache.candidatesAt(name, T14, { publisher: PUB }),
      [],
      `candidates('${name}') must not resolve`,
    );
  }

  // And a family genuinely called `__proto__` is an ordinary family.
  await cache.put("__proto__", T15, periodKey(2), { publisher: PUB });
  assert.deepEqual(
    (await cache.candidatesAt("__proto__", T15, { publisher: PUB })).map(
      (/** @type {any} */ k) => k[0],
    ),
    [2],
  );
  assert.deepEqual(await held(cache, "coordinate"), [
    coordinate("__proto__", T15),
    coordinate(PREMIUM, T14),
  ]);
});

test("two browsers over one storage keep their period keys apart", async () => {
  // Two `Browser`s are two users (demo/actors/Browser.js), and two users on one
  // machine is the one thing separate storage was standing in for. Handed the
  // same backend, they must still not read or overwrite one another: the host
  // gives each its own cache namespace, so a key one filed is a family name the
  // other's store never holds. Without that scope both file under one prefix, the
  // second put lands on the first's coordinate, and the client that never
  // unlocked the article reads the other client's key back.
  const clock = new Clock(AT);
  const network = new Network({ clock });
  const storage = new Storage();
  const issuers = [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL }];

  const one = new Browser({ clock, network, storage, issuers, cacheNamespace: "one" });
  const two = new Browser({ clock, network, storage, issuers, cacheNamespace: "two" });

  await one.cache.put(PREMIUM, T14, periodKey(1), { publisher: PUB });
  await two.cache.put(PREMIUM, T14, periodKey(2), { publisher: PUB });

  assert.deepEqual(
    (await one.cache.candidatesAt(PREMIUM, T14, { publisher: PUB })).map(
      (/** @type {any} */ k) => k[0],
    ),
    [1],
    "the first client keeps its own key across the second writing the same coordinate over one storage",
  );
  assert.deepEqual(
    (await two.cache.candidatesAt(PREMIUM, T14, { publisher: PUB })).map(
      (/** @type {any} */ k) => k[0],
    ),
    [2],
    "and the second client never reads the first client's key back",
  );
});

test("prefix-related namespaces over one storage stay isolated", async () => {
  // Two logical clients over one store whose injected namespaces are dotted
  // prefixes of each other: `a` and `a.b`. A storage key is
  // `dca.periodKeys.<namespace-token>.<family>`, so if the namespace goes in
  // raw, `a`'s prefix `dca.periodKeys.a.` is a prefix of every key `a.b`
  // files, and the cache scoped to `a` reads - and, at capacity, evicts - the
  // entries of the cache scoped to `a.b`. `client-<N>` tokens never trip this
  // because none is a dotted prefix of another; an injected name can be.
  const storage = new Storage();
  const a = new PeriodKeyCache({ storage, namespace: "a", maxEntries: 1 });
  const ab = new PeriodKeyCache({ storage, namespace: "a.b" });

  // a.b files first, at the oldest period - the entry `a` would pick as its
  // eviction victim if the prefix let it see it.
  await ab.put(PREMIUM, T10, periodKey(2), { publisher: PUB });
  await a.put(PREMIUM, T14, periodKey(1), { publisher: PUB });

  // Reads stay inside a namespace. `entries` scans the store by prefix, so a
  // dotted namespace that is a prefix of another must not draw its families in.
  assert.deepEqual(
    await held(a, "coordinate"),
    [coordinate(PREMIUM, T14)],
    "a reads only its own family, not a.b whose key also starts dca.periodKeys.a.",
  );
  assert.deepEqual(await held(ab, "coordinate"), [coordinate(PREMIUM, T10)]);
  assert.deepEqual(
    (await a.candidatesAt(PREMIUM, T14, { publisher: PUB })).map((/** @type {any} */ k) => k[0]),
    [1],
  );
  assert.deepEqual(
    (await ab.candidatesAt(PREMIUM, T10, { publisher: PUB })).map((/** @type {any} */ k) => k[0]),
    [2],
  );

  // A capacity-limited put on `a` counts and evicts over its own namespace
  // alone. Under the collision it would see a.b's T10 as the oldest entry
  // anywhere and evict it to make room for its own new key.
  await a.put(FREE, T15, periodKey(3), { publisher: PUB });

  assert.deepEqual(
    (await ab.candidatesAt(PREMIUM, T10, { publisher: PUB })).map((/** @type {any} */ k) => k[0]),
    [2],
    "a.b keeps its entry through a capacity put on a",
  );
  assert.deepEqual(await held(ab, "coordinate"), [coordinate(PREMIUM, T10)]);
});

test("a cache with no namespace neither reads nor evicts a namespaced client's families", async () => {
  // A page client left bare beside a widget client scoped to `widget`, over one
  // store. The bare prefix `dca.periodKeys.` is a string prefix of the widget's
  // `dca.periodKeys.d2lkZ2V0.`, so a plain prefix scan would draw the widget's
  // family into the page client's view, count it against the page's capacity
  // and evict it there.
  const storage = new Storage();
  const widget = new PeriodKeyCache({ storage, namespace: "widget" });
  const page = new PeriodKeyCache({ storage, maxEntries: 1 });

  // The widget files at the oldest period, the victim a capacity pass that
  // saw it would pick first.
  await widget.put(PREMIUM, T10, periodKey(9), { publisher: PUB });
  await page.put(PREMIUM, T14, periodKey(1), { publisher: PUB });
  await page.put(FREE, T15, periodKey(2), { publisher: PUB });

  assert.deepEqual(
    await held(page, "coordinate"),
    [coordinate(FREE, T15)],
    "the page client reads only its own family, and its capacity still holds",
  );
  assert.deepEqual(
    (await widget.candidatesAt(PREMIUM, T10, { publisher: PUB })).map(
      (/** @type {any} */ k) => k[0],
    ),
    [9],
    "the widget keeps its key through the page client's capacity puts",
  );
  assert.deepEqual(await held(widget, "coordinate"), [coordinate(PREMIUM, T10)]);
  assert.deepEqual(
    await page.candidatesAt(PREMIUM, T10, { publisher: PUB }),
    [],
    "and the page client never trials the widget's key",
  );
});

test("a bare storage-backed cache refuses a family its own scan would take for a namespaced one", async () => {
  // A publisher context is an origin, so a stored family starts `https:` and
  // reaches `:` before any `.`. A family that starts with a base64url token and
  // a `.` has the shape of another client's namespace; filing it would leave a
  // key the bare cache's own scan skips.
  const storage = new Storage();
  const page = new PeriodKeyCache({ storage });
  await assert.rejects(() => page.put(PREMIUM, T14, periodKey(1), { publisher: "news.example" }), {
    code: "bad_key",
  });
  assert.deepEqual([...(await storage.keys())], []);

  // A namespaced cache has no such shape to protect, and a Map-backed bare cache
  // scans nothing.
  const scoped = new PeriodKeyCache({ storage, namespace: "page" });
  await scoped.put(PREMIUM, T14, periodKey(1), { publisher: "news.example" });
  assert.equal((await scoped.candidatesAt(PREMIUM, T14, { publisher: "news.example" })).length, 1);
  const memory = new PeriodKeyCache();
  await memory.put(PREMIUM, T14, periodKey(1), { publisher: "news.example" });
  assert.equal((await memory.candidatesAt(PREMIUM, T14, { publisher: "news.example" })).length, 1);
});

test("one instance's puts into one family take turns, so concurrent puts keep both coordinates", async () => {
  // One tab opens two items of one group with `Promise.all`. Each put reads the
  // family, adds its key and writes the family back. Without turns inside the
  // instance both read the empty family and the second write carries only its
  // own coordinate. The cross-tab lost write above stays as designed.
  const sequential = new PeriodKeyCache({ storage: new Storage() });
  await sequential.put(PREMIUM, T14, periodKey(1), { publisher: PUB });
  await sequential.put(PREMIUM, T15, periodKey(2), { publisher: PUB });
  assert.deepEqual(await held(sequential, "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T14),
  ]);

  const storage = new Storage();
  const cache = new PeriodKeyCache({ storage });
  await Promise.all([
    cache.put(PREMIUM, T14, periodKey(1), { publisher: PUB }),
    cache.put(PREMIUM, T15, periodKey(2), { publisher: PUB }),
  ]);
  // The next page load builds a new cache over the same store.
  const nextPage = new PeriodKeyCache({ storage });
  assert.deepEqual(await held(nextPage, "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T14),
  ]);
});

test("a read's eviction write takes its turn behind a concurrent put", async () => {
  // A read that finds the store over this instance's capacity evicts and
  // writes the family back. Started beside a put into the same family, it must
  // not write a snapshot taken before the put landed. A roomier cache over the
  // same store, such as another tab's, left three entries; this one keeps two.
  const storage = new Storage();
  const roomy = new PeriodKeyCache({ storage, maxEntries: 3 });
  await roomy.put(PREMIUM, T10, periodKey(10), { publisher: PUB });
  await roomy.put(PREMIUM, T11, periodKey(11), { publisher: PUB });
  await roomy.put(PREMIUM, T12, periodKey(12), { publisher: PUB });

  const cache = new PeriodKeyCache({ storage, maxEntries: 2 });
  await Promise.all([
    cache.put(PREMIUM, T15, periodKey(15), { publisher: PUB }),
    cache.candidatesAt(PREMIUM, T12, { publisher: PUB }),
  ]);
  assert.deepEqual(await held(new PeriodKeyCache({ storage, maxEntries: 2 }), "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T12),
  ]);
});

test("a storage fault still reaches its caller, and the next operation runs", async () => {
  // Taking turns must not swallow a fault or leave a failed turn blocking the
  // ones queued behind it.
  let failNextSet = true;
  const storage = new Storage({
    gate: ({ op }) => {
      if (op === "set" && failNextSet) {
        failNextSet = false;
        throw new Error("the disk is full");
      }
      return undefined;
    },
  });
  const cache = new PeriodKeyCache({ storage });
  const [first, second] = await Promise.allSettled([
    cache.put(PREMIUM, T14, periodKey(1), { publisher: PUB }),
    cache.put(PREMIUM, T15, periodKey(2), { publisher: PUB }),
  ]);
  assert.equal(first.status, "rejected");
  assert.match(String(/** @type {any} */ (first).reason?.message), /the disk is full/);
  assert.equal(second.status, "fulfilled");
  assert.deepEqual(
    (await cache.candidatesAt(PREMIUM, T15, { publisher: PUB })).map(
      (/** @type {any} */ k) => k[0],
    ),
    [2],
  );
});

for (const operation of ["get", "reconcile"]) {
  test(`reader reset drains an old ${operation} and cannot reload its namespace`, async () => {
    const boundary = brake();
    const storage = new Storage({ gate: boundary.gate });
    const cache = new PeriodKeyCache({ storage, namespace: "reader" });
    const other = new PeriodKeyCache({ storage, namespace: "unrelated" });
    const context = { publisher: PUB };
    const key = new Uint8Array(16).fill(7);
    await cache.put(PREMIUM, T14, key, context);
    await other.put(PREMIUM, T14, key, context);
    const entered = boundary.hold(({ op }) => op === (operation === "set" ? "set" : "get"));
    const old =
      operation === "set"
        ? cache.put(PREMIUM, T15, key, context)
        : operation === "get"
          ? cache.candidatesAt(PREMIUM, T14, context)
          : cache.reconcile();
    const retired = assert.rejects(old, { code: "context_retired" });
    await entered;
    let completed = false;
    const clearing = cache.clearReaderContext().then(() => {
      completed = true;
    });
    await assert.rejects(cache.entries(), { code: "context_retired" });
    assert.equal(completed, false, "issued storage work must settle before deletion");
    boundary.release();
    await Promise.all([retired, clearing]);
    assert.deepEqual(await cache.entries(), []);
    const reloaded = new PeriodKeyCache({ storage, namespace: "reader" });
    assert.deepEqual(await reloaded.entries(), []);
    assert.equal((await other.entries()).length, 1, "another namespace survives");
    await cache.put(PREMIUM, T15, key, context);
    assert.equal((await cache.candidatesAt(PREMIUM, T15, context)).length, 1);
  });
}

test("failed durable reader cleanup detaches access and cannot become a successful retry", async () => {
  const fault = new Error("remove failed");
  let fail = false;
  let erases = 0;
  const storage = new Storage({
    gate: ({ op }) => {
      if (fail && op === "remove" && ++erases === 2) throw fault;
    },
  });
  const cache = new PeriodKeyCache({ storage, namespace: "reader" });
  await cache.put(PREMIUM, T14, new Uint8Array(16).fill(7), { publisher: PUB });
  await cache.put(FREE, T14, new Uint8Array(16).fill(8), { publisher: PUB });
  fail = true;
  await assert.rejects(cache.clearReaderContext(), (error) => error === fault);
  assert.equal(erases, 2, "a later erase failure cannot be hidden by the first success");
  await assert.rejects(cache.candidatesAt(PREMIUM, T14, { publisher: PUB }), {
    code: "context_retired",
  });
  fail = false;
  await assert.rejects(cache.clearReaderContext(), (error) => error === fault);
  assert.equal(
    (await new PeriodKeyCache({ storage, namespace: "reader" }).entries()).length,
    1,
    "the host must retire this unresolved persistent namespace",
  );
});

test("distinct rivals sharing bytes survive reload and a repeated older key keeps its order", async () => {
  const older = new Uint8Array(16).fill(1);
  const newer = older.slice();
  newer[15] = 2;
  for (const storage of [undefined, new Storage()]) {
    const cache = new PeriodKeyCache({ storage });
    const context = { publisher: PUB };
    await cache.put(PREMIUM, T14, older, context);
    await cache.put(PREMIUM, T14, newer, context);
    await cache.put(PREMIUM, T14, older, context);
    await cache.put(PREMIUM, T14, older.slice(), context);
    assert.deepEqual(await cache.candidatesAt(PREMIUM, T14, context), [newer, older]);
    if (storage) {
      assert.deepEqual(await new PeriodKeyCache({ storage }).candidatesAt(PREMIUM, T14, context), [
        newer,
        older,
      ]);
    }
  }
});

test("reconcile repeatedly repairs a lost family and retains coordinates and rivals across a later put", async () => {
  const context = { publisher: PUB };
  const first = new Uint8Array(16).fill(1);
  const second = new Uint8Array(16).fill(2);
  const third = new Uint8Array(16).fill(3);
  for (const replacement of [false, true]) {
    const storage = new Storage();
    const cache = new PeriodKeyCache({ storage });
    await cache.put(PREMIUM, T10, first, context);
    await cache.put(PREMIUM, T11, second, context);
    const [storageKey] = await storage.keys();
    await storage.remove(storageKey);
    if (replacement) {
      await new PeriodKeyCache({ storage }).put(PREMIUM, T11, third, context);
      await cache.put(PREMIUM, T12, third, context);
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      await cache.reconcile();
      const reloaded = new PeriodKeyCache({ storage });
      assert.deepEqual(await reloaded.candidatesAt(PREMIUM, T10, context), [first]);
      const rivals = await reloaded.candidatesAt(PREMIUM, T11, context);
      assert.equal(rivals.length, replacement ? 2 : 1);
      assert.ok(rivals.some((key) => Buffer.from(key).equals(second)));
      if (replacement) {
        assert.ok(rivals.some((key) => Buffer.from(key).equals(third)));
        assert.deepEqual(await reloaded.candidatesAt(PREMIUM, T12, context), [third]);
      }
      await storage.remove(storageKey);
    }
  }
});

test("reconcile applies expiry and capacity to its union and retains only that bounded result", async () => {
  const storage = new Storage();
  const context = { publisher: PUB };
  let expired;
  const cache = new PeriodKeyCache({
    storage,
    maxEntries: 2,
    clock: { now: () => 0 },
    evictionPolicy: ({ t }) => t === expired,
  });
  for (const t of [T10, T11]) await cache.put(PREMIUM, t, new Uint8Array(16).fill(1), context);
  const [storageKey] = await storage.keys();
  await storage.remove(storageKey);
  const other = new PeriodKeyCache({ storage });
  for (const t of [T12, T13, T14]) await other.put(PREMIUM, t, new Uint8Array(16).fill(2), context);
  expired = T14;
  for (let attempt = 0; attempt < 2; attempt++) {
    await cache.reconcile();
    assert.deepEqual((await held(new PeriodKeyCache({ storage }), "coordinate")).sort(), [
      coordinate(PREMIUM, T12),
      coordinate(PREMIUM, T13),
    ]);
    await storage.remove(storageKey);
  }
});

test("reconcile bounds the union of independently retained rivals", async () => {
  const storage = new Storage();
  const cache = new PeriodKeyCache({ storage });
  const context = { publisher: PUB };
  for (let n = 1; n <= 4; n++) await cache.put(PREMIUM, T14, new Uint8Array(16).fill(n), context);
  const [storageKey] = await storage.keys();
  await storage.remove(storageKey);
  const other = new PeriodKeyCache({ storage });
  for (let n = 5; n <= 8; n++) await other.put(PREMIUM, T14, new Uint8Array(16).fill(n), context);
  await cache.reconcile();
  assert.equal(JSON.parse(await storage.get(storageKey))[T14].length, 4);
  const rivals = await new PeriodKeyCache({ storage }).candidatesAt(PREMIUM, T14, context);
  assert.equal(rivals.length, 4, "repair cannot exceed the coordinate's rival bound");
  assert.equal(new Set(rivals.map(base64urlEncode)).size, 4);
});

test("an issuer-keyed cache accepts a singular issuer read without mixing families", async () => {
  const cache = new PeriodKeyCache({ keyBy: keyByIssuer });
  const key = new Uint8Array(16).fill(1);
  await cache.put(PREMIUM, T14, key, { publisher: PUB, issuerName: "alpha" });
  assert.deepEqual(
    await cache.candidatesAt(PREMIUM, T14, { publisher: PUB, issuerName: "alpha" }),
    [key],
  );
  assert.deepEqual(
    await cache.candidatesAt(PREMIUM, T14, { publisher: PUB, issuerName: "beta" }),
    [],
  );
});

test("namespace deletion starts only after an issued write has landed", async () => {
  let release, announce;
  const held = {
    promise: new Promise((resolve) => {
      release = resolve;
    }),
    release: () => release(),
  };
  const entered = {
    promise: new Promise((resolve) => {
      announce = resolve;
    }),
    release: () => announce(),
  };
  let holdNextSet = false;
  let armed = false;
  let setLanded = false;
  let keysBeforeSet = false;
  const storage = new Storage({
    gate({ op }) {
      if (op === "set" && holdNextSet) {
        holdNextSet = false;
        entered.release();
        return held.promise.then(() => {
          setLanded = true;
        });
      }
      if (op === "keys" && armed && !setLanded) keysBeforeSet = true;
      return undefined;
    },
  });
  const cache = new PeriodKeyCache({ storage, namespace: "reader" });
  const key = new Uint8Array(16).fill(7);
  await cache.put(PREMIUM, T14, key, { publisher: PUB });
  holdNextSet = true;
  const old = cache.put(PREMIUM, T15, key, { publisher: PUB });
  await entered.promise;
  armed = true;
  const clearing = cache.clearReaderContext();
  held.release();
  await assert.rejects(old, { code: "context_retired" });
  await clearing;
  assert.equal(keysBeforeSet, false, "cleanup listed the namespace only after the write landed");
  assert.deepEqual(await new PeriodKeyCache({ storage, namespace: "reader" }).entries(), []);
});

test("a default-namespace reset leaves namespaced siblings in the shared store", async () => {
  const storage = new Storage();
  const main = new PeriodKeyCache({ storage });
  const sibling = new PeriodKeyCache({ storage, namespace: "unrelated" });
  const key = new Uint8Array(16).fill(7);
  await main.put(PREMIUM, T14, key, { publisher: PUB });
  await sibling.put(PREMIUM, T14, key, { publisher: PUB });
  assert.equal((await sibling.entries()).length, 1, "the sibling holds a key");
  await main.clearReaderContext();
  assert.deepEqual(await main.entries(), []);
  assert.equal((await sibling.entries()).length, 1, "the sibling namespace survived");
  assert.equal(
    (await new PeriodKeyCache({ storage, namespace: "unrelated" }).entries()).length,
    1,
    "a reload of the sibling namespace still finds its key",
  );
});
