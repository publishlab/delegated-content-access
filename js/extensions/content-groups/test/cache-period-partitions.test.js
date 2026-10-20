// @ts-check
//
// The shared period-key cache files content-group period keys under the
// extension's structured partitions. One dedicated instance per entry kind
// holds them; an ordinary instance over the same store never reads them, and
// neither instance accepts the other's calls. Stored content-group families
// are versioned and carry their kind, which a load checks.

import test from "node:test";
import assert from "node:assert/strict";

import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { Storage } from "../../../demo/actors/Storage.js";
import { CONTRACT, periodKeyPartition } from "../core-shared/construction.js";

const PUBLISHER = "https://news.example";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
const KIND = CONTRACT.keyKinds.periodKey;
const T = "261014T1500";

/** @param {number} fill */
const key = (fill) => new Uint8Array(16).fill(fill);

/** @param {string} contentName @param {string} [group] */
const partitionOf = (contentName, group = "politics") =>
  periodKeyPartition(PUBLISHER, GEOMETRY, contentName, group);

/** @param {any} error @param {string} code @param {RegExp} message */
const fails = (error, code, message) => error?.code === code && message.test(error.message);

test("one partition per content name: a key filed for bodytext is no candidate for headline", async () => {
  const cache = new PeriodKeyCache({ entryKind: KIND });
  await cache.put("politics", T, key(1), { partition: partitionOf("bodytext") });

  assert.deepEqual(
    await cache.candidatesAt("politics", T, { partition: partitionOf("bodytext") }),
    [key(1)],
  );
  assert.deepEqual(
    await cache.candidatesAt("politics", T, { partition: partitionOf("headline") }),
    [],
    "a period key of bodytext must not be tried for headline",
  );
});

test("partition parts encode injectively: parts that join alike stay apart", async () => {
  const cache = new PeriodKeyCache({ entryKind: KIND });
  await cache.put("g", T, key(1), { partition: { kind: KIND, parts: ["a|b", "c"] } });
  await cache.put("g", T, key(2), { partition: { kind: KIND, parts: ["a", "b|c"] } });
  await cache.put("g", T, key(3), { partition: { kind: KIND, parts: ["a\0b", "c"] } });
  await cache.put("g", T, key(4), { partition: { kind: KIND, parts: ["a", "b\0c"] } });

  for (const [parts, fill] of /** @type {const} */ ([
    [["a|b", "c"], 1],
    [["a", "b|c"], 2],
    [["a\0b", "c"], 3],
    [["a", "b\0c"], 4],
  ])) {
    assert.deepEqual(
      await cache.candidatesAt("g", T, { partition: { kind: KIND, parts: [...parts] } }),
      [key(fill)],
    );
  }
});

test("a partitioned cache refuses a partition of another kind, an ordinary call and a handle", async () => {
  assert.throws(
    () => new PeriodKeyCache({ entryKind: KIND, keyBy: ({ accessGroup }) => accessGroup }),
    (error) => fails(error, "bad_config", /partition/),
  );
  assert.throws(
    () => new PeriodKeyCache({ entryKind: "" }),
    (error) => fails(error, "bad_config", /entryKind/),
  );

  const cache = new PeriodKeyCache({ entryKind: KIND });
  const other = { kind: "someOtherKind", parts: ["x"] };
  await assert.rejects(cache.put("politics", T, key(1), { partition: other }), (error) =>
    fails(error, "bad_key", /partition of kind/),
  );
  await assert.rejects(cache.candidatesAt("politics", T, { partition: other }), (error) =>
    fails(error, "bad_key", /partition of kind/),
  );
  await assert.rejects(cache.put("politics", T, key(1), { publisher: PUBLISHER }), (error) =>
    fails(error, "bad_key", /files under a partition/),
  );
  await assert.rejects(
    cache.candidatesAt("politics", T, { publisher: PUBLISHER, issuerNames: ["issuer"] }),
    (error) => fails(error, "bad_key", /files under a partition/),
  );
  await assert.rejects(
    cache.put("politics", T, key(1), { partition: { kind: KIND, parts: [] } }),
    (error) => fails(error, "bad_key", /parts/),
  );
  await assert.rejects(
    cache.put("politics", T, key(1), { partition: { kind: KIND, parts: ["a", 7] } }),
    (error) => fails(error, "bad_key", /parts/),
  );

  const handle = await globalThis.crypto.subtle.importKey("raw", key(9), "AES-GCM", false, [
    "unwrapKey",
  ]);
  await assert.rejects(
    cache.put("politics", T, handle, { partition: partitionOf("bodytext") }),
    (error) => fails(error, "bad_key", /bytes/),
  );
});

test("an ordinary cache refuses a partitioned entry, so content-group bytes never reach it", async () => {
  const ordinary = new PeriodKeyCache();
  await assert.rejects(
    ordinary.put("politics", T, key(1), {
      publisher: PUBLISHER,
      partition: partitionOf("bodytext"),
    }),
    (error) => fails(error, "bad_key", /ordinary period-key cache/),
  );
  await assert.rejects(
    ordinary.candidatesAt("politics", T, {
      publisher: PUBLISHER,
      partition: partitionOf("bodytext"),
    }),
    (error) => fails(error, "bad_key", /ordinary period-key cache/),
  );
  assert.deepEqual(await ordinary.entries(), []);
});

test("stored families are versioned, carry their kind and reload in a new instance", async () => {
  const storage = new Storage();
  const writer = new PeriodKeyCache({ entryKind: KIND, storage });
  await writer.put("politics", T, key(1), { partition: partitionOf("bodytext") });

  const stored = await storage.keys();
  assert.equal(stored.length, 1);
  const prefix = `dca.keyFamilies.${Buffer.from(KIND).toString("base64url")}.`;
  assert.ok(stored[0].startsWith(prefix), `${stored[0]} files under the entry-kind prefix`);
  const value = JSON.parse(/** @type {string} */ (await storage.get(stored[0])));
  assert.equal(value.v, 1);
  assert.equal(value.kind, KIND);
  assert.deepEqual(value.family, [KIND, ...partitionOf("bodytext").parts, "politics"]);
  assert.deepEqual(Object.keys(value.periods), [T]);

  const reader = new PeriodKeyCache({ entryKind: KIND, storage });
  assert.deepEqual(
    await reader.candidatesAt("politics", T, { partition: partitionOf("bodytext") }),
    [key(1)],
  );
  assert.deepEqual(
    await reader.candidatesAt("politics", T, { partition: partitionOf("headline") }),
    [],
  );
});

test("a load refuses a stored family of another kind, another version or a moved family", async () => {
  const prefix = `dca.keyFamilies.${Buffer.from(KIND).toString("base64url")}.`;
  const family = [KIND, ...partitionOf("bodytext").parts, "politics"];
  const token = Buffer.from(JSON.stringify(family)).toString("base64url");
  const periods = { [T]: [{ key: Buffer.from(key(1)).toString("base64url"), order: 1 }] };

  for (const [value, message] of /** @type {const} */ ([
    [{ v: 1, kind: "periodKey", family, periods }, /kind/],
    [{ v: 2, kind: KIND, family, periods }, /version/],
    [{ v: 1, kind: KIND, family: [...family.slice(0, -1), "sports"], periods }, /family/],
    [{ [T]: periods[T] }, /version/],
  ])) {
    const storage = new Storage();
    await storage.set(prefix + token, JSON.stringify(value));
    const cache = new PeriodKeyCache({ entryKind: KIND, storage });
    await assert.rejects(
      cache.candidatesAt("politics", T, { partition: partitionOf("bodytext") }),
      (error) => fails(error, "bad_storage", message),
    );
  }
});

test("ordinary and content-group instances share one store without reading each other", async () => {
  const storage = new Storage();
  const ordinary = new PeriodKeyCache({ storage });
  const groups = new PeriodKeyCache({ entryKind: KIND, storage });

  await ordinary.put("politics", T, key(7), { publisher: PUBLISHER });
  await groups.put("politics", T, key(1), { partition: partitionOf("bodytext") });

  assert.deepEqual(await ordinary.candidatesAt("politics", T, { publisher: PUBLISHER }), [key(7)]);
  assert.deepEqual(
    (await ordinary.entries()).map(({ key: held }) => held),
    [key(7)],
    "the ordinary instance sees no content-group bytes",
  );
  assert.deepEqual(
    (await groups.entries()).map(({ key: held }) => held),
    [key(1)],
    "the content-group instance sees no ordinary bytes",
  );

  await groups.clearReaderContext();
  assert.deepEqual(await ordinary.candidatesAt("politics", T, { publisher: PUBLISHER }), [key(7)]);
  assert.equal((await storage.keys()).length, 1);
});

test("capacity applies to stored content-group families on load", async () => {
  const storage = new Storage();
  const writer = new PeriodKeyCache({ entryKind: KIND, storage, maxEntries: 8 });
  const labels = ["261014T1200", "261014T1300", "261014T1400", "261014T1500"];
  for (const [index, t] of labels.entries())
    await writer.put("politics", t, key(index + 1), { partition: partitionOf("bodytext") });

  const reader = new PeriodKeyCache({ entryKind: KIND, storage, maxEntries: 2 });
  assert.deepEqual(
    (await reader.entries()).map(({ t }) => t),
    ["261014T1500", "261014T1400"],
  );
  assert.equal(
    Object.keys(
      JSON.parse(/** @type {string} */ (await storage.get((await storage.keys())[0]))).periods,
    ).length,
    2,
  );
});

test("reset fences a delayed content-group write: no late write under a retired reader", async () => {
  /** @type {(() => void)|null} */
  let release = null;
  let hold = true;
  const storage = new Storage({
    gate: ({ op }) => {
      if (op !== "set" || !hold) return undefined;
      hold = false;
      return new Promise((resolve) => {
        release = () => resolve(undefined);
      });
    },
  });
  const cache = new PeriodKeyCache({ entryKind: KIND, storage });
  const filing = cache.put("politics", T, key(1), { partition: partitionOf("bodytext") });
  while (release === null) await new Promise((resolve) => setImmediate(resolve));

  const clearing = cache.clearReaderContext();
  /** @type {() => void} */ (release)();
  await assert.rejects(filing, (error) => fails(error, "context_retired", /retired/));
  await clearing;

  assert.deepEqual(await storage.keys(), [], "the store holds nothing after reset");
  assert.deepEqual(
    await cache.candidatesAt("politics", T, { partition: partitionOf("bodytext") }),
    [],
  );
});
