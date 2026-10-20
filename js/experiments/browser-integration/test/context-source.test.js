// @ts-check
//
// Units for the context source in
// `experiments/browser-integration/implementation/context-source.js`. Ordering
// tests log every listener call and assert the whole sequence: a source that
// delivers nested calls, or hands a late subscriber an older snapshot, writes a
// different log.

import test from "node:test";
import assert from "node:assert/strict";

import { admitSnapshot, createContextSource } from "../implementation/context-source.js";

const MAX = Number.MAX_SAFE_INTEGER;

/**
 * @param {number} sequence
 * @param {boolean} contextKnown
 * @param {string | number | boolean | null} contextRevision
 */
function snap(sequence, contextKnown, contextRevision) {
  return { sequence, contextKnown, contextRevision };
}

/** @param {import("../implementation/context-source.js").ContextSnapshot} s */
function label(s) {
  return `${s.sequence}${s.contextKnown ? "" : "?"}:${String(s.contextRevision)}`;
}

test("subscribe replays the current snapshot before it returns, passing the returned stop", () => {
  const source = createContextSource(snap(0, false, null));
  /** @type {string[]} */
  const log = [];
  /** @type {Array<() => void>} */
  const stops = [];

  const stop = source.provider.subscribe((s, st) => {
    log.push(label(s));
    stops.push(st);
  });
  log.push("returned");

  assert.deepEqual(log, ["0?:null", "returned"]);
  assert.equal(stops[0], stop);
});

test("the provider exposes subscribe only; publishing stays with the controller", () => {
  const source = createContextSource(snap(0, true, "r1"));
  assert.deepEqual(Object.keys(source.provider), ["subscribe"]);
  assert.ok(Object.isFrozen(source.provider));
  assert.ok(Object.isFrozen(source));
});

test("a later sequence is delivered; an older or equal one is ignored", () => {
  const source = createContextSource(snap(1, true, "r1"));
  /** @type {string[]} */
  const seen = [];
  source.provider.subscribe((s) => seen.push(label(s)));

  assert.equal(source.publish(snap(3, false, "r1")), true);
  assert.equal(source.publish(snap(2, true, "r1")), false); // a delayed older observation
  assert.equal(source.publish(snap(3, true, "r1")), false);
  assert.equal(source.publish(snap(4, true, "r1")), true);

  assert.deepEqual(seen, ["1:r1", "3?:r1", "4:r1"]);
});

test("snapshots are frozen copies: editing the published object changes nothing", () => {
  const source = createContextSource(snap(0, true, "r1"));
  /** @type {import("../implementation/context-source.js").ContextSnapshot[]} */
  const seen = [];
  source.provider.subscribe((s) => seen.push(s));
  const published = snap(1, true, "r2");
  source.publish(published);
  published.contextRevision = "r9";

  assert.equal(seen[1].contextRevision, "r2");
  assert.ok(seen.every((s) => Object.isFrozen(s)));
  assert.notEqual(seen[1], published);
});

test("a revision may stay through an unknown interval but never return after a change", () => {
  const source = createContextSource(snap(0, true, "r1"));
  /** @type {string[]} */
  const seen = [];
  source.provider.subscribe((s) => seen.push(label(s)));

  assert.equal(source.publish(snap(1, false, "r1")), true);
  assert.equal(source.publish(snap(2, true, "r1")), true);
  assert.equal(source.publish(snap(3, false, "r2")), true); // unknown carries the new revision
  assert.throws(() => source.publish(snap(4, true, "r1")), { code: "revision_reused" });
  assert.equal(source.publish(snap(5, true, "r2")), true);

  assert.deepEqual(seen, ["0:r1", "1?:r1", "2:r1", "3?:r2", "5:r2"]);
});

test("revisions compare by equality without type coercion", () => {
  const source = createContextSource(snap(0, true, 1));
  assert.equal(source.publish(snap(1, true, "1")), true); // a string is another revision
  assert.throws(() => source.publish(snap(2, true, 1)), { code: "revision_reused" });
  assert.equal(source.publish(snap(3, true, true)), true);
  assert.equal(source.publish(snap(4, true, null)), true);
});

test("positive and negative zero are the same numeric revision", () => {
  const source = createContextSource(snap(0, true, 0));
  assert.equal(source.publish(snap(1, false, -0)), true);
  assert.equal(source.publish(snap(2, true, "next")), true);
  assert.throws(() => source.publish(snap(3, true, 0)), { code: "revision_reused" });
});

test("refuses snapshots that are not exactly three valid members", () => {
  /** @type {Array<[string, unknown]>} */
  const cases = [
    ["null", null],
    ["array", [0, true, "r"]],
    ["extra member", { ...snap(1, true, "r"), account: "signed-in" }],
    ["symbol member", { ...snap(1, true, "r"), [Symbol("x")]: 1 }],
    [
      "hidden member",
      Object.defineProperty({ ...snap(1, true, "r") }, "userId", { value: 7, enumerable: false }),
    ],
    ["missing revision", { sequence: 1, contextKnown: true }],
    ["sequence -1", snap(-1, true, "r")],
    ["sequence 1.5", snap(1.5, true, "r")],
    ["sequence reserved for end", snap(MAX, false, "r")],
    ["sequence string", { ...snap(1, true, "r"), sequence: "1" }],
    ["known string", { ...snap(1, true, "r"), contextKnown: "yes" }],
    ["revision NaN", snap(1, true, NaN)],
    ["revision Infinity", snap(1, true, Infinity)],
    ["revision object", { ...snap(1, true, "r"), contextRevision: { id: 7 } }],
    ["revision undefined", { ...snap(1, true, "r"), contextRevision: undefined }],
  ];
  const source = createContextSource(snap(0, true, "r"));
  for (const [name, value] of cases) {
    assert.throws(
      () => createContextSource(/** @type {any} */ (value)),
      { code: "bad_config" },
      name,
    );
    assert.throws(() => source.publish(/** @type {any} */ (value)), { code: "bad_config" }, name);
  }
});

test("end sends the next sequence as a final unknown, stops subscribers and ignores later publications", () => {
  const source = createContextSource(snap(0, true, "r1"));
  /** @type {string[]} */
  const seen = [];
  source.provider.subscribe((s) => seen.push(label(s)));
  source.publish(snap(1, true, "r2"));

  source.end();
  source.end();

  assert.equal(source.publish(snap(2, true, "r2")), false);
  assert.deepEqual(seen, ["0:r1", "1:r2", "2?:r2"]);
});

test("the last producer sequence leaves room for end: MAX - 1 ends at MAX", () => {
  const source = createContextSource(snap(0, true, "r1"));
  /** @type {string[]} */
  const seen = [];
  source.provider.subscribe((s) => seen.push(label(s)));

  assert.equal(source.publish(snap(MAX - 1, true, "r1")), true);
  source.end();

  assert.deepEqual(seen, ["0:r1", `${MAX - 1}:r1`, `${MAX}?:r1`]);
});

test("a consumer admits an ordinary snapshot at MAX; only producers stop below it", () => {
  assert.deepEqual(admitSnapshot(snap(MAX, false, "r1")), snap(MAX, false, "r1"));
  assert.deepEqual(admitSnapshot(snap(MAX, true, "r1")), snap(MAX, true, "r1"));
  assert.throws(() => admitSnapshot(snap(MAX + 1, false, "r1")), { code: "bad_config" });
});

test("a late subscriber after the end replays the final unknown and is stopped", () => {
  const source = createContextSource(snap(0, true, "r1"));
  source.end();
  /** @type {string[]} */
  const seen = [];
  /** @type {boolean[]} */
  const sameStop = [];

  const stop = source.provider.subscribe((s, st) => {
    seen.push(label(s));
    sameStop.push(st === stop);
  });
  source.publish(snap(5, true, "r1"));

  assert.deepEqual(seen, ["1?:r1"]);
  assert.equal(typeof stop, "function");
  stop(); // already stopped; stopping again is harmless
});

test("stop is idempotent and ends all later calls; stop during replay works", () => {
  const source = createContextSource(snap(0, true, "r1"));
  /** @type {string[]} */
  const a = [];
  /** @type {string[]} */
  const b = [];
  const stopA = source.provider.subscribe((s) => a.push(label(s)));
  source.provider.subscribe((s, stop) => {
    b.push(label(s));
    stop();
  });
  stopA();
  stopA();
  source.publish(snap(1, true, "r1"));

  assert.deepEqual(a, ["0:r1"]);
  assert.deepEqual(b, ["0:r1"]);
});

test("a publication inside a listener queues behind the current notification", () => {
  const source = createContextSource(snap(0, true, "r1"));
  /** @type {string[]} */
  const log = [];
  source.provider.subscribe((s) => {
    log.push(`A:${label(s)}`);
    if (s.sequence === 1) {
      source.publish(snap(2, false, "r1"));
      log.push("A:published");
    }
  });
  source.provider.subscribe((s) => log.push(`B:${label(s)}`));
  log.length = 0;

  source.publish(snap(1, true, "r1"));

  // Nested delivery would show A:2?:r1 before B:1:r1.
  assert.deepEqual(log, ["A:1:r1", "A:published", "B:1:r1", "A:2?:r1", "B:2?:r1"]);
});

test("a publication inside replay is queued until the replay returns", () => {
  const source = createContextSource(snap(0, false, "r1"));
  /** @type {string[]} */
  const log = [];
  source.provider.subscribe((s) => {
    log.push(`start:${label(s)}`);
    if (!s.contextKnown) source.publish(snap(1, true, "r1"));
    log.push(`end:${label(s)}`);
  });
  log.push("returned");

  assert.deepEqual(log, ["start:0?:r1", "end:0?:r1", "start:1:r1", "end:1:r1", "returned"]);
});

test("subscribing inside a notification replays the latest and skips older queued snapshots", () => {
  const source = createContextSource(snap(0, true, "r1"));
  /** @type {string[]} */
  const log = [];
  source.provider.subscribe((s) => {
    if (s.sequence !== 1) return;
    source.publish(snap(2, true, "r2")); // queued for the subscribers present now
    source.provider.subscribe((late) => log.push(`late:${label(late)}`));
    log.push("subscribed");
  });
  source.provider.subscribe((s) => log.push(`early:${label(s)}`));
  log.length = 0;

  source.publish(snap(1, true, "r1"));

  assert.deepEqual(log, ["late:2:r2", "subscribed", "early:1:r1", "early:2:r2"]);
});

test("end inside a listener queues the final snapshot behind the current notification", () => {
  const source = createContextSource(snap(0, true, "r1"));
  /** @type {string[]} */
  const log = [];
  source.provider.subscribe((s) => {
    log.push(`A:${label(s)}`);
    if (s.sequence === 1) source.end();
  });
  source.provider.subscribe((s) => log.push(`B:${label(s)}`));
  log.length = 0;

  source.publish(snap(1, true, "r1"));

  assert.deepEqual(log, ["A:1:r1", "B:1:r1", "A:2?:r1", "B:2?:r1"]);
});

test("a throwing listener or reporter does not stop the others or the publication", () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "reportError");
  /** @type {unknown[]} */
  const reported = [];
  Object.defineProperty(globalThis, "reportError", {
    configurable: true,
    writable: true,
    value: (/** @type {unknown} */ error) => {
      reported.push(error);
      throw new Error("reporter bug");
    },
  });
  try {
    const source = createContextSource(snap(0, true, "r1"));
    /** @type {string[]} */
    const seen = [];
    source.provider.subscribe(() => {
      throw new Error("listener bug");
    });
    source.provider.subscribe((s) => seen.push(label(s)));

    assert.doesNotThrow(() => source.publish(snap(1, false, "r1")));
    assert.deepEqual(seen, ["0:r1", "1?:r1"]);
    assert.equal(reported.length, 2); // replay and the publication
  } finally {
    if (original) Object.defineProperty(globalThis, "reportError", original);
    else delete (/** @type {any} */ (globalThis).reportError);
  }
});

test("subscribe refuses a listener that is not a function", () => {
  const source = createContextSource(snap(0, true, "r1"));
  assert.throws(() => source.provider.subscribe(/** @type {any} */ ("listener")), {
    code: "bad_config",
  });
});

test("ending during initial replay still delivers the queued final unknown", () => {
  const source = createContextSource({ sequence: 0, contextKnown: true, contextRevision: "r1" });
  const seen = [];
  source.provider.subscribe((snapshot) => {
    seen.push([snapshot.sequence, snapshot.contextKnown]);
    if (snapshot.sequence === 0) source.end();
  });
  assert.deepEqual(seen, [
    [0, true],
    [1, false],
  ]);
});
