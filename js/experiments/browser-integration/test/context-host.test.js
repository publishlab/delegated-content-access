// @ts-check
//
// Units for the host test composition in
// `experiments/browser-integration/test-lib/context-host.js`. Waits are
// checked with a race against an already resolved marker, so a test can tell
// a pending wait from a settled one without timers.

import test from "node:test";
import assert from "node:assert/strict";

import { createContextSource } from "../implementation/context-source.js";

const MAX = Number.MAX_SAFE_INTEGER;
import { createContextHost } from "../test-lib/context-host.js";

const ROUTE = "paywall_subscription_service";
const SCOPE = { routes: [ROUTE] };

/**
 * @param {number} sequence
 * @param {boolean} contextKnown
 * @param {string | number | boolean | null} contextRevision
 */
function snap(sequence, contextKnown, contextRevision) {
  return { sequence, contextKnown, contextRevision };
}

/**
 * "pending" while the promise has not settled, otherwise its value.
 *
 * @param {Promise<boolean>} promise
 */
async function state(promise) {
  const marker = "pending";
  return Promise.race([promise, Promise.resolve(marker)]);
}

/**
 * A foreign provider the test drives by hand, for sources that misbehave.
 *
 * @param {{ replay?: unknown }} [options]
 */
function manualSource(options = {}) {
  /** @type {Array<(snapshot: any, stop: () => void) => void>} */
  const listeners = [];
  let stopped = 0;
  return {
    provider: {
      /** @param {(snapshot: any, stop: () => void) => void} listener */
      subscribe(listener) {
        const stop = () => {
          stopped += 1;
        };
        listeners.push(listener);
        if (Object.hasOwn(options, "replay")) listener(options.replay, stop);
        return stop;
      },
    },
    /** @param {unknown} snapshot */
    send(snapshot) {
      for (const listener of listeners) listener(snapshot, () => {});
    },
    stopped: () => stopped,
  };
}

test("an initial unknown captures nothing; a known snapshot then allows capture", () => {
  const source = createContextSource(snap(0, false, null));
  const host = createContextHost(source.provider, SCOPE);

  assert.equal(host.capture(ROUTE), null);
  source.publish(snap(1, true, "r1"));
  const work = host.capture(ROUTE);

  assert.ok(work);
  assert.equal(work.route, ROUTE);
  assert.equal(work.isEligible(), true);
});

test("unknown suspends and the same revision resumes live work", async () => {
  const source = createContextSource(snap(0, true, "r1"));
  const host = createContextHost(source.provider, SCOPE);
  const work = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));

  source.publish(snap(1, false, "r1"));
  const wait = work.waitUntilKnown();

  assert.equal(work.isEligible(), false);
  assert.equal(host.capture(ROUTE), null); // unknown is not anonymous: no new work
  assert.equal(await state(wait), "pending");

  source.publish(snap(2, true, "r1"));

  assert.equal(await wait, true);
  assert.equal(work.isEligible(), true);
});

test("a revision change retires work permanently and settles its wait false", async () => {
  const source = createContextSource(snap(0, true, "r1"));
  const host = createContextHost(source.provider, SCOPE);
  const work = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));
  source.publish(snap(1, false, "r1"));
  const wait = work.waitUntilKnown();

  source.publish(snap(2, true, "r2")); // an account switch under the same menu label

  assert.equal(await wait, false);
  assert.equal(work.isEligible(), false);
  assert.equal(await work.waitUntilKnown(), false);

  const next = host.capture(ROUTE); // the new generation captures fresh work
  assert.ok(next);
  assert.equal(next.isEligible(), true);
  assert.equal(work.isEligible(), false);
});

test("an unknown snapshot that carries a new revision retires work too", async () => {
  const source = createContextSource(snap(0, true, "r1"));
  const host = createContextHost(source.provider, SCOPE);
  const work = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));

  source.publish(snap(1, false, "r2"));
  source.publish(snap(2, true, "r2"));

  assert.equal(work.isEligible(), false);
  assert.equal(await work.waitUntilKnown(), false);
});

test("an eligible wait resolves true at once", async () => {
  const source = createContextSource(snap(0, true, "r1"));
  const host = createContextHost(source.provider, SCOPE);
  const work = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));

  assert.equal(await state(work.waitUntilKnown()), true);
});

test("disposing one work retires only that work and settles its wait false", async () => {
  const source = createContextSource(snap(0, true, "r1"));
  const host = createContextHost(source.provider, SCOPE);
  const a = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));
  const b = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));
  source.publish(snap(1, false, "r1"));
  const waitA = a.waitUntilKnown();
  const waitB = b.waitUntilKnown();

  a.dispose();
  a.dispose();
  source.publish(snap(2, true, "r1"));

  assert.equal(await waitA, false);
  assert.equal(await waitB, true);
  assert.equal(a.isEligible(), false);
  assert.equal(b.isEligible(), true);
});

test("disposing the host retires all its work, settles waits and unsubscribes", async () => {
  const manual = manualSource({ replay: snap(0, true, "r1") });
  const host = createContextHost(manual.provider, SCOPE);
  const work = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));
  manual.send(snap(1, false, "r1"));
  const wait = work.waitUntilKnown();

  host.dispose();
  host.dispose();
  manual.send(snap(2, true, "r1")); // a source that keeps calling after stop changes nothing

  assert.equal(await wait, false);
  assert.equal(work.isEligible(), false);
  assert.equal(host.capture(ROUTE), null);
  assert.equal(manual.stopped(), 1);
});

test("a replacement source that repeats the revision does not revive old work", () => {
  const oldSource = createContextSource(snap(0, true, "r1"));
  const oldHost = createContextHost(oldSource.provider, SCOPE);
  const oldWork = /** @type {NonNullable<ReturnType<typeof oldHost.capture>>} */ (
    oldHost.capture(ROUTE)
  );

  oldHost.dispose(); // the host retires the old association before the new one
  const newSource = createContextSource(snap(0, true, "r1"));
  const newHost = createContextHost(newSource.provider, SCOPE);
  const newWork = /** @type {NonNullable<ReturnType<typeof newHost.capture>>} */ (
    newHost.capture(ROUTE)
  );

  assert.equal(oldWork.isEligible(), false);
  assert.equal(newWork.isEligible(), true);
});

test("the end of the source only suspends; explicit host disposal retires", async () => {
  const source = createContextSource(snap(0, true, "r1"));
  const host = createContextHost(source.provider, SCOPE);
  const work = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));
  const wait = work.waitUntilKnown();
  assert.equal(await wait, true);

  source.end(); // the final unknown is an ordinary unknown at sequence 1
  const pending = work.waitUntilKnown();

  assert.equal(work.isEligible(), false);
  assert.equal(host.capture(ROUTE), null);
  assert.equal(await state(pending), "pending");

  host.dispose(); // discovery removal or replacement retires the association

  assert.equal(await pending, false);
  assert.equal(work.isEligible(), false);
});

test("a host created after the source ended sees an unknown and captures nothing", () => {
  const source = createContextSource(snap(0, true, "r1"));
  source.end();

  const host = createContextHost(source.provider, SCOPE);

  assert.equal(host.capture(ROUTE), null);
});

test("an unknown at the last safe integer is no end signal: the wait stays until disposal", async () => {
  const manual = manualSource({ replay: snap(0, true, "r1") });
  const host = createContextHost(manual.provider, SCOPE);
  const work = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));

  manual.send(snap(MAX, false, "r1"));
  const wait = work.waitUntilKnown();

  assert.equal(work.isEligible(), false);
  assert.equal(host.capture(ROUTE), null);
  assert.equal(await state(wait), "pending");
  assert.equal(manual.stopped(), 0); // the host does not end the association by itself

  host.dispose();

  assert.equal(await wait, false);
  assert.equal(manual.stopped(), 1);
});

test("a malformed snapshot replayed during subscribe stops the source after subscribe", () => {
  const manual = manualSource({ replay: { sequence: 0, contextKnown: true } });

  const host = createContextHost(manual.provider, SCOPE);

  assert.equal(host.capture(ROUTE), null);
  assert.equal(manual.stopped(), 1);
});

test("an older observation from a foreign source does not overwrite a later one", () => {
  const manual = manualSource({ replay: snap(3, true, "r1") });
  const host = createContextHost(manual.provider, SCOPE);
  const work = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));

  manual.send(snap(2, false, "r1")); // delayed and older: ignored
  assert.equal(work.isEligible(), true);

  manual.send(snap(4, false, "r1"));
  assert.equal(work.isEligible(), false);
});

test("a malformed observation from a foreign source ends the association", async () => {
  const manual = manualSource({ replay: snap(0, true, "r1") });
  const host = createContextHost(manual.provider, SCOPE);
  const work = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (host.capture(ROUTE));

  manual.send({ sequence: 1, contextKnown: true, contextRevision: "r1", userId: 7 });

  assert.equal(work.isEligible(), false);
  assert.equal(await work.waitUntilKnown(), false);
  assert.equal(host.capture(ROUTE), null);
  assert.equal(manual.stopped(), 1);
});

test("a source that does not replay leaves capture null until a snapshot arrives", () => {
  const manual = manualSource();
  const host = createContextHost(manual.provider, SCOPE);

  assert.equal(host.capture(ROUTE), null);
  manual.send(snap(0, true, "r1"));
  assert.ok(host.capture(ROUTE));
});

test("each host governs only its routes; another source's change leaves it alone", () => {
  const siteSource = createContextSource(snap(0, true, "r1"));
  const partnerSource = createContextSource(snap(0, true, "p1"));
  const siteHost = createContextHost(siteSource.provider, { routes: [ROUTE] });
  const partnerHost = createContextHost(partnerSource.provider, { routes: ["partner_issuer"] });
  const site = /** @type {NonNullable<ReturnType<typeof siteHost.capture>>} */ (
    siteHost.capture(ROUTE)
  );
  const partner = /** @type {NonNullable<ReturnType<typeof partnerHost.capture>>} */ (
    partnerHost.capture("partner_issuer")
  );

  partnerSource.publish(snap(1, true, "p2"));

  assert.equal(site.isEligible(), true);
  assert.equal(partner.isEligible(), false);
  assert.throws(() => siteHost.capture("partner_issuer"), { code: "bad_config" });
});

test("a host refuses a scope without a nonempty list of routes", () => {
  const source = createContextSource(snap(0, true, "r1"));
  for (const scope of [
    null,
    {},
    { routes: [] },
    { routes: [""] },
    { routes: "a" },
    { routes: [7] },
  ]) {
    assert.throws(() => createContextHost(source.provider, /** @type {any} */ (scope)), {
      code: "bad_config",
    });
  }
});

test("work captured during unknown is impossible; work resumed keeps its route", async () => {
  const source = createContextSource(snap(0, true, "r1"));
  const host = createContextHost(source.provider, { routes: [ROUTE, "second_route"] });
  const work = /** @type {NonNullable<ReturnType<typeof host.capture>>} */ (
    host.capture("second_route")
  );
  source.publish(snap(1, false, "r1"));
  assert.equal(host.capture("second_route"), null);
  source.publish(snap(2, true, "r1"));

  assert.equal(work.route, "second_route");
  assert.equal(await work.waitUntilKnown(), true);
});
