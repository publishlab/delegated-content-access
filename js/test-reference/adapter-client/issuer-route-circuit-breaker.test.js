// @ts-check
//
// The reachability state a client keeps per issuer route, read directly. The
// composed cases in `test-reference/demo-actors/transport.test.js` carry the timeout accounting, the
// state shared across page loads, the concurrent attempts already in flight,
// and the fallback the walk skips. This file pins the component under them: the
// options it refuses, the one url a record touches, and each transition between
// closed, open and half-open on a clock the test moves by hand.
//
// Every case builds its own breaker with explicit numbers, so a change to the
// defaults moves only the one case that reads them.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { IssuerRouteCircuitBreaker } from "../../adapter-client/IssuerRouteCircuitBreaker.js";

const URL_A = "https://issuer-a.example/unlock";
const URL_B = "https://issuer-b.example/unlock";

/** A fixed instant every case counts from, so the window arithmetic reads plainly. */
const T0 = new Date("2025-10-23T14:20:00Z");

/** @param {number} ms @returns {Date} */
function after(ms) {
  return new Date(T0.getTime() + ms);
}

/** Two failures open it, the window is a minute, and a call waits five seconds. */
function breaker() {
  return new IssuerRouteCircuitBreaker({ threshold: 2, window: 60_000, timeout: 5_000 });
}

describe("An issuer-route circuit breaker's configuration", () => {
  test("refuses an option it has no meaning for", () => {
    assert.throws(
      () => new IssuerRouteCircuitBreaker(/** @type {any} */ ({ retries: 3 })),
      (/** @type {any} */ error) =>
        error.code === "unsupported_option" && /retries/.test(error.message),
    );
  });

  test("refuses a threshold, window or timeout that is not a positive number", () => {
    for (const name of ["threshold", "window", "timeout"]) {
      for (const value of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
        assert.throws(
          () => new IssuerRouteCircuitBreaker(/** @type {any} */ ({ [name]: value })),
          (/** @type {any} */ error) =>
            error.code === "bad_config" && new RegExp(name).test(error.message),
          `${name}=${value}`,
        );
      }
    }
  });

  test("takes its defaults when it is handed nothing", () => {
    const fresh = new IssuerRouteCircuitBreaker();
    assert.equal(fresh.threshold, 2);
    assert.equal(fresh.window, 30_000);
    assert.equal(fresh.timeout, 2_000);
  });

  test("exposes the timeout a call gets to wait", () => {
    assert.equal(breaker().timeout, 5_000);
  });
});

describe("What an issuer-route circuit breaker holds per url", () => {
  test("starts closed and allows a url it has never seen", () => {
    const held = breaker();
    assert.equal(held.allows(URL_A, T0), true);
    assert.deepEqual(held.stateOf(URL_A), { state: "closed", failures: 0, openedAt: null });
  });

  test("opens on the threshold failure and skips calls inside the window", () => {
    const held = breaker();
    held.recordFailure(URL_A, T0);
    assert.equal(held.allows(URL_A, after(1)), true, "one failure under the threshold");

    held.recordFailure(URL_A, after(10));
    assert.deepEqual(held.stateOf(URL_A), {
      state: "open",
      failures: 2,
      openedAt: after(10).getTime(),
    });
    assert.equal(held.allows(URL_A, after(20)), false);
    assert.equal(held.allows(URL_A, after(60_009)), false, "the last instant inside the window");
  });

  test("keeps one url's failures off another", () => {
    const held = breaker();
    held.recordFailure(URL_A, T0);
    held.recordFailure(URL_A, T0);
    assert.equal(held.allows(URL_A, T0), false);
    assert.equal(held.allows(URL_B, T0), true);
    assert.deepEqual(held.stateOf(URL_B), { state: "closed", failures: 0, openedAt: null });
  });

  test("half-opens once the window has passed", () => {
    const held = breaker();
    held.recordFailure(URL_A, T0);
    held.recordFailure(URL_A, T0);

    assert.equal(held.allows(URL_A, after(60_000)), true);
    assert.equal(held.stateOf(URL_A).state, "half-open");
  });

  test("opens again on the first failure of a half-open call", () => {
    const held = breaker();
    held.recordFailure(URL_A, T0);
    held.recordFailure(URL_A, T0);
    held.allows(URL_A, after(60_000));

    held.recordFailure(URL_A, after(60_100));
    assert.deepEqual(held.stateOf(URL_A), {
      state: "open",
      failures: 3,
      openedAt: after(60_100).getTime(),
    });
    assert.equal(held.allows(URL_A, after(60_200)), false, "the window runs from the trial");
  });

  test("closes and forgets its failures when a half-open call succeeds", () => {
    const held = breaker();
    held.recordFailure(URL_A, T0);
    held.recordFailure(URL_A, T0);
    held.allows(URL_A, after(60_000));

    held.recordSuccess(URL_A);
    assert.deepEqual(held.stateOf(URL_A), { state: "closed", failures: 0, openedAt: null });
    assert.equal(held.allows(URL_A, after(60_100)), true);
  });

  test("half-opens after a backward clock step, and one failed probe reopens it for one window", () => {
    // The breaker reads the wall clock the host hands it. The clock steps back
    // an hour while the url is open, after a sleep or a manual fix. Measured
    // against the earlier wall time, the window would not pass for an hour and
    // a minute of real time, and a client with one issuer gets no key until a
    // reload builds a new breaker.
    const held = breaker();
    held.recordFailure(URL_A, T0);
    held.recordFailure(URL_A, T0);
    const stepped = after(-3_600_000 + 1_000);

    assert.equal(held.allows(URL_A, stepped), true, "one probe goes out");
    assert.equal(held.stateOf(URL_A).state, "half-open");

    // The probe fails. The breaker reopens on the stepped clock, so the next
    // window is one window long again.
    held.recordFailure(URL_A, stepped);
    assert.deepEqual(held.stateOf(URL_A), {
      state: "open",
      failures: 3,
      openedAt: stepped.getTime(),
    });
    assert.equal(held.allows(URL_A, new Date(stepped.getTime() + 59_999)), false);
    assert.equal(held.allows(URL_A, new Date(stepped.getTime() + 60_000)), true);
  });
});

describe("What an issuer-route circuit breaker hands an observer", () => {
  test("returns a copy from stateOf, so writing to it leaves the breaker alone", () => {
    const held = breaker();
    held.recordFailure(URL_A, T0);

    const observed = held.stateOf(URL_A);
    observed.failures = 99;
    observed.state = "open";
    assert.deepEqual(held.stateOf(URL_A), { state: "closed", failures: 1, openedAt: null });
    assert.equal(held.allows(URL_A, after(1)), true);
  });

  test("returns copies from stats, one entry per url it has seen", () => {
    const held = breaker();
    held.recordFailure(URL_A, T0);
    held.allows(URL_B, T0);

    const stats = held.stats();
    assert.deepEqual(Object.keys(stats).sort(), [URL_A, URL_B].sort());
    stats[URL_A].failures = 99;
    assert.equal(held.stateOf(URL_A).failures, 1);
  });
});
