// @ts-check
//
// Per-client reachability state for the issuer routes a client walks, keyed by
// unlock url. One issuer failing says nothing about another, and two urls on
// one host are two things that can fail apart.
//
// `IssuerRouteCircuitBreaker.recordFailure` increments the counter on the live
// state object. It never writes back a snapshot taken before the call. There is
// no store under it and so no await inside the update, which is what keeps two
// concurrent unlocks from each writing failCount=1 over the other. What they do
// share is the read before the call: both ask whether the breaker allows a call
// while neither has failed yet, so both go out. A breaker cannot recall a
// request already in flight, so it opens one round of calls late.

import { dcaError } from "../core-shared/errors.js";

/**
 * The demonstration Browser and reference scenarios use these settings when
 * no breaker configuration is supplied. A host selects its own configuration.
 */
const DEFAULT_BREAKER = { threshold: 2, window: 30_000, timeout: 2_000 };

/**
 * @typedef {object} BreakerState
 * @property {'closed'|'open'|'half-open'} state
 * @property {number} failures
 * @property {number|null} openedAt
 */

/**
 * Per issuer url: closed until it has failed its threshold, open for a window,
 * then half-open and letting calls through again, and closed on the first
 * success.
 *
 * A 5xx answer is a failure: the port broke, not the issuer deciding, and the
 * breaker counts it the same as an unreachable call. Any other answer is a
 * success. A 403 from a fallback or a 401 from an issuer that will not grant is
 * a server that is up and talking, and a breaker that opened on those would
 * take a working issuer out of the walk for saying no.
 */
export class IssuerRouteCircuitBreaker {
  #threshold;
  #window;
  #timeout;

  /** @type {Map<string, BreakerState>} */
  #urls = new Map();

  /**
   * @param {{ threshold?: number, window?: number, timeout?: number }} [config]
   */
  constructor(config = {}) {
    for (const name of Object.keys(config)) {
      if (!Object.hasOwn(DEFAULT_BREAKER, name)) {
        throw dcaError(
          "unsupported_option",
          `a breaker has no ${name} yet, and will not pretend to`,
        );
      }
    }
    const { threshold, window, timeout } = { ...DEFAULT_BREAKER, ...config };
    for (const [name, value] of Object.entries({ threshold, window, timeout })) {
      if (!Number.isFinite(value) || value <= 0) {
        throw dcaError("bad_config", `a breaker ${name} is a positive number, got ${value}`);
      }
    }

    this.#threshold = threshold;
    this.#window = window;
    this.#timeout = timeout;
  }

  /** What a call gets to wait before it is a failure. */
  get timeout() {
    return this.#timeout;
  }

  get threshold() {
    return this.#threshold;
  }

  get window() {
    return this.#window;
  }

  /**
   * @param {string} url
   * @returns {BreakerState}
   */
  #for(url) {
    let state = this.#urls.get(url);
    if (!state) {
      state = { state: "closed", failures: 0, openedAt: null };
      this.#urls.set(url, state);
    }
    return state;
  }

  /**
   * Whether a call to this url may go out, at this moment. An open breaker
   * whose window has passed half-opens here, and from then on this method
   * answers true to every call until `recordFailure` opens the breaker again or
   * `recordSuccess` closes it. The transition is a read of the clock rather
   * than a timer that fired. A clock read earlier than the time the breaker
   * opened also half-opens it.
   *
   * @param {string} url
   * @param {Date} now
   * @returns {boolean}
   */
  allows(url, now) {
    const held = this.#for(url);
    if (held.state !== "open") return true;

    // A negative elapsed time means the host's clock stepped back while the url
    // was open. Waiting for the earlier wall time to come round again would
    // keep the url shut for the size of the step. A probe is safe instead: one
    // failure reopens the url for a whole window measured on the new clock.
    const elapsed = now.getTime() - /** @type {number} */ (held.openedAt);
    if (elapsed < 0 || elapsed >= this.#window) {
      held.state = "half-open";
      return true;
    }
    return false;
  }

  /**
   * @param {string} url
   * @param {Date} now
   * @returns {void}
   */
  recordFailure(url, now) {
    const held = this.#for(url);
    held.failures++;
    if (held.state === "half-open" || held.failures >= this.#threshold) {
      held.state = "open";
      held.openedAt = now.getTime();
    }
  }

  /**
   * @param {string} url
   * @returns {void}
   */
  recordSuccess(url) {
    const held = this.#for(url);
    held.state = "closed";
    held.failures = 0;
    held.openedAt = null;
  }

  /**
   * @param {string} url
   * @returns {BreakerState}
   */
  stateOf(url) {
    return { ...this.#for(url) };
  }

  /**
   * @returns {Record<string, BreakerState>}
   */
  stats() {
    /** @type {Record<string, BreakerState>} */
    const out = Object.create(null);
    for (const [url, state] of this.#urls) out[url] = { ...state };
    return out;
  }
}
