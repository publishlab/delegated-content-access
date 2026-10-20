// @ts-check
//
// Host composition for tests: one association between a context source and
// the issuer routes it governs, and the captured work that association hands
// out. This is test composition, not a reference-client lifetime manager. The
// exchange proofs use it to gate dispatch, retained-key use and output.
//
// The host captures article A's work while the source says known "r1". The
// SDK goes unknown: A is suspended, `isEligible()` is false and
// `waitUntilKnown()` stays pending. The SDK confirms "r1" again: A resumes and
// the wait resolves true. The reader then switches to "r2": A is retired for
// good and a pending wait resolves false. A later "r1" from a restarted source
// reaches a new host, never A, because disposing the old host retired A too.
// When the source ends it sends an ordinary unknown: A stays suspended until
// the host disposes the association. No sequence value means "ended".

import { dcaError } from "../../../core-shared/errors.js";
import { admitSnapshot } from "../implementation/context-source.js";

/**
 * @typedef {object} CapturedWork
 * @property {string} route - the configured issuer route this work belongs to
 * @property {() => boolean} isEligible - true only while known under the captured revision
 * @property {() => Promise<boolean>} waitUntilKnown
 *   Resolves true once the work is eligible, false once it is retired.
 * @property {() => void} dispose - retires this work only
 */

/**
 * @typedef {object} ContextHost
 * @property {(route: string) => CapturedWork | null} capture
 *   Null while the context is unknown or the association has ended.
 * @property {() => void} dispose - ends the association and retires all its work
 */

/**
 * @param {import("../implementation/context-source.js").ContextSourceProvider} source
 * @param {{ routes: string[] }} scope - the issuer routes this source governs
 * @returns {ContextHost}
 */
export function createContextHost(source, scope) {
  const routes = new Set(admitRoutes(scope));
  /** @type {import("../implementation/context-source.js").ContextSnapshot | null} */
  let latest = null;
  /**
   * Each revision change and the end of the association start a new
   * generation. Work captured in an older generation never becomes eligible.
   */
  let generation = 0;
  let ended = false;
  /** @type {Set<Work>} */
  const live = new Set();
  /** @type {(() => void) | null} */
  let stop = null;

  function known() {
    return !ended && latest !== null && latest.contextKnown;
  }

  /** Retires all work of the current generation. */
  function retireAll() {
    generation += 1;
    for (const work of [...live]) work.retire();
  }

  function end() {
    if (ended) return;
    ended = true;
    stop?.();
    retireAll();
  }

  /** @param {unknown} snapshot */
  function observe(snapshot) {
    if (ended) return;
    let admitted;
    try {
      admitted = admitSnapshot(snapshot);
    } catch {
      end(); // a malformed observation cannot keep any work eligible
      return;
    }
    if (latest !== null && admitted.sequence <= latest.sequence) return;
    const revisionChanged = latest !== null && admitted.contextRevision !== latest.contextRevision;
    latest = admitted;
    if (revisionChanged) retireAll();
    if (admitted.contextKnown) for (const work of [...live]) work.resume();
  }

  // The source replays synchronously. A source that does not leaves `latest`
  // null, so capture returns null until a snapshot arrives. A malformed replay
  // ends the association during subscribe, before `stop` exists.
  stop = source.subscribe((snapshot) => observe(snapshot));
  if (ended) stop();

  return Object.freeze({
    capture(route) {
      if (!routes.has(route)) {
        throw dcaError("bad_config", `route ${route} is not governed by this context host`);
      }
      if (!known()) return null;
      const work = new Work(route, generation, {
        eligible: (/** @type {number} */ captured) => known() && captured === generation,
        release: (/** @type {Work} */ done) => live.delete(done),
      });
      live.add(work);
      return work.view();
    },

    dispose: end,
  });
}

class Work {
  #retired = false;
  /** @type {Set<(known: boolean) => void>} */
  #waiters = new Set();

  /**
   * @param {string} route
   * @param {number} generation
   * @param {{ eligible: (generation: number) => boolean, release: (work: Work) => void }} host
   */
  constructor(route, generation, host) {
    this.route = route;
    this.generation = generation;
    this.host = host;
  }

  isEligible() {
    return !this.#retired && this.host.eligible(this.generation);
  }

  /** @returns {Promise<boolean>} */
  waitUntilKnown() {
    if (this.#retired) return Promise.resolve(false);
    if (this.isEligible()) return Promise.resolve(true);
    return new Promise((resolve) => this.#waiters.add(resolve));
  }

  /** A known snapshot under the captured revision arrived. */
  resume() {
    if (!this.isEligible()) return;
    this.#settle(true);
  }

  /** Permanent: nothing makes this work eligible again. */
  retire() {
    if (this.#retired) return;
    this.#retired = true;
    this.host.release(this);
    this.#settle(false);
  }

  /** @param {boolean} known */
  #settle(known) {
    const waiters = [...this.#waiters];
    this.#waiters.clear();
    for (const resolve of waiters) resolve(known);
  }

  /** @returns {CapturedWork} */
  view() {
    return Object.freeze({
      route: this.route,
      isEligible: () => this.isEligible(),
      waitUntilKnown: () => this.waitUntilKnown(),
      dispose: () => this.retire(),
    });
  }
}

/**
 * @param {unknown} scope
 * @returns {string[]}
 */
function admitRoutes(scope) {
  const routes =
    scope !== null && typeof scope === "object" && Object.hasOwn(scope, "routes")
      ? /** @type {{ routes: unknown }} */ (scope).routes
      : null;
  if (
    !Array.isArray(routes) ||
    routes.length === 0 ||
    !routes.every((route) => typeof route === "string" && route !== "")
  ) {
    throw dcaError("bad_config", "a context host governs a nonempty list of issuer routes");
  }
  return routes;
}
