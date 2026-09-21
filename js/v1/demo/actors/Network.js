// @ts-check
//
// `Network` routes a url to whatever serves it, and a scenario takes a url down
// through it. Both ends of the demo call through it: a `Browser` posting an
// unlock, and a fallback `IssuerServer` probing the primary's health. The
// server is a client too, and the catch-22 only exists because both of them
// are here.
//
// Each caller sees its own reachability. A url has one condition of its own and
// any number of exceptions carved on it, one per caller. Setting the url's
// condition clears the exceptions, so a scenario reads in the order it
// happened: set the world, then set who differs from it. Without that, a test
// cannot hold "the primary is up from the fallback's vantage and down from the
// browser's", and the catch-22 stays a paragraph instead of a test.
//
// `Network` runs no timer anywhere. `slow(url, ms)` records a latency, a caller
// posts with a timeout budget, and `#call` compares the two at call time.
// Longer than the budget fails as a timeout; shorter answers late. Waiting is
// charged to the injected `Clock`: the latency when the answer came, the budget
// when the caller gave up. Elapsed time is then arithmetic over two configured
// numbers, and a breaker window subtracts rather than races.
//
// A url fails in two ways, and they cost differently. `offline` refuses the
// connection: immediate, and it costs nothing. A host that accepts and never
// answers is `slow` past the budget, and that costs the caller its whole
// budget. A breaker treats them alike; a clock does not, and this demo would
// report false elapsed time if it did.
//
// `Network` checks wire safety on every call, in both directions, and nothing
// turns the check off. Everything crossing here is a JSON primitive, a plain
// object or an array. A `Uint8Array` would arrive as `{"0":31,...}` and a
// `CryptoKey` as `{}`, and a later decrypt would then fail for no visible
// reason. Serialising happens at this seam, so the check happens here too, with
// the path to the offending value in the message. Shape validation is a
// separate, opt-in thing and lives elsewhere.
//
// The wire serialises for real. A handler receives JSON.parse of the string the
// caller's payload made, and the caller gets back JSON.parse of the string the
// handler's body made, never the same object in either direction. A wire that
// handed the live object across would let a server read the client's private
// state through it, let either side see the other's later mutations, and let a
// response cache hand every caller one shared body; it would also make every
// test that compares the two sides compare a thing to itself. assertWireSafe
// stays in front of the stringify because JSON.parse(stringify) launders rather
// than refuses: a CryptoKey arrives as {} with no word about where it was lost.
// structuredClone fails the same way over a wider range of values: it carries a
// CryptoKey and a Uint8Array intact, which is exactly what must not cross.
//
// `Network` measures cost here for the same reason: it counts the string that
// crosses. It counts UTF-8 bytes, the measure the issuer caps a body by, so
// this number and the issuer's `maxBodyBytes` limit read in one unit, rather
// than the string's UTF-16 code units diverging from it the moment a body
// carries a character outside ASCII.

import { dcaError } from "../../core-shared/errors.js";
import { utf8Encode } from "../../core-shared/codec.js";
import { assertWireSafe } from "../support/wireSafe.js";

/**
 * @typedef {object} Condition
 * @property {boolean} reachable
 * @property {number} latency - milliseconds this url takes to answer
 */

/**
 * @typedef {object} UrlStats
 * @property {number} attempts - `post` calls that were delivered or failed on the wire
 * @property {number} probes - `probe` calls, counted apart: how often a fallback asked
 * @property {number} failures - offline, timeout and no-route, together
 * @property {number} requestBytes
 * @property {number} responseBytes
 */

/** Reachable, and answering instantly. Every url starts here until a scenario says otherwise. */
const HEALTHY = { reachable: true, latency: 0 };

export class Network {
  /** @type {{ now: () => Date, advance: (ms: number) => void }} */
  #clock;

  /** @type {Map<string, (payload: any, context: { from: any, credential: any, origin: string|undefined }) => any>} */
  #routes = new Map();

  /** @type {Map<string, { own: Condition, byCaller: Map<any, Condition> }>} */
  #conditions = new Map();

  /** @type {Map<string, UrlStats>} */
  #stats = new Map();

  /**
   * @param {object} config
   * @param {{ now: () => Date, advance: (ms: number) => void }} config.clock - what
   *   waiting is charged to. Required: a network that cannot spend time cannot
   *   express a timeout, and a demo with a real timer in it cannot be replayed.
   */
  constructor(config) {
    for (const name of Object.keys(config ?? {})) {
      if (name !== "clock") {
        throw dcaError("unsupported_option", `Network has no ${name} yet, and will not pretend to`);
      }
    }
    if (typeof config?.clock?.advance !== "function" || typeof config?.clock?.now !== "function") {
      throw dcaError("bad_config", "a Network takes the Clock the rest of the world runs on");
    }
    this.#clock = config.clock;
  }

  /**
   * @param {string} url
   * @param {(payload: any, context: { from: any, credential: any, origin: string|undefined }) => any} handler -
   *   `{ status, body }`, or a promise of one
   * @returns {void}
   */
  serve(url, handler) {
    if (typeof url !== "string" || url.length === 0) {
      throw dcaError("bad_config", "a route needs a url");
    }
    if (typeof handler !== "function") {
      throw dcaError("bad_config", `whatever serves ${url} has to be callable`);
    }
    if (this.#routes.has(url)) {
      throw dcaError(
        "bad_config",
        `${url} is already served; two servers on one url is a wiring mistake`,
      );
    }
    this.#routes.set(url, handler);
  }

  /**
   * @param {string} url
   * @returns {{ own: Condition, byCaller: Map<any, Condition> }}
   */
  #conditionsFor(url) {
    let entry = this.#conditions.get(url);
    if (!entry) {
      entry = { own: { ...HEALTHY }, byCaller: new Map() };
      this.#conditions.set(url, entry);
    }
    return entry;
  }

  /**
   * The condition a caller meets: its own exception if it has one, the url's
   * otherwise.
   *
   * @param {string} url
   * @param {any} from
   * @returns {Condition}
   */
  #conditionFor(url, from) {
    const entry = this.#conditions.get(url);
    if (!entry) return { ...HEALTHY };
    return entry.byCaller.get(from) ?? entry.own;
  }

  /**
   * Sets a url's own condition, or carves an exception for one caller. A
   * url-level change clears the exceptions, so a scenario sets the world first,
   * then sets who differs from it.
   *
   * @param {string} url
   * @param {{ from?: any }} scope
   * @param {Partial<Condition>} change
   * @returns {void}
   */
  #set(url, scope, change) {
    const entry = this.#conditionsFor(url);
    if (scope?.from === undefined) {
      entry.own = { ...entry.own, ...change };
      entry.byCaller.clear();
      return;
    }
    entry.byCaller.set(scope.from, { ...(entry.byCaller.get(scope.from) ?? entry.own), ...change });
  }

  /**
   * @param {string} url
   * @param {{ from?: any }} [scope]
   * @returns {void}
   */
  offline(url, scope = {}) {
    this.#set(url, scope, { reachable: false });
  }

  /**
   * Reachable again, at whatever latency it had. A url that was slow before
   * it went down is slow again when it comes back.
   *
   * @param {string} url
   * @param {{ from?: any }} [scope]
   * @returns {void}
   */
  online(url, scope = {}) {
    this.#set(url, scope, { reachable: true });
  }

  /**
   * @param {string} url
   * @param {number} milliseconds - what this url takes to answer
   * @param {{ from?: any }} [scope]
   * @returns {void}
   */
  slow(url, milliseconds, scope = {}) {
    if (!Number.isFinite(milliseconds) || milliseconds < 0) {
      throw dcaError("bad_config", `a latency is a number of milliseconds, got ${milliseconds}`);
    }
    this.#set(url, scope, { latency: milliseconds });
  }

  /**
   * Reachable and instant again: the state everything starts in, and the way
   * back from both kinds of trouble at once.
   *
   * @param {string} url
   * @param {{ from?: any }} [scope]
   * @returns {void}
   */
  healthy(url, scope = {}) {
    this.#set(url, scope, { ...HEALTHY });
  }

  /**
   * @param {string} url
   * @returns {UrlStats}
   */
  #statsFor(url) {
    let entry = this.#stats.get(url);
    if (!entry) {
      entry = { attempts: 0, probes: 0, failures: 0, requestBytes: 0, responseBytes: 0 };
      this.#stats.set(url, entry);
    }
    return entry;
  }

  /**
   * One call over the wire, whichever kind. Wire safety is checked before
   * anything is counted: a payload that cannot be serialised never left the
   * caller, so it is not an attempt the url can be blamed for.
   *
   * @param {string} url
   * @param {any} payload
   * @param {{ from?: any, timeout?: number, credential?: any, origin?: string, kind: 'attempt'|'probe' }} options
   * @returns {Promise<{ status: number, body: any }>}
   */
  async #call(url, payload, { from, timeout, credential, origin, kind }) {
    assertWireSafe(payload);
    // The credential travels beside the payload rather than in it: every
    // real deployment sends what authenticates a caller as a header, and the
    // DCA request body has no field for one. It serialises all the same, so
    // the same rule applies to it.
    if (credential !== undefined) assertWireSafe(credential);
    if (origin !== undefined && typeof origin !== "string") {
      throw dcaError("bad_config", "a Network origin is a string when supplied");
    }

    const stats = this.#statsFor(url);
    if (kind === "probe") stats.probes++;
    else stats.attempts++;

    // The request as it crosses. Counted, then delivered: the handler gets
    // the parse of this string, never the caller's object.
    const requestText = JSON.stringify(payload ?? null);
    stats.requestBytes += utf8Encode(requestText).length;

    const { reachable, latency } = this.#conditionFor(url, from);

    if (!reachable) {
      stats.failures++;
      throw dcaError("offline", `${url} refused the connection`);
    }

    if (timeout !== undefined && latency > timeout) {
      // The caller waited its whole budget and gave up. That costs the
      // budget, not the latency: nobody waits past the point they stopped
      // waiting.
      this.#clock.advance(timeout);
      stats.failures++;
      throw dcaError("timeout", `${url} took longer than ${timeout}ms`);
    }

    const handler = this.#routes.get(url);
    if (!handler) {
      stats.failures++;
      throw dcaError("no_route", `nothing serves ${url}`);
    }

    this.#clock.advance(latency);

    // The credential travels as a header does: serialised. A live object
    // here would be a client handing the server a window into its state.
    const answer = await handler(JSON.parse(requestText), {
      from,
      credential: credential === undefined ? undefined : JSON.parse(JSON.stringify(credential)),
      origin,
    });
    assertWireSafe(answer?.body);

    // And back the same way: the body the caller receives is the parse of
    // the string that was counted, never the handler's own object.
    const responseText = JSON.stringify(answer?.body ?? null);
    stats.responseBytes += utf8Encode(responseText).length;

    return { status: answer.status, body: JSON.parse(responseText) };
  }

  /**
   * @param {string} url
   * @param {any} payload
   * @param {{ from?: any, timeout?: number, credential?: any, origin?: string }} [options]
   * @returns {Promise<{ status: number, body: any }>}
   */
  post(url, payload, options = {}) {
    return this.#call(url, payload, { ...options, kind: "attempt" });
  }

  /**
   * A health check. Counted apart from an unlock because "how often did the
   * fallback ask" is what the TTL is asserted with, and it must not be hidden
   * inside the traffic it is deciding about.
   *
   * @param {string} url
   * @param {{ from?: any, timeout?: number }} [options]
   * @returns {Promise<{ status: number, body: any }>}
   */
  probe(url, options = {}) {
    return this.#call(url, null, { ...options, kind: "probe" });
  }

  /**
   * What crossed, per url. A snapshot: a caller holding one cannot change
   * what the network reports next.
   *
   * @returns {Record<string, UrlStats>}
   */
  stats() {
    /** @type {Record<string, UrlStats>} */
    const out = Object.create(null);
    for (const [url, entry] of this.#stats) out[url] = { ...entry };
    return out;
  }
}
