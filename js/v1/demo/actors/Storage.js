// @ts-check
//
// What a `Browser` keeps things in. Each `Browser` makes its own - two of them
// are two users, and separate storage stands in for two separate machines. Two
// tabs share one: one `Browser`, two live `PageLoad`s, racing over this.
//
// Every call here is async on purpose. The backing is a `Map`, and a `Map`
// answers instantly; every call returns a promise anyway. The promise serves
// the behaviour under test rather than a future IndexedDB adapter. A
// synchronous store keeps every write atomic - read, modify and write land in
// one turn, no other tab can run between them - and then no tab can lose a key
// to another. The whole concurrency family drops out by construction rather
// than by argument, and a demo that cannot reach it cannot show what a real
// store does.
//
// THE SHAPE. `get`, `set`, `keys`, `remove` over string keys and string values.
// localStorage is `getItem`/`setItem`/`removeItem` plus `key(n)`, and IndexedDB
// is `get`/`put`/`delete`/`getAllKeys`; both fit behind these four, and neither
// needs a fifth. Values are strings because localStorage has no other kind -
// the caller serialises, which is where the encoding decision belongs.
//
// `Storage` keeps only values that are wire-safe, the rule `Network` holds a
// payload to. A `Uint8Array` put here would come back as "[object Object]" out
// of a real store, and a `CryptoKey` cannot be kept at all; both are refused
// loudly rather than mangled quietly three layers from where the mistake was
// made.
//
// THE GATE gives a test the seam it drives the interleaving from: an operation
// holds there until the test lets go, so one tab can be stopped inside its
// read-modify-write gap while another runs to completion. Nothing here is
// timed. A `setTimeout` would leave the order to chance, and the point of
// this class is a fixed order.

import { dcaError } from "../../core-shared/errors.js";

/**
 * Called before every operation and awaited. Return nothing for the ordinary
 * case; return a promise to hold the operation open. It sees what the
 * operation is and which key it names, which is enough to stop one write
 * without stopping the reads around it.
 *
 * A gate that throws fails the operation, which is how a full disk or a
 * revoked permission would arrive - available here, and unused so far.
 *
 * @typedef {(call: { op: 'get'|'set'|'keys'|'remove', key?: string }) => any} StorageGate
 */

export class Storage {
  /** @type {Map<string, string>} */
  #entries = new Map();

  /** @type {StorageGate|null} */
  #gate;

  #gets = 0;
  #sets = 0;
  #removes = 0;
  #keyLists = 0;

  /**
   * @param {{ gate?: StorageGate }} [config]
   */
  constructor(config = {}) {
    for (const name of Object.keys(config)) {
      if (name !== "gate") {
        throw dcaError("unsupported_option", `Storage has no ${name} yet, and will not pretend to`);
      }
    }
    if (config.gate !== undefined && typeof config.gate !== "function") {
      throw dcaError("bad_config", "a Storage gate is a function called before every operation");
    }
    this.#gate = config.gate ?? null;
  }

  /**
   * The turn every operation takes. Without a gate this is one microtask -
   * still a turn, still enough for another tab to run.
   *
   * @param {'get'|'set'|'keys'|'remove'} op
   * @param {string} [key]
   * @returns {Promise<void>}
   */
  async #turn(op, key) {
    await this.#gate?.({ op, key });
  }

  /**
   * @param {string} key
   */
  #assertKey(key) {
    if (typeof key !== "string") {
      throw dcaError("bad_storage", `a storage key is a string, got ${typeof key}`);
    }
  }

  /**
   * @param {string} key
   * @returns {Promise<string|undefined>} undefined for a key never written -
   *   a miss is the ordinary case, not a throw
   */
  async get(key) {
    this.#assertKey(key);
    await this.#turn("get", key);
    this.#gets++;
    return this.#entries.get(key);
  }

  /**
   * @param {string} key
   * @param {string} value
   * @returns {Promise<void>}
   */
  async set(key, value) {
    this.#assertKey(key);
    if (typeof value !== "string") {
      throw dcaError("bad_storage", `a store keeps strings; ${key} was handed a ${typeof value}`);
    }
    await this.#turn("set", key);
    this.#sets++;
    this.#entries.set(key, value);
  }

  /**
   * @param {string} key
   * @returns {Promise<void>}
   */
  async remove(key) {
    this.#assertKey(key);
    await this.#turn("remove", key);
    this.#removes++;
    this.#entries.delete(key);
  }

  /**
   * Every key held, in the order they were first written. A caller that
   * needs an order sorts; a store makes no promise about one.
   *
   * @returns {Promise<string[]>}
   */
  async keys() {
    await this.#turn("keys");
    this.#keyLists++;
    return [...this.#entries.keys()];
  }

  /**
   * Bookkeeping, the way it sits on every other actor. What a test uses to
   * assert "nothing was written".
   *
   * @returns {{ gets: number, sets: number, removes: number, keyLists: number }}
   */
  stats() {
    return { gets: this.#gets, sets: this.#sets, removes: this.#removes, keyLists: this.#keyLists };
  }
}
