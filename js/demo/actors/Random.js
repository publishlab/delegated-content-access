// @ts-check
//
// Entropy comes from here, injected the way `Clock` injects time. Nonces,
// content keys and renderIds all draw on it, and nothing else in the demo
// calls crypto.getRandomValues. Without that, a failing run cannot be replayed
// and test vectors cannot be regenerated.
//
// Real by default. Seeded when a scenario has to repeat exactly, and the
// seeded generator is a plain PRNG with no security claim at all.

/**
 * @param {number} seed
 * @returns {() => number} successive uint32 values
 */
function splitmix32(seed) {
  let state = seed | 0;
  return () => {
    state = (state + 0x9e3779b9) | 0;
    let t = state ^ (state >>> 16);
    t = Math.imul(t, 0x21f0aaad);
    t = t ^ (t >>> 15);
    t = Math.imul(t, 0x735a2d97);
    return (t ^ (t >>> 15)) >>> 0;
  };
}

import { dcaError } from "../../core-shared/errors.js";

export class Random {
  /** @type {(() => number)|null} */
  #next;

  /**
   * @param {{ seed?: number }} [options] - a seed makes the run reproducible
   */
  constructor(options = {}) {
    this.#next = options.seed === undefined ? null : splitmix32(options.seed);
  }

  /** Whether this run can be replayed. */
  get seeded() {
    return this.#next !== null;
  }

  /**
   * @param {number} n
   * @returns {Uint8Array}
   */
  bytes(n) {
    if (!Number.isInteger(n) || n < 0) {
      throw dcaError("bad_config", `Random.bytes needs a non-negative integer, got ${n}`);
    }

    const out = new Uint8Array(n);
    if (this.#next === null) {
      globalThis.crypto.getRandomValues(out);
      return out;
    }

    for (let i = 0; i < n; i += 4) {
      const word = this.#next();
      out[i] = word & 0xff;
      if (i + 1 < n) out[i + 1] = (word >>> 8) & 0xff;
      if (i + 2 < n) out[i + 2] = (word >>> 16) & 0xff;
      if (i + 3 < n) out[i + 3] = (word >>> 24) & 0xff;
    }
    return out;
  }
}
