// @ts-check
//
// This module takes the timings and derivation counts that `run.js` asks for. `run.js`
// imports it, supplies the operation to run, and prints the numbers that come back.
//
// Two numbers describe one chain-key operation, and they measure different things:
//
//   HKDF count   how many `crypto.subtle.deriveBits` calls the operation
//                spends. `spec-profile--chain-keys.md` **Bounds** models this count
//                as `2N - 1` per expansion. It repeats exactly on a rerun, and a
//                derivation-work bound limits it.
//   wall time    how long the operation took on this box, in milliseconds. It varies
//                from host to host, so this module reports a median over repeated
//                readings with the min and max beside it.
//
// Wall time comes from `process.hrtime.bigint()`, a monotonic counter that no
// clock adjustment moves. The reference itself reads the time only through an
// injected `Clock`, so nothing measured here reads a host clock.
//
// Warm-up: the first readings of a JIT-compiled path are slower than the ones
// after it, and this benchmark measures the steady cost of the path rather
// than the cost of compiling it. `readings()` runs `warmup` iterations, discards
// them, and reports only the `runs` that follow. No other helper in this tree does
// this, so it lives here, beside its only caller.

/** Discarded iterations before the first recorded one. */
export const WARMUP = 2;

/** Recorded iterations. An odd count, so the median is one reading rather than a mean of two. */
export const RUNS = 11;

/**
 * HKDF invocations spent by one call, counted at the WebCrypto boundary where the
 * chain construction derives. This swaps `deriveBits` for a counting wrapper and
 * restores it in a `finally`, the same way
 * `extensions/chain-keys/test/client-chain-cache.test.js` counts derivations.
 *
 * @template T
 * @param {() => Promise<T>} run
 * @returns {Promise<{ value: T, count: number }>}
 */
export async function derivations(run) {
  const subtle = globalThis.crypto.subtle;
  const deriveBits = subtle.deriveBits;
  let count = 0;
  subtle.deriveBits = async function (/** @type {any[]} */ ...args) {
    count++;
    return deriveBits.apply(this, /** @type {any} */ (args));
  };
  try {
    const value = await run();
    return { value, count };
  } finally {
    subtle.deriveBits = deriveBits;
  }
}

/**
 * One reading: what the call returned and how many milliseconds it took.
 *
 * @template T
 * @param {() => Promise<T>} run
 * @returns {Promise<{ value: T, ms: number }>}
 */
export async function timed(run) {
  const started = process.hrtime.bigint();
  const value = await run();
  const ended = process.hrtime.bigint();
  return { value, ms: Number(ended - started) / 1e6 };
}

/**
 * The middle of an odd number of readings.
 *
 * @param {number[]} values
 * @returns {number}
 */
export function median(values) {
  return [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
}

/**
 * @typedef {object} Readings
 * @property {number} median - milliseconds
 * @property {number} min - milliseconds
 * @property {number} max - milliseconds
 * @property {number} runs - recorded iterations
 * @property {number} warmup - discarded iterations
 * @property {any} last - what the final recorded iteration returned
 */

/**
 * Run one operation `WARMUP + RUNS` times and report the readings after warm-up.
 * Every iteration builds whatever it needs inside `run`, so a caller measuring a cold
 * path passes a `run` that starts cold each time.
 *
 * @param {() => Promise<any>} run
 * @param {{ warmup?: number, runs?: number }} [config]
 * @returns {Promise<Readings>}
 */
export async function readings(run, { warmup = WARMUP, runs = RUNS } = {}) {
  for (let index = 0; index < warmup; index++) await run();

  /** @type {number[]} */
  const values = [];
  let last;
  for (let index = 0; index < runs; index++) {
    const reading = await timed(run);
    values.push(reading.ms);
    last = reading.value;
  }

  return {
    median: median(values),
    min: Math.min(...values),
    max: Math.max(...values),
    runs,
    warmup,
    last,
  };
}

/**
 * @param {number} count
 * @returns {string} digits grouped in threes, `30 786`
 */
export function grouped(count) {
  return String(count).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
}

/**
 * One reading set as a line of text: the median first, then the min and max around
 * it and the iteration counts behind it.
 *
 * @param {Readings} taken
 * @returns {string}
 */
export function spread(taken) {
  const at = (/** @type {number} */ value) => value.toFixed(2);
  return (
    `${at(taken.median)} ms median (${at(taken.min)} min, ${at(taken.max)} max, ` +
    `${taken.runs} runs after ${taken.warmup} discarded)`
  );
}

/**
 * What the printed figures were taken on. Wall times from a container on a shared
 * host are good for an order of magnitude and not for their exact digits, so the
 * second line states that caveat beside the figures.
 *
 * @param {{ cpus: () => { model: string }[], platform: () => string, release: () => string }} os
 * @returns {string}
 */
export function environment(os) {
  const cpus = os.cpus();
  return [
    `Node ${process.version}, ${cpus[0]?.model ?? "unknown CPU"}, ${cpus.length} logical CPUs visible.`,
    `${os.platform()} ${os.release()}, a container on a shared host: wall times are indicative.`,
  ].join("\n");
}
