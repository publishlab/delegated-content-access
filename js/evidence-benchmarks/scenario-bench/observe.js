// @ts-check
import { AsyncLocalStorage } from "node:async_hooks";
import { performance } from "node:perf_hooks";
import { gzipSync } from "node:zlib";

/** @typedef {"setup" | "primary" | "probes" | "unscoped"} ObservationPhase */
/** Async observation context is local to this process and follows awaited work.
 * Nested setup/probe observations keep their enclosing diagnostic phase.
 * @type {AsyncLocalStorage<ObservationPhase>}
 */
export const observationContext = new AsyncLocalStorage();

/** @param {string} name @returns {ObservationPhase} */
function phaseFor(name) {
  const outer = observationContext.getStore();
  if (outer === "setup" || outer === "probes") return outer;
  if (["setup", "keySetup", "initial-cache-setup"].includes(name)) return "setup";
  if (name.startsWith("probe:")) return "probes";
  return "primary";
}

/** Keep diagnostic observations out of primary role/step timing series.
 * @param {string} name @param {ObservationPhase} phase
 */
function timingName(name, phase) {
  if (phase === "probes" && !name.startsWith("probe:")) return `probe:${name}`;
  if (
    phase === "setup" &&
    !name.startsWith("setup:") &&
    !["setup", "keySetup", "initial-cache-setup"].includes(name)
  )
    return `setup:${name}`;
  return name;
}

/** @typedef {Record<string, unknown>} Fields */
/** @typedef {{document: unknown, text: string, status?: number, partitions?: Record<string, string>}} Capture */
/** @typedef {{milliseconds: number, nested: boolean}} Timing */
/** @typedef {{name: string, passed: boolean, details?: unknown}} Check */
/** @typedef {{scope: string, timeSteps?: boolean}} ObservationOptions */

/** Repeated boundary observations remain separate physical messages.
 * @template T
 * @param {Record<string, T | T[]>} target @param {string} name @param {T} value
 */
function append(target, name, value) {
  const previous = Object.hasOwn(target, name) ? target[name] : undefined;
  if (previous === undefined) target[name] = value;
  else if (Array.isArray(previous)) previous.push(value);
  else target[name] = [previous, value];
}

/** @param {ObservationOptions} options */
export function createObserver(options) {
  /** @type {Record<string, Capture | Capture[]>} */
  const captures = /** @type {Record<string, Capture | Capture[]>} */ (Object.create(null));
  /** @type {Record<string, Timing | Timing[]>} */
  const timings = /** @type {Record<string, Timing | Timing[]>} */ (Object.create(null));
  /** @type {Record<string, number>} */
  const work = /** @type {Record<string, number>} */ (Object.create(null));
  /** @type {Record<string, unknown>} */
  const cache = /** @type {Record<string, unknown>} */ (Object.create(null));
  /** @type {Check[]} */
  const checks = [];
  return {
    scope: options.scope,
    captures,
    timings,
    work,
    cache,
    checks,
    /** @template T @param {string} name @param {() => T | Promise<T>} fn @param {{nested?: boolean, step?: boolean}} [settings] */
    async time(name, fn, settings = {}) {
      // Detailed steps are opt-in; role timings retain nesting independently.
      const phase = phaseFor(name);
      if (settings.step && !options.timeSteps) return await observationContext.run(phase, fn);
      const start = performance.now();
      try {
        return await observationContext.run(phase, fn);
      } finally {
        append(timings, timingName(name, phase), {
          milliseconds: performance.now() - start,
          nested: settings.nested === true,
        });
      }
    },
    /** @param {string} name @param {unknown} document @param {{text?: string, status?: number, partitions?: Record<string, string>}} [settings] */
    capture(name, document, settings = {}) {
      const serializationStart = performance.now();
      const text = settings.text ?? JSON.stringify(document);
      if (typeof text !== "string") throw new TypeError(`capture ${name} has no JSON text`);
      const parsed = JSON.parse(text);
      if (!equalJson(parsed, document)) {
        throw new Error(`capture ${name} text does not match document`);
      }
      if (settings.partitions) {
        const joinedBytes = Object.values(settings.partitions).reduce(
          (sum, part) => sum + Buffer.byteLength(part, "utf8"),
          0,
        );
        if (
          joinedBytes !== Buffer.byteLength(text, "utf8") ||
          Object.values(settings.partitions).join("") !== text
        ) {
          throw new Error(`capture ${name} partitions must concatenate to its exact text`);
        }
      }
      append(timings, "totalCaptureSerializationAndValidation", {
        milliseconds: performance.now() - serializationStart,
        nested: false,
      });
      append(captures, name, {
        document: parsed,
        text,
        ...(settings.status === undefined ? {} : { status: settings.status }),
        ...(settings.partitions ? { partitions: structuredClone(settings.partitions) } : {}),
      });
    },
    /** @param {string} name @param {boolean} passed @param {unknown} [details] */
    check(name, passed, details) {
      if (typeof passed !== "boolean") throw new TypeError(`check ${name} must be boolean`);
      checks.push({ name, passed, ...(details === undefined ? {} : { details }) });
    },
    /** @param {string} name @param {number} [amount] */
    count(name, amount = 1) {
      if (!Number.isFinite(amount)) throw new TypeError(`counter ${name} must be finite`);
      work[name] = (work[name] ?? 0) + amount;
    },
    /** @param {string} name @param {unknown} data */
    snapshot(name, data) {
      cache[name] = structuredClone(data);
    },
  };
}

/** Object member ordering is irrelevant to a parsed capture.
 * @param {unknown} a @param {unknown} b @returns {boolean}
 */
function equalJson(a, b) {
  if (Object.is(a, b)) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((value, index) => equalJson(value, b[index]));
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const left = /** @type {Fields} */ (a);
    const right = /** @type {Fields} */ (b);
    return (
      Object.keys(left).length === Object.keys(right).length &&
      Object.keys(left).every(
        (key) => Object.hasOwn(right, key) && equalJson(left[key], right[key]),
      )
    );
  }
  return false;
}

/** @param {string} text */
function bytes(text) {
  return { json: Buffer.byteLength(text, "utf8"), gzip: gzipSync(text, { level: 9 }).byteLength };
}

/** @param {Capture} capture */
function captureSize(capture) {
  return {
    available: true,
    ...bytes(capture.text),
    ...(capture.partitions
      ? {
          partitions: Object.fromEntries(
            Object.entries(capture.partitions).map(([name, text]) => [name, bytes(text)]),
          ),
          partitionGzipAdditive: false,
        }
      : {}),
  };
}

/** @param {ReturnType<typeof createObserver>} observe @param {number} elapsed */
export function finishObservation(observe, elapsed) {
  /** @type {Record<string, unknown>} */
  const captures = { ...observe.captures };
  /** @type {Record<string, unknown>} */
  const sizes = /** @type {Record<string, unknown>} */ (Object.create(null));
  const compressionStart = performance.now();
  for (const [name, value] of Object.entries(observe.captures)) {
    sizes[name] = Array.isArray(value) ? value.map(captureSize) : captureSize(value);
  }
  append(observe.timings, "totalArtifactByteAccountingAndGzip", {
    milliseconds: performance.now() - compressionStart,
    nested: false,
  });
  for (const name of ["delivery", "dcaData", "request", "response"]) {
    if (!Object.hasOwn(captures, name)) {
      const missing = {
        available: false,
        reason: "No capture was recorded for this stage in this sample/scope",
      };
      captures[name] = missing;
      sizes[name] = missing;
    }
  }
  return {
    captures,
    sizes,
    work: /** @type {Record<string, unknown>} */ (observe.work),
    timings: { ...observe.timings, execution: { milliseconds: elapsed, nested: false } },
    cache: Object.keys(observe.cache).length
      ? observe.cache
      : {
          available: false,
          reason: "Client cache was not observed in this scope",
        },
    checks: observe.checks,
    success: observe.checks.every((check) => check.passed),
  };
}
