// @ts-check
import { webcrypto } from "node:crypto";
import { parentPort, workerData } from "node:worker_threads";
import { executeSample } from "./runBench.js";
import { observationContext } from "./observe.js";

/** Algorithm names only; no key bytes or arguments leave this instrumentation.
 * @param {unknown} value @returns {string}
 */
function algorithmName(value) {
  if (typeof value === "string") return value;
  if (
    value !== null &&
    typeof value === "object" &&
    "name" in value &&
    typeof value.name === "string"
  )
    return value.name;
  return "unspecified";
}

/** Count attempted stock WebCrypto calls inside this isolated worker only.
 * @returns {{counts: Record<import("./observe.js").ObservationPhase, Record<string, number>>, total: Record<string, number>, restore: () => void}}
 */
function instrument() {
  /** @type {Record<import("./observe.js").ObservationPhase, Record<string, number>>} */
  const counts = { setup: {}, primary: {}, probes: {}, unscoped: {} };
  /** @type {Record<string, number>} */
  const total = {};
  /** @type {(() => void)[]} */
  const restorers = [];
  /** @param {object} target @param {string} method @param {number} algorithmIndex */
  function wrap(target, method, algorithmIndex) {
    const members = /** @type {Record<string, unknown>} */ (target);
    const original = members[method];
    if (typeof original !== "function")
      throw new Error(`WebCrypto method ${method} is unavailable`);
    const ownDescriptor = Object.getOwnPropertyDescriptor(target, method);
    Object.defineProperty(target, method, {
      configurable: true,
      writable: true,
      /** @param {unknown[]} args */
      value(...args) {
        let algorithm = args[algorithmIndex];
        if (
          method === "exportKey" &&
          algorithm &&
          typeof algorithm === "object" &&
          "algorithm" in algorithm
        )
          algorithm = algorithm.algorithm;
        const name = `${method}:${algorithmName(algorithm)}`;
        const phase = observationContext.getStore() ?? "unscoped";
        counts[phase][name] = (counts[phase][name] ?? 0) + 1;
        total[name] = (total[name] ?? 0) + 1;
        return Reflect.apply(original, target, args);
      },
    });
    restorers.push(() => {
      if (ownDescriptor) Object.defineProperty(target, method, ownDescriptor);
      else Reflect.deleteProperty(target, method);
    });
  }
  try {
    for (const method of [
      "encrypt",
      "decrypt",
      "sign",
      "verify",
      "digest",
      "generateKey",
      "deriveBits",
      "deriveKey",
    ])
      wrap(webcrypto.subtle, method, 0);
    wrap(webcrypto.subtle, "importKey", 2);
    wrap(webcrypto.subtle, "exportKey", 1);
    wrap(webcrypto.subtle, "wrapKey", 3);
    wrap(webcrypto.subtle, "unwrapKey", 3);
    wrap(webcrypto, "getRandomValues", -1);
    wrap(webcrypto, "randomUUID", -1);
  } catch (error) {
    for (const restore of restorers.reverse()) restore();
    throw error;
  }
  return {
    counts,
    total,
    restore() {
      for (const restore of restorers.reverse()) restore();
    },
  };
}

if (parentPort) {
  try {
    // Import before installing wrappers: module loading is setup, not role work.
    const module = await import(workerData.scenarioUrl);
    const scenario = module.scenario;
    if (!scenario || typeof scenario.execute !== "function")
      throw new TypeError("Worker module must export scenario");
    if (!Object.isFrozen(scenario)) {
      throw new Error(
        "Crypto counting requires the module to export a frozen scenario in the worker",
      );
    }
    if (scenario.id !== workerData.scenarioId)
      throw new Error("Worker scenario identity does not match supplied scenario");
    const requested =
      typeof scenario.requestedProfiles === "function"
        ? scenario.requestedProfiles(workerData.input)
        : scenario.requestedProfiles;
    if (JSON.stringify(requested) !== JSON.stringify(workerData.requestedProfiles))
      throw new Error("Worker profile selection does not match supplied scenario");
    const declarations =
      typeof scenario.profileDeclarations === "function"
        ? scenario.profileDeclarations(workerData.input)
        : (scenario.profileDeclarations ?? []);
    if (JSON.stringify(declarations) !== JSON.stringify(workerData.profileDeclarations))
      throw new Error("Worker profile declarations do not match supplied scenario");
    const instrumentation = instrument();
    try {
      const sample = await executeSample(scenario, workerData.input, workerData.measurement);
      sample.work.crypto = instrumentation.counts;
      sample.work.cryptoTotal = instrumentation.total;
      parentPort.postMessage({ sample });
    } finally {
      instrumentation.restore();
    }
  } catch (error) {
    parentPort.postMessage({
      error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    });
  }
}
