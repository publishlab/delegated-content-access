// @ts-check
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { Worker } from "node:worker_threads";
import { resolveProfiles, validateProfileCatalogue } from "../../tools/profileCatalogue.js";
import { createObserver, finishObservation } from "./observe.js";

/** @typedef {Record<string, unknown>} Input */
/** @typedef {"publisher" | "publisher-issuer" | "full"} Scope */
/** @typedef {{scope?: Scope, runs?: number, warmup?: number, timeSteps?: boolean, countCrypto?: boolean}} Measurement */
/** @typedef {{id: string, dependsOn: string[], ref: string, status: "proposal" | "public-working-draft"}} ProfileDeclaration */
/** @typedef {{id: string, requestedProfiles: string[] | ((input: Input) => string[]), defaults: Input,
 * profileDeclarations?: ProfileDeclaration[] | ((input: Input) => ProfileDeclaration[]),
 * resolveInput?: (input: Input) => Input | Promise<Input>,
 * execute: (context: {input: Input, observe: ReturnType<typeof createObserver>, scope: Scope}) => unknown | Promise<unknown>}} Scenario */
/** @typedef {ReturnType<typeof finishObservation>} Sample */

const catalogueUrl = new URL("../../../verification/profile-catalogue/v1.json", import.meta.url);
const repositoryUrl = new URL("../../..", import.meta.url);

/** Resolve catalogued profiles through the shared resolver. Explicit scenario
 * declarations can only append selected leaves whose parents are catalogued;
 * they supply no catalogue duties or adoption claim.
 * @param {unknown} source @param {string[]} requested @param {ProfileDeclaration[]} declarations
 */
function resolveScenarioProfiles(source, requested, declarations) {
  const catalogue = validateProfileCatalogue(source);
  const known = new Set(catalogue.profiles.map((profile) => profile.id));
  if (
    !Array.isArray(requested) ||
    requested.some((id) => typeof id !== "string" || !/^[\x21-\x7e]+$/.test(id))
  )
    throw new TypeError("requestedProfiles must be profile identifiers");
  if (new Set(requested).size !== requested.length)
    throw new Error("requestedProfiles has duplicate names");
  if (!Array.isArray(declarations)) throw new TypeError("profileDeclarations must be an array");
  /** @type {Map<string, ProfileDeclaration>} */
  const declared = new Map();
  for (const declaration of declarations) {
    if (!declaration || typeof declaration !== "object" || Array.isArray(declaration))
      throw new TypeError("Invalid profile declaration");
    const { id, dependsOn, ref, status } = declaration;
    if (typeof id !== "string" || !/^[\x21-\x7e]+$/.test(id))
      throw new TypeError("Declared profile ID must use visible ASCII");
    if (known.has(id)) throw new Error(`Profile declaration cannot shadow catalogue profile ${id}`);
    if (declared.has(id)) throw new Error(`Duplicate profile declaration ${id}`);
    if (!requested.includes(id)) throw new Error(`Unused profile declaration ${id}`);
    if (
      !Array.isArray(dependsOn) ||
      dependsOn.length === 0 ||
      dependsOn.some((parent) => !known.has(parent)) ||
      new Set(dependsOn).size !== dependsOn.length
    )
      throw new Error(`Declared profile ${id} requires unique catalogued parents`);
    if (typeof ref !== "string" || ref.trim() !== ref || !ref)
      throw new TypeError(`Declared profile ${id} requires a reference`);
    if (status !== "proposal" && status !== "public-working-draft")
      throw new Error(`Invalid declaration status for ${id}`);
    if (Object.keys(declaration).some((key) => !["id", "dependsOn", "ref", "status"].includes(key)))
      throw new Error(`Unknown declaration member for ${id}`);
    declared.set(id, structuredClone(declaration));
  }
  for (const id of requested)
    if (!known.has(id) && !declared.has(id)) throw new Error(`unknown requested profile ${id}`);
  const cataloguedRequests = [
    ...new Set(requested.flatMap((id) => declared.get(id)?.dependsOn ?? [id])),
  ];
  const resolution = resolveProfiles(catalogue, cataloguedRequests);
  const ancestorSets = new Map(
    requested.map((id) => [
      id,
      new Set(resolveProfiles(catalogue, declared.get(id)?.dependsOn ?? [id]).resolvedProfiles),
    ]),
  );
  const requestedProfiles = requested
    .filter(
      (id) =>
        declared.has(id) ||
        !requested.some((other) => other !== id && ancestorSets.get(other)?.has(id)),
    )
    .sort();
  return {
    requestedProfiles: requested.length ? requestedProfiles : resolution.requestedProfiles,
    resolvedProfiles: [...resolution.resolvedProfiles, ...[...declared.keys()].sort()],
    profileDeclarations: [...declared.values()].sort((left, right) =>
      left.id < right.id ? -1 : left.id > right.id ? 1 : 0,
    ),
    catalogueCoverage: declarations.length ? "partial" : "complete",
  };
}

/** Strict override merge. Arrays are values, not index-keyed configuration.
 * @param {Input} defaults @param {Input} overrides @param {string} [path] @returns {Input}
 */
export function mergeInput(defaults, overrides, path = "input") {
  if (!isRecord(defaults) || !isRecord(overrides)) throw new TypeError(`${path} must be an object`);
  const merged = structuredClone(defaults);
  for (const [key, value] of Object.entries(overrides)) {
    if (!Object.hasOwn(defaults, key)) throw new Error(`Unknown ${path}.${key}`);
    const previous = defaults[key];
    if (isRecord(previous)) {
      if (!isRecord(value)) throw new TypeError(`${path}.${key} must be an object`);
      merged[key] = mergeInput(previous, value, `${path}.${key}`);
    } else {
      merged[key] = structuredClone(value);
    }
  }
  return merged;
}

/** @param {unknown} value @returns {value is Input} */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** @param {Measurement} value */
function measurementOptions(value) {
  if (!isRecord(value)) throw new TypeError("measurement must be an object");
  for (const key of Object.keys(value)) {
    if (!["scope", "runs", "warmup", "timeSteps", "countCrypto"].includes(key)) {
      throw new Error(`Unknown measurement.${key}`);
    }
  }
  const options = {
    scope: "full",
    runs: 1,
    warmup: 0,
    timeSteps: false,
    countCrypto: false,
    ...value,
  };
  if (!["publisher", "publisher-issuer", "full"].includes(options.scope))
    throw new Error("Invalid measurement.scope");
  if (!Number.isSafeInteger(options.runs) || options.runs < 1)
    throw new Error("measurement.runs must be a positive integer");
  if (!Number.isSafeInteger(options.warmup) || options.warmup < 0)
    throw new Error("measurement.warmup must be a nonnegative integer");
  if (typeof options.timeSteps !== "boolean" || typeof options.countCrypto !== "boolean")
    throw new Error("Instrumentation options must be boolean");
  return /** @type {Required<Measurement>} */ (options);
}

/** @returns {{revision: string | null, dirty: boolean | null, reason?: string}} */
function gitState() {
  try {
    const settings = {
      cwd: repositoryUrl,
      encoding: /** @type {const} */ ("utf8"),
      stdio: /** @type {["ignore", "pipe", "ignore"]} */ (["ignore", "pipe", "ignore"]),
    };
    return {
      revision: execFileSync("git", ["rev-parse", "HEAD"], settings).trim(),
      dirty:
        execFileSync("git", ["status", "--porcelain", "--untracked-files=normal"], settings).trim()
          .length > 0,
    };
  } catch {
    return { revision: null, dirty: null, reason: "Git provenance unavailable" };
  }
}

/** Execute one sample with fresh scenario-owned roles; input is cloned per call.
 * Exported for the isolated instrumentation worker, not a second public runner.
 * @param {Scenario} scenario @param {Input} input @param {Required<Measurement>} measurement
 * @returns {Promise<Sample>}
 */
export async function executeSample(scenario, input, measurement) {
  const observe = createObserver(measurement);
  const start = performance.now();
  try {
    await scenario.execute({ input: structuredClone(input), observe, scope: measurement.scope });
  } catch (error) {
    observe.check(
      "execution completed",
      false,
      error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    );
  }
  // Executing without any verification is never reported as verified success.
  if (observe.checks.length === 0) observe.check("scenario supplied verification checks", false);
  return finishObservation(observe, performance.now() - start);
}

/** @param {string | URL} scenarioUrl @param {Input} input @param {Required<Measurement>} measurement @param {string} scenarioId @param {string[]} requestedProfiles @param {ProfileDeclaration[]} profileDeclarations @returns {Promise<Sample>} */
function workerSample(
  scenarioUrl,
  input,
  measurement,
  scenarioId,
  requestedProfiles,
  profileDeclarations,
) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./cryptoWorker.js", import.meta.url), {
      workerData: {
        scenarioUrl: String(scenarioUrl),
        input,
        measurement,
        scenarioId,
        requestedProfiles,
        profileDeclarations,
      },
      // Parent --input-type and test-runner flags do not describe a file worker.
      execArgv: process.execArgv.filter((arg) => !arg.startsWith("--input-type")),
    });
    let received = false;
    worker.once("message", (message) => {
      received = true;
      if (message.error) reject(new Error(message.error));
      else resolve(message.sample);
    });
    worker.once("error", reject);
    worker.once("exit", (code) => {
      if (!received) reject(new Error(`Crypto worker exited without a sample (${code})`));
    });
  });
}

/** @param {number[]} values */
function distribution(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
  return {
    count: sorted.length,
    median,
    min: sorted[0],
    max: sorted.at(-1),
    spread: sorted[sorted.length - 1] - sorted[0],
  };
}

/** Summarize numeric measurements without treating absent metrics as zero.
 * @param {unknown[]} values
 */
function numericSummary(values) {
  /** @type {Record<string, number[]>} */
  const metrics = Object.create(null);
  /** @param {unknown} value @param {string} path */
  function visit(value, path) {
    if (typeof value === "number" && Number.isFinite(value)) (metrics[path] ??= []).push(value);
    else if (value && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) visit(child, path ? `${path}.${key}` : key);
    }
  }
  for (const value of values) visit(value, "");
  return Object.fromEntries(
    Object.entries(metrics).map(([name, numbers]) => [name, distribution(numbers)]),
  );
}

/** @param {Sample[]} samples */
function summarize(samples) {
  /** @type {Record<string, number[]>} */
  const observations = /** @type {Record<string, number[]>} */ (Object.create(null));
  for (const sample of samples) {
    for (const [name, timings] of Object.entries(sample.timings)) {
      const entries = Array.isArray(timings) ? timings : [timings];
      (observations[name] ??= []).push(
        entries.reduce((sum, timing) => sum + timing.milliseconds, 0),
      );
    }
  }
  return {
    runs: samples.length,
    passed: samples.filter((sample) => sample.success).length,
    sizes: numericSummary(samples.map((sample) => sample.sizes)),
    work: numericSummary(samples.map((sample) => sample.work)),
    timings: Object.fromEntries(
      Object.entries(observations).map(([name, values]) => [name, distribution(values)]),
    ),
  };
}

/** Run one resolved logical workload; each repetition has fresh roles and randomness.
 * Only discloseable scenario inputs belong in the report. Fixture private keys
 * must be generated inside execute(), never supplied as reportable input.
 * @param {{scenario: Scenario, input?: Input, measurement?: Measurement, scenarioUrl?: string | URL}} options
 */
export async function runBench({ scenario, input = {}, measurement = {}, scenarioUrl }) {
  const setupStart = performance.now();
  if (
    !scenario ||
    typeof scenario.id !== "string" ||
    !scenario.id ||
    typeof scenario.execute !== "function"
  )
    throw new TypeError("A named executable scenario is required");
  if (!isRecord(input)) throw new TypeError("input must be an object");
  const resolvedMeasurement = measurementOptions(measurement);
  if (resolvedMeasurement.countCrypto) {
    if (!scenarioUrl)
      throw new Error("Crypto counting requires scenarioUrl for an isolated worker");
    if (!Object.isFrozen(scenario)) {
      throw new Error(
        "Crypto counting requires a frozen scenario export so its execution cannot be replaced",
      );
    }
    const loaded = await import(String(scenarioUrl));
    if (loaded.scenario !== scenario) {
      throw new Error(
        "Crypto counting requires the unmodified scenario export from scenarioUrl; supplied scenario identity does not match",
      );
    }
  }
  const effectiveInput = scenario.resolveInput
    ? await scenario.resolveInput(structuredClone(input))
    : mergeInput(scenario.defaults, input);
  if (!isRecord(effectiveInput)) throw new TypeError("Scenario resolveInput must return an object");
  // Reject non-JSON values rather than silently dropping them from saved inputs.
  const serialized = JSON.stringify(effectiveInput, (_key, value) => {
    if (
      typeof value === "undefined" ||
      typeof value === "function" ||
      typeof value === "symbol" ||
      typeof value === "bigint" ||
      (typeof value === "number" && !Number.isFinite(value))
    )
      throw new TypeError("Resolved input must be JSON-compatible");
    return value;
  });
  const resolvedInput = /** @type {Input} */ (JSON.parse(serialized));
  const requested =
    typeof scenario.requestedProfiles === "function"
      ? scenario.requestedProfiles(resolvedInput)
      : scenario.requestedProfiles;
  const declarations =
    typeof scenario.profileDeclarations === "function"
      ? scenario.profileDeclarations(resolvedInput)
      : (scenario.profileDeclarations ?? []);
  const profiles = resolveScenarioProfiles(
    JSON.parse(readFileSync(catalogueUrl, "utf8")),
    requested,
    declarations,
  );
  const setup = {
    scenario: scenario.id,
    input: resolvedInput,
    ...profiles,
    measurement: resolvedMeasurement,
    runtime: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      instrumentation: resolvedMeasurement.countCrypto
        ? "isolated-worker-webcrypto-counts"
        : "none",
    },
    git: gitState(),
    milliseconds: performance.now() - setupStart,
  };
  /** @type {Sample[]} */
  const samples = [];
  /** @type {Sample[]} */
  const warmupSamples = [];
  for (let index = 0; index < resolvedMeasurement.warmup + resolvedMeasurement.runs; index++) {
    let sample;
    try {
      sample = resolvedMeasurement.countCrypto
        ? await workerSample(
            /** @type {string | URL} */ (scenarioUrl),
            resolvedInput,
            resolvedMeasurement,
            scenario.id,
            requested,
            declarations,
          )
        : await executeSample(scenario, resolvedInput, resolvedMeasurement);
    } catch (error) {
      const observe = createObserver(resolvedMeasurement);
      observe.check(
        "sample worker completed",
        false,
        error instanceof Error ? error.message : String(error),
      );
      sample = finishObservation(observe, 0);
    }
    if (index < resolvedMeasurement.warmup) warmupSamples.push(sample);
    else samples.push(sample);
  }
  const first = samples[0];
  return {
    setup,
    samples,
    warmupSamples,
    captures: first.captures,
    sizes: first.sizes,
    work: first.work,
    timings: first.timings,
    cache: first.cache,
    checks: first.checks,
    success: [...warmupSamples, ...samples].every((sample) => sample.success),
    summary: summarize(samples),
  };
}
