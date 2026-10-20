import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { randomUUID } from "node:crypto";

import { isDriverOwnedModule, isSafeModulePath } from "./routing.mjs";

/** @param {string} name @param {string | undefined} value */
export function booleanEnvironment(name, value) {
  if (value === undefined || value === "0") return false;
  if (value === "1") return true;
  throw new TypeError(`${name} is unset, 0, or 1`);
}

/**
 * A bridge runs in `overlay` mode, the default, or `strict` mode.
 *
 * @param {string | undefined} value
 * @returns {'overlay'|'strict'}
 */
export function bridgeMode(value) {
  const mode = value ?? "overlay";
  if (mode !== "overlay" && mode !== "strict")
    throw new TypeError(`DCA_BRIDGE_MODE "${mode}" is unknown; modes are overlay and strict`);
  return mode;
}

/**
 * The named module set of a strict run, from `DCA_BRIDGE_MODULES`: reference
 * module paths separated by commas, such as
 * `core-shared--publisher-issuer/periodKeys.js,core-shared/periodKeyProfiles.js`. Unset means
 * every implementation module routes. A set that names no module, a path that
 * is no implementation module path, or a path named twice is refused.
 *
 * @param {string | undefined} value
 * @returns {readonly string[] | undefined}
 */
export function bridgeModules(value) {
  if (value === undefined) return undefined;
  const modules = value.split(",").map((entry) => entry.trim());
  const named = modules.length > 0 && modules.every((module) => module.length > 0);
  if (!named)
    throw new TypeError("DCA_BRIDGE_MODULES lists reference module paths, comma-separated");
  for (const module of modules) {
    const implementation = isSafeModulePath(module) && !isDriverOwnedModule(module);
    if (!implementation)
      throw new TypeError(
        `DCA_BRIDGE_MODULES names ${module}, which is no implementation module path`,
      );
  }
  const distinct = new Set(modules).size === modules.length;
  if (!distinct) throw new TypeError("DCA_BRIDGE_MODULES names each module once");
  return Object.freeze(modules);
}

/** Variables that were renamed. Each maps to its replacement. */
const OBSOLETE_VARIABLES = Object.freeze({
  DCA_PORT_ROOT: "DCA_TARGET_ROOT",
  DCA_PORT_NAMESPACE: "DCA_TARGET_NAMESPACE",
});

/**
 * Refuses a renamed variable before any adapter starts, so a stale shell
 * setting cannot silently leave the test target unconfigured.
 *
 * @param {NodeJS.ProcessEnv} [environment]
 */
export function refuseObsoleteVariables(environment = process.env) {
  for (const [obsolete, replacement] of Object.entries(OBSOLETE_VARIABLES))
    if (environment[obsolete] !== undefined)
      throw new Error(`${obsolete} is obsolete; use ${replacement}`);
}

/** @param {Date} date */
function utcFileStamp(date) {
  return date
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}/, "");
}

/** @param {{ parent: string, bridgeId: string, pid?: number, now?: Date }} options */
export function createRunDirectory({ parent, bridgeId, pid = process.pid, now = new Date() }) {
  if (parent.length === 0) throw new TypeError("DCA_LOG_DIR is a non-empty directory path");
  mkdirSync(parent, { recursive: true });
  const prefix = `run--${utcFileStamp(now)}--${bridgeId}--${pid}`;
  for (let suffix = 0; ; suffix += 1) {
    const directory = join(parent, suffix === 0 ? prefix : `${prefix}--${suffix}`);
    try {
      mkdirSync(directory);
      return directory;
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
    }
  }
}

/** @param {string} directory */
function isRunDirectory(directory) {
  return basename(directory).startsWith("run--") && existsSync(join(directory, "run.json"));
}

/** @param {{ bridgeId: string, environment?: NodeJS.ProcessEnv, pid?: number }} options */
export function bridgeEnvironment({ bridgeId, environment = process.env, pid = process.pid }) {
  const debug = booleanEnvironment("DCA_DEBUG", environment.DCA_DEBUG);
  const timing = booleanEnvironment("DCA_TIMING", environment.DCA_TIMING);
  const logDirectory = environment.DCA_LOG_DIR;
  if (logDirectory === undefined) return { debug, timing };
  const runDirectory = isRunDirectory(logDirectory)
    ? logDirectory
    : createRunDirectory({ parent: logDirectory, bridgeId, pid });
  const stem = `${bridgeId}-${pid}-${randomUUID()}`;
  return {
    debug,
    runDirectory,
    transcriptPath: join(runDirectory, `${stem}.transcript.jsonl`),
    ...(timing ? { timingPath: join(runDirectory, `${stem}.timing.json`) } : {}),
    timing,
  };
}

/** @param {string} directory @param {Record<string, unknown>} record */
export function writeRunRecord(directory, record) {
  writeFileSync(join(directory, "run.json"), `${JSON.stringify(record, null, 2)}\n`);
}
