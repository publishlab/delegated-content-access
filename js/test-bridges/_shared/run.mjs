#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { basename, dirname, join, resolve } from "node:path";

import {
  booleanEnvironment,
  bridgeMode,
  bridgeModules,
  createRunDirectory,
  refuseObsoleteVariables,
  writeRunRecord,
} from "./environment.mjs";
import {
  CASE_REPORT,
  bridgeIds,
  bridgeModule,
  exclusionArguments,
  exclusionsOf,
  namedExclusions,
  portableSelection,
  portableSelectionArguments,
  runnerArguments,
  verifySelectionEvidence,
} from "./run-support.mjs";
import { listCases } from "./list-cases.mjs";

refuseObsoleteVariables();
const requestedBridge = process.env.DCA_BRIDGE;
if (requestedBridge === undefined || requestedBridge === "")
  throw new Error(
    `DCA_BRIDGE names the bridge to run: bridge IDs: ${bridgeIds().join(", ")}; or a path to a bridge.mjs`,
  );
// A package script runs in js; pnpm keeps the caller's directory in
// INIT_CWD. Relative DCA_BRIDGE and DCA_TARGET_ROOT paths resolve against it.
const callerDirectory = process.env.INIT_CWD || process.cwd();
const v1Root = fileURLToPath(new URL("../../", import.meta.url));
const packagePath = fileURLToPath(new URL("../../package.json", import.meta.url));
const preload = fileURLToPath(new URL("./preload.mjs", import.meta.url));
const requestedSelection = process.argv[2] ?? "public";
const namedSelection =
  requestedSelection.endsWith(".test.js") || requestedSelection === "public"
    ? undefined
    : portableSelection({ v1Root, name: requestedSelection });
if (namedSelection && process.argv.length !== 3)
  throw new Error("runner takes one named portable selection");
const directArguments = namedSelection
  ? undefined
  : runnerArguments({
      packagePath,
      v1Root,
      arguments_: process.argv.slice(2),
      environment: process.env,
    });
// Named exclusions skip exact cases of the one test file a direct run names.
// A portable selection registers its cases in the test file instead.
const exclusionsPath = process.env.DCA_BRIDGE_EXCLUSIONS;
const oneFile = namedSelection === undefined && requestedSelection !== "public";
if (exclusionsPath !== undefined && !oneFile)
  throw new Error("DCA_BRIDGE_EXCLUSIONS applies to a direct run of one test file");
const exclusions =
  exclusionsPath === undefined
    ? []
    : exclusionsOf(
        namedExclusions(readFileSync(resolve(callerDirectory, exclusionsPath), "utf8")),
        requestedSelection,
      );
// Each exclusion names exactly one registered case of the file, so a renamed
// or duplicated case cannot hide behind it.
if (exclusions.length > 0) {
  const declared = listCases(resolve(v1Root, requestedSelection));
  for (const entry of exclusions) {
    const count = declared.filter((name) => name === entry.name).length;
    if (count !== 1)
      throw new Error(
        `DCA_BRIDGE_EXCLUSIONS names "${entry.name}", which ${requestedSelection} declares ${count} times; an exclusion names exactly one case`,
      );
  }
}
// A bridge module path resolves against the caller's directory before the
// runner changes into js. The run directory takes the bridge's directory
// name as its label.
const bridgePath = bridgeModule(requestedBridge, callerDirectory);
const bridgeId = basename(dirname(bridgePath));
const debug = booleanEnvironment("DCA_DEBUG", process.env.DCA_DEBUG);
const timing = booleanEnvironment("DCA_TIMING", process.env.DCA_TIMING);
const requestedMode = bridgeMode(process.env.DCA_BRIDGE_MODE);
const runMode = namedSelection ? "strict" : requestedMode;
const modules = bridgeModules(process.env.DCA_BRIDGE_MODULES);
if (modules !== undefined && namedSelection)
  throw new Error(
    "a portable selection routes every module it imports; DCA_BRIDGE_MODULES is for a direct strict run",
  );
if (modules !== undefined && runMode !== "strict")
  throw new Error(
    "DCA_BRIDGE_MODULES names the modules of a strict run; set DCA_BRIDGE_MODE=strict",
  );
const started = new Date();
const startedAt = started.toISOString();
let runDirectory;
const childEnvironment = { ...process.env };
// The runner changes into js before starting Node. Keep the caller's
// coordinates usable by resolving the bridge module and test-target root first.
childEnvironment.DCA_BRIDGE = bridgePath;
if (childEnvironment.DCA_TARGET_ROOT !== undefined)
  childEnvironment.DCA_TARGET_ROOT = resolve(callerDirectory, childEnvironment.DCA_TARGET_ROOT);
let temporaryLogParent;
if (namedSelection) {
  if (process.env.DCA_BRIDGE_MODE !== undefined && process.env.DCA_BRIDGE_MODE !== "strict")
    throw new Error("portable selections require DCA_BRIDGE_MODE=strict");
  childEnvironment.DCA_BRIDGE_MODE = "strict";
  childEnvironment.DCA_TEST_SELECTION = namedSelection.name;
  if (process.env.DCA_LOG_DIR === undefined) {
    temporaryLogParent = mkdtempSync(join(tmpdir(), "dca-portable-selection-"));
    childEnvironment.DCA_LOG_DIR = temporaryLogParent;
  }
}
// A run over a named module set reports which modules it left on the
// reference, so it keeps a transcript as a selection does.
if (modules !== undefined && process.env.DCA_LOG_DIR === undefined) {
  temporaryLogParent = mkdtempSync(join(tmpdir(), "dca-module-set-"));
  childEnvironment.DCA_LOG_DIR = temporaryLogParent;
}
if (childEnvironment.DCA_LOG_DIR !== undefined)
  runDirectory = createRunDirectory({ parent: resolve(childEnvironment.DCA_LOG_DIR), bridgeId });
let arguments_ = directArguments ?? [];
if (exclusions.length > 0) arguments_.splice(1, 0, ...exclusionArguments(exclusions));
let caseReportPath;
if (namedSelection) {
  // The run reporter writes the case report into the run directory, where the
  // runner reads it after Node exits.
  if (runDirectory === undefined) throw new Error("portable selection has no run directory");
  caseReportPath = join(runDirectory, CASE_REPORT);
  arguments_ = portableSelectionArguments(namedSelection, { reportPath: caseReportPath });
}
if (runDirectory !== undefined) {
  writeRunRecord(runDirectory, {
    command: [process.execPath, ...arguments_],
    selector: process.argv.slice(2),
    startedAt,
    bridge: bridgePath,
    mode: runMode,
    ...(modules === undefined ? {} : { modules }),
    ...(exclusionsPath === undefined ? {} : { exclusions }),
    workerFiles: [],
  });
  childEnvironment.DCA_LOG_DIR = runDirectory;
}
arguments_.unshift("--import", preload);
if (debug) process.stderr.write(`dca bridge runner: ${bridgeId}; ${arguments_.join(" ")}\n`);
const began = performance.now();
const child = spawnSync(process.execPath, arguments_, {
  cwd: v1Root,
  env: childEnvironment,
  stdio: "inherit",
});
const elapsedMs = performance.now() - began;
const status = child.error ? 1 : (child.status ?? 1);
let verifiedStatus = status;
if (namedSelection) {
  const evidenceDirectory = runDirectory ?? childEnvironment.DCA_LOG_DIR;
  try {
    const summary = verifySelectionEvidence(
      namedSelection,
      transcriptShards(evidenceDirectory),
      caseReportText(caseReportPath),
    );
    // A selection that requires class members or constructors reports them
    // beside its exports.
    const membersClause =
      summary.requiredMembersTotal === 0
        ? ""
        : `required members ${summary.requiredMembersCalled}/${summary.requiredMembersTotal} called; `;
    const constructorsClause =
      summary.requiredConstructorsTotal === 0
        ? ""
        : `required constructors ${summary.requiredConstructorsCalled}/${summary.requiredConstructorsTotal} called; `;
    process.stderr.write(
      `dca bridge runner: portable ${namedSelection.name}: ${summary.passed} selected tests passed; required exports ${summary.requiredCalled}/${summary.requiredTotal} called; ${membersClause}${constructorsClause}${summary.externalCalls} external calls; ${summary.referenceFallbacks} reference fallbacks; ${summary.uncarriedResults} uncarried results; Node exit ${status}\n`,
    );
  } catch (error) {
    verifiedStatus = 1;
    process.stderr.write(
      `dca bridge runner: portable ${namedSelection.name} verification failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
  }
} else if (runDirectory && modules !== undefined) {
  const finals = transcriptShards(runDirectory)
    .flat()
    .filter((record) => record.event === "final");
  const calls = finals.reduce((total, record) => total + record.externalCalls, 0);
  const uncarried = finals.reduce((total, record) => total + (record.uncarriedResults ?? 0), 0);
  const unrouted = [...new Set(finals.flatMap((record) => record.unroutedModules ?? []))].sort();
  const left = unrouted.length === 0 ? "none" : unrouted.join(", ");
  process.stderr.write(
    `dca bridge runner: strict over named modules ${modules.join(", ")}: ${calls} external calls; ${uncarried} uncarried results; left on the reference: ${left}\n`,
  );
} else if (runDirectory && runMode === "overlay") {
  const finals = transcriptShards(runDirectory)
    .flat()
    .filter((record) => record.event === "final");
  const calls = finals.reduce((total, record) => total + record.externalCalls, 0);
  const fallbacks = finals.reduce((total, record) => total + record.referenceFallbacks, 0);
  const uncarried = finals.reduce((total, record) => total + (record.uncarriedResults ?? 0), 0);
  process.stderr.write(
    calls === 0
      ? "dca bridge runner: overlay made no external calls; this run is vacuous as bridge evidence\n"
      : `dca bridge runner: overlay: ${calls} external calls; ${fallbacks} reference fallbacks; ${uncarried} uncarried results, each a failed call after dispatch\n`,
  );
}
if (exclusionsPath !== undefined) {
  const named = exclusions.map((entry) => `"${entry.name}" (${entry.reason})`).join("; ");
  const cases = exclusions.length === 1 ? "case" : "cases";
  process.stderr.write(
    `dca bridge runner: excluded ${exclusions.length} named ${cases} of ${requestedSelection}${named === "" ? "" : `: ${named}`}\n`,
  );
}
const finishedAt = new Date().toISOString();
if (runDirectory) {
  const workerFiles = readdirSync(runDirectory)
    .filter((name) => name !== "run.json" && name !== CASE_REPORT)
    .sort();
  writeRunRecord(runDirectory, {
    command: [process.execPath, ...arguments_],
    selector: process.argv.slice(2),
    startedAt,
    finishedAt,
    ...(timing ? { elapsedMs } : {}),
    exitStatus: verifiedStatus,
    bridge: bridgePath,
    mode: runMode,
    ...(modules === undefined ? {} : { modules }),
    ...(exclusionsPath === undefined ? {} : { exclusions }),
    workerFiles,
  });
}
process.stderr.write(
  timing
    ? `dca bridge runner: ${elapsedMs.toFixed(1)} ms; exit ${verifiedStatus}\n`
    : `dca bridge runner: exit ${verifiedStatus}\n`,
);
if (child.error) process.stderr.write(`dca bridge runner: ${child.error.message}\n`);
if (temporaryLogParent) rmSync(temporaryLogParent, { recursive: true, force: true });
process.exitCode = verifiedStatus;

/**
 * The case report's text, or undefined when Node left none behind.
 *
 * @param {string | undefined} path
 */
function caseReportText(path) {
  if (path === undefined || !existsSync(path)) return undefined;
  return readFileSync(path, "utf8");
}

/** @param {string | undefined} directory @returns {any[][]} */
function transcriptShards(directory) {
  if (directory === undefined) throw new Error("portable selection has no transcript directory");
  return readdirSync(directory)
    .filter((file) => file.endsWith(".transcript.jsonl"))
    .map((file) => {
      const text = readFileSync(join(directory, file), "utf8").trim();
      return text.length === 0 ? [] : text.split("\n").map((line) => JSON.parse(line));
    });
}
