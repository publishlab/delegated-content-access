// @ts-check

// The public JavaScript gate for this demo, as one package script.
//
//     npm run check
//
// It runs no conformance work. It lints, then verifies the admitted checked-
// JavaScript slice, source boundaries, JavaScript reference behavior, and
// experiments.
// Vectors, repository tooling, portable contracts, and cross-runtime replay
// have their own explicit commands and are not called from here. This script
// never downloads a toolchain.
//
// Exit codes:
//   0  every required public-gate stage held
//   1  a required stage ran and failed
//   2  a required stage could not run or verified less than it set out to
//
// `js/check` is a forwarder to this script.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { npmLauncher } from "./npmLauncher.js";

/**
 * @typedef {object} Counts
 * @property {number} tests
 * @property {number} pass
 * @property {number} fail
 * @property {number} cancelled
 * @property {number} skipped
 * @property {number} todo
 */

/**
 * @typedef {object} Verdict
 * @property {'PASS' | 'FAIL' | 'PART'} verdict
 * @property {string} reason - the tally's detail column
 * @property {string} [note] - a line printed above the tally, as the sh gate prints it
 */

const SUMMARY_KEYS = /** @type {const} */ ([
  "tests",
  "pass",
  "fail",
  "cancelled",
  "skipped",
  "todo",
]);

/**
 * Sum the TAP summary lines a lane prints. An aggregate lane prints one
 * summary per child, so every line counts toward the same total.
 *
 * @param {string} output - the lane's combined stdout and stderr
 * @returns {Counts}
 */
export function tapCounts(output) {
  /** @type {Counts} */
  const counts = { tests: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
  for (const key of SUMMARY_KEYS) {
    const lines = output.matchAll(new RegExp(`^# ${key} ([0-9]+)\\s*$`, "gm"));
    for (const line of lines) counts[key] += Number(line[1]);
  }
  return counts;
}

/**
 * The static stage answers with its exit status alone.
 *
 * @param {number | null} status
 * @returns {Verdict}
 */
export function staticDecision(status) {
  if (status === 0) return { verdict: "PASS", reason: "held" };
  return { verdict: "FAIL", reason: `exit ${status}` };
}

/**
 * Judge one behavioral stage from what the lane reported.
 *
 * A run that reports its own failures or cancellations has already answered.
 * It is judged FAIL before a skip ceiling or a todo pin can call the same run
 * partial, so a stale pin cannot print one PART line over every failure the
 * tier named.
 *
 * @param {number | null} status - the lane's exit status
 * @param {Counts} counts
 * @param {number} skipCeiling - the maximum accepted skips
 * @param {number | null} todoPin - the exact accepted todos, or null for no pin
 * @returns {Verdict}
 */
export function stageDecision(status, counts, skipCeiling, todoPin) {
  const held =
    status === 0 &&
    counts.tests > 0 &&
    counts.pass > 0 &&
    counts.cancelled === 0 &&
    counts.skipped <= skipCeiling &&
    (todoPin === null || counts.todo === todoPin);
  if (held) {
    return {
      verdict: "PASS",
      reason: `${counts.tests} tests, ${counts.skipped} skipped, ${counts.todo} todo`,
    };
  }

  const detail = `${counts.tests} tests, ${counts.fail} failed, ${counts.cancelled} cancelled`;
  if (counts.fail > 0 || counts.cancelled > 0) return { verdict: "FAIL", reason: detail };
  if (status === 0 && counts.tests === 0) {
    return { verdict: "PART", reason: detail, note: "reported zero tests; refusing a green run." };
  }
  if (status === 0 && counts.pass === 0) {
    return {
      verdict: "PART",
      reason: detail,
      note: "reported no passing tests; refusing a green run.",
    };
  }
  if (counts.skipped > skipCeiling) {
    return {
      verdict: "PART",
      reason: detail,
      note: `skipped ${counts.skipped} test(s), above its ${skipCeiling}-test ceiling.`,
    };
  }
  if (todoPin !== null && counts.todo !== todoPin) {
    return {
      verdict: "PART",
      reason: detail,
      note: `reported ${counts.todo} todo test(s), expected exactly ${todoPin}.`,
    };
  }
  if (counts.tests === 0) {
    return {
      verdict: "PART",
      reason: detail,
      note: "did not produce a complete failing test transcript.",
    };
  }
  return { verdict: "FAIL", reason: detail };
}

/**
 * A partial result wins: a failed result says a completed check disagreed,
 * while a partial one says the gate cannot claim it completed its required
 * work.
 *
 * @param {Verdict[]} verdicts
 * @returns {0 | 1 | 2}
 */
export function gateExitCode(verdicts) {
  if (verdicts.some((one) => one.verdict === "PART")) return 2;
  if (verdicts.some((one) => one.verdict === "FAIL")) return 1;
  return 0;
}

/**
 * The lines a reader needs from a lane that disagreed.
 *
 * @param {string} output
 * @returns {string}
 */
function diagnostics(output) {
  const named = output
    .split("\n")
    .filter((line) => /^not ok |^# (?:fail|cancelled) /.test(line) || /# SKIP\b/i.test(line));
  if (named.length > 0) return named.join("\n");
  return output.split("\n").slice(-50).join("\n");
}

/**
 * @param {string} verdict
 * @param {string} label
 * @param {string} reason
 * @returns {string}
 */
function row(verdict, label, reason) {
  return `  ${verdict.padEnd(4)}  ${label.padEnd(32)} ${reason}`;
}

/**
 * @param {string} script - the package script to run
 * @returns {{ status: number | null, output: string, launched: boolean }}
 */
function runLane(script) {
  const { command, commandArgs } = npmLauncher();
  const child = spawnSync(command, [...commandArgs, "run", script], {
    cwd: resolve(dirname(fileURLToPath(import.meta.url)), ".."),
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (child.error) return { status: null, output: "", launched: false };
  return {
    status: child.status,
    output: `${child.stdout ?? ""}${child.stderr ?? ""}`,
    launched: true,
  };
}

function main() {
  console.log("GATED - public JavaScript checks");
  console.log("");

  /** @type {Verdict[]} */
  const verdicts = [];
  /** @type {string[]} */
  const tally = [];

  /**
   * @param {string} script
   * @param {string} label
   * @param {number} [skipCeiling]
   * @param {number | null} [todoPin]
   */
  const stage = (script, label, skipCeiling, todoPin) => {
    const behavioral = skipCeiling !== undefined;
    console.log(`${label}: npm run ${script} from js`);
    const lane = runLane(script);
    if (!lane.launched) {
      console.log(`${label}: cannot run; node and npm are both required.`);
      const verdict = /** @type {Verdict} */ ({ verdict: "PART", reason: "no node or npm" });
      verdicts.push(verdict);
      tally.push(row("PART", label, "no node or npm"));
      console.log("");
      return;
    }

    if (!behavioral) {
      const verdict = staticDecision(lane.status);
      if (verdict.verdict !== "PASS") console.log(lane.output.split("\n").slice(-50).join("\n"));
      verdicts.push(verdict);
      tally.push(row(verdict.verdict, label, verdict.reason));
      console.log("");
      return;
    }

    const counts = tapCounts(lane.output);
    console.log(
      `${counts.tests} tests, ${counts.pass} passed, ${counts.fail} failed, ` +
        `${counts.cancelled} cancelled, ${counts.skipped} skipped, ${counts.todo} todo`,
    );
    const verdict = stageDecision(lane.status, counts, skipCeiling, todoPin ?? null);
    if (verdict.note) console.log(`${label} ${verdict.note}`);
    if (verdict.verdict !== "PASS") console.log(diagnostics(lane.output));
    verdicts.push(verdict);
    tally.push(row(verdict.verdict, label, verdict.reason));
    console.log("");
  };

  // These are repository and reference-implementation checks only. The public
  // reference selector excludes the explicit vector tier. Portable contracts
  // and repository tooling are deliberately absent even though `npm test`
  // includes them.
  stage("lint", "Lint");
  stage("format:check", "Formatting");
  stage("check:types", "Checked JavaScript slice");
  stage("check:boundaries", "JavaScript source boundaries", 0, 0);
  stage("test:reference:public", "JavaScript reference behavior", 1, 0);
  stage("test:experiments", "JavaScript experiment tier", 0, 8);

  console.log("TALLY");
  for (const line of tally) console.log(line);
  console.log("");

  const code = gateExitCode(verdicts);
  const partial = verdicts.filter((one) => one.verdict === "PART").length;
  const failed = verdicts.filter((one) => one.verdict === "FAIL").length;
  if (code === 2) {
    console.log(
      `RESULT: partial public-gate run. ${partial} required stage(s) could not run ` +
        "or verified less than intended.",
    );
  } else if (code === 1) {
    console.log(`RESULT: ${failed} required public-gate stage(s) failed.`);
  } else {
    console.log(
      "RESULT: lint, checked JavaScript, boundaries, vector-free reference behavior, " +
        "and experiments held.",
    );
  }
  process.exitCode = code;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
