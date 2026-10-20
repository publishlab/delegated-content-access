// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { gateExitCode, stageDecision, staticDecision, tapCounts } from "./run-gate.js";

/** @param {Partial<import('./run-gate.js').Counts>} counts */
function counts(counts) {
  return { tests: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0, todo: 0, ...counts };
}

test("a clean lane within its ceiling and on its pin holds", () => {
  const verdict = stageDecision(0, counts({ tests: 40, pass: 39, skipped: 1 }), 1, 0);
  assert.equal(verdict.verdict, "PASS");
  assert.equal(verdict.reason, "40 tests, 1 skipped, 0 todo");
});

test("a reported failure wins over a skip ceiling and a todo pin", () => {
  const verdict = stageDecision(
    1,
    counts({ tests: 40, pass: 30, fail: 2, skipped: 8, todo: 3 }),
    0,
    0,
  );
  assert.equal(verdict.verdict, "FAIL");
  assert.equal(verdict.reason, "40 tests, 2 failed, 0 cancelled");
});

test("a cancelled test is a failure, not a partial run", () => {
  const verdict = stageDecision(1, counts({ tests: 4, pass: 3, cancelled: 1 }), 0, 0);
  assert.equal(verdict.verdict, "FAIL");
});

test("a green run reporting zero tests is refused", () => {
  const verdict = stageDecision(0, counts({}), 0, 0);
  assert.equal(verdict.verdict, "PART");
  assert.equal(verdict.note, "reported zero tests; refusing a green run.");
});

test("a green run with no passing test is refused", () => {
  const verdict = stageDecision(0, counts({ tests: 3, skipped: 3 }), 3, 0);
  assert.equal(verdict.verdict, "PART");
  assert.equal(verdict.note, "reported no passing tests; refusing a green run.");
});

test("skips above the ceiling make the stage partial", () => {
  const verdict = stageDecision(0, counts({ tests: 10, pass: 8, skipped: 2 }), 1, 0);
  assert.equal(verdict.verdict, "PART");
  assert.equal(verdict.note, "skipped 2 test(s), above its 1-test ceiling.");
});

test("a todo count off its pin makes the stage partial", () => {
  const verdict = stageDecision(2, counts({ tests: 10, pass: 8, todo: 2 }), 0, 8);
  assert.equal(verdict.verdict, "PART");
  assert.equal(verdict.note, "reported 2 todo test(s), expected exactly 8.");
});

test("no pin accepts any todo count", () => {
  const verdict = stageDecision(0, counts({ tests: 10, pass: 8, todo: 2 }), 0, null);
  assert.equal(verdict.verdict, "PASS");
});

test("the static stage reads its exit status alone", () => {
  assert.equal(staticDecision(0).verdict, "PASS");
  assert.equal(staticDecision(0).reason, "held");
  assert.equal(staticDecision(1).verdict, "FAIL");
  assert.equal(staticDecision(1).reason, "exit 1");
});

test("a partial stage wins over a failed one in the gate exit code", () => {
  assert.equal(
    gateExitCode([
      { verdict: "PASS", reason: "held" },
      { verdict: "FAIL", reason: "exit 1" },
      { verdict: "PART", reason: "no node or npm" },
    ]),
    2,
  );
  assert.equal(
    gateExitCode([
      { verdict: "PASS", reason: "held" },
      { verdict: "FAIL", reason: "exit 1" },
    ]),
    1,
  );
  assert.equal(gateExitCode([{ verdict: "PASS", reason: "held" }]), 0);
});

test("TAP summary lines are summed across every lane in the output", () => {
  const summed = tapCounts(
    [
      "# tests 10",
      "# pass 9",
      "# fail 0",
      "# cancelled 0",
      "# skipped 1",
      "# todo 0",
      "ok 1 - unrelated # tests 99",
      "# tests 4",
      "# pass 4",
      "# fail 0",
      "# cancelled 0",
      "# skipped 0",
      "# todo 2",
    ].join("\n"),
  );
  assert.deepEqual(summed, { tests: 14, pass: 13, fail: 0, cancelled: 0, skipped: 1, todo: 2 });
});

test("partial and failing lanes print browser skip reasons without relaxing the ceiling", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-gate-diagnostics-"));
  try {
    const launcher = join(directory, "npm.cjs");
    // Substitute only the package launcher: exercise the real gate's output
    // and exit decision without running its lint, browser or test lanes.
    writeFileSync(
      launcher,
      `
      const script = process.argv[3];
      if (script === "test:reference:public") {
        console.log("ok 1 - ordinary case");
        console.log("ok 2 - browser oracle # SKIP Chromium unavailable: reference browser");
        console.log("    ok 3 - nested oracle # SKIP Chromium unavailable: nested browser");
        console.log("ok 4 - another oracle # SKIP Chromium unavailable: another browser");
        console.log("# tests 4\\n# pass 1\\n# fail 0\\n# cancelled 0\\n# skipped 3\\n# todo 0");
      } else if (script === "test:experiments") {
        console.log("ok 1 - comparison # SKIP Chromium unavailable: experiment browser");
        console.log("not ok 2 - comparison completeness");
        console.log("# tests 11\\n# pass 1\\n# fail 1\\n# cancelled 0\\n# skipped 1\\n# todo 8");
        process.exitCode = 1;
      } else {
        console.log("# tests 1\\n# pass 1\\n# fail 0\\n# cancelled 0\\n# skipped 0\\n# todo 0");
      }
    `,
    );
    const child = spawnSync(
      process.execPath,
      [fileURLToPath(new URL("./run-gate.js", import.meta.url))],
      {
        env: { ...process.env, npm_execpath: launcher },
        encoding: "utf8",
      },
    );
    assert.ifError(child.error);
    assert.equal(child.status, 2, child.stdout + child.stderr);
    assert.match(child.stdout, /skipped 3 test\(s\), above its 1-test ceiling/);
    assert.match(child.stdout, /# SKIP Chromium unavailable: reference browser/);
    assert.match(child.stdout, /# SKIP Chromium unavailable: nested browser/);
    assert.match(child.stdout, /# SKIP Chromium unavailable: experiment browser/);
    assert.match(child.stdout, /not ok 2 - comparison completeness/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
