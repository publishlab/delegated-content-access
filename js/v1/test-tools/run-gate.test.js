// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

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
