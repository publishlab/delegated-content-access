import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  booleanEnvironment,
  bridgeEnvironment,
  createRunDirectory,
  refuseObsoleteVariables,
  writeRunRecord,
} from "../environment.mjs";

test("bridge boolean environment values are explicit", () => {
  assert.equal(booleanEnvironment("DCA_DEBUG", undefined), false);
  assert.equal(booleanEnvironment("DCA_DEBUG", "0"), false);
  assert.equal(booleanEnvironment("DCA_DEBUG", "1"), true);
  assert.throws(() => booleanEnvironment("DCA_DEBUG", "yes"), /unset, 0, or 1/);
});

test("a requested log parent gives each run and worker distinct files", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-bridge-"));
  try {
    const firstRun = createRunDirectory({
      bridgeId: "js",
      parent: directory,
      pid: 41,
      now: new Date("2026-09-22T14:30:12Z"),
    });
    writeRunRecord(firstRun, {});
    const first = bridgeEnvironment({
      bridgeId: "js",
      environment: { DCA_LOG_DIR: firstRun, DCA_TIMING: "1" },
      pid: 41,
    });
    const second = bridgeEnvironment({
      bridgeId: "js",
      environment: { DCA_LOG_DIR: firstRun, DCA_TIMING: "1" },
      pid: 41,
    });
    const secondRun = createRunDirectory({
      bridgeId: "plain",
      parent: directory,
      pid: 41,
      now: new Date("2026-09-22T14:30:12Z"),
    });
    assert.equal(existsSync(directory), true);
    assert.match(firstRun, /run--20260922T143012Z--js--41$/);
    assert.notEqual(firstRun, secondRun);
    assert.equal(first.runDirectory, firstRun);
    assert.notEqual(first.transcriptPath, second.transcriptPath);
    assert.notEqual(first.timingPath, second.timingPath);
    assert.match(first.transcriptPath, /js-41-.*\.transcript\.jsonl$/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("unset logging creates no directory", () => {
  assert.deepEqual(bridgeEnvironment({ bridgeId: "js", environment: {}, pid: 41 }), {
    debug: false,
    timing: false,
  });
});

test("an obsolete root or namespace variable refuses and names its replacement", () => {
  assert.throws(
    () => refuseObsoleteVariables({ DCA_PORT_ROOT: "/target" }),
    /^Error: DCA_PORT_ROOT is obsolete; use DCA_TARGET_ROOT$/,
  );
  assert.throws(
    () => refuseObsoleteVariables({ DCA_PORT_NAMESPACE: "Fixture" }),
    /^Error: DCA_PORT_NAMESPACE is obsolete; use DCA_TARGET_NAMESPACE$/,
  );
  assert.throws(() => refuseObsoleteVariables({ DCA_PORT_ROOT: "" }), /use DCA_TARGET_ROOT/);
  refuseObsoleteVariables({ DCA_TARGET_ROOT: "/target", DCA_TARGET_NAMESPACE: "Fixture" });
});
