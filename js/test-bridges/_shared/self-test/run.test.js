import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bridgeIds } from "../run-support.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const runner = join(root, "test-bridges/_shared/run.mjs");
const geometryTest = "test-reference/core-shared/geometry-bounds.test.js";

/** @param {string[]} arguments_ @param {Record<string, string>} env @param {string} [cwd] */
function run(arguments_, env, cwd = root) {
  const environment = { ...process.env, ...env };
  // A direct run leaves the reporter to Node, which picks spec on Node 24;
  // these checks read TAP totals, so the runner's child gets TAP.
  environment.NODE_OPTIONS = `${process.env.NODE_OPTIONS ?? ""} --test-reporter=tap`;
  delete environment.NODE_TEST_CONTEXT;
  for (const name of ["DCA_BRIDGE", "DCA_TARGET_ROOT", "DCA_BRIDGE_MODE", "INIT_CWD"])
    if (!(name in env)) delete environment[name];
  return spawnSync(process.execPath, [runner, ...arguments_], {
    cwd,
    env: environment,
    encoding: "utf8",
  });
}

test("the runner refuses without DCA_BRIDGE and names the choices", () => {
  const refused = run([geometryTest], {});
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /DCA_BRIDGE/);
  assert.match(refused.stderr, new RegExp(`bridge IDs: ${bridgeIds().join(", ")}`));
  assert.match(refused.stderr, /a path to a bridge\.mjs/);
  assert.doesNotMatch(refused.stdout, /^# pass/m);
  assert.ok(bridgeIds().includes("js-loopback"));
});

test("a relative DCA_BRIDGE resolves from the caller's directory in INIT_CWD", () => {
  const elsewhere = mkdtempSync(join(tmpdir(), "dca-runner-cwd-"));
  try {
    const passed = run(
      [geometryTest],
      {
        DCA_BRIDGE: "test-bridges/js-loopback/bridge.mjs",
        DCA_BRIDGE_MODE: "strict",
        INIT_CWD: root,
      },
      elsewhere,
    );
    assert.equal(passed.status, 0, passed.stderr);
    assert.match(passed.stdout, /^# pass [1-9]\d*$/m);
  } finally {
    rmSync(elsewhere, { recursive: true, force: true });
  }
});

test("a relative DCA_TARGET_ROOT resolves from the caller's directory in INIT_CWD", () => {
  // The caller stands in a directory holding target/, a copy of the geometry
  // module. A strict run fails unless the adapter finds it there.
  const caller = mkdtempSync(join(tmpdir(), "dca-runner-caller-"));
  const geometry = join(caller, "target/core-shared/geometryBounds.js");
  mkdirSync(dirname(geometry), { recursive: true });
  copyFileSync(join(root, "core-shared/geometryBounds.js"), geometry);
  try {
    const passed = run([geometryTest], {
      DCA_BRIDGE: "js",
      DCA_TARGET_ROOT: "target",
      DCA_BRIDGE_MODE: "strict",
      INIT_CWD: caller,
    });
    assert.equal(passed.status, 0, `${passed.stdout}${passed.stderr}`);
    assert.match(passed.stdout, /^# pass [1-9]\d*$/m);
  } finally {
    rmSync(caller, { recursive: true, force: true });
  }
});

test("DCA_BRIDGE_MODE=reference refuses as an unknown mode", () => {
  const refused = run([geometryTest], { DCA_BRIDGE: "js-loopback", DCA_BRIDGE_MODE: "reference" });
  assert.notEqual(refused.status, 0);
  assert.match(
    refused.stderr,
    /DCA_BRIDGE_MODE "reference" is unknown; modes are overlay and strict/,
  );
  assert.doesNotMatch(refused.stdout, /^# pass/m);
});

test("a direct bridge preload refuses DCA_BRIDGE_MODE=reference", () => {
  const environment = { ...process.env, DCA_BRIDGE_MODE: "reference" };
  delete environment.NODE_TEST_CONTEXT;
  const refused = spawnSync(
    process.execPath,
    ["--import", join(root, "test-bridges/js-loopback/bridge.mjs"), "--test", geometryTest],
    { cwd: root, env: environment, encoding: "utf8" },
  );
  assert.notEqual(refused.status, 0);
  assert.match(
    `${refused.stdout}${refused.stderr}`,
    /DCA_BRIDGE_MODE "reference" is unknown; modes are overlay and strict/,
  );
});
