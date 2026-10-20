import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const runner = join(root, "test-bridges/_shared/run.mjs");
const FILE = "test-reference/core-shared/binary-strings.test.js";
const EXCLUDED = "a character outside the alphabet is refused, padding and standard base64 with it";

/**
 * Runs the runner over js-loopback, strict, with the given exclusion list.
 *
 * @param {string[]} arguments_ @param {unknown} [list]
 */
function run(arguments_, list) {
  const directory = mkdtempSync(join(tmpdir(), "dca-exclusions-"));
  const environment = { ...process.env, DCA_BRIDGE: "js-loopback", DCA_BRIDGE_MODE: "strict" };
  // A direct run leaves the reporter to Node, which picks spec on Node 24;
  // these checks read TAP totals, so the runner's child gets TAP.
  environment.NODE_OPTIONS = `${process.env.NODE_OPTIONS ?? ""} --test-reporter=tap`;
  delete environment.NODE_TEST_CONTEXT;
  delete environment.DCA_TARGET_ROOT;
  delete environment.DCA_LOG_DIR;
  delete environment.DCA_BRIDGE_EXCLUSIONS;
  if (list !== undefined) {
    const path = join(directory, "exclusions.json");
    writeFileSync(path, JSON.stringify(list));
    environment.DCA_BRIDGE_EXCLUSIONS = path;
  }
  try {
    return spawnSync(process.execPath, [runner, ...arguments_], {
      cwd: root,
      env: environment,
      encoding: "utf8",
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("a direct run skips each named exclusion of its file and names it with its reason", () => {
  const whole = run([FILE]);
  assert.equal(whole.status, 0, whole.stderr);
  const wholePassed = Number(/^# pass (\d+)$/m.exec(whole.stdout)?.[1]);
  assert.ok(whole.stdout.includes(EXCLUDED));

  const excluded = run([FILE], {
    version: 1,
    exclusions: [
      { file: FILE, name: EXCLUDED, reason: "the example reason" },
      { file: "test-reference/core-shared/codec.test.js", name: "another", reason: "elsewhere" },
    ],
  });
  assert.equal(excluded.status, 0, excluded.stderr);
  assert.match(excluded.stdout, new RegExp(`^# pass ${wholePassed - 1}$`, "m"));
  assert.ok(!excluded.stdout.includes(EXCLUDED));
  assert.ok(
    excluded.stderr.includes(
      `dca bridge runner: excluded 1 named case of ${FILE}: "${EXCLUDED}" (the example reason)`,
    ),
    excluded.stderr,
  );
  assert.ok(!excluded.stderr.includes("another"));
});

test("named exclusions are refused for a portable selection and for the public run", () => {
  const list = {
    version: 1,
    exclusions: [{ file: FILE, name: EXCLUDED, reason: "the example reason" }],
  };
  for (const selector of ["portable-core", "public"]) {
    const refused = run([selector], list);
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, /DCA_BRIDGE_EXCLUSIONS applies to a direct run of one test file/);
    assert.doesNotMatch(refused.stdout, /^# pass/m);
  }
});

test("a named exclusion must name exactly one case of its file before anything runs", () => {
  const refused = run([FILE], {
    version: 1,
    exclusions: [{ file: FILE, name: "a case this file does not declare", reason: "a typo" }],
  });
  assert.notEqual(refused.status, 0);
  assert.match(
    refused.stderr,
    /DCA_BRIDGE_EXCLUSIONS names "a case this file does not declare", which test-reference\/core-shared\/binary-strings\.test\.js declares 0 times/,
  );
  assert.doesNotMatch(refused.stdout, /^# pass/m);
});
