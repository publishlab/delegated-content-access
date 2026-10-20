import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("portable selection registers all by default and only selected tests", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-portable-test-"));
  const fixture = join(directory, "fixture.test.mjs");
  const helper = new URL("../test-reference/support/portable-test.js", import.meta.url).href;
  writeFileSync(
    fixture,
    `import { test, portableTest } from ${JSON.stringify(helper)};\n` +
      `test("ordinary", () => {});\n` +
      `portableTest("portable-core")("portable", () => {});\n`,
  );
  try {
    const run = (value) => {
      const env = { ...process.env, DCA_TEST_SELECTION: value };
      delete env.NODE_TEST_CONTEXT;
      return spawnSync(process.execPath, ["--test", "--test-reporter=tap", fixture], {
        encoding: "utf8",
        env,
      });
    };
    const ordinary = run(undefined);
    const selected = run("portable-core");
    assert.equal(ordinary.status, 0);
    assert.match(ordinary.stdout + ordinary.stderr, /# tests 2/);
    assert.equal(selected.status, 0);
    assert.match(selected.stdout + selected.stderr, /# tests 1/);
    assert.match(selected.stdout, /# pass 1/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("portable selection validates names", async () => {
  const { portableTest } = await import("../test-reference/support/portable-test.js");
  assert.throws(() => portableTest(""), TypeError);
});
