// What this test proves about the promise shape of a crossed export.
//
// The reference `core-shared/aead.js` declares `encrypt` async, so a test
// expects a promise from it: `assert.rejects(() => encrypt(...))` fails on a
// synchronous throw. This test target answers the same export with a
// synchronous function, as a PHP port does. The proxy keeps the reference
// export's promise shape: the target's answer resolves the promise and the
// target's refusal rejects it, with the target's own code and message. A
// bridge failure before dispatch still throws at once, so it cannot pass for a
// target rejection.

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const jsBridge = join(root, "test-bridges/js/bridge.mjs");

/** @param {string} path */
const moduleUrl = (path) => JSON.stringify(pathToFileURL(join(root, path)).href);

// A synchronous stand-in for the async reference export. It refuses a key
// that is not 16 bytes with its own message, and otherwise answers bytes the
// probe can recognize.
const TARGET_AEAD = `import { DcaError } from "./errors.js";
export function encrypt(key) {
  if (key.length !== 16) throw new DcaError("bad_key", "target refuses a " + key.length + "-byte key");
  return new Uint8Array([7, key.length]);
}
`;

const PROBE = `import test from "node:test";
import assert from "node:assert/strict";
import { encrypt } from ${moduleUrl("core-shared/aead.js")};
import { DcaError } from ${moduleUrl("core-shared/errors.js")};
const nonce = new Uint8Array(12);
const plaintext = new Uint8Array([1]);
test("probe", async () => {
  const answered = encrypt(new Uint8Array(16), nonce, plaintext);
  assert.ok(answered instanceof Promise, "an answer comes back as a promise");
  assert.deepEqual(await answered, new Uint8Array([7, 16]));

  const refused = encrypt(new Uint8Array(32), nonce, plaintext);
  assert.ok(refused instanceof Promise, "a refusal comes back as a rejected promise");
  await assert.rejects(
    refused,
    (error) =>
      error instanceof DcaError &&
      error.code === "bad_key" &&
      error.message === "target refuses a 32-byte key",
  );

  // A value no bridge value carries fails before dispatch, synchronously.
  assert.throws(() => encrypt(() => {}, nonce, plaintext));
});
`;

test("a synchronous target answer keeps the reference export's promise shape", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-promise-shape-"));
  const target = join(directory, "target");
  const probe = join(directory, "probe.test.js");
  mkdirSync(join(target, "core-shared"), { recursive: true });
  copyFileSync(join(root, "core-shared/errors.js"), join(target, "core-shared/errors.js"));
  writeFileSync(join(target, "core-shared/aead.js"), TARGET_AEAD);
  writeFileSync(probe, PROBE);
  try {
    const environment = {
      ...process.env,
      DCA_BRIDGE_MODE: "strict",
      DCA_TARGET_ROOT: target,
    };
    delete environment.NODE_TEST_CONTEXT;
    delete environment.DCA_LOG_DIR;
    delete environment.DCA_TEST_SELECTION;
    delete environment.DCA_BRIDGE_MODULES;
    const run = spawnSync(
      process.execPath,
      ["--import", jsBridge, "--test", "--test-reporter=tap", probe],
      {
        cwd: root,
        env: environment,
        encoding: "utf8",
      },
    );
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.match(run.stdout, /^# pass 1$/m);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
