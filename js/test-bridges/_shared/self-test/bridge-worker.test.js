import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { defineBridge } from "../bridge-definition.mjs";
import { ProcessBinding } from "../register.mjs";

const protocol = new URL("../protocol.mjs", import.meta.url).href;
const ROOT_VARIABLE = "DCA_TARGET_ROOT";

/**
 * Writes an adapter that reports its working directory and the root variable
 * it received in the `describe` identity, then starts it with `settings`.
 *
 * @param {{ adapterCwd?: string, targetRoot?: string }} settings
 */
async function probe(settings) {
  const directory = mkdtempSync(join(tmpdir(), "dca-probe-adapter-"));
  const script = join(directory, "adapter.mjs");
  writeFileSync(
    script,
    `import { FrameDecoder, encodeFrame } from ${JSON.stringify(protocol)};
const decoder = new FrameDecoder();
const root = process.env[${JSON.stringify(ROOT_VARIABLE)}];
process.stdin.on("data", (chunk) => {
  for (const request of decoder.push(chunk))
    process.stdout.write(encodeFrame({ version: 1, id: request.id, type: "response",
      result: { kind: "observation", value: request.type === "describe" ? {
        identity: { cwd: process.cwd(), root: root === undefined ? "(absent)" : root },
        capabilities: { valueTypes: [], moduleDiscovery: true },
      } : null } }));
});
`,
  );
  const binding = new ProcessBinding(
    defineBridge({ id: "probe", command: process.execPath, arguments: [script], ...settings }),
  );
  try {
    await binding.start();
    return /** @type {{ identity: { cwd: string, root: string } }} */ (binding.description)
      .identity;
  } finally {
    await binding.dispose();
    rmSync(directory, { recursive: true, force: true });
  }
}

/** @param {string | undefined} value @param {() => Promise<void>} body */
async function withCallerRoot(value, body) {
  const saved = process.env[ROOT_VARIABLE];
  if (value === undefined) delete process.env[ROOT_VARIABLE];
  else process.env[ROOT_VARIABLE] = value;
  try {
    await body();
  } finally {
    if (saved === undefined) delete process.env[ROOT_VARIABLE];
    else process.env[ROOT_VARIABLE] = saved;
  }
}

test("the child starts in adapterCwd and receives targetRoot, each on its own", async () => {
  const adapterCwd = realpathSync(mkdtempSync(join(tmpdir(), "dca-adapter-cwd-")));
  const targetRoot = realpathSync(mkdtempSync(join(tmpdir(), "dca-target-root-")));
  try {
    await withCallerRoot(undefined, async () => {
      assert.deepEqual(await probe({ adapterCwd, targetRoot }), {
        cwd: adapterCwd,
        root: targetRoot,
      });
      assert.deepEqual(await probe({ adapterCwd }), { cwd: adapterCwd, root: "(absent)" });
      assert.deepEqual(await probe({ targetRoot }), { cwd: process.cwd(), root: targetRoot });
    });
  } finally {
    rmSync(adapterCwd, { recursive: true, force: true });
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("a root the caller's shell set does not reach a child with no targetRoot", async () => {
  const adapterCwd = realpathSync(mkdtempSync(join(tmpdir(), "dca-adapter-cwd-")));
  const targetRoot = realpathSync(mkdtempSync(join(tmpdir(), "dca-target-root-")));
  try {
    await withCallerRoot("/inherited/from/the/shell", async () => {
      assert.deepEqual(await probe({ adapterCwd }), { cwd: adapterCwd, root: "(absent)" });
      assert.deepEqual(await probe({ adapterCwd, targetRoot }), {
        cwd: adapterCwd,
        root: targetRoot,
      });
    });
  } finally {
    rmSync(adapterCwd, { recursive: true, force: true });
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

for (const [obsolete, replacement] of [
  ["DCA_PORT_ROOT", "DCA_TARGET_ROOT"],
  ["DCA_PORT_NAMESPACE", "DCA_TARGET_NAMESPACE"],
]) {
  test(`${obsolete} refuses before the adapter starts`, async () => {
    const directory = mkdtempSync(join(tmpdir(), "dca-obsolete-variable-"));
    const marker = join(directory, "started");
    const script = join(directory, "adapter.mjs");
    writeFileSync(
      script,
      `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(marker)}, "");\n`,
    );
    const saved = process.env[obsolete];
    process.env[obsolete] = directory;
    const binding = new ProcessBinding(
      defineBridge({ id: "obsolete", command: process.execPath, arguments: [script] }),
      { timeout: 1000 },
    );
    try {
      await assert.rejects(binding.start(), {
        message: `${obsolete} is obsolete; use ${replacement}`,
      });
      assert.equal(existsSync(marker), false, "the adapter never started");
    } finally {
      if (saved === undefined) delete process.env[obsolete];
      else process.env[obsolete] = saved;
      await binding.dispose();
      rmSync(directory, { recursive: true, force: true });
    }
  });
}

test("an adapter that exits before answering names its exit code and stderr in the failure", async () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-refusing-adapter-"));
  const script = join(directory, "adapter.mjs");
  // An early line past the 4 KiB tail must drop out; the last line stays.
  writeFileSync(
    script,
    `process.stderr.write("early line that scrolls out of the tail\\n" + "x".repeat(8192) + "\\n");
process.stderr.write("adapter refuses: DCA_EXAMPLE_SETTING is malformed\\n");
process.exitCode = 3;
`,
  );
  const binding = new ProcessBinding(
    defineBridge({ id: "refusing", command: process.execPath, arguments: [script] }),
    { timeout: 5000 },
  );
  try {
    const failure = await binding.start().then(
      () => assert.fail("the adapter answered describe"),
      (/** @type {Error} */ error) => error.message,
    );
    assert.match(failure, /^bridge describe failed: child_exit/);
    assert.match(failure, /exit code 3/);
    assert.match(failure, /adapter refuses: DCA_EXAMPLE_SETTING is malformed/);
    assert.doesNotMatch(failure, /early line/);
    assert.ok(failure.length < 4096 + 200, "the failure holds only the stderr tail");
  } finally {
    await binding.dispose();
    rmSync(directory, { recursive: true, force: true });
  }
});

/** @param {number} pid */
function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** @param {number} pid */
async function gone(pid) {
  for (let attempt = 0; attempt < 100 && alive(pid); attempt += 1) await delay(20);
  return !alive(pid);
}

/**
 * Writes an adapter that records its pid, answers describe, runs `onCall`
 * with `request` and `respond(value)` in scope for each call, and answers
 * dispose. With `lingers`, it ignores the end of stdin and stays alive until
 * it is killed.
 *
 * @param {string} directory @param {{ onCall?: string, lingers?: boolean }} [options]
 */
function scriptedAdapter(directory, options = {}) {
  const pidFile = join(directory, "pid");
  const script = join(directory, "adapter.mjs");
  writeFileSync(
    script,
    `import { writeFileSync } from "node:fs";
import { FrameDecoder, encodeFrame } from ${JSON.stringify(protocol)};
writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
${options.lingers ? 'setInterval(() => {}, 60_000);\nprocess.on("SIGTERM", () => {});' : ""}
const decoder = new FrameDecoder();
const answer = (request, value) => process.stdout.write(encodeFrame({ version: 1, id: request.id,
  type: "response", result: { kind: "observation", value } }));
process.stdin.on("data", (chunk) => {
  for (const request of decoder.push(chunk)) {
    if (request.type === "describe")
      answer(request, { capabilities: { valueTypes: ["list", "number", "string"], moduleDiscovery: true } });
    else if (request.type === "call") {
      const respond = (value) => answer(request, value);
      ${options.onCall ?? "respond(null);"}
    } else answer(request, null);
  }
});
`,
  );
  return { script, pid: () => Number(readFileSync(pidFile, "utf8")) };
}

/**
 * Starts a binding over a scripted adapter, runs `body`, then disposes it.
 *
 * @param {{ onCall?: string, lingers?: boolean, maximum?: number }} options
 * @param {(binding: ProcessBinding, pid: number) => Promise<void>} body
 */
async function withAdapter(options, body) {
  const directory = mkdtempSync(join(tmpdir(), "dca-scripted-adapter-"));
  const adapter = scriptedAdapter(directory, options);
  const binding = new ProcessBinding(
    defineBridge({ id: "scripted", command: process.execPath, arguments: [adapter.script] }),
    { timeout: 5000, ...(options.maximum === undefined ? {} : { maximum: options.maximum }) },
  );
  try {
    await binding.start();
    binding.operations.set("op-1", { id: "op-1", sourceExport: "op", callShape: "sync" });
    await body(binding, adapter.pid());
  } finally {
    await binding.dispose();
    rmSync(directory, { recursive: true, force: true });
  }
}

/** @param {() => unknown} action */
function failureOf(action) {
  const started = performance.now();
  try {
    action();
  } catch (error) {
    return { message: /** @type {Error} */ (error).message, elapsed: performance.now() - started };
  }
  return assert.fail("the call did not fail");
}

for (const [name, onCall, exit] of [
  ["exits", 'process.stderr.write("dying on call\\n"); process.exit(7);', /\(exit code 7\)/],
  [
    "is killed",
    'process.stderr.write("dying on call\\n"); process.kill(process.pid, "SIGKILL");',
    /\(signal SIGKILL\)/,
  ],
]) {
  test(`a child that ${name} mid-call fails that call and every later one, without a hang`, async () => {
    await withAdapter({ onCall }, async (binding, pid) => {
      const pending = failureOf(() => binding.call("op-1", [1]));
      assert.match(pending.message, /^bridge infrastructure failure: child_exit/);
      assert.match(pending.message, exit);
      assert.match(pending.message, /dying on call/);
      assert.ok(pending.elapsed < 4000, "the exit ended the call, not the timeout");
      const later = failureOf(() => binding.call("op-1", [1]));
      assert.match(later.message, /broken/);
      assert.match(later.message, exit);
      assert.ok(later.elapsed < 100, "a later call fails without dispatch");
      assert.equal(await gone(pid), true);
    });
  });
}

test("a response larger than the payload fails that call, breaks the binding and kills the child", async () => {
  await withAdapter(
    { maximum: 4096, onCall: 'respond("x".repeat(10_000));' },
    async (binding, pid) => {
      const oversized = failureOf(() => binding.call("op-1", [1]));
      assert.match(oversized.message, /^bridge infrastructure failure: response_too_large/);
      assert.match(oversized.message, /exceeds 4096 bytes/);
      assert.ok(oversized.elapsed < 4000, "the size ended the call, not the timeout");
      const later = failureOf(() => binding.call("op-1", [1]));
      assert.match(later.message, /broken/);
      assert.ok(later.elapsed < 100, "a later call fails without dispatch");
      assert.equal(await gone(pid), true, "the adapter child was killed");
    },
  );
});

test("dispose kills and reaps a child that outlives its acknowledgement", async () => {
  let childPid = 0;
  await withAdapter({ lingers: true }, async (binding, pid) => {
    childPid = pid;
    assert.equal(binding.call("op-1", [1]), null);
  });
  assert.equal(alive(childPid), false, "no child, and no zombie, once dispose resolves");
});

test("dispose after a broken binding is safe and idempotent", async () => {
  await withAdapter({ onCall: "process.exit(7);" }, async (binding, pid) => {
    assert.throws(() => binding.call("op-1", [1]), /child_exit/);
    await binding.dispose();
    await binding.dispose();
    assert.equal(alive(pid), false);
  });
  await withAdapter(
    { maximum: 4096, onCall: 'respond("x".repeat(10_000));', lingers: true },
    async (binding, pid) => {
      assert.throws(() => binding.call("op-1", [1]), /response_too_large/);
      await binding.dispose();
      await binding.dispose();
      assert.equal(alive(pid), false);
    },
  );
});

for (const disposes of [true, false]) {
  test(`the test process exits when its tests end${disposes ? "" : " without dispose"}, and the adapter with it`, async () => {
    const directory = mkdtempSync(join(tmpdir(), "dca-exiting-driver-"));
    try {
      const adapter = scriptedAdapter(directory, { lingers: true });
      const driver = join(directory, "driver.mjs");
      writeFileSync(
        driver,
        `import { defineBridge } from ${JSON.stringify(new URL("../bridge-definition.mjs", import.meta.url).href)};
import { ProcessBinding } from ${JSON.stringify(new URL("../register.mjs", import.meta.url).href)};
const binding = new ProcessBinding(defineBridge({ id: "exiting", command: process.execPath,
  arguments: [${JSON.stringify(adapter.script)}] }), { timeout: 5000 });
await binding.start();
binding.operations.set("op-1", { id: "op-1", sourceExport: "op", callShape: "sync" });
binding.call("op-1", [1]);
${disposes ? "await binding.dispose();" : ""}
`,
      );
      const child = spawn(process.execPath, [driver], { stdio: "ignore" });
      const status = await Promise.race([
        new Promise((resolve) => child.once("exit", resolve)),
        delay(10_000).then(() => "still running"),
      ]);
      if (status === "still running") child.kill("SIGKILL");
      assert.equal(status, 0, "the driver process exited by itself");
      assert.equal(await gone(adapter.pid()), true, "the adapter did not outlive the test process");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
