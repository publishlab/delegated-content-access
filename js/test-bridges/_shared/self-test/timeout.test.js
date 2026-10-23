import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { defineBridge } from "../bridge-definition.mjs";
import { ProcessBinding } from "../register.mjs";

const protocol = new URL("../protocol.mjs", import.meta.url).href;

/** @param {number} pid */
function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Writes an adapter that answers describe, then never answers a call.
 *
 * @param {string} directory
 */
function hangingAdapter(directory) {
  const pidFile = join(directory, "pid");
  const script = join(directory, "adapter.mjs");
  writeFileSync(
    script,
    `import { writeFileSync } from "node:fs";
import { FrameDecoder, encodeFrame } from ${JSON.stringify(protocol)};
writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
const decoder = new FrameDecoder();
process.stdin.on("data", (chunk) => {
  for (const request of decoder.push(chunk))
    if (request.type === "describe")
      process.stdout.write(encodeFrame({ version: 1, id: request.id, type: "response",
        result: { kind: "observation", value: { capabilities: { valueTypes: ["list", "number"], moduleDiscovery: true } } } }));
});
`,
  );
  return { pidFile, script };
}

test("a timed-out call kills the adapter and marks the binding broken", async () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-hanging-adapter-"));
  const { pidFile, script } = hangingAdapter(directory);
  const binding = new ProcessBinding(
    defineBridge({ id: "hanging", command: process.execPath, arguments: [script] }),
    { debug: process.env.DCA_DEBUG === "1" },
  );
  try {
    // Startup keeps the default timeout, so a loaded machine cannot fail it.
    await binding.start();
    binding.timeout = 300;
    binding.operations.set("op-1", { id: "op-1", sourceExport: "stuck", callShape: "sync" });
    assert.throws(() => binding.call("op-1", [1]), /timeout/);
    const started = performance.now();
    assert.throws(() => binding.call("op-1", [1]), /broken/);
    assert.ok(performance.now() - started < 300, "a broken binding does not wait again");
    const pid = Number(readFileSync(pidFile, "utf8"));
    for (let attempt = 0; attempt < 50 && alive(pid); attempt += 1) await delay(20);
    assert.equal(alive(pid), false, "the adapter child was killed");
  } finally {
    await binding.dispose();
    rmSync(directory, { recursive: true, force: true });
  }
});

// Only the driver's clock may end a call. A second clock in the worker that
// fires first hands the driver an ordinary `timeout` answer: the binding stays
// usable, the adapter lives, and the next call dispatches and times out again.
// Raising the driver's wait after start exposes such a clock every time.
test("a call ends only on the driver's clock, and its timeout always breaks the binding", async () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-hanging-adapter-"));
  const { pidFile, script } = hangingAdapter(directory);
  const binding = new ProcessBinding(
    defineBridge({ id: "hanging", command: process.execPath, arguments: [script] }),
    { timeout: 10_000 },
  );
  try {
    await binding.start();
    // The startup budget also tolerates a loaded integration runner. Raising
    // the call budget still exposes any stale worker-side startup clock.
    binding.timeout = 11_500;
    binding.operations.set("op-1", { id: "op-1", sourceExport: "stuck", callShape: "sync" });
    const started = performance.now();
    assert.throws(() => binding.call("op-1", [1]), /timeout/);
    assert.ok(performance.now() - started >= 11_400, "the driver's wait decided the timeout");
    assert.throws(() => binding.call("op-1", [1]), /broken/);
    const pid = Number(readFileSync(pidFile, "utf8"));
    for (let attempt = 0; attempt < 50 && alive(pid); attempt += 1) await delay(20);
    assert.equal(alive(pid), false, "the adapter child was killed");
  } finally {
    await binding.dispose();
    rmSync(directory, { recursive: true, force: true });
  }
});
