import { spawn } from "node:child_process";
import { parentPort, workerData } from "node:worker_threads";

import { FrameDecoder, encodeFrame } from "./protocol.mjs";

const decoder = new FrameDecoder();
if (!parentPort) throw new Error("bridge worker needs a parent port");
const port = parentPort;
/** @type {Map<string, (result: unknown) => void>} */
const pending = new Map();
let sequence = 0;
// The last 4 KiB of the child's stderr. An adapter that refuses at startup
// says why there, and the failure the driver reports carries it.
const STDERR_TAIL_BYTES = 4096;
let stderrTail = Buffer.alloc(0);
/** @type {Record<string, unknown> | undefined} Set once the child can answer nothing more. */
let ended;
const adapterArguments =
  workerData.adapter === undefined
    ? [...workerData.arguments]
    : [...workerData.arguments, workerData.adapter];
// The child gets the target root only from its bridge definition. A root the
// caller's shell exported must not reach an adapter that was given none.
const childEnvironment = { ...process.env };
delete childEnvironment.DCA_TARGET_ROOT;
if (workerData.targetRoot !== undefined) childEnvironment.DCA_TARGET_ROOT = workerData.targetRoot;
const child = spawn(workerData.command, adapterArguments, {
  cwd: workerData.adapterCwd,
  env: childEnvironment,
  stdio: ["pipe", "pipe", "pipe"],
});

child.stdout.on("data", (chunk) => {
  if (ended) return;
  try {
    for (const response of decoder.push(chunk, workerData.maximum)) {
      const waiting = pending.get(response.id);
      if (waiting) {
        pending.delete(response.id);
        waiting(response);
      }
    }
  } catch (error) {
    // The stream has lost its frame boundaries, so nothing after this can be
    // read: fail every call and stop the child.
    end({
      infrastructure: error instanceof RangeError ? "response_too_large" : "malformed_response",
      message: errorMessage(error),
    });
    child.kill("SIGKILL");
  }
});
child.stderr.on("data", (chunk) => {
  const joined = Buffer.concat([stderrTail, chunk]);
  stderrTail = Buffer.from(joined.subarray(Math.max(0, joined.byteLength - STDERR_TAIL_BYTES)));
  port.postMessage({ type: "diagnostic", text: String(chunk) });
});
// A write to a child that has exited fails here; `close` reports the exit.
child.stdin.on("error", () => {});
child.on("error", (error) =>
  end({ infrastructure: "child_error", message: errorMessage(error), ...stderrText() }),
);
// `close` follows `exit` once stdout and stderr have drained, so the tail is
// complete.
child.on("close", (code, signal) =>
  end({ infrastructure: "child_exit", code, signal, ...stderrText() }),
);
// `exit` means the child is reaped, so its pid no longer names it.
child.on("exit", () => port.postMessage({ type: "exited" }));
port.postMessage({ type: "ready", pid: child.pid });

/** @param {unknown} error */
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function stderrText() {
  return stderrTail.byteLength === 0 ? {} : { stderr: stderrTail.toString("utf8") };
}

/** @param {Record<string, unknown>} failure */
function end(failure) {
  ended ??= failure;
  failAll(ended);
}

/** @param {unknown} result */
function failAll(result) {
  for (const resolve of pending.values()) resolve(result);
  pending.clear();
}

/**
 * Writes the first of these that fits the payload: the result itself, a
 * failure without its stderr tail, or `response_too_large`. `-1` says none
 * fits.
 *
 * @param {unknown} result @param {SharedArrayBuffer} control @param {SharedArrayBuffer} payload
 */
function signal(result, control, payload) {
  const destination = new Uint8Array(payload);
  const state = new Int32Array(control);
  const encoded = JSON.stringify(result);
  /** @type {unknown[]} */
  const candidates = [result];
  if (result && typeof result === "object" && "stderr" in result) {
    candidates.push({ ...result, stderr: undefined });
  }
  candidates.push({
    infrastructure: "response_too_large",
    message: `bridge result of ${encoded.length} characters exceeds the ${destination.byteLength}-byte payload`,
  });
  let size = -1;
  for (const candidate of candidates) {
    const bytes = new TextEncoder().encode(JSON.stringify(candidate));
    if (bytes.byteLength <= destination.byteLength) {
      destination.set(bytes);
      size = bytes.byteLength;
      break;
    }
  }
  Atomics.store(state, 1, size);
  Atomics.store(state, 0, 1);
  Atomics.notify(state, 0);
}

// Stops the child and says `closed` once it is reaped. The adapter should
// already be exiting after its dispose acknowledgement; SIGKILL follows a
// grace period.
function close() {
  const finish = () => {
    port.postMessage({ type: "closed" });
    port.close();
  };
  if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) {
    finish();
    return;
  }
  child.once("exit", finish);
  child.kill("SIGTERM");
  setTimeout(() => child.kill("SIGKILL"), 500).unref();
}

/**
 * The export names of a reference module and whether each is a function, a
 * class or any other value, read from the module this worker imports. The
 * worker has no bridge hooks, so the import is the plain reference module.
 *
 * @param {string} url
 */
async function referenceExports(url) {
  try {
    const namespace = await import(url);
    return {
      exports: Object.entries(namespace).map(([name, value]) => [name, exportKind(value)]),
    };
  } catch (error) {
    return { error: errorMessage(error) };
  }
}

/**
 * A class keeps a `prototype` it cannot overwrite; an ordinary or generator
 * function's `prototype` is writable, and an arrow or async function has none.
 *
 * @param {unknown} value
 */
function exportKind(value) {
  if (typeof value !== "function") return "value";
  return Object.getOwnPropertyDescriptor(value, "prototype")?.writable === false
    ? "class"
    : "function";
}

/**
 * @param {Record<string, unknown>} request
 * @returns {Promise<unknown>}
 */
function requestAdapter(request) {
  if (ended) return Promise.resolve(ended);
  const id = `${process.pid}-${++sequence}`;
  // The driver's wait is the only clock. When it gives up it marks the
  // binding broken and sends `kill`; the child's exit then settles this call.
  return new Promise((resolve) => {
    pending.set(id, resolve);
    child.stdin.write(encodeFrame({ ...request, id }, workerData.maximum));
  });
}

port.on("message", async (message) => {
  if (message.type === "kill") {
    child.kill("SIGKILL");
    return;
  }
  if (message.type === "close") {
    close();
    return;
  }
  if (message.type === "call") {
    signal(await requestAdapter(message.request), message.control, message.payload);
    return;
  }
  if (message.type === "exports") {
    signal(await referenceExports(message.url), message.control, message.payload);
    return;
  }
});
