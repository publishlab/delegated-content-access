import test from "node:test";
import assert from "node:assert/strict";

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { defineBridge } from "../bridge-definition.mjs";
import { FrameDecoder, assertRequest, assertResponse, encodeFrame } from "../protocol.mjs";
import { ProcessBinding } from "../register.mjs";

test("framed JSON survives chunking and rejects incomplete, malformed, and oversized frames", () => {
  const frame = encodeFrame({ answer: 7 });
  const decoder = new FrameDecoder();
  assert.deepEqual(decoder.push(frame.subarray(0, 3)), []);
  assert.deepEqual(decoder.push(frame.subarray(3)), [{ answer: 7 }]);
  decoder.finish();
  assert.throws(() => encodeFrame({ long: "x".repeat(10) }, 2), /exceeds/);
  assert.throws(() => new FrameDecoder().push(new Uint8Array([0, 0, 0, 1, 123])), /not JSON/);
  const incomplete = new FrameDecoder();
  incomplete.push(new Uint8Array([0, 0, 0, 2, 123]));
  assert.throws(() => incomplete.finish(), /mid-frame/);
});

test("request validation rejects unknown, stale, and uncorrelatable requests", () => {
  assert.equal(assertRequest({ version: 1, id: "a", type: "describe" }).type, "describe");
  assert.throws(() => assertRequest({ version: 0, id: "a", type: "describe" }), /version/);
  assert.throws(() => assertRequest({ version: 1, id: "", type: "describe" }), /id/);
  assert.throws(() => assertRequest({ version: 1, id: "a", type: "unknown" }), /unknown/);
  assert.throws(() => assertRequest({ version: 1, id: "a", type: "call" }), /protocol/);
  assert.throws(
    () =>
      assertRequest({
        version: 1,
        id: "a",
        type: "call",
        protocol: "dca-test-bridge/v1",
        operation: "one",
      }),
    /input/,
  );
  assert.throws(
    () =>
      assertResponse({ version: 1, id: "a", type: "response", result: { kind: "observation" } }),
    /exact variant/,
  );
  assert.throws(
    () =>
      assertResponse(
        { version: 1, id: "wrong", type: "response", result: { kind: "unsupported" } },
        "a",
      ),
    /does not match/,
  );
});

test("a call frame names its protocol in protocol and survives framing", () => {
  const call = {
    version: 1,
    id: "a",
    type: "call",
    protocol: "dca-test-bridge/v1",
    operation: "one",
    input: [],
  };
  const [decoded] = new FrameDecoder().push(encodeFrame(call));
  assert.deepEqual(assertRequest(decoded), call);
  assert.throws(
    () => assertRequest({ ...call, protocol: "dca-test-bridge/v2" }),
    /protocol is dca-test-bridge\/v1/,
  );
});

test("a call frame may mark arguments that stand for instances of a reference class", () => {
  const call = {
    version: 1,
    id: "a",
    type: "call",
    protocol: "dca-test-bridge/v1",
    operation: "one",
    input: [{ n: 1 }, 2],
    instances: [{ argument: 0, sourceModule: "fixture/box.js", sourceExport: "Box" }],
  };
  assert.deepEqual(assertRequest(call), call);
  for (const instances of [
    [],
    "Box",
    [{ argument: 2, sourceModule: "fixture/box.js", sourceExport: "Box" }],
    [{ argument: -1, sourceModule: "fixture/box.js", sourceExport: "Box" }],
    [{ argument: 0, sourceModule: "../box.js", sourceExport: "Box" }],
    [{ argument: 0, sourceModule: "fixture/box.js", sourceExport: "not a name" }],
    [{ argument: 0, sourceModule: "fixture/box.js", sourceExport: "Box", data: "toObject" }],
    [
      { argument: 0, sourceModule: "fixture/box.js", sourceExport: "Box" },
      { argument: 0, sourceModule: "fixture/box.js", sourceExport: "Box" },
    ],
  ])
    assert.throws(
      () => assertRequest({ ...call, instances }),
      /bridge call instances/,
      JSON.stringify(instances),
    );
});

test("a call frame that carries target is refused, with or without protocol", () => {
  const call = { version: 1, id: "a", type: "call", operation: "one", input: [] };
  assert.throws(() => assertRequest({ ...call, target: "dca-test-bridge/v1" }), /target/);
  assert.throws(
    () => assertRequest({ ...call, protocol: "dca-test-bridge/v1", target: "dca-test-bridge/v1" }),
    /target/,
  );
});

test("the driver sends protocol, not target, in every call it makes", async () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-frame-echo-"));
  const script = join(directory, "adapter.mjs");
  const protocol = new URL("../protocol.mjs", import.meta.url).href;
  // Answers a call with the member names and protocol of the frame it received.
  writeFileSync(
    script,
    `import { FrameDecoder, encodeFrame } from ${JSON.stringify(protocol)};
const decoder = new FrameDecoder();
process.stdin.on("data", (chunk) => {
  for (const request of decoder.push(chunk))
    process.stdout.write(encodeFrame({ version: 1, id: request.id, type: "response",
      result: { kind: "observation", value: request.type === "describe"
        ? { capabilities: { valueTypes: ["list", "string"], moduleDiscovery: true } }
        : request.type === "call" ? [Object.keys(request).sort(), request.protocol] : null } }));
});
`,
  );
  const binding = new ProcessBinding(
    defineBridge({ id: "frame-echo", command: process.execPath, arguments: [script] }),
  );
  try {
    await binding.start();
    binding.operations.set("op-1", { id: "op-1", sourceExport: "echo", callShape: "sync" });
    const expected = [
      ["id", "input", "operation", "protocol", "type", "version"],
      "dca-test-bridge/v1",
    ];
    assert.deepEqual(binding.call("op-1", []), expected);
    assert.deepEqual(await binding.callAsync("op-1", []), expected);
  } finally {
    await binding.dispose();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("an uncarried result carries one diagnostic and nothing else", () => {
  const response = (/** @type {Record<string, unknown>} */ result) => ({
    version: 1,
    id: "a",
    type: "response",
    result,
  });
  assert.equal(
    assertResponse(response({ kind: "uncarried", message: "no bridge value" })).result.kind,
    "uncarried",
  );
  assert.throws(() => assertResponse(response({ kind: "uncarried" })), /known exact variant/);
  assert.throws(
    () => assertResponse(response({ kind: "uncarried", message: "x", value: 1 })),
    /known exact variant/,
  );
});

test("an observation may declare the JS type of positions in its value", () => {
  const response = (/** @type {Record<string, unknown>} */ result) => ({
    version: 1,
    id: "a",
    type: "response",
    result: { kind: "observation", value: { items: [] }, ...result },
  });
  for (const declared of [
    "all",
    [],
    [{ at: [], type: "record" }],
    [{ at: ["items"], type: "list" }],
    [{ at: ["items", 0], type: "Uint8Array" }],
  ])
    assert.equal(assertResponse(response({ declared })).result.kind, "observation");
  for (const declared of [
    "list",
    true,
    [{ at: [], type: "string" }],
    [{ at: "items", type: "list" }],
    [{ at: [-1], type: "list" }],
    [{ at: [0.5], type: "list" }],
    [{ at: [true], type: "list" }],
    [{ at: [], type: "list", extra: 1 }],
    [{ type: "list" }],
  ])
    assert.throws(
      () => assertResponse(response({ declared })),
      /known exact variant/,
      JSON.stringify(declared),
    );
});

test("a response says settled only to mark a promise", () => {
  const response = (/** @type {unknown} */ settled) => ({
    version: 1,
    id: "a",
    type: "response",
    settled,
    result: { kind: "observation", value: 1 },
  });
  assert.equal(assertResponse(response("promise")).settled, "promise");
  assert.throws(() => assertResponse(response("later")), /settled is "promise"/);
});

test("a call frame may name one receiver handle, in the exact handle layout", () => {
  const receiver = { $type: "Handle", class: "class-1", handle: "h-a-1" };
  const call = {
    version: 1,
    id: "a",
    type: "call",
    protocol: "dca-test-bridge/v1",
    operation: "op-7",
    input: [1],
    receiver,
  };
  assert.deepEqual(assertRequest(call), call);
  for (const wrong of [
    null,
    "h-a-1",
    { $type: "Handle", class: "class-1" },
    { $type: "Handle", class: "", handle: "h-a-1" },
    { ...receiver, extra: 1 },
    { $type: "Record", value: receiver },
  ])
    assert.throws(
      () => assertRequest({ ...call, receiver: wrong }),
      /bridge call receiver is one handle/,
      JSON.stringify(wrong),
    );
});
