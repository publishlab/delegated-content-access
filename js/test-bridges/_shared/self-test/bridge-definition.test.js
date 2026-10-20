import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";

import { defineBridge } from "../bridge-definition.mjs";

test("a bridge definition freezes a process launch description", () => {
  const bridge = defineBridge({
    id: "example-bridge",
    adapter: "adapter.mjs",
    arguments: ["--flag"],
  });
  assert.equal(bridge.id, "example-bridge");
  assert.ok(Object.isFrozen(bridge));
  assert.ok(Object.isFrozen(bridge.arguments));
  assert.throws(() => defineBridge({ id: "Example", adapter: "adapter.mjs" }), /kebab/);
  assert.throws(() => defineBridge({ id: "example", adapter: "" }), /adapter/);
});

test("a command alone starts a compiled adapter with no script path", () => {
  const bridge = defineBridge({ id: "compiled", command: "/opt/example/adapter" });
  assert.equal(bridge.command, "/opt/example/adapter");
  assert.equal(bridge.adapter, undefined);
  assert.throws(() => defineBridge({ id: "compiled" }), /command or an adapter/);
});

test("the adapter working directory and the target root are separate settings", () => {
  const both = defineBridge({
    id: "example-bridge",
    command: "/opt/example/adapter",
    adapterCwd: "/work/adapter",
    targetRoot: "/work/target",
  });
  assert.equal(both.adapterCwd, "/work/adapter");
  assert.equal(both.targetRoot, "/work/target");
  const rootOnly = defineBridge({
    id: "example-bridge",
    command: "/opt/example/adapter",
    targetRoot: "relative/target",
  });
  assert.equal(rootOnly.adapterCwd, process.cwd());
  assert.equal(rootOnly.targetRoot, resolve("relative/target"));
  assert.equal(Object.hasOwn(rootOnly, "portRoot"), false);
});

test("a bridge definition gives the target root no default", () => {
  const bridge = defineBridge({
    id: "example-bridge",
    command: "/opt/example/adapter",
    adapterCwd: "/work/adapter",
  });
  assert.equal(bridge.targetRoot, undefined);
  assert.throws(
    () => defineBridge({ id: "example-bridge", command: "/opt/example/adapter", targetRoot: "" }),
    /target root/,
  );
  assert.throws(
    () => defineBridge({ id: "example-bridge", command: "/opt/example/adapter", adapterCwd: "" }),
    /adapter working directory/,
  );
});
