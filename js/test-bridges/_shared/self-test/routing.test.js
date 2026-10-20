import test from "node:test";
import assert from "node:assert/strict";

import {
  isDriverOwnedModule,
  validateDescription,
  validateCapabilities,
  validateErrorTypes,
  validateModuleClasses,
  validateModuleMembers,
} from "../routing.mjs";

test("initial capabilities advertise value types and module discovery only", () => {
  assert.deepEqual(validateCapabilities({ valueTypes: ["number"], moduleDiscovery: true }), {
    valueTypes: ["number"],
    moduleDiscovery: true,
  });
  assert.throws(() => validateCapabilities({ valueTypes: [] }), /module discovery/);
});

test("module members reject unsafe exports and duplicate identities", () => {
  const member = { id: "op-1", sourceExport: "call", callShape: "sync" };
  assert.deepEqual(validateModuleMembers({ members: [member] }), [member]);
  assert.throws(
    () => validateModuleMembers({ members: [member, { ...member, sourceExport: "other" }] }),
    /IDs are unique/,
  );
  assert.throws(
    () => validateModuleMembers({ members: [{ ...member, sourceExport: "not-an-export" }] }),
    /safe IDs/,
  );
});

test("module members admit asynchronous callable exports", () => {
  const member = { id: "op-async", sourceExport: "callAsync", callShape: "async" };
  assert.deepEqual(validateModuleMembers({ members: [member] }), [member]);
});

test("error descriptors require safe reference locations and unique opaque IDs", () => {
  const descriptor = {
    id: "error-t5AVNYg6c0fydcLn",
    sourceModule: "fixture/errors.js",
    sourceExport: "FixtureError",
  };
  assert.deepEqual(validateErrorTypes([descriptor]), [descriptor]);
  assert.throws(
    () => validateErrorTypes([{ ...descriptor, sourceModule: "../errors.js" }]),
    /safe IDs, modules, and exports/,
  );
  assert.throws(
    () => validateErrorTypes([descriptor, { ...descriptor, sourceExport: "OtherError" }]),
    /IDs are unique/,
  );
});

test("tests, test helpers and demo modules are driver-owned and never cross", () => {
  for (const path of [
    "test-reference/support/keys.js",
    "test-lib/harnesses/issuer.js",
    "test-reference/support/portable-test.js",
    "demo/support/page.js",
    "extensions/chain-keys/test/world.js",
    "extensions/content-key-seal-omission/test-lib/load.js",
    "extensions/chain-keys/demo/world.js",
    "core-shared/codec.test.js",
  ])
    assert.equal(isDriverOwnedModule(path), true, path);
  for (const path of ["core-shared/codec.js", "adapter-client/periodKeys.js", "ports/crypto.js"])
    assert.equal(isDriverOwnedModule(path), false, path);
});

test("a describe reply has exactly identity, capabilities and top-level errorTypes", () => {
  const capabilities = { valueTypes: ["number"], moduleDiscovery: true };
  const described = validateDescription({
    identity: { bridge: "example", adapterVersion: "1" },
    capabilities,
    errorTypes: [],
  });
  assert.deepEqual(described.capabilities, capabilities);
  assert.deepEqual(described.errorTypes, []);
  assert.deepEqual(validateDescription({ capabilities }).errorTypes, []);
  assert.throws(
    () => validateDescription({ capabilities: { ...capabilities, errorTypes: [] } }),
    /capabilities have only valueTypes and moduleDiscovery/,
  );
  assert.throws(
    () => validateDescription({ capabilities, operations: [] }),
    /describe reply has only identity, capabilities and errorTypes/,
  );
  assert.throws(
    () => validateDescription({ identity: { bridge: 1 }, capabilities }),
    /identity members are strings/,
  );
});

test("a describe reply that offers target fixtures or callbacks is refused", () => {
  const capabilities = { valueTypes: ["record"], moduleDiscovery: true };
  const fixtures = [{ id: "fixture-1", name: "counter", callShape: "sync" }];
  assert.throws(
    () => validateDescription({ capabilities, fixtures }),
    /describe reply has only identity, capabilities and errorTypes/,
  );
  assert.throws(
    () => validateDescription({ capabilities: { ...capabilities, callbacks: true } }),
    /capabilities have only valueTypes and moduleDiscovery/,
  );
});

test("a module description may declare classes whose instance members the test target claims", () => {
  const members = [{ id: "op-1", sourceExport: "open", callShape: "sync" }];
  const counter = {
    id: "class-1",
    sourceExport: "Counter",
    members: [
      { id: "op-2", sourceMember: "add", callShape: "sync" },
      { id: "op-3", sourceMember: "later", callShape: "async" },
    ],
  };
  assert.deepEqual(validateModuleClasses({ members }, members), []);
  assert.deepEqual(validateModuleClasses({ members, classes: [counter] }, members), [counter]);
  const member = counter.members[0];
  for (const classes of [
    "Counter",
    [{ ...counter, extra: 1 }],
    [{ ...counter, id: "" }],
    [{ ...counter, sourceExport: "not-a-class" }],
    [{ ...counter, members: [{ ...member, callShape: "value" }] }],
    [{ ...counter, members: [{ ...member, sourceMember: "not-a-member" }] }],
    [{ ...counter, members: [{ ...member, sourceExport: "add" }] }],
  ])
    assert.throws(
      () => validateModuleClasses({ members, classes }, members),
      /module classes have safe IDs, exports and members/,
      JSON.stringify(classes),
    );
  assert.throws(
    () =>
      validateModuleClasses(
        { members, classes: [counter, { ...counter, sourceExport: "B" }] },
        members,
      ),
    /IDs are unique/,
  );
  assert.throws(
    () =>
      validateModuleClasses(
        { members, classes: [{ ...counter, members: [{ ...member, id: "op-1" }] }] },
        members,
      ),
    /IDs are unique/,
  );
  assert.throws(
    () =>
      validateModuleClasses(
        { members, classes: [{ ...counter, members: [member, { ...member, id: "op-9" }] }] },
        members,
      ),
    /member names are unique/,
  );
});
