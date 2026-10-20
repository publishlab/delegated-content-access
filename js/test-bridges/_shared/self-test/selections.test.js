import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { portableSelection, portableSelectionArguments } from "../run-support.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const runner = join(root, "test-bridges/_shared/run.mjs");
const runReporter = join(root, "test-bridges/_shared/run-reporter.mjs");

/** @param {Record<string, unknown>} document */
function temporarySelection(document) {
  const v1Root = mkdtempSync(join(tmpdir(), "dca-selection-"));
  mkdirSync(join(v1Root, "test-bridges", "_shared", "selections"), { recursive: true });
  mkdirSync(join(v1Root, "test"), { recursive: true });
  writeFileSync(
    join(v1Root, "test", "fixture.test.js"),
    'import test from "node:test";\ntest("pinned", () => {});\n',
  );
  writeFileSync(
    join(v1Root, "test-bridges", "_shared", "selections", "fixture.json"),
    JSON.stringify(document),
  );
  return v1Root;
}

test("portable-core names unchanged portable tests independently of a bridge", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-core" });
  assert.equal(selection.testCount, 48);
  const options = { reportPath: "/run/case-counts.json", environment: {}, interactive: false };
  assert.deepEqual(
    portableSelectionArguments(selection, options),
    portableSelectionArguments(selection, options),
  );
  assert.deepEqual(
    portableSelectionArguments(selection, {
      ...options,
      environment: { DCA_NODE_TEST_ISOLATION: "none" },
    }).slice(0, 7),
    [
      "--experimental-test-isolation=process",
      "--test-concurrency=1",
      "--test-reporter=tap",
      "--test-reporter-destination=stdout",
      `--test-reporter=${runReporter}`,
      "--test-reporter-destination=/run/case-counts.json",
      "--test",
    ],
  );
  assert.deepEqual(selection.required[0], {
    module: "core-shared/aead.js",
    exports: ["encrypt", "decrypt", "decryptToKey"],
  });
});

test("portable-publisher names its stateless publisher-planning cases", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-publisher" });
  assert.ok(selection.testCount > 0);
  // A terminal gets Node's spec stream, as a direct run does; a pipe gets TAP.
  assert.deepEqual(
    portableSelectionArguments(selection, {
      reportPath: "/run/case-counts.json",
      environment: {},
      interactive: true,
    }).slice(0, 7),
    [
      "--experimental-test-isolation=process",
      "--test-concurrency=1",
      "--test-reporter=spec",
      "--test-reporter-destination=stdout",
      `--test-reporter=${runReporter}`,
      "--test-reporter-destination=/run/case-counts.json",
      "--test",
    ],
  );
  assert.deepEqual(selection.required, [
    {
      module: "core-publisher/siteResourcePlan.js",
      exports: ["planSiteResources"],
    },
  ]);
});

test("portable-issuer names its direct request-check cases and maps the request argument", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-issuer" });
  assert.ok(selection.testCount > 0);
  assert.deepEqual(selection.required, [
    { module: "core-issuer/IssuerEngine.js", exports: ["checkVersion", "checkEnvelopes"] },
  ]);
  const request = { module: "core-shared--client-issuer/DcaRequest.js", export: "DcaRequest" };
  assert.deepEqual(selection.inputs, [
    {
      module: "core-issuer/IssuerEngine.js",
      export: "checkVersion",
      argument: 0,
      class: request,
      data: "toObject",
    },
    {
      module: "core-issuer/IssuerEngine.js",
      export: "checkEnvelopes",
      argument: 0,
      class: request,
      data: "toObject",
    },
  ]);
});

test("portable-object-core names its object case and parse-refusal twin, its factory and the member it calls", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-object-core" });
  assert.equal(selection.testCount, 2);
  assert.deepEqual(selection.tests, [{ file: "test-reference/core-shared/dca-request.test.js" }]);
  assert.deepEqual(selection.required, [
    { module: "core-shared--client-issuer/DcaRequest.js", exports: ["parseDcaRequest"] },
    {
      module: "core-shared--client-issuer/DcaRequest.js",
      class: "DcaRequest",
      members: ["toObject"],
    },
  ]);
  assert.deepEqual(selection.inputs, []);
});

test("portable-core-dynamic names its cases of another JSON kind in three files and the exports they call", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-core-dynamic" });
  assert.equal(selection.testCount, 5);
  assert.deepEqual(selection.tests, [
    { file: "test-reference/core-shared/aead.test.js" },
    { file: "test-reference/adapter-client/periodkeys.test.js" },
    { file: "test-reference/core-shared/shared-primitive-misuse.test.js" },
  ]);
  assert.deepEqual(selection.required, [
    { module: "core-shared/aead.js", exports: ["encrypt"] },
    {
      module: "core-shared--publisher-issuer/periodKeys.js",
      exports: ["formatT", "currentT"],
    },
    { module: "core-shared--publisher-issuer/bind.js", exports: ["bindValue"] },
    { module: "core-shared/periodKeyProfiles.js", exports: ["periodKeyProfile"] },
  ]);
  assert.deepEqual(selection.inputs, []);
});

test("portable-object-core-dynamic names its parse refusal of another JSON kind and the factory it calls", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-object-core-dynamic" });
  assert.equal(selection.testCount, 1);
  assert.deepEqual(selection.tests, [{ file: "test-reference/core-shared/dca-request.test.js" }]);
  assert.deepEqual(selection.required, [
    { module: "core-shared--client-issuer/DcaRequest.js", exports: ["parseDcaRequest"] },
  ]);
  assert.deepEqual(selection.inputs, []);
});

test("portable-sealer-origin names its five Sealer cases, the factory and the members they call", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-sealer-origin" });
  assert.equal(selection.testCount, 5);
  assert.deepEqual(selection.tests, [
    { file: "test-reference/core-publisher/sealer-origin.test.js" },
  ]);
  assert.deepEqual(selection.required, [
    { module: "core-publisher/testing/sealerFactory.js", exports: ["sealerForRender"] },
    {
      module: "core-publisher/Sealer.js",
      class: "Sealer",
      members: ["resource", "content", "seal"],
    },
  ]);
});

test("portable-sealer-refusals names its typed refusal cases in three files, the factory and the members they call", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-sealer-refusals" });
  assert.equal(selection.testCount, 6);
  assert.deepEqual(selection.tests, [
    { file: "test-reference/core-publisher/sealer-origin.test.js" },
    { file: "test-reference/core-publisher/sealer-options.test.js" },
    { file: "test-reference/core-publisher/sealer-factory.test.js" },
  ]);
  assert.deepEqual(selection.required, [
    { module: "core-publisher/testing/sealerFactory.js", exports: ["sealerForRender"] },
    {
      module: "core-publisher/Sealer.js",
      class: "Sealer",
      members: ["resource", "content", "seal"],
    },
  ]);
});

test("portable-sealer-refusals-dynamic names its refusal cases of another JSON kind in two files, the factory and the member they call", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-sealer-refusals-dynamic" });
  assert.equal(selection.testCount, 4);
  assert.deepEqual(selection.tests, [
    { file: "test-reference/core-publisher/sealer-options.test.js" },
    { file: "test-reference/core-publisher/sealer-factory.test.js" },
  ]);
  assert.deepEqual(selection.required, [
    { module: "core-publisher/testing/sealerFactory.js", exports: ["sealerForRender"] },
    {
      module: "core-publisher/Sealer.js",
      class: "Sealer",
      members: ["content"],
    },
  ]);
});

test("portable-key-sealing-refusals-dynamic names its stand-in-key refusal cases and the two exports they call", () => {
  const selection = portableSelection({
    v1Root: root,
    name: "portable-key-sealing-refusals-dynamic",
  });
  assert.equal(selection.testCount, 7);
  assert.deepEqual(selection.tests, [{ file: "test-reference/core-shared/keySealing.test.js" }]);
  assert.deepEqual(selection.required, [
    { module: "core-shared--publisher-issuer/keySealing.js", exports: ["seal", "open"] },
  ]);
});

test("no typed key-sealing selection claims cases a stand-in key contradicts", () => {
  assert.throws(() => portableSelection({ v1Root: root, name: "portable-key-sealing-refusals" }));
});

test("portable-sealer-issuers names its mixed-issuer case, the factory and the members it calls", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-sealer-issuers" });
  assert.equal(selection.testCount, 1);
  assert.deepEqual(selection.tests, [
    { file: "test-reference/core-publisher/sealer-composition.test.js" },
  ]);
  assert.deepEqual(selection.required, [
    { module: "core-publisher/testing/sealerFactory.js", exports: ["sealerForRender"] },
    {
      module: "core-publisher/Sealer.js",
      class: "Sealer",
      members: ["resource", "content", "seal"],
    },
  ]);
});

test("portable-sealer-descriptors names its three content-representation cases, the factory and the members they call", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-sealer-descriptors" });
  assert.equal(selection.testCount, 3);
  assert.deepEqual(selection.tests, [
    { file: "test-reference/core-publisher/sealer-composition.test.js" },
  ]);
  assert.deepEqual(selection.required, [
    { module: "core-publisher/testing/sealerFactory.js", exports: ["sealerForRender"] },
    {
      module: "core-publisher/Sealer.js",
      class: "Sealer",
      members: ["resource", "content", "seal"],
    },
  ]);
});

test("portable-sealer-runtime names its runtime clock and random case, the factory and the members it calls", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-sealer-runtime" });
  assert.equal(selection.testCount, 1);
  assert.deepEqual(selection.tests, [
    { file: "test-reference/core-publisher/sealer-factory.test.js" },
  ]);
  assert.deepEqual(selection.required, [
    { module: "core-publisher/testing/sealerFactory.js", exports: ["sealerForRender"] },
    {
      module: "core-publisher/Sealer.js",
      class: "Sealer",
      members: ["resource", "content", "seal"],
    },
  ]);
});

test("portable-sealer-period-keys names its period-key wire case, the factory and the members it calls", () => {
  const selection = portableSelection({ v1Root: root, name: "portable-sealer-period-keys" });
  assert.equal(selection.testCount, 1);
  assert.deepEqual(selection.tests, [{ file: "test-reference/adapter-client/periodkeys.test.js" }]);
  assert.deepEqual(selection.required, [
    { module: "core-publisher/testing/sealerFactory.js", exports: ["sealerForRender"] },
    {
      module: "core-publisher/Sealer.js",
      class: "Sealer",
      members: ["resource", "content", "seal"],
    },
  ]);
});

test("a required class member names its module, class and members exactly", () => {
  const base = { version: 1, testCount: 1, tests: [{ file: "test/fixture.test.js" }] };
  const member = { module: "fixture.js", class: "Box", members: ["open"] };
  const listed = temporarySelection({ ...base, required: [member] });
  try {
    assert.deepEqual(portableSelection({ v1Root: listed, name: "fixture" }).required, [member]);
  } finally {
    rmSync(listed, { recursive: true, force: true });
  }
  for (const required of [
    [{ ...member, exports: ["run"] }],
    [{ ...member, members: [] }],
    [{ ...member, class: "not a class" }],
    [{ module: "fixture.js", members: ["open"] }],
    [{ fixtures: ["counter"] }],
  ]) {
    const malformed = temporarySelection({ ...base, required });
    try {
      assert.throws(
        () => portableSelection({ v1Root: malformed, name: "fixture" }),
        /selection required operations name a module and exports, or a module, class and members/,
        JSON.stringify(required),
      );
    } finally {
      rmSync(malformed, { recursive: true, force: true });
    }
  }
});

test("a portable selection refuses a top-level member it does not read", () => {
  // A stale member such as `"callbacks": true` would otherwise be ignored, and
  // a reader would take it for a route the run grants.
  const base = {
    version: 1,
    testCount: 1,
    tests: [{ file: "test/fixture.test.js" }],
    required: [{ module: "fixture.js", exports: ["run"] }],
  };
  const stale = temporarySelection({ ...base, callbacks: true });
  try {
    assert.throws(
      () => portableSelection({ v1Root: stale, name: "fixture" }),
      /selection has no member callbacks; it reads version, testCount, tests, required, inputs and constructors/,
    );
  } finally {
    rmSync(stale, { recursive: true, force: true });
  }
});

test("a portable selection rejects malformed counts and missing files", () => {
  const malformedRoot = temporarySelection({ version: 2, tests: [], required: [] });
  const countRoot = temporarySelection({
    version: 1,
    testCount: 0,
    tests: [{ file: "test/fixture.test.js" }],
    required: [{ module: "fixture.js", exports: ["run"] }],
  });
  const missingRoot = temporarySelection({
    version: 1,
    testCount: 1,
    tests: [{ file: "test/missing.test.js" }],
    required: [{ module: "fixture.js", exports: ["run"] }],
  });
  try {
    assert.throws(
      () => portableSelection({ v1Root: malformedRoot, name: "fixture" }),
      /version is 1/,
    );
    assert.throws(
      () => portableSelection({ v1Root: countRoot, name: "fixture" }),
      /testCount is a positive safe integer/,
    );
    assert.throws(() => portableSelection({ v1Root: missingRoot, name: "fixture" }), /ENOENT/);
  } finally {
    rmSync(malformedRoot, { recursive: true, force: true });
    rmSync(countRoot, { recursive: true, force: true });
    rmSync(missingRoot, { recursive: true, force: true });
  }
});

test("a selection may list input mappings, each exact and each argument once", () => {
  const base = {
    version: 1,
    testCount: 1,
    tests: [{ file: "test/fixture.test.js" }],
    required: [{ module: "fixture.js", exports: ["run"] }],
  };
  const mapping = {
    module: "fixture.js",
    export: "run",
    argument: 0,
    class: { module: "box.js", export: "Box" },
    data: "data",
  };
  const listed = temporarySelection({ ...base, inputs: [mapping] });
  const none = temporarySelection(base);
  try {
    assert.deepEqual(portableSelection({ v1Root: listed, name: "fixture" }).inputs, [mapping]);
    assert.deepEqual(portableSelection({ v1Root: none, name: "fixture" }).inputs, []);
  } finally {
    rmSync(listed, { recursive: true, force: true });
    rmSync(none, { recursive: true, force: true });
  }
  for (const inputs of [
    {},
    [{ ...mapping, argument: -1 }],
    [{ ...mapping, argument: 1.5 }],
    [{ ...mapping, module: "../fixture.js" }],
    [{ ...mapping, export: "not a name" }],
    [{ ...mapping, class: { module: "box.js" } }],
    [{ ...mapping, class: { module: "box.js", export: "Box", extra: 1 } }],
    [{ ...mapping, data: "" }],
    [{ ...mapping, extra: 1 }],
    [mapping, { ...mapping, class: { module: "other.js", export: "Other" } }],
  ]) {
    const malformed = temporarySelection({ ...base, inputs });
    try {
      assert.throws(
        () => portableSelection({ v1Root: malformed, name: "fixture" }),
        /selection inputs/,
        JSON.stringify(inputs),
      );
    } finally {
      rmSync(malformed, { recursive: true, force: true });
    }
  }
});

test("a selection may opt classes into constructor routing, each exact and once", () => {
  const base = {
    version: 1,
    testCount: 1,
    tests: [{ file: "test/fixture.test.js" }],
    required: [{ module: "fixture.js", exports: ["run"] }],
  };
  const constructor = { module: "box.js", class: "Box" };
  const listed = temporarySelection({ ...base, constructors: [constructor] });
  const none = temporarySelection(base);
  try {
    assert.deepEqual(portableSelection({ v1Root: listed, name: "fixture" }).constructors, [
      constructor,
    ]);
    assert.deepEqual(portableSelection({ v1Root: none, name: "fixture" }).constructors, []);
  } finally {
    rmSync(listed, { recursive: true, force: true });
    rmSync(none, { recursive: true, force: true });
  }
  for (const constructors of [
    {},
    [{ module: "../box.js", class: "Box" }],
    [{ module: "box.js", class: "not a name" }],
    [{ module: "box.js" }],
    [{ ...constructor, extra: 1 }],
    [constructor, constructor],
  ]) {
    const malformed = temporarySelection({ ...base, constructors });
    try {
      assert.throws(
        () => portableSelection({ v1Root: malformed, name: "fixture" }),
        /selection constructors/,
        JSON.stringify(constructors),
      );
    } finally {
      rmSync(malformed, { recursive: true, force: true });
    }
  }
  // An input mapping sends an instance of its class as data; a routed class
  // has no such instance, so one class is never both.
  const mapped = temporarySelection({
    ...base,
    constructors: [constructor],
    inputs: [
      {
        module: "fixture.js",
        export: "run",
        argument: 0,
        class: { module: "box.js", export: "Box" },
        data: "data",
      },
    ],
  });
  try {
    assert.throws(
      () => portableSelection({ v1Root: mapped, name: "fixture" }),
      /selection constructors name box\.js Box, which an input mapping sends as data/,
    );
  } finally {
    rmSync(mapped, { recursive: true, force: true });
  }
});

test("the js-loopback selection forces strict routing, rejects reference fallbacks and passes no explicit undefined", () => {
  const logs = mkdtempSync(join(tmpdir(), "dca-core-selection-"));
  try {
    const run = spawnSync(process.execPath, [runner, "portable-core"], {
      cwd: root,
      env: {
        ...process.env,
        DCA_BRIDGE: "js-loopback",
        DCA_LOG_DIR: logs,
        NODE_TEST_CONTEXT: undefined,
      },
      encoding: "utf8",
    });
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stdout, /^# fail 0$/m);
    assert.match(
      run.stderr,
      /[1-9]\d* selected tests passed; required exports (\d+)\/\1 called; [1-9]\d* external calls; 0 reference fallbacks; 0 uncarried results; Node exit 0/,
    );
    // A typed port has no argument that is present and undefined, so a
    // portable-core call never sends the undefined tag. The direct tests keep
    // those JavaScript guards.
    const calls = transcriptRecords(logs).filter((record) => record.event === "call");
    assert.ok(calls.length > 0, "the run wrote its calls to the transcript");
    const undefinedInputs = calls
      .map((record) => JSON.stringify(record.input))
      .filter((input) => input.includes('{"$type":"undefined"}'));
    assert.deepEqual(undefinedInputs, []);
  } finally {
    rmSync(logs, { recursive: true, force: true });
  }
});

test("the js-loopback issuer selection crosses the request checks with no fallback", () => {
  const run = spawnSync(process.execPath, [runner, "portable-issuer"], {
    cwd: root,
    env: { ...process.env, DCA_BRIDGE: "js-loopback", NODE_TEST_CONTEXT: undefined },
    encoding: "utf8",
  });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /^# fail 0$/m);
  assert.match(
    run.stderr,
    /[1-9]\d* selected tests passed; required exports (\d+)\/\1 called; [1-9]\d* external calls; 0 reference fallbacks; 0 uncarried results; Node exit 0/,
  );
});

/**
 * The transcript records of every run directory below `logs`.
 *
 * @param {string} logs
 */
function transcriptRecords(logs) {
  return readdirSync(logs, { recursive: true, encoding: "utf8" })
    .filter((file) => file.endsWith(".transcript.jsonl"))
    .flatMap((file) =>
      readFileSync(join(logs, file), "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line)),
    );
}

test("the js-loopback object selection answers the factory and the member in the test target", () => {
  const logs = mkdtempSync(join(tmpdir(), "dca-object-selection-"));
  try {
    const run = spawnSync(process.execPath, [runner, "portable-object-core"], {
      cwd: root,
      env: {
        ...process.env,
        DCA_BRIDGE: "js-loopback",
        DCA_LOG_DIR: logs,
        NODE_TEST_CONTEXT: undefined,
      },
      encoding: "utf8",
    });
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stdout, /^# fail 0$/m);
    assert.match(
      run.stderr,
      /portable portable-object-core: 2 selected tests passed; required exports 1\/1 called; required members 1\/1 called; 5 external calls; 0 reference fallbacks; 0 uncarried results; Node exit 0/,
    );
    const records = transcriptRecords(logs);
    const module = records.find(
      (record) =>
        record.event === "module" &&
        record.sourceModule === "core-shared--client-issuer/DcaRequest.js",
    );
    const factory = module.members.find(
      (/** @type {any} */ member) => member.sourceExport === "parseDcaRequest",
    );
    const request = module.classes.find(
      (/** @type {any} */ entry) => entry.sourceExport === "DcaRequest",
    );
    const toObject = request.members.find(
      (/** @type {any} */ member) => member.sourceMember === "toObject",
    );
    const [final] = records.filter((record) => record.event === "final");
    assert.equal(final.entry, "test-reference/core-shared/dca-request.test.js");
    assert.deepEqual(final.routes, {
      [factory.id]: { external: 3, reference: 0 },
      [toObject.id]: { external: 2, reference: 0 },
    });
  } finally {
    rmSync(logs, { recursive: true, force: true });
  }
});

test("the unchanged object case fails against a JS test target whose document comes back reordered", () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-object-wrong-"));
  mkdirSync(join(targetRoot, "core-shared--client-issuer"));
  writeFileSync(
    join(targetRoot, "core-shared--client-issuer/DcaRequest.js"),
    `export class DcaRequest {
  #document;
  constructor(document) { this.#document = document; }
  toObject() {
    const { version, issuerName, ...rest } = this.#document;
    return { version, issuerName, ...rest };
  }
}
export function parseDcaRequest(document) { return new DcaRequest(JSON.parse(document)); }
`,
  );
  try {
    const run = spawnSync(process.execPath, [runner, "portable-object-core"], {
      cwd: root,
      env: {
        ...process.env,
        DCA_BRIDGE: "js",
        DCA_TARGET_ROOT: targetRoot,
        NODE_TEST_CONTEXT: undefined,
      },
      encoding: "utf8",
    });
    // The target refuses nothing, so the parse-refusal twin fails beside the
    // reordered document.
    assert.notEqual(run.status, 0, run.stdout);
    assert.match(run.stdout, /^# fail 2$/m);
    assert.match(
      run.stdout,
      /not ok 1 - the document goes back as it arrived, members nobody named included\n[^]*?error: \|-\n\s+Expected values to be strictly deep-equal/,
    );
    assert.match(run.stderr, /portable selection passed 0\/2; failed 2/);
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("the js-loopback Sealer selection builds each Sealer through the factory and calls it through its handle", () => {
  const logs = mkdtempSync(join(tmpdir(), "dca-sealer-selection-"));
  try {
    const run = spawnSync(process.execPath, [runner, "portable-sealer-origin"], {
      cwd: root,
      env: {
        ...process.env,
        DCA_BRIDGE: "js-loopback",
        DCA_LOG_DIR: logs,
        NODE_TEST_CONTEXT: undefined,
      },
      encoding: "utf8",
    });
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stdout, /^# fail 0$/m);
    assert.match(
      run.stderr,
      /portable portable-sealer-origin: 5 selected tests passed; required exports 1\/1 called; required members 3\/3 called; 44 external calls; 0 reference fallbacks; 0 uncarried results; Node exit 0/,
    );
    const records = transcriptRecords(logs);
    const factoryModule = records.find(
      (record) =>
        record.event === "module" &&
        record.sourceModule === "core-publisher/testing/sealerFactory.js",
    );
    const factory = factoryModule.members.find(
      (/** @type {any} */ entry) => entry.sourceExport === "sealerForRender",
    );
    const module = records.find(
      (record) => record.event === "module" && record.sourceModule === "core-publisher/Sealer.js",
    );
    const sealer = module.classes.find(
      (/** @type {any} */ entry) => entry.sourceExport === "Sealer",
    );
    /** @param {string} name */
    const member = (name) =>
      sealer.members.find((/** @type {any} */ entry) => entry.sourceMember === name).id;
    const [final] = records.filter((record) => record.event === "final");
    assert.equal(final.entry, "test-reference/core-publisher/sealer-origin.test.js");
    // One Sealer for the origin case, two for the isolation case, three
    // for each admission case and two for the profile case, all in the one
    // adapter session of the test file.
    assert.deepEqual(final.routes, {
      [factory.id]: { external: 11, reference: 0 },
      [member("resource")]: { external: 11, reference: 0 },
      [member("content")]: { external: 11, reference: 0 },
      [member("seal")]: { external: 11, reference: 0 },
    });
  } finally {
    rmSync(logs, { recursive: true, force: true });
  }
});

test("the unchanged Sealer cases fail against a JS test target whose factory configures another origin", () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-sealer-wrong-"));
  mkdirSync(join(targetRoot, "core-publisher/testing"), { recursive: true });
  /** @param {string} path */
  const reference = (path) => JSON.stringify(pathToFileURL(join(root, path)).href);
  writeFileSync(
    join(targetRoot, "core-publisher/testing/sealerFactory.js"),
    `import { sealerForRender as configured } from ${reference("core-publisher/testing/sealerFactory.js")};
export async function sealerForRender(setup) { return configured({ ...setup, origin: "https://other.example" }); }
`,
  );
  writeFileSync(
    join(targetRoot, "core-publisher/Sealer.js"),
    `export { Sealer } from ${reference("core-publisher/Sealer.js")};\n`,
  );
  try {
    const run = spawnSync(process.execPath, [runner, "portable-sealer-origin"], {
      cwd: root,
      env: {
        ...process.env,
        DCA_BRIDGE: "js",
        DCA_TARGET_ROOT: targetRoot,
        NODE_TEST_CONTEXT: undefined,
      },
      encoding: "utf8",
    });
    assert.notEqual(run.status, 0, run.stdout);
    assert.match(run.stdout, /^# fail 5$/m);
    assert.match(run.stdout, /Expected values to be strictly equal/);
    assert.match(run.stdout, /https:\/\/other\.example/);
    assert.match(run.stderr, /portable selection passed 0\/5; failed 5/);
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

/**
 * Runs a Sealer selection strictly against a JavaScript test target whose
 * factory wraps the reference one and changes its setup with `change`, a
 * JavaScript expression over `setup`.
 *
 * @param {string} selection
 * @param {string} change
 */
function runWithWrongFactory(selection, change) {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-sealer-wrong-"));
  mkdirSync(join(targetRoot, "core-publisher/testing"), { recursive: true });
  /** @param {string} path */
  const reference = (path) => JSON.stringify(pathToFileURL(join(root, path)).href);
  writeFileSync(
    join(targetRoot, "core-publisher/testing/sealerFactory.js"),
    `import { sealerForRender as configured } from ${reference("core-publisher/testing/sealerFactory.js")};
export async function sealerForRender(setup) { return configured(${change}); }
`,
  );
  writeFileSync(
    join(targetRoot, "core-publisher/Sealer.js"),
    `export { Sealer } from ${reference("core-publisher/Sealer.js")};\n`,
  );
  try {
    return spawnSync(process.execPath, [runner, selection], {
      cwd: root,
      env: {
        ...process.env,
        DCA_BRIDGE: "js",
        DCA_TARGET_ROOT: targetRoot,
        NODE_TEST_CONTEXT: undefined,
      },
      encoding: "utf8",
    });
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
}

test("the unchanged period-key case fails against a JS test target whose factory reads another random stream", () => {
  const run = runWithWrongFactory(
    "portable-sealer-period-keys",
    "{ ...setup, randomStream: setup.randomStream.map((byte) => byte ^ 0xff) }",
  );
  assert.notEqual(run.status, 0, run.stdout);
  assert.match(run.stdout, /^# fail 1$/m);
  assert.match(run.stdout, /Expected values to be strictly equal/);
  assert.match(run.stderr, /portable selection passed 0\/1; failed 1/);
});

test("the unchanged mixed-issuer case fails against a JS test target whose factory drops the RSA-OAEP issuer", () => {
  const run = runWithWrongFactory(
    "portable-sealer-issuers",
    "{ ...setup, issuers: setup.issuers.slice(0, 1) }",
  );
  assert.notEqual(run.status, 0, run.stdout);
  assert.match(run.stdout, /^# fail 1$/m);
  assert.match(run.stdout, /Expected values to be strictly deep-equal/);
  assert.match(run.stdout, /paywall_fallback_service/);
  assert.match(run.stderr, /portable selection passed 0\/1; failed 1/);
});

test("under portable-issuer a request crosses as its document, a plain record meets the target's own refusal, and a bridge refusal cannot pass for it", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-issuer-probe-"));
  const logs = join(directory, "logs");
  const probe = join(directory, "probe.test.js");
  /** @param {string} path */
  const moduleUrl = (path) => JSON.stringify(pathToFileURL(join(root, path)).href);
  writeFileSync(
    probe,
    `import test from "node:test";
import assert from "node:assert/strict";
import { checkVersion } from ${moduleUrl("core-issuer/IssuerEngine.js")};
import { DcaRequest } from ${moduleUrl("core-shared--client-issuer/DcaRequest.js")};
test("probe", () => {
  assert.equal(checkVersion(new DcaRequest({ version: "1" })), undefined);
  assert.throws(() => checkVersion({ version: "1" }), { code: "bad_config" });
  // A bridge refusal carries no target code, so it cannot pass for one: an
  // instance at the unlisted argument 1 fails before dispatch, and the
  // assertion that expects the target's bad_config fails on it.
  let bridgeError;
  try {
    checkVersion(new DcaRequest({ version: "1" }), [new DcaRequest({})]);
  } catch (error) {
    bridgeError = error;
  }
  assert.match(String(bridgeError?.message), /bridge values are JSON data/);
  assert.equal(bridgeError?.code, undefined);
  assert.throws(
    () => assert.throws(() => { throw bridgeError; }, { code: "bad_config" }),
    assert.AssertionError,
  );
});
`,
  );
  try {
    const environment = {
      ...process.env,
      DCA_BRIDGE_MODE: "strict",
      DCA_TEST_SELECTION: "portable-issuer",
      DCA_LOG_DIR: logs,
    };
    delete environment.NODE_TEST_CONTEXT;
    delete environment.DCA_TARGET_ROOT;
    const run = spawnSync(
      process.execPath,
      ["--import", join(root, "test-bridges/js-loopback/bridge.mjs"), "--test", probe],
      { cwd: root, env: environment, encoding: "utf8" },
    );
    assert.equal(run.status, 0, run.stdout);
    const records = readdirSync(logs, { recursive: true, encoding: "utf8" })
      .filter((file) => file.endsWith(".transcript.jsonl"))
      .flatMap((file) =>
        readFileSync(join(logs, file), "utf8")
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line)),
      );
    const calls = records.filter((record) => record.event === "call");
    assert.deepEqual(
      calls.map((record) => [record.input, record.instances, record.response.result.kind]),
      [
        [
          [{ version: "1" }],
          [
            {
              argument: 0,
              sourceModule: "core-shared--client-issuer/DcaRequest.js",
              sourceExport: "DcaRequest",
            },
          ],
          "observation",
        ],
        [[{ version: "1" }], undefined, "refusal"],
      ],
    );
    assert.equal(calls[1].response.result.code, "bad_config");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the js-loopback publisher selection crosses the same selected publisher cases", () => {
  const run = spawnSync(process.execPath, [runner, "portable-publisher"], {
    cwd: root,
    env: { ...process.env, DCA_BRIDGE: "js-loopback", NODE_TEST_CONTEXT: undefined },
    encoding: "utf8",
  });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /^# fail 0$/m);
  assert.match(
    run.stderr,
    /[1-9]\d* selected tests passed; required exports (\d+)\/\1 called; [1-9]\d* external calls; 0 reference fallbacks; 0 uncarried results; Node exit 0/,
  );
});
