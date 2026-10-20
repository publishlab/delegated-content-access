import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  exclusionArguments,
  namedExclusions,
  publicSelectors,
  runnerArguments,
  verifySelectionEvidence,
} from "../run-support.mjs";

test("the public runner derives selectors from package authority without a shell", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-bridge-"));
  const packagePath = join(directory, "package.json");
  try {
    writeFileSync(
      packagePath,
      JSON.stringify({
        scripts: { "test:reference:public": 'node --test "test/a.test.js" "test/b.test.js"' },
      }),
    );
    assert.deepEqual(publicSelectors(packagePath), ["test/a.test.js", "test/b.test.js"]);
    assert.deepEqual(
      runnerArguments({ packagePath, v1Root: directory, arguments_: ["public"], environment: {} }),
      ["--experimental-test-isolation=process", "--test", "test/a.test.js", "test/b.test.js"],
    );
    assert.deepEqual(
      runnerArguments({
        packagePath,
        v1Root: directory,
        arguments_: ["test/a.test.js"],
        environment: {},
      }),
      ["--experimental-test-isolation=process", "--test", "test/a.test.js"],
    );
    assert.throws(
      () =>
        runnerArguments({
          packagePath,
          v1Root: directory,
          arguments_: ["../elsewhere.test.js"],
          environment: {},
        }),
      /stays under/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

/** @param {string} entry @param {string[]} operations @param {number} [uncarriedResults] */
function shard(entry, operations, uncarriedResults = 0) {
  return [
    { event: "capabilities", entry },
    {
      event: "module",
      sourceModule: "core/math.js",
      members: [
        { id: "op-1", sourceExport: "twice" },
        { id: "op-2", sourceExport: "half" },
      ],
    },
    ...operations.map((operation) => ({ event: "call", operation })),
    {
      event: "final",
      entry,
      externalCalls: operations.length,
      referenceFallbacks: 0,
      uncarriedResults,
    },
  ];
}

const selection = Object.freeze({
  name: "fixture",
  testCount: 2,
  tests: [{ file: "test/a.test.js" }, { file: "test/b.test.js" }],
  required: [{ module: "core/math.js", exports: ["twice", "half"] }],
});
/**
 * A case report as the run reporter writes it: counts per selected file and
 * Node's own run summary.
 *
 * @param {Record<string, Partial<Record<string, number>>>} files
 */
function caseReport(files) {
  const zero = { tests: 0, passed: 0, failed: 0, cancelled: 0, skipped: 0, todo: 0 };
  /** @type {Record<string, Record<string, number>>} */
  const complete = {};
  const node = { ...zero };
  for (const [file, partial] of Object.entries(files)) {
    const counts = { ...zero, ...partial };
    counts.tests = counts.passed + counts.failed + counts.cancelled + counts.skipped + counts.todo;
    complete[file] = counts;
    for (const name of Object.keys(zero))
      node[/** @type {keyof typeof zero} */ (name)] += counts[name];
  }
  return JSON.stringify({ version: 1, files: complete, node });
}
const passing = caseReport({ "test/a.test.js": { passed: 1 }, "test/b.test.js": { passed: 1 } });

test("a named selection summarizes passed tests and required exports called", () => {
  assert.deepEqual(
    verifySelectionEvidence(
      selection,
      [shard("test/a.test.js", ["op-1"]), shard("test/b.test.js", ["op-2"])],
      passing,
    ),
    {
      passed: 2,
      requiredCalled: 2,
      requiredTotal: 2,
      requiredMembersCalled: 0,
      requiredMembersTotal: 0,
      requiredConstructorsCalled: 0,
      requiredConstructorsTotal: 0,
      externalCalls: 2,
      referenceFallbacks: 0,
      uncarriedResults: 0,
    },
  );
});

test("a named selection fails on an uncarried result and names its operation", () => {
  const uncarried = [
    ...shard("test/b.test.js", ["op-2"]).slice(0, -1),
    { event: "uncarried", operation: "op-1", input: [], response: {} },
    {
      event: "final",
      entry: "test/b.test.js",
      externalCalls: 1,
      referenceFallbacks: 0,
      uncarriedResults: 1,
    },
  ];
  assert.throws(
    () =>
      verifySelectionEvidence(selection, [shard("test/a.test.js", ["op-1"]), uncarried], passing),
    /^Error: portable selection had 1 uncarried result: core\/math\.js twice$/,
  );
});

test("a named selection needs an external call from every selected file", () => {
  assert.throws(
    () =>
      verifySelectionEvidence(
        selection,
        [shard("test/a.test.js", ["op-1", "op-2"]), shard("test/b.test.js", [])],
        passing,
      ),
    /test\/b\.test\.js made no external call/,
  );
});

test("a named selection reports every required export it did not call", () => {
  assert.throws(
    () =>
      verifySelectionEvidence(
        selection,
        [shard("test/a.test.js", ["op-1"]), shard("test/b.test.js", ["op-1"])],
        passing,
      ),
    /required exports 1\/2 called; not called: core\/math\.js half/,
  );
});

/**
 * One process's shard: its adapter numbers members in describe order, as the
 * contract permits, so another process may give the same ID to another export.
 *
 * @param {string} entry @param {string} sourceModule @param {string} sourceExport @param {string[]} operations
 */
function numberedShard(entry, sourceModule, sourceExport, operations) {
  return [
    { event: "capabilities", entry },
    { event: "module", sourceModule, members: [{ id: "m1", sourceExport }] },
    ...operations.map((operation) => ({ event: "call", operation })),
    { event: "final", entry, externalCalls: operations.length, referenceFallbacks: 0 },
  ];
}

const twoModules = Object.freeze({
  name: "fixture",
  testCount: 2,
  tests: [{ file: "test/a.test.js" }, { file: "test/b.test.js" }],
  required: [
    { module: "impl/one.js", exports: ["one"] },
    { module: "impl/two.js", exports: ["two"] },
  ],
});

test("a call counts only for the export its own process described under that ID", () => {
  // Both processes call, so every file makes an external call; only file b's
  // call reaches `two`, and file a's `m1` names `one`.
  assert.deepEqual(
    verifySelectionEvidence(
      twoModules,
      [
        numberedShard("test/a.test.js", "impl/one.js", "one", ["m1"]),
        numberedShard("test/b.test.js", "impl/two.js", "two", ["m1"]),
      ],
      passing,
    ),
    {
      passed: 2,
      requiredCalled: 2,
      requiredTotal: 2,
      requiredMembersCalled: 0,
      requiredMembersTotal: 0,
      requiredConstructorsCalled: 0,
      requiredConstructorsTotal: 0,
      externalCalls: 2,
      referenceFallbacks: 0,
      uncarriedResults: 0,
    },
  );
  assert.throws(
    () =>
      verifySelectionEvidence(
        twoModules,
        [
          [
            ...numberedShard("test/a.test.js", "impl/one.js", "one", []),
            { event: "call", operation: "unrelated" },
          ],
          numberedShard("test/b.test.js", "impl/two.js", "two", ["m1"]),
        ],
        passing,
      ),
    /required exports 1\/2 called; not called: impl\/one\.js one/,
  );
});

test("one call cannot satisfy two exports that share an ID across modules", () => {
  const single = { ...twoModules, testCount: 1, tests: [{ file: "test/a.test.js" }] };
  const shared = [
    { event: "capabilities", entry: "test/a.test.js" },
    {
      event: "module",
      sourceModule: "impl/one.js",
      members: [{ id: "shared", sourceExport: "one" }],
    },
    {
      event: "module",
      sourceModule: "impl/two.js",
      members: [{ id: "shared", sourceExport: "two" }],
    },
    { event: "call", operation: "shared" },
    { event: "final", entry: "test/a.test.js", externalCalls: 1, referenceFallbacks: 0 },
  ];
  assert.throws(
    () =>
      verifySelectionEvidence(single, [shared], caseReport({ "test/a.test.js": { passed: 1 } })),
    /member ID shared /,
  );
});

const bothCalled = [shard("test/a.test.js", ["op-1"]), shard("test/b.test.js", ["op-2"])];

for (const count of ["todo", "skipped", "cancelled", "failed"]) {
  test(`a named selection fails when a case ends as ${count}`, () => {
    assert.throws(
      () =>
        verifySelectionEvidence(
          selection,
          bothCalled,
          caseReport({ "test/a.test.js": { passed: 1 }, "test/b.test.js": { [count]: 1 } }),
        ),
      new RegExp(`passed 1/2; .*${count} 1.*; test/b\\.test\\.js: ${count} 1$`),
    );
  });
}

test("a named selection fails when its passed cases differ from the manifest's count", () => {
  assert.throws(
    () => verifySelectionEvidence({ ...selection, testCount: 3 }, bothCalled, passing),
    /passed 2 tests, expected 3/,
  );
  assert.throws(
    () =>
      verifySelectionEvidence(
        selection,
        bothCalled,
        caseReport({ "test/a.test.js": { passed: 2 }, "test/b.test.js": { passed: 1 } }),
      ),
    /passed 3 tests, expected 2/,
  );
});

test("a named selection fails when a selected file registered no case", () => {
  assert.throws(
    () =>
      verifySelectionEvidence(
        selection,
        bothCalled,
        caseReport({ "test/a.test.js": { passed: 2 } }),
      ),
    /selected file test\/b\.test\.js registered no case/,
  );
});

test("a named selection fails when the report names a file outside the selection", () => {
  assert.throws(
    () =>
      verifySelectionEvidence(
        selection,
        bothCalled,
        caseReport({
          "test/a.test.js": { passed: 1 },
          "test/b.test.js": { passed: 1 },
          "test/c.test.js": { passed: 1 },
        }),
      ),
    /case report names test\/c\.test\.js, which the selection does not/,
  );
});

test("a named selection fails without the reporter's final report", () => {
  for (const missing of [undefined, "", "\n"])
    assert.throws(
      () => verifySelectionEvidence(selection, bothCalled, missing),
      /no case report from its test reporter/,
    );
});

test("a named selection fails on a malformed case report", () => {
  const good = JSON.parse(passing);
  const malformed = [
    "{",
    "[]",
    JSON.stringify({ ...good, version: 2 }),
    JSON.stringify({ ...good, files: [] }),
    JSON.stringify({ version: 1, files: good.files }),
    JSON.stringify({ ...good, node: { ...good.node, todo: -1 } }),
    JSON.stringify({ ...good, node: { ...good.node, extra: 0 } }),
    JSON.stringify({
      ...good,
      files: { ...good.files, "test/a.test.js": { ...good.files["test/a.test.js"], passed: 1.5 } },
    }),
    // a file's cases do not add up to its registered count
    JSON.stringify({
      ...good,
      files: { ...good.files, "test/a.test.js": { ...good.files["test/a.test.js"], tests: 2 } },
    }),
  ];
  for (const text of malformed)
    assert.throws(
      () => verifySelectionEvidence(selection, bothCalled, text),
      /case report is malformed/,
      text,
    );
});

test("a named selection fails when the reporter's counts differ from Node's run summary", () => {
  const good = JSON.parse(passing);
  assert.throws(
    () =>
      verifySelectionEvidence(
        selection,
        bothCalled,
        JSON.stringify({ ...good, node: { ...good.node, tests: 3, failed: 1 } }),
      ),
    /reporter counted tests 2, passed 2, failed 0, .*; Node's run summary says tests 3, passed 2, failed 1/,
  );
});

/**
 * One process's shard in which `open` returns a handle whose class declares
 * `add` and `later`, and the listed operations are called.
 *
 * @param {string} entry @param {string[]} operations
 */
function objectShard(entry, operations) {
  return [
    { event: "capabilities", entry },
    {
      event: "module",
      sourceModule: "core/counter.js",
      members: [{ id: "op-1", sourceExport: "open" }],
      classes: [
        {
          id: "class-1",
          sourceExport: "Counter",
          members: [
            { id: "op-2", sourceMember: "add", callShape: "sync" },
            { id: "op-3", sourceMember: "later", callShape: "async" },
          ],
        },
      ],
    },
    ...operations.map((operation) => ({ event: "call", operation })),
    { event: "final", entry, externalCalls: operations.length, referenceFallbacks: 0 },
  ];
}

const objectSelection = Object.freeze({
  name: "fixture",
  testCount: 1,
  tests: [{ file: "test/a.test.js" }],
  required: [
    { module: "core/counter.js", exports: ["open"] },
    { module: "core/counter.js", class: "Counter", members: ["add"] },
  ],
});
const onePassing = caseReport({ "test/a.test.js": { passed: 1 } });

test("a required class member counts only when the test target answered it", () => {
  assert.deepEqual(
    verifySelectionEvidence(
      objectSelection,
      [objectShard("test/a.test.js", ["op-1", "op-2"])],
      onePassing,
    ),
    {
      passed: 1,
      requiredCalled: 1,
      requiredTotal: 1,
      requiredMembersCalled: 1,
      requiredMembersTotal: 1,
      requiredConstructorsCalled: 0,
      requiredConstructorsTotal: 0,
      externalCalls: 2,
      referenceFallbacks: 0,
      uncarriedResults: 0,
    },
  );
  // The factory alone does not show that the object it returned was used in the target.
  assert.throws(
    () =>
      verifySelectionEvidence(
        objectSelection,
        [objectShard("test/a.test.js", ["op-1", "op-3"])],
        onePassing,
      ),
    /required members 0\/1 called; not called: core\/counter\.js Counter#add/,
  );
});

/**
 * One process's shard in which the test target claims the constructor of
 * `Counter` and the listed operations are called.
 *
 * @param {string} entry @param {string[]} operations
 */
function constructorShard(entry, operations) {
  const [capabilities, module, ...rest] = objectShard(entry, operations);
  const [counter] = /** @type {any} */ (module).classes;
  const classes = [{ ...counter, construct: { id: "new-1" } }];
  return [capabilities, { ...module, classes }, ...rest];
}

const constructorSelection = Object.freeze({
  name: "fixture",
  testCount: 1,
  tests: [{ file: "test/a.test.js" }],
  required: [{ module: "core/counter.js", class: "Counter", members: ["add"] }],
  constructors: [{ module: "core/counter.js", class: "Counter" }],
});

test("an opted-in constructor counts only when the test target constructed the class", () => {
  assert.deepEqual(
    verifySelectionEvidence(
      constructorSelection,
      [constructorShard("test/a.test.js", ["new-1", "op-2"])],
      onePassing,
    ),
    {
      passed: 1,
      requiredCalled: 0,
      requiredTotal: 0,
      requiredMembersCalled: 1,
      requiredMembersTotal: 1,
      requiredConstructorsCalled: 1,
      requiredConstructorsTotal: 1,
      externalCalls: 2,
      referenceFallbacks: 0,
      uncarriedResults: 0,
    },
  );
  assert.throws(
    () =>
      verifySelectionEvidence(
        constructorSelection,
        [constructorShard("test/a.test.js", ["op-2"])],
        onePassing,
      ),
    /required constructors 0\/1 called; not called: new core\/counter\.js Counter/,
  );
});

test("a named exclusion names one case by its file, its exact name and a reason", () => {
  const exclusion = {
    file: "test-reference/example/cases.test.js",
    name: "a case, (with) punctuation*",
    reason: "a value the bridge cannot carry",
  };
  assert.deepEqual(namedExclusions(JSON.stringify({ version: 1, exclusions: [exclusion] })), [
    exclusion,
  ]);
  const refused = [
    ["not json", /DCA_BRIDGE_EXCLUSIONS holds JSON/],
    [JSON.stringify({ version: 2, exclusions: [exclusion] }), /version 1/],
    [JSON.stringify({ version: 1, exclusions: [exclusion], extra: 1 }), /version 1/],
    [JSON.stringify({ version: 1, exclusions: [{ ...exclusion, reason: "" }] }), /file, name/],
    [JSON.stringify({ version: 1, exclusions: [{ ...exclusion, extra: 1 }] }), /file, name/],
    [JSON.stringify({ version: 1, exclusions: [{ ...exclusion, file: "x.js" }] }), /file, name/],
    [
      JSON.stringify({ version: 1, exclusions: [{ ...exclusion, file: "../outside.test.js" }] }),
      /file, name/,
    ],
    [JSON.stringify({ version: 1, exclusions: [exclusion, exclusion] }), /once/],
  ];
  for (const [text, message] of refused)
    assert.throws(() => namedExclusions(/** @type {string} */ (text)), message);
});

test("a named exclusion skips exactly its own name", () => {
  const [argument] = exclusionArguments([
    { file: "a.test.js", name: "a case, (with) punctuation*", reason: "why" },
  ]);
  assert.equal(argument, "--test-skip-pattern=^a case, \\(with\\) punctuation\\*$");
  const pattern = new RegExp(argument.slice("--test-skip-pattern=".length));
  assert.equal(pattern.test("a case, (with) punctuation*"), true);
  assert.equal(pattern.test("a case, (with) punctuation* and more"), false);
  assert.equal(pattern.test("a case, with punctuation"), false);
});
