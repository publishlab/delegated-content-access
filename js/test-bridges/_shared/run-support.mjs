import { existsSync, readdirSync, readFileSync } from "node:fs";
import { isAbsolute, join, normalize, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CASE_COUNT_NAMES } from "./run-reporter.mjs";
import { isIdentifier, isSafeModulePath } from "./routing.mjs";

const bridgesRoot = fileURLToPath(new URL("../", import.meta.url));
const runReporter = fileURLToPath(new URL("./run-reporter.mjs", import.meta.url));
const BRIDGE_ID = /^[a-z][a-z0-9-]*$/;

/**
 * The bridge IDs shipped beside `_shared/`: each kebab-case directory that
 * holds a `bridge.mjs`. A leading `_` or `.` marks a directory that is not a
 * bridge.
 */
export function bridgeIds() {
  return readdirSync(bridgesRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && BRIDGE_ID.test(entry.name))
    .filter((entry) => existsSync(join(bridgesRoot, entry.name, "bridge.mjs")))
    .map((entry) => entry.name)
    .sort();
}

/**
 * Resolves `DCA_BRIDGE` to a bridge module path. A value ending in `.mjs` is a
 * path, relative to `cwd`; any other value is a bridge ID.
 *
 * @param {string} value @param {string} cwd
 */
export function bridgeModule(value, cwd) {
  if (value.endsWith(".mjs")) return resolve(cwd, value);
  const path = join(bridgesRoot, value, "bridge.mjs");
  if (BRIDGE_ID.test(value) && existsSync(path)) return path;
  throw new Error(
    `DCA_BRIDGE "${value}" names no bridge; bridge IDs: ${bridgeIds().join(", ")}; or a path to a bridge.mjs`,
  );
}

/** @param {string} root @param {string} candidate */
function selectionPath(root, candidate) {
  if (!/^[a-z][a-z0-9-]*$/.test(candidate))
    throw new Error("selection names are lowercase kebab-case");
  return resolve(root, "test-bridges", "_shared", "selections", `${candidate}.json`);
}

/** @param {string} root @param {string} candidate */
function selectorPath(root, candidate) {
  if (!candidate.endsWith(".test.js")) throw new Error("selection files are .test.js paths");
  if (isAbsolute(candidate)) throw new Error("selection files stay under js");
  const absolute = resolve(root, candidate);
  const containment = relative(resolve(root), absolute);
  if (
    containment === "" ||
    containment === ".." ||
    containment.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)
  )
    throw new Error("selection files stay under js");
  return absolute;
}

/** The top-level members a selection manifest may hold; any other is refused. */
const SELECTION_MEMBERS = ["version", "testCount", "tests", "required", "inputs", "constructors"];

/**
 * Loads a named portable selection. Test-local metadata decides which cases
 * register; this manifest owns the files, expected count and required routes.
 *
 * @param {{ v1Root: string, name: string }} options
 */
export function portableSelection({ v1Root, name }) {
  let document;
  try {
    document = JSON.parse(readFileSync(selectionPath(v1Root, name), "utf8"));
  } catch (error) {
    if (error instanceof SyntaxError)
      throw new Error(`selection ${name} is valid JSON`, { cause: error });
    throw error;
  }
  if (!document || typeof document !== "object" || Array.isArray(document))
    throw new TypeError("selection is an object");
  for (const member of Object.keys(document)) {
    if (!SELECTION_MEMBERS.includes(member))
      throw new TypeError(
        `selection has no member ${member}; it reads ${SELECTION_MEMBERS.slice(0, -1).join(", ")} and ${SELECTION_MEMBERS.at(-1)}`,
      );
  }
  const selection =
    /** @type {{ version?: unknown, testCount?: unknown, tests?: unknown, required?: unknown }} */ (
      document
    );
  if (selection.version !== 1) throw new TypeError("selection version is 1");
  if (!Number.isSafeInteger(selection.testCount) || Number(selection.testCount) <= 0)
    throw new TypeError("selection testCount is a positive safe integer");
  if (!Array.isArray(selection.tests) || selection.tests.length === 0)
    throw new TypeError("selection has tests");
  if (!Array.isArray(selection.required) || selection.required.length === 0)
    throw new TypeError("selection has required operations");
  const files = new Set();
  const tests = selection.tests.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry))
      throw new TypeError("selection tests are objects");
    const test = /** @type {{ file?: unknown }} */ (entry);
    if (typeof test.file !== "string") throw new TypeError("selection tests name a file");
    if (files.has(test.file)) throw new TypeError("selection test files are unique");
    files.add(test.file);
    selectorPath(v1Root, test.file);
    readFileSync(selectorPath(v1Root, test.file), "utf8");
    return Object.freeze({ file: test.file });
  });
  const required = selection.required.map(selectionRequirement);
  const inputs = selectionInputs(/** @type {{ inputs?: unknown }} */ (selection).inputs);
  const constructors = selectionConstructors(
    /** @type {{ constructors?: unknown }} */ (selection).constructors,
  );
  for (const constructor of constructors) {
    const mapped = inputs.some(
      (mapping) =>
        mapping.class.module === constructor.module && mapping.class.export === constructor.class,
    );
    if (mapped)
      throw new TypeError(
        `selection constructors name ${constructor.module} ${constructor.class}, which an input mapping sends as data`,
      );
  }
  return Object.freeze({
    name,
    tests: Object.freeze(tests),
    required: Object.freeze(required),
    inputs,
    constructors,
    testCount: Number(selection.testCount),
  });
}

/**
 * A selection's constructor opt-ins. Each names one reference class whose
 * `new` the run routes to the test target; the selection then requires that
 * constructor to be called. A selection without `constructors` routes none.
 *
 * @param {unknown} constructors @returns {readonly { module: string, class: string }[]}
 */
function selectionConstructors(constructors) {
  if (constructors === undefined) return Object.freeze([]);
  if (!Array.isArray(constructors)) throw new TypeError("selection constructors are a list");
  const listed = new Set();
  return Object.freeze(
    constructors.map((entry) => {
      const constructor = /** @type {any} */ (entry);
      const exact = hasExactMembers(constructor, ["module", "class"]);
      const valid =
        exact && isSafeModulePath(constructor.module) && isIdentifier(constructor.class);
      if (!valid) throw new TypeError("selection constructors name a module and a class");
      const key = `${constructor.module}\0${constructor.class}`;
      if (listed.has(key)) throw new TypeError("selection constructors list each class once");
      listed.add(key);
      return Object.freeze({ module: constructor.module, class: constructor.class });
    }),
  );
}

/**
 * A required operation: exports of a module, or instance members of a class
 * that a module's test target claims.
 *
 * @typedef {{ module: string, exports: readonly string[] } | { module: string, class: string, members: readonly string[] }} Requirement
 */

/** @param {unknown} value */
function isNameList(value) {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((name) => typeof name === "string" && name.length > 0)
  );
}

/**
 * One entry of a selection's `required`: a module and its exports, or a
 * module, a class it exports and that class's members.
 *
 * @param {unknown} entry @returns {Requirement}
 */
function selectionRequirement(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry))
    throw new TypeError("selection required operations are objects");
  const requirement =
    /** @type {{ module?: unknown, exports?: unknown, class?: unknown, members?: unknown }} */ (
      entry
    );
  const module = requirement.module;
  const inModule = typeof module === "string" && module.endsWith(".js");
  const exportsForm =
    hasExactMembers(requirement, ["module", "exports"]) && isNameList(requirement.exports);
  const membersForm =
    hasExactMembers(requirement, ["module", "class", "members"]) &&
    typeof requirement.class === "string" &&
    isIdentifier(requirement.class) &&
    isNameList(requirement.members);
  if (!inModule || (!exportsForm && !membersForm))
    throw new TypeError(
      "selection required operations name a module and exports, or a module, class and members",
    );
  if (exportsForm)
    return Object.freeze({
      module: /** @type {string} */ (module),
      exports: Object.freeze([.../** @type {string[]} */ (requirement.exports)]),
    });
  return Object.freeze({
    module: /** @type {string} */ (module),
    class: /** @type {string} */ (requirement.class),
    members: Object.freeze([.../** @type {string[]} */ (requirement.members)]),
  });
}

/** @typedef {{ module: string, export: string, argument: number, class: { module: string, export: string }, data: string }} InputMapping */

/** @param {unknown} value @param {string[]} names */
function hasExactMembers(value, names) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...names].sort();
  return (
    actual.length === expected.length && actual.every((name, index) => name === expected[index])
  );
}

/**
 * A selection's input mappings. Each names one argument of one reference
 * export that the driver sends as the data of a class instance, and the class
 * and data method that give it. A selection without `inputs` maps nothing.
 *
 * @param {unknown} inputs @returns {readonly InputMapping[]}
 */
function selectionInputs(inputs) {
  if (inputs === undefined) return Object.freeze([]);
  if (!Array.isArray(inputs)) throw new TypeError("selection inputs are a list");
  const listed = new Set();
  return Object.freeze(
    inputs.map((entry) => {
      const mapping = /** @type {any} */ (entry);
      if (
        !hasExactMembers(mapping, ["module", "export", "argument", "class", "data"]) ||
        !hasExactMembers(mapping.class, ["module", "export"]) ||
        !isSafeModulePath(mapping.module) ||
        !isSafeModulePath(mapping.class.module) ||
        !isIdentifier(mapping.export) ||
        !isIdentifier(mapping.class.export) ||
        !isIdentifier(mapping.data) ||
        !Number.isSafeInteger(mapping.argument) ||
        mapping.argument < 0
      )
        throw new TypeError(
          "selection inputs name a module, export, argument index, class module and export, and data method",
        );
      const key = `${mapping.module}\0${mapping.export}\0${mapping.argument}`;
      if (listed.has(key)) throw new TypeError("selection inputs list each argument once");
      listed.add(key);
      return Object.freeze({
        module: mapping.module,
        export: mapping.export,
        argument: mapping.argument,
        class: Object.freeze({ module: mapping.class.module, export: mapping.class.export }),
        data: mapping.data,
      });
    }),
  );
}

/** The case report's file name in a named selection's run directory. */
export const CASE_REPORT = "case-counts.json";

/**
 * Node's arguments for a named selection. Node's own stream goes to stdout,
 * spec on a terminal and TAP otherwise, as in a run without a reporter; the
 * run reporter writes the case report to `reportPath`.
 *
 * @param {{ tests: readonly { file: string }[] }} selection
 * @param {{ reportPath: string, environment?: NodeJS.ProcessEnv, interactive?: boolean }} options
 */
export function portableSelectionArguments(
  selection,
  { reportPath, environment = process.env, interactive = process.stdout.isTTY === true },
) {
  return [
    "--experimental-test-isolation=process",
    `--test-concurrency=${environment.DCA_NODE_TEST_CONCURRENCY ?? 1}`,
    `--test-reporter=${interactive ? "spec" : "tap"}`,
    "--test-reporter-destination=stdout",
    `--test-reporter=${runReporter}`,
    `--test-reporter-destination=${reportPath}`,
    "--test",
    ...selection.tests.map((test) => test.file),
  ];
}

/** @param {string} packagePath */
export function publicSelectors(packagePath) {
  const manifest = JSON.parse(readFileSync(packagePath, "utf8"));
  const script = manifest.scripts?.["test:reference:public"];
  if (typeof script !== "string")
    throw new Error("package.json has no test:reference:public script");
  const selectors = [...script.matchAll(/"([^"\n]*\.test\.js)"/g)].map((match) => match[1]);
  if (selectors.length === 0) throw new Error("test:reference:public has no quoted test selectors");
  return selectors;
}

/** @typedef {{ file: string, name: string, reason: string }} NamedExclusion */

/**
 * Reads a named exclusion list, the file `DCA_BRIDGE_EXCLUSIONS` names:
 * `{ "version": 1, "exclusions": [{ "file", "name", "reason" }] }`. Each entry
 * names one case by its test file under js, its exact name and why the run
 * skips it. A pair of file and name appears once.
 *
 * @param {string} text
 * @returns {readonly NamedExclusion[]}
 */
export function namedExclusions(text) {
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    throw new Error("DCA_BRIDGE_EXCLUSIONS holds JSON");
  }
  const versioned =
    document !== null &&
    typeof document === "object" &&
    !Array.isArray(document) &&
    hasExactMembers(document, ["version", "exclusions"]) &&
    document.version === 1 &&
    Array.isArray(document.exclusions);
  if (!versioned) throw new Error("DCA_BRIDGE_EXCLUSIONS holds version 1 and a list of exclusions");
  const exclusions = /** @type {unknown[]} */ (document.exclusions);
  if (!exclusions.every(isNamedExclusion))
    throw new Error(
      "each named exclusion has a file, name and reason: a .test.js path under js and two non-empty strings",
    );
  const entries = /** @type {NamedExclusion[]} */ (exclusions);
  const pairs = new Set(
    entries.map((entry) => JSON.stringify([normalize(entry.file), entry.name])),
  );
  if (pairs.size !== entries.length)
    throw new Error("DCA_BRIDGE_EXCLUSIONS names each case of a file once");
  return Object.freeze(
    entries.map((entry) =>
      Object.freeze({ file: entry.file, name: entry.name, reason: entry.reason }),
    ),
  );
}

/** @param {unknown} value */
function isNamedExclusion(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const entry = /** @type {{ file?: unknown, name?: unknown, reason?: unknown }} */ (value);
  const exact = hasExactMembers(value, ["file", "name", "reason"]);
  const filed = typeof entry.file === "string" && isTestFilePath(entry.file);
  const named = typeof entry.name === "string" && entry.name.length > 0;
  const reasoned = typeof entry.reason === "string" && entry.reason.length > 0;
  return exact && filed && named && reasoned;
}

/** @param {string} path */
function isTestFilePath(path) {
  const segments = normalize(path).split("/");
  const contained = !isAbsolute(path) && !segments.includes("..");
  return contained && path.endsWith(".test.js");
}

/**
 * The exclusions of one test file, by its path under js.
 *
 * @param {readonly NamedExclusion[]} exclusions @param {string} file
 */
export function exclusionsOf(exclusions, file) {
  return exclusions.filter((entry) => normalize(entry.file) === normalize(file));
}

/**
 * Node's arguments that skip each excluded case: an anchored pattern of its
 * exact name, so no other case matches it.
 *
 * @param {readonly NamedExclusion[]} exclusions
 */
export function exclusionArguments(exclusions) {
  return exclusions.map(
    (entry) => `--test-skip-pattern=^${entry.name.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&")}$`,
  );
}

/** @param {{ packagePath: string, v1Root: string, arguments_: string[], environment?: NodeJS.ProcessEnv }} options */
export function runnerArguments({ packagePath, v1Root, arguments_, environment = process.env }) {
  const [selection = "public", ...extra] = arguments_;
  if (extra.length > 0) throw new Error("runner takes public or one explicit .test.js path");
  const selectors =
    selection === "public" ? publicSelectors(packagePath) : [explicitSelector(v1Root, selection)];
  return [
    `--experimental-test-isolation=${environment.DCA_NODE_TEST_ISOLATION ?? "process"}`,
    "--test",
    ...selectors,
  ];
}

/** @param {string} root @param {string} candidate */
function explicitSelector(root, candidate) {
  if (!candidate.endsWith(".test.js")) throw new Error("explicit selection is one .test.js path");
  if (isAbsolute(candidate)) throw new Error("explicit selection stays under js");
  const absolute = resolve(root, candidate);
  const containment = relative(resolve(root), absolute);
  if (
    containment === "" ||
    containment === ".." ||
    containment.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)
  )
    throw new Error("explicit selection stays under js");
  return candidate;
}

/** @typedef {import("./run-reporter.mjs").CaseCounts} CaseCounts */

/** @param {unknown} value @param {string} where @returns {CaseCounts} */
function caseCounts(value, where) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`case report is malformed: ${where} is not an object`);
  const names = Object.keys(value).sort();
  if (names.join() !== [...CASE_COUNT_NAMES].sort().join())
    throw new Error(`case report is malformed: ${where} holds ${names.join(", ")}`);
  const record = /** @type {Record<string, unknown>} */ (value);
  for (const name of CASE_COUNT_NAMES)
    if (!Number.isSafeInteger(record[name]) || Number(record[name]) < 0)
      throw new Error(`case report is malformed: ${where} ${name} is not a count`);
  const counts = /** @type {CaseCounts} */ (record);
  if (
    counts.tests !==
    counts.passed + counts.failed + counts.cancelled + counts.skipped + counts.todo
  )
    throw new Error(`case report is malformed: ${where} does not add up to its tests`);
  return counts;
}

/** @param {CaseCounts} counts @param {readonly (keyof CaseCounts)[]} [names] */
function listCounts(counts, names = CASE_COUNT_NAMES) {
  return names.map((name) => `${name} ${counts[name]}`).join(", ");
}

/**
 * Parses the run reporter's case report, refusing a missing or malformed one.
 *
 * @param {string | undefined} text
 */
function caseReport(text) {
  if (text === undefined || text.trim() === "")
    throw new Error("portable selection has no case report from its test reporter");
  let document;
  try {
    document = JSON.parse(text);
  } catch (error) {
    throw new Error("portable selection case report is malformed: not JSON", { cause: error });
  }
  if (!document || typeof document !== "object" || Array.isArray(document))
    throw new Error("portable selection case report is malformed: not an object");
  if (document.version !== 1)
    throw new Error("portable selection case report is malformed: version is not 1");
  if (!document.files || typeof document.files !== "object" || Array.isArray(document.files))
    throw new Error("portable selection case report is malformed: files is not an object");
  /** @type {Map<string, CaseCounts>} */
  const files = new Map();
  for (const [file, counts] of Object.entries(document.files))
    files.set(file, caseCounts(counts, `file ${file}`));
  return { files, node: caseCounts(document.node, "Node's run summary") };
}

/**
 * Checks the case report: every selected file registered cases, every case
 * passed, and the passed count equals the manifest's.
 *
 * @param {{ testCount: number, tests: readonly { file: string }[] }} selection
 * @param {string | undefined} reportText
 */
function verifyCaseCounts(selection, reportText) {
  const { files, node } = caseReport(reportText);
  /** @type {CaseCounts} */
  const total = { tests: 0, passed: 0, failed: 0, cancelled: 0, skipped: 0, todo: 0 };
  for (const counts of files.values())
    for (const name of CASE_COUNT_NAMES) total[name] += counts[name];
  if (CASE_COUNT_NAMES.some((name) => total[name] !== node[name]))
    throw new Error(
      `portable selection reporter counted ${listCounts(total)}; Node's run summary says ${listCounts(node)}`,
    );
  const selected = new Set(selection.tests.map((test) => test.file));
  for (const file of files.keys())
    if (!selected.has(file))
      throw new Error(`portable selection case report names ${file}, which the selection does not`);
  for (const file of selected)
    if ((files.get(file)?.tests ?? 0) === 0)
      throw new Error(`selected file ${file} registered no case`);
  /** @type {(keyof CaseCounts)[]} */
  const unpassed = ["failed", "cancelled", "skipped", "todo"];
  if (unpassed.some((name) => total[name] !== 0)) {
    const byFile = [...files]
      .filter(([, counts]) => unpassed.some((name) => counts[name] !== 0))
      .map(
        ([file, counts]) =>
          `${file}: ${listCounts(
            counts,
            unpassed.filter((name) => counts[name] !== 0),
          )}`,
      );
    throw new Error(
      `portable selection passed ${total.passed}/${total.tests}; ${listCounts(total, unpassed)}; ${byFile.join("; ")}`,
    );
  }
  if (total.passed !== selection.testCount)
    throw new Error(
      `portable selection passed ${total.passed} tests, expected ${selection.testCount}`,
    );
  return total.passed;
}

/**
 * Checks a named selection's case report and transcript shards against its
 * manifest. Under process isolation one shard belongs to one test file, and
 * every selected file must make at least one external call.
 *
 * @param {{ testCount: number, tests: readonly { file: string }[], required: readonly Requirement[], constructors?: readonly { module: string, class: string }[] }} selection
 * @param {any[][]} shards transcript records, one list per shard
 * @param {string | undefined} reportText the run reporter's case report
 */
export function verifySelectionEvidence(selection, shards, reportText) {
  const records = shards.flat();
  const finals = records.filter((record) => record.event === "final");
  if (finals.length === 0) throw new Error("portable selection produced no final transcript");
  const externalCalls = finals.reduce((total, record) => total + record.externalCalls, 0);
  const referenceFallbacks = finals.reduce((total, record) => total + record.referenceFallbacks, 0);
  if (referenceFallbacks !== 0) throw new Error("portable selection used a reference fallback");
  // Dispatched calls whose answer the bridge could not carry back: each one
  // failed, and none is an external call or a fallback. A case that expects a
  // throw could pass on that failure, so the selection refuses any of them.
  const uncarriedResults = finals.reduce(
    (total, record) => total + (record.uncarriedResults ?? 0),
    0,
  );
  if (uncarriedResults !== 0) {
    const operations = shards.flatMap((shard) => {
      const names = new Map(
        shard
          .filter((record) => record.event === "module")
          .flatMap((record) => [
            ...record.members.map((/** @type {any} */ member) => [
              member.id,
              `${record.sourceModule} ${member.sourceExport}`,
            ]),
            ...classMembers(record).map(({ id, name }) => [id, `${record.sourceModule} ${name}`]),
          ]),
      );
      return shard
        .filter((record) => record.event === "uncarried")
        .map((record) => names.get(record.operation) ?? record.operation);
    });
    const named = [...new Set(operations)];
    throw new Error(
      `portable selection had ${uncarriedResults} uncarried result${uncarriedResults === 1 ? "" : "s"}${named.length === 0 ? "" : `: ${named.join(", ")}`}`,
    );
  }
  /** @type {Map<string, Set<string>>} */
  const called = new Map();
  for (const shard of shards) {
    /** @type {Map<string, { sourceModule: string, sourceExport: string }>} */
    const memberOf = new Map();
    /** @param {string} id @param {string} sourceModule @param {string} sourceExport */
    const claim = (id, sourceModule, sourceExport) => {
      if (memberOf.has(id)) throw new Error(`bridge member ID ${id} claimed twice in one process`);
      memberOf.set(id, { sourceModule, sourceExport });
    };
    for (const record of shard) {
      if (record.event !== "module") continue;
      for (const member of record.members)
        claim(member.id, record.sourceModule, member.sourceExport);
      // A class member counts under `Class#member`, which no export name can spell.
      for (const { id, name } of classMembers(record)) claim(id, record.sourceModule, name);
    }
    for (const record of shard) {
      if (record.event !== "call") continue;
      const member = memberOf.get(record.operation);
      if (!member) continue;
      const exports = called.get(member.sourceModule) ?? new Set();
      called.set(member.sourceModule, exports.add(member.sourceExport));
    }
  }
  /** @type {string[]} */
  const missing = [];
  /** @type {string[]} */
  const missingMembers = [];
  let requiredTotal = 0;
  let requiredMembersTotal = 0;
  for (const requirement of selection.required) {
    const names =
      "exports" in requirement
        ? requirement.exports
        : requirement.members.map((member) => `${requirement.class}#${member}`);
    const unmet = "exports" in requirement ? missing : missingMembers;
    for (const name of names) {
      if ("exports" in requirement) requiredTotal += 1;
      else requiredMembersTotal += 1;
      if (!called.get(requirement.module)?.has(name)) unmet.push(`${requirement.module} ${name}`);
    }
  }
  // An opted-in constructor counts under `new Class`, which no export or
  // member name can spell.
  const constructors = selection.constructors ?? [];
  const missingConstructors = constructors
    .filter((constructor) => !called.get(constructor.module)?.has(`new ${constructor.class}`))
    .map((constructor) => `new ${constructor.module} ${constructor.class}`);
  const requiredConstructorsTotal = constructors.length;
  const requiredConstructorsCalled = requiredConstructorsTotal - missingConstructors.length;
  const requiredCalled = requiredTotal - missing.length;
  const requiredMembersCalled = requiredMembersTotal - missingMembers.length;
  if (missing.length > 0)
    throw new Error(
      `required exports ${requiredCalled}/${requiredTotal} called; not called: ${missing.join(", ")}`,
    );
  if (missingMembers.length > 0)
    throw new Error(
      `required members ${requiredMembersCalled}/${requiredMembersTotal} called; not called: ${missingMembers.join(", ")}`,
    );
  if (missingConstructors.length > 0)
    throw new Error(
      `required constructors ${requiredConstructorsCalled}/${requiredConstructorsTotal} called; not called: ${missingConstructors.join(", ")}`,
    );
  for (const { file } of selection.tests) {
    const calls = shards
      .filter((shard) => shard.some((record) => record.entry === file))
      .flat()
      .filter((record) => record.event === "call").length;
    if (calls === 0) throw new Error(`selected file ${file} made no external call`);
  }
  const passed = verifyCaseCounts(selection, reportText);
  return {
    passed,
    requiredCalled,
    requiredTotal,
    requiredMembersCalled,
    requiredMembersTotal,
    requiredConstructorsCalled,
    requiredConstructorsTotal,
    externalCalls,
    referenceFallbacks,
    uncarriedResults,
  };
}

/**
 * The class members a transcript's module record declares, each by its
 * operation ID and `Class#member` name, and each claimed constructor by its
 * operation ID and `new Class`.
 *
 * @param {any} record @returns {{ id: string, name: string }[]}
 */
function classMembers(record) {
  const classes = Array.isArray(record.classes) ? record.classes : [];
  return classes.flatMap((/** @type {any} */ entry) => [
    ...entry.members.map((/** @type {any} */ member) => ({
      id: member.id,
      name: `${entry.sourceExport}#${member.sourceMember}`,
    })),
    ...(entry.construct === undefined
      ? []
      : [{ id: entry.construct.id, name: `new ${entry.sourceExport}` }]),
  ]);
}
