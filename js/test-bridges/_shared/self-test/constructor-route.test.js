// What this test proves about routing `new X` to the test target.
//
// A strict run constructs a reference class on the reference unless the run
// opts that class in. An opted-in class export becomes a stand-in: `new X(...)`
// builds the test target's object and answers its handle proxy, and a class
// the test target does not construct fails before dispatch instead of running
// the reference constructor. The test target here is a JavaScript tree whose
// module at the reference path of `DcaRequest.js` holds a neutral counter
// class under that export name; nothing in it follows the reference class.

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const ROUTED = "core-shared--client-issuer/DcaRequest.js";
const ABSENT = "core-client/ResponseAssociation.js";

/** @param {string} path */
const url = (path) => JSON.stringify(pathToFileURL(join(root, path)).href);

// The test target throws the reference's own error class, which the driver
// maps back to the class the probe imports.
const TARGET = `import { DcaError } from "../core-shared/errors.js";
export class DcaRequest {
  #total;
  constructor(start) {
    if (typeof start !== "number" || start < 0)
      throw new DcaError("bad_start", "a tally starts at a non-negative number");
    this.#total = start;
  }
  add(step) { this.#total += step; return this.#total; }
}
`;

// A preload that starts the js bridge with an explicit constructor opt-in.
const PRELOAD = `import { defineBridge } from ${url("test-bridges/_shared/bridge-definition.mjs")};
import { registerBridge } from ${url("test-bridges/_shared/register.mjs")};
const active = await registerBridge(
  defineBridge({ id: "js", adapter: ${JSON.stringify(join(root, "test-bridges/js/adapter.mjs"))}, targetRoot: process.env.DCA_TARGET_ROOT }),
  { mode: process.env.PROBE_MODE, constructors: JSON.parse(process.env.PROBE_CONSTRUCTORS) },
);
process.once("beforeExit", () => active.dispose());
`;

const ROUTED_PROBE = `import test from "node:test";
import assert from "node:assert/strict";
import { DcaRequest } from ${url(ROUTED)};
import { DcaError } from ${url("core-shared/errors.js")};
test("probe", () => {
  const first = new DcaRequest(5);
  assert.equal(first.add(1), 6, "the test target's object holds its start");
  const second = new DcaRequest(10);
  assert.notEqual(second, first);
  assert.equal(second.add(0), 10);
  assert.equal(first.add(0), 6);
  assert.throws(
    () => new DcaRequest(-1),
    (error) =>
      error instanceof DcaError &&
      error.code === "bad_start" &&
      error.message === "a tally starts at a non-negative number",
  );
  // Limits the route states, not reference behavior it borrows.
  assert.equal(first instanceof DcaRequest, false);
  assert.equal(Object.getPrototypeOf(first), null);
  assert.throws(() => DcaRequest(1), /is a class; construct it with new/);
  class Derived extends DcaRequest {}
  assert.throws(() => new Derived(1), /a routed class cannot be subclassed/);
});
`;

const ABSENT_PROBE = `import test from "node:test";
import assert from "node:assert/strict";
import { DcaRequest } from ${url(ROUTED)};
import { ResponseAssociation } from ${url(ABSENT)};
test("probe", () => {
  assert.equal(new DcaRequest(1).add(1), 2);
  assert.throws(
    () => new ResponseAssociation({}, "issuer", {}),
    /^Error: strict bridge run: new core-client\\/ResponseAssociation\\.js ResponseAssociation is not claimed by the test target$/,
  );
});
`;

const DEFAULT_PROBE = `import test from "node:test";
import assert from "node:assert/strict";
import { DcaRequest, parseDcaRequest } from ${url(ROUTED)};
test("probe", () => {
  // Without an opt-in the class export is the reference class: its
  // constructor runs locally and builds a reference instance.
  const request = new DcaRequest(5);
  assert.ok(request instanceof DcaRequest);
  assert.equal(typeof request.toObject, "function");
  assert.equal("add" in request, false);
  assert.throws(() => parseDcaRequest("x"), /is not claimed by the test target/);
});
`;

/**
 * Runs `probe` under the preload with `constructors` as the opt-in.
 *
 * @param {string} probe @param {unknown} constructors @param {string} [mode]
 */
function run(probe, constructors, mode = "strict") {
  const directory = mkdtempSync(join(tmpdir(), "dca-constructor-route-"));
  const target = join(directory, "target");
  mkdirSync(join(target, "core-shared--client-issuer"), { recursive: true });
  mkdirSync(join(target, "core-shared"), { recursive: true });
  copyFileSync(join(root, "core-shared/errors.js"), join(target, "core-shared/errors.js"));
  writeFileSync(join(target, ROUTED), TARGET);
  writeFileSync(join(directory, "preload.mjs"), PRELOAD);
  writeFileSync(join(directory, "probe.test.js"), probe);
  try {
    const environment = {
      ...process.env,
      DCA_TARGET_ROOT: target,
      PROBE_MODE: mode,
      PROBE_CONSTRUCTORS: JSON.stringify(constructors),
    };
    delete environment.NODE_TEST_CONTEXT;
    delete environment.DCA_LOG_DIR;
    delete environment.DCA_TEST_SELECTION;
    delete environment.DCA_BRIDGE_MODULES;
    delete environment.DCA_BRIDGE_MODE;
    return spawnSync(
      process.execPath,
      [
        "--import",
        join(directory, "preload.mjs"),
        "--test",
        "--test-reporter=tap",
        join(directory, "probe.test.js"),
      ],
      { cwd: root, env: environment, encoding: "utf8" },
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("an opted-in class builds the test target's object and answers its handle proxy", () => {
  const result = run(ROUTED_PROBE, [{ module: ROUTED, class: "DcaRequest" }]);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /^# pass 1$/m);
});

test("an opted-in class the test target does not construct fails before any reference constructor runs", () => {
  const result = run(ABSENT_PROBE, [
    { module: ROUTED, class: "DcaRequest" },
    { module: ABSENT, class: "ResponseAssociation" },
  ]);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /^# pass 1$/m);
});

test("a class no opt-in names stays the reference class", () => {
  const result = run(DEFAULT_PROBE, []);
  // The probe crosses nothing, so the strict run then fails as empty.
  assert.match(result.stdout, /^# pass 1$/m, result.stdout + result.stderr);
  assert.match(result.stdout + result.stderr, /strict bridge run made no external calls/);
});

test("an opt-in names a class export of the reference module, in a strict run", () => {
  const notClass = run(ROUTED_PROBE, [{ module: ROUTED, class: "parseDcaRequest" }]);
  assert.notEqual(notClass.status, 0);
  assert.match(
    notClass.stdout + notClass.stderr,
    /constructor opt-in names core-shared--client-issuer\/DcaRequest\.js parseDcaRequest, which the reference module does not export as a class/,
  );
  const overlay = run(ROUTED_PROBE, [{ module: ROUTED, class: "DcaRequest" }], "overlay");
  assert.notEqual(overlay.status, 0);
  assert.match(
    overlay.stdout + overlay.stderr,
    /constructor opt-ins route classes of a strict run/,
  );
});
