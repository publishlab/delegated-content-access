import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const runner = join(root, "test-bridges/_shared/run.mjs");

function run(selection, logs, target) {
  return spawnSync(process.execPath, [runner, selection], {
    cwd: root,
    env: {
      ...process.env,
      NODE_TEST_CONTEXT: undefined,
      DCA_BRIDGE: target ? "js" : "js-loopback",
      DCA_TARGET_ROOT: target,
      DCA_LOG_DIR: logs,
    },
    encoding: "utf8",
  });
}

function records(logs) {
  return readdirSync(logs, { recursive: true, encoding: "utf8" })
    .filter((file) => file.endsWith(".transcript.jsonl"))
    .flatMap((file) => readFileSync(join(logs, file), "utf8").trim().split("\n").map(JSON.parse));
}

for (const [selection, calls, constructors] of [
  ["portable-client-cache-ownership", 10, 2],
  ["portable-sealer-ownership", 8, 0],
]) {
  test(`${selection} crosses its ownership assertions without fallback`, () => {
    const directory = mkdtempSync(join(tmpdir(), "dca-ownership-selection-"));
    try {
      const child = run(selection, directory);
      assert.ifError(child.error);
      assert.equal(child.status, 0, child.stdout + child.stderr);
      assert.match(child.stdout, /^# pass 1$/m);
      assert.match(child.stderr, /required members 3\/3 called/);
      if (constructors) assert.match(child.stderr, /required constructors 2\/2 called/);
      else assert.match(child.stderr, /required exports 1\/1 called/);
      const finals = records(directory).filter((record) => record.event === "final");
      assert.equal(finals.length, 1);
      assert.equal(finals[0].lifecycle, "disposed");
      assert.equal(finals[0].mode, "strict");
      assert.equal(finals[0].externalCalls, calls);
      assert.equal(finals[0].referenceFallbacks, 0);
      assert.equal(finals[0].uncarriedResults, 0);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}

// Deliberately broken targets exercise the same shared assertions. They wrap
// real reference objects; the test driver still owns every expected result.
for (const selection of ["portable-client-cache-ownership", "portable-sealer-ownership"]) {
  test(`${selection} rejects a broken target's ownership behavior`, () => {
    const directory = mkdtempSync(join(tmpdir(), "dca-broken-ownership-"));
    const target = join(directory, "target");
    function source(module, code) {
      const path = join(target, module);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, code);
    }
    const original = (module) => JSON.stringify(pathToFileURL(join(root, module)).href);
    try {
      source("package.json", '{"type":"module"}');
      if (selection === "portable-client-cache-ownership") {
        source(
          "adapter-client/PeriodKeyCache.js",
          `export { PeriodKeyCache } from ${original("adapter-client/PeriodKeyCache.js")};`,
        );
        source(
          "core-client/ContentKeyResolver.js",
          `import { ContentKeyResolver as Resolver } from ${original("core-client/ContentKeyResolver.js")};
           export class ContentKeyResolver extends Resolver { async clearReaderContext() {} }`,
        );
      } else {
        source(
          "core-publisher/Sealer.js",
          `export { Sealer } from ${original("core-publisher/Sealer.js")};`,
        );
        source(
          "core-publisher/testing/sealerFactory.js",
          `import { sealerForRender as create } from ${original("core-publisher/testing/sealerFactory.js")};
           let shared;
           export async function sealerForRender(setup) { return shared ??= await create(setup); }`,
        );
      }
      const logs = join(directory, "logs");
      const child = run(selection, logs, target);
      assert.ifError(child.error);
      assert.notEqual(child.status, 0, child.stdout + child.stderr);
      assert.match(child.stdout, /^# fail 1$/m);
      assert.match(
        child.stdout,
        selection === "portable-client-cache-ownership"
          ? /Expected values to be strictly deep-equal/
          : /Expected "actual" not to be reference-equal/,
      );
      const finals = records(logs).filter((record) => record.event === "final");
      assert.equal(finals.length, 1);
      assert.ok(finals[0].externalCalls > 0);
      assert.equal(finals[0].referenceFallbacks, 0);
      assert.equal(finals[0].uncarriedResults, 0);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
