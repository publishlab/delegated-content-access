import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { gzipSync, gunzipSync } from "node:zlib";
import { runBench } from "../runBench.js";
import { formatReport } from "../format.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const baseline = ["dca-profile-baseline"];
const fixture = (execute, extra = {}) => ({
  id: "fixture",
  defaults: { title: "A story" },
  requestedProfiles: baseline,
  execute,
  ...extra,
});

test("accounting uses exact UTF-8 wire bytes and keeps repeated physical messages", async () => {
  const report = await runBench({
    scenario: fixture(({ observe }) => {
      observe.capture(
        "dcaData",
        { title: "blå" },
        {
          text: '{ "title": "blå" }',
          partitions: { framing: '{ "title": ', value: '"blå"', end: " }" },
        },
      );
      observe.capture("request", { name: "first" });
      observe.capture("request", { name: "second" });
      observe.check("measured", true);
    }),
  });
  assert.equal(report.success, true);
  const { text } = report.captures.dcaData;
  assert.equal(report.sizes.dcaData.json, Buffer.byteLength(text));
  assert.equal(report.sizes.dcaData.gzip, gzipSync(text, { level: 9 }).length);
  assert.equal(gunzipSync(gzipSync(text, { level: 9 })).toString(), text);
  assert.equal(
    Object.values(report.sizes.dcaData.partitions).reduce((sum, part) => sum + part.json, 0),
    report.sizes.dcaData.json,
  );
  assert.equal(report.sizes.dcaData.partitionGzipAdditive, false);
  assert.equal(report.captures.request.length, 2);
  assert.equal(report.captures.request[0].document.name, "first");
  assert.equal(report.captures.response.available, false);
});

test("bad captures, exceptions, failed checks and absent verification never become success", async () => {
  for (const execute of [
    ({ observe }) => observe.capture("dcaData", { x: 1 }, { text: '{"x":2}' }),
    ({ observe }) => observe.capture("dcaData", { x: 1 }, { partitions: { invented: "no" } }),
    () => {
      throw new Error("deliberate opening failure");
    },
    ({ observe }) => observe.check("opening", false),
    () => {},
  ]) {
    const report = await runBench({ scenario: fixture(execute) });
    assert.equal(report.success, false);
    assert.ok(report.checks.some((check) => !check.passed));
    assert.equal(
      JSON.parse(formatReport(report, { format: "json", show: "sizes" })).success,
      false,
    );
  }
});

test("workload resolves once, independent repetitions retain separate samples and views never rerun", async () => {
  let resolved = 0;
  let executions = 0;
  const scenario = fixture(
    async ({ input, observe }) => {
      assert.equal(input.title, "resolved");
      input.title = "mutated";
      executions++;
      observe.capture("dcaData", { sample: executions });
      await observe.time("publisher", async () => {});
      observe.check("sample", true);
    },
    {
      resolveInput() {
        resolved++;
        return { title: "resolved" };
      },
    },
  );
  const report = await runBench({ scenario, measurement: { runs: 2, warmup: 1 } });
  assert.equal(resolved, 1);
  assert.equal(executions, 3);
  assert.equal(report.samples.length, 2);
  assert.equal(report.summary.timings.publisher.count, 2);
  assert.equal(report.samples[0].captures.dcaData.document.sample, 2);
  assert.equal(report.samples[1].captures.dcaData.document.sample, 3);
  formatReport(report, { show: "sizes,checks" });
  formatReport(report, { show: "all", detail: "full" });
  assert.equal(executions, 3);
  assert.equal(report.setup.input.title, "resolved");
});

test("unknown inputs, invalid scopes and unknown profile selections fail before execution", async () => {
  let executed = false;
  const scenario = fixture(() => {
    executed = true;
  });
  await assert.rejects(runBench({ scenario, input: { typo: 1 } }), /Unknown.*typo/);
  await assert.rejects(runBench({ scenario, measurement: { scope: "invented" } }), /scope/);
  await assert.rejects(runBench({ scenario, measurement: { runs: 0 } }), /runs/);
  await assert.rejects(runBench({ scenario, measurement: { countCrypto: true } }), /scenarioUrl/);
  await assert.rejects(
    runBench({ scenario: { ...scenario, requestedProfiles: ["invented"] } }),
    /unknown requested profile/,
  );
  assert.equal(executed, false);
});

test("CLI stdin, selected views and separate exports keep exact artifacts and failure evidence", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "dca-bench-cli-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const module = join(dir, "case.mjs");
  await writeFile(
    module,
    `export const scenario = {
    id:'cli-fixture', defaults:{title:'default',fail:false}, requestedProfiles:['dca-profile-baseline'],
    execute({input,observe}) { observe.capture('dcaData',{title:input.title}); observe.check('opening', !input.fail); }
  };`,
  );
  const output = join(dir, "artifacts");
  const exported = join(dir, "metadata.json");
  const invoke = (args, input) =>
    spawnSync(process.execPath, ["cli.js", "--scenario", module, ...args], {
      cwd: root,
      encoding: "utf8",
      input,
    });
  const result = invoke(
    [
      "--input",
      "-",
      "--format",
      "json",
      "--show",
      "sizes",
      "--out",
      output,
      "--save",
      `dca-data=${exported}`,
    ],
    '{"title":"Saved article"}',
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).captures, undefined);
  const report = JSON.parse(await readFile(join(output, "report.json"), "utf8"));
  assert.equal(report.setup.input.title, "Saved article");
  assert.equal(await readFile(exported, "utf8"), report.captures.dcaData.text);
  assert.equal(
    await readFile(join(output, "sample-1/capture-dcaData/1.json"), "utf8"),
    report.captures.dcaData.text,
  );
  assert.notEqual(invoke(["--out", output]).status, 0);
  const failedOut = join(dir, "failed");
  const failed = invoke(
    ["--input", "-", "--format", "json", "--show", "sizes", "--out", failedOut],
    '{"fail":true}',
  );
  assert.equal(failed.status, 1);
  assert.equal(JSON.parse(failed.stdout).success, false);
  assert.equal(
    JSON.parse(await readFile(join(failedOut, "report.json"), "utf8")).checks[0].passed,
    false,
  );
  for (const args of [
    ["--scope", "unknown"],
    ["--input", "-", "--input", "-"],
    ["--runtime", "reuse"],
    ["--show", "typo"],
  ])
    assert.notEqual(invoke(args, "{}").status, 0);
});

test("crypto counting is isolated and ordinary behavior agrees with uninstrumented execution", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "dca-bench-crypto-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "count.mjs");
  await writeFile(
    path,
    `export const scenario = Object.freeze({
    id:'counts', defaults:{}, requestedProfiles:['dca-profile-baseline'],
    async execute({observe}) {
      const bytes = await globalThis.crypto.subtle.digest('SHA-256',new Uint8Array([1,2]));
      observe.capture('dcaData',{digest:Buffer.from(bytes).toString('hex')}); observe.check('digest',bytes.byteLength===32);
    }
  });`,
  );
  const scenarioUrl = pathToFileURL(path).href;
  const { scenario } = await import(scenarioUrl);
  const original = globalThis.crypto.subtle.digest;
  const plain = await runBench({ scenario });
  const counted = await runBench({ scenario, scenarioUrl, measurement: { countCrypto: true } });
  assert.equal(counted.success, true, JSON.stringify(counted.checks));
  assert.deepEqual(plain.captures.dcaData, counted.captures.dcaData);
  assert.equal(globalThis.crypto.subtle.digest, original);
  assert.ok(counted.work.crypto);
  assert.match(counted.setup.runtime.instrumentation, /isolated/);
});

test("uncatalogued declarations preserve profile status without accepting arbitrary names", async () => {
  const declaration = {
    id: "bench-proposal",
    dependsOn: baseline,
    status: "proposal",
    ref: "docs/proposal.md",
  };
  const scenario = fixture(({ observe }) => observe.check("proposal execution", true), {
    requestedProfiles: ["bench-proposal"],
    profileDeclarations: [declaration],
  });
  const report = await runBench({ scenario });
  assert.deepEqual(report.setup.requestedProfiles, ["bench-proposal"]);
  assert.deepEqual(report.setup.resolvedProfiles, [...baseline, "bench-proposal"]);
  assert.equal(report.setup.catalogueCoverage, "partial");
  assert.equal(report.setup.profileDeclarations[0].status, "proposal");
  for (const changed of [
    { ...declaration, dependsOn: ["unknown-parent"] },
    { ...declaration, id: baseline[0] },
    { ...declaration, status: "adopted" },
  ])
    await assert.rejects(runBench({ scenario: { ...scenario, profileDeclarations: [changed] } }));
  await assert.rejects(runBench({ scenario: { ...scenario, requestedProfiles: baseline } }));
});

test("summary presentation exposes later failed samples even when the first sample passed", async () => {
  let calls = 0;
  const report = await runBench({
    scenario: fixture(({ observe }) => {
      observe.check("opening", ++calls === 1, "second sample failed");
    }),
    measurement: { runs: 2 },
  });
  const text = formatReport(report);
  assert.equal(report.success, false);
  assert.match(text, /checks sample 1: 1\/1 passed/);
  assert.match(text, /checks sample 2: 0\/1 passed/);
  assert.match(text, /second sample failed/);
});

test("freezing a mutated mutable export cannot substitute worker behavior", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "dca-bench-mutable-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "mutable.mjs");
  await writeFile(
    path,
    `export const scenario={id:'mutable',defaults:{},requestedProfiles:['dca-profile-baseline'],execute({observe}){observe.check('original',true)}};`,
  );
  const scenarioUrl = pathToFileURL(path).href;
  const { scenario } = await import(scenarioUrl);
  await assert.rejects(
    runBench({ scenario, scenarioUrl, measurement: { countCrypto: true } }),
    /frozen/,
  );
  scenario.execute = ({ observe }) => observe.check("changed", false);
  Object.freeze(scenario);
  const report = await runBench({ scenario, scenarioUrl, measurement: { countCrypto: true } });
  assert.equal(report.success, false);
  assert.ok(report.checks.some(({ passed }) => !passed));
});
