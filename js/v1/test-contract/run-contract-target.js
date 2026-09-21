// @ts-check

// One deliberately small selector: the npm command selects one target or the
// base inventory, and its arguments supply every binding. This validates each
// static declaration, then Node runs the selected target tests. It discovers
// nothing and adapts no DCA behavior.

import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

import {
  assertBindingSupportsTarget,
  contractReporterArguments,
  declaredBaseTargets,
} from "./support/contract-runner-validation.js";
import { selectFixtureFiles } from "./support/fixture-manifest.js";

const CONTRACT_ROOT = fileURLToPath(new URL("./", import.meta.url));
const V1_ROOT = fileURLToPath(new URL("../", import.meta.url));
const VERIFICATION_ROOT = fileURLToPath(new URL("../../../verification/", import.meta.url));
const VERDICT_REPORTER = fileURLToPath(
  new URL("../test-tools/test-verdict-reporter.mjs", import.meta.url),
);
const manifest = JSON.parse(
  readFileSync(new URL("./contract-targets.json", import.meta.url), "utf8"),
);
const commandArguments = process.argv.slice(2);
const bindingArguments =
  commandArguments[0] === "--" ? commandArguments.slice(1) : commandArguments;
const runnerName = process.env.npm_lifecycle_event;
const baseSelection = runnerName === "test:contract:base";
const matchingTargets = Object.entries(manifest).filter(
  ([, candidate]) => candidate.runner === runnerName,
);

if (
  !runnerName ||
  bindingArguments.length === 0 ||
  (!baseSelection && matchingTargets.length !== 1) ||
  (baseSelection && bindingArguments.length !== 1)
) {
  throw new Error(
    "run this selector through test:contract:base with one binding, or one manifest-backed test:contract:<target> command with one or more bindings",
  );
}

/**
 * @param {string} targetName
 * @param {any} target
 * @param {string} bindingArgument
 * @param {any} bindingModule
 */
function runTarget(targetName, target, bindingArgument, bindingModule) {
  const targetDirectory = resolve(CONTRACT_ROOT, target.directory);
  const testFile = resolve(targetDirectory, target.test);
  const readme = readFileSync(resolve(targetDirectory, "README.md"), "utf8");
  const machineBlock = readme.match(/<!-- contract-target\n([\s\S]*?)\n-->/);
  if (!machineBlock) throw new Error(`${targetName}: README has no contract-target block`);
  const documented = JSON.parse(machineBlock[1]);
  if (JSON.stringify(documented) !== JSON.stringify(target)) {
    throw new Error(
      `${targetName}: README contract-target block differs from contract-targets.json`,
    );
  }
  if (!existsSync(testFile)) throw new Error(`${targetName}: missing target test ${target.test}`);

  const selectedFixtureFiles = selectFixtureFiles(
    VERIFICATION_ROOT,
    target.fixtureSets,
    target.fixtureConsumer,
    target.fixtureFormats,
  );
  const availableFormats = new Set();
  for (const fixtureFile of selectedFixtureFiles) {
    availableFormats.add(JSON.parse(readFileSync(fixtureFile, "utf8")).vectorFormat);
  }
  if (selectedFixtureFiles.length === 0) {
    throw new Error(`${targetName}: fixture selection resolves to zero files`);
  }
  for (const vectorFormat of target.fixtureFormats) {
    if (!availableFormats.has(vectorFormat)) {
      throw new Error(
        `${targetName}: selected fixture format ${JSON.stringify(vectorFormat)} is not consumed by ${target.fixtureSets.join(", ")}`,
      );
    }
  }

  const declared = bindingModule.dcaTestBinding?.targets?.[targetName];
  assertBindingSupportsTarget(targetName, target, declared);

  console.log(
    `contract target ${targetName}; required access: ${target.requiredAccess}; fixtures: ${target.fixtureSets.join(", ")} formats ${target.fixtureFormats.join(", ")}`,
  );
  // The binding has already been imported above for declaration validation.
  // Preload that same explicit module into the isolated test child so a
  // target suite can consume it without creating another dynamic-import
  // boundary of its own.
  const preload = `globalThis.__dcaTestBinding = (await import(process.env.DCA_TEST_BINDING)).dcaTestBinding;`;
  // One file per spawn already; the flag only avoids a redundant worker thread. DCA_NODE_TEST_ISOLATION defaults to 'none'.
  const isolation = process.env.DCA_NODE_TEST_ISOLATION || "none";
  const child = spawnSync(
    process.execPath,
    [
      "--import",
      `data:text/javascript,${encodeURIComponent(preload)}`,
      `--experimental-test-isolation=${isolation}`,
      "--test",
      ...contractReporterArguments(VERDICT_REPORTER),
      testFile,
    ],
    {
      cwd: V1_ROOT,
      env: {
        ...process.env,
        DCA_TEST_BINDING: pathToFileURL(resolve(process.cwd(), bindingArgument)).href,
        DCA_TEST_TARGET: targetName,
        DCA_TEST_TARGET_CONFIG: JSON.stringify(target),
        DCA_TEST_FIXTURE_FILES: JSON.stringify(selectedFixtureFiles),
        DCA_TEST_SELECTED_FIXTURES: String(selectedFixtureFiles.length),
      },
      encoding: "utf8",
    },
  );
  process.stdout.write(child.stdout ?? "");
  process.stderr.write(child.stderr ?? "");
  if (child.error) throw child.error;
  if (child.status !== 0) process.exitCode = child.status ?? 1;
}

for (const bindingArgument of bindingArguments) {
  const bindingUrl = pathToFileURL(resolve(process.cwd(), bindingArgument)).href;
  const bindingModule = await import(bindingUrl);
  const selectedTargets = baseSelection
    ? declaredBaseTargets(manifest, bindingModule.dcaTestBinding)
    : [matchingTargets[0][0]];
  for (const targetName of selectedTargets) {
    runTarget(targetName, manifest[targetName], bindingArgument, bindingModule);
  }
}
