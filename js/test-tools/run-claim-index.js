import { observedEnvelopeTags } from "./envelope-evidence.js";
import { readFileSync, globSync, readdirSync, existsSync } from "node:fs";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "node:test";
import { spawnSync } from "node:child_process";
import {
  completedTestFiles,
  discoverFixturePackageRoots,
  failedTestFiles,
  evaluateScenario,
  recordedPackageCheckCommand,
  reduceClaimTestEvents,
  selectEvidenceTestFiles,
  validateClaimIndex,
  validateRecordedPackageInventory,
} from "./claim-index.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const here = fileURLToPath(new URL("../", import.meta.url));
const index = JSON.parse(readFileSync(resolve(root, "verification/claim-index/v1.json"), "utf8"));
const catalogue = JSON.parse(readFileSync(resolve(root, index.catalogue), "utf8"));
const packageJson = JSON.parse(readFileSync(resolve(here, "package.json"), "utf8"));

function requireNode24() {
  const [major, minor] = process.versions.node.split(".").map(Number);
  if (major < 24 || (major === 24 && minor < 19))
    throw new Error("claim:evidence requires Node 24.19 or newer");
}

function gateFiles() {
  const patterns = [...packageJson.scripts["test:unit"].matchAll(/"([^"]+\.test\.js)"/g)];
  if (patterns.length !== 1) throw new Error("test:unit discovery glob changed");
  return new Set(globSync(patterns[0][1], { cwd: here }).map((path) => path.replaceAll("\\", "/")));
}

function inventory() {
  const listedVectors = readFileSync(resolve(root, "verification/vectors/sets.txt"), "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
  const vectorRoot = resolve(root, "verification/vectors");
  const roots = ["baseline", "profiles", "experiments"].map((name) =>
    resolve(vectorRoot, "v1", name),
  );
  const actualVectors = [
    ...readdirSync(vectorRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && entry.name !== "v1")
      .map((entry) => `vectors/${entry.name}`),
    ...roots.flatMap((directory) =>
      existsSync(directory)
        ? readdirSync(directory, { withFileTypes: true })
            .filter((entry) => entry.isDirectory())
            .map(
              (entry) =>
                `vectors/v1/${relative(resolve(vectorRoot, "v1"), resolve(directory, entry.name)).replaceAll("\\", "/")}`,
            )
        : [],
    ),
  ];
  const actualFixtures = discoverFixturePackageRoots(resolve(root, "verification/fixtures"));
  validateRecordedPackageInventory(
    listedVectors,
    actualVectors,
    index.recordedPackages.map((entry) => entry.id),
    actualFixtures,
  );
}

async function observeTests(scope) {
  const evidenceFiles = [
    ...new Set(
      index.scenarios.flatMap((scenario) => [
        ...scenario.evidence.map((entry) => entry.test.file),
        scenario.compositionEvidence.test.file,
      ]),
    ),
  ];
  const selection = selectEvidenceTestFiles([...gateFiles()], evidenceFiles, scope);
  const events = [];
  const stream = run({
    files: selection.selected.map((file) => resolve(here, file)),
    concurrency: false,
  });
  for await (const event of stream)
    if (["test:pass", "test:fail", "test:skip", "test:summary"].includes(event.type))
      events.push(event);
  const completedFiles = completedTestFiles(events);
  const failedFiles = failedTestFiles(events);
  for (const file of selection.selected)
    if (!completedFiles.has(resolve(here, file)))
      throw new Error(`test file did not finish: ${file}`);
  const tests = events.filter(
    (event) =>
      !(
        event.data.nesting === 0 &&
        event.data.name?.endsWith(".test.js") &&
        resolve(here, event.data.name) === event.data.file
      ) && ["test:pass", "test:fail", "test:skip"].includes(event.type),
  );
  const reduced = reduceClaimTestEvents(tests, catalogue).map((entry) => ({
    ...entry,
    file: entry.file && relative(here, entry.file).replaceAll("\\", "/"),
  }));
  const failedTests = reduced.filter((entry) => entry.outcome === "failed").length;
  return {
    observedFiles: completedFiles.size,
    admittedFiles: selection.admittedFiles,
    unobservedFiles: selection.unobservedFiles,
    failedTests,
    failedFiles: [...failedFiles].map((file) => relative(here, file).replaceAll("\\", "/")).sort(),
    tests: reduced,
    envelopeTags: observedEnvelopeTags(tests),
  };
}

function command(label, commandName, args, cwd = root) {
  const result = spawnSync(commandName, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
  });
  return {
    id: label,
    status: result.status === 0 ? "passed" : "failed",
    exitCode: result.status,
    output: `${result.stdout ?? ""}${result.stderr ?? ""}`.trim().split("\n").at(-1),
  };
}

function sourceState() {
  const revision = spawnSync("git", ["rev-parse", "--verify", "HEAD"], {
    cwd: root,
    encoding: "utf8",
  });
  const status = spawnSync("git", ["status", "--porcelain"], {
    cwd: root,
    encoding: "utf8",
  });
  return {
    revision: revision.status === 0 ? revision.stdout.trim() : null,
    workingTree: status.status === 0 ? (status.stdout.trim() ? "dirty" : "clean") : "unknown",
  };
}

async function main() {
  requireNode24();
  const scope = process.argv[2] === "--all" ? "all" : "evidence";
  if (process.argv.length > 3 || (process.argv[2] && process.argv[2] !== "--all"))
    throw new Error("claim runner accepts only --all or no argument");
  validateClaimIndex(index, catalogue);
  inventory();
  const source = sourceState();
  const tests = await observeTests(scope);
  const packageChecks = new Map();
  const packageResults = index.recordedPackages.map((entry) => {
    const check = recordedPackageCheckCommand(entry.path);
    const key = JSON.stringify([check.executable, check.args]);
    let result = packageChecks.get(key);
    if (!result) {
      result = command(
        entry.id,
        check.executable === "node" ? process.execPath : check.executable,
        check.args,
      );
      packageChecks.set(key, result);
    }
    return { ...result, id: entry.id };
  });
  const packageMap = new Map(packageResults.map((entry) => [entry.id, entry]));
  const scenarios = index.scenarios.map((scenario) => ({
    ...evaluateScenario(index, catalogue, scenario.id, tests.tests, packageResults),
    recordedPackages: scenario.recordedPackages.map((id) => packageMap.get(id)),
  }));
  const profileSupport = catalogue.profiles.map((profile) => {
    const declarations = index.support.filter((entry) => entry.profile === profile.id);
    const roles = [
      ...new Set(
        (catalogue.duties ?? [])
          .filter((duty) => duty.profile === profile.id)
          .map((duty) => duty.role),
      ),
    ].sort();
    return {
      profile: profile.id,
      status: declarations.length ? "declared" : "unclaimed",
      roles: roles.map((role) => ({
        role,
        status: declarations.find((entry) => entry.role === role)?.status ?? "unclaimed",
      })),
    };
  });
  process.stdout.write(
    `${JSON.stringify(
      {
        schema: "dca-scoped-profile-evidence-result/v1",
        testScope: scope,
        source,
        subject: index.subject,
        deploymentEnablement: index.deploymentEnablement,
        profileSupport,
        testRun: {
          observedFiles: tests.observedFiles,
          admittedFiles: tests.admittedFiles,
          unobservedFiles: tests.unobservedFiles,
          failedTests: tests.failedTests,
          failedFiles: tests.failedFiles,
          envelopeTags: tests.envelopeTags,
        },
        portfolioEnvelopeObservations: {
          tags: tests.envelopeTags,
          interpretation:
            "Portfolio-wide observations only; these do not satisfy scenario evidence selectors.",
        },
        scenarios,
        packageIntegrity: packageResults,
        scopeLimit:
          "Catalogue-bounded evidence only; this output is not full normative conformance.",
      },
      null,
      2,
    )}\n`,
  );
  if (
    tests.failedTests > 0 ||
    tests.failedFiles.length > 0 ||
    packageResults.some((entry) => entry.status !== "passed")
  )
    process.exitCode = 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
