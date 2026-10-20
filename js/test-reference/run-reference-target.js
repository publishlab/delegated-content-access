// @ts-check

// Select one existing reference target from the authoritative inventory. This
// is deliberately a static selector, not filesystem discovery: the inventory
// names both cross-layer flat tests and tests in source-layer directories.

import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { isAbsolute, relative, resolve, sep } from "node:path";

const V1_ROOT = resolve(fileURLToPath(new URL("../", import.meta.url)));
const inventory = JSON.parse(
  readFileSync(new URL("../test/test-inventory.json", import.meta.url), "utf8"),
);
const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const [target, ...extraArguments] = process.argv.slice(2);

if (typeof target !== "string" || target.length === 0 || extraArguments.length !== 0) {
  throw new Error(
    "run this selector through one npm test:reference:<target> command with exactly one target",
  );
}

const scriptName = `test:reference:${target}`;
const expectedCommand = `node test-reference/run-reference-target.js ${target}`;
if (
  process.env.npm_lifecycle_event !== scriptName ||
  packageJson.scripts?.[scriptName] !== expectedCommand
) {
  throw new Error(`${target}: run this selector through ${JSON.stringify(scriptName)}`);
}

const inventoryFiles = Object.entries(inventory)
  .filter(
    ([, entry]) =>
      entry.target === target || (Array.isArray(entry.targets) && entry.targets.includes(target)),
  )
  .map(([file]) => file)
  .sort();
if (inventoryFiles.length === 0) {
  throw new Error(`${target}: test-inventory.json has no runnable reference tests`);
}

const testFiles = inventoryFiles.map((testFile) =>
  testFile.startsWith("test-reference/") ? testFile : `test/${testFile}`,
);
for (const testFile of testFiles) {
  const path = resolve(V1_ROOT, testFile);
  const relativePath = relative(V1_ROOT, path);
  const leavesRoot =
    relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath);
  if (leavesRoot || !testFile.endsWith(".test.js") || !existsSync(path)) {
    throw new Error(`${target}: inventory entry is not a runnable reference test: ${testFile}`);
  }
}

console.log(`reference target ${target}; ${testFiles.length} inventory-selected test files`);
const child = spawnSync(process.execPath, ["--test", ...testFiles], {
  cwd: V1_ROOT,
  stdio: "inherit",
});
if (child.error) throw child.error;
process.exitCode = child.status ?? 1;
