// Lists the test cases one test file declares, one name per line, whatever
// name the file gives its declaring function: `test`, a `portableTest`
// binding or the full-suite `test` it imports under another name. Node's own
// runner loads the file in a child process with no bridge and reports each
// case it registers. The cases run there on the reference, since Node 22
// applies no skip pattern to an in-process run; whether they pass does not
// change the list. A suite is not a case; the cases inside it are. A file
// that fails to load lists nothing and exits 1.
//
//     node test-bridges/_shared/list-cases.mjs <test-file>
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { run } from "node:test";
import { fileURLToPath } from "node:url";

const self = fileURLToPath(import.meta.url);

/**
 * The case names `file` declares, in registration order. The file loads in a
 * child process of its own, without `DCA_TEST_SELECTION`: a named portable
 * selection turns every other case into a no-op that never registers, and
 * the list is the whole file.
 *
 * @param {string} file @param {NodeJS.ProcessEnv} [environment]
 * @returns {string[]}
 */
export function listCases(file, environment = process.env) {
  const childEnvironment = { ...environment };
  delete childEnvironment.DCA_TEST_SELECTION;
  delete childEnvironment.NODE_TEST_CONTEXT;
  const listed = spawnSync(process.execPath, [self, file], {
    env: childEnvironment,
    encoding: "utf8",
  });
  if (listed.status !== 0)
    throw new Error(`cannot list the cases of ${file}: ${listed.stderr.trim()}`);
  return listed.stdout.split("\n").filter((line) => line.length > 0);
}

/** @param {string} file */
async function printCases(file) {
  delete process.env.DCA_TEST_SELECTION;
  const path = resolve(file);
  const names = [];
  let loaded = true;
  // A file that throws while it loads is reported as one failed test named
  // by its path.
  for await (const event of run({ files: [path], isolation: "none" })) {
    if (event.type === "test:fail" && event.data.name === path) loaded = false;
    const isCase = event.type === "test:enqueue" && event.data.type === "test";
    if (isCase && event.data.name !== path) names.push(event.data.name);
  }
  if (!loaded) {
    process.stderr.write(`${file} did not load\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(names.map((name) => `${name}\n`).join(""));
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === self) {
  const [file, ...rest] = process.argv.slice(2);
  if (!file || rest.length > 0) {
    process.stderr.write("usage: node list-cases.mjs <test-file>\n");
    process.exit(2);
  }
  await printCases(file);
}
