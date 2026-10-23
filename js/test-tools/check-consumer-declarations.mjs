// Check the same consumers against generated declarations in an isolated tree.
// Uses the installed compiler and leaves no generated files in the source tree.
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const fixtureRoot = join(root, "test-reference");
const { compilerOptions, files } = JSON.parse(
  readFileSync(join(fixtureRoot, "tsconfig.types.json"), "utf8"),
);
if (!Array.isArray(files) || files.length === 0)
  throw new Error("consumer declaration checks require an explicit nonempty files list");

const compiler = join(root, "node_modules/typescript/bin/tsc");
/** @param {string} config */
function check(config) {
  const result = spawnSync(process.execPath, [compiler, "--project", config, "--pretty", "false"], {
    cwd: root,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`consumer declaration compiler failed (${result.signal ?? result.status})`);
}

const temporary = mkdtempSync(join(tmpdir(), "dca-consumer-declarations-"));
try {
  const emitted = join(temporary, "emitted");
  const emitConfig = join(temporary, "emit.json");
  writeFileSync(
    emitConfig,
    JSON.stringify({
      compilerOptions: {
        ...compilerOptions,
        noEmit: false,
        noEmitOnError: true,
        declaration: true,
        emitDeclarationOnly: true,
        rootDir: root,
        outDir: emitted,
      },
      files: files.map((file) => join(fixtureRoot, file)),
    }),
  );
  console.log("Emitting reference declarations for the consumer fixtures");
  check(emitConfig);

  // Preserve NodeNext package interpretation, while copying no runtime sources.
  const { type } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  writeFileSync(join(emitted, "package.json"), JSON.stringify({ type }));
  for (const file of files) {
    const target = join(emitted, "test-reference", file);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(join(fixtureRoot, file), target);
  }
  const consumerConfig = join(emitted, "test-reference/tsconfig.types.json");
  writeFileSync(
    consumerConfig,
    JSON.stringify({ compilerOptions: { ...compilerOptions, allowJs: false }, files }),
  );
  console.log("Checking consumers against emitted declarations only");
  check(consumerConfig);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
