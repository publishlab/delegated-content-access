// @ts-check
// Compile affected core entry points from actual role-only copies, then consume
// their declarations with no JavaScript source available to the compiler.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const compiler = join(root, "node_modules/typescript/bin/tsc");
const { compilerOptions } = JSON.parse(
  readFileSync(join(root, "test-reference/tsconfig.types.json"), "utf8"),
);
const selections = [
  {
    role: "client",
    extensions: ["content-groups", "chain-keys", "content-key-seal-omission", "html-content-map"],
  },
  { role: "issuer", extensions: ["content-groups", "chain-keys"] },
  { role: "publisher", extensions: ["content-groups", "chain-keys"] },
];

/** Copy JavaScript sources recursively, without linking back to the source tree.
 * @param {string} from @param {string} to
 */
function copySources(from, to) {
  mkdirSync(to, { recursive: true });
  for (const entry of readdirSync(from, { withFileTypes: true })) {
    if (entry.isDirectory()) copySources(join(from, entry.name), join(to, entry.name));
    else if (entry.isFile() && entry.name.endsWith(".js"))
      copyFileSync(join(from, entry.name), join(to, entry.name));
  }
}

/** A role selects only universal, own-role and named pairwise core directories.
 * @param {string} from @param {string} to @param {string} role
 */
function copyRole(from, to, role) {
  for (const entry of readdirSync(from, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (
      entry.name === "core-shared" ||
      entry.name === `core-${role}` ||
      (entry.name.startsWith("core-shared--") &&
        entry.name.slice("core-shared--".length).split("-").includes(role))
    )
      copySources(join(from, entry.name), join(to, entry.name));
  }
}

/** @param {string} config @param {string} cwd */
function check(config, cwd) {
  const result = spawnSync(process.execPath, [compiler, "--project", config, "--pretty", "false"], {
    cwd,
    encoding: "utf8",
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${config}:\n${result.stdout}${result.stderr}`);
}

for (const { role, extensions } of selections) {
  test(`${role} core entries emit and consume declarations without outer layers`, () => {
    const temporary = mkdtempSync(join(tmpdir(), `dca-core-declarations-${role}-`));
    try {
      const source = join(temporary, "source");
      const emitted = join(temporary, "emitted");
      copyRole(root, source, role);
      for (const name of extensions)
        copyRole(join(root, "extensions", name), join(source, "extensions", name), role);
      writeFileSync(join(source, "package.json"), '{"type":"module"}');
      const fixture = `test-reference/core-${role}/types--extraction.ts`;
      mkdirSync(dirname(join(source, fixture)), { recursive: true });
      copyFileSync(join(root, fixture), join(source, fixture));
      const emitConfig = join(source, "tsconfig.json");
      writeFileSync(
        emitConfig,
        JSON.stringify({
          compilerOptions: {
            ...compilerOptions,
            noEmit: false,
            noEmitOnError: true,
            declaration: true,
            emitDeclarationOnly: true,
            rootDir: source,
            outDir: emitted,
          },
          files: [fixture],
        }),
      );
      check(emitConfig, source);

      // Consumer resolution can reach only emitted declarations, never the
      // copied JavaScript or the original repository's outer layers.
      rmSync(source, { recursive: true, force: true });
      writeFileSync(join(emitted, "package.json"), '{"type":"module"}');
      copyFileSync(join(root, fixture), join(emitted, fixture));
      const consumerConfig = join(emitted, "tsconfig.json");
      writeFileSync(
        consumerConfig,
        JSON.stringify({
          compilerOptions: { ...compilerOptions, allowJs: false },
          files: [fixture],
        }),
      );
      check(consumerConfig, emitted);
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });
}
