// @ts-check
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
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));

for (const scenario of ["valid", "invalid-consumer", "invalid-declaration"]) {
  test(`declaration runner: ${scenario}, with temporary output cleaned`, () => {
    const directory = mkdtempSync(join(tmpdir(), "dca-declaration-runner-test-"));
    try {
      mkdirSync(join(directory, "test-tools"));
      mkdirSync(join(directory, "test-reference"));
      const temporary = join(directory, "temporary");
      mkdirSync(temporary);
      symlinkSync(join(root, "node_modules"), join(directory, "node_modules"), "junction");
      copyFileSync(
        join(root, "test-tools/check-consumer-declarations.mjs"),
        join(directory, "test-tools/check-consumer-declarations.mjs"),
      );
      writeFileSync(join(directory, "package.json"), '{"type":"module"}');
      writeFileSync(
        join(directory, "test-reference/tsconfig.types.json"),
        JSON.stringify({
          ...JSON.parse(readFileSync(join(root, "test-reference/tsconfig.types.json"), "utf8")),
          files: ["consumer.ts"],
        }),
      );
      writeFileSync(
        join(directory, "api.js"),
        scenario === "invalid-declaration"
          ? "/** @returns {MissingType} */ export function answer() { return 7; }"
          : "/** @returns {number} */ export function answer() { return 7; }",
      );
      writeFileSync(
        join(directory, "test-reference/consumer.ts"),
        'import { answer } from "../api.js";\n' +
          (scenario === "invalid-consumer" ? "answer().invented();\n" : "answer();\n"),
      );
      const child = spawnSync(
        process.execPath,
        [join(directory, "test-tools/check-consumer-declarations.mjs")],
        {
          cwd: directory,
          env: { ...process.env, TMPDIR: temporary, TMP: temporary, TEMP: temporary },
          encoding: "utf8",
        },
      );
      assert.ifError(child.error);
      const output = child.stdout + child.stderr;
      if (scenario === "valid") {
        assert.equal(child.status, 0, output);
        assert.match(output, /Checking consumers against emitted declarations only/);
      } else {
        assert.notEqual(child.status, 0, output);
        assert.match(output, scenario === "invalid-consumer" ? /invented/ : /MissingType/);
        if (scenario === "invalid-declaration")
          assert.match(output, /Checking consumers against emitted declarations only/);
      }
      assert.deepEqual(readdirSync(temporary), [], "temporary compiler output was removed");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
