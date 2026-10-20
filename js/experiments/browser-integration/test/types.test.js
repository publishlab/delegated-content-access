// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const TYPESCRIPT = resolve(TEST_DIR, "../../../node_modules/typescript/bin/tsc");
const PARTICIPANT = resolve(TEST_DIR, "../test-lib/participant.ts");

test("emitted participant declarations accept valid code and reject annotated invalid shapes", () => {
  const result = spawnSync(
    process.execPath,
    [
      TYPESCRIPT,
      "--noEmit",
      "--strict",
      "--target",
      "ES2024",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--lib",
      "ES2024,DOM,DOM.Iterable",
      PARTICIPANT,
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.equal(result.signal, null);
});
