// @ts-check
//
// A compact-ECDH publisher draws a fresh ephemeral key pair for every envelope
// (docs/spec-profile--compact-ecdh.md Section 4.1). `sealTranscript` and
// `sealEnvelopeTranscript` take the pair from their caller, so they stay
// exported only because `seal` and the deterministic test facility share
// them; JavaScript has no package-private export. This test is the guard:
// outside `hpke.js`, `envelope.js` and `testing/`, no module names them, and
// only tests and the vector recorder import `testing/`.

import test from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join, normalize, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const TRANSCRIPT_SEALERS = /\b(sealTranscript|sealEnvelopeTranscript)\b/;
const TESTING = "extensions/compact-ecdh/core-shared--publisher-issuer/testing/";
const IMPORT_SPECIFIER = /\b(?:from|import)\s*\(?\s*["']([^"']+)["']/g;
const MAY_NAME_SEALERS = new Set([
  "extensions/compact-ecdh/core-shared--publisher-issuer/hpke.js",
  "extensions/compact-ecdh/core-shared--publisher-issuer/envelope.js",
  "extensions/compact-ecdh/core-shared--publisher-issuer/testing/deterministicHpke.js",
  "extensions/compact-ecdh/test/export-surface.test.js",
]);

/** @returns {Promise<string[]>} every .js and .mjs under js, outside node_modules */
async function sources() {
  const entries = await readdir(ROOT, { recursive: true, withFileTypes: true });
  return entries
    .filter((e) => e.isFile() && /\.m?js$/.test(e.name))
    .map((e) => relative(ROOT, join(e.parentPath, e.name)))
    .filter((path) => !path.split("/").includes("node_modules"));
}

/** @param {string} path */
function mayImportTesting(path) {
  return (
    /(^|\/)test[^/]*\//.test(path) ||
    path.endsWith(".test.js") ||
    path === "extensions/compact-ecdh/tools/record-dca-vectors.mjs" ||
    path.startsWith(TESTING)
  );
}

test("only the HPKE modules and the test facility name the transcript sealers", async () => {
  const offenders = [];
  for (const path of await sources()) {
    if (MAY_NAME_SEALERS.has(path)) continue;
    if (TRANSCRIPT_SEALERS.test(await readFile(join(ROOT, path), "utf8"))) offenders.push(path);
  }
  assert.deepEqual(offenders, []);
});

test("only tests and the vector recorder import the deterministic test facility", async () => {
  const offenders = [];
  for (const path of await sources()) {
    if (mayImportTesting(path)) continue;
    const text = await readFile(join(ROOT, path), "utf8");
    const resolved = [...text.matchAll(IMPORT_SPECIFIER)]
      .map((m) => m[1])
      .filter((specifier) => specifier.startsWith("."))
      .map((specifier) => normalize(join(dirname(path), specifier)));
    if (resolved.some((target) => target.startsWith(TESTING))) offenders.push(path);
  }
  assert.deepEqual(offenders, []);
});
