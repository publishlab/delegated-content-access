#!/usr/bin/env node
// @ts-check
// Records raw JSON spellings, independently specified expectations and domain
// observations. --check verifies exact membership, hashes and repeatability;
// it never writes. This records geometry admission, not a whole-profile claim.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { settleChainGeometry } from "../extensions/chain-keys/core-shared/chainKeyConstruction.js";
import { DcaError } from "../core-shared/errors.js";
import { CHECKSUM_FILE, checksumsText } from "./checksums.js";

export const PACKAGE_ID = "fixtures/v1/profiles/dca-profile-chain-keys/geometry-admission";
export const PACKAGE_DIR = fileURLToPath(
  new URL(`../../verification/${PACKAGE_ID}/`, import.meta.url),
);
const REPO_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const PAYLOAD_FILES = ["expected.json", "inputs.json", "observations.json"];
export const PACKAGE_FILES = [...PAYLOAD_FILES, "README.md", "manifest.json", CHECKSUM_FILE].sort();

// Deliberately raw text: JSON.stringify would erase the property being tested.
const INPUTS = `{
  "format": "chain-keys-geometry-admission/v1",
  "cases": [
    { "id": "integer", "geometry": { "chainsPerDay": 2, "periodMinutes": 60 } },
    { "id": "chains-decimal", "geometry": { "chainsPerDay": 2.0, "periodMinutes": 60 } },
    { "id": "chains-exponent", "geometry": { "chainsPerDay": 2e0, "periodMinutes": 60 } },
    { "id": "minutes-decimal", "geometry": { "chainsPerDay": 2, "periodMinutes": 60.0 } },
    { "id": "minutes-exponent", "geometry": { "chainsPerDay": 2, "periodMinutes": 6e1 } },
    { "id": "chains-fraction", "geometry": { "chainsPerDay": 2.5, "periodMinutes": 60 } },
    { "id": "minutes-fraction", "geometry": { "chainsPerDay": 2, "periodMinutes": 60.5 } },
    { "id": "chains-string", "geometry": { "chainsPerDay": "2", "periodMinutes": 60 } },
    { "id": "minutes-string", "geometry": { "chainsPerDay": 2, "periodMinutes": "60" } }
  ]
}
`;

/** @param {unknown} value */
const json = (value) => `${JSON.stringify(value, null, 2)}\n`;

/**
 * Expectations come from chain keys §12.1 (#document-member) and chain §7.2, not domain output.
 * 1440 / 2 = 720 minutes; 720 / 60 = 12 positions, below §22's bound.
 */
function expectations() {
  const geometry = {
    chainsPerDay: 2,
    periodMinutes: 60,
    windowMinutes: 720,
    positionsPerWindow: 12,
  };
  return {
    authority: [
      "docs/spec-profile--chain-keys.md#document-member",
      "docs/spec-profile--chain-keys.md#windows",
      "docs/spec-profile--chain-keys.md#bounds",
    ],
    derivation:
      "Positive JSON integer values; windowMinutes = 1440 / 2 = 720; positionsPerWindow = 720 / 60 = 12 <= 288.",
    cases: [
      ...[
        "integer",
        "chains-decimal",
        "chains-exponent",
        "minutes-decimal",
        "minutes-exponent",
      ].map((id) => ({ id, admitted: true, geometry })),
      ...["chains-fraction", "minutes-fraction", "chains-string", "minutes-string"].map((id) => ({
        id,
        admitted: false,
      })),
    ],
  };
}

/** @param {string} raw */
function observe(raw) {
  const inputs = JSON.parse(raw);
  return inputs.cases.map((/** @type {{id: string, geometry: unknown}} */ input) => {
    try {
      return { id: input.id, admitted: true, geometry: settleChainGeometry(input.geometry) };
    } catch (error) {
      // Only an actual domain refusal is recorded, not a broken harness/import.
      if (!(error instanceof DcaError)) throw error;
      return { id: input.id, admitted: false };
    }
  });
}

/** @param {string} [sourceCommit] @returns {Promise<Map<string, string>>} */
export async function recordPackage(sourceCommit = "") {
  const expected = expectations();
  const observations = observe(INPUTS);
  assert.deepEqual(
    observations,
    expected.cases,
    "refusing to record domain behavior contrary to the specification expectations",
  );
  const files = new Map([
    ["inputs.json", INPUTS],
    ["expected.json", json(expected)],
    ["observations.json", json({ cases: observations })],
  ]);
  const sums = await checksumsText(
    [...files].map(([file, text]) => ({ file, bytes: Buffer.from(text) })),
  );
  const members = sums
    .trim()
    .split("\n")
    .map((line) => {
      const [sha256, path] = line.split("  ");
      return { path, sha256 };
    });
  files.set(
    "manifest.json",
    json({
      schema: "dca-fixture-package-manifest/v1",
      package: PACKAGE_ID,
      profile: "dca-profile-chain-keys",
      format: "chain-keys-geometry-admission/v1",
      stability: "draft",
      scope: {
        boundary: "parsed JSON geometry pair admitted by settleChainGeometry",
        cases: 9,
      },
      provenance: {
        recorder: "js/tools/record-chain-keys-geometry-admission.js",
        sourceCommit,
        expectedResults:
          "Hand-specified from chain keys document-member and §7.2/§22; never derived from implementation observations.",
      },
      members,
      consumers: [
        {
          path: "js/test-vectors/chain-keys-geometry-admission.test.js",
          role: "domain replay",
        },
        {
          path: "js/test-tools/record-chain-keys-geometry-admission.test.js",
          role: "recorder self-test",
        },
        {
          command: "node js/tools/record-chain-keys-geometry-admission.js --check",
          role: "package check",
        },
      ],
      limitations: [
        "JavaScript domain admission only; not independent conformance or complete profile coverage.",
        "No issuer exchange, cryptographic operation, capability grant or normative refusal-code assertion.",
        "Raw spellings are preserved in inputs.json; observations intentionally report parsed values.",
      ],
    }),
  );
  files.set(CHECKSUM_FILE, sums);
  return files;
}

/** @param {string} dir */
export async function checkPackage(dir) {
  /** @type {string[]} */
  const findings = [];
  let entries;
  let manifest;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
    manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  } catch (error) {
    return {
      status: 2,
      findings: [],
      summary: `geometry package check could not run: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  const actual = new Set(entries.map((entry) => entry.name));
  for (const name of PACKAGE_FILES)
    if (!actual.has(name)) findings.push(`membership: missing ${name}`);
  for (const entry of entries) {
    if (!PACKAGE_FILES.includes(entry.name) || !entry.isFile())
      findings.push(`membership: extra or non-file ${entry.name}`);
  }
  if (
    typeof manifest.provenance?.sourceCommit !== "string" ||
    !["draft", "frozen"].includes(manifest.stability)
  ) {
    findings.push("manifest: invalid provenance or stability");
  }
  const fresh = await recordPackage(manifest.provenance?.sourceCommit ?? "");
  // Stability is lifecycle metadata; freeze must not change payload expectations.
  const canonicalManifest = JSON.parse(fresh.get("manifest.json") ?? "null");
  canonicalManifest.stability = manifest.stability;
  fresh.set("manifest.json", json(canonicalManifest));
  for (const [name, text] of fresh) {
    if (!actual.has(name) || !entries.find((entry) => entry.name === name)?.isFile()) continue;
    if (readFileSync(join(dir, name), "utf8") !== text) findings.push(`drift: ${name}`);
  }
  // Check hashes of the actual bytes as well as comparing with regeneration.
  const actualPayloads = PAYLOAD_FILES.filter((file) =>
    entries.find((entry) => entry.name === file)?.isFile(),
  );
  const sums = await checksumsText(
    actualPayloads.map((file) => ({ file, bytes: readFileSync(join(dir, file)) })),
  );
  for (const line of sums.trim().split("\n").filter(Boolean)) {
    const [sha256, file] = line.split("  ");
    if (
      !Array.isArray(manifest.members) ||
      !manifest.members.some(
        (/** @type {any} */ member) => member.path === file && member.sha256 === sha256,
      )
    )
      findings.push(`checksum: ${file} (manifest.json)`);
    if (
      entries.find((entry) => entry.name === CHECKSUM_FILE)?.isFile() &&
      !readFileSync(join(dir, CHECKSUM_FILE), "utf8").split("\n").includes(line)
    )
      findings.push(`checksum: ${file} (${CHECKSUM_FILE})`);
  }
  return {
    status: findings.length ? 1 : 0,
    findings,
    summary: findings.length
      ? `geometry package check failed: ${findings.length} findings`
      : "6 recorded files match membership, checksums and a fresh recording (9 geometry cases)",
  };
}

/** @param {string} dir */
export async function writePackage(dir) {
  let prior;
  try {
    prior = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
  }
  if (prior && prior.stability !== "draft")
    throw new Error("refusing to overwrite a frozen or invalid geometry package");
  const probe = await recordPackage(prior?.provenance?.sourceCommit ?? "");
  const unchanged = PAYLOAD_FILES.every((file) => {
    try {
      return readFileSync(join(dir, file), "utf8") === probe.get(file);
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
      return false;
    }
  });
  const sourceCommit =
    unchanged && prior?.provenance?.sourceCommit
      ? prior.provenance.sourceCommit
      : execFileSync("git", ["rev-parse", "--short", "HEAD"], {
          cwd: REPO_ROOT,
          encoding: "utf8",
        }).trim();
  const outputs = await recordPackage(sourceCommit);
  mkdirSync(dir, { recursive: true });
  for (const [file, text] of outputs) writeFileSync(join(dir, file), text);
  return [...outputs.keys()];
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== "--check"))
    throw new Error("usage: node js/tools/record-chain-keys-geometry-admission.js [--check]");
  if (args[0] === "--check") {
    const result = await checkPackage(PACKAGE_DIR);
    for (const finding of result.findings) console.error(finding);
    (result.status === 0 ? console.log : console.error)(result.summary);
    process.exitCode = result.status;
  } else {
    for (const file of await writePackage(PACKAGE_DIR)) console.log(`wrote ${PACKAGE_ID}/${file}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 2;
  });
}
