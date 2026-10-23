// @ts-check
//
// Tests the period-key composition recorder's package check and its refusals.
// Each case copies the recorded package into a temporary directory, damages
// the copy one way, and asserts the exact finding and exit status. The replay
// of the recorded exchange lives in
// js/test-vectors/period-key-composition.test.js.

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ISSUER_DECISIONS,
  MANIFEST_FILE,
  PACKAGE_DIR,
  checkPackage,
  readPrior,
  recordComposition,
  writePackage,
} from "../tools/record-period-key-composition.js";
import { CHECKSUM_FILE, checksumsText } from "../tools/checksums.js";
import { T_NEXT, T_NOW } from "../demo/scenarios/fixtures.js";

const RECORDER = fileURLToPath(
  new URL("../tools/record-period-key-composition.js", import.meta.url),
);
const REPO_ROOT = fileURLToPath(new URL("../../", import.meta.url));

/** The order of the P-256 group; `n - s` is the other valid ECDSA signature for one input. */
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/**
 * Runs `body` over a fresh copy of the recorded package and removes it after.
 *
 * @param {(dir: string) => Promise<void>} body
 */
async function withCopy(body) {
  const dir = `${mkdtempSync(join(tmpdir(), "dca-period-key-fixture-"))}/`;
  try {
    for (const name of readdirSync(PACKAGE_DIR)) copyFileSync(PACKAGE_DIR + name, dir + name);
    await body(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** @param {string} dir @param {string} name */
const read = (dir, name) => readFileSync(dir + name, "utf8");

/** @param {string} dir */
const snapshot = (dir) =>
  Object.fromEntries(readdirSync(dir).map((name) => [name, readFileSync(dir + name, "utf8")]));

/**
 * Rewrites the manifest sha256 values and SHA256SUMS over the payloads on
 * disk, so a tamper is consistent everywhere a checksum could catch it.
 *
 * @param {string} dir
 */
async function resum(dir) {
  const manifest = JSON.parse(read(dir, MANIFEST_FILE));
  const payloads = [];
  for (const member of manifest.members) {
    const bytes = readFileSync(dir + member.path);
    member.sha256 = Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex");
    payloads.push({ file: member.path, bytes });
  }
  writeFileSync(dir + MANIFEST_FILE, `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(dir + CHECKSUM_FILE, await checksumsText(payloads));
}

/**
 * Replaces render A's token signature everywhere it is recorded: the
 * renders.json field, its markup, and the request the client posted.
 *
 * @param {string} dir
 * @param {(signature: Uint8Array) => Uint8Array} change
 */
function replaceFirstSignature(dir, change) {
  const token = JSON.parse(read(dir, "renders.json")).steps[0].resourceJWT;
  const signature = token.split(".")[2];
  const replaced = Buffer.from(
    change(new Uint8Array(Buffer.from(signature, "base64url"))),
  ).toString("base64url");
  for (const name of ["renders.json", "exchange.json"]) {
    const text = read(dir, name);
    assert.ok(text.includes(signature));
    writeFileSync(dir + name, text.replaceAll(signature, replaced));
  }
}

test("a clean copy of the recorded package holds every check", async () => {
  await withCopy(async (dir) => {
    const result = await checkPackage(dir);
    assert.deepEqual(result.findings, []);
    assert.equal(result.status, 0);
    assert.match(
      result.summary,
      /^7 recorded files match membership, checksums and a fresh recording$/,
    );
  });
});

test("a missing member fails membership", async () => {
  await withCopy(async (dir) => {
    rmSync(`${dir}exchange.json`);
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    assert.ok(
      result.findings.includes("membership: missing exchange.json"),
      result.findings.join("\n"),
    );
  });
  await withCopy(async (dir) => {
    rmSync(`${dir}README.md`);
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    assert.deepEqual(
      result.findings,
      ["membership: missing README.md"],
      "the README is required but not hashed",
    );
  });
});

test("an extra file or directory fails membership, whatever its kind", async () => {
  await withCopy(async (dir) => {
    writeFileSync(`${dir}stray.json`, "{}\n");
    writeFileSync(`${dir}notes.txt`, "notes\n");
    mkdirSync(`${dir}nested`);
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    assert.deepEqual(
      result.findings.filter((finding) => finding.startsWith("membership:")).sort(),
      [
        "membership: extra nested/ (a package holds files only)",
        "membership: extra notes.txt",
        "membership: extra stray.json",
      ],
    );
  });
});

test("a manifest member with no file on disk fails membership", async () => {
  await withCopy(async (dir) => {
    const manifest = JSON.parse(read(dir, MANIFEST_FILE));
    manifest.members.unshift({ path: "absent.json", sha256: "0".repeat(64) });
    writeFileSync(dir + MANIFEST_FILE, `${JSON.stringify(manifest, null, 2)}\n`);
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    assert.ok(result.findings.includes("membership: missing absent.json"));
    assert.ok(result.findings.includes(`membership: ${CHECKSUM_FILE} omits absent.json`));
  });
});

test("a changed byte fails the checksums and the regeneration", async () => {
  await withCopy(async (dir) => {
    const text = read(dir, "exchange.json");
    const periodKey = JSON.parse(text).exchanges[0].body.keys.periodKeys.find(
      (/** @type {any} */ record) =>
        record.accessGroup === "premium" && record.period === "251023T1400",
    ).key;
    const flipped = `${periodKey[0] === "A" ? "B" : "A"}${periodKey.slice(1)}`;
    writeFileSync(`${dir}exchange.json`, text.replace(`"${periodKey}"`, `"${flipped}"`));
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    assert.deepEqual(result.findings, [
      "checksum: exchange.json (manifest.json)",
      "checksum: exchange.json (SHA256SUMS)",
      "drift: exchange.json",
    ]);
  });
});

test("a tamper with rewritten checksums still fails the regeneration", async () => {
  // Membership and checksums hold here, so only a fresh recording catches it.
  await withCopy(async (dir) => {
    const text = read(dir, "exchange.json");
    writeFileSync(`${dir}exchange.json`, text.replace('"status": 401', '"status": 200'));
    await resum(dir);
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    assert.deepEqual(result.findings, [
      "drift: exchange.json",
      "drift: manifest.json",
      "drift: SHA256SUMS",
    ]);
  });
});

test("a different valid signature over the same header and payload is retained", async () => {
  // ECDSA admits (r, n - s) beside (r, s). Retention keeps whichever valid
  // signature is recorded, so a regeneration never needs the old random bytes.
  await withCopy(async (dir) => {
    replaceFirstSignature(dir, (signature) => {
      const s = BigInt(`0x${Buffer.from(signature.subarray(32)).toString("hex")}`);
      const other = (P256_ORDER - s).toString(16).padStart(64, "0");
      return new Uint8Array([...signature.subarray(0, 32), ...Buffer.from(other, "hex")]);
    });
    const unsummed = await checkPackage(dir);
    assert.deepEqual(unsummed.findings, [
      "checksum: exchange.json (manifest.json)",
      "checksum: exchange.json (SHA256SUMS)",
      "checksum: renders.json (manifest.json)",
      "checksum: renders.json (SHA256SUMS)",
      "drift: manifest.json",
      "drift: SHA256SUMS",
    ]);
    await resum(dir);
    const summed = await checkPackage(dir);
    assert.deepEqual(summed.findings, []);
    assert.equal(summed.status, 0);
  });
});

test("a signature that does not verify is not retained, so the regeneration drifts", async () => {
  await withCopy(async (dir) => {
    replaceFirstSignature(dir, (signature) => {
      const changed = Uint8Array.from(signature);
      changed[63] ^= 1;
      return changed;
    });
    await resum(dir);
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    assert.ok(result.findings.includes("drift: renders.json"), result.findings.join("\n"));
    assert.ok(result.findings.includes("drift: exchange.json"), "the client posts the new token");
  });
});

test("two recordings from the same package write the same text, equal to the package", async () => {
  const prior = readPrior(PACKAGE_DIR);
  const first = await recordComposition({ prior });
  const second = await recordComposition({ prior });
  assert.deepEqual([...first.keys()].sort(), [...second.keys()].sort());
  for (const [name, text] of first) {
    assert.equal(second.get(name), text, name);
    assert.equal(read(PACKAGE_DIR, name), text, `${name} on disk`);
  }
});

test("the recorder refuses a story that shows no partial grant or no refusal", async () => {
  const wholeGrant = structuredClone(ISSUER_DECISIONS);
  wholeGrant[0].periodGrants = [{ accessGroup: "premium", periods: [T_NOW, T_NEXT] }];
  await assert.rejects(
    recordComposition({ issuerDecisions: wholeGrant, sourceCommit: () => "test" }),
    /refusing to record: step 1 must grant only the current period/,
  );
  const noRefusal = structuredClone(ISSUER_DECISIONS);
  noRefusal[1].periodGrants = [{ accessGroup: "premium", periods: [T_NEXT] }];
  await assert.rejects(
    recordComposition({ issuerDecisions: noRefusal, sourceCommit: () => "test" }),
    /refusing to record: step 3 must be refused with no keys/,
  );
});

test("a frozen package is never rewritten", async () => {
  await withCopy(async (dir) => {
    const manifest = JSON.parse(read(dir, MANIFEST_FILE));
    manifest.stability = "frozen";
    writeFileSync(dir + MANIFEST_FILE, `${JSON.stringify(manifest, null, 2)}\n`);
    const before = snapshot(dir);
    await assert.rejects(writePackage(dir), /is frozen, and this run would overwrite it/);
    assert.deepEqual(snapshot(dir), before);
  });
});

test("a check that cannot read the package exits 2", async () => {
  const missing = await checkPackage(join(tmpdir(), "dca-period-key-fixture-absent/"));
  assert.equal(missing.status, 2);
  assert.match(missing.summary, /could not run: no package directory/);
  await withCopy(async (dir) => {
    writeFileSync(dir + MANIFEST_FILE, "not json\n");
    const unreadable = await checkPackage(dir);
    assert.equal(unreadable.status, 2);
    assert.match(unreadable.summary, /could not run: manifest.json is missing or not JSON/);
  });
});

test("the CLI checks the recorded package from the repository root and writes nothing", async () => {
  const before = snapshot(PACKAGE_DIR);
  const check = spawnSync(process.execPath, [RECORDER, "--check"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  assert.equal(check.status, 0, `${check.stdout}${check.stderr}`);
  assert.equal(check.stderr, "");
  assert.equal(
    check.stdout.trim().split("\n").at(-1),
    "7 recorded files match membership, checksums and a fresh recording",
  );

  const unknown = spawnSync(process.execPath, [RECORDER, "--dir", "/tmp"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  assert.equal(unknown.status, 2);
  assert.match(
    unknown.stderr,
    /usage: node js\/tools\/record-period-key-composition.js \[--check\]/,
  );
  assert.deepEqual(snapshot(PACKAGE_DIR), before);
});
