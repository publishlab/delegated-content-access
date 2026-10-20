// @ts-check
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
  PACKAGE_DIR,
  PACKAGE_FILES,
  checkPackage,
  recordPackage,
  writePackage,
} from "../tools/record-chain-keys-geometry-admission.js";

/** @param {string} dir */
const snapshot = (dir) =>
  Object.fromEntries(readdirSync(dir).map((file) => [file, readFileSync(join(dir, file), "utf8")]));

/** @param {(dir: string) => Promise<void>} run */
async function withCopy(run) {
  const dir = mkdtempSync(join(tmpdir(), "dca-geometry-admission-"));
  try {
    for (const file of PACKAGE_FILES) copyFileSync(join(PACKAGE_DIR, file), join(dir, file));
    await run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("recording and checking are repeatable and checking writes nothing", async () => {
  await withCopy(async (dir) => {
    const before = snapshot(dir);
    assert.equal((await checkPackage(dir)).status, 0);
    assert.deepEqual(snapshot(dir), before);
    await writePackage(dir);
    await writePackage(dir);
    assert.deepEqual(snapshot(dir), before, "unchanged recording also retains source provenance");
  });
});

test("exact membership rejects missing payloads, README, extra files and directories", async () => {
  for (const file of ["inputs.json", "README.md"])
    await withCopy(async (dir) => {
      rmSync(join(dir, file));
      const result = await checkPackage(dir);
      assert.equal(result.status, 1);
      assert.ok(result.findings.includes(`membership: missing ${file}`));
    });
  await withCopy(async (dir) => {
    writeFileSync(join(dir, "extra.json"), "{}\n");
    mkdirSync(join(dir, "nested"));
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    assert.ok(result.findings.includes("membership: extra or non-file extra.json"));
    assert.ok(result.findings.includes("membership: extra or non-file nested"));
  });
});

test("raw spelling loss fails checksums and regeneration despite equal parsed values", async () => {
  await withCopy(async (dir) => {
    const path = join(dir, "inputs.json");
    const raw = readFileSync(path, "utf8");
    const changed = raw.replace('"chainsPerDay": 2e0,', '"chainsPerDay": 2,');
    assert.deepEqual(JSON.parse(changed), JSON.parse(raw));
    writeFileSync(path, changed);
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    for (const finding of [
      "drift: inputs.json",
      "checksum: inputs.json (manifest.json)",
      "checksum: inputs.json (SHA256SUMS)",
    ])
      assert.ok(result.findings.includes(finding), finding);
  });
});

test("rewritten hashes cannot bless changed independent expectations", async () => {
  await withCopy(async (dir) => {
    const path = join(dir, "expected.json");
    writeFileSync(
      path,
      readFileSync(path, "utf8").replaceAll('"windowMinutes": 720', '"windowMinutes": 721'),
    );
    const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
    const sums = [];
    for (const member of manifest.members) {
      member.sha256 = Buffer.from(
        await crypto.subtle.digest("SHA-256", readFileSync(join(dir, member.path))),
      ).toString("hex");
      sums.push(`${member.sha256}  ${member.path}`);
    }
    writeFileSync(join(dir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    writeFileSync(join(dir, "SHA256SUMS"), `${sums.join("\n")}\n`);
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    assert.ok(result.findings.includes("drift: expected.json"));
    assert.ok(!result.findings.some((finding) => finding.startsWith("checksum:")));
  });
});

test("a frozen package can be checked but never rewritten", async () => {
  await withCopy(async (dir) => {
    const path = join(dir, "manifest.json");
    const manifest = JSON.parse(readFileSync(path, "utf8"));
    manifest.stability = "frozen";
    writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
    const before = snapshot(dir);
    assert.equal((await checkPackage(dir)).status, 0);
    await assert.rejects(writePackage(dir), /refusing to overwrite a frozen/);
    assert.deepEqual(snapshot(dir), before);
  });
});

test("manifest membership itself cannot hide payloads", async () => {
  await withCopy(async (dir) => {
    const path = join(dir, "manifest.json");
    const manifest = JSON.parse(readFileSync(path, "utf8"));
    manifest.members.pop();
    writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
    const result = await checkPackage(dir);
    assert.equal(result.status, 1);
    assert.ok(result.findings.includes("drift: manifest.json"));
    assert.ok(result.findings.some((finding) => finding.startsWith("checksum:")));
  });
});

test("unreadable package reports could-not-run, CLI works from a foreign cwd", async () => {
  await withCopy(async (dir) => {
    writeFileSync(join(dir, "manifest.json"), "not json\n");
    assert.equal((await checkPackage(dir)).status, 2);
    assert.equal((await checkPackage(join(dir, "absent"))).status, 2);
  });
  const before = snapshot(PACKAGE_DIR);
  const recorder = fileURLToPath(
    new URL("../tools/record-chain-keys-geometry-admission.js", import.meta.url),
  );
  const result = spawnSync(process.execPath, [recorder, "--check"], {
    cwd: tmpdir(),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /6 recorded files.*9 geometry cases/);
  const misuse = spawnSync(process.execPath, [recorder, "--unknown"], { encoding: "utf8" });
  assert.equal(misuse.status, 2);
  assert.deepEqual(snapshot(PACKAGE_DIR), before);
});

test("expectations are held independently of recorded domain observations", async () => {
  const files = await recordPackage("test");
  const expected = JSON.parse(files.get("expected.json") ?? "null");
  const observed = JSON.parse(files.get("observations.json") ?? "null");
  assert.deepEqual(observed.cases, expected.cases);
  assert.equal(
    expected.cases.filter((/** @type {{admitted: boolean}} */ entry) => entry.admitted).length,
    5,
  );
  assert.equal(
    expected.cases.filter((/** @type {{admitted: boolean}} */ entry) => !entry.admitted).length,
    4,
  );
  assert.ok(expected.authority.includes("docs/spec-profile--chain-keys.md#document-member"));
});
