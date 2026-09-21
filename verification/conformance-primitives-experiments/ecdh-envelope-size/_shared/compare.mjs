#!/usr/bin/env node
// The only place that holds expectations and assigns verdicts. It reads the
// frozen fixture and one observation file per runtime, holds every runtime
// against the recorded `expected` block, then holds the runtimes against each
// other, prints the matrix, and exits 0 when every answered observation
// matched, 1 when one did not, and 2 when something was not answered at all.
//
//     node _shared/compare.mjs <observations.json> ...
//
// `node/probe.mjs --record` writes the `expected` block this file reads. A
// runtime that says `unsupported` for a profile is printed as such and fails
// nothing: it answered inside the contract by saying its library has no way in.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import process from "node:process";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(join(here, "fixture.json"), "utf8"));
const expected = fixture.expected;

const paths = process.argv.slice(2);
if (paths.length === 0) {
  console.error("compare.mjs needs at least one observation file");
  process.exit(2);
}

const PROFILES = Object.keys(expected.profiles);
const CHECKS = ["seal", "derive", "open", "wrong-bind", "tamper", "invalid-point", "non-residue", "widths"];

// Which recorded field each column reads, so a runtime is held against the
// recording field by field rather than through a second description of it.
const FIELDS = {
  seal: ["envelopeHex", "envelopeBase64url"],
  derive: ["derivedKeyHex", "derivedNonceHex"],
  open: ["openedKeyHex"],
  "wrong-bind": ["wrongBind"],
  tamper: ["flippedCiphertext"],
  "invalid-point": ["invalidPoint"],
  "non-residue": ["nonResiduePoint"],
  widths: ["decodedBytes", "base64urlChars", "pointBytes"],
};
const ALL_FIELDS = Object.values(FIELDS).flat();

const disagreements = [];
const incomplete = [];
const unsupported = [];
const rows = [];
const modes = [];
const answered = new Map(PROFILES.map((profile) => [profile, []]));

function note(list, runtime, profile, check, want, got) {
  list.push({ runtime, profile, check, want, got });
}

// base64url without padding grows by four characters per three bytes, so the
// width is computed rather than read from a second recorded literal.
function base64urlWidth(byteLength) {
  return Math.ceil((byteLength * 4) / 3);
}

function equalPair(a, b) {
  return a && b && a.keyHex === b.keyHex && a.nonceHex === b.nonceHex;
}

function profileRow(runtime, profile, observed) {
  const want = expected.profiles[profile];
  const verdicts = {};

  if (observed?.status === "unsupported") {
    for (const check of CHECKS) verdicts[check] = "n/a";
    unsupported.push({ runtime, profile, reason: observed.reason ?? "no reason given" });
    return verdicts;
  }
  if (!observed || observed.status !== "answered") {
    for (const check of CHECKS) verdicts[check] = "none";
    note(incomplete, runtime, profile, "status", "answered", observed?.status ?? "missing");
    return verdicts;
  }

  for (const check of CHECKS) {
    let held = true;
    for (const field of FIELDS[check]) {
      if (want[field] === observed[field]) continue;
      held = false;
      note(disagreements, runtime, profile, `${check} (${field})`, want[field], observed[field]);
    }
    verdicts[check] = held ? "ok" : "BAD";
  }

  // The width is recorded as one literal and read a second time through the
  // arithmetic, so a recording that disagreed with base64url itself shows up here.
  if (observed.base64urlChars !== base64urlWidth(observed.decodedBytes)) {
    verdicts.widths = "BAD";
    note(
      disagreements,
      runtime,
      profile,
      "widths (base64url arithmetic)",
      base64urlWidth(observed.decodedBytes),
      observed.base64urlChars,
    );
  }

  answered.get(profile).push({ runtime, observed });
  return verdicts;
}

function reuseRows(runtime, observations) {
  for (const profile of PROFILES) {
    const pairs = observations.ephemeralReuse?.[profile];
    const wanted = observations.profiles?.[profile]?.status === "answered" &&
      expected.profiles[profile].decodedBytes !== 109;
    if (!wanted) continue;
    if (!pairs) {
      note(incomplete, runtime, profile, "ephemeral-reuse", "four derived pairs", "missing");
      continue;
    }
    const want = expected.ephemeralReuse;
    const checks = [
      ["repeat is identical", equalPair(pairs.sameEphemeralSameBind, pairs.sameEphemeralSameBindRepeat), true],
      ["another BIND differs", equalPair(pairs.sameEphemeralSameBind, pairs.sameEphemeralOtherBind), false],
      ["fresh ephemeral differs", equalPair(pairs.sameEphemeralSameBind, pairs.freshEphemeralSameBind), false],
      ["same-BIND pair matches the recording", equalPair(pairs.sameEphemeralSameBind, want.sameEphemeralSameBind), true],
      ["other-BIND pair matches the recording", equalPair(pairs.sameEphemeralOtherBind, want.sameEphemeralOtherBind), true],
      [
        "fresh-ephemeral pair matches the recording",
        equalPair(pairs.freshEphemeralSameBind, want.freshEphemeralSameBind),
        true,
      ],
    ];
    for (const [label, got, wantValue] of checks) {
      if (got !== wantValue) note(disagreements, runtime, profile, `ephemeral reuse: ${label}`, wantValue, got);
    }
  }
}

// Two runtimes matching the recording already agree, so this checks the same
// thing a second way and catches the case a recording cannot: a field one
// runtime reports and another leaves out.
function crossRuntime() {
  const lines = [];
  for (const profile of PROFILES) {
    const seen = answered.get(profile);
    if (seen.length < 2) {
      lines.push(`  ${profile.padEnd(22)}${seen.length} runtime answered, so there is no pair to compare`);
      continue;
    }
    const [first, ...rest] = seen;
    let held = true;
    for (const other of rest) {
      for (const field of ALL_FIELDS) {
        if (first.observed[field] === other.observed[field]) continue;
        held = false;
        note(
          disagreements,
          `${first.runtime} vs ${other.runtime}`,
          profile,
          `cross-runtime (${field})`,
          first.observed[field],
          other.observed[field],
        );
      }
    }
    lines.push(
      `  ${profile.padEnd(22)}${seen.map((s) => s.runtime).join(", ")}: ${held ? "same bytes" : "DIFFERENT bytes"}`,
    );
  }
  return lines;
}

for (const path of paths) {
  let observations;
  try {
    observations = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    note(incomplete, path, "-", "observation file", "parseable JSON", error.message);
    continue;
  }
  const runtime = observations.runtime ?? path;
  modes.push(
    `${runtime.padEnd(8)} ${observations.runtimeVersion} / ${observations.cryptoProvider} / ` +
      `compressed-point import: ${observations.compressedPointImport}`,
  );
  for (const profile of PROFILES) {
    rows.push({ runtime, profile, verdicts: profileRow(runtime, profile, observations.profiles?.[profile]) });
  }
  reuseRows(runtime, observations);
}

const crossLines = crossRuntime();

const cell = (value) => String(value).padEnd(15);
console.log("runtimes");
for (const mode of modes) console.log(`  ${mode}`);
console.log("");
console.log(`  ${"runtime".padEnd(8)}${"profile".padEnd(22)}${CHECKS.map(cell).join("")}`);
for (const row of rows) {
  console.log(
    `  ${row.runtime.padEnd(8)}${row.profile.padEnd(22)}${CHECKS.map((c) => cell(row.verdicts[c] ?? "-")).join("")}`,
  );
}
console.log("");
console.log(`  against the recording in fixture.json, recorded by ${expected.recordedBy}`);
console.log("");
console.log("  runtimes against each other");
for (const line of crossLines) console.log(line);
console.log("");
console.log("  widths");
for (const profile of PROFILES) {
  const want = expected.profiles[profile];
  console.log(
    `  ${profile.padEnd(22)}${want.decodedBytes} decoded bytes, ` +
      `${want.base64urlChars} unpadded base64url characters`,
  );
}
console.log("");
if (unsupported.length > 0) {
  console.log("  unsupported, which fails nothing");
  for (const entry of unsupported) {
    console.log(`  ${entry.runtime.padEnd(8)}${entry.profile.padEnd(22)}${entry.reason}`);
  }
  console.log("");
}

if (incomplete.length > 0) {
  const first = incomplete[0];
  console.log(`RESULT: partial. ${first.runtime} ${first.profile} ${first.check}: wanted ${first.want}, got ${first.got}`);
  process.exit(2);
}
if (disagreements.length > 0) {
  const first = disagreements[0];
  console.log("RESULT: disagreement. The first one in full:");
  console.log(`  runtime: ${first.runtime}`);
  console.log(`  profile: ${first.profile}`);
  console.log(`  check:   ${first.check}`);
  console.log(`  wanted:  ${first.want}`);
  console.log(`  got:     ${first.got}`);
  console.log(`  ${disagreements.length} disagreement(s) in total`);
  process.exit(1);
}
console.log(`RESULT: every runtime matched the recording on the profiles it answered, across ${PROFILES.length} profiles.`);
process.exit(0);
