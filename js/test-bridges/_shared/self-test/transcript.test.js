import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { TranscriptWriter } from "../transcript.mjs";

test("transcripts are opt-in append-only driver records", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-bridge-"));
  const path = join(directory, "worker.transcript.jsonl");
  try {
    const writer = new TranscriptWriter(path);
    writer.write("capabilities", { snapshot: { operations: ["one"] } });
    writer.write("final", { verdict: "pass" });
    const rows = readFileSync(path, "utf8").trim().split("\n").map(JSON.parse);
    assert.deepEqual(
      rows.map((row) => row.event),
      ["capabilities", "final"],
    );
    new TranscriptWriter().write("never", { written: false });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
