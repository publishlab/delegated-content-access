import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { TimingWriter } from "../timing.mjs";

test("timing is opt-in and emits one compact worker record", () => {
  const directory = mkdtempSync(join(tmpdir(), "dca-bridge-"));
  const path = join(directory, "timing.json");
  try {
    const disabled = new TimingWriter();
    disabled.call(3);
    disabled.finish();
    assert.equal(existsSync(path), false);
    const enabled = new TimingWriter(path);
    enabled.call(1.5);
    enabled.call(3.5);
    enabled.finish({ ready: true });
    const record = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(record.calls, 2);
    assert.equal(record.maximumCallMs, 3.5);
    assert.equal(record.ready, true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
