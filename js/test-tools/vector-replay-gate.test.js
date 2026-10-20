import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const gate = fileURLToPath(new URL("../../verification/vectors/check-replays.sh", import.meta.url));

test("the all-set gate rejects a set without a replayer", () => {
  const result = spawnSync(
    "sh",
    [gate, "--check-map", "v1/baseline/rsa-oaep-envelope-open", "v1-new-set"],
    {
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 2);
  assert.match(result.stderr, /no replayer for set v1-new-set/);
});
