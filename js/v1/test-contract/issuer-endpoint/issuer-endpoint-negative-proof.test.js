// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

export const ASSERTED_ENDPOINT_NEGATIVE_PROOF = true;

test("issuer-endpoint wrong binding fails at the denied response status", () => {
  const env = { ...process.env, npm_lifecycle_event: "test:contract:issuer-endpoint" };
  delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(
    process.execPath,
    [
      "test-contract/run-contract-target.js",
      "test-contract/issuer-endpoint/bindings/wrong-status-issuer-endpoint-binding.js",
    ],
    {
      cwd: new URL("../../", import.meta.url),
      env,
      encoding: "utf8",
    },
  );
  assert.equal(child.status, 1, "the contract lane rejects the wrong response");
  const transcript = `${child.stdout}\n${child.stderr}`;
  assert.match(transcript, /not ok \d+ - denied:/, "the denied contract case fails");
  assert.match(transcript, /denied answers the status the contract table holds/);
  assert.match(transcript, /expected: 401/);
  assert.match(transcript, /actual: 400/);
});
