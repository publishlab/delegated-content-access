// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

export const ASSERTED_GREEN_OUTER_PROOF = true;

test("issuer-core wrong binding fails at the raw policyData field", () => {
  const env = { ...process.env, npm_lifecycle_event: "test:contract:issuer-core" };
  delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(
    process.execPath,
    [
      "test-contract/run-contract-target.js",
      "test-contract/issuer-core/bindings/wrong-result-issuer-core-binding.js",
    ],
    {
      cwd: new URL("../../", import.meta.url),
      env,
      encoding: "utf8",
    },
  );
  assert.notEqual(child.status, 0, "the selector rejects the wrong raw core result");
  const transcript = `${child.stdout}\n${child.stderr}`;
  assert.match(
    transcript,
    /not ok 2 - seal-ecdh\.json: admit carries the original document/,
    "the expected format-1 success assertion fails",
  );
  assert.match(transcript, /policyData/, "the failure names the semantic field");
  assert.match(
    transcript,
    /wrong-policy-data/,
    "the diagnostic carries the wrong binding sentinel",
  );
  assert.match(
    transcript,
    /opaqueCoreContractSentinel: 'policy-data:seal-ecdh\.json'/,
    "the diagnostic carries the expected policyData sentinel",
  );
});
