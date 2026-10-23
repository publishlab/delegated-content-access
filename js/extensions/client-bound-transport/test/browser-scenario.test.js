// @ts-check
// Sibling to base suite: js/test-reference/demo-browser/scenario.test.js

import test from "node:test";
import assert from "node:assert/strict";

import { run } from "../../../demo/browser/scenario.js";
import { CONTENT_NAME } from "../../../demo/scenarios/fixtures.js";
import * as clientBoundEcdh from "../ecdhP256.js";
import { clientBoundKeyCapability } from "../core-client/clientBoundKeyCapability.js";
import { keyAt } from "../../../test-reference/support/namedRecords.js";

test("client-bound: the client offers a key, the issuer wraps to it, and the cache holds handles", async () => {
  const trace = await run(
    { transportMode: "client-bound" },
    { profile: clientBoundEcdh, capability: clientBoundKeyCapability },
  );
  const [unlock] = trace.steps.filter((step) => step.kind === "unlock");

  assert.equal(
    unlock.request.clientPublicKey.kty,
    "EC",
    "the client offers its public half, as a JWK",
  );
  assert.equal(unlock.request.clientPublicKey.d, undefined, "and only the public half");
  assert.equal(unlock.status, 200);
  assert.equal(unlock.transportMode, "client-bound");
  assert.equal(Object.hasOwn(unlock.response.transport, "mode"), false);
  assert.deepEqual(
    Object.keys(keyAt(unlock.response.keys.contentKeys, { contentName: CONTENT_NAME })),
    ["key", "nonce"],
    "a wrapped pair rather than the bytes",
  );

  // The client holds a handle it cannot export, so the trace says so in place
  // of base64url, the one thing the page must not print bytes for, because
  // there are none to print.
  for (const entry of unlock.cache) {
    assert.doesNotMatch(entry.key, /^[A-Za-z0-9_-]+$/, "a key handle never leaves the client");
  }

  // Underneath the transport the run is unchanged: one call, and the article
  // a period on still opens out of the cache.
  assert.equal(trace.summary.unlockCalls, 1);
  assert.equal(trace.summary.articlesOpened, 2);
});
