//
// Direct demo IssuerServer configuration behavior. Policy and browser stories
// live in access-policy-core.test.js and access-policy.test.js respectively.

import test from "node:test";
import assert from "node:assert/strict";

import { IssuerServer } from "../demo/actors/IssuerServer.js";
import { actorWorld } from "../demo/scenarios/world.js";

test("a server requires a policy that can decide", async () => {
  const { network, clock, publisherRegistrations } = await actorWorld();

  for (const accessPolicy of [undefined, {}]) {
    assert.throws(
      () =>
        new IssuerServer({
          clock,
          network,
          issuerName: "paywall_third_service",
          unlockUrl: "https://third.example.com/unlock",
          keyStore: { get: () => undefined },
          publisherRegistrations,
          ...(accessPolicy === undefined ? {} : { accessPolicy }),
        }),
      (/** @type {any} */ err) => err.code === "bad_config",
    );
  }
});
