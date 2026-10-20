import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { ISSUER_NAME } from "../../demo/scenarios/fixtures.js";
import { requestFor } from "../../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { DOMAIN, world } from "../../test-lib/fixtures/wire-policy-world.js";

describe("exact publisher registration at the issuer endpoint", () => {
  test("the request kid selects the registered verification key", async () => {
    const w = await world();
    const { processor, endpoint, publisherRegistration } = w.endpointWith();
    const { status, body } = await unlockThroughAdmission(
      processor,
      endpoint,
      requestFor((await w.render()).page, ISSUER_NAME, ["bodytext"]),
      publisherRegistration,
    );
    assert.equal(status, 200);
    assert.equal(typeof body.keys.contentKeys.bodytext, "string");
  });

  test("a wrong registration refuses before opening any key", async () => {
    const w = await world();
    const { processor, endpoint, publisherRegistrations } = w.endpointWith();
    const request = requestFor((await w.render()).page, ISSUER_NAME, ["bodytext"]);
    const wrong = publisherRegistrations.get("sign-2025-10-other");
    const { status, body } = await unlockThroughAdmission(processor, endpoint, request, wrong);
    assert.equal(status, 400);
    assert.equal(body.error, "unknown_publisher_key");
  });

  test("the policy coordinate is the verified signed origin, and the registration carries none", async () => {
    const w = await world();
    /** @type {any[]} */
    const seen = [];
    const { processor, endpoint, publisherRegistration } = w.endpointWith({
      accessPolicy: {
        decide(claims, requested, input) {
          seen.push(input.publisher);
          return { contentNames: requested.contentNames };
        },
      },
    });
    const rendered = await w.render();
    const { status } = await unlockThroughAdmission(
      processor,
      endpoint,
      requestFor(rendered.page, ISSUER_NAME, ["bodytext"]),
      publisherRegistration,
    );

    assert.equal(status, 200);
    assert.deepEqual(seen, [{ origin: `https://${DOMAIN}` }]);
    assert.equal(
      publisherRegistration.origins,
      undefined,
      "onboarding this publisher named no origin",
    );
  });
});
