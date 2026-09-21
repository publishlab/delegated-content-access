import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { requestFor } from "../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";
import { BODYTEXT, ISSUER_NAME, world } from "../test-lib/fixtures/endpoint-hardening-world.js";

describe("The document, to its last byte", () => {
  test("no answer is made from a document that does not parse to its last byte", async () => {
    const { render, endpointWith, asked } = await world();
    const page = await render();

    const document = JSON.stringify(requestFor(page, ISSUER_NAME, [BODYTEXT]));

    // Streaming is not modelled anywhere here and is not faked: `Network`
    // hands a handler one whole payload, and the port takes one whole string,
    // so there is no point at which half a document exists to answer from.
    // The other half of the same rule is reachable: a document whose opening
    // parses and whose tail does not is refused whole, with nothing built from
    // the part that was good.
    const truncated = document.slice(0, Math.floor(document.length / 2));
    const trailing = `${document} and then some`;
    const twice = `${document}${document}`;

    for (const [name, body] of Object.entries({ truncated, trailing, twice })) {
      const { processor, endpoint, registration } = endpointWith({});
      const answer = await unlockThroughAdmission(processor, endpoint, body, registration);
      assert.equal(answer.status, 400, name);
      assert.equal(answer.body.error, "invalid_json", name);
      assert.equal(answer.body.keys, undefined, name);
    }
    assert.equal(asked.engine, 0, "a document that does not parse never reaches the engine");

    // The prefix of `trailing` is a request that would have been served, which
    // is what makes the refusal a decision rather than an accident.
    const { processor, endpoint, registration } = endpointWith({});
    const served = await unlockThroughAdmission(processor, endpoint, document, registration);
    assert.equal(served.status, 200);
  });
});
