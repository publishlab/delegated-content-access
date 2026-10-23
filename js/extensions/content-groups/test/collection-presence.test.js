// @ts-check
// Present malformed collections are not omission. Keep candidate refusal
// atomic while retaining independently admitted ordinary capabilities.
import test from "node:test";
import assert from "node:assert/strict";
import { world, item } from "./_lib/world.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { ContentGroupRequestBuilder } from "../core-client/ContentGroupRequestBuilder.js";

test("null request collections refuse before policy through the issuer endpoint", async (t) => {
  const w = await world();
  const p = await w.publish({
    ordinary: ["headline"],
    items: [item("bodytext", ["politics"]), item("headline")],
  });
  const base = new ContentGroupRequestBuilder()
    .build(new DcaData(p.page, { publisherOrigin: p.origin }), "issuer", ["bodytext", "headline"])
    .toObject();
  for (const name of ["contentGroups", "contentKeys", "requestedChainCutoffs"]) {
    await t.test(name, async () => {
      const issuer = w.issuer();
      const request =
        name === "requestedChainCutoffs"
          ? { ...base, [name]: null }
          : { ...base, requested: { ...base.requested, [name]: null } };
      const response = await issuer.answer(request);
      assert.equal(response.status, 400);
      assert.equal(response.code, "binding_failed");
      assert.equal(issuer.calls.decide.length, 0, "malformed input never reaches policy");
    });
  }
  const issuer = w.issuer();
  assert.equal(
    (await issuer.answer(base)).status,
    200,
    "omitted optional collections remain valid",
  );
  assert.equal(issuer.calls.decide.length, 1);
});

test("malformed response errors refuse the candidate member while the ordinary sibling opens", async (t) => {
  const w = await world();
  const p = await w.publish({
    ordinary: ["headline"],
    items: [item("bodytext", ["politics"]), item("headline")],
  });
  for (const errors of [undefined, {}, null, false, { periodKeys: null }]) {
    await t.test(String(JSON.stringify(errors)), async () => {
      const client = w.reader().client(p, w.issuer(), {
        answered: (/** @type {any} */ body) => {
          if (errors !== undefined) body.contentGroupKeys.errors = errors;
          return body;
        },
      });
      const answer = await client.unlock(["bodytext", "headline"]);
      const valid =
        errors === undefined ||
        (errors !== null && typeof errors === "object" && Object.keys(errors).length === 0);
      assert.deepEqual(answer.missing, valid ? [] : ["bodytext"]);
      assert.ok(await client.open("headline"), "an independent ordinary key remains usable");
      if (valid)
        assert.ok(await client.open("bodytext"), "absent or empty errors permit the candidate");
      else
        assert.equal(
          await client.open("bodytext"),
          null,
          "no key from the malformed member is retained",
        );
    });
  }
});

test("malformed requested containers refuse before policy, including ordinary siblings", async (t) => {
  const w = await world();
  const p = await w.publish({
    ordinary: ["headline"],
    items: [item("bodytext", ["politics"]), item("headline")],
  });
  const base = new ContentGroupRequestBuilder()
    .build(new DcaData(p.page, { publisherOrigin: p.origin }), "issuer", ["bodytext", "headline"])
    .toObject();
  for (const requested of [null, false, 7, "groups", []]) {
    await t.test(JSON.stringify(requested), async () => {
      const issuer = w.issuer();
      const response = await issuer.answer({ ...base, requested });
      assert.equal(response.status, 400);
      assert.equal(response.code, "binding_failed");
      assert.equal(issuer.calls.decide.length, 0);
    });
  }
});
