// Real default request alternatives and per-item connector refusal.
import test from "node:test";
import assert from "node:assert/strict";
import { world, item, chainPolicy } from "./_lib/world.js";
import { find, findAll } from "./_lib/records.js";

const denied = () => ({ grants: [], authorizePeriod: () => false });
const itemOnly = (input) => ({
  grants: input.items.map((contentName) => ({ kind: "item", contentName })),
  authorizePeriod: () => false,
});
const reusableOnly = (input) => ({
  ...chainPolicy()(input),
  grants: chainPolicy()(input).grants.filter((grant) => grant.kind !== "item"),
});

test("the same default request lets issuer policy choose reusable, item-only, or no access", async () => {
  const w = await world();
  const publication = await w.publish({ items: [item("bodytext", ["sports"], "entitled story")] });
  for (const [mode, policy] of [
    ["reusable", reusableOnly],
    ["item", itemOnly],
    ["denied", denied],
  ]) {
    const issuer = w.issuer({ policy });
    const client = w.reader().client(publication, issuer);
    await client.attempt(["bodytext"]);
    assert.equal(client.sent.length, 1, mode);
    assert.deepEqual(client.sent[0].requested.contentGroups, [
      { contentName: "bodytext", groups: ["sports"] },
    ]);
    assert.deepEqual(
      findAll(client.sent[0].requested.contentKeys, { contentName: "bodytext" }).map(
        (route) => route.group,
      ),
      ["sports"],
    );
    assert.equal(await client.open("bodytext"), mode === "denied" ? null : "entitled story");
    const result = issuer.calls.answers[0].body.contentGroupKeys;
    if (mode === "item") {
      assert.ok(find(result.contentKeys, { contentName: "bodytext" }));
      assert.equal(result.chainKeys, undefined);
      assert.equal(result.periodKeys, undefined);
    } else if (mode === "reusable") {
      assert.ok(find(result.chainKeys, { contentName: "bodytext" }));
      assert.equal(result.contentKeys, undefined);
    } else {
      assert.equal(result, undefined);
    }
  }
});

test("a malformed connector sibling leaves valid grouped and ordinary items openable", async () => {
  const w = await world();
  const publication = await w.publish({
    items: [
      item("bodytext", ["sports"], "valid body"),
      item("headline", ["sports"], "damaged"),
      item("purchase", undefined, "ordinary"),
    ],
    ordinary: ["purchase"],
  });
  // An empty connector collection does not admit: an item carries one to maxGroups records.
  find(publication.page.contentData, { contentName: "headline" }).connectors = [];
  const issuer = w.issuer({ policy: reusableOnly });
  const client = w.reader().client(publication, issuer);
  await client.attempt(["bodytext", "headline", "purchase"]);
  assert.equal(client.sent.length, 1);
  assert.deepEqual(
    client.sent[0].requested.contentGroups.map((entry) => entry.contentName),
    ["bodytext"],
  );
  assert.equal(await client.open("bodytext"), "valid body");
  assert.equal(await client.open("purchase"), "ordinary");
  assert.equal(await client.open("headline"), null);
});

test("a refused group response member preserves authenticated ordinary progress in the route walk", async () => {
  const w = await world();
  const publication = await w.publish({
    items: [item("bodytext", ["sports"], "grouped"), item("purchase", undefined, "ordinary")],
    ordinary: ["purchase"],
  });
  const issuer = w.issuer({ policy: reusableOnly });
  const client = w.reader().client(publication, issuer, {
    answered(body) {
      body.contentGroupKeys.unknown = {};
      return body;
    },
  });
  const result = await client.unlock(["bodytext", "purchase"]);
  assert.deepEqual(result.missing, ["bodytext"]);
  assert.equal(await client.open("purchase"), "ordinary");
  assert.equal(await client.open("bodytext"), null);
  assert.equal(client.sent.length, 1);
});
