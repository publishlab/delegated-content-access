// @ts-check
//
// Sparse vocabulary on the named-record wire. A page whose items author
// different group sets carries one connector record per authored group and
// nothing for the groups an item does not use. A reader that asks for one
// group of one item sends records for that coordinate only, and the answer
// names that coordinate only: no record pads an unused group, item or window
// into the exchange.

import test from "node:test";
import assert from "node:assert/strict";

import { item, names, world } from "./_lib/world.js";
import { connectorsOf } from "./_lib/records.js";

test("a 1-of-100 group publishes, requests and answers one coordinate, with no padding", async () => {
  const w = await world();
  const vocabulary = names(100);
  const only = vocabulary[57];
  const published = await w.publish({ items: [item("wide", vocabulary), item("narrow", [only])] });

  // The page carries each item's own authored groups, one record each.
  assert.deepEqual(
    connectorsOf(published.page, "narrow").map((record) => record.group),
    [only],
  );
  assert.deepEqual(
    connectorsOf(published.page, "wide").map((record) => record.group),
    vocabulary,
  );

  const issuer = w.issuer();
  const client = w.reader().client(published, issuer, {
    narrowing: { requestedContentGroups: { narrow: [only] } },
  });
  await client.unlock(["narrow"]);
  assert.equal(await client.open("narrow"), "content:narrow");

  // The request names one content name and one group, and relays only that
  // name's seeds: nothing of `wide` and none of the other 99 groups.
  assert.equal(client.sent.length, 1);
  const [sent] = client.sent;
  assert.deepEqual(sent.requested.contentGroups, [{ contentName: "narrow", groups: [only] }]);
  assert.ok(sent.sealed.contentWindowSeeds.length > 0);
  for (const seed of sent.sealed.contentWindowSeeds) assert.equal(seed.contentName, "narrow");
  for (const route of sent.requested.contentKeys ?? []) assert.equal(route.contentName, "narrow");

  // The answer holds records at the requested coordinate only.
  const answered = issuer.calls.answers[0].body.contentGroupKeys;
  const records = [
    ...(answered.chainKeys ?? []),
    ...(answered.periodKeys ?? []),
    ...(answered.contentKeys ?? []),
  ];
  assert.ok(records.length > 0);
  for (const record of records) {
    assert.equal(record.contentName, "narrow");
    if (record.group !== undefined) assert.equal(record.group, only);
  }
  assert.equal(answered.errors, undefined);
});
