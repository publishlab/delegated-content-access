import test from "node:test";
import assert from "node:assert/strict";
import { t0World, t0Client, exchange, TEXT, BEFORE } from "../../chain-keys/test/t0-world.js";
import { ChainKeyCache } from "../../chain-keys/core-client/ChainKeyCache.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import { world, item, chainPolicy, T12, NEXT } from "./_lib/world.js";

test("explicit unlock holds every recovered item before a capacity-one response lease ends", async () => {
  const w = await world();
  const issuer = w.issuer({
    policy(input) {
      const decision = chainPolicy()(input);
      return { ...decision, grants: decision.grants.filter((grant) => grant.kind === "chain") };
    },
  });
  const page = await w.publish({
    items: [item("bodytext", ["sports"], "body"), item("caption", ["sports"], "caption")],
  });
  const reader = w.reader({ limits: { maxCachedWindows: 1 } });
  const client = reader.client(page, issuer);

  const result = await client.attempt(["bodytext", "caption"]);
  assert.equal(result.status, 200);
  assert.equal(result.application.accepted, 2);
  assert.equal((await reader.chainKeyCache().entries()).length, 1);
  for (const [name, text] of [
    ["bodytext", "body"],
    ["caption", "caption"],
  ]) {
    assert.equal(
      utf8Decode((await client.delivery.openLocal(name)).bytes),
      text,
      "the obtaining unlock holds the authenticated key even when its family is evicted",
    );
  }
  assert.equal(client.sent.length, 1, "openLocal makes no second acquisition");
});

async function generations(maxTrialsPerItem) {
  const w = await world();
  const issuer = w.issuer();
  const reader = w.reader({ limits: { maxRivalsPerWindow: 5, maxTrialsPerItem } });
  const pages = [];
  for (let i = 1; i <= 5; i++) {
    const page = await w.publish({
      retainedSecret: new Uint8Array(32).fill(i),
      items: [item("bodytext", ["sports"], `generation ${i}`)],
    });
    pages.push(page);
    const client = reader.client(page, issuer);
    await client.unlock(["bodytext"]);
    assert.equal(
      await client.open("bodytext"),
      `generation ${i}`,
      "each genuine admitted grant opens in its obtaining operation",
    );
  }
  assert.equal((await reader.chainKeyCache().entries()).length, 5);
  return { reader, issuer, pages };
}

test("five retained content-group rivals open cold within an adequate item trial budget", async () => {
  const { reader, issuer, pages } = await generations(4096);
  for (const [i, page] of pages.entries()) {
    const local = reader.client(page, issuer);
    assert.equal(await local.open("bodytext"), `generation ${i + 1}`);
    assert.equal(local.sent.length, 0, "retained reuse makes no request");
  }
});

test("a deliberately lower trial limit leaves an older retained rival unread", async () => {
  const { reader, issuer, pages } = await generations(4);
  const old = reader.client(pages[0], issuer);
  assert.equal(await old.open("bodytext"), null);
  assert.equal(old.sent.length, 0);
  assert.equal(
    await reader.client(pages[4], issuer).open("bodytext"),
    "generation 5",
    "the same finite allowance still opens a recent retained rival",
  );
  await old.unlock(["bodytext"]);
  assert.equal(
    await old.open("bodytext"),
    "generation 1",
    "a new authorized obtaining-operation grant is usable despite the lower retained-read budget",
  );
});

async function plain(client, page) {
  return utf8Decode(
    await client.decrypt(client.parse(page), "bodytext", client.extract(page, "bodytext")),
  );
}
test("ordinary five-retained counterpart shows memo-assisted warm reuse and independent four-chain cold-coordinate cap", async () => {
  const cache = new ChainKeyCache({ maxRivalsPerWindow: 5 });
  const pages = [];
  const coldPages = [];
  for (let i = 1; i <= 5; i++) {
    const { world, render } = await t0World({
      secretFill: i,
      authorizePeriod: (t) => t < "251023T1200",
    });
    for (let j = 0; j < i; j++) await render();
    const page = await render();
    pages.push(page);
    coldPages.push(await render("2025-10-23T10:00:00Z"));
    world.clock.set(BEFORE);
    const { client } = t0Client(cache);
    assert.equal((await exchange(world, client, page)).response.status, 200);
    assert.equal(await plain(client, page), TEXT);
  }
  assert.equal((await cache.entries()).filter((e) => e.kind === "chain-key").length, 5);
  const results = [];
  for (const page of pages) {
    const { client } = t0Client(cache);
    const key = await client.contentKeyFor(client.parse(page), "bodytext");
    results.push(key !== null);
    if (key) assert.equal(await plain(client, page), TEXT);
  }
  assert.deepEqual(results, [true, true, true, true, true]);
  const cold = [];
  for (const page of coldPages) {
    const { client } = t0Client(cache);
    const key = await client.contentKeyFor(client.parse(page), "bodytext");
    cold.push(key !== null);
    if (key) assert.equal(await plain(client, page), TEXT);
  }
  assert.deepEqual(cold, [false, true, true, true, true]);
});

test("sparse content names across two windows preserve first use at capacity one and reacquire evicted name", async () => {
  const w = await world();
  const policy = (input) => ({
    grants: Object.entries(input.contentGroups).flatMap(([contentName, { groups, windows }]) =>
      groups.flatMap((group) =>
        windows.map((windowStart) => ({
          kind: "chain",
          contentName,
          group,
          windowStart,
          cutoffT: windowStart === T12 ? "261014T1800" : "261015T0600",
        })),
      ),
    ),
    authorizePeriod: () => true,
  });
  const issuer = w.issuer({ policy });
  const items = [item("bodytext", ["sports"], "body"), item("caption", ["sports"], "caption")];
  const old = await w.publish({ items });
  const next = await w.publish({ at: NEXT, items });
  const future = await w.publish({ at: "261015T0700", items });
  const reader = w.reader({ limits: { maxCachedWindows: 1 } });
  const first = reader.client(old, issuer);
  await first.unlock(["bodytext", "caption"]);
  assert.equal(await first.open("bodytext"), "body");
  assert.equal(await first.open("caption"), "caption");
  assert.equal((await reader.chainKeyCache().entries()).length, 1);
  const local = reader.client(next, issuer);
  const sparse = [await local.open("bodytext"), await local.open("caption")];
  assert.equal(sparse.filter((x) => x !== null).length, 1);
  assert.equal(local.sent.length, 0);
  await local.unlock(["bodytext", "caption"]);
  assert.equal(await local.open("bodytext"), "body");
  assert.equal(await local.open("caption"), "caption");
  const later = reader.client(future, issuer);
  assert.equal(await later.open("bodytext"), null);
  assert.equal(await later.open("caption"), null);
});
