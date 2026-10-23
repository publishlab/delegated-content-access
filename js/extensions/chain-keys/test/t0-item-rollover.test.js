// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { base64urlDecode, utf8Decode } from "../../../core-shared/codec.js";
import { decrypt } from "../../../core-shared/aead.js";
import { wrapNonceOf } from "../../../test-reference/support/contentKeyWrapNonceOctets.js";
import { ORIGIN, ISSUER_NAME } from "../../../demo/scenarios/fixtures.js";
import { GEOMETRY, TEXT, BEFORE, t0World, t0Client, exchange } from "./t0-world.js";
import { issuerBlockOf, periodsOn, wrapsOf } from "../../../test-lib/helpers/inspect.js";
import { periodKeyMap } from "../../../test-reference/support/namedRecords.js";
import { cutoffsOf } from "./world.js";

async function plaintext(client, page, name = "bodytext") {
  const data = client.parse(page);
  return utf8Decode(await client.decrypt(data, name, client.extract(page, name)));
}

const cutoffs = (body) => cutoffsOf(body.keys?.chainKeys, "premium").sort();

test("hourly T0-only items reuse independent T+6 grants before, at and after rollover", async () => {
  const { world, render, families } = await t0World();
  const before = await render();
  const at = await render("2025-10-23T12:00:00Z");
  const after = await render("2025-10-23T17:00:00Z");
  const future = await render("2025-10-23T18:00:00Z");
  for (const [page, label] of [
    [before, "251023T1100"],
    [at, "251023T1200"],
    [after, "251023T1700"],
  ]) {
    assert.deepEqual(periodsOn(page, "bodytext", "premium"), [label]);
  }
  world.clock.set(BEFORE);
  const initial = t0Client();
  const unlocked = await exchange(world, initial.client, before);
  assert.equal(unlocked.response.status, 200);
  assert.deepEqual(unlocked.request.requestedPeriodKeys, [
    { accessGroup: "premium", periods: ["251023T1100"] },
  ]);
  assert.deepEqual(cutoffs(unlocked.response.body), ["251023T1100", "251023T1700"]);
  assert.equal(await plaintext(initial.client, before), TEXT);
  assert.equal(await plaintext(initial.client, at), TEXT);
  assert.equal(await plaintext(initial.client, after), TEXT);
  assert.equal(
    await initial.client.contentKeyFor(initial.client.parse(future), "bodytext"),
    null,
    "the granted cutoff excludes T+7 even though the publisher supplied that window terminal",
  );

  // Possession variants use only keys actually returned above. No independently
  // derived key is seeded into the client to make a missing grant appear held.
  const held = periodKeyMap(unlocked.response.body.keys.chainKeys, "cutoff").premium;
  for (const [name, labels, oldOpens, newOpens] of [
    ["both", ["251023T1100", "251023T1700"], true, true],
    ["current only", ["251023T1100"], true, false],
    ["next only", ["251023T1700"], false, true],
    ["none", [], false, false],
  ]) {
    const reader = t0Client();
    for (const t of labels)
      await reader.cache.put("premium", t, base64urlDecode(held[t]), {
        publisher: ORIGIN,
        ...GEOMETRY,
      });
    world.clock.set("2025-10-23T12:01:00Z");
    for (const [page, opens] of [
      [before, oldOpens],
      [at, newOpens],
    ]) {
      const data = reader.client.parse(page);
      assert.equal((await reader.client.contentKeyFor(data, "bodytext")) !== null, opens, name);
      if (opens) assert.equal(await plaintext(reader.client, page), TEXT, name);
    }
  }
  const partial = t0Client();
  const partialData = partial.client.parse(before);
  const partialRequest = partial.client.buildRequest(partialData, ISSUER_NAME, ["bodytext"]);
  const partialBody = structuredClone(unlocked.response.body);
  partialBody.keys.chainKeys = partialBody.keys.chainKeys.filter(
    (/** @type {any} */ record) =>
      !(record.accessGroup === "premium" && record.cutoff === "251023T1700"),
  );
  await partial.client.applyResponse(partialData, ISSUER_NAME, partialBody, partialRequest);
  assert.equal(await plaintext(partial.client, before), TEXT);
  assert.equal(await partial.client.contentKeyFor(partial.client.parse(at), "bodytext"), null);
  const completed = await exchange(world, partial.client, at);
  assert.deepEqual(
    completed.request.requestedPeriodKeys,
    [{ accessGroup: "premium", periods: ["251023T1200"] }],
    "a partial answer recovers the new item's precise period, without an old-item T1 hint",
  );
  assert.equal(await plaintext(partial.client, at), TEXT);

  const fresh = t0Client();
  const recovered = await exchange(world, fresh.client, before);
  assert.deepEqual(recovered.request.requestedPeriodKeys, [
    { accessGroup: "premium", periods: ["251023T1100"] },
  ]);
  assert.deepEqual(
    cutoffs(recovered.response.body),
    ["251023T1100", "251023T1800"],
    "old-item recovery and the new current horizon have independently calculated cutoffs",
  );
  assert.equal(await plaintext(fresh.client, before), TEXT);

  const wrap = wrapsOf(before, "bodytext", "premium")[0];
  // Control: the wrap's own period key opens it with the derived nonce, so each
  // refusal below comes from the key alone.
  await decrypt(
    await families.premium.periodKey("premium", wrap.period),
    wrapNonceOf(before, "bodytext", "premium", wrap.period),
    base64urlDecode(wrap.key),
  );
  for (const label of ["251023T1200", "251023T2300"]) {
    await assert.rejects(
      decrypt(
        await families.premium.periodKey("premium", label),
        wrapNonceOf(before, "bodytext", "premium", wrap.period),
        base64urlDecode(wrap.key),
      ),
      { name: "OperationError" },
      "future/wrong-window raw period bytes cannot authenticate the T0 ckey",
    );
  }
});

test("denied next-window reach stays denied and old markup missing its source cannot silently use the next window", async () => {
  const { world, render } = await t0World({ authorizePeriod: (t) => t < "251023T1200" });
  const old = await render();
  const next = await render("2025-10-23T12:00:00Z");
  world.clock.set(BEFORE);
  const reader = t0Client();
  const answer = await exchange(world, reader.client, old);
  assert.deepEqual(cutoffs(answer.response.body), ["251023T1100"]);
  assert.equal(await plaintext(reader.client, old), TEXT);
  assert.equal(await reader.client.contentKeyFor(reader.client.parse(next), "bodytext"), null);
  const denied = await exchange(world, t0Client().client, next);
  assert.deepEqual(cutoffsOf(denied.response.body.keys?.chainKeys, "premium"), []);

  const permitted = await t0World();
  const incomplete = await permitted.render();
  const incompleteSealed = issuerBlockOf(incomplete, ISSUER_NAME).sealed;
  incompleteSealed.chainKeys = incompleteSealed.chainKeys.filter(
    (/** @type {any} */ record) =>
      !(record.accessGroup === "premium" && record.cutoff === "251023T1100"),
  );
  permitted.world.clock.set("2025-10-23T12:01:00Z");
  const missing = t0Client();
  const refusal = await exchange(permitted.world, missing.client, incomplete);
  assert.deepEqual(refusal.request.requestedPeriodKeys, [
    { accessGroup: "premium", periods: ["251023T1100"] },
  ]);
  assert.equal(
    await missing.client.contentKeyFor(refusal.data, "bodytext"),
    null,
    "a next-window capability is not a route to an old-window T0-only item",
  );
});

test("mixed ordinary groups retain base alternatives and period projection recovers the T0-only chain item", async () => {
  const { world, render } = await t0World({ ordinary: true, representation: "period-keys" });
  const page = await render();
  assert.deepEqual(periodsOn(page, "bodytext", "premium"), ["251023T1100"]);
  assert.deepEqual(periodsOn(page, "ordinary", "archive"), ["251023T1100", "251023T1200"]);
  // A real prior-generation projected response populates the ordinary cache.
  const previous = await t0World({ representation: "period-keys", secretFill: 19 });
  await previous.render(); // Distinct render identity from this fixture's new publisher.
  const oldPage = await previous.render();
  const stale = t0Client();
  await exchange(previous.world, stale.client, oldPage);
  assert.equal(await plaintext(stale.client, oldPage), TEXT);
  assert.equal(
    await stale.client.contentKeyFor(stale.client.parse(page), "bodytext"),
    null,
    "stale ordinary bytes cannot authenticate the newly enabled chain generation",
  );
  const answer = await exchange(world, stale.client, page, ["bodytext", "ordinary"]);
  assert.equal(answer.response.status, 200);
  assert.equal(answer.response.body.keys?.chainKeys, undefined);
  assert.ok(periodKeyMap(answer.response.body.keys.periodKeys).premium["251023T1100"]);
  assert.equal(await plaintext(stale.client, page), TEXT);
  assert.equal(await plaintext(stale.client, page, "ordinary"), "ordinary body");
});
