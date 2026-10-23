// Pending answer candidates must survive until opening even when they exceed
// the later retained-rival limit. Exercise the stock issuer, client and caches.
import test from "node:test";
import assert from "node:assert/strict";
import { contentNameSeed, contentNameSeedAad } from "../core-shared/construction.js";
import { sealSeed } from "../core-shared/seed-envelope.js";
import { CHAIN, GEOMETRY, NEXT, PUBLISHER, T12, T18, claimsOf, item, world } from "./_lib/world.js";

for (const { rivals, maxRivalsPerWindow } of [
  { rivals: 2, maxRivalsPerWindow: 4 },
  { rivals: 5, maxRivalsPerWindow: 2 },
]) {
  test(`${rivals} pending candidates plus the next window open with ${maxRivalsPerWindow} retained rivals`, async () => {
    const limits = {
      maxSeedWindows: rivals + 1,
      maxResponseMembers: rivals + 2,
      maxRivalsPerWindow,
    };
    const w = await world();
    const published = await w.publish({
      at: "261014T1500",
      limits,
      ordinary: ["headline"],
      seedWindows: { issuer: { bodytext: [T12, NEXT] } },
      items: [item("bodytext", ["politics"]), item("headline")],
    });
    const aad = await contentNameSeedAad(
      {
        publisher: PUBLISHER,
        renderId: claimsOf(published.page.resourceJWT).renderId,
        issuerName: "issuer",
        contentName: "bodytext",
        windowStartLabel: T12,
        periodGeometry: GEOMETRY,
      },
      CHAIN,
    );
    const seeds = published.page.issuerData.find((b) => b.issuerName === "issuer").sealed
      .contentWindowSeeds;
    // Place every wrong rotation before the opening candidate. Retention is
    // not permission to discard admitted candidates before the attempt.
    for (let rival = 1; rival < rivals; rival++) {
      const secret = new Uint8Array(32).fill(rival + 20);
      seeds.unshift({
        contentName: "bodytext",
        windowStart: T12,
        key: await sealSeed(
          await contentNameSeed(secret, PUBLISHER, GEOMETRY, "bodytext", T12, CHAIN),
          w.opening.issuer.publicKey,
          aad,
        ),
      });
    }
    const policy = () => ({
      authorizePeriod: () => true,
      grants: [
        {
          kind: "chain",
          contentName: "bodytext",
          group: "politics",
          windowStart: T12,
          cutoffT: T18,
        },
        {
          kind: "chain",
          contentName: "bodytext",
          group: "politics",
          windowStart: NEXT,
          cutoffT: NEXT,
        },
      ],
    });
    const issuer = w.issuer({ policy, limits });
    const reader = w.reader({ limits });
    const client = reader.client(published, issuer, {
      narrowing: { requestedContentKeys: {} },
    });
    let failure;
    try {
      await client.unlock(["bodytext", "headline"]);
    } catch (error) {
      failure = error;
    }
    const answer = issuer.calls.answers[0];
    assert.equal(answer.status, 200);
    const records = answer.body.contentGroupKeys.chainKeys;
    assert.equal(records.length, rivals + 1);
    assert.equal(new Set(records.map((record) => record.cutoff)).size, 2);
    assert.deepEqual(
      {
        failure: failure?.code,
        bodytext: await client.open("bodytext"),
        headline: await client.open("headline"),
      },
      { failure: undefined, bodytext: "content:bodytext", headline: "content:headline" },
    );
    assert.ok((await reader.chainKeyCache().entries()).length <= 2 * maxRivalsPerWindow);
  });
}
