// @ts-check
// Genuine serialized metadata and one real unlock response. Unlike run.js this
// comparison does not normalize random cryptographic carriers before gzip.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { utf8Decode } from "../../core-shared/codec.js";
import { t0World, t0Client, exchange, TEXT } from "../../extensions/chain-keys/test/t0-world.js";

const destination = new URL("./t0-artifacts/", import.meta.url);
await mkdir(destination, { recursive: true });
const rows = [];
for (const [name, universe, active] of [
  ["one-group", ["premium"], ["premium"]],
  ["two-groups", ["premium", "second"], ["premium", "second"]],
  ["sparse-group", ["premium", "second", "third", "fourth"], ["premium"]],
]) {
  const measured = [];
  let baselineResponse;
  for (const slots of [1, 2]) {
    const { world, render } = await t0World({
      groups: universe,
      ...(slots === 1 ? {} : { chainItemSlots: slots }),
    });
    const page = await render(undefined, active);
    assert.deepEqual(Object.keys(page.contentData.bodytext.keys), active);
    assert.deepEqual(
      Object.keys(page.issuerData.paywall_subscription_service.sealed.chainKeys),
      active,
    );
    for (const group of active) assert.equal(page.contentData.bodytext.keys[group].length, slots);
    const { client } = t0Client();
    const { data, request, response } = await exchange(world, client, page);
    assert.equal(response.status, 200);
    if (baselineResponse === undefined) baselineResponse = response.body;
    else
      assert.deepEqual(
        response.body,
        baselineResponse,
        "item alternatives do not change granted capability bytes",
      );
    assert.deepEqual(Object.keys(response.body.keys.chainKeys), active);
    for (const group of active)
      assert.deepEqual(Object.keys(response.body.keys.chainKeys[group]), [
        "251023T1100",
        "251023T1700",
      ]);
    assert.equal(
      utf8Decode(await client.decrypt(data, "bodytext", client.extract(page, "bodytext"))),
      TEXT,
    );
    const { sealedContent: _ciphertext, ...metadata } = page;
    const documents = { metadata, request, response: response.body };
    const sizes = {};
    for (const [kind, value] of Object.entries(documents)) {
      const json = JSON.stringify(value);
      await writeFile(new URL(`${name}--${slots}-wrap--${kind}.json`, destination), json + "\n");
      sizes[kind] = { raw: Buffer.byteLength(json), gzip: gzipSync(json, { level: 9 }).length };
    }
    measured.push({ slots, ...sizes });
  }
  const saving = (kind) => ({
    raw: measured[1][kind].raw - measured[0][kind].raw,
    rawPercent: Number(
      ((100 * (measured[1][kind].raw - measured[0][kind].raw)) / measured[1][kind].raw).toFixed(2),
    ),
    gzip: measured[1][kind].gzip - measured[0][kind].gzip,
    gzipPercent: Number(
      ((100 * (measured[1][kind].gzip - measured[0][kind].gzip)) / measured[1][kind].gzip).toFixed(
        2,
      ),
    ),
  });
  rows.push({
    name,
    universe,
    active,
    measured,
    saved: { metadata: saving("metadata"), response: saving("response") },
  });
}
const summary = {
  method:
    "Genuine compact JSON, excluding sealedContent; gzip level 9; current plus six hourly periods; independent two-window supply; random carriers are not normalized.",
  rows,
};
await writeFile(new URL("measurements.json", destination), JSON.stringify(summary, null, 2) + "\n");
console.log(JSON.stringify(summary, null, 2));
console.log(`Saved actual documents in ${fileURLToPath(destination)}`);
