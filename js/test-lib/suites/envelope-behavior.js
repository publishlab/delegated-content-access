import assert from "node:assert/strict";
import { test as nodeTest } from "node:test";

/**
 * Portable behavior assertions: the adapter owns keys, carrier and composition.
 * Shared by stock and comparison adapters, without carrier-layout assumptions.
 * Period/chain cases exercise envelope BIND vocabulary, not profile conformance.
 * @param {{createRecipient: () => Promise<any>, seal: (bytes: Uint8Array, recipient: any, binding: any) => Promise<string>, open: (sealed: string, recipient: any, binding: any) => Promise<Uint8Array>}} adapter
 * @param {(name: string, fn: () => Promise<void>) => unknown} [register]
 *   - the owning test file selects which run registers these assertions
 */
export function envelopeBehavior(adapter, register = nodeTest) {
  const renderId = "AAECAwQFBgcICQoLDA0ODw";
  const content = { renderId, contentName: "bodytext" };
  const period = { renderId, accessGroup: "members", t: "261021T1200" };
  const chain = {
    renderId,
    accessGroup: "members",
    suppliedT: "261021T1200",
    chainKey: true,
    chainsPerDay: 1,
    periodMinutes: 60,
  };
  const payload = Uint8Array.from({ length: 16 }, (_, i) => i);

  for (const [name, binding] of [
    ["content", content],
    ["period", period],
    ["chain", chain],
  ]) {
    register(`${name}: real recovery and retained replay opening`, async () => {
      const recipient = await adapter.createRecipient();
      const sealed = await adapter.seal(payload, recipient, binding);
      assert.deepEqual(await adapter.open(sealed, recipient, binding), payload);
      assert.deepEqual(await adapter.open(sealed, recipient, binding), payload);
    });
  }

  const relabels = [
    ["content render", content, { ...content, renderId: "AQECAwQFBgcICQoLDA0ODw" }],
    ["content name", content, { ...content, contentName: "sidebar" }],
    ["content/period kind", content, period],
    ["period render", period, { ...period, renderId: "AQECAwQFBgcICQoLDA0ODw" }],
    ["period group", period, { ...period, accessGroup: "premium" }],
    ["period label", period, { ...period, t: "261021T1300" }],
    ["period/chain kind", period, chain],
    ["chain render", chain, { ...chain, renderId: "AQECAwQFBgcICQoLDA0ODw" }],
    ["chain group", chain, { ...chain, accessGroup: "premium" }],
    ["chain position", chain, { ...chain, suppliedT: "261021T1300" }],
    ["chain count geometry", chain, { ...chain, chainsPerDay: 2 }],
    ["chain period geometry", chain, { ...chain, periodMinutes: 30 }],
    ["chain/period kind", chain, period],
  ];
  for (const [name, original, replacement] of relabels) {
    register(`rejects relabel: ${name}`, async () => {
      const recipient = await adapter.createRecipient();
      const sealed = await adapter.seal(payload, recipient, original);
      await assert.rejects(adapter.open(sealed, recipient, replacement), { code: "unseal_failed" });
    });
  }
  register("another recipient cannot recover the payload", async () => {
    const recipient = await adapter.createRecipient();
    const other = await adapter.createRecipient();
    const sealed = await adapter.seal(payload, recipient, content);
    await assert.rejects(adapter.open(sealed, other, content), { code: "unseal_failed" });
  });
}
