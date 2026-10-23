// Behavioral assertions depend on the adapter below, not prototype internals.
// They can follow an adopted implementation into core with a replacement adapter.
import assert from "node:assert/strict";
import { test } from "node:test";
import { encrypt, decrypt, decryptToKey } from "../../../core-shared/aead.js";

const plaintext = new TextEncoder().encode("permitted article");
const zero = new Uint8Array(12);
const aad = new TextEncoder().encode("unchanged content binding");
export const bytes = (n) => new Uint8Array(16).fill(n);
// Test lookup keeps semantic paths separate from physical record positions.
const coordinateFields = {
  keys: {
    contentKeys: ["contentName"],
    periodKeys: ["accessGroup", "period"],
    chainKeys: ["accessGroup", "cutoff"],
  },
  contentGroupKeys: {
    contentKeys: ["contentName"],
    periodKeys: ["contentName", "accessGroup", "period"],
    chainKeys: ["contentName", "accessGroup", "cutoff"],
  },
};
export function at(body, [section, collection, ...coordinate]) {
  const fields = coordinateFields[section][collection];
  const record = body[section][collection].find((record) =>
    fields.every((field, i) => record[field] === coordinate[i]),
  );
  assert.ok(
    record,
    `missing fixture coordinate: ${JSON.stringify([section, collection, ...coordinate])}`,
  );
  assert.ok(Object.hasOwn(record, "key"), "fixture coordinate has no key");
  return record.key;
}

export function responseBehavior(adapter) {
  const content = ["keys", "contentKeys", "bodytext"];
  const period = ["keys", "periodKeys", "paid", "261021T1200"];
  const chain = ["keys", "chainKeys", "paid", "261021T1200"];
  const cgContent = ["contentGroupKeys", "contentKeys", "bodytext"];
  const cgPeriod = ["contentGroupKeys", "periodKeys", "bodytext", "paid", "261021T1200"];
  const cgChain = ["contentGroupKeys", "chainKeys", "bodytext", "paid", "261021T1200"];
  const body = () => ({
    keys: {
      contentKeys: [
        { contentName: "bodytext", key: bytes(1) },
        { contentName: "sidebar", key: bytes(2) },
      ],
      periodKeys: [{ accessGroup: "paid", period: "261021T1200", key: bytes(3) }],
      chainKeys: [{ accessGroup: "paid", cutoff: "261021T1200", key: bytes(4) }],
    },
    contentGroupKeys: {
      contentKeys: [{ contentName: "bodytext", key: bytes(5) }],
      periodKeys: [
        { contentName: "bodytext", accessGroup: "paid", period: "261021T1200", key: bytes(6) },
      ],
      chainKeys: [
        { contentName: "bodytext", accessGroup: "paid", cutoff: "261021T1200", key: bytes(7) },
      ],
    },
  });

  test("behavior: all six paths recover keys with specified custody and real use", async () => {
    const client = await adapter.client();
    const response = await (await adapter.preflight(client.publicKey)).prepare(body());
    const opener = await adapter.open(response.transport, client.privateKey);
    const contentHandle = await opener.open(
      at(response, content),
      ["decrypt"],
      "contentKey",
      content,
    );
    assert.equal(contentHandle.extractable, false);
    assert.deepEqual(contentHandle.usages, ["decrypt"]);
    await assert.rejects(globalThis.crypto.subtle.exportKey("raw", contentHandle));
    assert.deepEqual(
      await decrypt(contentHandle, zero, await encrypt(bytes(1), zero, plaintext, aad), aad),
      plaintext,
    );
    const periodHandle = await opener.open(
      at(response, period),
      ["unwrapKey"],
      "periodKey",
      period,
    );
    assert.equal(periodHandle.extractable, false);
    assert.deepEqual(periodHandle.usages, ["unwrapKey"]);
    const itemWrap = await encrypt(bytes(3), zero, bytes(1), aad);
    const unwrappedItem = await decryptToKey(periodHandle, zero, itemWrap, aad, ["decrypt"]);
    assert.deepEqual(
      await decrypt(unwrappedItem, zero, await encrypt(bytes(1), zero, plaintext, aad), aad),
      plaintext,
    );
    assert.deepEqual(await opener.open(at(response, chain), [], "chainKey", chain), bytes(4));
    const groupedContent = await opener.open(
      at(response, cgContent),
      ["decrypt"],
      "contentKey",
      cgContent,
    );
    assert.equal(groupedContent.extractable, false);
    assert.deepEqual(
      await decrypt(groupedContent, zero, await encrypt(bytes(5), zero, plaintext, aad), aad),
      plaintext,
    );
    assert.deepEqual(
      await opener.open(at(response, cgPeriod), [], "contentGroupPeriodKey", cgPeriod),
      bytes(6),
    );
    assert.deepEqual(
      await opener.open(at(response, cgChain), [], "contentGroupChainKey", cgChain),
      bytes(7),
    );
  });

  test("behavior: record order and partial sibling removal preserve original entries", async () => {
    const client = await adapter.client();
    const response = await (await adapter.preflight(client.publicKey)).prepare(body());
    const reordered = {
      keys: {
        chainKeys: response.keys.chainKeys,
        contentKeys: [...response.keys.contentKeys].reverse(),
      },
    };
    const opener = await adapter.open(response.transport, client.privateKey);
    const handle = await opener.open(at(reordered, content), ["decrypt"], "contentKey", content);
    reordered.keys.contentKeys = reordered.keys.contentKeys.filter(
      (record) => record.contentName !== "sidebar",
    );
    const again = await opener.open(at(reordered, content), ["decrypt"], "contentKey", content);
    for (const key of [handle, again])
      assert.deepEqual(
        await decrypt(key, zero, await encrypt(bytes(1), zero, plaintext, aad), aad),
        plaintext,
      );
  });

  test("behavior: retained individual ciphertext reopens using only original context", async () => {
    const client = await adapter.client();
    let response = await (await adapter.preflight(client.publicKey)).prepare(body());
    const retained = structuredClone({
      value: at(response, period),
      transport: response.transport,
      path: period,
      kind: "periodKey",
    });
    response = null;
    assert.equal(response, null);
    const opener = await adapter.open(retained.transport, client.privateKey);
    const handle = await opener.open(retained.value, ["unwrapKey"], retained.kind, retained.path);
    const recovered = await decryptToKey(
      handle,
      zero,
      await encrypt(bytes(3), zero, bytes(1), aad),
      aad,
      ["decrypt"],
    );
    assert.deepEqual(
      await decrypt(recovered, zero, await encrypt(bytes(1), zero, plaintext, aad), aad),
      plaintext,
    );
  });

  test("behavior: another client, another agreement and modified ciphertext fail", async () => {
    const client = await adapter.client();
    const other = await adapter.client();
    const response = await (await adapter.preflight(client.publicKey)).prepare(body());
    const next = await (await adapter.preflight(client.publicKey)).prepare(body());
    const wrongClient = await adapter.open(response.transport, other.privateKey);
    const wrongAgreement = await adapter.open(next.transport, client.privateKey);
    for (const opener of [wrongClient, wrongAgreement])
      await assert.rejects(opener.open(at(response, content), ["decrypt"], "contentKey", content), {
        name: "OperationError",
      });
    const opener = await adapter.open(response.transport, client.privateKey);
    const entry = at(response, content);
    const corrupted = { ...entry, key: (entry.key[0] === "A" ? "B" : "A") + entry.key.slice(1) };
    await assert.rejects(opener.open(entry, ["unwrapKey"], "periodKey", content), {
      name: "OperationError",
    });
    await assert.rejects(opener.open(corrupted, ["decrypt"], "contentKey", content), {
      name: "OperationError",
    });
  });
}
