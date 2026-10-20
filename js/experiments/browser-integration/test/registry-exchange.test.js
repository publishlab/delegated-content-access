// @ts-check
// Independent participants share discovery only. Real JSON bytes and issuer-approved
// keys cross the DCA path; the host captures each content-handler connection.
import test from "node:test";
import assert from "node:assert/strict";
import { installRegistry } from "../implementation/registry.js";
import { createContentHandler } from "../implementation/content-handler.js";
import { connectSelected } from "../test-lib/registry-client.js";
import { exchange, deferred } from "../test-lib/exchange.js";

/** @type {import("../implementation/registry.js").RegistryKey} */
const SELECTED = { interface: "dca.content-handler", major: 1, name: "article" };
const article = {
  name: "bodytext",
  contentType: "text/html",
  bytes: new TextEncoder().encode("<p>Byrådet åpnet havna.</p>"),
};

for (const order of ["provider-first", "client-first"]) {
  test(`separate ${order} participants use configured registry and real serialized JSON exchange`, async () => {
    const publisher = await exchange([article]);
    const client = await publisher.client();
    assert.ok(publisher.bytes instanceof Uint8Array);
    assert.deepEqual(await client.open("bodytext"), article.bytes);
    const host = { DelegatedContentAccess: { unrelated: "keep" } };
    const providerRegistry = installRegistry(host);
    const handler = createContentHandler();
    /** @type {(() => void) | null} */
    let remove = null;
    if (order === "provider-first") remove = providerRegistry.register(SELECTED, handler);

    const clientRegistry = installRegistry(host);
    assert.equal(clientRegistry, providerRegistry);
    assert.equal(host.DelegatedContentAccess.unrelated, "keep");
    const arrival = deferred();
    /** @type {object | null} */
    let selected = null;
    let observations = 0;
    const stop = clientRegistry.observe(SELECTED, (entry) => {
      observations += 1;
      selected = entry.provider;
      if (entry.provider !== null) arrival.resolve();
    });
    if (order === "client-first") {
      assert.equal(selected, null);
      assert.equal(
        connectSelected(clientRegistry, SELECTED, {
          delivery: client.delivery,
          isEligible: () => true,
          targets: {},
        }),
        null,
      );
      // A different name or major cannot satisfy the configured dependency.
      const unrelated = providerRegistry.register({ ...SELECTED, name: "another" }, handler);
      const otherMajor = providerRegistry.register({ ...SELECTED, major: 2 }, handler);
      assert.equal(selected, null);
      assert.equal(observations, 1);
      unrelated();
      otherMajor();
      remove = providerRegistry.register(SELECTED, handler);
    }
    await arrival.promise;
    assert.ok(selected !== null);
    /** @type {unknown[]} */
    const writes = [];
    const connection = connectSelected(clientRegistry, SELECTED, {
      delivery: client.delivery,
      isEligible: () => true,
      values: { bodytext: "strictUTF8" },
      targets: {
        bodytext({ contentType, value, commit }) {
          assert.equal(contentType, article.contentType);
          commit(() => writes.push(value));
          return { status: "handled" };
        },
      },
    });
    assert.ok(connection !== null);
    assert.deepEqual(await connection.handleContent({ bodytext: await client.open("bodytext") }), {
      bodytext: { status: "handled" },
    });
    assert.deepEqual(writes, [new TextDecoder().decode(article.bytes)]);
    connection.dispose();
    stop();
    assert.ok(remove !== null);
    remove();
  });
}

test("replacement changes new discovery while a captured handler finishes its real exchange", async () => {
  const client = await (await exchange([article])).client();
  const host = {};
  const providerRegistry = installRegistry(host);
  const clientRegistry = installRegistry(host);
  const oldProvider = createContentHandler();
  const newProvider = createContentHandler();
  const removeOld = providerRegistry.register(SELECTED, oldProvider);
  /** @type {import("../implementation/registry.js").RegistryEntry<object>[]} */
  const entries = [];
  const stop = clientRegistry.observe(SELECTED, (entry) => entries.push(entry));
  const gate = deferred();
  const started = deferred();
  /** @type {unknown[]} */
  const oldWrites = [];
  /** @type {unknown[]} */
  const newWrites = [];
  const captured = connectSelected(clientRegistry, SELECTED, {
    delivery: client.delivery,
    isEligible: () => true,
    values: { bodytext: "strictUTF8" },
    targets: {
      async bodytext({ value, commit }) {
        started.resolve();
        await gate.promise;
        commit(() => oldWrites.push(value));
        return { status: "handled" };
      },
    },
  });
  assert.ok(captured !== null);
  const pending = captured.handleContent({ bodytext: await client.open("bodytext") });
  await started.promise;
  removeOld();
  assert.equal(clientRegistry.lookup(SELECTED), null);
  const removeNew = providerRegistry.register(SELECTED, newProvider);
  removeOld(); // stale disposer cannot remove the replacement
  assert.equal(clientRegistry.lookup(SELECTED), newProvider);
  const fresh = connectSelected(clientRegistry, SELECTED, {
    delivery: client.delivery,
    isEligible: () => true,
    values: { bodytext: "strictUTF8" },
    targets: {
      bodytext({ value, commit }) {
        commit(() => newWrites.push(value));
        return { status: "handled" };
      },
    },
  });
  assert.ok(fresh !== null);
  try {
    assert.deepEqual(await fresh.handleContent({ bodytext: await client.open("bodytext") }), {
      bodytext: { status: "handled" },
    });
    assert.deepEqual(oldWrites, []);
  } finally {
    gate.resolve();
  }
  assert.deepEqual(await pending, { bodytext: { status: "handled" } });
  assert.deepEqual(oldWrites, [new TextDecoder().decode(article.bytes)]);
  assert.deepEqual(newWrites, oldWrites);
  assert.equal(entries.length, 3);
  assert.equal(entries[0].provider, oldProvider);
  assert.deepEqual(entries[1], { provider: null, registration: null });
  assert.equal(entries[2].provider, newProvider);
  assert.notEqual(entries[0].registration, entries[2].registration);
  captured.dispose();
  fresh.dispose();
  stop();
  removeNew();
});

test("generic discovery does not make an incompatible selected provider a content handler", () => {
  const registry = installRegistry({});
  const remove = registry.register(SELECTED, { subscribe() {} });
  assert.throws(
    () =>
      connectSelected(registry, SELECTED, { delivery: {}, isEligible: () => true, targets: {} }),
    /not a content handler/,
  );
  remove();
});
