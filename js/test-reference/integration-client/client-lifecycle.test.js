import { setImmediate as nextTurn } from "node:timers/promises";
// Lifecycle is an application contract over captured reference clients. These
// tests use real sealing, issuer admission, key retention and content opening.
// The tiny presenter below models the host's side-effect boundary, not a new
// reference API or a login-provider implementation.
import test from "node:test";
import assert from "node:assert/strict";
import { createBrowserClient } from "../../integration-client/createBrowserClient.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { writeMarkupDelivery } from "../../adapter-publisher/writeMarkupDelivery.js";
import { Storage } from "../../demo/actors/Storage.js";
import { ISSUER_NAME } from "../../demo/scenarios/fixtures.js";
import { utf8Decode } from "../../core-shared/codec.js";
import { world, PUB, BODYTEXT, T_NOW } from "../../test-lib/fixtures/wire-policy-world.js";
import { domOver } from "../../test-lib/helpers/domOver.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { issuerBlockOf } from "../../test-lib/helpers/inspect.js";
import { connectSessionSource } from "./support/session-source-connection.js";

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function fixture(kind) {
  const w = await world();
  const rendered = await w.render(kind === "item" ? { periodKeySupply: null } : {});
  if (kind === "period") {
    // This delivered alternative supplies only period-key envelopes to the
    // issuer. The issuer's genuine response therefore cannot supply item keys.
    issuerBlockOf(rendered.dcaData, ISSUER_NAME).sealed.contentKeys = [];
  }
  const markup = writeMarkupDelivery({
    dcaData: rendered.dcaData,
    sealedContent: rendered.sealedContent,
  });
  const { processor, endpoint, publisherRegistration } = w.endpointWith();
  return {
    client({ namespace, storage, hold = async () => {} } = {}) {
      const cache = new PeriodKeyCache({
        ...(namespace ? { namespace } : {}),
        ...(storage ? { storage } : {}),
      });
      const client = createBrowserClient({
        unlockUrl: "https://issuer.example/unlock",
        root: domOver(markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        cache,
        relayPeriodKeys: kind === "period",
        persistRawPeriodKeys: true,
        transport: {
          async post(_url, request) {
            const response = await unlockThroughAdmission(
              processor,
              endpoint,
              request,
              publisherRegistration,
            );
            await hold();
            return { ...response, contentType: "application/json" };
          },
        },
      });
      return { client, cache };
    },
  };
}

function context(client, view = { owner: null, text: null }) {
  const ctx = { client, view, live: true };
  view.owner = ctx;
  return ctx;
}

async function openedText(client, beforeKey = async () => {}) {
  const item = client.dcaData.contentItemFor(BODYTEXT.name);
  assert.ok(item);
  const bytes = await client.opener.open({
    item,
    ciphertext: client.reader.extract(BODYTEXT.name),
    resolveKey: async () => {
      const { key } = await client.resolver.contentKeyWithOriginFor(client.dcaData, BODYTEXT.name);
      await beforeKey();
      return key;
    },
  });
  return utf8Decode(bytes);
}

async function present(ctx, beforeKey) {
  // This check saves work, but only the check after opening decides eligibility.
  if (!ctx.live || ctx.view.owner !== ctx) return false;
  const text = await openedText(ctx.client, beforeKey);
  if (!ctx.live || ctx.view.owner !== ctx) return false;
  ctx.view.text = text; // synchronous presentation side effect
  return true;
}

async function keyFor(client) {
  return client.resolver.contentKeyFor(client.dcaData, BODYTEXT.name);
}

for (const kind of ["item", "period"]) {
  test(`${kind} output: a late response belongs to the captured, still-live client`, async () => {
    const f = await fixture(kind);
    const arrived = deferred(),
      release = deferred();
    const a = f.client({
      hold: async () => {
        arrived.resolve();
        await release.promise;
      },
    });
    const b = f.client();
    const alice = context(a.client),
      bob = context(b.client);
    let current = alice;
    const pending = current.client.unlock([BODYTEXT.name]);
    await arrived.promise;
    current = bob;
    release.resolve();
    const result = await pending;
    assert.equal(result.status, 200);
    assert.ok(result.application.accepted > 0);
    assert.equal(await keyFor(current.client), null, "current client acquired no old-owner key");
    assert.ok(await keyFor(alice.client));
    assert.equal(await present(alice), true, "independent live old presenter remains eligible");
    assert.equal(alice.view.text, BODYTEXT.value);
    assert.equal(bob.view.text, null);
    if (kind === "period") {
      assert.deepEqual(result.body.keys.contentKeys, []);
      assert.ok(
        (await a.cache.candidatesAt(BODYTEXT.accessGroups[0], T_NOW, { publisher: PUB })).length,
      );
      assert.deepEqual(await b.cache.entries(), []);
    } else {
      assert.deepEqual(
        await a.cache.entries(),
        [],
        "item-only result has no reusable period entry",
      );
    }
  });

  test(`${kind} output: retiring before late response cannot present into a successor`, async () => {
    const f = await fixture(kind),
      storage = new Storage();
    const arrived = deferred(),
      release = deferred();
    const a = f.client({
      storage,
      namespace: "alice",
      hold: async () => {
        arrived.resolve();
        await release.promise;
      },
    });
    const b = f.client({ storage, namespace: "bob" });
    const alice = context(a.client);
    const pending = alice.client.unlock([BODYTEXT.name]);
    await arrived.promise;
    alice.live = false; // retirement precedes successor ownership of the view
    const bob = context(b.client, alice.view);
    release.resolve();
    assert.equal((await pending).status, 200);
    assert.equal(await present(alice), false);
    assert.equal(bob.view.text, null);
    assert.equal(await keyFor(bob.client), null);
    assert.deepEqual(await b.cache.entries(), []);
    assert.ok(await keyFor(alice.client), "retirement did not revoke bytes held by old owner");
  });
}

test("retirement during a period-cache write preserves another live context and isolates the successor", async () => {
  const f = await fixture("period"),
    arrived = deferred(),
    release = deferred();
  const alicePrefix = `dca.periodKeys.${Buffer.from("alice").toString("base64url")}.`;
  let held = false;
  const storage = new Storage({
    gate: async ({ op, key }) => {
      if (!held && op === "set" && key.startsWith(alicePrefix)) {
        held = true;
        arrived.resolve();
        await release.promise;
      }
    },
  });
  const a = f.client({ storage, namespace: "alice" });
  const b = f.client({ storage, namespace: "independent" });
  const c = f.client({ storage, namespace: "successor" });
  const alice = context(a.client),
    independent = context(b.client);
  const pending = alice.client.unlock([BODYTEXT.name]);
  await arrived.promise;
  alice.live = false;
  const successor = context(c.client, alice.view);
  assert.equal((await independent.client.unlock([BODYTEXT.name])).status, 200);
  assert.equal(await present(independent), true);
  release.resolve();
  assert.equal((await pending).status, 200);
  assert.equal(await present(alice), false);
  assert.equal(successor.view.text, null);
  assert.equal(await keyFor(successor.client), null);
  assert.deepEqual(await c.cache.entries(), []);
  assert.ok((await a.cache.entries()).length, "old write finished only in its own partition");
  assert.ok((await b.cache.entries()).length, "retirement did not clear independent state");
  assert.equal(await present(independent), true);
});

test("a final presentation check catches same-label switching during content opening", async () => {
  const f = await fixture("item");
  const a = f.client(),
    b = f.client();
  assert.equal((await a.client.unlock([BODYTEXT.name])).status, 200);
  const alice = context(a.client),
    started = deferred(),
    release = deferred();
  const pending = present(alice, async () => {
    started.resolve();
    await release.promise;
  });
  await started.promise;
  // Both menu observations say signed-in. The actual session integration sends
  // a context-change signal; the host retires the old context independently.
  alice.live = false;
  const bob = context(b.client, alice.view);
  release.resolve();
  assert.equal(await pending, false);
  assert.equal(bob.view.text, null);
  assert.equal(await keyFor(bob.client), null);

  // Negative control: an early-only check admits a stale side effect after an
  // await. The final guard above is the difference under the same interleaving.
  const old = context(a.client),
    earlyStarted = deferred(),
    earlyRelease = deferred();
  const unsafe = (async () => {
    if (!old.live) return;
    const text = await openedText(old.client, async () => {
      earlyStarted.resolve();
      await earlyRelease.promise;
    });
    old.view.text = text;
  })();
  await earlyStarted.promise;
  old.live = false;
  const next = context(b.client, old.view);
  earlyRelease.resolve();
  await unsafe;
  assert.equal(next.view.text, BODYTEXT.value, "early-only guard exhibits the stale completion");
});

test("a configured session callback retires shared routes without retiring an unrelated source", async () => {
  const f = await fixture("item");
  const routeA = context(f.client().client);
  const routeB = context(f.client().client);
  const unrelated = context(f.client().client);
  for (const ctx of [routeA, routeB, unrelated]) {
    assert.equal((await ctx.client.unlock([BODYTEXT.name])).status, 200);
  }
  const configuredScopes = new Map([
    ["shared-credential-source", [routeA, routeB]],
    ["independent-source", [unrelated]],
  ]);
  // Exercise the consumer's configured callback, not a fabricated login
  // provider. Public menu labels and issuer key ownership decide no scope.
  const onContextChange = (source) => {
    for (const ctx of configuredScopes.get(source)) ctx.live = false;
  };
  onContextChange("shared-credential-source");
  assert.equal(await present(routeA), false);
  assert.equal(await present(routeB), false);
  assert.equal(await present(unrelated), true);
  assert.equal(unrelated.view.text, BODYTEXT.value);
  assert.ok(await keyFor(routeA.client), "scope retirement is not cryptographic revocation");
});

function controlledSource(initial) {
  let listener = null;
  let originalListener = null;
  let disposed = 0;
  return {
    source: {
      subscribe(callback) {
        listener = originalListener = callback;
        callback(initial);
        return () => {
          disposed++;
          listener = null;
        };
      },
    },
    emit(snapshot) {
      listener?.(snapshot);
    },
    queued(snapshot) {
      originalListener(snapshot);
    },
    disposalCount() {
      return disposed;
    },
  };
}

function snapshot(sequence, contextRevision, contextKnown = true) {
  const observedAt = Date.now();
  return {
    sequence,
    contextRevision,
    contextKnown,
    account: { state: "signed-in", observedAt, validUntil: observedAt + 60_000 },
  };
}

test("session fixture handles initial unknown, stale sequence and same-label context switch", async () => {
  const connect = connectSessionSource,
    f = await fixture("item");
  const source = controlledSource(snapshot(0, 0, false));
  const arrived = deferred(),
    release = deferred(),
    oldDone = deferred(),
    placed = deferred();
  let created = 0;
  const outputs = [];
  const dispose = connect(
    source.source,
    () => {
      const first = created++ === 0;
      const { client } = f.client({
        hold: first
          ? async () => {
              arrived.resolve();
              await release.promise;
            }
          : undefined,
      });
      if (first) {
        const unlock = client.unlock;
        client.unlock = async (names) => {
          try {
            return await unlock(names);
          } finally {
            oldDone.resolve();
          }
        };
      }
      return client;
    },
    async (client) => ({ bodytext: await openedText(client) }),
    (opened) => {
      outputs.push(opened.bodytext);
      placed.resolve();
    },
  );
  assert.equal(created, 0, "unknown initial ownership cannot start a context");
  source.emit(snapshot(1, "alice"));
  await arrived.promise;
  source.emit(snapshot(0, "stale", false));
  source.emit(snapshot(2, "alice"));
  assert.equal(created, 1, "stale events and same-context observations do not replace it");
  source.emit(snapshot(3, "bob")); // menu label still signed-in
  await placed.promise;
  assert.equal(created, 2);
  assert.deepEqual(outputs, [BODYTEXT.value]);
  release.resolve();
  await oldDone.promise;
  await nextTurn();
  assert.deepEqual(outputs, [BODYTEXT.value], "old completion cannot also present");
  dispose();
  dispose();
  assert.equal(source.disposalCount(), 1);
});

test("session fixture disposal suppresses pending opening and queued callbacks", async () => {
  const connect = connectSessionSource,
    f = await fixture("item");
  const source = controlledSource(snapshot(0, "alice"));
  const started = deferred(),
    release = deferred(),
    openedDone = deferred();
  let created = 0;
  const outputs = [];
  const dispose = connect(
    source.source,
    () => {
      created++;
      return f.client().client;
    },
    async (client) => {
      try {
        return {
          bodytext: await openedText(client, async () => {
            started.resolve();
            await release.promise;
          }),
        };
      } finally {
        openedDone.resolve();
      }
    },
    (opened) => outputs.push(opened.bodytext),
  );
  await started.promise;
  dispose();
  dispose();
  source.queued(snapshot(1, "bob"));
  assert.equal(created, 1, "already queued notification is ignored after disposal");
  assert.equal(source.disposalCount(), 1);
  release.resolve();
  await openedDone.promise;
  await nextTurn();
  assert.deepEqual(outputs, [], "final guard survives disposal during an await");
});
