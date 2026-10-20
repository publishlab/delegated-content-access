// Two separately implemented provider adapters feed the same DCA consumer.
import test from "node:test";
import assert from "node:assert/strict";
import { createContentHandler } from "../implementation/content-handler.js";
import { adaptAuthorizationFeed } from "../implementation/authorization-feed-adapter.js";
import { adaptSessionEvents } from "../implementation/session-event-adapter.js";
import { createContextHost } from "../test-lib/context-host.js";
import { deferred, exchange } from "../test-lib/exchange.js";

const ROUTE = "subscription";
function sessionEventApi() {
  /** @type {((session: SessionRecord | null) => void) | null} */
  let listener = null;
  return {
    onSessionChange(callback) {
      listener = callback;
      return () => {
        listener = null;
      };
    },
    publish(session) {
      listener?.(session);
    },
  };
}

function authorizationFeedApi() {
  /** @type {(() => void) | null} */
  let listener = null;
  /** @type {Array<{resolve: (value: AuthorizationLease | null) => void, reject: (error: Error) => void}>} */
  const reads = [];
  return {
    readAuthorizationLease() {
      return new Promise((resolve, reject) => reads.push({ resolve, reject }));
    },
    onLeaseChange(callback) {
      listener = callback;
      return () => {
        listener = null;
      };
    },
    notifyChange() {
      listener?.();
    },
    resolveRead(index, value) {
      reads[index]?.resolve(value);
    },
    rejectRead(index) {
      reads[index]?.reject(new Error("lease read unavailable"));
    },
  };
}

/** @param {import("../test-lib/context-host.js").ContextHost} host @param {string | null} credential */
function capture(host, credential) {
  const work = host.capture(ROUTE);
  return work && credential ? { work, credential } : null;
}

function makeStableConsumer() {
  const handler = createContentHandler();
  /** @type {import("../implementation/content-handler.js").ContentConnection | null} */
  let activeConnection = null;
  const target = { text: null, writes: 0 };

  return {
    target,
    async use(binding, afterResponse = async () => {}) {
      // A connection captures the work that owns its delivery and destination.
      // Retire it before a successor can perform any effect; keep the provider
      // and this consumer object stable across the replacement.
      activeConnection?.dispose();
      const { work, client } = binding;
      const connection = handler.connect({
        delivery: client.delivery,
        isEligible: () => work.isEligible(),
        values: { bodytext: "strictUTF8" },
        targets: {
          bodytext({ value, commit }) {
            commit(() => {
              target.text = value;
              target.writes += 1;
            });
            return { status: "handled" };
          },
        },
      });
      activeConnection = connection;
      if (!work.isEligible()) return { status: "stale" };
      const unlocked = await gated(work, () => client.unlock(afterResponse, binding.credential));
      if (!unlocked.completed || unlocked.value === null) return { status: "stale" };
      const opened = await gated(work, () => client.open("bodytext"));
      if (!opened.completed) return { status: "stale" };
      const handled = await gated(work, () => connection.handleContent({ bodytext: opened.value }));
      return handled.completed ? handled.value.bodytext : { status: "stale" };
    },
    dispose() {
      activeConnection?.dispose();
      activeConnection = null;
    },
  };
}

/** @template T @param {import("../test-lib/context-host.js").CapturedWork} work @param {() => Promise<T>} operation */
async function gated(work, operation) {
  if (!work.isEligible()) return { completed: false };
  return { completed: true, value: await operation() };
}

test("independent session-event and authorization-feed adapters preserve a stable serialized-DCA consumer", async () => {
  const article = new TextEncoder().encode("<article>Protected article</article>");
  const publisher = await exchange([
    { name: "bodytext", bytes: article, contentType: "text/html" },
  ]);
  const firstIssued = deferred();
  const releaseFirstResponse = deferred();
  /** @type {Array<string | undefined>} */
  const credentialsUsed = [];
  const sendRequest = async (requestJson, credential) => {
    const request = JSON.parse(requestJson);
    const wireBody = JSON.stringify(request);
    assert.equal(wireBody.includes("event-token-a1"), false);
    assert.equal(wireBody.includes("feed-token-b1"), false);
    credentialsUsed.push(/** @type {string | undefined} */ (credential));
    const response = await publisher.respond(requestJson);
    if (credential === "Bearer event-token-a1") {
      firstIssued.resolve();
      await releaseFirstResponse.promise;
    }
    return response;
  };

  // Provider A exposes synchronous session-change events and a bearer field.
  const sessions = sessionEventApi();
  const adapterA = adaptSessionEvents(sessions);
  const hostA = createContextHost(adapterA.provider, { routes: [ROUTE] });
  assert.equal(capture(hostA, adapterA.readBearerCredential()), null);
  assert.deepEqual(credentialsUsed, []);

  sessions.publish({
    accountRef: "reader-17",
    credentialRef: "key-1",
    bearerToken: "event-token-a1",
  });
  const workA = capture(hostA, adapterA.readBearerCredential());
  assert.ok(workA);
  // Context ownership is application wiring: each captured operation gets a
  // separate client/resolver and an admission guard bound to that same work.
  const clientA = publisher.createClient({}, sendRequest, workA.work.isEligible);
  const consumer = makeStableConsumer();
  const predecessor = consumer.use({ ...workA, client: clientA });
  await firstIssued.promise;
  assert.equal(clientA.responseApplications, 0);
  assert.equal(await clientA.keyFor("bodytext"), null);

  // The event API binds a new credential to a different reader while the
  // response for the captured request is still pending.
  sessions.publish({
    accountRef: "reader-29",
    credentialRef: "key-2",
    bearerToken: "event-token-a2",
  });
  assert.equal(workA.work.isEligible(), false);
  assert.deepEqual(credentialsUsed, ["Bearer event-token-a1"]);

  // Replace the provider with a separate async lease API. Startup is unknown
  // until its first read completes; it does not reuse adapter A's parser.
  adapterA.dispose();
  hostA.dispose();
  const feed = authorizationFeedApi();
  const adapterB = adaptAuthorizationFeed(feed);
  const hostB = createContextHost(adapterB.provider, { routes: [ROUTE] });
  assert.equal(capture(hostB, adapterB.currentLease()?.bearer ?? null), null);
  assert.deepEqual(credentialsUsed, ["Bearer event-token-a1"]);
  feed.resolveRead(0, {
    accountHandle: "reader-feed-8",
    keyHandle: "lease-1",
    bearer: "feed-token-b1",
  });
  await adapterB.ready;
  const workB = capture(
    hostB,
    adapterB.currentLease()?.bearer ? `Bearer ${adapterB.currentLease().bearer}` : null,
  );
  assert.ok(workB);
  const clientB = publisher.createClient({}, sendRequest, workB.work.isEligible);
  assert.notEqual(clientB, clientA);
  assert.equal(
    await clientB.keyFor("bodytext"),
    null,
    "the successor begins with no held item key",
  );
  assert.deepEqual(await consumer.use({ ...workB, client: clientB }), { status: "handled" });
  assert.equal(clientB.responseApplications, 1, "B's eligible response reaches its own resolver");
  const keyB = await clientB.keyFor("bodytext");
  assert.ok(keyB, "the admitted successor response supplies a usable item key");
  assert.deepEqual(credentialsUsed, ["Bearer event-token-a1", "Bearer feed-token-b1"]);
  assert.equal(consumer.target.text, "<article>Protected article</article>");
  assert.equal(consumer.target.writes, 1);
  assert.equal(Buffer.from(publisher.bytes).toString("utf8").includes("event-token-a1"), false);
  assert.equal(Buffer.from(publisher.bytes).toString("utf8").includes("feed-token-b1"), false);

  // Completion of A's already-issued response cannot write over B's target.
  releaseFirstResponse.resolve();
  assert.deepEqual(await predecessor, { status: "stale" });
  assert.equal(clientA.responseApplications, 0, "retired A never invokes response application");
  assert.equal(await clientA.keyFor("bodytext"), null, "A's resolver never receives its late key");
  assert.equal(clientB.responseApplications, 1, "A's response cannot enter B's resolver");
  assert.deepEqual(await clientB.keyFor("bodytext"), keyB);
  assert.equal(consumer.target.text, "<article>Protected article</article>");
  assert.equal(consumer.target.writes, 1);

  consumer.dispose();
  hostB.dispose();
  adapterB.dispose();
  assert.equal(await clientB.unlock(undefined, workB.credential), null);
  assert.equal(clientB.requests, 1, "disposed work cannot dispatch another request");
  feed.notifyChange(); // stopped subscription; no new read is issued
  assert.equal(capture(hostB, adapterB.currentLease()?.bearer ?? null), null);
});

test("a failed lease refresh retires prior work even when a later read repeats its handles", async () => {
  const feed = authorizationFeedApi();
  const adapter = adaptAuthorizationFeed(feed);
  const host = createContextHost(adapter.provider, { routes: [ROUTE] });
  feed.resolveRead(0, {
    accountHandle: "reader-1",
    keyHandle: "key-1",
    bearer: "token-1",
  });
  await adapter.ready;
  const work = host.capture(ROUTE);
  assert.ok(work);
  assert.equal(work.isEligible(), true);

  feed.notifyChange();
  assert.equal(adapter.currentLease(), null);
  assert.equal(work.isEligible(), false, "notification suspends use before the read settles");
  feed.rejectRead(1);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(adapter.currentLease(), null);
  assert.equal(work.isEligible(), false);
  assert.equal(host.capture(ROUTE), null);

  feed.notifyChange();
  feed.resolveRead(2, {
    accountHandle: "reader-1",
    keyHandle: "key-1",
    bearer: "token-2",
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(work.isEligible(), false, "the failed read left an unresolved transition");
  assert.equal(adapter.currentLease()?.bearer, "token-2");
  assert.equal(
    host.capture(ROUTE)?.isEligible(),
    true,
    "a new operation can use the recovered lease",
  );

  host.dispose();
  adapter.dispose();
});

test("one completed matching lease read confirms continuity without retiring suspended work", async () => {
  const feed = authorizationFeedApi();
  const adapter = adaptAuthorizationFeed(feed);
  const host = createContextHost(adapter.provider, { routes: [ROUTE] });
  feed.resolveRead(0, { accountHandle: "reader-1", keyHandle: "key-1", bearer: "token-1" });
  await adapter.ready;
  const work = host.capture(ROUTE);
  assert.ok(work);
  feed.notifyChange();
  assert.equal(work.isEligible(), false);
  feed.resolveRead(1, { accountHandle: "reader-1", keyHandle: "key-1", bearer: "token-2" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(work.isEligible(), true);
  assert.equal(adapter.currentLease()?.bearer, "token-2");
  host.dispose();
  adapter.dispose();
});

test("overlapping lease notifications cannot confirm the skipped association", async () => {
  const feed = authorizationFeedApi();
  const adapter = adaptAuthorizationFeed(feed);
  const host = createContextHost(adapter.provider, { routes: [ROUTE] });
  feed.resolveRead(0, { accountHandle: "reader-1", keyHandle: "key-1", bearer: "token-1" });
  await adapter.ready;
  const work = host.capture(ROUTE);
  assert.ok(work);
  feed.notifyChange();
  feed.notifyChange();
  feed.resolveRead(2, { accountHandle: "reader-1", keyHandle: "key-1", bearer: "token-2" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(work.isEligible(), false, "the skipped read may have observed another association");
  feed.resolveRead(1, { accountHandle: "reader-2", keyHandle: "key-2", bearer: "late" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(
    adapter.currentLease()?.bearer,
    "token-2",
    "stale read cannot overwrite newer state",
  );
  host.dispose();
  adapter.dispose();
});

test("distinct handle tuples and mutable feed values cannot cross associations", async () => {
  const sessions = sessionEventApi();
  const sessionAdapter = adaptSessionEvents(sessions);
  const sessionHost = createContextHost(sessionAdapter.provider, { routes: [ROUTE] });
  const firstSession = { accountRef: "a\0b", credentialRef: "c", bearerToken: "event-one" };
  sessions.publish(firstSession);
  const sessionWork = sessionHost.capture(ROUTE);
  assert.ok(sessionWork);
  firstSession.bearerToken = "mutated-without-event";
  assert.equal(sessionAdapter.readBearerCredential(), "Bearer event-one");
  sessions.publish({ accountRef: "a", credentialRef: "b\0c", bearerToken: "event-two" });
  assert.equal(sessionWork.isEligible(), false, "NUL in handles cannot collide as a tuple");

  const feed = authorizationFeedApi();
  const adapter = adaptAuthorizationFeed(feed);
  const host = createContextHost(adapter.provider, { routes: [ROUTE] });
  const firstLease = { accountHandle: "a\0b", keyHandle: "c", bearer: "lease-one" };
  feed.resolveRead(0, firstLease);
  await adapter.ready;
  const work = host.capture(ROUTE);
  assert.ok(work);
  firstLease.bearer = "mutated-without-event";
  firstLease.accountHandle = "other";
  assert.deepEqual(adapter.currentLease(), {
    accountHandle: "a\0b",
    keyHandle: "c",
    bearer: "lease-one",
  });
  feed.notifyChange();
  feed.resolveRead(1, { accountHandle: "a", keyHandle: "b\0c", bearer: "lease-two" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(work.isEligible(), false, "distinct feed tuples retire old work");

  sessionHost.dispose();
  sessionAdapter.dispose();
  assert.equal(
    sessionAdapter.readBearerCredential(),
    null,
    "disposed event adapter exposes no stale bearer",
  );
  sessionAdapter.dispose();
  host.dispose();
  adapter.dispose();
  assert.equal(adapter.currentLease(), null);
  adapter.dispose();
});

test("disposing during a pending feed read ignores its late credential", async () => {
  const feed = authorizationFeedApi();
  const adapter = adaptAuthorizationFeed(feed);
  feed.resolveRead(0, { accountHandle: "reader-1", keyHandle: "key-1", bearer: "token-1" });
  await adapter.ready;
  feed.notifyChange();
  adapter.dispose();
  feed.resolveRead(1, { accountHandle: "reader-2", keyHandle: "key-2", bearer: "late-token" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(adapter.currentLease(), null);
  adapter.dispose();
});

/** @typedef {{accountRef: string, credentialRef: string, bearerToken: string}} SessionRecord */
/** @typedef {{accountHandle: string, keyHandle: string, bearer: string}} AuthorizationLease */
