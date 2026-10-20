// Real dispatch and opened content cross the captured source association.
import test from "node:test";
import assert from "node:assert/strict";
import { setImmediate as turn } from "node:timers/promises";
import { createContextSource } from "../implementation/context-source.js";
import { createContextHost } from "../test-lib/context-host.js";
import { createContentHandler } from "../implementation/content-handler.js";
import { createAccountSource } from "../implementation/account-source.js";
import { createAccountMenu } from "../test-lib/account-menu.js";
import { installRegistry } from "../implementation/registry.js";
import { exchange, deferred } from "../test-lib/exchange.js";

const snapshot = (sequence, contextKnown = true, contextRevision = "r1") => ({
  sequence,
  contextKnown,
  contextRevision,
});
const item = (text = "<p>Article A</p>") => ({
  name: "bodytext",
  bytes: new TextEncoder().encode(text),
  contentType: "text/html",
});
const scope = { routes: ["subscription"] };

// Recheck after the wait: a known observation may be superseded before the
// promise continuation runs. Dispatch/effect initiation must see current ownership.
async function gated(work, operation) {
  while (await work.waitUntilKnown()) {
    if (!work.isEligible()) continue;
    return { completed: true, value: await operation() };
  }
  return { completed: false };
}
async function present(
  work,
  client,
  target,
  { unlock = true, afterResponse = async () => {}, granted = () => {} } = {},
) {
  const connection = createContentHandler().connect({
    delivery: client.delivery,
    isEligible: () => work.isEligible() && target.owner === work,
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
  try {
    if (unlock) {
      const sent = await gated(work, () => client.unlock(afterResponse));
      if (!sent.completed) return { status: "stale" };
      granted();
    }
    const opened = await gated(work, () => client.open("bodytext"));
    if (!opened.completed) return { status: "stale" };
    const output = await gated(work, () => connection.handleContent({ bodytext: opened.value }));
    const outcome = output.completed ? output.value.bodytext : { status: "stale" };
    if (outcome.status === "stale") work.dispose();
    return outcome;
  } finally {
    connection.dispose();
  }
}
function target(work) {
  return { owner: work, text: null, writes: 0 };
}

test("initial unknown prevents client work and actual issuer dispatch until known", async () => {
  const client = (await exchange([item()])).createClient();
  const source = createContextSource(snapshot(0, false));
  const host = createContextHost(source.provider, scope);
  assert.equal(host.capture("subscription"), null);
  assert.equal(client.requests, 0);
  source.publish(snapshot(1));
  const work = host.capture("subscription");
  assert.ok(work);
  const view = target(work);
  assert.equal((await present(work, client, view)).status, "handled");
  assert.equal(client.requests, 1);
  assert.equal(view.text, "<p>Article A</p>");
  host.dispose();
});

test("unknown before dispatch suspends captured work; same revision resumes without substitution", async () => {
  const client = (await exchange([item()])).createClient();
  const source = createContextSource(snapshot(0));
  const host = createContextHost(source.provider, scope);
  const work = host.capture("subscription");
  assert.ok(work);
  const view = target(work);
  source.publish(snapshot(1, false));
  const pending = present(work, client, view);
  await turn();
  assert.equal(client.requests, 0);
  assert.equal(view.writes, 0);
  source.publish(snapshot(2));
  assert.equal((await pending).status, "handled");
  assert.equal(client.requests, 1);
  assert.equal(view.writes, 1);
  host.dispose();
});

test("already sent response stays captured through unknown; output waits and same revision resumes", async () => {
  const client = (await exchange([item()])).createClient();
  const source = createContextSource(snapshot(0));
  const host = createContextHost(source.provider, scope);
  const work = host.capture("subscription");
  const view = target(work);
  const response = deferred(),
    release = deferred(),
    applied = deferred();
  const pending = present(work, client, view, {
    afterResponse: async () => {
      response.resolve();
      await release.promise;
    },
    granted: applied.resolve,
  });
  await response.promise;
  assert.equal(client.requests, 1);
  source.publish(snapshot(1, false));
  release.resolve();
  await applied.promise;
  await turn();
  assert.equal(view.writes, 0);
  assert.ok(await client.keyFor("bodytext"));
  source.publish(snapshot(2));
  assert.equal((await pending).status, "handled");
  assert.equal(client.requests, 1);
  assert.equal(view.writes, 1);
  host.dispose();
});

test("retained authorized key use waits through unknown and resumes without a new issuer request", async () => {
  const client = (await exchange([item()])).createClient();
  await client.unlock();
  const source = createContextSource(snapshot(0));
  const host = createContextHost(source.provider, scope);
  const work = host.capture("subscription");
  const view = target(work);
  source.publish(snapshot(1, false));
  const pending = present(work, client, view, { unlock: false });
  await turn();
  assert.equal(client.requests, 1);
  assert.equal(view.writes, 0);
  source.publish(snapshot(2));
  assert.equal((await pending).status, "handled");
  assert.equal(client.requests, 1);
  assert.equal(view.writes, 1);
  host.dispose();
});

test("source replacement repeating the revision retires old response ownership and keeps successor live", async () => {
  const publisher = await exchange([item()]);
  const oldClient = publisher.createClient();
  const freshClient = publisher.createClient();
  const oldSource = createContextSource(snapshot(0));
  const newSource = createContextSource(snapshot(0));
  const registry = installRegistry({});
  const key = { interface: "dca.access-context", major: 1, name: "login" };
  let host = null;
  const stop = registry.observe(key, (entry) => {
    host?.dispose();
    host = entry.provider ? createContextHost(entry.provider, scope) : null;
  });
  const removeOld = registry.register(key, oldSource.provider);
  const oldWork = host.capture("subscription");
  const view = target(oldWork);
  const started = deferred(),
    release = deferred();
  const pending = present(oldWork, oldClient, view, {
    afterResponse: async () => {
      started.resolve();
      await release.promise;
    },
  });
  await started.promise;
  removeOld();
  const removeNew = registry.register(key, newSource.provider);
  assert.equal(oldWork.isEligible(), false);
  const freshWork = host.capture("subscription");
  view.owner = freshWork;
  assert.equal(await freshClient.keyFor("bodytext"), null);
  assert.equal((await present(freshWork, freshClient, view)).status, "handled");
  release.resolve();
  assert.equal((await pending).status, "stale");
  assert.ok(await oldClient.keyFor("bodytext")); // Delivered capability remains in its captured client.
  assert.equal(view.writes, 1);
  assert.equal(freshClient.requests, 1);
  stop();
  removeNew();
  host.dispose();
});

test("same-label context revision change excludes old asynchronous output from a reused destination", async () => {
  const a = (await exchange([item("<p>A</p>")])).createClient();
  const b = (await exchange([item("<p>B</p>")])).createClient();
  const account = createAccountSource({
    sequence: 0,
    observedAt: 0,
    validUntil: 2000,
    signedIn: "yes",
    actionReady: { signIn: false, signOut: false, openAccount: false },
  });
  const menu = createAccountMenu(account.provider, () => 1000);
  assert.equal(menu.view().signedIn, "yes");
  const source = createContextSource(snapshot(0, true, "alice-generation"));
  const host = createContextHost(source.provider, scope);
  const old = host.capture("subscription");
  const view = target(old);
  const started = deferred(),
    release = deferred();
  const pending = present(old, a, view, {
    afterResponse: async () => {
      started.resolve();
      await release.promise;
    },
  });
  await started.promise;
  source.publish(snapshot(1, true, "bob-generation"));
  assert.equal(menu.view().signedIn, "yes");
  const fresh = host.capture("subscription");
  view.owner = fresh;
  assert.equal((await present(fresh, b, view)).status, "handled");
  release.resolve();
  assert.equal((await pending).status, "stale");
  assert.equal(view.text, "<p>B</p>");
  assert.equal(view.writes, 1);
  host.dispose();
});

test("shared source scopes retire their own routes while an unrelated live context continues", async () => {
  const publisher = await exchange([item()]);
  const shared = createContextSource(snapshot(0));
  const independent = createContextSource(snapshot(0));
  const host = createContextHost(shared.provider, { routes: ["subscription", "meter"] });
  const other = createContextHost(independent.provider, scope);
  const one = host.capture("subscription"),
    two = host.capture("meter"),
    live = other.capture("subscription");
  shared.publish(snapshot(1, true, "r2"));
  assert.equal(one.isEligible(), false);
  assert.equal(two.isEligible(), false);
  const client = publisher.createClient(),
    view = target(live);
  assert.equal((await present(live, client, view)).status, "handled");
  assert.equal(client.requests, 1);
  host.dispose();
  other.dispose();
});

test("disposal during unknown ends the wait and never starts a request after recovery", async () => {
  const client = (await exchange([item()])).createClient();
  const source = createContextSource(snapshot(0));
  const host = createContextHost(source.provider, scope);
  const work = host.capture("subscription");
  const view = target(work);
  source.publish(snapshot(1, false));
  const pending = present(work, client, view);
  await turn();
  work.dispose();
  assert.equal((await pending).status, "stale");
  source.publish(snapshot(2));
  assert.equal(work.isEligible(), false);
  assert.equal(client.requests, 0);
  assert.equal(view.writes, 0);
  host.dispose();
});

test("a synchronous known/unknown race cannot dispatch after wait promise resolution", async () => {
  const client = (await exchange([item()])).createClient();
  const source = createContextSource(snapshot(0));
  const host = createContextHost(source.provider, scope);
  const work = host.capture("subscription");
  const view = target(work);
  const pending = present(work, client, view);
  source.publish(snapshot(1, false));
  await turn();
  assert.equal(client.requests, 0);
  source.publish(snapshot(2));
  assert.equal((await pending).status, "handled");
  assert.equal(client.requests, 1);
  host.dispose();
});

test("unknown during an asynchronous callback makes it stale and later recovery cannot revive it", async () => {
  const client = await (await exchange([item()])).client();
  const source = createContextSource(snapshot(0));
  const host = createContextHost(source.provider, scope);
  const work = host.capture("subscription");
  const view = target(work);
  const started = deferred(),
    release = deferred();
  const connection = createContentHandler().connect({
    delivery: client.delivery,
    isEligible: work.isEligible,
    values: { bodytext: "strictUTF8" },
    targets: {
      async bodytext({ value, commit }) {
        started.resolve();
        await release.promise;
        commit(() => {
          view.text = value;
          view.writes += 1;
        });
        return { status: "handled" };
      },
    },
  });
  const pending = connection.handleContent({ bodytext: await client.open("bodytext") });
  await started.promise;
  source.publish(snapshot(1, false));
  release.resolve();
  assert.equal((await pending).bodytext.status, "stale");
  work.dispose(); // A stale handler ends this captured operation permanently.
  source.publish(snapshot(2));
  assert.equal(work.isEligible(), false);
  assert.equal(
    (await connection.handleContent({ bodytext: await client.open("bodytext") })).bodytext.status,
    "stale",
  );
  assert.equal(view.writes, 0);
  connection.dispose();
  host.dispose();
});
