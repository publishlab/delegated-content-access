// @ts-check
// Shared observable contracts for independently implemented browser participants.

import test from "node:test";
import assert from "node:assert/strict";

/** @param {number} sequence @param {boolean} contextKnown @param {string} contextRevision */
function contextSnapshot(sequence, contextKnown, contextRevision) {
  return { sequence, contextKnown, contextRevision };
}

/** @param {number} sequence @param {"yes"|"no"|"unknown"} signedIn @param {number} observedAt @param {number} validUntil */
function accountSnapshot(sequence, signedIn, observedAt, validUntil) {
  return {
    sequence,
    observedAt,
    validUntil,
    signedIn,
    actionReady: { signIn: true, signOut: false, openAccount: false },
  };
}

function deferred() {
  /** @type {(value: void | PromiseLike<void>) => void} */
  let resolve = () => {};
  /** @type {Promise<void>} */
  const promise = new Promise((done) => {
    resolve = () => done(undefined);
  });
  return { promise, resolve };
}

/**
 * Register contracts against supplied factories. The suite imports no reference
 * implementation; another participant can supply equivalent factories and a
 * source/host driver while reusing these observable expectations.
 *
 * @param {{
 *   createRegistry: (host?: object) => import("../types/registry.js").ClientRegistry,
 *   createContextSource: (initial: import("../types/context-source.js").ContextSnapshot) => import("../types/context-source.js").ContextSourceController,
 *   createContextHost: (source: import("../types/context-source.js").ContextSourceProvider, scope: {routes: string[]}) => import("./context-host.js").ContextHost,
 *   createAccountSource: (initial: import("../types/account-source.js").AccountSnapshot, actions?: import("../types/account-source.js").AccountInitiators) => {provider: import("../types/account-source.js").AccountProvider, publish: (snapshot: import("../types/account-source.js").AccountSnapshot) => boolean, end: () => void},
 *   createAccountMenu: (provider: import("../types/account-source.js").AccountProvider, now: () => number) => {view: () => {signedIn: "yes"|"no"|"unknown", actionReady: Record<import("../types/account-source.js").AccountAction, boolean>}, invoke: (action: import("../types/account-source.js").AccountAction) => Promise<import("../types/account-source.js").ActionOutcome>, dispose: () => void},
 *   createContentHandler: () => import("../types/content-handler.js").ContentHandler,
 * }} implementation
 */
export function registerContracts(implementation) {
  test("context replay is synchronous, copied/frozen and uses the returned idempotent stop", () => {
    const source = implementation.createContextSource(contextSnapshot(0, false, "r1"));
    /** @type {import("../types/context-source.js").ContextSnapshot[]} */
    const seen = [];
    /** @type {Array<() => void>} */
    const stops = [];
    let returned = false;
    const stop = source.provider.subscribe((snapshot, callbackStop) => {
      if (seen.length === 0) {
        assert.equal(returned, false, "initial replay precedes subscribe return");
      }
      seen.push(snapshot);
      stops.push(callbackStop);
    });
    returned = true;
    assert.equal(stops[0], stop);
    assert.ok(Object.isFrozen(seen[0]));
    const published = contextSnapshot(1, true, "r2");
    assert.equal(source.publish(published), true);
    published.contextRevision = "mutated";
    assert.equal(seen[1].contextRevision, "r2");
    stop();
    stop();
    assert.equal(source.publish(contextSnapshot(2, true, "r2")), true);
    assert.equal(seen.length, 2, "stopped listener receives no later publications");
  });

  test("unknown context can resume its captured revision; a revision change retires it", async () => {
    const source = implementation.createContextSource(contextSnapshot(0, true, "r1"));
    const host = implementation.createContextHost(source.provider, { routes: ["subscription"] });
    const work = host.capture("subscription");
    assert.ok(work);
    assert.equal(source.publish(contextSnapshot(1, false, "r1")), true);
    assert.equal(work.isEligible(), false);
    const resumed = work.waitUntilKnown();
    assert.equal(source.publish(contextSnapshot(2, true, "r1")), true);
    assert.equal(await resumed, true);
    assert.equal(work.isEligible(), true);
    assert.equal(source.publish(contextSnapshot(3, true, "r2")), true);
    assert.equal(await work.waitUntilKnown(), false);
    assert.equal(work.isEligible(), false);
    host.dispose();
  });

  test("source end publishes final unknown, stops listeners and replays that final snapshot late", () => {
    const source = implementation.createContextSource(contextSnapshot(4, true, "r1"));
    /** @type {Array<import("../types/context-source.js").ContextSnapshot>} */
    const seen = [];
    /** @type {Array<() => void>} */
    const stops = [];
    const stop = source.provider.subscribe((snapshot, callbackStop) => {
      seen.push(snapshot);
      stops.push(callbackStop);
    });
    assert.equal(stops[0], stop);
    source.end();
    source.end();
    assert.deepEqual(
      seen.map(({ sequence, contextKnown, contextRevision }) => [
        sequence,
        contextKnown,
        contextRevision,
      ]),
      [
        [4, true, "r1"],
        [5, false, "r1"],
      ],
    );
    assert.equal(source.publish(contextSnapshot(6, true, "r1")), false);
    /** @type {Array<import("../types/context-source.js").ContextSnapshot>} */
    const late = [];
    /** @type {Array<() => void>} */
    const lateStops = [];
    const lateStop = source.provider.subscribe((snapshot, callbackStop) => {
      late.push(snapshot);
      lateStops.push(callbackStop);
    });
    assert.equal(lateStops[0], lateStop);
    lateStop();
    assert.equal(late.length, 1);
    assert.deepEqual([late[0].sequence, late[0].contextKnown], [5, false]);
  });

  test("account replay preserves original freshness and expiry changes a menu read without an event", () => {
    let now = 1500;
    const initial = accountSnapshot(0, "yes", 1000, 2000);
    const source = implementation.createAccountSource(initial);
    /** @type {Array<import("../types/account-source.js").AccountSnapshot>} */
    const observations = [];
    source.provider.subscribe((snapshot) => observations.push(snapshot));
    initial.validUntil = 9000;
    assert.equal(observations[0].validUntil, 2000);
    assert.ok(Object.isFrozen(observations[0]));
    const menu = implementation.createAccountMenu(source.provider, () => now);
    assert.equal(menu.view().signedIn, "yes");
    now = 2000;
    assert.equal(menu.view().signedIn, "unknown");
    assert.equal(observations.length, 1, "expiry is derived without a producer event");
    const lateMenu = implementation.createAccountMenu(source.provider, () => now);
    assert.equal(
      lateMenu.view().signedIn,
      "unknown",
      "late replay does not refresh original times",
    );
    lateMenu.dispose();
    menu.dispose();
  });

  test("account action initiation is synchronous and never invents an observed account state", async () => {
    const pending = deferred();
    let initiated = 0;
    const source = implementation.createAccountSource(accountSnapshot(0, "unknown", 1000, 2000), {
      signIn() {
        initiated += 1;
        return pending.promise.then(() => "started");
      },
    });
    const menu = implementation.createAccountMenu(source.provider, () => 1500);
    const result = menu.invoke("signIn");
    assert.equal(initiated, 1, "upstream action begins before invoke returns");
    assert.equal(menu.view().signedIn, "unknown");
    pending.resolve();
    assert.equal(await result, "started");
    assert.equal(
      menu.view().signedIn,
      "unknown",
      "action completion is not an account observation",
    );
    menu.dispose();
  });

  test("registry observes and selects only its exact configured key", () => {
    const registry = implementation.createRegistry({});
    const selected = { interface: "dca.content-handler", major: 1, name: "article" };
    const differentName = { ...selected, name: "fallback" };
    const wrongMajor = { ...selected, major: 2 };
    const provider = { connect() {} };
    const remove = registry.register(selected, provider);
    let returned = false;
    /** @type {unknown[]} */
    const seen = [];
    const stop = registry.observe(selected, (entry) => {
      assert.equal(returned, false, "initial registry replay is synchronous");
      seen.push(entry.provider);
    });
    returned = true;
    assert.equal(seen[0], provider);
    assert.equal(registry.lookup(selected), provider);
    assert.equal(registry.lookup(differentName), null);
    assert.equal(registry.lookup(wrongMajor), null);
    stop();
    remove();
    assert.deepEqual(seen, [provider], "unselected keys do not notify this observer");
  });

  test("a stale registry disposer cannot remove a successor registration", () => {
    const registry = implementation.createRegistry({});
    const key = { interface: "dca.content-handler", major: 1, name: "article" };
    const first = { connect() {} };
    const second = { connect() {} };
    const removeFirst = registry.register(key, first);
    removeFirst();
    const removeSecond = registry.register(key, second);
    removeFirst();
    assert.equal(registry.lookup(key), second);
    assert.throws(() => registry.register(key, first));
    removeSecond();
    assert.equal(registry.lookup(key), null);
  });

  test("a delayed callback cannot commit after its eligibility is lost", async () => {
    const gate = deferred();
    const entered = deferred();
    let eligible = true;
    let effects = 0;
    const handler = implementation.createContentHandler();
    const connection = handler.connect({
      delivery: { contentData: [{ contentName: "bodytext", contentType: "text/html" }] },
      isEligible: () => eligible,
      targets: {
        bodytext: async ({ commit }) => {
          entered.resolve();
          await gate.promise;
          commit(() => effects++);
          return { status: "handled" };
        },
      },
    });
    const result = connection.handleContent({ bodytext: new Uint8Array([1]) });
    await entered.promise;
    eligible = false;
    gate.resolve();
    assert.equal((await result).bodytext.status, "stale");
    assert.equal(effects, 0);
    connection.dispose();
  });

  test("handler distinguishes clean refusal from inconsistent effect reports", async () => {
    let effects = 0;
    const handler = implementation.createContentHandler();
    const connection = handler.connect({
      delivery: {
        contentData: [
          { contentName: "clean", contentType: "text/plain" },
          { contentName: "refusedAfterEffect", contentType: "text/plain" },
          { contentName: "handledWithoutEffect", contentType: "text/plain" },
        ],
      },
      isEligible: () => true,
      targets: {
        clean: () => ({ status: "refused", reason: "unsupported" }),
        refusedAfterEffect: ({ commit }) => {
          commit(() => effects++);
          return { status: "refused", reason: "unsupported" };
        },
        handledWithoutEffect: () => ({ status: "handled" }),
      },
    });
    const outcomes = await connection.handleContent({
      clean: new Uint8Array([1]),
      refusedAfterEffect: new Uint8Array([2]),
      handledWithoutEffect: new Uint8Array([3]),
    });
    assert.equal(outcomes.clean.status, "refused");
    assert.equal(outcomes.refusedAfterEffect.status, "failed");
    assert.equal(outcomes.handledWithoutEffect.status, "failed");
    assert.equal(effects, 1, "the contract does not imply rollback of an effect already applied");
    connection.dispose();
  });

  test("after partial failure a retry is refused for reconciliation without repeating effects", async () => {
    let calls = 0;
    let effects = 0;
    const connection = implementation.createContentHandler().connect({
      delivery: { contentData: [{ contentName: "bodytext", contentType: "text/html" }] },
      isEligible: () => true,
      targets: {
        bodytext: ({ commit }) => {
          calls += 1;
          commit(() => effects++);
          return { status: "failed", reason: "later_step_failed" };
        },
      },
    });
    const bytes = new Uint8Array([4, 5]);
    assert.equal((await connection.handleContent({ bodytext: bytes })).bodytext.status, "failed");
    assert.equal((await connection.handleContent({ bodytext: bytes })).bodytext.status, "refused");
    assert.equal(calls, 1);
    assert.equal(effects, 1, "an applied partial effect remains visible and is not replayed");
    connection.dispose();
  });
}
