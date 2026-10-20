// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { createAccountSource, accountFromLocal } from "../implementation/account-source.js";
import { createAccountMenu } from "../test-lib/account-menu.js";

const readiness = { signIn: true, signOut: false, openAccount: false };
const snapshot = (sequence = 0, signedIn = "unknown", actionReady = readiness) => ({
  sequence,
  observedAt: 1000,
  validUntil: 2000,
  signedIn,
  actionReady,
});

test("account replay preserves original times, copied readiness and exact stop identity", () => {
  const initial = snapshot();
  const source = createAccountSource(initial);
  const seen = [];
  let passedStop;
  const stop = source.provider.subscribe((s, halt) => {
    seen.push(s);
    passedStop = halt;
  });
  assert.equal(stop, passedStop);
  assert.equal(seen[0].observedAt, 1000);
  initial.actionReady = { signIn: false, signOut: false, openAccount: false };
  assert.equal(seen[0].actionReady.signIn, true);
  assert.ok(Object.isFrozen(seen[0]));
  assert.ok(Object.isFrozen(seen[0].actionReady));
  stop();
  stop();
  source.publish(snapshot(1, "yes"));
  assert.equal(seen.length, 1);
});

test("the menu derives expiry after a clock jump without a new source event", () => {
  let clock = 1500;
  const source = createAccountSource(snapshot(0, "yes"), { signIn: () => "started" });
  const menu = createAccountMenu(source.provider, () => clock);
  assert.equal(menu.view().signedIn, "yes");
  assert.equal(menu.view().actionReady.signIn, true);
  clock = 2000;
  assert.deepEqual(menu.view(), {
    signedIn: "unknown",
    actionReady: { signIn: false, signOut: false, openAccount: false },
  });
  const late = createAccountMenu(source.provider, () => clock);
  assert.equal(late.view().signedIn, "unknown"); // Late replay cannot renew validUntil.
  late.dispose();
  menu.dispose();
});

test("an unknown hint can offer ready sign-in and initiation runs inside the click", async () => {
  let started = 0;
  const source = createAccountSource(snapshot(), {
    signIn() {
      started += 1;
      return "started";
    },
  });
  const menu = createAccountMenu(source.provider, () => 1500);
  assert.equal(menu.view().signedIn, "unknown");
  const pending = menu.invoke("signIn");
  assert.equal(started, 1);
  assert.equal(await pending, "started");
  assert.equal(menu.view().signedIn, "unknown");
  source.publish(snapshot(1, "yes"));
  assert.equal(menu.view().signedIn, "yes");
  menu.dispose();
});

test("presence and readiness are both required; clicks are never queued for future readiness", async () => {
  let calls = 0;
  const source = createAccountSource(snapshot(), {
    signOut() {
      calls += 1;
      return "started";
    },
  });
  const menu = createAccountMenu(source.provider, () => 1500);
  assert.equal(menu.view().actionReady.signIn, false); // Ready but method absent.
  assert.equal(await menu.invoke("signIn"), "unsupported");
  assert.equal(await menu.invoke("signOut"), "unsupported");
  source.publish(snapshot(1, "unknown", { signIn: false, signOut: true, openAccount: false }));
  assert.equal(calls, 0);
  assert.equal(await menu.invoke("signOut"), "started");
  assert.equal(calls, 1);
  menu.dispose();
});

for (const [name, initiate] of [
  [
    "throw",
    () => {
      throw new Error("SDK failed");
    },
  ],
  ["rejection", () => Promise.reject(new Error("SDK failed"))],
  ["invalid outcome", () => "logged-in"],
])
  test(`action ${name} reports failed without inventing account state`, async () => {
    const source = createAccountSource(snapshot(), { signIn: initiate });
    const menu = createAccountMenu(source.provider, () => 1500);
    assert.equal(await menu.invoke("signIn"), "failed");
    assert.equal(menu.view().signedIn, "unknown");
    menu.dispose();
  });

test("local account hints map explicitly and preserve original freshness", () => {
  for (const [state, signedIn] of [
    ["signed-in", "yes"],
    ["signed-out", "no"],
    ["unknown", "unknown"],
  ]) {
    assert.deepEqual(
      accountFromLocal({ state, observedAt: 1000, validUntil: 2000 }, 4, readiness),
      snapshot(4, signedIn),
    );
  }
  assert.throws(
    () => accountFromLocal({ state: "maybe", observedAt: 1000, validUntil: 2000 }, 0, readiness),
    { code: "bad_config" },
  );
});

test("older observations cannot overwrite current account/readiness", () => {
  const source = createAccountSource(snapshot());
  const seen = [];
  source.provider.subscribe((s) => seen.push(s.sequence));
  assert.equal(source.publish(snapshot(2, "yes")), true);
  assert.equal(source.publish(snapshot(1, "no")), false);
  assert.equal(source.publish(snapshot(2, "no")), false);
  assert.deepEqual(seen, [0, 2]);
});

test("reentrant account publication is ordered and late subscribe skips queued older changes", () => {
  const source = createAccountSource(snapshot());
  const calls = [];
  source.provider.subscribe((s) => {
    if (s.sequence !== 1) return;
    calls.push("A1");
    source.publish(snapshot(2));
    source.provider.subscribe((next) => calls.push(`C${next.sequence}`));
    calls.push("Aend");
  });
  source.provider.subscribe((s) => {
    if (s.sequence > 0) calls.push(`B${s.sequence}`);
  });
  source.publish(snapshot(1));
  assert.deepEqual(calls, ["A1", "C2", "Aend", "B1", "B2"]);
});

test("stop during replay prevents publication and thrown listener/reporter cannot interrupt peers", () => {
  const source = createAccountSource(snapshot());
  let stopped = 0;
  let peers = 0;
  const old = Object.getOwnPropertyDescriptor(globalThis, "reportError");
  Object.defineProperty(globalThis, "reportError", {
    value() {
      throw new Error("reporter failed");
    },
    configurable: true,
  });
  try {
    source.provider.subscribe((_s, stop) => {
      stopped += 1;
      stop();
    });
    source.provider.subscribe(() => {
      throw new Error("listener failed");
    });
    source.provider.subscribe(() => {
      peers += 1;
    });
    source.publish(snapshot(1));
    assert.equal(stopped, 1);
    assert.equal(peers, 2);
  } finally {
    if (old) Object.defineProperty(globalThis, "reportError", old);
    else delete globalThis.reportError;
  }
});

test("end emits unknown, stops all subscriptions and refuses later actions/publications", async () => {
  let calls = 0;
  const source = createAccountSource(snapshot(0, "yes"), {
    signIn() {
      calls += 1;
      return "started";
    },
  });
  const seen = [];
  source.provider.subscribe((s) => seen.push(s));
  source.end();
  source.end();
  assert.equal(seen.length, 2);
  assert.equal(seen[1].sequence, 1);
  assert.equal(seen[1].signedIn, "unknown");
  assert.equal(seen[1].observedAt, 1000);
  assert.equal(seen[1].validUntil, 2000);
  assert.equal(source.publish(snapshot(2, "yes")), false);
  assert.equal(await source.provider.actions.signIn(), "unsupported");
  assert.equal(calls, 0);
  let late = 0;
  source.provider.subscribe((s) => {
    late += 1;
    assert.equal(s.signedIn, "unknown");
  });
  assert.equal(late, 1);
});

test("account producers reserve MAX_SAFE_INTEGER for their final unknown observation", () => {
  const source = createAccountSource(snapshot(Number.MAX_SAFE_INTEGER - 1, "yes"));
  const seen = [];
  source.provider.subscribe((s) => seen.push([s.sequence, s.signedIn]));
  source.end();
  assert.deepEqual(seen, [
    [Number.MAX_SAFE_INTEGER - 1, "yes"],
    [Number.MAX_SAFE_INTEGER, "unknown"],
  ]);
  assert.equal(source.publish(snapshot(Number.MAX_SAFE_INTEGER, "yes")), false);
});

test("an account consumer treats MAX_SAFE_INTEGER as an ordinary observation", () => {
  /** @type {import("../implementation/account-source.js").AccountProvider} */
  const provider = {
    actions: {},
    subscribe(listener) {
      listener(snapshot(Number.MAX_SAFE_INTEGER, "yes"), () => {});
      return () => {};
    },
  };
  const menu = createAccountMenu(provider, () => 1500);
  assert.equal(menu.view().signedIn, "yes");
  menu.dispose();
});

test("menu disposal invalidates stale display and action use", async () => {
  const source = createAccountSource(snapshot(0, "yes"), { signIn: () => "started" });
  const menu = createAccountMenu(source.provider, () => 1500);
  menu.dispose();
  menu.dispose();
  source.publish(snapshot(1, "no"));
  assert.equal(menu.view().signedIn, "unknown");
  assert.equal(await menu.invoke("signIn"), "unsupported");
});

test("malformed times, readiness, sequences and extra identity members refuse", () => {
  for (const input of [
    { ...snapshot(), observedAt: -1 },
    { ...snapshot(), validUntil: 999 },
    { ...snapshot(), observedAt: 1.5 },
    { ...snapshot(), sequence: Number.MAX_SAFE_INTEGER },
    { ...snapshot(), signedIn: "signed-in" },
    { ...snapshot(), actionReady: { ...readiness, token: true } },
    { ...snapshot(), userId: "alice" },
    Object.defineProperty(snapshot(), "secret", { value: "hidden" }),
  ])
    assert.throws(() => createAccountSource(input), { code: "bad_config" });
  assert.throws(() => createAccountSource(snapshot(), { signIn: undefined }), {
    code: "bad_config",
  });
});

test("ending during initial account replay still delivers final unknown", () => {
  const source = createAccountSource(snapshot(0, "yes"));
  const seen = [];
  source.provider.subscribe((s) => {
    seen.push([s.sequence, s.signedIn]);
    if (s.sequence === 0) source.end();
  });
  assert.deepEqual(seen, [
    [0, "yes"],
    [1, "unknown"],
  ]);
});
