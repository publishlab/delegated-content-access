// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import {
  KEY_CONTRAST_ACTIONS,
  createKeyContrastRunner,
} from "../../demo/browser/key-attempt-runners.js";
import { PageLoad } from "../../demo/actors/PageLoad.js";

const KEY_CONTRAST_SETUP = Object.freeze({
  at: "2025-10-23T14:20:00Z",
  seed: 1,
  period: Object.freeze({ length: 60, slots: 2 }),
  transportMode: "direct",
  fallback: false,
  primaryOffline: false,
});

test("the fixed mismatch probe is not a public PageLoad cross-page operation", () => {
  assert.equal(
    Object.getOwnPropertyNames(PageLoad.prototype).some((name) => /probe|mismatch/i.test(name)),
    false,
    "only the scenario-specific demo helper may run the cross-render mismatch",
  );
});

test("the fixed A-held-CKey-on-B action is a real failed open and leaves B protected", async () => {
  const runner = await createKeyContrastRunner(KEY_CONTRAST_SETUP);
  const before = runner.trace();
  const unlock = before.steps.find((step) => step.kind === "unlock" && step.label === "A");
  const openedA = before.steps.find(
    (step) => step.kind === "open" && step.label === "A" && step.opened,
  );

  assert.deepEqual(
    unlock.wire.response,
    {
      contentKeyNames: ["bodytext"],
      periodKeyCoordinates: [{ accessGroup: "premium", t: ["251023T1400", "251023T1500"] }],
      chainKeyCoordinates: [],
      counts: { contentKeys: 1, periodKeys: 2, chainKeys: 0 },
    },
    "the retained direct response is coordinates and counts, never a raw CKey",
  );
  assert.equal(
    Object.hasOwn(unlock.wire.response, "keys"),
    false,
    "the trace has no raw response key map",
  );
  assert.deepEqual(
    openedA.origin,
    {
      contentName: "bodytext",
      kind: "held-content-key",
    },
    "A's successful open observes its own held CKey rather than inferring it from the response",
  );

  const probe = await runner.dispatch(KEY_CONTRAST_ACTIONS.probe);
  assert.deepEqual(probe.probe, {
    sourceRenderId: before.steps[0].render.renderId,
    targetRenderId: before.steps.at(-1).render.renderId,
    contentName: "bodytext",
    sourceOrigin: "held-content-key",
    opened: false,
    error: "decrypt_failed",
  });
  assert.equal(probe.articleState, "protected");
  assert.equal(probe.sourceLoadUnchanged, true, "the probe does not change A load state");
  assert.equal(probe.targetLoadUnchanged, true, "the probe does not change B load state");
  assert.equal(probe.cacheUnchanged, true, "the probe does not change the browser cache");
  assert.equal(Object.isFrozen(probe), true);
  assert.equal(Object.isFrozen(probe.probe), true);
  assert.throws(() => {
    probe.probe.error = "no_key";
  }, TypeError);

  const trace = runner.trace();
  assert.deepEqual(trace.steps.at(-1), probe);
  assert.equal(
    trace.steps.at(-1).articleState,
    "protected",
    "B was not resolved or opened by the probe",
  );
});

test("the only normal B action uses the actual cached period-key path and opens B", async () => {
  const runner = await createKeyContrastRunner(KEY_CONTRAST_SETUP);
  const opened = await runner.dispatch(KEY_CONTRAST_ACTIONS.open);

  assert.deepEqual(opened.covered, ["bodytext"]);
  assert.deepEqual(opened.missing, []);
  assert.deepEqual(opened.resolutionOrigin, {
    contentName: "bodytext",
    kind: "cached-period-key",
    accessGroup: "premium",
    t: "251023T1500",
  });
  assert.deepEqual(opened.origin, {
    contentName: "bodytext",
    kind: "held-content-key",
  });
  assert.equal(opened.opened, true);
  assert.equal(opened.error, null);
  assert.equal(opened.articleState, "open");
  assert.equal(opened.text, "<p>The harbour plan goes to a second reading.</p>");

  await assert.rejects(
    () => runner.dispatch(KEY_CONTRAST_ACTIONS.probe),
    (/** @type {any} */ error) => error.code === "bad_config",
    "the mismatch probe exists only at the paused protected-B state",
  );
});

test("the direct runner rejects unknown actions without changing its trace", async () => {
  const runner = await createKeyContrastRunner(KEY_CONTRAST_SETUP);
  const before = runner.trace();

  await assert.rejects(
    () => runner.dispatch("caller-supplied-key-or-target"),
    (/** @type {any} */ error) => error.code === "unsupported_option",
  );
  assert.deepEqual(runner.trace(), before);
});

test("concurrent direct-runner probes record exactly one action", async () => {
  const runner = await createKeyContrastRunner(KEY_CONTRAST_SETUP);
  const action = KEY_CONTRAST_ACTIONS.probe;
  const results = await Promise.allSettled([runner.dispatch(action), runner.dispatch(action)]);
  const fulfilled = results.filter((result) => result.status === "fulfilled");
  const rejected = results.filter((result) => result.status === "rejected");

  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason.code, "bad_config");
  assert.equal(
    runner.trace().steps.filter((step) => step.kind === "probe" && step.action === action).length,
    1,
    "the session appends only the one action that acquired the in-flight guard",
  );
});

test("the runner rejects a declaration outside its fixed direct-world contract before actor construction", async () => {
  await assert.rejects(
    () => createKeyContrastRunner({ ...KEY_CONTRAST_SETUP, seed: 2 }),
    (error) => error.code === "bad_config",
  );
});
