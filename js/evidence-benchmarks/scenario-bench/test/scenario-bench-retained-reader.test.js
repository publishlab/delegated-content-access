import test from "node:test";
import assert from "node:assert/strict";
import { runBench } from "../runBench.js";
import { scenario } from "../scenarios/chain-keys/retained-reader.js";

for (const representation of ["chain-keys", "period-keys"])
  test(`retained reader measures reuse, denial, window transition, expiry and teardown: ${representation}`, async () => {
    const report = await runBench({ scenario, input: { representation } });
    assert.equal(report.success, true, JSON.stringify(report.checks));
    assert.equal(report.work.resource, 3);
    assert.equal(report.work["first:unlock"], 1);
    assert.equal(report.work["second:unlock"] ?? 0, 0);
    assert.equal(report.work["saved:unlock"] ?? 0, 0);
    assert.equal(report.work["next-window:unlock"], 1);
    assert.equal(report.captures["denied:response"].status, 401);
    assert.equal(report.captures["denied:response"].document.error, "denied");
    assert.equal(
      report.checks.find(({ name }) => name === "second:item:restricted").details.code,
      "no_key",
    );
    assert.equal(report.captures["saved:delivery"], undefined);
    assert.deepEqual(report.captures.delivery, {
      available: false,
      reason: "No capture was recorded for this stage in this sample/scope",
    });
    assert.notEqual(
      report.captures["first:delivery"].text,
      report.captures["second:delivery"].text,
    );
    const first = report.cache["first:after"];
    const second = report.cache["second:after"];
    assert.deepEqual(second.storage, first.storage);
    assert.ok(report.cache["next-window:after"].storage.totalBytes > first.storage.totalBytes);
    const chainCount = (snapshot) => snapshot.caches.chain.chainKeys;
    assert.equal(chainCount(first), representation === "chain-keys" ? 1 : 0);
    assert.equal(
      chainCount(report.cache["next-window:after"]),
      representation === "chain-keys" ? 2 : 0,
    );
    assert.ok(report.cache["expiry:clock-advanced"].storage.totalBytes > 0);
    assert.equal(report.cache["expiry:after-enumeration"].caches.chain.entries, 0);
    assert.equal(report.cache["expiry:after-enumeration"].caches.period.entries, 0);
    assert.equal(report.cache["expiry:after-cleanup"].storage.totalBytes, 0);
    assert.equal(report.cache.teardown.storage.entries, 0);
    assert.ok(!JSON.stringify(report.cache).includes('"key":'));
    assert.ok(report.timings["next-window:publisher"].milliseconds > 0);
  });

test("retained workload samples start fresh, retain independent randomness, and support crypto counting", async () => {
  const report = await runBench({ scenario, measurement: { runs: 2 } });
  assert.equal(report.success, true, JSON.stringify(report.checks));
  for (const sample of report.samples) {
    assert.equal(sample.cache.before.storage.entries, 0);
    assert.equal(sample.work["first:unlock"], 1);
    assert.equal(sample.cache.teardown.storage.entries, 0);
  }
  assert.notEqual(
    report.samples[0].captures["first:delivery"].text,
    report.samples[1].captures["first:delivery"].text,
  );
  const counted = await runBench({
    scenario,
    scenarioUrl: new URL("../scenarios/chain-keys/retained-reader.js", import.meta.url).href,
    measurement: { countCrypto: true, timeSteps: true },
  });
  assert.equal(counted.success, true, JSON.stringify(counted.checks));
  assert.ok(Object.keys(counted.work.cryptoTotal).length > 0);
});

test("retained input refuses ambiguous steps, reverse clocks, missing saved deliveries and unsupported scope", async () => {
  for (const steps of [
    [{ id: "bad", at: "2026-10-14T23:00:00Z", resourceId: "a", cleanup: true }],
    [{ id: "bad", at: "2026-10-14T23:00:00Z", reopen: "missing" }],
    [
      { id: "a", at: "2026-10-14T23:00:00Z", resourceId: "a" },
      { id: "b", at: "2026-10-14T22:00:00Z", cleanup: true },
    ],
  ])
    assert.throws(() => scenario.resolveInput({ steps }));
  assert.throws(
    () => scenario.resolveInput({ publisher: { maxChainMembersPerMessage: 32 } }),
    /16-member/,
  );
  const unsupported = await runBench({ scenario, measurement: { scope: "publisher" } });
  assert.equal(unsupported.success, false);
  assert.match(unsupported.checks[0].details, /full scope/);
});
