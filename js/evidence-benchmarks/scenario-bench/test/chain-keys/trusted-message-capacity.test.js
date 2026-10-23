import test from "node:test";
import assert from "node:assert/strict";
import { runBench } from "../../runBench.js";
import { scenario } from "../../scenarios/chain-keys/groups.js";

test("100 groups with two source windows traverse real roles under explicit capacity", async () => {
  const input = {
    publisher: { groups: 100, maxChainMembersPerMessage: 200 },
    client: { routeProbes: false },
  };
  const report = await runBench({ scenario, input });
  assert.deepEqual(
    report.checks.filter((check) => !check.passed),
    [],
  );
  assert.equal(report.work.unlock, 1);
  const [issuer] = report.captures.dcaData.document.issuerData;
  assert.equal(issuer.issuerName, "issuer");
  const source = issuer.sealed;
  const distinct = (records, fields) =>
    new Set(records.map((record) => JSON.stringify(fields.map((field) => record[field])))).size;
  assert.equal(distinct(source.periodKeys, ["accessGroup"]), 100);
  assert.equal(source.chainKeys.length, 200);
  assert.equal(distinct(source.chainKeys, ["accessGroup", "cutoff"]), 200);
  const returned = report.captures.response.document.keys.chainKeys;
  assert.equal(distinct(returned, ["accessGroup"]), 100);
  assert.equal(report.cache.after.caches.chain.chainKeys, 100);
  const limits = report.cache["trusted-reference-limits"];
  assert.equal(limits.kind, "configuration");
  assert.equal(limits.exceedsCurrentSpecificationBound, true);
  assert.equal(
    report.checks.some((check) => check.name === "trusted-reference-limits"),
    false,
  );
  const floor = await runBench({
    scenario,
    input: { publisher: { groups: 100 }, client: { routeProbes: false } },
  });
  assert.equal(floor.checks.find((check) => check.name === "chain-member-bound").passed, false);
});
