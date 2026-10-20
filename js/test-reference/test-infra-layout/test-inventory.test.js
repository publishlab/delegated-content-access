// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const TEST_DIR = fileURLToPath(new URL("../../test/", import.meta.url));
const REFERENCE_TEST_DIR = fileURLToPath(new URL("../", import.meta.url));
const VECTOR_TEST_DIR = fileURLToPath(new URL("../../test-vectors/", import.meta.url));
const EXTENSIONS_DIR = fileURLToPath(new URL("../../extensions/", import.meta.url));
const inventory = JSON.parse(
  readFileSync(new URL("../../test/test-inventory.json", import.meta.url), "utf8"),
);
const packageJson = JSON.parse(
  readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
);
const GROUPS = new Set([
  "issuer-contract",
  "optional-contract-profile",
  "reference-unit",
  "reference-system",
]);
const TARGETS = new Set([
  "core-shared",
  "publisher-core",
  "issuer-core",
  "issuer-endpoint",
  "client-core",
  "adapter-publisher",
  "adapter-client",
  "adapter-issuer",
  "integration-client",
  "integration-publisher",
  "integration-issuer",
  "ports",
  "actors",
  "system",
  "environment",
  "layout",
]);
const EXPECTED_TEST_FILES = [
  "access-policy.test.js",
  "browser-fetch-outcomes.test.js",
  "browser-origin-boundary.test.js",
  "leak-checks.test.js",
  "markup-load.test.js",
  "markup-placement.test.js",
  "multi-issuer.test.js",
  "resource-tamper.test.js",
  "rotation.test.js",
  "seal-unseal-decrypt.test.js",
  "test-reference/adapter-client/cache-eviction.test.js",
  "test-reference/adapter-client/fetch-transport.test.js",
  "test-reference/adapter-client/issuer-route-circuit-breaker.test.js",
  "test-reference/adapter-client/json-delivery-reader.test.js",
  "test-reference/adapter-client/markup-delivery-reader.test.js",
  "test-reference/adapter-client/periodkeys.test.js",
  "test-reference/adapter-client/route-attempts.test.js",
  "test-reference/adapter-client/storage-concurrency.test.js",
  "test-reference/adapter-issuer/browser-unlock-http.test.js",
  "test-reference/adapter-publisher/json-writer.test.js",
  "test-reference/adapter-publisher/markup-writer.test.js",
  "test-reference/core-client/authenticated-item-selection.test.js",
  "test-reference/core-client/content-key-resolver.test.js",
  "test-reference/core-client/content-key-wrap-attempt.test.js",
  "test-reference/core-client/dca-data.test.js",
  "test-reference/core-client/dca-request-builder.test.js",
  "test-reference/core-client/envelope-relay.test.js",
  "test-reference/core-client/open-content.test.js",
  "test-reference/core-client/resolver-operation-cleanup.test.js",
  "test-reference/core-client/response-report-admission.test.js",
  "test-reference/core-client/wire-lookup-client.test.js",
  "test-reference/core-client/wire-policy-adapter-client.test.js",
  "test-reference/core-issuer/endpoint-admission.test.js",
  "test-reference/core-issuer/envelope-algorithms.test.js",
  "test-reference/core-issuer/envelope-procedure-selection.test.js",
  "test-reference/core-issuer/invalid-curve-point.test.js",
  "test-reference/core-issuer/issuer-ordinary-baseline.test.js",
  "test-reference/core-issuer/issuer-processor.test.js",
  "test-reference/core-issuer/jwt-proof.test.js",
  "test-reference/core-issuer/period-label-grants.test.js",
  "test-reference/core-issuer/request-checks.test.js",
  "test-reference/core-issuer/wire-lookup-endpoint.test.js",
  "test-reference/core-issuer/wire-lookup-issuer.test.js",
  "test-reference/core-issuer/wire-policy-issuer-endpoint.test.js",
  "test-reference/core-publisher/envelope-selection.test.js",
  "test-reference/core-publisher/fixed-period-key-supply.test.js",
  "test-reference/core-publisher/issuer-request-budget.test.js",
  "test-reference/core-publisher/publisher-composition.test.js",
  "test-reference/core-publisher/publisher-config-validation.test.js",
  "test-reference/core-publisher/sealer-composition.test.js",
  "test-reference/core-publisher/sealer-content-key-only.test.js",
  "test-reference/core-publisher/sealer-factory.test.js",
  "test-reference/core-publisher/sealer-names.test.js",
  "test-reference/core-publisher/sealer-options.test.js",
  "test-reference/core-publisher/sealer-origin.test.js",
  "test-reference/core-publisher/site-resource-plan.test.js",
  "test-reference/core-shared--publisher-issuer/bind.test.js",
  "test-reference/core-shared--publisher-issuer/binding-relabel-invariant.test.js",
  "test-reference/core-shared/aead.test.js",
  "test-reference/core-shared/binary-strings.test.js",
  "test-reference/core-shared/codec.test.js",
  "test-reference/core-shared/content-aad.test.js",
  "test-reference/core-shared/crypto-provider.test.js",
  "test-reference/core-shared/dca-request.test.js",
  "test-reference/core-shared/geometry-bounds.test.js",
  "test-reference/core-shared/keySealing.test.js",
  "test-reference/core-shared/names.test.js",
  "test-reference/core-shared/publisher-origin.test.js",
  "test-reference/core-shared/response-keys.test.js",
  "test-reference/core-shared/shared-primitive-misuse.test.js",
  "test-reference/demo-actors/access-policy-actors.test.js",
  "test-reference/demo-actors/actors.test.js",
  "test-reference/demo-actors/clock-skew.test.js",
  "test-reference/demo-actors/endpoint-hardening.test.js",
  "test-reference/demo-actors/issuer-walk.test.js",
  "test-reference/demo-actors/transport.test.js",
  "test-reference/demo-browser/key-attempt-runners.test.js",
  "test-reference/demo-browser/scenario.test.js",
  "test-reference/demo-scenarios/world-provisioning.test.js",
  "test-reference/demo-support/access-policy-core.test.js",
  "test-reference/demo-support/object-delivery-reader.test.js",
  "test-reference/demo-support/publisher-registrations.test.js",
  "test-reference/demo-support/random-period-key-supply.test.js",
  "test-reference/integration-client/baseline-example.test.js",
  "test-reference/integration-client/client-lifecycle.test.js",
  "test-reference/integration-client/createBrowserClient.test.js",
  "test-reference/integration-client/decoder-contract.test.js",
  "test-reference/integration-client/derived-content-aad--async-capture.test.js",
  "test-reference/integration-client/derived-content-aad--bound-inputs.test.js",
  "test-reference/integration-client/derived-content-aad--format-mismatch.test.js",
  "test-reference/integration-client/derived-content-aad--signature-refresh.test.js",
  "test-reference/integration-client/route-walk-outcomes.test.js",
  "test-reference/integration-client/trusted-endpoint-routing.test.js",
  "test-reference/integration-issuer/createIssuerCore.test.js",
  "test-reference/integration-issuer/envelope-procedure-contribution.test.js",
  "test-reference/integration-issuer/publisher-signing-retirement.test.js",
  "test-reference/integration-ports/endpoint-port-hardening.test.js",
  "test-reference/integration-publisher/createPublisher.test.js",
  "test-reference/test-infra-bridge-surface/reference-exports.test.js",
  "test-reference/test-infra-environment/webcrypto-environment.test.js",
  "test-reference/test-infra-layout/test-inventory.test.js",
  "time.test.js",
  "wire-policy.test.js",
];
const EXPECTED_TARGET_COUNTS = {
  actors: 9,
  "adapter-client": 8,
  "adapter-issuer": 1,
  "adapter-publisher": 2,
  "client-core": 10,
  "core-shared": 14,
  environment: 2,
  "integration-client": 10,
  "integration-issuer": 3,
  "integration-publisher": 1,
  "issuer-core": 10,
  "issuer-endpoint": 3,
  layout: 2,
  ports: 1,
  "publisher-core": 11,
  system: 17,
};
const EXPECTED_VECTOR_TEST_FILES = [
  "baseline-issuer-admission.test.js",
  "bind.test.js",
  "chain-keys-geometry-admission.test.js",
  "chain-keys-prefix.test.js",
  "client-bound-vectors.test.js",
  "duplicateMembers.test.js",
  "ecdh-open.test.js",
  "issuer-endpoint-port.test.js",
  "period-key-composition.test.js",
  "sealer-factory-records.test.js",
  "vectors.test.js",
];

/**
 * @param {string} directory
 * @param {string} prefix
 * @returns {string[]}
 */
function ownedTestFiles(directory, prefix) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = `${prefix}${entry.name}`;
    if (entry.isDirectory()) return ownedTestFiles(`${directory}/${entry.name}`, `${path}/`);
    return entry.name.endsWith(".test.js") ? [path] : [];
  });
}

test("every reference test has one authority group and a target baseline", (t) => {
  const tests = [
    ...ownedTestFiles(TEST_DIR, ""),
    ...ownedTestFiles(REFERENCE_TEST_DIR, "test-reference/"),
  ].sort();
  assert.deepEqual(tests, EXPECTED_TEST_FILES, "the reference-suite baseline is unchanged");
  assert.deepEqual(Object.keys(inventory).sort(), EXPECTED_TEST_FILES);

  /** @type {Record<string, number>} */
  const targetCounts = Object.fromEntries([...TARGETS].sort().map((target) => [target, 0]));

  for (const [file, entry] of Object.entries(/** @type {Record<string, any>} */ (inventory))) {
    assert.ok(GROUPS.has(entry.group), `${file}: unknown group ${JSON.stringify(entry.group)}`);
    const hasTarget = Object.hasOwn(entry, "target");
    const hasTargets = Object.hasOwn(entry, "targets");
    assert.notEqual(hasTarget, hasTargets, `${file}: has exactly one of target or targets`);

    if (hasTarget) {
      assert.ok(
        TARGETS.has(entry.target),
        `${file}: unknown target ${JSON.stringify(entry.target)}`,
      );
      assert.ok(!Object.hasOwn(entry, "splitReason"), `${file}: one target has no splitReason`);
      targetCounts[entry.target] = (targetCounts[entry.target] ?? 0) + 1;
    } else {
      assert.ok(
        Array.isArray(entry.targets) && entry.targets.length > 0,
        `${file}: targets is a nonempty array`,
      );
      assert.equal(
        new Set(entry.targets).size,
        entry.targets.length,
        `${file}: targets are unique`,
      );
      for (const target of entry.targets) {
        assert.ok(TARGETS.has(target), `${file}: unknown target ${JSON.stringify(target)}`);
        targetCounts[target] = (targetCounts[target] ?? 0) + 1;
      }
      assert.equal(typeof entry.splitReason, "string", `${file}: mixed targets need splitReason`);
      assert.ok(entry.splitReason.length > 0, `${file}: splitReason is empty`);
    }
    if (entry.group.startsWith("reference-")) {
      assert.equal(typeof entry.reason, "string", `${file}: reference-only needs a reason`);
      assert.ok(entry.reason.length > 0, `${file}: reference-only reason is empty`);
    }
  }

  const baseline = Object.fromEntries(
    Object.entries(targetCounts).sort(([a], [b]) => a.localeCompare(b)),
  );
  assert.deepEqual(baseline, EXPECTED_TARGET_COUNTS, "the reference target baseline is unchanged");
  t.diagnostic(`target baseline (${tests.length} reference tests): ${JSON.stringify(baseline)}`);
});

test("recorded-vector tests have one explicit directory-owned tier", () => {
  const files = readdirSync(VECTOR_TEST_DIR)
    .filter((file) => file.endsWith(".test.js"))
    .sort();
  assert.deepEqual(files, EXPECTED_VECTOR_TEST_FILES);
  for (const file of files) {
    assert.equal(
      Object.hasOwn(inventory, `test-vectors/${file}`),
      false,
      `${file}: vector tests do not enter the base reference inventory`,
    );
  }
  assert.equal(
    packageJson.scripts["test:reference:vectors"],
    'node --experimental-test-isolation="${DCA_NODE_TEST_ISOLATION:-process}" --test "test-vectors/*.test.js"',
  );
  assert.equal(
    packageJson.scripts["test:reference:public"],
    'node --experimental-test-isolation="${DCA_NODE_TEST_ISOLATION:-process}" --test --test-reporter=tap "test/**/*.test.js" "test-reference/**/*.test.js" "extensions/*/test/**/*.test.js" "test-extensions/*.test.js" "test-profiles/*.test.js"',
  );
});

test("every populated reference target has one inventory-backed runner command", () => {
  /** @type {Record<string, number>} */
  const targetCounts = Object.fromEntries([...TARGETS].map((target) => [target, 0]));
  for (const entry of Object.values(/** @type {Record<string, any>} */ (inventory))) {
    const entryTargets = Object.hasOwn(entry, "target") ? [entry.target] : entry.targets;
    for (const target of entryTargets) targetCounts[target] += 1;
  }

  for (const target of TARGETS) {
    const runner = `test:reference:${target}`;
    if (targetCounts[target] === 0) {
      assert.equal(
        packageJson.scripts[runner],
        undefined,
        `${target}: an empty target has no runner command`,
      );
      continue;
    }
    assert.equal(
      packageJson.scripts[runner],
      `node test-reference/run-reference-target.js ${target}`,
      `${target}: runner selects precisely this inventory target`,
    );
  }
  assert.equal(packageJson.scripts["test:all"], "npm run test && npm run test:experiments");
  assert.equal(
    packageJson.scripts["test:experiments"],
    'node --test "experiments/*/test/*.test.js"',
  );
  assert.equal(
    packageJson.scripts["test:reference:core-shared:extracted"],
    'node --test "test-reference/core-shared/*.test.js"',
  );
});

test("base and extension lanes recursively run every owned test directory", () => {
  assert.equal(
    packageJson.scripts["test:reference:base"],
    'node --experimental-test-isolation="${DCA_NODE_TEST_ISOLATION:-process}" --test "test/**/*.test.js" "test-reference/**/*.test.js"',
  );

  const extensions = readdirSync(EXTENSIONS_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  for (const name of extensions) {
    assert.equal(
      packageJson.scripts[`test:reference:extension:${name}`],
      `node --experimental-test-isolation="\${DCA_NODE_TEST_ISOLATION:-process}" --test "extensions/${name}/test/**/*.test.js"`,
      `${name}: recursively inclusive extension test lane`,
    );
  }
  assert.equal(
    packageJson.scripts["test:reference:public"],
    'node --experimental-test-isolation="${DCA_NODE_TEST_ISOLATION:-process}" --test --test-reporter=tap "test/**/*.test.js" "test-reference/**/*.test.js" "extensions/*/test/**/*.test.js" "test-extensions/*.test.js" "test-profiles/*.test.js"',
  );
});
