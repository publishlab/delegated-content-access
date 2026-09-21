// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const TEST_DIR = fileURLToPath(new URL("./", import.meta.url));
const REFERENCE_TEST_DIR = fileURLToPath(new URL("../test-reference/", import.meta.url));
const VECTOR_TEST_DIR = fileURLToPath(new URL("../test-vectors/", import.meta.url));
const EXTENSIONS_DIR = fileURLToPath(new URL("../extensions/", import.meta.url));
const inventory = JSON.parse(
  readFileSync(new URL("./test-inventory.json", import.meta.url), "utf8"),
);
const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
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
  "ports",
  "actors",
  "system",
  "environment",
  "layout",
]);
const EXPECTED_TEST_FILES = [
  "access-policy-actors.test.js",
  "access-policy-core.test.js",
  "access-policy.test.js",
  "actors.test.js",
  "bind.test.js",
  "binding-relabel-invariant.test.js",
  "browser-origin-boundary.test.js",
  "cache-eviction.test.js",
  "clock-skew.test.js",
  "content-key-resolver.test.js",
  "dca-data.test.js",
  "dca-request-builder.test.js",
  "endpoint-admission.test.js",
  "endpoint-hardening.test.js",
  "endpoint-port-hardening.test.js",
  "exact-period-key-supply.test.js",
  "invalid-curve-point.test.js",
  "issuer-ordinary-baseline.test.js",
  "issuer-processor.test.js",
  "issuer-walk.test.js",
  "jwt-proof.test.js",
  "key-attempt-runners.test.js",
  "leak-checks.test.js",
  "markup-delivery-reader.test.js",
  "markup-load.test.js",
  "markup-placement.test.js",
  "markup-writer.test.js",
  "multi-issuer.test.js",
  "object-delivery-reader.test.js",
  "open-content.test.js",
  "period-prefix.test.js",
  "publisher-registrations.test.js",
  "reference-exports.test.js",
  "resource-tamper.test.js",
  "rotation.test.js",
  "scenario.test.js",
  "seal-unseal-decrypt.test.js",
  "sealer-direct-only.test.js",
  "sealer-names.test.js",
  "storage-concurrency.test.js",
  "test-inventory.test.js",
  "test-reference/adapter-client/issuer-route-circuit-breaker.test.js",
  "test-reference/adapter-client/periodkeys.test.js",
  "test-reference/adapter-issuer/browser-unlock-http.test.js",
  "test-reference/core-publisher/publisher-config-validation.test.js",
  "test-reference/core-publisher/sealer-composition.test.js",
  "test-reference/core-publisher/sealer-options.test.js",
  "test-reference/core-publisher/sealer-origin.test.js",
  "test-reference/core-publisher/site-resource-plan.test.js",
  "test-reference/core-shared/aead.test.js",
  "test-reference/core-shared/binary-strings.test.js",
  "test-reference/core-shared/codec.test.js",
  "test-reference/core-shared/crypto-provider.test.js",
  "test-reference/core-shared/dca-request.test.js",
  "test-reference/core-shared/geometry-bounds.test.js",
  "test-reference/core-shared/keySealing.test.js",
  "test-reference/core-shared/names.test.js",
  "test-reference/core-shared/publisher-origin.test.js",
  "test-reference/core-shared/response-keys.test.js",
  "test-reference/core-shared/shared-primitive-misuse.test.js",
  "test-reference/integration-client/createBrowserClient.test.js",
  "time.test.js",
  "transport.test.js",
  "webcrypto-environment.test.js",
  "wire-lookup-client.test.js",
  "wire-lookup-endpoint.test.js",
  "wire-lookup-issuer.test.js",
  "wire-policy-adapter-client.test.js",
  "wire-policy-issuer-endpoint.test.js",
  "wire-policy.test.js",
  "world-provisioning.test.js",
];
const EXPECTED_TARGET_COUNTS = {
  actors: 8,
  "adapter-client": 5,
  "adapter-issuer": 1,
  "adapter-publisher": 1,
  "client-core": 5,
  "core-shared": 13,
  environment: 1,
  "integration-client": 1,
  "issuer-core": 7,
  "issuer-endpoint": 3,
  layout: 2,
  ports: 1,
  "publisher-core": 6,
  system: 17,
};
const EXPECTED_VECTOR_TEST_FILES = [
  "bind.test.js",
  "client-bound-vectors.test.js",
  "duplicateMembers.test.js",
  "issuer-endpoint-port.test.js",
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
    'node --experimental-test-isolation="${DCA_NODE_TEST_ISOLATION:-process}" --test "test/**/*.test.js" "test-reference/**/*.test.js" "extensions/*/test/**/*.test.js" "test-extensions/*.test.js" "test-profiles/*.test.js"',
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
    'node --experimental-test-isolation="${DCA_NODE_TEST_ISOLATION:-process}" --test "test/**/*.test.js" "test-reference/**/*.test.js" "extensions/*/test/**/*.test.js" "test-extensions/*.test.js" "test-profiles/*.test.js"',
  );
});
