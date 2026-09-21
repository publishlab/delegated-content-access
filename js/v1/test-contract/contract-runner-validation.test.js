// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ASSERTED_GREEN_OUTER_PROOF } from "./issuer-core/issuer-core-negative-proof.test.js";
import { ASSERTED_ENDPOINT_NEGATIVE_PROOF } from "./issuer-endpoint/issuer-endpoint-negative-proof.test.js";

import {
  assertBindingSupportsTarget,
  assertContractManifestScriptCoverage,
  contractReporterArguments,
  declaredBaseTargets,
} from "./support/contract-runner-validation.js";
import { selectFixtureFiles } from "./support/fixture-manifest.js";

const target = {
  versions: ["1"],
  deliveryModes: ["direct"],
  contractProfiles: [],
  observations: [],
};

const CONTRACT_VALIDATOR =
  'node --experimental-test-isolation="${DCA_NODE_TEST_ISOLATION:-process}" --test --test-reporter=spec --test-reporter-destination=stdout --test-reporter=./test-tools/test-verdict-reporter.mjs --test-reporter-destination=stderr test-contract/contract-runner-validation.test.js';

void ASSERTED_GREEN_OUTER_PROOF;
void ASSERTED_ENDPOINT_NEGATIVE_PROOF;

test("selected target accepts a binding with additional capabilities", () => {
  assert.doesNotThrow(() =>
    assertBindingSupportsTarget("issuer-endpoint", target, {
      versions: ["1", "2"],
      deliveryModes: ["direct", "queued"],
      contractProfiles: ["optional-profile"],
      observations: ["trace"],
      driver: {},
    }),
  );
});

test("selected target rejects a missing required capability", () => {
  assert.throws(
    () =>
      assertBindingSupportsTarget("issuer-endpoint", target, {
        versions: ["1"],
        deliveryModes: [],
        contractProfiles: [],
        observations: [],
        driver: {},
      }),
    /does not support deliveryModes "direct"/,
  );
});

test("selected target rejects a binding that omits its required profile", () => {
  assert.throws(
    () =>
      assertBindingSupportsTarget(
        "issuer-endpoint",
        { ...target, contractProfiles: ["dca-v1-exact-period"] },
        {
          versions: ["1"],
          deliveryModes: ["direct"],
          contractProfiles: [],
          observations: [],
          driver: {},
        },
      ),
    /does not support contractProfiles "dca-v1-exact-period"/,
  );
});

test("the base selector runs declared base targets in manifest order", () => {
  const manifest = { endpoint: {}, core: {} };
  assert.deepEqual(
    declaredBaseTargets(manifest, {
      targets: { core: {}, extension: {}, endpoint: {} },
    }),
    ["endpoint", "core"],
  );
});

test("the base selector refuses a binding with no base target", () => {
  assert.throws(
    () => declaredBaseTargets({ endpoint: {}, core: {} }, { targets: { extension: {} } }),
    /declares none of the base targets/,
  );
  assert.throws(() => declaredBaseTargets({ endpoint: {}, core: {} }, {}), /declares no targets/);
});

test("contract target children keep TAP output and apply the shared verdict reporter", () => {
  assert.deepEqual(contractReporterArguments("/verdict.mjs"), [
    "--test-reporter=tap",
    "--test-reporter-destination=stdout",
    "--test-reporter=/verdict.mjs",
    "--test-reporter-destination=stderr",
  ]);
  assert.throws(() => contractReporterArguments(""), /needs a module path/);
});

test("fixture selection rejects paths that escape their package", () => {
  const root = mkdtempSync(join(tmpdir(), "dca-fixture-selector-"));
  const fixtureDir = join(root, "fixtures", "protocol-v1");
  mkdirSync(fixtureDir, { recursive: true });
  writeFileSync(join(root, "outside.json"), '{"vectorFormat":"1"}\n');
  writeFileSync(
    join(fixtureDir, "manifest.json"),
    JSON.stringify({
      schema: "dca-protocol-fixture-manifest/v1",
      protocol: "dca",
      version: "1",
      stability: "draft",
      files: [{ path: "../../outside.json", vectorFormat: "1", consumers: ["base-contract"] }],
    }),
  );
  try {
    assert.throws(
      () => selectFixtureFiles(root, ["fixtures/protocol-v1"], "base-contract", ["1"]),
      /unsafe path/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("fixture selection rejects duplicate packages and duplicate members", () => {
  const root = mkdtempSync(join(tmpdir(), "dca-fixture-selector-"));
  const fixtureDir = join(root, "fixtures", "protocol-v1");
  mkdirSync(fixtureDir, { recursive: true });
  writeFileSync(join(fixtureDir, "one.json"), '{"vectorFormat":"1"}\n');
  const manifest = {
    schema: "dca-protocol-fixture-manifest/v1",
    protocol: "dca",
    version: "1",
    stability: "draft",
    files: [{ path: "one.json", vectorFormat: "1", consumers: ["base-contract"] }],
  };
  writeFileSync(join(fixtureDir, "manifest.json"), JSON.stringify(manifest));
  try {
    assert.throws(
      () =>
        selectFixtureFiles(
          root,
          ["fixtures/protocol-v1", "fixtures/protocol-v1"],
          "base-contract",
          ["1"],
        ),
      /duplicate fixture package/,
    );
    manifest.files.push({ ...manifest.files[0] });
    writeFileSync(join(fixtureDir, "manifest.json"), JSON.stringify(manifest));
    assert.throws(
      () => selectFixtureFiles(root, ["fixtures/protocol-v1"], "base-contract", ["1"]),
      /repeats "one.json"/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the manifest runners and local binding commands are explicit", () => {
  const manifest = JSON.parse(
    readFileSync(new URL("./contract-targets.json", import.meta.url), "utf8"),
  );
  const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.doesNotThrow(() => assertContractManifestScriptCoverage(manifest, packageJson));
});

test("script coverage rejects baked-in bindings and masked local aggregates", () => {
  const manifest = { alpha: { runner: "test:contract:alpha" } };
  const scripts = {
    "test:contract": `${CONTRACT_VALIDATOR} && npm run test:contract:reference:base && npm run test:contract:fixture:issuer-endpoint`,
    "test:contract:base": "node test-contract/run-contract-target.js",
    "test:contract:reference:base":
      "npm run test:contract:base -- test-contract/bindings/reference-base-binding.js",
    "test:contract:fixture:issuer-endpoint":
      "npm run test:contract:issuer-endpoint -- test-contract/issuer-endpoint/bindings/fixture-issuer-endpoint-binding.js",
    "test:contract:alpha": "node test-contract/run-contract-target.js",
  };

  assert.throws(
    () =>
      assertContractManifestScriptCoverage(manifest, {
        scripts: {
          ...scripts,
          "test:contract:alpha": `${scripts["test:contract:alpha"]} binding.js`,
        },
      }),
    /is not a direct contract selector command/,
  );
  assert.throws(
    () =>
      assertContractManifestScriptCoverage(manifest, {
        scripts: {
          ...scripts,
          "test:contract:base": `${scripts["test:contract:base"]} binding.js`,
        },
      }),
    /is not the argument-only base selector/,
  );
  assert.throws(
    () =>
      assertContractManifestScriptCoverage(manifest, {
        scripts: { ...scripts, "test:contract": `${scripts["test:contract"]} || echo masked` },
      }),
    /is not the allowed validator, reference and fixture chain/,
  );
});

test("script coverage rejects a shared or missing target selector", () => {
  const scripts = {
    "test:contract": `${CONTRACT_VALIDATOR} && npm run test:contract:reference:base && npm run test:contract:fixture:issuer-endpoint`,
    "test:contract:base": "node test-contract/run-contract-target.js",
    "test:contract:reference:base":
      "npm run test:contract:base -- test-contract/bindings/reference-base-binding.js",
    "test:contract:fixture:issuer-endpoint":
      "npm run test:contract:issuer-endpoint -- test-contract/issuer-endpoint/bindings/fixture-issuer-endpoint-binding.js",
    "test:contract:alpha": "node test-contract/run-contract-target.js",
  };
  assert.throws(
    () =>
      assertContractManifestScriptCoverage(
        {
          alpha: { runner: "test:contract:alpha" },
          beta: { runner: "test:contract:alpha" },
        },
        { scripts },
      ),
    /runner "test:contract:alpha" is shared/,
  );
  assert.throws(
    () =>
      assertContractManifestScriptCoverage(
        {
          alpha: { runner: "test:contract:alpha" },
          beta: { runner: "test:contract:beta" },
        },
        { scripts },
      ),
    /beta: package\.json has no "test:contract:beta" script/,
  );
});
