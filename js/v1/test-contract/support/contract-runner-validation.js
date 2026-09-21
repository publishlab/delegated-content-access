// @ts-check

const CAPABILITY_FIELDS = ["versions", "deliveryModes", "contractProfiles", "observations"];
const SELECTOR = "node test-contract/run-contract-target.js";
const VALIDATOR =
  'node --experimental-test-isolation="${DCA_NODE_TEST_ISOLATION:-process}" --test --test-reporter=spec --test-reporter-destination=stdout --test-reporter=./test-tools/test-verdict-reporter.mjs --test-reporter-destination=stderr test-contract/contract-runner-validation.test.js';
const REFERENCE_BASE = "npm run test:contract:reference:base";
const FIXTURE_ENDPOINT = "npm run test:contract:fixture:issuer-endpoint";

/**
 * @param {string} reporter
 * @returns {string[]}
 */
export function contractReporterArguments(reporter) {
  if (typeof reporter !== "string" || reporter.length === 0) {
    throw new Error("the contract verdict reporter needs a module path");
  }
  return [
    "--test-reporter=tap",
    "--test-reporter-destination=stdout",
    `--test-reporter=${reporter}`,
    "--test-reporter-destination=stderr",
  ];
}

/**
 * The manifest enumerates contract targets explicitly. Its runner names must
 * therefore resolve to argument-only selector scripts. The local aggregate
 * selects its reference and fixture bindings under separate names.
 * This reads declarations only: it discovers neither targets nor bindings.
 *
 * @param {Record<string, any>} manifest
 * @param {{ scripts?: Record<string, string> }} packageJson
 */
export function assertContractManifestScriptCoverage(manifest, packageJson) {
  const scripts = packageJson.scripts ?? {};
  const aggregate = scripts["test:contract"];
  if (typeof aggregate !== "string") throw new Error("package.json has no test:contract script");

  /** @type {Set<string>} */
  const runners = new Set();
  for (const [targetName, target] of Object.entries(manifest)) {
    const runner = target?.runner;
    if (typeof runner !== "string" || runner.length === 0) {
      throw new Error(`${targetName}: contract target has no runner`);
    }
    if (runners.has(runner)) {
      throw new Error(
        `${targetName}: runner ${JSON.stringify(runner)} is shared by multiple contract targets`,
      );
    }
    runners.add(runner);

    const command = scripts[runner];
    if (typeof command !== "string") {
      throw new Error(`${targetName}: package.json has no ${JSON.stringify(runner)} script`);
    }
    if (command !== SELECTOR) {
      throw new Error(
        `${targetName}: ${JSON.stringify(runner)} is not a direct contract selector command`,
      );
    }
  }

  if (scripts["test:contract:base"] !== SELECTOR) {
    throw new Error("test:contract:base is not the argument-only base selector");
  }
  if (
    scripts["test:contract:reference:base"] !==
    "npm run test:contract:base -- test-contract/bindings/reference-base-binding.js"
  ) {
    throw new Error(
      "test:contract:reference:base does not select the checked-in reference binding",
    );
  }
  if (
    scripts["test:contract:fixture:issuer-endpoint"] !==
    "npm run test:contract:issuer-endpoint -- test-contract/issuer-endpoint/bindings/fixture-issuer-endpoint-binding.js"
  ) {
    throw new Error("test:contract:fixture:issuer-endpoint does not select the fixture binding");
  }
  if (aggregate !== `${VALIDATOR} && ${REFERENCE_BASE} && ${FIXTURE_ENDPOINT}`) {
    throw new Error("test:contract is not the allowed validator, reference and fixture chain");
  }
}

/**
 * A target requires a subset of a binding's declared capabilities. Bindings
 * may support additional versions, modes, profiles, or observations.
 *
 * @param {string} targetName
 * @param {any} target
 * @param {any} declared
 */
export function assertBindingSupportsTarget(targetName, target, declared) {
  if (!declared?.driver) throw new Error(`${targetName}: binding declares no driver`);
  for (const field of CAPABILITY_FIELDS) {
    for (const value of target[field] ?? []) {
      if (!declared[field]?.includes(value)) {
        throw new Error(
          `${targetName}: binding does not support ${field} ${JSON.stringify(value)}`,
        );
      }
    }
  }
}

/**
 * Select the closed base targets one explicitly supplied binding declares.
 * Other declarations are left for future extension-contract selectors.
 *
 * @param {Record<string, any>} manifest
 * @param {any} binding
 * @returns {string[]}
 */
export function declaredBaseTargets(manifest, binding) {
  const declarations = binding?.targets;
  if (declarations === null || typeof declarations !== "object") {
    throw new Error("base contract binding declares no targets");
  }
  const selected = Object.keys(manifest).filter((targetName) =>
    Object.hasOwn(declarations, targetName),
  );
  if (selected.length === 0) {
    throw new Error("base contract binding declares none of the base targets");
  }
  return selected;
}
