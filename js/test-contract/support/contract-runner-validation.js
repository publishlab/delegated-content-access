// @ts-check

const CAPABILITY_FIELDS = ["versions", "deliveryModes", "contractProfiles", "observations"];
const SELECTOR = "node test-contract/run-contract-target.js";
const VALIDATOR =
  'node --experimental-test-isolation="${DCA_NODE_TEST_ISOLATION:-process}" --test --test-reporter=spec --test-reporter-destination=stdout --test-reporter=./test-tools/test-verdict-reporter.mjs --test-reporter-destination=stderr test-contract/contract-runner-validation.test.js';
const REFERENCE_BASE = "npm run test:contract:reference:base";
const FIXTURE_ENDPOINT = "npm run test:contract:fixture:issuer-endpoint";
const REFERENCE_HTML_WRITER = "npm run test:contract:reference:html-writer";
const REFERENCE_BROWSER_ORIGIN = "npm run test:contract:reference:issuer-browser-origin";

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
  if (
    scripts["test:contract:reference:issuer-browser-origin"] !==
    "npm run test:contract:issuer-browser-origin -- test-contract/issuer-browser-origin/bindings/reference-issuer-browser-origin-binding.js"
  ) {
    throw new Error(
      "test:contract:reference:issuer-browser-origin does not select the browser-Origin binding",
    );
  }
  if (
    scripts["test:contract:reference:html-writer"] !==
    "npm run test:contract:html-writer -- test-contract/html-writer/bindings/reference-html-writer-binding.js"
  ) {
    throw new Error("test:contract:reference:html-writer does not select the HTML-writer binding");
  }
  if (
    aggregate !==
    `${VALIDATOR} && ${REFERENCE_BASE} && ${FIXTURE_ENDPOINT} && ${REFERENCE_BROWSER_ORIGIN} && ${REFERENCE_HTML_WRITER}`
  ) {
    throw new Error(
      "test:contract is not the allowed validator, reference, fixture and selected-profile chain",
    );
  }
}

/**
 * Every manifest target needs an aggregate-selected binding, or a named owner
 * for its deliberate exclusion. A reference-base binding may cover only a
 * subset; this checks the union of the bindings the local aggregate runs.
 *
 * @param {Record<string, any>} manifest
 * @param {{ name: string, targets: Record<string, any> }[]} bindings
 * @param {Record<string, { owner: string, reason: string }>} exclusions
 */
export function assertContractTargetCoverage(manifest, bindings, exclusions = {}) {
  const covered = new Set();
  for (const binding of bindings) {
    if (typeof binding?.name !== "string" || !binding.name || !binding.targets) {
      throw new Error("contract coverage needs named binding target declarations");
    }
    for (const targetName of Object.keys(binding.targets)) {
      if (!Object.hasOwn(manifest, targetName)) {
        throw new Error(`${binding.name} declares unknown contract target ${targetName}`);
      }
      covered.add(targetName);
    }
  }
  for (const [targetName, exclusion] of Object.entries(exclusions)) {
    if (!Object.hasOwn(manifest, targetName) || covered.has(targetName)) {
      throw new Error(`${targetName}: contract coverage exclusion is unknown or already covered`);
    }
    if (!exclusion?.owner?.trim() || !exclusion?.reason?.trim()) {
      throw new Error(`${targetName}: contract coverage exclusion needs an owner and reason`);
    }
  }
  for (const targetName of Object.keys(manifest)) {
    if (!covered.has(targetName) && !Object.hasOwn(exclusions, targetName)) {
      throw new Error(`${targetName}: no aggregate-selected contract binding or owned exclusion`);
    }
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
 * Selected-profile targets require their own explicit selector even when the
 * same binding also declares base targets.
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
  const selected = Object.keys(manifest).filter(
    (targetName) =>
      manifest[targetName].selection !== "selected-profile" &&
      Object.hasOwn(declarations, targetName),
  );
  if (selected.length === 0) {
    throw new Error("base contract binding declares none of the base targets");
  }
  return selected;
}
