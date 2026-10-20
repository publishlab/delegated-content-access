// @ts-check

import { readdirSync } from "node:fs";
import { resolve } from "node:path";
import { ENVELOPE_TAGS } from "./envelope-evidence.js";
import { resolveProfiles, validateProfileCatalogue } from "../tools/profileCatalogue.js";

/** @typedef {Record<string, string | boolean>} TypedSelection */
/** @typedef {{id: string, profile: string, role: string, status: 'supported'|'unsupported', duties: string[], alternatives: Record<string, Array<string|boolean>>, compatibleSelections: TypedSelection[]}} Support */
/** @typedef {{id: string, path: string, profile: string|null, associatedDuties: string[], status: 'claim'|'unmapped'|'experiment'}} RecordedPackage */
/** @typedef {{test: {file: string, name: string}, roles: string[], duties: string[]}} EvidenceRef */
/** @typedef {{text: string, category: string, status: 'not-rechecked'}} LegacyGap */
/** @typedef {{id: string, requestedProfiles: string[], roles: string[], selections: Record<string, TypedSelection>, requiredDuties: string[], unresolvedApplicability: string[], recordedPackages: string[], legacy: {id: string, declaredDuties: string[], algorithms: string[], gaps: LegacyGap[]}, compositionEvidence: {test: {file: string, name: string}, roles: string[], requestedProfiles: string[]}, evidence: EvidenceRef[]}} Scenario */
/** @typedef {{schema: string, catalogue: string, subject: {id: string, roles: string[]}, support: Support[], deploymentEnablement: null, scenarios: Scenario[], recordedPackages: RecordedPackage[]}} ScopedIndex */
/** @typedef {{file: string, name: string, outcome: 'passed'|'failed'|'skipped'|'todo', duties: string[]}} ObservedTest */
/** @typedef {{type: string, data: {name: string, file?: string, skip?: unknown, todo?: unknown, tags?: unknown, details?: {type?: string}}}} ClaimTestEvent */

/** Each fixture package that a dedicated recorder owns, with that recorder. */
const FIXTURE_RECORDERS = new Map([
  [
    "verification/fixtures/v1/profiles/dca-profile-chain-keys/geometry-admission",
    "js/tools/record-chain-keys-geometry-admission.js",
  ],
  [
    "verification/fixtures/v1/profiles/dca-profile-chain-keys/issuer-client-prefix",
    "js/tools/record-chain-keys-prefix.js",
  ],
  [
    "verification/fixtures/v1/profiles/dca-profile-period-keys/issuer-client-composition",
    "js/tools/record-period-key-composition.js",
  ],
]);
const FIXTURE_GENERATOR_PACKAGES = new Set([
  "verification/fixtures/v1/baseline/issuer-admission",
  "verification/fixtures/v1/profiles/dca-profile-period-keys/issuer-admission",
  "verification/fixtures/v1/reference/protocol-regressions",
]);

/** @param {unknown} value @param {string} label */
function object(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError(`${label} must be an object`);
  return /** @type {Record<string, unknown>} */ (value);
}

/** @param {unknown} value @param {string} label */
function text(value, label) {
  if (typeof value !== "string" || !/^[\x21-\x7e]+$/.test(value))
    throw new TypeError(`${label} must be a nonempty visible-ASCII string`);
  return value;
}

/** @param {unknown} value @param {string} label */
function labelText(value, label) {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0)
    throw new TypeError(`${label} must be nonempty text`);
  return value;
}

/** @param {unknown} value @param {string} label */
function names(value, label) {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
  const result = value.map((item, index) => text(item, `${label}[${index}]`));
  if (new Set(result).size !== result.length) throw new Error(`${label} has duplicate values`);
  return result;
}

/** @param {unknown} value @param {string} label */
function records(value, label) {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
  const result = value.map((item, index) => object(item, `${label}[${index}]`));
  const ids = result.map((item, index) => text(item.id, `${label}[${index}].id`));
  if (new Set(ids).size !== ids.length) throw new Error(`${label} has duplicate IDs`);
  return result;
}

/**
 * Select the owning recorded-package checker. A fixture must never be passed
 * to the vector checksum command with its prefix silently sliced away.
 * @param {string} packagePath
 * @returns {{executable: 'sh' | 'node', args: string[]}}
 */
export function recordedPackageCheckCommand(packagePath) {
  const normalizedPath = packagePath.replace(/\/$/, "");
  const recorder = FIXTURE_RECORDERS.get(normalizedPath);
  if (recorder !== undefined) return { executable: "node", args: [recorder, "--check"] };
  if (FIXTURE_GENERATOR_PACKAGES.has(normalizedPath))
    return { executable: "node", args: ["js/tools/make-vectors.js", "--check"] };
  const vectorPrefix = "verification/vectors/";
  const relative = packagePath.slice(vectorPrefix.length).replace(/\/$/, "");
  if (
    packagePath.startsWith(vectorPrefix) &&
    /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(relative)
  )
    return { executable: "sh", args: ["verification/vectors/check-sums.sh", relative] };
  throw new Error(`no recorded package checker for ${packagePath}`);
}

/** @param {string} directory @returns {string[]} */
export function discoverFixturePackageRoots(directory) {
  /** @param {string} parent @param {string} prefix @param {boolean} root @returns {string[]} */
  function walk(parent, prefix, root) {
    const entries = readdirSync(parent, { withFileTypes: true });
    const children = entries.filter((entry) => entry.isDirectory());
    if (children.length === 0 && !root) return [prefix];
    const undeclared = entries
      .filter((entry) => !entry.isDirectory() && entry.name !== "README.md")
      .map((entry) => entry.name)
      .sort();
    if (undeclared.length)
      throw new Error(`fixture container ${prefix} holds undeclared ${undeclared.join(", ")}`);
    return children.flatMap((entry) =>
      walk(resolve(parent, entry.name), `${prefix}/${entry.name}`, false),
    );
  }
  return walk(directory, "fixtures", true);
}

/**
 * Require the manifest, exact-depth discovered vector directories and evidence
 * index to name the same packages. Integrity checks never confer role credit.
 * @param {string[]} listedVectors
 * @param {string[]} actualVectors
 * @param {string[]} recordedIds
 * @param {string[]} actualFixtures
 */
export function validateRecordedPackageInventory(
  listedVectors,
  actualVectors,
  recordedIds,
  actualFixtures,
) {
  const listed = new Set(listedVectors.map((path) => `vectors/${path}`));
  const indexed = new Set(recordedIds);
  const expected = new Set([...listed, ...actualFixtures]);
  const vectorMismatch = [...new Set([...listed, ...actualVectors])].filter(
    (id) => !listed.has(id) || !actualVectors.includes(id),
  );
  const indexMismatch = [...new Set([...expected, ...indexed])].filter(
    (id) => !expected.has(id) || !indexed.has(id),
  );
  if (vectorMismatch.length || indexMismatch.length)
    throw new Error(
      `recorded package inventory mismatch: ${[...vectorMismatch, ...indexMismatch].join(", ")}`,
    );
}

/** @param {string[]} admittedFiles @param {string[]} evidenceFiles @param {'evidence'|'all'} scope */
export function selectEvidenceTestFiles(admittedFiles, evidenceFiles, scope) {
  if (scope !== "evidence" && scope !== "all") throw new Error(`unknown evidence scope ${scope}`);
  const admitted = new Set(admittedFiles);
  for (const file of evidenceFiles)
    if (!admitted.has(file)) throw new Error(`evidence file is outside test:unit: ${file}`);
  const selected = scope === "all" ? [...admitted].sort() : [...new Set(evidenceFiles)].sort();
  return {
    selected,
    admittedFiles: admitted.size,
    unobservedFiles: [...admitted].filter((file) => !selected.includes(file)).sort(),
  };
}

/** @param {Array<{type: string, data: {file?: string}}>} events */
export function completedTestFiles(events) {
  return new Set(
    events
      .filter((event) => event.type === "test:summary" && event.data.file)
      .map((event) => event.data.file),
  );
}

/** @param {Array<{type: string, data: {file?: string, success?: boolean}}>} events */
export function failedTestFiles(events) {
  return new Set(
    events
      .filter(
        (event) => event.type === "test:summary" && event.data.file && event.data.success === false,
      )
      .map((event) => event.data.file),
  );
}

/** @param {unknown} value @param {string} label */
function stringList(value, label) {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
  return value.map((entry, index) => {
    if (typeof entry !== "string" || entry.trim() !== entry || entry.length === 0)
      throw new TypeError(`${label}[${index}] must be nonempty text`);
    return entry;
  });
}

/** @param {unknown} value @param {string} label */
function selectionObject(value, label) {
  const selection = object(value, label);
  /** @type {TypedSelection} */
  const copy = {};
  for (const [key, item] of Object.entries(selection)) {
    if (typeof item !== "string" && typeof item !== "boolean")
      throw new TypeError(`${label}.${key} must be a string or boolean`);
    copy[key] = item;
  }
  return copy;
}

/**
 * Validate typed selections against the catalogue's declared choices and
 * conditional constraints. No selection is inferred from a passing test.
 * @param {unknown} selectionsInput
 * @param {string[]} requestedProfiles
 * @param {string[]} resolvedProfiles
 * @param {unknown} catalogueInput
 * @returns {Record<string, TypedSelection>}
 */
export function validateSelections(
  selectionsInput,
  requestedProfiles,
  resolvedProfiles,
  catalogueInput,
) {
  const catalogue = validateProfileCatalogue(catalogueInput);
  const selections = object(selectionsInput, "scenario.selections");
  const byProfile = new Map((catalogue.selections ?? []).map((entry) => [entry.profile, entry]));
  const resolved = new Set(resolvedProfiles);
  for (const profile of Object.keys(selections))
    if (!resolved.has(profile)) throw new Error(`selection for unrequested profile ${profile}`);
  for (const profile of requestedProfiles)
    if (
      profile !== catalogue.baseline &&
      byProfile.has(profile) &&
      !Object.hasOwn(selections, profile)
    )
      throw new Error(`scenario is missing selection for ${profile}`);
  for (const profile of Object.keys(selections)) {
    if (!resolved.has(profile)) continue;
    const specification = byProfile.get(profile);
    if (!specification) continue;
    const chosen = selectionObject(selections[profile], `scenario.selections.${profile}`);
    const choiceSpec = object(specification.choices, `catalogue selection ${profile}.choices`);
    const choiceKeys = Object.keys(choiceSpec).sort();
    if (Object.keys(chosen).sort().join("\0") !== choiceKeys.join("\0"))
      throw new Error(`selection for ${profile} must name exactly ${choiceKeys.join(", ")}`);
    for (const [key, allowed] of Object.entries(choiceSpec)) {
      const actual = chosen[key];
      if (Array.isArray(allowed)) {
        if (!allowed.includes(actual)) throw new Error(`invalid ${profile}.${key}: ${actual}`);
      } else if (allowed === "boolean") {
        if (typeof actual !== "boolean") throw new Error(`${profile}.${key} must be boolean`);
      } else if (typeof actual !== "string") {
        throw new Error(`${profile}.${key} must be a string`);
      }
    }
    for (const requirement of specification.requires ?? []) {
      const condition = requirement.if ?? {};
      if (Object.entries(condition).every(([key, value]) => chosen[key] === value)) {
        const consequence = requirement.then ?? {};
        for (const [key, value] of Object.entries(consequence))
          if (chosen[key] !== value)
            throw new Error(`invalid combination for ${profile}: ${key} must be ${value}`);
      }
    }
    for (const requirement of specification.requiresProfiles ?? []) {
      const condition = requirement.if ?? {};
      if (Object.entries(condition).every(([key, value]) => chosen[key] === value))
        for (const requiredProfile of requirement.profiles ?? [])
          if (!resolved.has(requiredProfile))
            throw new Error(`selection for ${profile} requires profile ${requiredProfile}`);
    }
  }
  return /** @type {Record<string, TypedSelection>} */ (selections);
}

/**
 * Validate the language-neutral scoped evidence index.
 * @param {unknown} input
 * @param {unknown} catalogueInput
 */
export function validateClaimIndex(input, catalogueInput) {
  const catalogue = validateProfileCatalogue(catalogueInput);
  const index = object(input, "evidence index");
  if (index.schema !== "dca-scoped-profile-evidence/v1")
    throw new Error("unknown scoped-evidence schema");
  if (index.catalogue !== "verification/profile-catalogue/v1.json")
    throw new Error("unknown evidence catalogue");
  if (index.deploymentEnablement !== null)
    throw new Error("deploymentEnablement must be null until explicitly asserted");
  const subject = object(index.subject, "subject");
  text(subject.id, "subject.id");
  const subjectRoles = names(subject.roles, "subject.roles");
  if (subjectRoles.length === 0) throw new Error("subject.roles must name at least one role");
  for (const role of subjectRoles)
    if (!["publisher", "issuer", "client"].includes(role)) throw new Error(`unknown role ${role}`);
  const profileMap = new Map(catalogue.profiles.map((profile) => [profile.id, profile]));
  const dutyMap = new Map((catalogue.duties ?? []).map((duty) => [duty.id, duty]));
  const supports = /** @type {Support[]} */ (records(index.support, "support"));
  for (const support of supports) {
    const profile = text(support.profile, "support.profile");
    if (!profileMap.has(profile)) throw new Error(`unknown support profile ${profile}`);
    const role = text(support.role, "support.role");
    if (!subjectRoles.includes(role))
      throw new Error(`support role ${role} is outside subject roles`);
    if (!["supported", "unsupported"].includes(/** @type {string} */ (support.status)))
      throw new Error(`support ${support.id} has unknown status`);
    for (const dutyId of names(support.duties, `support ${support.id}.duties`)) {
      const duty = dutyMap.get(dutyId);
      if (!duty || duty.profile !== profile || duty.role !== role)
        throw new Error(`support ${support.id} has duty outside its profile/role`);
    }
    const declaredDutySet = new Set(support.duties);
    const requiredSupportDuties = (catalogue.duties ?? [])
      .filter((duty) => duty.profile === profile && duty.role === role)
      .map((duty) => duty.id);
    if (support.status === "supported")
      for (const dutyId of requiredSupportDuties)
        if (!declaredDutySet.has(dutyId))
          throw new Error(`support ${support.id} omits catalogue duty ${dutyId}`);
    const alternatives = /** @type {Record<string, Array<string|boolean>>} */ (
      object(support.alternatives, `support ${support.id}.alternatives`)
    );
    const selectionSpec = new Map(
      (catalogue.selections ?? []).map((entry) => [entry.profile, entry]),
    );
    const choices = selectionSpec.get(profile)?.choices ?? {};
    for (const [key, values] of Object.entries(alternatives)) {
      if (!Array.isArray(values))
        throw new TypeError(`support ${support.id}.alternatives.${key} must be an array`);
      const allowed = key === "envelopeAlgorithm" ? null : choices[key];
      if (key !== "envelopeAlgorithm" && allowed === undefined)
        throw new Error(`support ${support.id} names unknown selection dimension ${key}`);
      for (const value of values) {
        if (typeof value !== "string" && typeof value !== "boolean")
          throw new TypeError(`support ${support.id}.alternatives.${key} has an invalid value`);
        if (Array.isArray(allowed) && (typeof value !== "string" || !allowed.includes(value)))
          throw new Error(
            `support ${support.id}.alternatives.${key} has undeclared value ${value}`,
          );
        if (allowed === "boolean" && typeof value !== "boolean")
          throw new TypeError(`support ${support.id}.alternatives.${key} must use booleans`);
      }
    }
    if (
      support.status === "supported" &&
      profile === catalogue.baseline &&
      ["publisher", "issuer"].includes(role) &&
      !(alternatives.envelopeAlgorithm ?? []).includes("ecdh-p256")
    )
      throw new Error(`support ${support.id} omits mandatory baseline ecdh-p256 support`);
    if (!Array.isArray(support.compatibleSelections))
      throw new TypeError(`support ${support.id}.compatibleSelections must be an array`);
    const combinationKeys = Object.keys(alternatives)
      .filter((key) => key !== "envelopeAlgorithm")
      .sort();
    for (const [index, selectionInput] of support.compatibleSelections.entries()) {
      const selection = selectionObject(
        selectionInput,
        `support ${support.id}.compatibleSelections[${index}]`,
      );
      if (Object.keys(selection).sort().join("\0") !== combinationKeys.join("\0"))
        throw new Error(
          `support ${support.id} compatibility entry must name exactly ${combinationKeys.join(", ")}`,
        );
      for (const [key, value] of Object.entries(selection)) {
        const allowed = choices[key];
        if (!alternatives[key].includes(value))
          throw new Error(
            `support ${support.id} compatibility value ${key}=${value} is not declared`,
          );
        if (Array.isArray(allowed) && (typeof value !== "string" || !allowed.includes(value)))
          throw new Error(`support ${support.id} has undeclared compatible value ${value}`);
        if (allowed === "boolean" && typeof value !== "boolean")
          throw new TypeError(`support ${support.id} compatible ${key} must be boolean`);
      }
    }
  }
  const packageEntries = /** @type {RecordedPackage[]} */ (
    records(index.recordedPackages, "recordedPackages")
  );
  const packageMap = new Map();
  for (const entry of packageEntries) {
    const id = text(entry.id, "recorded package id");
    const path = text(entry.path, `package ${id}.path`);
    if (/^(vectors|fixtures)\//.test(id) && path.replace(/\/$/, "") !== `verification/${id}`)
      throw new Error(`package ${id} path does not match its ID`);
    if (!profileMap.has(/** @type {string} */ (entry.profile)) && entry.profile !== null)
      throw new Error(`package ${id} has unknown profile`);
    if (!["claim", "unmapped", "experiment"].includes(/** @type {string} */ (entry.status)))
      throw new Error(`package ${id} has unknown status`);
    const associated = names(entry.associatedDuties, `package ${id}.associatedDuties`);
    for (const dutyId of associated)
      if (!dutyMap.has(dutyId)) throw new Error(`unknown duty ${dutyId}`);
    packageMap.set(id, entry);
  }
  const scenarios = /** @type {Scenario[]} */ (records(index.scenarios, "scenarios"));
  const evidenceKeys = new Set();
  const scenarioIds = new Set(scenarios.map((scenario) => scenario.id));
  if (scenarioIds.size !== scenarios.length) throw new Error("scenarios have duplicate IDs");
  const testRoles = new Set(["publisher", "issuer", "client"]);
  for (const scenario of scenarios) {
    const id = /** @type {string} */ (scenario.id);
    const requested = names(scenario.requestedProfiles, `scenario ${id}.requestedProfiles`);
    const resolution = resolveProfiles(catalogue, requested);
    if (resolution.requestedProfiles.length !== requested.length)
      throw new Error(`scenario ${id} repeats a profile dependency`);
    validateSelections(
      scenario.selections,
      resolution.requestedProfiles,
      resolution.resolvedProfiles,
      catalogue,
    );
    const roles = names(scenario.roles, `scenario ${id}.roles`);
    if (roles.length === 0) throw new Error(`scenario ${id}.roles must name at least one role`);
    for (const role of roles)
      if (!subjectRoles.includes(role)) throw new Error(`unknown scenario role ${role}`);
    for (const packageId of names(scenario.recordedPackages, `scenario ${id}.recordedPackages`))
      if (!packageMap.has(packageId))
        throw new Error(`scenario ${id} has unknown package ${packageId}`);
    const legacy = object(scenario.legacy, `scenario ${id}.legacy`);
    text(legacy.id, `scenario ${id}.legacy.id`);
    const legacyDuties = names(legacy.declaredDuties, `scenario ${id}.legacy.declaredDuties`);
    for (const dutyId of legacyDuties)
      if (!dutyMap.has(dutyId))
        throw new Error(`scenario ${id} legacy declaration has unknown duty ${dutyId}`);
    stringList(legacy.algorithms, `scenario ${id}.legacy.algorithms`);
    if (!Array.isArray(legacy.gaps))
      throw new TypeError(`scenario ${id}.legacy.gaps must be an array`);
    for (const [gapIndex, rawGap] of legacy.gaps.entries()) {
      const gap = object(rawGap, `scenario ${id}.legacy.gaps[${gapIndex}]`);
      labelText(gap.text, `scenario ${id}.legacy.gaps[${gapIndex}].text`);
      if (!/^[a-z][a-z0-9-]*$/.test(/** @type {string} */ (gap.category)))
        throw new TypeError(
          `scenario ${id}.legacy.gaps[${gapIndex}].category must be a kebab-case category`,
        );
      if (gap.status !== "not-rechecked")
        throw new Error(`scenario ${id}.legacy.gaps[${gapIndex}] must remain not-rechecked`);
    }
    names(legacy.algorithms, `scenario ${id}.legacy.algorithms`);
    const unresolved = names(
      scenario.unresolvedApplicability,
      `scenario ${id}.unresolvedApplicability`,
    );
    for (const dutyId of unresolved)
      if (!dutyMap.has(dutyId)) throw new Error(`unknown duty ${dutyId}`);
    if (!Array.isArray(scenario.evidence))
      throw new TypeError(`scenario ${id}.evidence must be an array`);
    for (const [evidenceIndex, rawEvidence] of scenario.evidence.entries()) {
      const evidence = object(rawEvidence, `scenario ${id}.evidence[${evidenceIndex}]`);
      const test = object(evidence.test, `scenario ${id}.evidence[${evidenceIndex}].test`);
      const file = text(test.file, `scenario ${id}.evidence.test.file`);
      const name = labelText(test.name, `scenario ${id}.evidence.test.name`);
      const key = `${id}\0${file}\0${name}`;
      if (evidenceKeys.has(key)) throw new Error(`scenario ${id} repeats evidence test ${name}`);
      evidenceKeys.add(key);
      const evidenceRoles = names(evidence.roles, `scenario ${id}.evidence.roles`);
      if (evidenceRoles.some((role) => !testRoles.has(role) || !roles.includes(role)))
        throw new Error(`scenario ${id} evidence has role outside its subject scope`);
      for (const dutyId of names(evidence.duties, `scenario ${id}.evidence.duties`)) {
        const duty = dutyMap.get(dutyId);
        if (
          !duty ||
          !evidenceRoles.includes(duty.role) ||
          !resolution.resolvedProfiles.includes(duty.profile)
        )
          throw new Error(
            `scenario ${id} evidence duty ${dutyId} is outside its role/profile scope`,
          );
      }
    }
    const composition = object(scenario.compositionEvidence, `scenario ${id}.compositionEvidence`);
    const compositionTest = object(composition.test, `scenario ${id}.compositionEvidence.test`);
    const compositionFile = text(
      compositionTest.file,
      `scenario ${id}.compositionEvidence.test.file`,
    );
    const compositionName = labelText(
      compositionTest.name,
      `scenario ${id}.compositionEvidence.test.name`,
    );
    if (
      !scenario.evidence.some(
        (entry) => entry.test.file === compositionFile && entry.test.name === compositionName,
      )
    )
      throw new Error(`scenario ${id} composition test must also have a scoped evidence record`);
    if (
      names(composition.roles, `scenario ${id}.compositionEvidence.roles`).sort().join("\0") !==
      [...roles].sort().join("\0")
    )
      throw new Error(`scenario ${id} composition evidence must name its complete role scope`);
    if (
      names(composition.requestedProfiles, `scenario ${id}.compositionEvidence.requestedProfiles`)
        .sort()
        .join("\0") !== [...resolution.requestedProfiles].sort().join("\0")
    )
      throw new Error(
        `scenario ${id} composition evidence must name its concrete profile combination`,
      );
    for (const dutyId of names(scenario.requiredDuties, `scenario ${id}.requiredDuties`)) {
      const duty = dutyMap.get(dutyId);
      if (
        !duty ||
        !roles.includes(duty.role) ||
        !resolution.resolvedProfiles.includes(duty.profile)
      )
        throw new Error(`scenario ${id} required duty ${dutyId} is outside its closure`);
    }
    const mandatoryBaseline = (catalogue.duties ?? [])
      .filter((duty) => duty.profile === catalogue.baseline && roles.includes(duty.role))
      .map((duty) => duty.id);
    for (const dutyId of mandatoryBaseline)
      if (!scenario.requiredDuties.includes(dutyId))
        throw new Error(`scenario ${id} omits mandatory baseline duty ${dutyId}`);
    const accountedDuties = new Set([
      ...scenario.requiredDuties,
      ...scenario.unresolvedApplicability,
    ]);
    for (const duty of catalogue.duties ?? [])
      if (
        resolution.resolvedProfiles.includes(duty.profile) &&
        roles.includes(duty.role) &&
        !accountedDuties.has(duty.id)
      )
        throw new Error(`scenario ${id} leaves catalogue duty unclassified: ${duty.id}`);
    for (const dutyId of unresolved)
      if (scenario.requiredDuties.includes(dutyId))
        throw new Error(`scenario ${id} cannot require unresolved duty ${dutyId}`);
  }
  return /** @type {ScopedIndex} */ (index);
}

/**
 * Resolve evidence for one scenario. Test identity and scenario must both
 * match; package integrity results are returned separately and never credited.
 * @param {unknown} input
 * @param {unknown} catalogueInput
 * @param {string} scenarioId
 * @param {ObservedTest[]} observed
 * @param {Array<{id: string, status: 'passed'|'failed'|'not-checked'}>} [packageChecks]
 */
export function evaluateScenario(input, catalogueInput, scenarioId, observed, packageChecks = []) {
  const index = validateClaimIndex(input, catalogueInput);
  const scenario = index.scenarios.find((entry) => entry.id === scenarioId);
  if (!scenario) throw new Error(`unknown scenario ${scenarioId}`);
  const expectedKeys = new Set([
    ...scenario.evidence.map((entry) => `${entry.test.file}\0${entry.test.name}`),
    `${scenario.compositionEvidence.test.file}\0${scenario.compositionEvidence.test.name}`,
  ]);
  const byIdentity = new Map();
  for (const entry of observed) {
    const key = `${entry.file}\0${entry.name}`;
    if (!expectedKeys.has(key)) continue;
    if (byIdentity.has(key))
      throw new Error(`ambiguous observed test identity ${entry.file}: ${entry.name}`);
    byIdentity.set(key, entry);
  }
  const required = scenario.requiredDuties;
  const evidenceResults = scenario.evidence.map((evidence) => {
    const result = byIdentity.get(`${evidence.test.file}\0${evidence.test.name}`);
    const duties = result ? evidence.duties.filter((duty) => result.duties.includes(duty)) : [];
    return {
      test: evidence.test,
      status: !result ? "missing" : result.outcome,
      creditedDuties: result?.outcome === "passed" ? duties : [],
      observedDuties: duties,
    };
  });
  const compositionEvent = byIdentity.get(
    `${scenario.compositionEvidence.test.file}\0${scenario.compositionEvidence.test.name}`,
  );
  const compositionStatus = compositionEvent?.outcome ?? "missing";
  const passingCredit = new Set(evidenceResults.flatMap((item) => item.creditedDuties));
  const missingDuties = required.filter((duty) => !passingCredit.has(duty));
  const failed =
    evidenceResults.some((item) => item.status === "failed") || compositionStatus === "failed";
  const missingEvidence = evidenceResults.some((item) =>
    ["missing", "skipped", "todo"].includes(item.status),
  );
  const support = index.support.filter((entry) =>
    scenario.requestedProfiles.some((requested) => {
      const closure = resolveProfiles(catalogueInput, [requested]).resolvedProfiles;
      return closure.includes(entry.profile) && scenario.roles.includes(entry.role);
    }),
  );
  const catalogue = validateProfileCatalogue(catalogueInput);
  const resolvedProfiles = resolveProfiles(catalogue, scenario.requestedProfiles).resolvedProfiles;
  const unclaimedSupport = resolvedProfiles.flatMap((profile) =>
    scenario.roles
      .filter((role) =>
        (catalogue.duties ?? []).some((duty) => duty.profile === profile && duty.role === role),
      )
      .filter((role) => !support.some((entry) => entry.profile === profile && entry.role === role))
      .map((role) => `${profile}/${role}`),
  );
  const unverifiedSelections = support.flatMap((entry) => {
    const selected = scenario.selections[entry.profile];
    if (!selected || entry.compatibleSelections.length > 0 || entry.profile === catalogue.baseline)
      return [];
    return [`${entry.profile}/${entry.role}`];
  });
  const unsupportedSelections = support.flatMap((entry) => {
    const selected = scenario.selections[entry.profile];
    if (!selected || entry.compatibleSelections.length === 0) return [];
    return entry.compatibleSelections.some((supported) => {
      const keys = Object.keys(supported);
      return keys.every((key) => supported[key] === selected[key]);
    })
      ? []
      : [`${entry.profile}/${entry.role}`];
  });
  const explicitlyUnsupported =
    support.some((entry) => entry.status === "unsupported") || unsupportedSelections.length > 0;
  const checkedPackages = new Map(packageChecks.map((entry) => [entry.id, entry]));
  const packageResults = scenario.recordedPackages.map(
    (id) => checkedPackages.get(id) ?? { id, status: "not-checked" },
  );
  const packageFailed = packageResults.some((entry) => entry.status === "failed");
  const packageIncomplete = packageResults.some((entry) => entry.status !== "passed");
  const complete =
    !failed &&
    compositionStatus === "passed" &&
    !missingEvidence &&
    missingDuties.length === 0 &&
    support.every((entry) => entry.status === "supported") &&
    unclaimedSupport.length === 0 &&
    unsupportedSelections.length === 0 &&
    unverifiedSelections.length === 0 &&
    !packageIncomplete &&
    scenario.unresolvedApplicability.length === 0 &&
    scenario.legacy.gaps.length === 0;
  return {
    id: scenario.id,
    status: failed || packageFailed ? "failed" : complete ? "verified-in-scope" : "incomplete",
    supportStatus: unclaimedSupport.length
      ? "unclaimed"
      : explicitlyUnsupported
        ? "unsupported"
        : "declared",
    unclaimedSupport,
    unsupportedSelections,
    unverifiedSelections,
    composition: {
      test: scenario.compositionEvidence.test,
      requestedProfiles: scenario.compositionEvidence.requestedProfiles,
      roles: scenario.compositionEvidence.roles,
      status: compositionStatus,
    },
    requiredDuties: [...required],
    passingDuties: [...passingCredit].filter((duty) => required.includes(duty)).sort(),
    missingDuties,
    unresolvedApplicability: [...scenario.unresolvedApplicability],
    evidence: evidenceResults,
    recordedPackages: packageResults,
    legacyGaps: scenario.legacy.gaps.map((gap) => ({ ...gap })),
    scopeLimit: "catalogue-bounded evidence only; this is not full normative conformance",
  };
}

/**
 * Reduce test events while preserving identity and outcomes for exact evidence matching.
 * @param {ClaimTestEvent[]} events
 * @param {unknown} catalogueInput
 */
export function reduceClaimTestEvents(events, catalogueInput) {
  const catalogue = validateProfileCatalogue(catalogueInput);
  const known = new Set((catalogue.duties ?? []).map((duty) => duty.id));
  /** @type {ObservedTest[]} */
  const output = [];
  /** @param {unknown} value */
  const directive = (value) => value === true || typeof value === "string";
  for (const event of events) {
    if (event.data.details?.type !== "test") continue;
    const tags = names(event.data.tags ?? [], "test tags");
    for (const tag of tags)
      if (!known.has(tag) && !ENVELOPE_TAGS.includes(tag))
        throw new Error(`unknown test duty tag ${tag}`);
    const skipped = event.type === "test:skip" || directive(event.data.skip);
    const todo = directive(event.data.todo);
    const outcome = skipped
      ? "skipped"
      : todo
        ? "todo"
        : event.type === "test:pass"
          ? "passed"
          : "failed";
    if (!event.data.file) throw new Error(`test event has no file identity: ${event.data.name}`);
    output.push({
      file: event.data.file,
      name: event.data.name,
      outcome,
      duties: tags.filter((tag) => known.has(tag)),
    });
  }
  return output;
}

/** @param {unknown} tags @param {unknown} catalogueInput */
export function classifyTestTags(tags, catalogueInput) {
  const catalogue = validateProfileCatalogue(catalogueInput);
  const values = names(tags, "test tags");
  const known = new Set((catalogue.duties ?? []).map((duty) => duty.id));
  for (const tag of values)
    if (!known.has(tag) && !ENVELOPE_TAGS.includes(tag))
      throw new Error(`unknown test duty tag ${tag}`);
  return {
    duties: values.filter((tag) => known.has(tag)),
    untagged: values.every((tag) => !known.has(tag)),
  };
}
