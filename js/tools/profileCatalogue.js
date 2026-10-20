// @ts-check

/**
 * Profile names are local conformance identifiers, never wire values. This
 * module accepts a catalogue value explicitly so callers choose its source.
 *
 * @typedef {{id: string, dependsOn: string[], ref: string, roles?: string[]}} Profile
 * @typedef {{id: string, profile: string, role: string, ref: string}} Duty
 * @typedef {{name: string, definedBy: string}} NamedSpec
 * @typedef {"boolean" | "named-spec-list" | string[]} Choice
 * @typedef {{if: Record<string, string | boolean>, then: Record<string, string | boolean>}} Requirement
 * @typedef {{profile: string, scope: string, decider: string, ref: string,
 *   choices: Record<string, Choice>, requires?: Requirement[],
 *   requiresProfiles?: {if: Record<string, string | boolean>, profiles: string[]}[]}} Selection
 * @typedef {{authority: string, baseline: string, profiles: Profile[],
 *   duties?: Duty[], selections?: Selection[]}} Catalogue
 */

const identifier = /^[\x21-\x7e]+$/;

/** @param {unknown} value @param {string} label */
function object(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return /** @type {Record<string, unknown>} */ (value);
}

/** @param {unknown} value @param {string} label */
function nonempty(value, label) {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0) {
    throw new TypeError(`${label} must be a nonempty, trimmed string`);
  }
  return value;
}

/** @param {unknown} value @param {string} label */
function name(value, label) {
  const result = nonempty(value, label);
  if (!identifier.test(result)) throw new TypeError(`${label} must use visible ASCII`);
  return result;
}

/** @param {unknown} value @param {string} label */
function array(value, label) {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
  return /** @type {unknown[]} */ (value);
}

/** @param {unknown} value @param {string} label */
function uniqueNames(value, label) {
  const names = array(value, label).map((entry, index) => name(entry, `${label}[${index}]`));
  if (new Set(names).size !== names.length) throw new Error(`${label} has duplicate names`);
  return names;
}

/** @param {string} a @param {string} b */
function ascii(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Validate catalogue structure and cross references. A profile's dependencies
 * must form a DAG rooted at the one declared baseline. Every other profile
 * either owns a duty or composes at least two effective direct parents. This
 * check is structural: whether a duty is substantive, and whether two parents
 * differ in meaning and can be satisfied together, stay editorial review.
 * @param {unknown} input
 * @returns {Catalogue}
 */
export function validateProfileCatalogue(input) {
  const catalogue = object(input, "catalogue");
  nonempty(catalogue.authority, "authority");
  const baseline = name(catalogue.baseline, "baseline");
  const profiles = array(catalogue.profiles, "profiles");
  if (profiles.length === 0) throw new Error("profiles must contain the baseline");

  /** @type {Map<string, string[]>} */
  const dependencies = new Map();
  for (const [index, value] of profiles.entries()) {
    const profile = object(value, `profiles[${index}]`);
    const id = name(profile.id, `profiles[${index}].id`);
    if (dependencies.has(id)) throw new Error(`duplicate profile ${id}`);
    dependencies.set(id, uniqueNames(profile.dependsOn, `profiles[${index}].dependsOn`));
    nonempty(profile.ref, `profiles[${index}].ref`);
    if (profile.roles !== undefined) uniqueNames(profile.roles, `profiles[${index}].roles`);
  }
  if (!dependencies.has(baseline)) throw new Error(`unknown baseline ${baseline}`);
  if (dependencies.get(baseline)?.length !== 0)
    throw new Error("baseline cannot depend on another profile");
  for (const [id, parents] of dependencies) {
    for (const parent of parents) {
      if (!dependencies.has(parent)) throw new Error(`${id} has unknown dependency ${parent}`);
    }
  }

  /** @type {Set<string>} */
  const visited = new Set();
  /** @type {Set<string>} */
  const visiting = new Set();
  /** @param {string} id */
  function visit(id) {
    if (visiting.has(id)) throw new Error(`profile dependency cycle at ${id}`);
    if (visited.has(id)) return;
    visiting.add(id);
    for (const parent of dependencies.get(id) ?? []) visit(parent);
    visiting.delete(id);
    visited.add(id);
  }
  for (const id of dependencies.keys()) visit(id);
  /** @type {Map<string, Set<string>>} */
  const ancestry = new Map();
  for (const id of dependencies.keys()) {
    /** @type {Set<string>} */
    const ancestors = new Set();
    /** @param {string} current */
    function collect(current) {
      for (const parent of dependencies.get(current) ?? []) {
        if (!ancestors.has(parent)) {
          ancestors.add(parent);
          collect(parent);
        }
      }
    }
    collect(id);
    ancestry.set(id, ancestors);
    if (id !== baseline && !ancestors.has(baseline))
      throw new Error(`${id} does not resolve the baseline`);
  }

  // The file order is a checked projection of the specification's canonical
  // dependency-ready order, rather than an independent ordering rule.
  const remaining = new Set(dependencies.keys());
  /** @type {string[]} */
  const canonical = [];
  while (remaining.size > 0) {
    const next = [...remaining]
      .filter((id) => (dependencies.get(id) ?? []).every((parent) => !remaining.has(parent)))
      .sort(ascii)[0];
    canonical.push(next);
    remaining.delete(next);
  }
  if (profiles.some((profile, index) => object(profile, "profile").id !== canonical[index])) {
    throw new Error("profiles must be in canonical dependency order");
  }

  const duties = catalogue.duties === undefined ? [] : array(catalogue.duties, "duties");
  const dutyIds = new Set();
  const dutyOwners = new Set();
  for (const [index, value] of duties.entries()) {
    const duty = object(value, `duties[${index}]`);
    const id = name(duty.id, `duties[${index}].id`);
    if (dutyIds.has(id)) throw new Error(`duplicate duty ${id}`);
    dutyIds.add(id);
    const profile = name(duty.profile, `duties[${index}].profile`);
    if (!dependencies.has(profile)) throw new Error(`duty ${id} has unknown profile ${profile}`);
    const role = name(duty.role, `duties[${index}].role`);
    if (!["publisher", "issuer", "client"].includes(role)) {
      throw new Error(`duty ${id} has unknown role ${role}`);
    }
    if (!id.startsWith(`${profile}/${role}/`) || id === `${profile}/${role}/`) {
      throw new Error(`duty ${id} must name its profile and role`);
    }
    nonempty(duty.ref, `duties[${index}].ref`);
    dutyOwners.add(profile);
  }
  for (const [id, parents] of dependencies) {
    if (id === baseline || dutyOwners.has(id)) continue;
    // A parent that another direct parent already requires adds nothing to
    // the composition. Dropping it here only counts; dependsOn, the closure
    // and the resolved order keep it.
    const effective = parents.filter(
      (parent) => !parents.some((other) => other !== parent && ancestry.get(other)?.has(parent)),
    );
    if (effective.length < 2)
      throw new Error(
        `profile ${id} adds no duty and composes fewer than two effective dependencies`,
      );
  }

  const selections =
    catalogue.selections === undefined ? [] : array(catalogue.selections, "selections");
  const selectionProfiles = new Set();
  for (const [index, value] of selections.entries()) {
    const selection = object(value, `selections[${index}]`);
    const profile = name(selection.profile, `selections[${index}].profile`);
    if (!dependencies.has(profile))
      throw new Error(`selection ${index} has unknown profile ${profile}`);
    if (selectionProfiles.has(profile)) throw new Error(`duplicate selection for ${profile}`);
    selectionProfiles.add(profile);
    nonempty(selection.scope, `selections[${index}].scope`);
    nonempty(selection.decider, `selections[${index}].decider`);
    nonempty(selection.ref, `selections[${index}].ref`);
    const choices = object(selection.choices, `selections[${index}].choices`);
    if (Object.keys(choices).length === 0)
      throw new Error(`selections[${index}].choices must not be empty`);
    for (const [field, descriptor] of Object.entries(choices)) {
      name(field, `selections[${index}].choices field`);
      if (Array.isArray(descriptor)) {
        if (uniqueNames(descriptor, `selections[${index}].choices.${field}`).length === 0) {
          throw new Error(`selections[${index}].choices.${field} must not be empty`);
        }
      } else if (descriptor !== "boolean" && descriptor !== "named-spec-list") {
        throw new TypeError(`selections[${index}].choices.${field} has unknown descriptor`);
      }
    }
    const requirements =
      selection.requires === undefined
        ? []
        : array(selection.requires, `selections[${index}].requires`);
    for (const [ruleIndex, value] of requirements.entries()) {
      const rule = object(value, `selections[${index}].requires[${ruleIndex}]`);
      for (const side of ["if", "then"]) {
        const conditions = object(
          rule[side],
          `selections[${index}].requires[${ruleIndex}].${side}`,
        );
        if (Object.keys(conditions).length === 0)
          throw new Error(`selection ${index} requirement ${side} must not be empty`);
        for (const [field, expected] of Object.entries(conditions)) {
          if (!Object.hasOwn(choices, field))
            throw new Error(`selection ${index} requirement has unknown field ${field}`);
          validateChoice(
            choices[field],
            expected,
            `selection ${index} requirement ${side}.${field}`,
          );
        }
      }
    }
  }

  // Conditional dependencies validate selected composition, independently
  // of the unconditional graph and the local typed-value requirements.
  for (const selection of selections) {
    const entry = object(selection, "selection");
    for (const ruleValue of entry.requiresProfiles === undefined
      ? []
      : array(entry.requiresProfiles, "requiresProfiles")) {
      const rule = object(ruleValue, "profile requirement");
      const conditions = object(rule.if, "profile requirement.if");
      if (Object.keys(conditions).length === 0)
        throw new Error("profile requirement.if must not be empty");
      for (const [field, expected] of Object.entries(conditions)) {
        const choices = object(entry.choices, "selection.choices");
        if (!Object.hasOwn(choices, field))
          throw new Error(`profile requirement has unknown field ${field}`);
        validateChoice(choices[field], expected, `profile requirement.${field}`);
      }
      const required = uniqueNames(rule.profiles, "profile requirement.profiles");
      if (required.length === 0) throw new Error("profile requirement.profiles must not be empty");
      for (const profile of required)
        if (!dependencies.has(profile))
          throw new Error(`profile requirement has unknown profile ${profile}`);
    }
  }
  return /** @type {Catalogue} */ (input);
}

/** @param {unknown} descriptor @param {unknown} value @param {string} label */
function validateChoice(descriptor, value, label) {
  if (descriptor === "boolean") {
    if (typeof value !== "boolean") throw new TypeError(`${label} must be boolean`);
  } else if (descriptor === "named-spec-list") {
    const entries = array(value, label);
    if (entries.length === 0) throw new Error(`${label} must not be empty`);
    const names = entries.map((entry, index) => {
      const item = object(entry, `${label}[${index}]`);
      nonempty(item.definedBy, `${label}[${index}].definedBy`);
      return name(item.name, `${label}[${index}].name`);
    });
    if (new Set(names).size !== names.length) throw new Error(`${label} has duplicate names`);
  } else if (Array.isArray(descriptor)) {
    if (typeof value !== "string" || !descriptor.includes(value)) {
      throw new Error(`${label} must be one of ${descriptor.join(", ")}`);
    }
  } else {
    throw new TypeError(`${label} has unknown choice descriptor`);
  }
}

/**
 * Validate one profile's typed selection and its declarative implications.
 * Every declared field is required; no undeclared field may acquire meaning.
 * @param {unknown} input
 * @param {unknown} profileId
 * @param {unknown} values
 * @param {string[]} [requestedProfiles] - configured profiles for this composition
 * @returns {Record<string, unknown>}
 */
export function validateSelection(input, profileId, values, requestedProfiles = []) {
  const catalogue = validateProfileCatalogue(input);
  const id = name(profileId, "profileId");
  if (!catalogue.profiles.some((profile) => profile.id === id))
    throw new Error(`unknown profile ${id}`);
  const selection = catalogue.selections?.find((entry) => entry.profile === id);
  if (selection === undefined) throw new Error(`profile ${id} has no typed selection`);
  const actual = object(values, "selection values");
  for (const [field, descriptor] of Object.entries(selection.choices)) {
    if (!Object.hasOwn(actual, field)) throw new Error(`selection missing ${field}`);
    validateChoice(descriptor, actual[field], `selection.${field}`);
  }
  for (const field of Object.keys(actual)) {
    if (!Object.hasOwn(selection.choices, field))
      throw new Error(`selection has unknown field ${field}`);
  }
  for (const rule of selection.requires ?? []) {
    if (Object.entries(rule.if).every(([field, expected]) => actual[field] === expected)) {
      for (const [field, expected] of Object.entries(rule.then)) {
        if (actual[field] !== expected) throw new Error(`selection requires ${field}=${expected}`);
      }
    }
  }
  for (const rule of selection.requiresProfiles ?? []) {
    if (Object.entries(rule.if).every(([field, expected]) => actual[field] === expected)) {
      const closure = resolveProfiles(catalogue, requestedProfiles).resolvedProfiles;
      for (const required of rule.profiles) {
        if (!closure.includes(required)) throw new Error(`selection requires profile ${required}`);
      }
    }
  }
  return actual;
}

/**
 * Resolve an unordered request into its most-specific leaves and dependency
 * closure. A caller must not repeat a requested profile.
 * @param {unknown} input
 * @param {unknown} requested
 * @returns {{requestedProfiles: string[], resolvedProfiles: string[]}}
 */
export function resolveProfiles(input, requested) {
  const catalogue = validateProfileCatalogue(input);
  const dependencies = new Map(
    catalogue.profiles.map((profile) => [profile.id, profile.dependsOn]),
  );
  const names = uniqueNames(requested, "requestedProfiles");
  if (names.length === 0) names.push(catalogue.baseline);
  for (const id of names) {
    if (!dependencies.has(id)) throw new Error(`unknown requested profile ${id}`);
  }

  /** @type {Set<string>} */
  const closure = new Set([catalogue.baseline]);
  /** @param {string} id */
  function add(id) {
    if (closure.has(id)) return;
    closure.add(id);
    for (const parent of dependencies.get(id) ?? []) add(parent);
  }
  for (const id of names) add(id);

  /** @param {string} ancestor @param {string} id */
  function inherits(ancestor, id) {
    for (const parent of dependencies.get(id) ?? []) {
      if (parent === ancestor || inherits(ancestor, parent)) return true;
    }
    return false;
  }
  const requestedProfiles = names
    .filter((id) => !names.some((other) => other !== id && inherits(id, other)))
    .sort(ascii);

  /** @type {string[]} */
  const resolvedProfiles = [];
  const remaining = new Set(closure);
  while (remaining.size > 0) {
    const ready = [...remaining]
      .filter((id) => (dependencies.get(id) ?? []).every((parent) => !remaining.has(parent)))
      .sort(ascii);
    // Catalogue validation already proved acyclicity.
    const next = ready[0];
    resolvedProfiles.push(next);
    remaining.delete(next);
  }
  return { requestedProfiles, resolvedProfiles };
}

/**
 * List the catalogue duties applicable to one role in a resolved closure.
 * This is a vocabulary for diagnostics, not a claim that a duty ran.
 * @param {unknown} input
 * @param {unknown} requested
 * @param {unknown} role
 * @returns {{requestedProfiles: string[], resolvedProfiles: string[], role: string, duties: string[]}}
 */
export function profileDutySummary(input, requested, role) {
  const catalogue = validateProfileCatalogue(input);
  const selectedRole = name(role, "role");
  if (!["publisher", "issuer", "client"].includes(selectedRole)) {
    throw new Error(`unknown role ${selectedRole}`);
  }
  const resolution = resolveProfiles(catalogue, requested);
  const resolved = new Set(resolution.resolvedProfiles);
  const duties = (catalogue.duties ?? [])
    .filter((duty) => duty.role === selectedRole && resolved.has(duty.profile))
    .map((duty) => duty.id)
    .sort(ascii);
  return { ...resolution, role: selectedRole, duties };
}
