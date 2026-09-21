// @ts-check
//
// What one render supplies one issuer. The plan is asked for once per issuer,
// before the render draws anything, and it states the access groups this
// issuer's period material covers, whether it receives the ordinary direct
// content-key map, the content names it has to be able to reach through those
// groups, and the extra members its block carries.
//
// A planner returns a value and writes nothing. Base assembles the block from
// the plan it checked, so a planner cannot reach into output that is already
// made, and no two issuers can disagree about anything the render emits once.
//
// Reachable names make a plan fail closed. An issuer that is supplied a
// narrower set of groups than the render wraps under, and no direct map, can be
// left unable to answer for an item while the wire still looks complete. If the
// plan names what that issuer has to reach, the plan is refused before the
// render exists.

import { dcaError } from "../core-shared/errors.js";

/** Every member a plan may declare. */
const PLAN_MEMBERS = [
  "suppliedAccessGroups",
  "directContentKeys",
  "reachableContentNames",
  "issuerMembers",
  "contentKeyWrap",
  "periodKeyDelivery",
];

/** The issuer-block members base writes itself. */
const BASE_ISSUER_MEMBERS = ["sealed", "unlockUrl", "keyId"];

/**
 * What a planner declares. Every member is optional, and an absent one falls
 * back to the ordinary render: every group of this render, the direct map,
 * nothing to reach beyond it and no extra members.
 *
 * @typedef {object} DeclaredIssuerSupplyPlan
 * @property {string[]} [suppliedAccessGroups] - the access groups this issuer's
 *   period material covers, each one a group this render wraps under
 * @property {boolean} [directContentKeys] - whether `sealed.contentKeys` is
 *   written for this issuer
 * @property {string[]} [reachableContentNames] - the content names this issuer
 *   must be able to reach through the groups it is supplied
 * @property {Record<string, any>} [issuerMembers] - extra members of this
 *   issuer's block, none of them a member base writes
 * @property {object} [contentKeyWrap] - the wrap strategy this issuer needs the
 *   render to have selected
 * @property {Record<string, ('exact'|'chain')[]>} [periodKeyDelivery]
 *   - per supplied access group; an omitted group gets the base exact route,
 *   and a two-member array declares the union explicitly
 *
 * @typedef {object} IssuerSupplyPlan
 * @property {string} issuerName
 * @property {string[]} suppliedAccessGroups
 * @property {boolean} directContentKeys
 * @property {string[]} reachableContentNames
 * @property {Record<string, any>} issuerMembers
 * @property {Record<string, readonly ('exact'|'chain')[]>} periodKeyDelivery
 * @property {boolean} periodKeyDeliveryDeclared
 */

/**
 * The plan base makes when it is not told otherwise: every issuer of a render
 * is supplied every access group and the direct map. The format's v1 render
 * carries exactly that.
 *
 * @returns {DeclaredIssuerSupplyPlan}
 */
export function ordinaryIssuerSupplyPlan() {
  return {};
}

/**
 * @param {unknown} planner
 * @returns {(issuer: any, context: { accessGroups: string[], contentNames: string[] }) => DeclaredIssuerSupplyPlan}
 */
export function checkedIssuerSupplyPlanner(planner) {
  if (planner === undefined) return ordinaryIssuerSupplyPlan;
  if (typeof planner !== "function") {
    throw dcaError(
      "bad_config",
      "an issuerSupplyPlanFor is a function taking one issuer and the render coordinates",
    );
  }
  return /** @type {any} */ (planner);
}

/**
 * One declared plan, read into the closed value the render executes.
 *
 * @param {string} issuerName - for the refusals
 * @param {unknown} declared
 * @param {{
 *   accessGroups: string[],
 *   items: { name: string, accessGroups: string[] }[],
 *   contentKeyWrapStrategy: object|null,
 * }} render
 * @returns {IssuerSupplyPlan}
 */
export function normalizedIssuerSupplyPlan(issuerName, declared, render) {
  const plan = declared === undefined ? {} : declared;
  if (plan === null || typeof plan !== "object") {
    throw dcaError("bad_config", `the supply plan for issuer "${issuerName}" is an object`);
  }
  for (const name of Object.keys(plan)) {
    if (!PLAN_MEMBERS.includes(name)) {
      throw dcaError(
        "unsupported_option",
        `a supply plan has no ${name} yet, and will not pretend to`,
      );
    }
  }
  const declaredPlan = /** @type {DeclaredIssuerSupplyPlan} */ (plan);

  if (
    Object.hasOwn(declaredPlan, "contentKeyWrap") &&
    declaredPlan.contentKeyWrap !== render.contentKeyWrapStrategy
  ) {
    throw dcaError(
      "bad_config",
      `issuer "${issuerName}" needs a content-key wrap this render did not select`,
    );
  }

  const suppliedAccessGroups = supplied(
    issuerName,
    declaredPlan.suppliedAccessGroups,
    render.accessGroups,
  );

  if (
    declaredPlan.directContentKeys !== undefined &&
    typeof declaredPlan.directContentKeys !== "boolean"
  ) {
    throw dcaError(
      "bad_config",
      `the direct content-key map for issuer "${issuerName}" is on or off`,
    );
  }

  const reachableContentNames = reachable(
    issuerName,
    declaredPlan.reachableContentNames,
    suppliedAccessGroups,
    render.items,
  );
  const periodKeyDelivery = deliveries(
    issuerName,
    declaredPlan.periodKeyDelivery,
    suppliedAccessGroups,
  );

  return Object.freeze({
    issuerName,
    suppliedAccessGroups,
    directContentKeys: declaredPlan.directContentKeys ?? true,
    reachableContentNames,
    issuerMembers: Object.freeze({ ...members(issuerName, declaredPlan.issuerMembers) }),
    periodKeyDelivery,
    periodKeyDeliveryDeclared: Object.hasOwn(declaredPlan, "periodKeyDelivery"),
  });
}

/**
 * A protected item cannot be emitted with a route no issuer can complete.
 * Direct delivery reaches every item in this render; a supplied access group
 * reaches the items wrapped under that group. The selected period-key delivery
 * is normalized with every supplied group, so this check needs only the closed
 * plan and the complete protected-item set.
 *
 * @param {{ name: string, accessGroups: string[] }[]} items
 * @param {IssuerSupplyPlan[]} plans
 * @returns {void}
 */
export function assertCompleteIssuerRoutes(items, plans) {
  for (const item of items) {
    const reachable = plans.some(
      (plan) =>
        plan.directContentKeys ||
        item.accessGroups.some((accessGroup) => plan.suppliedAccessGroups.includes(accessGroup)),
    );
    if (!reachable) {
      throw dcaError("bad_config", `no complete issuer route for protected content "${item.name}"`);
    }
  }
}

/**
 * Normalize the per-family representation without deciding whether this
 * publisher can serve it. The Sealer checks every route against its resolved
 * family plans before it asks a supplier for key material.
 *
 * @param {string} issuerName
 * @param {Record<string, ('exact'|'chain')[]>|undefined} declared
 * @param {string[]} suppliedAccessGroups
 * @returns {Record<string, readonly ('exact'|'chain')[]>}
 */
function deliveries(issuerName, declared, suppliedAccessGroups) {
  if (
    declared !== undefined &&
    (declared === null || typeof declared !== "object" || Array.isArray(declared))
  ) {
    throw dcaError(
      "bad_config",
      `period-key delivery for issuer "${issuerName}" is an object keyed by accessGroup`,
    );
  }

  /** @type {Record<string, readonly ('exact'|'chain')[]>} */
  const result = Object.create(null);
  for (const accessGroup of suppliedAccessGroups) {
    const selected =
      declared && Object.hasOwn(declared, accessGroup) ? declared[accessGroup] : ["exact"];
    if (
      !Array.isArray(selected) ||
      selected.length === 0 ||
      selected.length > 2 ||
      selected.some((mode) => mode !== "exact" && mode !== "chain") ||
      new Set(selected).size !== selected.length
    ) {
      throw dcaError(
        "bad_config",
        `period-key delivery for issuer "${issuerName}" and accessGroup "${accessGroup}" is [exact], [chain], or [exact, chain]`,
      );
    }
    const modes = selected.includes("exact") ? ["exact"] : [];
    if (selected.includes("chain")) modes.push("chain");
    Object.defineProperty(result, accessGroup, {
      value: Object.freeze(modes),
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }

  for (const accessGroup of Object.keys(declared ?? {})) {
    if (!suppliedAccessGroups.includes(accessGroup)) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" selects period-key delivery for unsupplied accessGroup "${accessGroup}"`,
      );
    }
  }
  return Object.freeze(result);
}

/**
 * The groups a plan supplies, in the order the render wraps under them, so two
 * issuers reading one render read one order.
 *
 * @param {string} issuerName
 * @param {string[]|undefined} declared
 * @param {string[]} accessGroups - every group of this render
 * @returns {string[]}
 */
function supplied(issuerName, declared, accessGroups) {
  if (declared === undefined) return [...accessGroups];
  if (!Array.isArray(declared)) {
    throw dcaError("bad_config", `the supplied accessGroups for issuer "${issuerName}" are a list`);
  }
  for (const accessGroup of declared) {
    if (!accessGroups.includes(accessGroup)) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" is supplied "${accessGroup}", which this render wraps nothing under`,
      );
    }
  }
  return accessGroups.filter((accessGroup) => declared.includes(accessGroup));
}

/**
 * @param {string} issuerName
 * @param {string[]|undefined} declared
 * @param {string[]} suppliedAccessGroups
 * @param {{ name: string, accessGroups: string[] }[]} items
 * @returns {string[]}
 */
function reachable(issuerName, declared, suppliedAccessGroups, items) {
  if (declared === undefined) return [];
  if (!Array.isArray(declared)) {
    throw dcaError(
      "bad_config",
      `the reachable contentNames for issuer "${issuerName}" are a list`,
    );
  }
  for (const contentName of declared) {
    const item = items.find((candidate) => candidate.name === contentName);
    if (!item) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" must reach "${contentName}", which this render does not carry`,
      );
    }
    if (!item.accessGroups.some((accessGroup) => suppliedAccessGroups.includes(accessGroup))) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" must reach "${contentName}" and is supplied no accessGroup it is wrapped under`,
      );
    }
  }
  return [...declared];
}

/**
 * @param {string} issuerName
 * @param {Record<string, any>|undefined} declared
 * @returns {Record<string, any>}
 */
function members(issuerName, declared) {
  if (declared === undefined) return {};
  if (declared === null || typeof declared !== "object" || Array.isArray(declared)) {
    throw dcaError(
      "bad_config",
      `the extra issuer members for issuer "${issuerName}" are an object`,
    );
  }
  for (const name of Object.keys(declared)) {
    if (BASE_ISSUER_MEMBERS.includes(name)) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" cannot be decorated with ${name}, which this render writes itself`,
      );
    }
  }
  return declared;
}
