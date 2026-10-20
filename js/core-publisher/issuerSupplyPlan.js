// @ts-check
//
// What one render supplies one issuer. The plan is asked for once per issuer,
// before the render draws anything, and it states the content names that
// receive a sealed content key, the access groups this issuer's period
// material covers, the content names it has to be able to reach through those
// groups, and the extra members its block carries.
//
// The publisher selects both kinds for every issuer block, and neither kind
// has a default: an absent selection is refused, never read as every name or
// every group, because a configuration omission would otherwise hand an
// issuer authority nobody chose. An explicitly empty list supplies nothing of
// that kind. The two kinds are independent: a period key still reaches every
// item wrapped under its group, whether or not the publisher also seals that
// item's content key to this issuer.
//
// A planner returns a value and writes nothing. Base assembles the block from
// the plan it checked, so a planner cannot reach into output that is already
// made, and no two issuers can disagree about anything the render emits once.
//
// Reachable names make a plan fail closed. An issuer that is supplied a
// narrower set of groups than the render wraps under, and no content key sealed
// to it for an item, can be left unable to answer for it while the wire still looks
// complete. If the plan names what that issuer has to reach, the plan is
// refused before the render exists.

import { dcaError } from "../core-shared/errors.js";
import { isPeriodKeyLabel } from "../core-shared/periodLabels.js";

/** Every member a plan may declare. */
const PLAN_MEMBERS = [
  "contentKeyNames",
  "suppliedAccessGroups",
  "reachableContentNames",
  "issuerMembers",
  "contentKeyWrap",
  "periodKeyDelivery",
  "periodKeySourceTs",
];

/** Reserved issuer-block members: base owns sealed/keyId; unlockUrl is forbidden on the wire. */
const RESERVED_ISSUER_MEMBERS = ["sealed", "unlockUrl", "keyId"];

/**
 * What a planner declares. `contentKeyNames` and `suppliedAccessGroups` are
 * required; the other members are optional.
 *
 * @typedef {object} DeclaredIssuerSupplyPlan
 * @property {string[]} [contentKeyNames] - the content names that receive
 *   a sealed content key in this issuer's block, each one an item of
 *   this render. Required.
 * @property {string[]} [suppliedAccessGroups] - the access groups this
 *   issuer's period material covers, each one a group this render wraps under.
 *   Required.
 * @property {string[]} [reachableContentNames] - the content names this issuer
 *   must be able to reach through the groups it is supplied
 * @property {Record<string, any>} [issuerMembers] - extra members of this
 *   issuer's block, none of them a member base writes
 * @property {object} [contentKeyWrap] - the wrap strategy this issuer needs the
 *   render to have selected
 * @property {Record<string, ('period-keys'|'chain-keys')[]>} [periodKeyDelivery]
 *   - per supplied access group; an omitted group gets the base period-key route,
 *   and a two-member array declares the union explicitly. It chooses the
 *   representation of a supplied group and never supplies one.
 * @property {Record<string, string[]>} [periodKeySourceTs] - publisher-only
 *   selection of ordinary period-key source labels per supplied group. Omitted
 *   groups retain every planned label; an explicit empty list selects none.
 *
 * @typedef {object} IssuerSupplyPlan
 * @property {string} issuerName
 * @property {string[]} contentKeyNames
 * @property {string[]} suppliedAccessGroups
 * @property {string[]} reachableContentNames
 * @property {Record<string, any>} issuerMembers
 * @property {Record<string, readonly ('period-keys'|'chain-keys')[]>} periodKeyDelivery
 * @property {Record<string, readonly string[]>} periodKeySourceTs
 * @property {boolean} periodKeyDeliveryDeclared
 */

/**
 * The explicit plan that supplies an issuer every content name and every
 * access group of the render. A publisher names it as its planner when it
 * means that; nothing falls back to it.
 *
 * @param {unknown} _issuer
 * @param {{ accessGroups: string[], contentNames: string[], now?: Date }} render
 * @returns {{ contentKeyNames: string[], suppliedAccessGroups: string[] }}
 */
export function wholeRenderIssuerSupplyPlan(_issuer, render) {
  return {
    contentKeyNames: [...render.contentNames],
    suppliedAccessGroups: [...render.accessGroups],
  };
}

/**
 * @param {unknown} planner
 * @returns {(issuer: any, context: { accessGroups: string[], contentNames: string[], now: Date }) => DeclaredIssuerSupplyPlan}
 */
export function checkedIssuerSupplyPlanner(planner) {
  if (planner === undefined) {
    throw dcaError(
      "bad_config",
      "a publisher selects each issuer's scope with an issuerSupplyPlanFor; without one no issuer is supplied anything",
    );
  }
  if (typeof planner !== "function") {
    throw dcaError(
      "bad_config",
      "an issuerSupplyPlanFor is a function taking one issuer and the render coordinates",
    );
  }
  return /** @type {any} */ (planner);
}

/**
 * One declared plan, read into the closed value the render executes. It checks
 * the members in this order: the plan's shape and member names, the wrap
 * strategy, the supplied groups, `contentKeyNames`, the reachable names, the
 * period-key delivery and the extra members.
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
  const contentKeyNames = contentKeySelection(issuerName, declaredPlan, render.items);

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
  const periodKeySourceTs = sourceTs(
    issuerName,
    declaredPlan.periodKeySourceTs,
    suppliedAccessGroups,
    periodKeyDelivery,
  );

  return Object.freeze({
    issuerName,
    contentKeyNames,
    suppliedAccessGroups,
    reachableContentNames,
    issuerMembers: Object.freeze({ ...members(issuerName, declaredPlan.issuerMembers) }),
    periodKeyDelivery,
    periodKeySourceTs,
    periodKeyDeliveryDeclared: Object.hasOwn(declaredPlan, "periodKeyDelivery"),
  });
}

/**
 * Check selector shape before asking for any key material. Membership in the
 * resolved family plan and per-issuer route coverage are checked by Sealer.
 *
 * @param {string} issuerName
 * @param {Record<string, string[]>|undefined} declared
 * @param {string[]} suppliedAccessGroups
 * @param {Record<string, readonly ('period-keys'|'chain-keys')[]>} periodKeyDelivery
 * @returns {Record<string, readonly string[]>}
 */
function sourceTs(issuerName, declared, suppliedAccessGroups, periodKeyDelivery) {
  if (
    declared !== undefined &&
    (declared === null || typeof declared !== "object" || Array.isArray(declared))
  ) {
    throw dcaError(
      "bad_config",
      `period-key source labels for issuer "${issuerName}" are an object keyed by accessGroup`,
    );
  }
  /** @type {Record<string, readonly string[]>} */
  const result = Object.create(null);
  for (const [accessGroup, labels] of Object.entries(declared ?? {})) {
    if (!suppliedAccessGroups.includes(accessGroup)) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" selects period-key source labels for unsupplied accessGroup "${accessGroup}"`,
      );
    }
    if (!periodKeyDelivery[accessGroup].includes("period-keys")) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" selects ordinary period-key source labels without period-key delivery for "${accessGroup}"`,
      );
    }
    if (
      !Array.isArray(labels) ||
      labels.some((t) => !isPeriodKeyLabel(t)) ||
      new Set(labels).size !== labels.length
    ) {
      throw dcaError(
        "bad_config",
        `period-key source labels for issuer "${issuerName}" and accessGroup "${accessGroup}" are a list of unique YYMMDDTHHMM labels`,
      );
    }
    Object.defineProperty(result, accessGroup, {
      value: Object.freeze([...labels]),
      enumerable: true,
    });
  }
  return Object.freeze(result);
}

/**
 * True when a closed plan supplies this issuer nothing of either kind. Base
 * writes no block for such an issuer: a block with no capability would only
 * give a client an issuer to ask that can open nothing in this render.
 *
 * @param {IssuerSupplyPlan} plan
 * @returns {boolean}
 */
export function suppliesNothing(plan) {
  return plan.contentKeyNames.length === 0 && plan.suppliedAccessGroups.length === 0;
}

/**
 * Coarse route check from declared scope alone. A sealed content key reaches
 * its selected item; a supplied access group is only a candidate route. The
 * Sealer checks that candidate against the selected ordinary and chain source
 * coordinates before acquiring key material.
 *
 * @param {{ name: string, accessGroups: string[] }[]} items
 * @param {IssuerSupplyPlan[]} plans
 * @returns {void}
 */
export function assertCompleteIssuerRoutes(items, plans) {
  for (const item of items) {
    const reachable = plans.some(
      (plan) =>
        plan.contentKeyNames.includes(item.name) ||
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
 * @param {Record<string, ('period-keys'|'chain-keys')[]>|undefined} declared
 * @param {string[]} suppliedAccessGroups
 * @returns {Record<string, readonly ('period-keys'|'chain-keys')[]>}
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

  /** @type {Record<string, readonly ('period-keys'|'chain-keys')[]>} */
  const result = Object.create(null);
  for (const accessGroup of suppliedAccessGroups) {
    const selected =
      declared && Object.hasOwn(declared, accessGroup) ? declared[accessGroup] : ["period-keys"];
    if (
      !Array.isArray(selected) ||
      selected.length === 0 ||
      selected.length > 2 ||
      selected.some((mode) => mode !== "period-keys" && mode !== "chain-keys") ||
      new Set(selected).size !== selected.length
    ) {
      throw dcaError(
        "bad_config",
        `period-key delivery for issuer "${issuerName}" and accessGroup "${accessGroup}" is [period-keys], [chain-keys], or [period-keys, chain-keys]`,
      );
    }
    const modes = selected.includes("period-keys") ? ["period-keys"] : [];
    if (selected.includes("chain-keys")) modes.push("chain-keys");
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
  if (declared === undefined) {
    throw dcaError(
      "bad_config",
      `issuer "${issuerName}" has no accessGroup selection; an empty list supplies none`,
    );
  }
  if (!Array.isArray(declared)) {
    throw dcaError("bad_config", `the supplied accessGroups for issuer "${issuerName}" are a list`);
  }
  for (const [index, accessGroup] of declared.entries()) {
    if (!accessGroups.includes(accessGroup)) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" is supplied "${accessGroup}", which this render wraps nothing under`,
      );
    }
    if (declared.indexOf(accessGroup) !== index) {
      throw dcaError("bad_config", `issuer "${issuerName}" is supplied "${accessGroup}" twice`);
    }
  }
  return accessGroups.filter((accessGroup) => declared.includes(accessGroup));
}

/**
 * The content names that receive a sealed content key, in render order.
 *
 * @param {string} issuerName
 * @param {DeclaredIssuerSupplyPlan} declared
 * @param {{ name: string }[]} items - every item of this render
 * @returns {string[]}
 */
function contentKeySelection(issuerName, declared, items) {
  const names = declared.contentKeyNames;
  if (names === undefined) {
    throw dcaError(
      "bad_config",
      `issuer "${issuerName}" has no content-key selection; an empty list supplies none`,
    );
  }
  if (!Array.isArray(names)) {
    throw dcaError("bad_config", `the contentKeyNames for issuer "${issuerName}" are a list`);
  }
  for (const [index, contentName] of names.entries()) {
    if (!items.some((item) => item.name === contentName)) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" selects content-key name "${contentName}", which this render does not carry`,
      );
    }
    if (names.indexOf(contentName) !== index) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" selects content-key name "${contentName}" twice`,
      );
    }
  }
  return items.map((item) => item.name).filter((contentName) => names.includes(contentName));
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
    if (RESERVED_ISSUER_MEMBERS.includes(name)) {
      throw dcaError(
        "bad_config",
        `issuer "${issuerName}" cannot be decorated with ${name}, which is reserved by the data format`,
      );
    }
  }
  return declared;
}
