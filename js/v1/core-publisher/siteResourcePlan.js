// @ts-check
//
// Structural publisher planning from plain data. This module deliberately
// stops before keys, crypto, serialized bytes and issuer policy: it counts the
// routes and bounded capability collections a later preview may materialize.

import { dcaError } from "../core-shared/errors.js";
import {
  validateAccessGroup,
  validateContentName,
  validateIssuerName,
} from "../core-shared/names.js";
import {
  inspectPeriodGeometryBounds,
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  MAX_EXACT_LEAVES_PER_FAMILY,
  MAX_EXACT_LEAVES_PER_RESPONSE,
  MAX_POSITIONS_PER_WINDOW,
} from "../core-shared/geometryBounds.js";
import { EXACT_PERIOD_PROFILE, exactPeriodProfile } from "../core-shared/exactPeriodProfiles.js";
import { assertCompleteIssuerRoutes, normalizedIssuerSupplyPlan } from "./issuerSupplyPlan.js";

/** @typedef {'ECDH-P256'|'RSA-OAEP'} IssuerMethod */
/** @typedef {'exactMembers'|'chainMembers'|'projectedLeaves'} ResponseFamilyField */
/** @typedef {'protectedItems'|'contentKeyInstances'|'contentToAccessGroupAssignments'|'contentKeyWraps'|'issuerRoutes'|'directSealedCapabilities'|'exactFamilies'|'exactMembers'|'exactResponseKeyCandidates'|'chainFamilies'|'chainMembers'|'chainWindows'|'projectedLeafCandidates'|'responseKeyCandidates'|'combinedFamilies'|'combinedMembers'} CountName */
/** @typedef {'positionsPerWindow'|'chainMembersPerFamily'|'chainMembersPerMessage'|'exactLeavesPerFamily'|'exactLeavesPerResponse'} LocalLimitName */
/** @typedef {Record<CountName, number>} Counts */
/** @typedef {{ exactMembers: number, chainMembers: number, projectedLeaves: number }} FamilyCandidates */
/** @typedef {{ projectedLeaves: number }} PlannedChainWindow */
/** @typedef {{ chainsPerDay: number, periodMinutes: number, positionsPerWindow: number, windows: PlannedChainWindow[] }} PlannedChainFamily */
/** @typedef {{ name: string, exactMembers: number, chain: PlannedChainFamily|null }} PlannedAccessGroup */
/** @typedef {{ name: string, accessGroups: string[], volume: number }} PlannedItem */
/** @typedef {import('./issuerSupplyPlan.js').IssuerSupplyPlan} IssuerSupplyPlan */
/** @typedef {{ issuerName: string, method: IssuerMethod, supply: IssuerSupplyPlan }} PlannedIssuer */
/** @typedef {{ directContentKeys: number, families: Map<string, FamilyCandidates> }} ScenarioIssuer */
/** @typedef {{ protectedItems: number, contentKeyInstances: number, contentToAccessGroupAssignments: number, contentKeyWraps: number, issuerRoutes: number, directSealedCapabilities: number }} ItemCounts */
/** @typedef {{ name: string, accessGroups: string[], volume: number, counts: ItemCounts }} ItemReport */
/** @typedef {{ protectedItems: number, contentKeyInstances: number, contentToAccessGroupAssignments: number, contentKeyWraps: number, issuerRoutes: number, exactFamilies: number, exactMembers: number, exactResponseKeyCandidates: number, chainFamilies: number, chainMembers: number, chainWindows: number, projectedLeafCandidates: number, responseKeyCandidates: number, combinedFamilies: number, combinedMembers: number }} AccessGroupCounts */
/** @typedef {{ name: string, counts: AccessGroupCounts }} AccessGroupReport */
/** @typedef {{ dimension: string, scope: string, used: number, protocolLimit: number, localLimit: number|null, effectiveLimit: number, remaining: number, limitingSource: 'local'|'protocol', binding: boolean }} LimitReport */
/** @typedef {{ issuerName: string, method: IssuerMethod, certainty: 'upperBound'|'scenario', counts: Counts, response: { directContentKeys: number, exactMembers: number, chainMembers: number, projectedLeaves: number, total: number } }} IssuerReport */
/** @typedef {{ name: string, volume: number, certainty: 'upperBound'|'scenario', counts: Counts, items: ItemReport[], accessGroups: AccessGroupReport[], issuers: IssuerReport[], limits: LimitReport[], firstBindingDimension: { dimension: string, scope: string, limitingSource: 'local'|'protocol', remaining: number }|null }} RenderReport */
/** @typedef {{ issuerName: string, method: IssuerMethod, counts: Counts }} SiteIssuerMethodReport */
/** @typedef {{ kind: 'dca-site-resource-plan', profile: { exactPeriod: { name: string, leafBytes: number, wrapAlgorithm: string } }, localLimits: SiteLocalLimits, renders: RenderReport[], site: { counts: Counts, byIssuerMethod: SiteIssuerMethodReport[] } }} SiteResourcePlanReport */

const METHODS = ["ECDH-P256", "RSA-OAEP"];
/** @type {Record<LocalLimitName, number>} */
const LOCAL_LIMITS = {
  positionsPerWindow: MAX_POSITIONS_PER_WINDOW,
  chainMembersPerFamily: MAX_CHAIN_MEMBERS_PER_FAMILY,
  chainMembersPerMessage: MAX_CHAIN_MEMBERS_PER_MESSAGE,
  exactLeavesPerFamily: MAX_EXACT_LEAVES_PER_FAMILY,
  exactLeavesPerResponse: MAX_EXACT_LEAVES_PER_RESPONSE,
};
/** @type {CountName[]} */
const COUNT_NAMES = [
  "protectedItems",
  "contentKeyInstances",
  "contentToAccessGroupAssignments",
  "contentKeyWraps",
  "issuerRoutes",
  "directSealedCapabilities",
  "exactFamilies",
  "exactMembers",
  "exactResponseKeyCandidates",
  "chainFamilies",
  "chainMembers",
  "chainWindows",
  "projectedLeafCandidates",
  "responseKeyCandidates",
  "combinedFamilies",
  "combinedMembers",
];

/** @param {string} left @param {string} right */
function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

/**
 * @typedef {{
 *   suppliedAccessGroups?: string[],
 *   directContentKeys?: boolean,
 *   reachableContentNames?: string[],
 *   issuerMembers?: Record<string, unknown>,
 *   periodKeyDelivery?: Record<string, ('exact'|'chain')[]>,
 * }} PlannedIssuerSupply
 * @typedef {{ accessGroup: string, exactMembers?: number, chainMembers?: number, projectedLeaves?: number }} PlannedResponseFamily
 * @typedef {{ issuerName: string, directContentKeys?: number, families?: PlannedResponseFamily[] }} PlannedIssuerResponse
 * @typedef {{ issuers: PlannedIssuerResponse[] }} PlannedResponseScenario
 * @typedef {{
 *   name: string,
 *   volume?: number,
 *   items: PlannedItem[],
 *   accessGroups: PlannedAccessGroup[],
 *   issuers: PlannedIssuer[],
 *   responseScenario?: PlannedResponseScenario,
 * }} PlannedRender
 * @typedef {{
 *   positionsPerWindow?: number,
 *   chainMembersPerFamily?: number,
 *   chainMembersPerMessage?: number,
 *   exactLeavesPerFamily?: number,
 *   exactLeavesPerResponse?: number,
 * }} SiteLocalLimits
 * @typedef {{ renders: PlannedRender[], localLimits?: SiteLocalLimits }} SiteResourcePlanInput
 */

/** @returns {Counts} */
function zeroCounts() {
  return /** @type {Counts} */ (Object.fromEntries(COUNT_NAMES.map((name) => [name, 0])));
}

/** @param {Counts} target @param {Counts} source @param {number} [factor] */
function addCounts(target, source, factor = 1) {
  for (const name of COUNT_NAMES)
    target[name] = safeAdd(target[name], safeMultiply(source[name], factor));
}

/** @param {number} left @param {number} right */
function safeAdd(left, right) {
  const result = left + right;
  if (!Number.isSafeInteger(result))
    throw dcaError("bad_config", "site planning counts must remain safe integers");
  return result;
}

/** @param {number} left @param {number} right */
function safeMultiply(left, right) {
  const result = left * right;
  if (!Number.isSafeInteger(result))
    throw dcaError("bad_config", "site planning counts must remain safe integers");
  return result;
}

/** @param {unknown} value @param {string} label @param {boolean} [allowZero] */
function count(value, label, allowZero = false) {
  if (!Number.isSafeInteger(value) || /** @type {number} */ (value) < (allowZero ? 0 : 1)) {
    throw dcaError(
      "bad_config",
      `${label} is ${allowZero ? "a non-negative" : "a positive"} safe integer`,
    );
  }
  return /** @type {number} */ (value);
}

/** Refuse runtime/configuration objects before any getters or callbacks run. @param {unknown} value */
function assertPlainData(value) {
  const seen = new Set();
  /** @param {unknown} candidate @param {string} path */
  function visit(candidate, path) {
    if (candidate === null || typeof candidate === "string" || typeof candidate === "boolean")
      return;
    if (typeof candidate === "number") {
      if (!Number.isFinite(candidate)) throw dcaError("bad_config", `${path} is finite plain data`);
      return;
    }
    if (typeof candidate !== "object")
      throw dcaError("bad_config", `${path} contains only plain data`);
    if (seen.has(candidate)) throw dcaError("bad_config", `${path} is not cyclic`);
    seen.add(candidate);
    const prototype = Object.getPrototypeOf(candidate);
    if (
      (Array.isArray(candidate) && prototype !== Array.prototype) ||
      (!Array.isArray(candidate) && prototype !== Object.prototype && prototype !== null)
    ) {
      throw dcaError("bad_config", `${path} contains no runtime objects`);
    }
    if (Object.getOwnPropertySymbols(candidate).length > 0) {
      throw dcaError("bad_config", `${path} contains no symbol members`);
    }
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    if (Array.isArray(candidate)) {
      const elements = Object.keys(descriptors).filter((name) => {
        const index = Number(name);
        return (
          Number.isInteger(index) &&
          index >= 0 &&
          index < candidate.length &&
          String(index) === name
        );
      });
      if (elements.length !== candidate.length)
        throw dcaError("bad_config", `${path} is not a sparse array`);
    }
    for (const [name, descriptor] of Object.entries(descriptors)) {
      if (!Object.hasOwn(descriptor, "value"))
        throw dcaError("bad_config", `${path}.${name} is a data member`);
      if (descriptor.value === undefined)
        throw dcaError("bad_config", `${path}.${name} is defined plain data`);
      visit(descriptor.value, `${path}.${name}`);
    }
    seen.delete(candidate);
  }
  visit(value, "site plan");
}

/** @param {unknown} value @param {string} label */
function object(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw dcaError("bad_config", `${label} is an object`);
  }
  return /** @type {Record<string, unknown>} */ (value);
}

/** @param {Record<string, unknown>} value @param {string[]} allowed @param {string} label */
function members(value, allowed, label) {
  for (const name of Object.keys(value)) {
    if (!allowed.includes(name)) throw dcaError("unsupported_option", `${label} has no ${name}`);
  }
}

/** @param {unknown} value @param {string} label */
function planningName(value, label) {
  if (typeof value !== "string" || value.length === 0)
    throw dcaError("bad_config", `${label} is a non-empty string`);
  return value;
}

/** @template T @param {T[]} values @param {(value: T) => string} key @param {string} label */
function uniqueSorted(values, key, label) {
  const sorted = [...values].sort((left, right) => compareText(key(left), key(right)));
  for (let index = 1; index < sorted.length; index++) {
    if (key(sorted[index - 1]) === key(sorted[index]))
      throw dcaError("bad_config", `${label} names are unique`);
  }
  return sorted;
}

/** @param {unknown} input @returns {SiteLocalLimits} */
function localLimits(input) {
  const source = input === undefined ? {} : object(input, "localLimits");
  members(source, Object.keys(LOCAL_LIMITS), "localLimits");
  /** @type {SiteLocalLimits} */
  const result = {};
  for (const [name, protocolLimit] of /** @type {[LocalLimitName, number][]} */ (
    Object.entries(LOCAL_LIMITS)
  )) {
    if (!Object.hasOwn(source, name)) continue;
    const local = count(source[name], `localLimits.${name}`);
    if (local > protocolLimit) {
      throw dcaError(
        "bad_config",
        `localLimits.${name} may tighten ${protocolLimit}, not redefine it`,
      );
    }
    result[name] = local;
  }
  return result;
}

/** @param {string} dimension @param {string} scope @param {number} used @param {number} protocolLimit @param {number|undefined} localLimit @returns {LimitReport} */
function limit(dimension, scope, used, protocolLimit, localLimit) {
  const effectiveLimit = localLimit ?? protocolLimit;
  if (used > protocolLimit) {
    throw dcaError(
      "bad_config",
      `${scope} uses ${used} ${dimension}; the protocol maximum is ${protocolLimit}`,
    );
  }
  if (used > effectiveLimit) {
    throw dcaError(
      "bad_config",
      `${scope} uses ${used} ${dimension}; the local limit is ${effectiveLimit}`,
    );
  }
  return {
    dimension,
    scope,
    used,
    protocolLimit,
    localLimit: localLimit ?? null,
    effectiveLimit,
    remaining: effectiveLimit - used,
    limitingSource: localLimit !== undefined && localLimit < protocolLimit ? "local" : "protocol",
    binding: used === effectiveLimit,
  };
}

/** @param {LimitReport[]} limits */
function firstBindingDimension(limits) {
  if (limits.length === 0) return null;
  let selected = limits[0];
  for (const candidate of limits.slice(1)) {
    if (candidate.remaining < selected.remaining) selected = candidate;
  }
  return {
    dimension: selected.dimension,
    scope: selected.scope,
    limitingSource: selected.limitingSource,
    remaining: selected.remaining,
  };
}

/** @param {unknown} declared @param {SiteLocalLimits} limits @returns {PlannedAccessGroup[]} */
function normalizeAccessGroups(declared, limits) {
  if (!Array.isArray(declared) || declared.length === 0) {
    throw dcaError("bad_config", "a render has a non-empty accessGroups list");
  }
  return uniqueSorted(
    declared.map((entry, index) => {
      const group = object(entry, `accessGroups[${index}]`);
      members(group, ["name", "exactMembers", "chain"], `accessGroup ${index}`);
      const name = validateAccessGroup(group.name);
      const exactMembers = count(group.exactMembers, `accessGroup "${name}" exactMembers`, true);
      let chain = null;
      if (group.chain !== undefined) {
        if (exactMembers === 0) {
          throw dcaError(
            "bad_config",
            `accessGroup "${name}" needs exact members to wrap content keys for its chain route`,
          );
        }
        const source = object(group.chain, `accessGroup "${name}" chain`);
        members(
          source,
          ["chainsPerDay", "periodMinutes", "windows"],
          `accessGroup "${name}" chain`,
        );
        const geometry = inspectPeriodGeometryBounds(source.chainsPerDay, source.periodMinutes);
        if (geometry.kind !== "valid") {
          throw dcaError(
            "bad_config",
            `accessGroup "${name}" has invalid period-chain geometry (${geometry.kind})`,
          );
        }
        const windows = Array.isArray(source.windows)
          ? source.windows.map((entry, windowIndex) => {
              const window = object(entry, `accessGroup "${name}" chain.windows[${windowIndex}]`);
              members(window, ["projectedLeaves"], `accessGroup "${name}" chain window`);
              const projectedLeaves = count(
                window.projectedLeaves,
                `accessGroup "${name}" projectedLeaves`,
              );
              if (projectedLeaves > geometry.positionsPerWindow) {
                throw dcaError(
                  "bad_config",
                  `accessGroup "${name}" projects ${projectedLeaves} leaves from a ${geometry.positionsPerWindow}-position window`,
                );
              }
              return { projectedLeaves };
            })
          : (() => {
              throw dcaError("bad_config", `accessGroup "${name}" chain.windows is a list`);
            })();
        if (windows.length === 0)
          throw dcaError("bad_config", `accessGroup "${name}" chain has at least one window`);
        limit(
          "positionsPerWindow",
          `accessGroup:${name}`,
          geometry.positionsPerWindow,
          MAX_POSITIONS_PER_WINDOW,
          limits.positionsPerWindow,
        );
        limit(
          "chainMembersPerFamily",
          `accessGroup:${name}:publisherSupply`,
          windows.length,
          MAX_CHAIN_MEMBERS_PER_FAMILY,
          limits.chainMembersPerFamily,
        );
        chain = {
          chainsPerDay: /** @type {number} */ (source.chainsPerDay),
          periodMinutes: /** @type {number} */ (source.periodMinutes),
          positionsPerWindow: geometry.positionsPerWindow,
          windows,
        };
      }
      return { name, exactMembers, chain };
    }),
    (group) => group.name,
    "accessGroup",
  );
}

/** @param {unknown} declared @param {Map<string, PlannedAccessGroup>} groups @returns {PlannedItem[]} */
function normalizeItems(declared, groups) {
  if (!Array.isArray(declared) || declared.length === 0)
    throw dcaError("bad_config", "a render has a non-empty items list");
  return uniqueSorted(
    declared.map((entry, index) => {
      const item = object(entry, `items[${index}]`);
      members(item, ["name", "accessGroups", "volume"], `item ${index}`);
      const name = validateContentName(item.name);
      if (!Array.isArray(item.accessGroups) || item.accessGroups.length === 0) {
        throw dcaError("bad_config", `item "${name}" has a non-empty accessGroups list`);
      }
      const accessGroups = [...item.accessGroups].map(validateAccessGroup).sort(compareText);
      if (new Set(accessGroups).size !== accessGroups.length)
        throw dcaError("bad_config", `item "${name}" accessGroups are unique`);
      for (const accessGroup of accessGroups) {
        if (!groups.has(accessGroup))
          throw dcaError("bad_config", `item "${name}" uses unknown accessGroup "${accessGroup}"`);
      }
      return { name, accessGroups, volume: count(item.volume ?? 1, `item "${name}" volume`) };
    }),
    (item) => item.name,
    "item",
  );
}

/** @param {unknown} declared @param {PlannedAccessGroup[]} groups @param {PlannedItem[]} items @returns {PlannedIssuer[]} */
function normalizeIssuers(declared, groups, items) {
  if (!Array.isArray(declared) || declared.length === 0)
    throw dcaError("bad_config", "a render has a non-empty issuers list");
  const render = {
    accessGroups: groups.map((group) => group.name),
    items,
    contentKeyWrapStrategy: null,
  };
  const issuers = uniqueSorted(
    declared.map((entry, index) => {
      const issuer = /** @type {Record<string, unknown> & { method: string }} */ (
        object(entry, `issuers[${index}]`)
      );
      members(issuer, ["issuerName", "method", "supply"], `issuer ${index}`);
      const issuerName = validateIssuerName(issuer.issuerName);
      if (!METHODS.includes(issuer.method))
        throw dcaError("bad_config", `issuer "${issuerName}" method is ECDH-P256 or RSA-OAEP`);
      const supply = issuer.supply === undefined ? {} : issuer.supply;
      if (Object.hasOwn(object(supply, `issuer "${issuerName}" supply`), "contentKeyWrap")) {
        throw dcaError(
          "unsupported_option",
          "site planning does not accept the runtime contentKeyWrap identity",
        );
      }
      const normalized = normalizedIssuerSupplyPlan(issuerName, supply, render);
      for (const accessGroup of normalized.suppliedAccessGroups) {
        if (
          normalized.periodKeyDelivery[accessGroup].includes("chain") &&
          !groups.find((group) => group.name === accessGroup)?.chain
        ) {
          throw dcaError(
            "bad_config",
            `issuer "${issuerName}" selects chain delivery for accessGroup "${accessGroup}" without a chain plan`,
          );
        }
      }
      return {
        issuerName,
        method: /** @type {IssuerMethod} */ (issuer.method),
        supply: normalized,
      };
    }),
    (issuer) => issuer.issuerName,
    "issuer",
  );
  const completePlans = issuers.map((issuer) => ({
    ...issuer.supply,
    suppliedAccessGroups: issuer.supply.suppliedAccessGroups.filter((accessGroup) => {
      const group = /** @type {PlannedAccessGroup} */ (
        groups.find((candidate) => candidate.name === accessGroup)
      );
      return (
        group.exactMembers > 0 &&
        issuer.supply.periodKeyDelivery[accessGroup].some(
          (mode) => mode === "exact" || mode === "chain",
        )
      );
    }),
  }));
  assertCompleteIssuerRoutes(items, completePlans);
  for (const [index, issuer] of issuers.entries()) {
    const reachableItems = items.filter((item) =>
      issuer.supply.reachableContentNames.includes(item.name),
    );
    assertCompleteIssuerRoutes(reachableItems, [completePlans[index]]);
  }
  return issuers;
}

/** @param {unknown} declared @param {PlannedIssuer[]} issuers @param {Map<string, PlannedAccessGroup>} groups @returns {Map<string, ScenarioIssuer>|null} */
function scenarioByIssuer(declared, issuers, groups) {
  if (declared === undefined) return null;
  const scenario = object(declared, "responseScenario");
  members(scenario, ["issuers"], "responseScenario");
  if (!Array.isArray(scenario.issuers))
    throw dcaError("bad_config", "responseScenario.issuers is a list");
  /** @type {Map<string, ScenarioIssuer>} */
  const result = new Map();
  for (const [index, entry] of scenario.issuers.entries()) {
    const selected = /** @type {Record<string, unknown> & { families?: unknown[] }} */ (
      object(entry, `responseScenario.issuers[${index}]`)
    );
    members(
      selected,
      ["issuerName", "directContentKeys", "families"],
      `response scenario issuer ${index}`,
    );
    const issuerName = validateIssuerName(selected.issuerName);
    if (!issuers.some((issuer) => issuer.issuerName === issuerName)) {
      throw dcaError("bad_config", `response scenario names unknown issuer "${issuerName}"`);
    }
    if (result.has(issuerName))
      throw dcaError("bad_config", "response scenario issuer names are unique");
    /** @type {Map<string, FamilyCandidates>} */
    const families = new Map();
    if (!Array.isArray(selected.families ?? []))
      throw dcaError("bad_config", `response scenario issuer "${issuerName}" families is a list`);
    for (const [familyIndex, entry] of (selected.families ?? []).entries()) {
      const family = object(entry, `response scenario ${issuerName}.families[${familyIndex}]`);
      members(
        family,
        ["accessGroup", "exactMembers", "chainMembers", "projectedLeaves"],
        "response scenario family",
      );
      const accessGroup = validateAccessGroup(family.accessGroup);
      if (!groups.has(accessGroup))
        throw dcaError(
          "bad_config",
          `response scenario names unknown accessGroup "${accessGroup}"`,
        );
      if (families.has(accessGroup))
        throw dcaError("bad_config", `response scenario family "${accessGroup}" is unique`);
      families.set(accessGroup, {
        exactMembers: count(family.exactMembers ?? 0, "scenario exactMembers", true),
        chainMembers: count(family.chainMembers ?? 0, "scenario chainMembers", true),
        projectedLeaves: count(family.projectedLeaves ?? 0, "scenario projectedLeaves", true),
      });
    }
    result.set(issuerName, {
      directContentKeys: count(selected.directContentKeys ?? 0, "scenario directContentKeys", true),
      families,
    });
  }
  return result;
}

/** @param {unknown} renderInput @param {SiteLocalLimits} local @returns {RenderReport} */
function planRender(renderInput, local) {
  const input = object(renderInput, "render");
  members(
    input,
    ["name", "volume", "items", "accessGroups", "issuers", "responseScenario"],
    "render",
  );
  const name = planningName(input.name, "render.name");
  const volume = count(input.volume ?? 1, `render "${name}" volume`);
  const groups = normalizeAccessGroups(input.accessGroups, local);
  /** @type {Map<string, PlannedAccessGroup>} */
  const groupsByName = new Map(groups.map((group) => [group.name, group]));
  const items = normalizeItems(input.items, groupsByName);
  for (const group of groups) {
    if (!items.some((item) => item.accessGroups.includes(group.name))) {
      throw dcaError("bad_config", `render "${name}" declares unused accessGroup "${group.name}"`);
    }
  }
  const issuers = normalizeIssuers(input.issuers, groups, items);
  const selections = scenarioByIssuer(input.responseScenario, issuers, groupsByName);
  /** @type {'upperBound'|'scenario'} */
  const certainty = selections === null ? "upperBound" : "scenario";
  /** @type {LimitReport[]} */
  const limits = [];
  const renderCounts = zeroCounts();

  for (const item of items) {
    renderCounts.protectedItems = safeAdd(renderCounts.protectedItems, item.volume);
    renderCounts.contentKeyInstances = safeAdd(renderCounts.contentKeyInstances, item.volume);
    renderCounts.contentToAccessGroupAssignments = safeAdd(
      renderCounts.contentToAccessGroupAssignments,
      safeMultiply(item.volume, item.accessGroups.length),
    );
    for (const accessGroup of item.accessGroups) {
      renderCounts.contentKeyWraps = safeAdd(
        renderCounts.contentKeyWraps,
        safeMultiply(
          item.volume,
          /** @type {PlannedAccessGroup} */ (groupsByName.get(accessGroup)).exactMembers,
        ),
      );
    }
  }

  const itemReports = items.map((item) => ({
    name: item.name,
    accessGroups: item.accessGroups,
    volume: item.volume,
    counts: {
      protectedItems: item.volume,
      contentKeyInstances: item.volume,
      contentToAccessGroupAssignments: safeMultiply(item.volume, item.accessGroups.length),
      contentKeyWraps: item.accessGroups.reduce(
        (total, accessGroup) =>
          safeAdd(
            total,
            safeMultiply(
              item.volume,
              /** @type {PlannedAccessGroup} */ (groupsByName.get(accessGroup)).exactMembers,
            ),
          ),
        0,
      ),
      issuerRoutes: 0,
      directSealedCapabilities: 0,
    },
  }));
  /** @type {Map<string, ItemReport>} */
  const itemReportByName = new Map(itemReports.map((item) => [item.name, item]));

  const accessGroupReports = groups.map((group) => {
    const protectedItems = items
      .filter((item) => item.accessGroups.includes(group.name))
      .reduce((total, item) => safeAdd(total, item.volume), 0);
    /** @type {AccessGroupCounts} */
    const counts = {
      protectedItems,
      contentKeyInstances: protectedItems,
      contentToAccessGroupAssignments: protectedItems,
      contentKeyWraps: safeMultiply(protectedItems, group.exactMembers),
      issuerRoutes: 0,
      exactFamilies: 0,
      exactMembers: 0,
      exactResponseKeyCandidates: 0,
      chainFamilies: 0,
      chainMembers: 0,
      chainWindows: 0,
      projectedLeafCandidates: 0,
      responseKeyCandidates: 0,
      combinedFamilies: 0,
      combinedMembers: 0,
    };
    return { name: group.name, counts };
  });
  /** @type {Map<string, AccessGroupReport>} */
  const groupReports = new Map(accessGroupReports.map((group) => [group.name, group]));

  const issuerReports = issuers.map((issuer) => {
    const counts = zeroCounts();
    /** @type {Map<string, FamilyCandidates>} */
    const familyCandidates = new Map();
    if (issuer.supply.directContentKeys) {
      counts.directSealedCapabilities = renderCounts.contentKeyInstances;
      counts.issuerRoutes = renderCounts.contentKeyInstances;
      for (const item of items) {
        const report = /** @type {ItemReport} */ (itemReportByName.get(item.name)).counts;
        report.directSealedCapabilities = safeAdd(report.directSealedCapabilities, item.volume);
        report.issuerRoutes = safeAdd(report.issuerRoutes, item.volume);
      }
    }
    for (const accessGroup of issuer.supply.suppliedAccessGroups) {
      const group = /** @type {PlannedAccessGroup} */ (groupsByName.get(accessGroup));
      const modes = issuer.supply.periodKeyDelivery[accessGroup];
      const assignedItems = items
        .filter((item) => item.accessGroups.includes(accessGroup))
        .reduce((total, item) => safeAdd(total, item.volume), 0);
      const candidate = { exactMembers: 0, chainMembers: 0, projectedLeaves: 0 };
      if (modes.includes("exact") && group.exactMembers > 0) {
        counts.exactFamilies++;
        counts.exactMembers = safeAdd(counts.exactMembers, group.exactMembers);
        counts.exactResponseKeyCandidates = safeAdd(
          counts.exactResponseKeyCandidates,
          group.exactMembers,
        );
        counts.issuerRoutes = safeAdd(counts.issuerRoutes, assignedItems);
        candidate.exactMembers = group.exactMembers;
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.exactFamilies++;
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.exactMembers =
          safeAdd(
            /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.exactMembers,
            group.exactMembers,
          );
        /** @type {AccessGroupReport} */ (
          groupReports.get(accessGroup)
        ).counts.exactResponseKeyCandidates = safeAdd(
          /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts
            .exactResponseKeyCandidates,
          group.exactMembers,
        );
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.issuerRoutes =
          safeAdd(
            /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.issuerRoutes,
            assignedItems,
          );
        for (const item of items.filter((candidate) =>
          candidate.accessGroups.includes(accessGroup),
        )) {
          const report = /** @type {ItemReport} */ (itemReportByName.get(item.name)).counts;
          report.issuerRoutes = safeAdd(report.issuerRoutes, item.volume);
        }
      }
      if (modes.includes("chain")) {
        counts.chainFamilies++;
        counts.chainMembers = safeAdd(
          counts.chainMembers,
          /** @type {PlannedChainFamily} */ (group.chain).windows.length,
        );
        counts.chainWindows = safeAdd(
          counts.chainWindows,
          /** @type {PlannedChainFamily} */ (group.chain).windows.length,
        );
        counts.projectedLeafCandidates = safeAdd(
          counts.projectedLeafCandidates,
          /** @type {PlannedChainFamily} */ (group.chain).windows.reduce(
            (total, window) => safeAdd(total, window.projectedLeaves),
            0,
          ),
        );
        counts.issuerRoutes = safeAdd(counts.issuerRoutes, assignedItems);
        candidate.chainMembers = /** @type {PlannedChainFamily} */ (group.chain).windows.length;
        candidate.projectedLeaves = /** @type {PlannedChainFamily} */ (group.chain).windows.reduce(
          (total, window) => safeAdd(total, window.projectedLeaves),
          0,
        );
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.chainFamilies++;
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.chainMembers =
          safeAdd(
            /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.chainMembers,
            candidate.chainMembers,
          );
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.chainWindows =
          safeAdd(
            /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.chainWindows,
            candidate.chainMembers,
          );
        /** @type {AccessGroupReport} */ (
          groupReports.get(accessGroup)
        ).counts.projectedLeafCandidates = safeAdd(
          /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts
            .projectedLeafCandidates,
          candidate.projectedLeaves,
        );
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.issuerRoutes =
          safeAdd(
            /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.issuerRoutes,
            assignedItems,
          );
        for (const item of items.filter((candidate) =>
          candidate.accessGroups.includes(accessGroup),
        )) {
          const report = /** @type {ItemReport} */ (itemReportByName.get(item.name)).counts;
          report.issuerRoutes = safeAdd(report.issuerRoutes, item.volume);
        }
        limits.push(
          limit(
            "chainMembersPerFamily",
            `render:${name}:issuer:${issuer.issuerName}:family:${accessGroup}:supply`,
            candidate.chainMembers,
            MAX_CHAIN_MEMBERS_PER_FAMILY,
            local.chainMembersPerFamily,
          ),
        );
      }
      familyCandidates.set(accessGroup, candidate);
    }
    counts.combinedFamilies = safeAdd(counts.exactFamilies, counts.chainFamilies);
    counts.combinedMembers = safeAdd(counts.exactMembers, counts.chainMembers);
    limits.push(
      limit(
        "chainMembersPerMessage",
        `render:${name}:issuer:${issuer.issuerName}:supply`,
        counts.chainMembers,
        MAX_CHAIN_MEMBERS_PER_MESSAGE,
        local.chainMembersPerMessage,
      ),
    );

    const selectedIssuer = selections?.get(issuer.issuerName);
    const response = {
      directContentKeys: 0,
      exactMembers: 0,
      chainMembers: 0,
      projectedLeaves: 0,
      total: 0,
    };
    let projectedLeafRoom = local.exactLeavesPerResponse ?? MAX_EXACT_LEAVES_PER_RESPONSE;
    response.directContentKeys =
      selections === null
        ? counts.directSealedCapabilities
        : (selectedIssuer?.directContentKeys ?? 0);
    if (response.directContentKeys > counts.directSealedCapabilities) {
      throw dcaError(
        "bad_config",
        `response scenario for issuer "${issuer.issuerName}" selects unavailable direct content keys`,
      );
    }
    for (const accessGroup of issuer.supply.suppliedAccessGroups) {
      const candidate = /** @type {FamilyCandidates} */ (familyCandidates.get(accessGroup));
      const selected =
        selections === null
          ? {
              ...candidate,
              projectedLeaves: Math.min(
                candidate.projectedLeaves,
                local.exactLeavesPerFamily ?? MAX_EXACT_LEAVES_PER_FAMILY,
                projectedLeafRoom,
              ),
            }
          : (selectedIssuer?.families.get(accessGroup) ?? {
              exactMembers: 0,
              chainMembers: 0,
              projectedLeaves: 0,
            });
      for (const field of /** @type {ResponseFamilyField[]} */ ([
        "exactMembers",
        "chainMembers",
        "projectedLeaves",
      ])) {
        if (selected[field] > candidate[field]) {
          throw dcaError(
            "bad_config",
            `response scenario for issuer "${issuer.issuerName}" selects unavailable ${field} for "${accessGroup}"`,
          );
        }
      }
      response.exactMembers = safeAdd(response.exactMembers, selected.exactMembers);
      response.chainMembers = safeAdd(response.chainMembers, selected.chainMembers);
      response.projectedLeaves = safeAdd(response.projectedLeaves, selected.projectedLeaves);
      projectedLeafRoom -= selected.projectedLeaves;
      /** @type {AccessGroupReport} */ (
        groupReports.get(accessGroup)
      ).counts.responseKeyCandidates = safeAdd(
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts
          .responseKeyCandidates,
        safeAdd(selected.exactMembers, safeAdd(selected.chainMembers, selected.projectedLeaves)),
      );
      if (candidate.chainMembers > 0) {
        limits.push(
          limit(
            "chainMembersPerFamily",
            `render:${name}:issuer:${issuer.issuerName}:family:${accessGroup}:response`,
            selected.chainMembers,
            MAX_CHAIN_MEMBERS_PER_FAMILY,
            local.chainMembersPerFamily,
          ),
        );
        limits.push(
          limit(
            "exactLeavesPerFamily",
            `render:${name}:issuer:${issuer.issuerName}:family:${accessGroup}:response`,
            selected.projectedLeaves,
            MAX_EXACT_LEAVES_PER_FAMILY,
            local.exactLeavesPerFamily,
          ),
        );
      }
    }
    if (selectedIssuer) {
      for (const accessGroup of selectedIssuer.families.keys()) {
        if (!familyCandidates.has(accessGroup)) {
          throw dcaError(
            "bad_config",
            `response scenario selects unsupplied family "${accessGroup}" for issuer "${issuer.issuerName}"`,
          );
        }
      }
    }
    limits.push(
      limit(
        "chainMembersPerMessage",
        `render:${name}:issuer:${issuer.issuerName}:response`,
        response.chainMembers,
        MAX_CHAIN_MEMBERS_PER_MESSAGE,
        local.chainMembersPerMessage,
      ),
    );
    limits.push(
      limit(
        "exactLeavesPerResponse",
        `render:${name}:issuer:${issuer.issuerName}:response`,
        response.projectedLeaves,
        MAX_EXACT_LEAVES_PER_RESPONSE,
        local.exactLeavesPerResponse,
      ),
    );
    response.total = safeAdd(
      response.directContentKeys,
      safeAdd(response.exactMembers, safeAdd(response.chainMembers, response.projectedLeaves)),
    );
    counts.responseKeyCandidates = response.total;
    addCounts(renderCounts, counts);
    return { issuerName: issuer.issuerName, method: issuer.method, certainty, counts, response };
  });

  for (const group of groups) {
    if (group.chain) {
      limits.push(
        limit(
          "positionsPerWindow",
          `render:${name}:family:${group.name}`,
          group.chain.positionsPerWindow,
          MAX_POSITIONS_PER_WINDOW,
          local.positionsPerWindow,
        ),
      );
    }
    const reportCounts = /** @type {AccessGroupReport} */ (groupReports.get(group.name)).counts;
    reportCounts.combinedFamilies = safeAdd(reportCounts.exactFamilies, reportCounts.chainFamilies);
    reportCounts.combinedMembers = safeAdd(reportCounts.exactMembers, reportCounts.chainMembers);
  }

  limits.sort((left, right) =>
    compareText(`${left.scope}:${left.dimension}`, `${right.scope}:${right.dimension}`),
  );
  return {
    name,
    volume,
    certainty,
    counts: renderCounts,
    items: itemReports,
    accessGroups: accessGroupReports,
    issuers: issuerReports,
    limits,
    firstBindingDimension: firstBindingDimension(limits),
  };
}

/** @template T @param {T} value @returns {Readonly<T>} */
function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

/**
 * Calculate structural resource use without touching runtime or wire material.
 *
 * @param {SiteResourcePlanInput} input
 * @returns {Readonly<SiteResourcePlanReport>}
 */
export function planSiteResources(input) {
  assertPlainData(input);
  const site = object(input, "site plan");
  members(site, ["renders", "localLimits"], "site plan");
  const local = localLimits(site.localLimits);
  if (!Array.isArray(site.renders) || site.renders.length === 0) {
    throw dcaError("bad_config", "a site plan has a non-empty renders list");
  }
  const renders = uniqueSorted(
    site.renders.map((render) => planRender(render, local)),
    (render) => render.name,
    "render",
  );
  const counts = zeroCounts();
  /** @type {Map<string, SiteIssuerMethodReport>} */
  const byIssuerMethod = new Map();
  for (const render of renders) {
    addCounts(counts, render.counts, render.volume);
    for (const issuer of render.issuers) {
      const key = `${issuer.issuerName}\u0000${issuer.method}`;
      if (!byIssuerMethod.has(key)) {
        byIssuerMethod.set(key, {
          issuerName: issuer.issuerName,
          method: issuer.method,
          counts: zeroCounts(),
        });
      }
      addCounts(
        /** @type {SiteIssuerMethodReport} */ (byIssuerMethod.get(key)).counts,
        issuer.counts,
        render.volume,
      );
    }
  }
  const report = {
    kind: /** @type {const} */ ("dca-site-resource-plan"),
    profile: {
      exactPeriod: exactPeriodProfile(EXACT_PERIOD_PROFILE),
    },
    localLimits: Object.fromEntries(
      Object.entries(local).sort(([left], [right]) => compareText(left, right)),
    ),
    renders,
    site: {
      counts,
      byIssuerMethod: [...byIssuerMethod.values()].sort((left, right) =>
        compareText(`${left.issuerName}:${left.method}`, `${right.issuerName}:${right.method}`),
      ),
    },
  };
  return deepFreeze(report);
}
