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
  MAX_PERIOD_KEYS_PER_FAMILY,
  MAX_PERIOD_KEYS_PER_RESPONSE,
  MAX_POSITIONS_PER_WINDOW,
} from "../core-shared/geometryBounds.js";
import { PERIOD_KEY_PROFILE, periodKeyProfile } from "../core-shared/periodKeyProfiles.js";
import { assertCompleteIssuerRoutes, normalizedIssuerSupplyPlan } from "./issuerSupplyPlan.js";

/** @typedef {'ecdh-p256'|'rsa-oaep'} IssuerMethod */
/** @typedef {'periodKeyMembers'|'chainMembers'|'projectedPeriodKeys'} ResponseFamilyField */
/** @typedef {'protectedItems'|'contentKeyInstances'|'contentToAccessGroupAssignments'|'contentKeyWraps'|'issuerRoutes'|'sealedContentKeys'|'periodKeyFamilies'|'periodKeyMembers'|'periodKeyResponseCandidates'|'chainFamilies'|'chainMembers'|'chainWindows'|'projectedPeriodKeyCandidates'|'responseKeyCandidates'|'combinedFamilies'|'combinedMembers'} CountName */
/** @typedef {'positionsPerWindow'|'chainMembersPerFamily'|'chainMembersPerMessage'|'periodKeysPerFamily'|'periodKeysPerResponse'} LocalLimitName */
/** @typedef {Record<CountName, number>} Counts */
/** @typedef {{ periodKeyMembers: number, chainMembers: number, projectedPeriodKeys: number }} FamilyCandidates */
/** @typedef {{ projectedPeriodKeys: number }} PlannedChainWindow */
/** @typedef {{ chainsPerDay: number, periodMinutes: number, positionsPerWindow: number, windows: PlannedChainWindow[] }} PlannedChainFamily */
/** @typedef {{ name: string, periodKeyMembers: number, chain: PlannedChainFamily|null }} PlannedAccessGroup */
/** @typedef {{ name: string, accessGroups: string[], volume: number }} PlannedItem */
/** @typedef {import('./issuerSupplyPlan.js').IssuerSupplyPlan} IssuerSupplyPlan */
/** @typedef {{ issuerName: string, method: IssuerMethod, supply: IssuerSupplyPlan }} PlannedIssuer */
/** @typedef {{ contentKeys: number, families: Map<string, FamilyCandidates> }} ScenarioIssuer */
/** @typedef {{ protectedItems: number, contentKeyInstances: number, contentToAccessGroupAssignments: number, contentKeyWraps: number, issuerRoutes: number, sealedContentKeys: number }} ItemCounts */
/** @typedef {{ name: string, accessGroups: string[], volume: number, counts: ItemCounts }} ItemReport */
/** @typedef {{ protectedItems: number, contentKeyInstances: number, contentToAccessGroupAssignments: number, contentKeyWraps: number, issuerRoutes: number, periodKeyFamilies: number, periodKeyMembers: number, periodKeyResponseCandidates: number, chainFamilies: number, chainMembers: number, chainWindows: number, projectedPeriodKeyCandidates: number, responseKeyCandidates: number, combinedFamilies: number, combinedMembers: number }} AccessGroupCounts */
/** @typedef {{ name: string, counts: AccessGroupCounts }} AccessGroupReport */
/** @typedef {{ dimension: string, scope: string, used: number, protocolLimit: number, localLimit: number|null, effectiveLimit: number, remaining: number, limitingSource: 'local'|'protocol', binding: boolean }} LimitReport */
/** @typedef {{ issuerName: string, method: IssuerMethod, certainty: 'upperBound'|'scenario', counts: Counts, response: { contentKeys: number, periodKeyMembers: number, chainMembers: number, projectedPeriodKeys: number, total: number } }} IssuerReport */
/** @typedef {{ name: string, volume: number, certainty: 'upperBound'|'scenario', counts: Counts, items: ItemReport[], accessGroups: AccessGroupReport[], issuers: IssuerReport[], limits: LimitReport[], firstBindingDimension: { dimension: string, scope: string, limitingSource: 'local'|'protocol', remaining: number }|null }} RenderReport */
/** @typedef {{ issuerName: string, method: IssuerMethod, counts: Counts }} SiteIssuerMethodReport */
/** @typedef {{ kind: 'dca-site-resource-plan', profile: { periodKeys: { name: string, periodKeyBytes: number, wrapAlgorithm: string } }, localLimits: SiteLocalLimits, renders: RenderReport[], site: { counts: Counts, byIssuerMethod: SiteIssuerMethodReport[] } }} SiteResourcePlanReport */

const METHODS = ["ecdh-p256", "rsa-oaep"];
/** @type {Record<LocalLimitName, number>} */
const LOCAL_LIMITS = {
  positionsPerWindow: MAX_POSITIONS_PER_WINDOW,
  chainMembersPerFamily: MAX_CHAIN_MEMBERS_PER_FAMILY,
  chainMembersPerMessage: MAX_CHAIN_MEMBERS_PER_MESSAGE,
  periodKeysPerFamily: MAX_PERIOD_KEYS_PER_FAMILY,
  periodKeysPerResponse: MAX_PERIOD_KEYS_PER_RESPONSE,
};
/** @type {CountName[]} */
const COUNT_NAMES = [
  "protectedItems",
  "contentKeyInstances",
  "contentToAccessGroupAssignments",
  "contentKeyWraps",
  "issuerRoutes",
  "sealedContentKeys",
  "periodKeyFamilies",
  "periodKeyMembers",
  "periodKeyResponseCandidates",
  "chainFamilies",
  "chainMembers",
  "chainWindows",
  "projectedPeriodKeyCandidates",
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
 *   contentKeyNames: string[],
 *   suppliedAccessGroups: string[],
 *   reachableContentNames?: string[],
 *   issuerMembers?: Record<string, unknown>,
 *   periodKeyDelivery?: Record<string, ('period-keys'|'chain-keys')[]>,
 * }} PlannedIssuerSupply
 * @typedef {{ accessGroup: string, periodKeyMembers?: number, chainMembers?: number, projectedPeriodKeys?: number }} PlannedResponseFamily
 * @typedef {{ issuerName: string, contentKeys?: number, families?: PlannedResponseFamily[] }} PlannedIssuerResponse
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
 *   periodKeysPerFamily?: number,
 *   periodKeysPerResponse?: number,
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
      members(group, ["name", "periodKeyMembers", "chain"], `accessGroup ${index}`);
      const name = validateAccessGroup(group.name);
      const periodKeyMembers = count(
        group.periodKeyMembers,
        `accessGroup "${name}" periodKeyMembers`,
        true,
      );
      let chain = null;
      if (group.chain !== undefined) {
        if (periodKeyMembers === 0) {
          throw dcaError(
            "bad_config",
            `accessGroup "${name}" needs period-key members to wrap content keys for its chain route`,
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
            `accessGroup "${name}" has invalid chain geometry (${geometry.kind})`,
          );
        }
        const windows = Array.isArray(source.windows)
          ? source.windows.map((entry, windowIndex) => {
              const window = object(entry, `accessGroup "${name}" chain.windows[${windowIndex}]`);
              members(window, ["projectedPeriodKeys"], `accessGroup "${name}" chain window`);
              const projectedPeriodKeys = count(
                window.projectedPeriodKeys,
                `accessGroup "${name}" projectedPeriodKeys`,
              );
              if (projectedPeriodKeys > geometry.positionsPerWindow) {
                throw dcaError(
                  "bad_config",
                  `accessGroup "${name}" projects ${projectedPeriodKeys} period keys from a ${geometry.positionsPerWindow}-position window`,
                );
              }
              return { projectedPeriodKeys };
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
      return { name, periodKeyMembers, chain };
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
        throw dcaError("bad_config", `issuer "${issuerName}" method is ecdh-p256 or rsa-oaep`);
      // No supply means no selection, which normalizedIssuerSupplyPlan refuses
      // rather than planning every name and group.
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
          normalized.periodKeyDelivery[accessGroup].includes("chain-keys") &&
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
        group.periodKeyMembers > 0 &&
        issuer.supply.periodKeyDelivery[accessGroup].some(
          (mode) => mode === "period-keys" || mode === "chain-keys",
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
      ["issuerName", "contentKeys", "families"],
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
        ["accessGroup", "periodKeyMembers", "chainMembers", "projectedPeriodKeys"],
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
        periodKeyMembers: count(family.periodKeyMembers ?? 0, "scenario periodKeyMembers", true),
        chainMembers: count(family.chainMembers ?? 0, "scenario chainMembers", true),
        projectedPeriodKeys: count(
          family.projectedPeriodKeys ?? 0,
          "scenario projectedPeriodKeys",
          true,
        ),
      });
    }
    result.set(issuerName, {
      contentKeys: count(selected.contentKeys ?? 0, "scenario contentKeys", true),
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
          /** @type {PlannedAccessGroup} */ (groupsByName.get(accessGroup)).periodKeyMembers,
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
              /** @type {PlannedAccessGroup} */ (groupsByName.get(accessGroup)).periodKeyMembers,
            ),
          ),
        0,
      ),
      issuerRoutes: 0,
      sealedContentKeys: 0,
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
      contentKeyWraps: safeMultiply(protectedItems, group.periodKeyMembers),
      issuerRoutes: 0,
      periodKeyFamilies: 0,
      periodKeyMembers: 0,
      periodKeyResponseCandidates: 0,
      chainFamilies: 0,
      chainMembers: 0,
      chainWindows: 0,
      projectedPeriodKeyCandidates: 0,
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
    for (const item of items.filter((candidate) =>
      issuer.supply.contentKeyNames.includes(candidate.name),
    )) {
      counts.sealedContentKeys = safeAdd(counts.sealedContentKeys, item.volume);
      counts.issuerRoutes = safeAdd(counts.issuerRoutes, item.volume);
      const report = /** @type {ItemReport} */ (itemReportByName.get(item.name)).counts;
      report.sealedContentKeys = safeAdd(report.sealedContentKeys, item.volume);
      report.issuerRoutes = safeAdd(report.issuerRoutes, item.volume);
    }
    for (const accessGroup of issuer.supply.suppliedAccessGroups) {
      const group = /** @type {PlannedAccessGroup} */ (groupsByName.get(accessGroup));
      const modes = issuer.supply.periodKeyDelivery[accessGroup];
      const assignedItems = items
        .filter((item) => item.accessGroups.includes(accessGroup))
        .reduce((total, item) => safeAdd(total, item.volume), 0);
      const candidate = { periodKeyMembers: 0, chainMembers: 0, projectedPeriodKeys: 0 };
      if (modes.includes("period-keys") && group.periodKeyMembers > 0) {
        counts.periodKeyFamilies++;
        counts.periodKeyMembers = safeAdd(counts.periodKeyMembers, group.periodKeyMembers);
        counts.periodKeyResponseCandidates = safeAdd(
          counts.periodKeyResponseCandidates,
          group.periodKeyMembers,
        );
        counts.issuerRoutes = safeAdd(counts.issuerRoutes, assignedItems);
        candidate.periodKeyMembers = group.periodKeyMembers;
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.periodKeyFamilies++;
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts.periodKeyMembers =
          safeAdd(
            /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts
              .periodKeyMembers,
            group.periodKeyMembers,
          );
        /** @type {AccessGroupReport} */ (
          groupReports.get(accessGroup)
        ).counts.periodKeyResponseCandidates = safeAdd(
          /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts
            .periodKeyResponseCandidates,
          group.periodKeyMembers,
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
      if (modes.includes("chain-keys")) {
        counts.chainFamilies++;
        counts.chainMembers = safeAdd(
          counts.chainMembers,
          /** @type {PlannedChainFamily} */ (group.chain).windows.length,
        );
        counts.chainWindows = safeAdd(
          counts.chainWindows,
          /** @type {PlannedChainFamily} */ (group.chain).windows.length,
        );
        counts.projectedPeriodKeyCandidates = safeAdd(
          counts.projectedPeriodKeyCandidates,
          /** @type {PlannedChainFamily} */ (group.chain).windows.reduce(
            (total, window) => safeAdd(total, window.projectedPeriodKeys),
            0,
          ),
        );
        counts.issuerRoutes = safeAdd(counts.issuerRoutes, assignedItems);
        candidate.chainMembers = /** @type {PlannedChainFamily} */ (group.chain).windows.length;
        candidate.projectedPeriodKeys = /** @type {PlannedChainFamily} */ (
          group.chain
        ).windows.reduce((total, window) => safeAdd(total, window.projectedPeriodKeys), 0);
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
        ).counts.projectedPeriodKeyCandidates = safeAdd(
          /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts
            .projectedPeriodKeyCandidates,
          candidate.projectedPeriodKeys,
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
    counts.combinedFamilies = safeAdd(counts.periodKeyFamilies, counts.chainFamilies);
    counts.combinedMembers = safeAdd(counts.periodKeyMembers, counts.chainMembers);
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
      contentKeys: 0,
      periodKeyMembers: 0,
      chainMembers: 0,
      projectedPeriodKeys: 0,
      total: 0,
    };
    let projectedPeriodKeyRoom = local.periodKeysPerResponse ?? MAX_PERIOD_KEYS_PER_RESPONSE;
    response.contentKeys =
      selections === null ? counts.sealedContentKeys : (selectedIssuer?.contentKeys ?? 0);
    if (response.contentKeys > counts.sealedContentKeys) {
      throw dcaError(
        "bad_config",
        `response scenario for issuer "${issuer.issuerName}" selects unavailable content keys`,
      );
    }
    for (const accessGroup of issuer.supply.suppliedAccessGroups) {
      const candidate = /** @type {FamilyCandidates} */ (familyCandidates.get(accessGroup));
      const selected =
        selections === null
          ? {
              ...candidate,
              projectedPeriodKeys: Math.min(
                candidate.projectedPeriodKeys,
                local.periodKeysPerFamily ?? MAX_PERIOD_KEYS_PER_FAMILY,
                projectedPeriodKeyRoom,
              ),
            }
          : (selectedIssuer?.families.get(accessGroup) ?? {
              periodKeyMembers: 0,
              chainMembers: 0,
              projectedPeriodKeys: 0,
            });
      for (const field of /** @type {ResponseFamilyField[]} */ ([
        "periodKeyMembers",
        "chainMembers",
        "projectedPeriodKeys",
      ])) {
        if (selected[field] > candidate[field]) {
          throw dcaError(
            "bad_config",
            `response scenario for issuer "${issuer.issuerName}" selects unavailable ${field} for "${accessGroup}"`,
          );
        }
      }
      response.periodKeyMembers = safeAdd(response.periodKeyMembers, selected.periodKeyMembers);
      response.chainMembers = safeAdd(response.chainMembers, selected.chainMembers);
      response.projectedPeriodKeys = safeAdd(
        response.projectedPeriodKeys,
        selected.projectedPeriodKeys,
      );
      projectedPeriodKeyRoom -= selected.projectedPeriodKeys;
      /** @type {AccessGroupReport} */ (
        groupReports.get(accessGroup)
      ).counts.responseKeyCandidates = safeAdd(
        /** @type {AccessGroupReport} */ (groupReports.get(accessGroup)).counts
          .responseKeyCandidates,
        safeAdd(
          selected.periodKeyMembers,
          safeAdd(selected.chainMembers, selected.projectedPeriodKeys),
        ),
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
            "periodKeysPerFamily",
            `render:${name}:issuer:${issuer.issuerName}:family:${accessGroup}:response`,
            selected.projectedPeriodKeys,
            MAX_PERIOD_KEYS_PER_FAMILY,
            local.periodKeysPerFamily,
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
        "periodKeysPerResponse",
        `render:${name}:issuer:${issuer.issuerName}:response`,
        response.projectedPeriodKeys,
        MAX_PERIOD_KEYS_PER_RESPONSE,
        local.periodKeysPerResponse,
      ),
    );
    response.total = safeAdd(
      response.contentKeys,
      safeAdd(
        response.periodKeyMembers,
        safeAdd(response.chainMembers, response.projectedPeriodKeys),
      ),
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
    reportCounts.combinedFamilies = safeAdd(
      reportCounts.periodKeyFamilies,
      reportCounts.chainFamilies,
    );
    reportCounts.combinedMembers = safeAdd(
      reportCounts.periodKeyMembers,
      reportCounts.chainMembers,
    );
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
      periodKeys: periodKeyProfile(PERIOD_KEY_PROFILE),
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
