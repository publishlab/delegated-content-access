// @ts-check
//
// One publisher configuration from a base configuration and a list of
// contributions. A contribution is what a selected extension adds: the seams
// it owns, a wrapper around the selected issuer supply planner, and the issuer
// config members it reads. Core decides who owns each seam and refuses two
// owners, so a host that selects two extensions which both set the render's
// wrap strategy fails when it builds the publisher, naming both.
//
// Composition runs before a Sealer exists and calls nothing it is handed: no
// clock, random, supply, sealing, strategy, planner or wrapper. Ownership
// follows from which members are present, never from asking a collaborator.
//
// Three seams have one owner each: `contentKeyWrapStrategy`, `keySealing` and
// `periodKeySupply`. The base configuration owns a seam it sets to a value; a
// core default the Sealer applies when nobody owns the seam is a fallback and
// competes with nobody. The planner is base's `issuerSupplyPlanFor` alone. A
// contribution wraps it and never replaces it, and the wrappers nest in list
// order, so the last one listed is the outermost and sees every plan inside it.
//
// Base imports no extension here. An extension validates its own values in its
// contribution factory; core checks only the contribution record and the
// generic seams.
//
// Two list-valued members let a contribution work per item without base
// learning its wire names. `itemPreparation` declares which items it gives a
// route, before the render draws anything, and prepares claims, item record
// members, issuer sealed sections and page members once the content keys are
// drawn and before the resource is signed. `itemOptionMembers` names the
// per-item options it reads; the Sealer captures them when an item is added.
// Every contribution keeps its own entries, and the Sealer refuses two
// contributions that write the same member.

import { dcaError } from "../core-shared/errors.js";
import { checkedIssuerSupplyPlanner } from "./issuerSupplyPlan.js";
import { ISSUER_CONFIG_MEMBERS } from "./publisherConfig.js";

/** The seams one owner selects for a whole publisher. */
const SEAMS = /** @type {const} */ (["contentKeyWrapStrategy", "keySealing", "periodKeySupply"]);

const CONTRIBUTION_MEMBERS = [
  "name",
  ...SEAMS,
  "issuerSupplyPlanWrapper",
  "issuerConfigMembers",
  "requiredSeams",
  "itemPreparation",
  "itemOptionMembers",
];

/** Item members base reads itself; no contribution may claim one as its option. */
const BASE_ITEM_MEMBERS = ["name", "value", "contentType", "accessGroups"];

const BASE_OWNER = "base";

/** @typedef {{ accessGroups: string[], contentNames: string[], now: Date }} PlannedRender */
/** @typedef {(issuer: any, render: PlannedRender) => any} IssuerSupplyPlanner */
/** @typedef {(inner: IssuerSupplyPlanner, issuer: any, render: PlannedRender) => any} IssuerSupplyPlanWrapper */
/** @typedef {'contentKeyWrapStrategy'|'keySealing'|'periodKeySupply'} PublisherSeam */

/**
 * What one selected extension adds to a publisher. Every member but `name` is
 * optional, and a member present as `undefined` is refused: presence is the
 * claim.
 *
 * @typedef {object} PublisherContribution
 * @property {string} name - nonempty, unique in the list and not `base`
 * @property {import('./contentKeyWrap.js').ContentKeyWrapStrategy} [contentKeyWrapStrategy]
 * @property {import('./Sealer.js').KeySealing} [keySealing]
 * @property {import('./Sealer.js').PeriodKeySupply} [periodKeySupply]
 * @property {IssuerSupplyPlanWrapper} [issuerSupplyPlanWrapper] - wraps the
 *   planner inside it; `inner` answers what the planner inside would
 * @property {string[]} [issuerConfigMembers] - issuer config members this
 *   contribution reads and validates; the Sealer receives entries without them
 * @property {PublisherSeam[]} [requiredSeams] - seams the composed
 *   configuration must have an owner for
 * @property {import('./Sealer.js').ItemPreparation} [itemPreparation] - per-item
 *   work this contribution adds to every render
 * @property {string[]} [itemOptionMembers] - per-item options this contribution
 *   reads; the Sealer and `createPublisher` admit them on each item
 */

/**
 * @typedef {object} ComposedPublisherConfig
 * @property {Readonly<Record<string, any>>} config - the Sealer configuration
 * @property {Readonly<Record<PublisherSeam, string|null>>} owners - `base`, a
 *   contribution name, or `null` where the Sealer applies its default
 * @property {readonly string[]} plannerOrder - the wrapper names, innermost first
 */

/** @param {unknown} value @returns {value is Record<string, any>} */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** @param {string} owner */
function ownerText(owner) {
  return owner === BASE_OWNER ? "the base configuration" : owner;
}

/**
 * A list member, copied and checked: nonempty strings, each once.
 *
 * @param {unknown} list
 * @param {string} name
 * @param {string} what
 * @returns {string[]}
 */
function nameList(list, name, what) {
  if (!Array.isArray(list)) throw dcaError("bad_config", `${name} lists its ${what} as a list`);
  const copy = [...list];
  for (const member of copy) {
    if (typeof member !== "string" || member === "") {
      throw dcaError("bad_config", `${name} lists ${what} as nonempty strings`);
    }
  }
  if (new Set(copy).size !== copy.length) {
    throw dcaError("bad_config", `${name} lists one of its ${what} twice`);
  }
  return copy;
}

/**
 * One contribution, read into a frozen copy.
 *
 * @param {unknown} contribution
 * @returns {Readonly<PublisherContribution & { issuerConfigMembers: string[], requiredSeams: string[], itemOptionMembers: string[] }>}
 */
function snapshotContribution(contribution) {
  if (!isRecord(contribution))
    throw dcaError("bad_config", "a publisher contribution is an object");
  for (const member of Reflect.ownKeys(contribution)) {
    if (typeof member !== "string" || !CONTRIBUTION_MEMBERS.includes(member)) {
      throw dcaError(
        "unsupported_option",
        `a publisher contribution has no ${String(member)} yet, and will not pretend to`,
      );
    }
    if (contribution[member] === undefined) {
      throw dcaError(
        "bad_config",
        `a publisher contribution omits ${member} instead of setting it to undefined`,
      );
    }
  }
  const { name } = contribution;
  if (typeof name !== "string" || name === "") {
    throw dcaError("bad_config", "a publisher contribution has a nonempty name");
  }
  if (name === BASE_OWNER) {
    throw dcaError("bad_config", `a publisher contribution is not named ${BASE_OWNER}`);
  }
  /** @type {Record<string, any>} */
  const copy = { name };
  for (const seam of SEAMS) {
    if (Object.hasOwn(contribution, seam)) copy[seam] = contribution[seam];
  }
  if (Object.hasOwn(contribution, "issuerSupplyPlanWrapper")) {
    if (typeof contribution.issuerSupplyPlanWrapper !== "function") {
      throw dcaError("bad_config", `${name} wraps the issuer supply planner with a function`);
    }
    copy.issuerSupplyPlanWrapper = contribution.issuerSupplyPlanWrapper;
  }
  copy.issuerConfigMembers = Object.hasOwn(contribution, "issuerConfigMembers")
    ? Object.freeze(nameList(contribution.issuerConfigMembers, name, "issuer config members"))
    : Object.freeze([]);
  copy.requiredSeams = Object.hasOwn(contribution, "requiredSeams")
    ? Object.freeze(nameList(contribution.requiredSeams, name, "required seams"))
    : Object.freeze([]);
  for (const seam of copy.requiredSeams) {
    if (!SEAMS.includes(seam)) {
      throw dcaError("bad_config", `${name} requires ${seam}, which is not a publisher seam`);
    }
  }
  if (Object.hasOwn(contribution, "itemPreparation")) {
    const preparation = contribution.itemPreparation;
    if (
      !isRecord(preparation) ||
      typeof preparation.routes !== "function" ||
      typeof preparation.prepare !== "function" ||
      (Object.hasOwn(preparation, "requestRelay") && typeof preparation.requestRelay !== "function")
    ) {
      throw dcaError(
        "bad_config",
        `${name} declares an item preparation as an object with routes(render) and prepare(context)`,
      );
    }
    copy.itemPreparation = Object.freeze({
      name,
      routes: preparation.routes,
      prepare: preparation.prepare,
      ...(Object.hasOwn(preparation, "requestRelay")
        ? { requestRelay: preparation.requestRelay }
        : {}),
      ...(Object.hasOwn(preparation, "envelopes")
        ? {
            envelopes: Object.freeze(
              nameList(preparation.envelopes, name, "item preparation envelopes"),
            ),
          }
        : {}),
    });
  }
  copy.itemOptionMembers = Object.hasOwn(contribution, "itemOptionMembers")
    ? Object.freeze(nameList(contribution.itemOptionMembers, name, "item option members"))
    : Object.freeze([]);
  for (const member of copy.itemOptionMembers) {
    if (BASE_ITEM_MEMBERS.includes(member)) {
      throw dcaError("bad_config", `${name} declares the item member ${member}, which base reads`);
    }
  }
  return /** @type {any} */ (Object.freeze(copy));
}

/**
 * A frozen copy of one plain configuration record: the same own members, each
 * read once and kept as enumerable as it was. Admission finds a named signing
 * kid by own membership and reads every other member by enumeration, so the
 * copy answers each check the original would have answered. Composition runs
 * no admission, so a value that is not a record stays as given for the Sealer
 * to refuse.
 *
 * @param {unknown} value
 */
function frozenRecord(value) {
  if (!isRecord(value)) return value;
  /** @type {Record<PropertyKey, unknown>} */
  const copy = {};
  for (const key of Reflect.ownKeys(value)) {
    const enumerable = Object.getOwnPropertyDescriptor(value, key)?.enumerable;
    Object.defineProperty(copy, key, { value: Reflect.get(value, key), enumerable });
  }
  return Object.freeze(copy);
}

/**
 * The base configuration, read into a copy: its own members, the issuer list,
 * each issuer entry, and the plain records inside them: the signing-key map,
 * the period and each issuer's limits. Keys and collaborators keep their
 * identity.
 *
 * @param {Record<string, any>} base
 */
function snapshotBase(base) {
  /** @type {Record<string, any>} */
  const copy = {};
  for (const name of Object.keys(base)) copy[name] = base[name];
  for (const name of ["signingKeys", "period"]) {
    if (Object.hasOwn(copy, name)) copy[name] = frozenRecord(copy[name]);
  }
  if (Array.isArray(base.issuers)) {
    copy.issuers = base.issuers.map((/** @type {unknown} */ issuer) => {
      if (!isRecord(issuer)) return issuer;
      const entry = { ...issuer };
      if (Object.hasOwn(entry, "limits")) entry.limits = frozenRecord(entry.limits);
      return Object.freeze(entry);
    });
  }
  return copy;
}

/**
 * Compose a publisher configuration from base and the selected contributions.
 * The result's `config` goes to `new Sealer(config)` or to `createPublisher`'s
 * own Sealers; the Sealer still applies its own checks to it.
 *
 * @param {Record<string, any>} base - the publisher configuration a Sealer takes;
 *   its `issuers` entries may carry members the contributions declare
 * @param {...PublisherContribution} contributions - in the order their planner
 *   wrappers nest, innermost first
 * @returns {Readonly<ComposedPublisherConfig>}
 */
export function composePublisherConfig(base, ...contributions) {
  if (!isRecord(base)) throw dcaError("bad_config", "a publisher composition takes a base object");
  for (const member of ["itemPreparations", "itemOptionMembers"]) {
    if (Object.hasOwn(base, member)) {
      throw dcaError("bad_config", `${member} comes from the selected contributions, not the base`);
    }
  }
  const config = snapshotBase(base);
  const selected = contributions.map(snapshotContribution);

  const names = new Set();
  for (const { name } of selected) {
    if (names.has(name)) {
      throw dcaError("bad_config", `the publisher contribution "${name}" is listed twice`);
    }
    names.add(name);
  }

  /** @type {Record<string, string|null>} */
  const owners = {};
  for (const seam of SEAMS) {
    owners[seam] = Object.hasOwn(config, seam) && config[seam] !== undefined ? BASE_OWNER : null;
    for (const contribution of selected) {
      if (!Object.hasOwn(contribution, seam)) continue;
      const owner = owners[seam];
      if (owner !== null) {
        throw dcaError(
          "bad_config",
          `${seam} has two owners: ${ownerText(owner)} and ${contribution.name}`,
        );
      }
      owners[seam] = contribution.name;
      config[seam] = /** @type {any} */ (contribution)[seam];
    }
  }

  for (const contribution of selected) {
    for (const seam of contribution.requiredSeams) {
      if (owners[seam] === null) {
        throw dcaError(
          "bad_config",
          `${contribution.name} needs ${seam}, and this render has no ${seam} to route through`,
        );
      }
    }
  }

  /** @type {Map<string, string>} */
  const declared = new Map();
  for (const contribution of selected) {
    for (const member of contribution.issuerConfigMembers) {
      if (ISSUER_CONFIG_MEMBERS.includes(member)) {
        throw dcaError(
          "bad_config",
          `${contribution.name} declares the issuer member ${member}, which base defines`,
        );
      }
      const other = declared.get(member);
      if (other !== undefined) {
        throw dcaError(
          "bad_config",
          `the issuer member ${member} is declared by ${other} and by ${contribution.name}`,
        );
      }
      declared.set(member, contribution.name);
    }
  }
  if (Array.isArray(config.issuers)) {
    config.issuers = Object.freeze(
      config.issuers.map((/** @type {unknown} */ issuer) => {
        if (!isRecord(issuer)) return issuer;
        /** @type {Record<string, any>} */
        const entry = {};
        for (const name of Object.keys(issuer)) {
          if (declared.has(name)) continue;
          if (!ISSUER_CONFIG_MEMBERS.includes(name)) {
            throw dcaError(
              "unsupported_option",
              `an issuer entry has no ${name} yet, and will not pretend to`,
            );
          }
          entry[name] = issuer[name];
        }
        return Object.freeze(entry);
      }),
    );
  }

  /** @type {Map<string, string>} */
  const itemOptions = new Map();
  for (const contribution of selected) {
    for (const member of contribution.itemOptionMembers) {
      const other = itemOptions.get(member);
      if (other !== undefined) {
        throw dcaError(
          "bad_config",
          `the item option ${member} is declared by ${other} and by ${contribution.name}`,
        );
      }
      itemOptions.set(member, contribution.name);
    }
  }
  if (itemOptions.size > 0) config.itemOptionMembers = Object.freeze([...itemOptions.keys()]);
  const preparations = selected.flatMap((contribution) =>
    contribution.itemPreparation === undefined ? [] : [contribution.itemPreparation],
  );
  if (preparations.length > 0) config.itemPreparations = Object.freeze(preparations);

  // Checked here even under wrappers: a wrapper calls the planner only once a
  // render asks, and would otherwise hide an unusable one until then.
  let planner = /** @type {IssuerSupplyPlanner} */ (
    checkedIssuerSupplyPlanner(config.issuerSupplyPlanFor)
  );
  /** @type {string[]} */
  const plannerOrder = [];
  for (const contribution of selected) {
    const wrapper = contribution.issuerSupplyPlanWrapper;
    if (wrapper === undefined) continue;
    const inner = planner;
    planner = (issuer, render) => wrapper(inner, issuer, render);
    plannerOrder.push(contribution.name);
  }
  config.issuerSupplyPlanFor = planner;

  return Object.freeze({
    config: Object.freeze(config),
    owners: Object.freeze(owners),
    plannerOrder: Object.freeze(plannerOrder),
  });
}
