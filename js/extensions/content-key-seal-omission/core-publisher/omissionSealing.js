// @ts-check
//
// This extension's publisher half, as one contribution to a composed
// publisher (`core-publisher/publisherComposition.js`). It reads the per-issuer
// deployment configuration, owns the render's content-key wrap when an issuer
// is active, and wraps the selected supply planner; the sealing itself stays
// base's.
//
// The wrap is one render-wide decision: each item record's `keys` is
// emitted once, so one issuer listing this extension makes the whole render
// carry the bound wrap, including for the readers of an inactive issuer in the
// same page. A per-issuer choice of representation is not available to anyone,
// so this module selects once, before the render starts.
//
// The per-issuer plan carries the rest: an active issuer receives no
// `sealed.contentKeys` map, only the period families its own material covers,
// the marker its block leads with, and the content names it has to be able to
// reach. Base checks that last one and refuses the render before any of it
// exists, which is where the fail-closed rule lives.
//
// Core checks the contribution record: a second owner of the wrap strategy, a
// missing period-key supply, an issuer member nobody declared and an unusable
// planner are its refusals. This module checks only its own members' values.

import { validateAccessGroup, validateContentName } from "../../../core-shared/names.js";
import { dcaError } from "../../../core-shared/errors.js";
import { ordinaryContentKeyWrap } from "../../../core-publisher/contentKeyWrap.js";
import { composePublisherConfig } from "../../../core-publisher/publisherComposition.js";
import { omissionBoundCandidates } from "../core-shared--client-publisher/omissionCandidates.js";
import { recordsByName } from "../../../core-shared--client-publisher/deliveryRecords.js";
import {
  EXTENSION_NAME,
  OMISSION_BIND_IDENTIFIER,
  omissionBindAad,
} from "../core-shared/omissionBind.js";

/**
 * One item record's wrap records as the `[accessGroup, entries]` families a
 * client's view hands to the bound-candidate projection: grouped by their
 * `accessGroup` field, each entry with its `period` label as `t`.
 *
 * @param {unknown} keys - the record's `keys` collection, as published
 * @returns {[string, any[]][]}
 */
function wrapFamilies(keys) {
  /** @type {Map<string, any[]>} */
  const families = new Map();
  for (const { accessGroup, period, ...entry } of Array.isArray(keys) ? keys : []) {
    if (!families.has(accessGroup)) families.set(accessGroup, []);
    families.get(accessGroup)?.push({ ...entry, t: period });
  }
  return [...families];
}

/** The issuer config members this extension reads beside base's. */
const ISSUER_MEMBERS = Object.freeze(["extensions", "grantable", "accessGroups"]);

/**
 * Base's `IssuerConfig` plus this extension's per-issuer deployment input.
 *
 * @typedef {object} IssuerConfig
 * @property {string} issuerName
 * @property {string} keyId
 * @property {string} algorithm - 'ecdh-p256'
 * @property {CryptoKey} publicKey
 * @property {string[]} [extensions] - the extensions active for this issuer in
 *   this render. Listing `content-key-seal-omission` omits its content-key map.
 * @property {string[]} [grantable] - the contentNames this issuer must be able
 *   to grant through the route. Every item of the render by default.
 * @property {string[]} [accessGroups] - the period families this issuer's
 *   material covers. The inner supply plan must select groups explicitly.
 */

/**
 * The bound wrap, as one content-key wrap strategy. The aad is this extension's
 * own binding over the coordinate the entry sits at, and the entry carries the
 * marker that tells the two representations apart: a base reader sees an entry
 * it can describe and cannot open, and this extension refuses an entry without
 * the marker rather than trying it unbound.
 *
 * @type {import('../../../core-publisher/contentKeyWrap.js').ContentKeyWrapStrategy}
 */
export const omissionContentKeyWrap = {
  aad: (coordinate) => omissionBindAad(coordinate),
  entry: ({ t, key }) => ({ t, key, bind: OMISSION_BIND_IDENTIFIER }),
};

/**
 * One issuer's members of this extension, copied where they arrive, so a host
 * that edits a list afterwards changes neither activation nor narrowing.
 *
 * @typedef {object} DeployedIssuer
 * @property {boolean} active
 * @property {any} grantable - a copied list, or the value as given when it is none
 * @property {string[]|undefined} accessGroups - a copied list, or undefined when unrestricted
 */

/**
 * One issuer entry's extension members, checked and copied. This refuses an
 * extension name the composition does not implement rather than writing it: a
 * marker for a route no code takes would announce a profile the render does not
 * have.
 *
 * @param {IssuerConfig} issuer
 * @returns {DeployedIssuer}
 */
function deployedIssuer(issuer) {
  const copied = (/** @type {unknown} */ list) =>
    Array.isArray(list) ? /** @type {string[]} */ ([...list]) : undefined;
  const extensions = copied(issuer?.extensions);
  for (const name of extensions ?? issuer?.extensions ?? []) {
    if (name !== EXTENSION_NAME) {
      throw dcaError("bad_config", `this publisher composes no extension "${name}"`);
    }
  }
  const accessGroups = copied(issuer?.accessGroups);
  // A grantable that is no list reaches base's plan check as given, which
  // refuses it there.
  const grantable = copied(issuer?.grantable) ?? issuer?.grantable;
  for (const accessGroup of accessGroups ?? issuer?.accessGroups ?? []) {
    validateAccessGroup(accessGroup);
  }
  for (const contentName of grantable ?? []) validateContentName(contentName);
  return Object.freeze({
    active: extensions !== undefined && extensions.includes(EXTENSION_NAME),
    grantable,
    accessGroups,
  });
}

/**
 * The inner plan's per-group selections without the groups narrowing removed.
 * A group the inner plan never supplied stays, so base still refuses a
 * selection for it; a value that is no object reaches base's check as given.
 *
 * @param {Record<string, any>} selected - the inner plan
 * @param {string[]} innerGroups - the groups the inner plan supplied
 * @param {string[]} suppliedAccessGroups - those groups after narrowing
 * @returns {Record<string, unknown>}
 */
function narrowedSelections(selected, innerGroups, suppliedAccessGroups) {
  /** @type {Record<string, unknown>} */
  const narrowed = {};
  for (const member of ["periodKeyDelivery", "periodKeySourceTs"]) {
    const value = selected[member];
    if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
    narrowed[member] = Object.fromEntries(
      Object.entries(value).filter(
        ([accessGroup]) =>
          !innerGroups.includes(accessGroup) || suppliedAccessGroups.includes(accessGroup),
      ),
    );
  }
  return narrowed;
}

/**
 * This extension as one publisher contribution. Active when any issuer lists
 * the extension: it then owns the render's wrap and needs a period-key supply,
 * which base or another contribution owns. Inactive, it claims no seam, so the
 * caller's wrap strategy stays, and it still narrows each issuer by its
 * `accessGroups`.
 *
 * @param {{ issuers: IssuerConfig[] }} config - the base publisher configuration,
 *   whose `issuers` entries carry this extension's members
 * @returns {Readonly<import('../../../core-publisher/publisherComposition.js').PublisherContribution>}
 */
export function omissionContribution(config) {
  const issuers = config?.issuers;
  if (!Array.isArray(issuers) || issuers.length === 0) {
    throw dcaError("bad_config", "this composition needs at least one issuer");
  }
  /** @type {Map<string, DeployedIssuer>} */
  const deployed = new Map();
  for (const issuer of issuers) deployed.set(issuer?.issuerName, deployedIssuer(issuer));
  const active = [...deployed.values()].some((issuer) => issuer.active);

  /** @type {import('../../../core-publisher/publisherComposition.js').IssuerSupplyPlanWrapper} */
  const issuerSupplyPlanWrapper = (inner, issuer, render) => {
    const configured = deployed.get(issuer.issuerName);
    // Composition strips this extension's members from every entry, so an
    // entry added after this factory read the list would otherwise render
    // ordinary and unrestricted whatever it listed. The Sealer asks for plans
    // before its first draw, so this refusal comes before any entropy.
    if (configured === undefined) {
      throw dcaError(
        "bad_config",
        `issuer "${issuer.issuerName}" was not configured when ${EXTENSION_NAME} was selected`,
      );
    }
    const declared = inner(issuer, render);
    const selected = declared === undefined ? {} : declared;
    if (selected === null || typeof selected !== "object" || Array.isArray(selected)) {
      throw dcaError("bad_config", "a composed issuer supply plan is an object");
    }
    // `accessGroups` belongs to the issuer's deployment configuration
    // rather than to the route it takes. An issuer deployed for premium
    // alone covers premium alone whether or not it lists this extension;
    // without that, an inactive issuer beside an active one loses the
    // restriction.
    const innerGroups = selected.suppliedAccessGroups;
    if (!Array.isArray(innerGroups)) {
      throw dcaError(
        "bad_config",
        "a composed issuer supply plan supplies accessGroups as a list; an empty list supplies none",
      );
    }
    for (const accessGroup of innerGroups) {
      if (!render.accessGroups.includes(accessGroup)) {
        throw dcaError(
          "bad_config",
          `a composed issuer supply plan supplies ${JSON.stringify(accessGroup)}, which this render does not carry`,
        );
      }
    }
    const restriction = configured.accessGroups;
    const suppliedAccessGroups = render.accessGroups.filter(
      (accessGroup) =>
        innerGroups.includes(accessGroup) &&
        (restriction === undefined || restriction.includes(accessGroup)),
    );
    // A delivery or source selection names a supplied group, so it leaves
    // the plan with its group; base refuses a selection for a group the
    // plan does not supply.
    const selections = narrowedSelections(selected, innerGroups, suppliedAccessGroups);

    // An inactive issuer keeps its selected content-key names and gets no
    // marker; only its supplied groups are narrowed by deployment
    // configuration.
    if (!configured.active) return { ...selected, suppliedAccessGroups, ...selections };

    return {
      ...selected,
      suppliedAccessGroups,
      ...selections,
      contentKeyNames: [],
      reachableContentNames: Array.isArray(configured.grantable)
        ? [...configured.grantable]
        : (configured.grantable ?? render.contentNames),
      issuerMembers: {
        ...(selected.issuerMembers ?? {}),
        extensions: [EXTENSION_NAME],
      },
      // An inner plan that named a wrap keeps it, so base's own check
      // refuses a wrap this render did not select instead of this wrapper
      // replacing it unseen.
      contentKeyWrap: Object.hasOwn(selected, "contentKeyWrap")
        ? selected.contentKeyWrap
        : omissionContentKeyWrap,
    };
  };

  return Object.freeze({
    name: EXTENSION_NAME,
    issuerConfigMembers: [...ISSUER_MEMBERS],
    issuerSupplyPlanWrapper,
    itemPreparation: {
      // Omission changes existing wraps and the supply plan, so it prepares
      // no extra item fields. Its relay still belongs in the request budget.
      routes: () => [],
      prepare: async () => ({}),
      requestRelay(delivery) {
        const items = recordsByName(delivery.contentData, "contentName", () => true) ?? new Map();
        const boundCandidates = omissionBoundCandidates([...items.keys()], (name) =>
          wrapFamilies(items.get(name).keys),
        );
        return {
          members: {
            extensions: [EXTENSION_NAME],
            ...(boundCandidates.length > 0 ? { boundCandidates } : {}),
          },
        };
      },
    },
    ...(active
      ? {
          contentKeyWrapStrategy: omissionContentKeyWrap,
          requiredSeams: /** @type {['periodKeySupply']} */ (["periodKeySupply"]),
        }
      : {}),
  });
}

/**
 * The two roles a `Sealer` takes when this extension is selected, and the
 * issuer entries without this extension's members: a view of
 * `composePublisherConfig(config, omissionContribution(config))` for a host
 * that spreads them over its own configuration. A render no issuer activated
 * wraps the way base would for this configuration, the caller's strategy
 * included.
 *
 * @param {{
 *   issuers: IssuerConfig[],
 *   periodKeySupply?: object,
 *   issuerSupplyPlanFor?: Function,
 *   contentKeyWrapStrategy?: import('../../../core-publisher/contentKeyWrap.js').ContentKeyWrapStrategy,
 * }} config - the publisher configuration, as the Sealer receives it
 * @returns {{
 *   issuers: object[],
 *   contentKeyWrapStrategy: import('../../../core-publisher/contentKeyWrap.js').ContentKeyWrapStrategy,
 *   issuerSupplyPlanFor: (issuer: { issuerName: string }, render: { accessGroups: string[], contentNames: string[] }) => object,
 *   itemPreparations: readonly import('../../../core-publisher/Sealer.js').ItemPreparation[],
 * }}
 */
export function omissionSealing(config) {
  const composed = composePublisherConfig(config, omissionContribution(config)).config;
  return {
    issuers: composed.issuers,
    contentKeyWrapStrategy: composed.contentKeyWrapStrategy ?? ordinaryContentKeyWrap,
    issuerSupplyPlanFor: composed.issuerSupplyPlanFor,
    itemPreparations: composed.itemPreparations,
  };
}
