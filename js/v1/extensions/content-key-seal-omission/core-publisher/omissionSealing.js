// @ts-check
//
// This extension's publisher half, as the two roles `core-publisher/Sealer.js`
// takes. It reads the per-issuer deployment configuration and answers the base
// issuer entries plus those two roles; the sealing itself stays base's.
//
// The wrap is one render-wide decision: `contentData[contentName].keys` is
// emitted once, so one issuer listing this extension makes the whole render
// carry the bound wrap, including for the readers of an inactive issuer in the
// same page. A per-issuer choice of representation is not available to anyone,
// so this module selects once, before the render starts.
//
// The per-issuer plan carries the rest: an active issuer receives no direct
// content-key map, only the period families its own material covers, the
// marker its block leads with, and the content names it has to be able to
// reach. Base checks that last one and refuses the render before any of it
// exists, which is where the fail-closed rule lives.

import { validateAccessGroup, validateContentName } from "../../../core-shared/names.js";
import { dcaError } from "../../../core-shared/errors.js";
import { ordinaryContentKeyWrap } from "../../../core-publisher/contentKeyWrap.js";
import { checkedIssuerSupplyPlanner } from "../../../core-publisher/issuerSupplyPlan.js";
import {
  EXTENSION_NAME,
  OMISSION_BIND_VERSION,
  omissionBindAad,
} from "../core-shared/omissionBind.js";

/** The base issuer members, and the three this extension reads beside them. */
const BASE_ISSUER_MEMBERS = ["issuerName", "keyId", "algorithm", "publicKey", "unlockUrl"];
const ISSUER_MEMBERS = [...BASE_ISSUER_MEMBERS, "extensions", "grantable", "accessGroups"];

/**
 * Base's `IssuerConfig` plus this extension's per-issuer deployment input.
 *
 * @typedef {object} IssuerConfig
 * @property {string} issuerName
 * @property {string} keyId
 * @property {string} algorithm - 'ECDH-P256'
 * @property {CryptoKey} publicKey
 * @property {string} unlockUrl
 * @property {string[]} [extensions] - the extensions active for this issuer in
 *   this render. Listing `content-key-seal-omission` omits its direct map.
 * @property {string[]} [grantable] - the contentNames this issuer must be able
 *   to grant through the route. Every item of the render by default.
 * @property {string[]} [accessGroups] - the period families this issuer's
 *   material covers. Every group of the render by default, which is base's rule.
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
  entry: ({ t, nonce, key }) => ({ t, nonce, key, bind: OMISSION_BIND_VERSION }),
};

/** @param {IssuerConfig} issuer */
function isActive(issuer) {
  return Array.isArray(issuer.extensions) && issuer.extensions.includes(EXTENSION_NAME);
}

/**
 * What a `Sealer` is composed with when this extension is selected: the issuer
 * entries with this extension's members read off them, and the two roles.
 *
 * @param {{ issuers: IssuerConfig[], periodKeySupply?: object, issuerSupplyPlanFor?: Function }} config - the
 *   publisher configuration, as the Sealer receives it
 * @returns {{
 *   issuers: object[],
 *   contentKeyWrapStrategy: import('../../../core-publisher/contentKeyWrap.js').ContentKeyWrapStrategy,
 *   issuerSupplyPlanFor: (issuer: { issuerName: string }, render: { accessGroups: string[], contentNames: string[] }) => object,
 * }}
 */
export function omissionSealing(config) {
  const issuers = config?.issuers;
  if (!Array.isArray(issuers) || issuers.length === 0) {
    throw dcaError("bad_config", "this composition needs at least one issuer");
  }
  for (const issuer of issuers) checkIssuer(issuer, config?.periodKeySupply);
  // Base owns the planner seam and its refusal, in `core-publisher/issuerSupplyPlan.js`.
  // The inner planner is checked here rather than by base, because base sees
  // the wrapper below and never the planner this composition was handed.
  const innerPlanFor = checkedIssuerSupplyPlanner(config.issuerSupplyPlanFor);

  /** @type {Map<string, IssuerConfig>} */
  const deployed = new Map();
  for (const issuer of issuers) deployed.set(issuer.issuerName, issuer);
  const activeCount = issuers.filter(isActive).length;

  return {
    issuers: issuers.map((issuer) => {
      /** @type {Record<string, any>} */
      const entry = {};
      for (const name of BASE_ISSUER_MEMBERS) {
        if (Object.hasOwn(issuer, name)) entry[name] = /** @type {any} */ (issuer)[name];
      }
      return entry;
    }),
    // One representation for the render, chosen before it starts. A render
    // no issuer activated wraps the way base wraps, so an inactive deployment
    // stays byte for byte where it was.
    contentKeyWrapStrategy: activeCount === 0 ? ordinaryContentKeyWrap : omissionContentKeyWrap,
    issuerSupplyPlanFor: (issuer, render) => {
      const configured = deployed.get(issuer.issuerName);
      const declared = innerPlanFor(issuer, render);
      const selected = declared === undefined ? {} : declared;
      if (selected === null || typeof selected !== "object" || Array.isArray(selected)) {
        throw dcaError("bad_config", "a composed issuer supply plan is an object");
      }
      // `accessGroups` belongs to the issuer's deployment configuration
      // rather than to the route it takes. An issuer deployed for premium
      // alone covers premium alone whether or not it lists this extension;
      // without that, an inactive issuer beside an active one loses the
      // restriction.
      const restricted = Array.isArray(configured?.accessGroups);
      const innerGroups = Object.hasOwn(selected, "suppliedAccessGroups")
        ? selected.suppliedAccessGroups
        : render.accessGroups;
      if (!Array.isArray(innerGroups)) {
        throw dcaError(
          "bad_config",
          "a composed issuer supply plan supplies accessGroups as a list",
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
      const suppliedAccessGroups = render.accessGroups.filter(
        (accessGroup) =>
          innerGroups.includes(accessGroup) &&
          (!restricted || configured?.accessGroups?.includes(accessGroup)),
      );

      // An inactive issuer gets the ordinary direct delivery and no marker:
      // the plan says nothing beyond the groups this issuer was configured for.
      if (!configured || !isActive(configured)) {
        return Object.hasOwn(selected, "suppliedAccessGroups") || restricted
          ? { ...selected, suppliedAccessGroups }
          : selected;
      }

      return {
        ...selected,
        suppliedAccessGroups,
        directContentKeys: false,
        reachableContentNames: configured.grantable ?? render.contentNames,
        issuerMembers: {
          ...(selected.issuerMembers ?? {}),
          extensions: [EXTENSION_NAME],
        },
        contentKeyWrap: omissionContentKeyWrap,
      };
    },
  };
}

/**
 * One issuer entry, checked where it arrives. This refuses an extension name
 * the composition does not implement rather than writing it: a marker for a
 * route no code takes would announce a profile the render does not have.
 *
 * @param {IssuerConfig} issuer
 * @param {object|undefined} periodKeySupply
 * @returns {void}
 */
function checkIssuer(issuer, periodKeySupply) {
  for (const name of Object.keys(issuer ?? {})) {
    if (!ISSUER_MEMBERS.includes(name)) {
      throw dcaError(
        "unsupported_option",
        `an issuer entry has no ${name} yet, and will not pretend to`,
      );
    }
  }
  for (const name of issuer.extensions ?? []) {
    if (name !== EXTENSION_NAME) {
      throw dcaError("bad_config", `this publisher composes no extension "${name}"`);
    }
  }
  for (const accessGroup of issuer.accessGroups ?? []) validateAccessGroup(accessGroup);
  for (const contentName of issuer.grantable ?? []) validateContentName(contentName);
  if (isActive(issuer) && periodKeySupply === undefined) {
    throw dcaError(
      "bad_config",
      `issuer "${issuer.issuerName}" lists ${EXTENSION_NAME} and this render has no periodKeySupply to route through`,
    );
  }
}
