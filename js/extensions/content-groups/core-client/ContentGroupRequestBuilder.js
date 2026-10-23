// @ts-check
//
// The content-group request rides the base request flow. This builder wraps a
// completed base (or other selected) request and adds one issuer's
// content-group members for the content names the attempt still needs:
// `sealed.contentWindowSeeds`, `requestedContentGroups`, `requestedContentKeys`,
// with the page's `renderPeriod` and `periodGeometry` and an optional
// `requestedChainCutoffs`. It relays seeds and connectors exactly as the page
// carried them; the issuer admits their widths and coordinates.
//
// It also offers the two generic seams the delivery client reads without
// knowing these member names: `keyFamilies` (what the added coordinates can
// return, so a seed-only request is an eligible route under the custody
// guards) and `routeProjection` (opaque route identities, so a conditional
// retry replays only the outstanding ones).

import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { settleLimits } from "../core-shared/construction.js";
import {
  REQUEST_MEMBERS,
  SEALED_MEMBERS,
  readContentGroupRequest,
  settleNarrowing,
} from "../core-shared--client-issuer/request.js";
import {
  contentGroupRequestMembers,
  contentGroupRequestSelection,
} from "../core-shared--client-publisher/requestProjection.js";

/**
 * @typedef {{ build: Function, acceptsPeriodKeyResponseCoordinate?:
 *   (accessGroup: string, t: string, request: unknown) => boolean,
 *   keyFamilies?: (request: any) => import("../../../core-client/requestBuilderContracts.js").ExtensionKeyFamilies }} InnerRequestBuilder
 */

const OPTIONS = ["clientPublicKey", "relayPeriodKeys", "innerBuilder", "limits", "narrowing"];

/** A group route of one content name, or its item-key route. */
/** @param {string} contentName @param {string} group */
const groupRoute = (contentName, group) => JSON.stringify(["group", contentName, group]);
/** @param {string} contentName */
const itemRoute = (contentName) => JSON.stringify(["item", contentName]);

/** @param {DcaRequest|any} request */
function documentOf(request) {
  return typeof request?.toObject === "function" ? request.toObject() : request;
}

export class ContentGroupRequestBuilder {
  /** @type {InnerRequestBuilder} */
  #builder;
  /** @type {import("../core-shared/construction.js").ContentGroupLimits} */
  #limits;
  /** @type {Readonly<Record<string, any>>} */
  #narrowing;
  /** @type {WeakMap<object, ReturnType<typeof readContentGroupRequest>>} */
  #read = new WeakMap();

  /**
   * @param {object} [config]
   * @param {unknown} [config.clientPublicKey] - base option, when no innerBuilder
   * @param {boolean} [config.relayPeriodKeys] - base option, when no innerBuilder
   * @param {InnerRequestBuilder} [config.innerBuilder] - the selected request
   *   composition this one extends
   * @param {Record<string, number>} [config.limits] - trusted content-group bounds
   * @param {Record<string, unknown>} [config.narrowing] - trusted local selection:
   *   `requestedContentGroups` (content name to group list),
   *   `requestedContentKeys` (content name to the one group whose connector
   *   records this builder relays, each as an item route),
   *   `requestedChainCutoffs` (window start to cutoff),
   *   `requestedContentItems` and `seedWindows` (local only). Selection never
   *   grants entitlement and never widens an attempt's needed names.
   */
  constructor(config = {}) {
    for (const name of Object.keys(config ?? {}))
      if (!OPTIONS.includes(name))
        throw dcaError(
          "unsupported_option",
          `ContentGroupRequestBuilder has no ${name} yet, and will not pretend to`,
        );
    if (
      config.innerBuilder !== undefined &&
      (config.clientPublicKey !== undefined || config.relayPeriodKeys !== undefined)
    )
      throw dcaError(
        "bad_config",
        "a content-group request takes an innerBuilder or base request options, not both",
      );
    /** @type {InnerRequestBuilder} */
    const builder =
      config.innerBuilder ??
      new DcaRequestBuilder({
        ...(config.clientPublicKey === undefined
          ? {}
          : { clientPublicKey: config.clientPublicKey }),
        ...(config.relayPeriodKeys === undefined
          ? {}
          : { relayPeriodKeys: config.relayPeriodKeys }),
      });
    if (typeof builder?.build !== "function")
      throw dcaError("bad_config", "a content-group request innerBuilder needs build");
    this.#builder = builder;
    if (typeof builder.acceptsPeriodKeyResponseCoordinate === "function") {
      /** @type {InnerRequestBuilder["acceptsPeriodKeyResponseCoordinate"]} */
      this.acceptsPeriodKeyResponseCoordinate =
        builder.acceptsPeriodKeyResponseCoordinate.bind(builder);
    }
    try {
      this.#limits = settleLimits(config.limits);
    } catch (cause) {
      throw Object.assign(dcaError("bad_config", /** @type {Error} */ (cause).message), { cause });
    }
    this.#narrowing = settleNarrowing(config.narrowing, this.#limits);
  }

  /**
   * @param {DcaData} page
   * @param {string} issuerName
   * @param {string[]} needed - content names this attempt still needs
   * @returns {DcaRequest}
   */
  build(page, issuerName, needed) {
    if (!(page instanceof DcaData))
      throw dcaError(
        "bad_config",
        "a content-group request is built from a DcaData; construct one first",
      );
    const items = this.#narrowing.requestedContentItems;
    const candidates = items === undefined ? [...needed] : needed.filter((n) => items.includes(n));
    const inner = this.#builder.build(page, issuerName, candidates);
    const selection = contentGroupRequestSelection(
      page.toObject(),
      issuerName,
      candidates,
      this.#narrowing,
      this.#limits,
    );
    if (selection === null) return inner;
    const document = documentOf(inner);
    const { sealed } = contentGroupRequestMembers(selection);
    /** @type {Record<string, unknown>} */
    const members = contentGroupRequestMembers(selection).members;
    for (const name of Object.keys(members))
      if (
        Object.hasOwn(document, name) &&
        JSON.stringify(document[name]) !== JSON.stringify(members[name])
      )
        throw dcaError("bad_config", `the inner request already carries a different ${name}`);
    return new DcaRequest({
      ...document,
      sealed: { ...own(document, "sealed"), ...sealed },
      ...members,
    });
  }

  /**
   * One reading of a request's content-group members, by request identity.
   * @param {any} request
   */
  #view(request) {
    if (request === null || typeof request !== "object")
      return readContentGroupRequest(request, this.#limits);
    if (this.#read.has(request)) return this.#read.get(request) ?? null;
    const view = readContentGroupRequest(request, this.#limits);
    this.#read.set(request, view);
    return view;
  }

  /**
   * What this request's content-group coordinates can return: item content
   * keys for `requestedContentKeys`, derivation keys (period and chain keys)
   * for `requestedContentGroups`.
   * @param {any} request
   * @returns {import("../../../core-client/requestBuilderContracts.js").ExtensionKeyFamilies}
   */
  keyFamilies(request) {
    const view = this.#view(request);
    const inner = this.#builder.keyFamilies?.(request);
    return {
      contentKeys:
        inner?.contentKeys === true || (view !== null && Object.keys(view.contentKeys).length > 0),
      familyKeys:
        inner?.familyKeys === true || (view !== null && Object.keys(view.contentGroups).length > 0),
    };
  }

  /** @type {import("../../../core-client/requestBuilderContracts.js").RouteProjection} */
  get routeProjection() {
    return {
      members: REQUEST_MEMBERS,
      sealedMembers: SEALED_MEMBERS,
      identities: (request) => {
        const view = this.#view(request);
        if (view === null) return [];
        return [
          ...Object.entries(view.contentGroups).flatMap(([name, { groups }]) =>
            groups.map((group) => groupRoute(name, group)),
          ),
          ...Object.keys(view.contentKeys).map(itemRoute),
        ];
      },
      project: (request, routes) => {
        const view = this.#view(request);
        if (view === null) return {};
        const kept = new Set(routes);
        /** @type {Record<string, string[]>} */
        const groups = {};
        /** @type {Record<string, readonly {group: string, connector: string}[]>} */
        const contentKeys = {};
        /** @type {Record<string, Record<string, readonly string[]>>} */
        const seeds = {};
        for (const [name, entry] of Object.entries(view.contentGroups)) {
          const list = entry.groups.filter((group) => kept.has(groupRoute(name, group)));
          if (list.length === 0) continue;
          groups[name] = list;
          seeds[name] = { ...view.seeds[name] };
        }
        // An item route keeps every alternative the request carried for it.
        for (const [name, alternatives] of Object.entries(view.contentKeys)) {
          if (!kept.has(itemRoute(name))) continue;
          contentKeys[name] = alternatives.map((route) => ({ ...route }));
          seeds[name] = { ...view.seeds[name] };
        }
        if (Object.keys(seeds).length === 0) return {};
        return contentGroupRequestMembers({
          seeds,
          groups,
          contentKeys,
          cutoffs:
            view.cutoffs === undefined
              ? undefined
              : Object.entries(view.cutoffs).flatMap(([windowStart, labels]) =>
                  labels.map((cutoff) => ({ windowStart, cutoff })),
                ),
          renderPeriod: view.renderPeriod,
          periodGeometry: view.periodGeometry,
        });
      },
      useful: (route, missing) => {
        const [, contentName] = JSON.parse(route);
        return missing.includes(contentName);
      },
    };
  }
}
