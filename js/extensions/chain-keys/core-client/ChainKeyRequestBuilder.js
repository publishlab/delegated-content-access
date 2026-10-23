// @ts-check
//
// Chain-key relay is independent of chain derivation. This builder wraps a
// completed request selection, copies only the selected issuer's chain families
// needed by the unresolved items, and carries the corresponding publisher
// geometry representation without rewriting it. It resolves the shared pair
// only to filter article hints onto its grid. Invalid root geometry and raw
// chain record maxima still decide whether a family has anything to relay.
// Every chain record of a selected family travels, rivals at one cutoff too:
// each is a candidate the issuer opens on its own.

import { acceptsPeriodKeyResponseCoordinate } from "./periodKeyResponseCoordinate.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { dcaError } from "../../../core-shared/errors.js";
import { chainMemberLimit } from "../../../core-shared/chainMemberLimit.js";
import { MAX_CHAIN_MEMBERS_PER_FAMILY } from "../../../core-shared/geometryBounds.js";
import { invalidChainGeometry, resolveChainGeometry } from "../core-shared/chainKeyConstruction.js";
import { own, setOwn } from "../../../core-shared/wire.js";
import { recordsByName } from "../../../core-shared--client-publisher/deliveryRecords.js";
import { ChainKeyRequest } from "../core-shared--client-issuer/ChainKeyRequest.js";
import {
  MAX_REQUESTED_PERIODS_PER_FAMILY,
  MAX_REQUESTED_PERIODS_PER_REQUEST,
  normalizeRequestedPeriodKeys,
  requestedPeriodKeyRecords,
} from "../core-shared--client-issuer/requestedPeriodKeys.js";

/** @typedef {{ build: Function,
 * keyFamilies?: (request: any) => import("../../../core-client/requestBuilderContracts.js").ExtensionKeyFamilies,
 * routeProjection?: import("../../../core-client/requestBuilderContracts.js").RouteProjection }} InnerRequestBuilder */

const OPTIONS = ["clientPublicKey", "relayPeriodKeys", "innerBuilder", "maxChainMembersPerMessage"];

/** @param {unknown} value */
function shallowCopy(value) {
  if (Array.isArray(value)) return [...value];
  if (value !== null && typeof value === "object") return { ...value };
  return value;
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** The shared geometry is copied without interpreting any family override.
 * @param {unknown} context
 * @returns {unknown}
 */
function selectedContext(context) {
  return shallowCopy(context);
}

/**
 * Raw record counts of the selected issuer's received `sealed.chainKeys`
 * collection, read off the parsed page before any value is filtered, any
 * rival deduplicated or any family projected. The issuer block is the last
 * whole block for the name; another issuer's block is a separate collection
 * and is not read. An element that is not a record, or names no string access
 * group, names no family and counts toward neither bound, as in the carrier
 * reader.
 *
 * @param {DcaData} page
 * @param {string} issuerName
 * @returns {{ total: number, byFamily: Map<string, number> }}
 */
function rawChainMemberCounts(page, issuerName) {
  const block = recordsByName(own(page.toObject(), "issuerData"), "issuerName", () => true)?.get(
    issuerName,
  );
  const collection = own(own(block, "sealed"), "chainKeys");
  /** @type {Map<string, number>} */
  const byFamily = new Map();
  let total = 0;
  if (Array.isArray(collection)) {
    for (const element of collection) {
      const accessGroup = own(element, "accessGroup");
      if (!record(element) || typeof accessGroup !== "string") continue;
      byFamily.set(accessGroup, (byFamily.get(accessGroup) ?? 0) + 1);
      total++;
    }
  }
  return { total, byFamily };
}

export class ChainKeyRequestBuilder {
  /** @type {InnerRequestBuilder} */
  #builder;
  /** @type {number} */
  #maxChainMembersPerMessage;

  /**
   * @param {object} [config]
   * @param {unknown} [config.clientPublicKey]
   * @param {boolean} [config.relayPeriodKeys]
   * @param {number} [config.maxChainMembersPerMessage] - trusted relay capacity, default 16
   * @param {InnerRequestBuilder} [config.innerBuilder]
   */
  constructor(config = {}) {
    this.#maxChainMembersPerMessage = chainMemberLimit(config?.maxChainMembersPerMessage);
    for (const name of Object.keys(config ?? {})) {
      if (!OPTIONS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `ChainKeyRequestBuilder has no ${name} yet, and will not pretend to`,
        );
      }
    }
    if (
      config?.innerBuilder !== undefined &&
      (config?.clientPublicKey !== undefined || config?.relayPeriodKeys !== undefined)
    ) {
      throw dcaError(
        "bad_config",
        "a chain-key request takes an innerBuilder or base request options, not both",
      );
    }
    /** @type {InnerRequestBuilder} */
    const builder =
      config?.innerBuilder ??
      new DcaRequestBuilder({
        ...(config?.clientPublicKey === undefined
          ? {}
          : { clientPublicKey: config.clientPublicKey }),
        ...(config?.relayPeriodKeys === undefined
          ? {}
          : { relayPeriodKeys: config.relayPeriodKeys }),
      });
    if (typeof builder?.build !== "function") {
      throw dcaError("bad_config", "a chain-key request innerBuilder needs build");
    }
    this.#builder = builder;
    // The wrapper adds stock chain coordinates without taking ownership of
    // the selected inner builder's delivery-client extension contracts.
    if (typeof builder.keyFamilies === "function") {
      this.keyFamilies = builder.keyFamilies.bind(builder);
    }
    this.routeProjection = builder.routeProjection;
  }

  /** Admit period projections from the immutable request, independently of derivation.
   * @param {string} accessGroup
   * @param {string} t
   * @param {unknown} request
   * @returns {boolean}
   */
  acceptsPeriodKeyResponseCoordinate(accessGroup, t, request) {
    return acceptsPeriodKeyResponseCoordinate(
      accessGroup,
      t,
      request,
      this.#maxChainMembersPerMessage,
    );
  }

  /**
   * @param {DcaData} page
   * @param {string} issuerName
   * @param {string[]} needed
   * @returns {ChainKeyRequest|import('../../../core-shared--client-issuer/DcaRequest.js').DcaRequest}
   */
  build(page, issuerName, needed) {
    if (!(page instanceof DcaData)) {
      throw dcaError(
        "bad_config",
        "a chain-key request is built from a DcaData; construct one first",
      );
    }
    const request = this.#builder.build(page, issuerName, needed);

    // A rejected delivery map supplies no geometry to any chain family, so
    // this delivery has no chain member to relay. Forwarding the map would
    // make a selecting issuer refuse the whole request, base sections too.
    const context = own(page.toObject(), "periodGeometry");
    if (invalidChainGeometry(context)) return request;

    // The trusted total capacity and fixed per-family bound apply to the whole
    // received collection. Counting after projection would accept an over-limit subset.
    const raw = rawChainMemberCounts(page, issuerName);
    if (raw.total > this.#maxChainMembersPerMessage) return request;

    /** @type {Record<string, unknown>[]} */
    const chainKeys = [];
    /** @type {string[]} */
    const selectedGroups = [];
    /** @type {Record<string, Set<string>>} */
    const requestedByGroup = {};
    const seen = new Set();
    for (const contentName of needed) {
      for (const accessGroup of page.accessGroupsFor(contentName)) {
        const chains = page.sealedChainKeysFor(issuerName, accessGroup);
        if (!Array.isArray(chains) || chains.length === 0) continue;
        if ((raw.byFamily.get(accessGroup) ?? 0) > MAX_CHAIN_MEMBERS_PER_FAMILY) continue;
        if (!seen.has(accessGroup)) {
          seen.add(accessGroup);
          // Relay defined members of every candidate without selecting a rival.
          for (const { accessGroup, cutoff, key } of chains)
            chainKeys.push({ accessGroup, cutoff, key });
          selectedGroups.push(accessGroup);
        }
        let labels = own(requestedByGroup, accessGroup);
        if (labels === undefined) {
          labels = new Set();
          setOwn(requestedByGroup, accessGroup, labels);
        }
        const geometry = resolveChainGeometry(context, accessGroup);
        const family = geometry === null ? { kind: "absent" } : { kind: "valid", geometry };
        for (const entry of page.sealedEntriesFor(contentName, accessGroup)) {
          if (typeof entry?.t !== "string") continue;
          try {
            normalizeRequestedPeriodKeys([{ accessGroup, periods: [entry.t] }], () => family);
            labels.add(entry.t);
          } catch {
            // A malformed or off-grid cached wrap label cannot become an
            // issuer hint. Missing/malformed geometry remains the issuer
            // family's failure scope; the relay never supplies defaults.
          }
        }
      }
    }

    if (selectedGroups.length === 0) return request;
    /** @type {{ accessGroup: string, periods: string[] }[]} */
    const rawRequestedPeriodKeys = [];
    // The selector is bounded independently of the authored wraps. A caller
    // needing more targets may make another request; this attempt chooses a
    // deterministic subset without enlarging the protocol input maxima.
    let remaining = MAX_REQUESTED_PERIODS_PER_REQUEST;
    for (const accessGroup of [...selectedGroups].sort()) {
      const labels = own(requestedByGroup, accessGroup);
      if (!labels?.size || remaining === 0) continue;
      const selected = [...labels]
        .sort()
        .slice(0, Math.min(MAX_REQUESTED_PERIODS_PER_FAMILY, remaining));
      rawRequestedPeriodKeys.push({ accessGroup, periods: selected });
      remaining -= selected.length;
    }
    const requestedPeriodKeys =
      rawRequestedPeriodKeys.length === 0
        ? []
        : requestedPeriodKeyRecords(
            normalizeRequestedPeriodKeys(rawRequestedPeriodKeys, () => ({ kind: "absent" })),
          );
    return ChainKeyRequest.fromRequest(request, {
      periodGeometry: selectedContext(context),
      chainKeys,
      ...(requestedPeriodKeys.length === 0 ? {} : { requestedPeriodKeys }),
    });
  }
}

/** Browser/PageLoad-compatible factory for relay without chain derivation. */
export function chainKeyRequestBuilderFactory(options = {}) {
  return new ChainKeyRequestBuilder(options);
}
