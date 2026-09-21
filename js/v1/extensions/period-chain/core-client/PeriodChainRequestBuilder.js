// @ts-check
//
// Period-chain relay is independent of chain derivation. This builder wraps a
// completed request selection, copies only the selected issuer's chain families
// needed by the unresolved items, and carries the corresponding publisher
// geometry representation without interpreting it.

import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own, setOwn } from "../../../core-shared/wire.js";
import { PeriodChainRequest } from "../core-shared--client-issuer/PeriodChainRequest.js";

const OPTIONS = ["clientPublicKey", "relayExactPeriod", "innerBuilder"];

/** @param {unknown} value */
function shallowCopy(value) {
  if (Array.isArray(value)) return [...value];
  if (value !== null && typeof value === "object") return { ...value };
  return value;
}

/**
 * Preserve the document's representation for the selected families. Fixed
 * document defaults remain defaults; complete family overrides remain
 * overrides. Malformed applicable values travel as written for the issuer to
 * reject rather than being repaired or inferred by the relay.
 *
 * @param {DcaData} page
 * @param {string[]} accessGroups
 * @returns {unknown}
 */
function selectedContext(page, accessGroups) {
  const context = own(page.toObject(), "periodChain");
  if (
    context === undefined ||
    context === null ||
    typeof context !== "object" ||
    Array.isArray(context)
  ) {
    return context;
  }

  /** @type {Record<string, unknown>} */
  const selected = {};
  for (const member of ["chainsPerDay", "periodMinutes"]) {
    if (Object.hasOwn(context, member)) setOwn(selected, member, own(context, member));
  }

  const overrides = own(context, "accessGroups");
  if (overrides !== undefined) {
    if (overrides === null || typeof overrides !== "object" || Array.isArray(overrides)) {
      setOwn(selected, "accessGroups", shallowCopy(overrides));
    } else {
      /** @type {Record<string, unknown>} */
      const selectedOverrides = {};
      for (const accessGroup of accessGroups) {
        if (Object.hasOwn(overrides, accessGroup)) {
          setOwn(selectedOverrides, accessGroup, shallowCopy(own(overrides, accessGroup)));
        }
      }
      if (Object.keys(selectedOverrides).length > 0)
        setOwn(selected, "accessGroups", selectedOverrides);
    }
  }
  return selected;
}

export class PeriodChainRequestBuilder {
  /** @type {{ build: Function }} */
  #builder;

  /**
   * @param {object} [config]
   * @param {unknown} [config.clientPublicKey]
   * @param {boolean} [config.relayExactPeriod]
   * @param {{ build: Function }} [config.innerBuilder]
   */
  constructor(config = {}) {
    for (const name of Object.keys(config ?? {})) {
      if (!OPTIONS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `PeriodChainRequestBuilder has no ${name} yet, and will not pretend to`,
        );
      }
    }
    if (
      config?.innerBuilder !== undefined &&
      (config?.clientPublicKey !== undefined || config?.relayExactPeriod !== undefined)
    ) {
      throw dcaError(
        "bad_config",
        "a period-chain request takes an innerBuilder or base request options, not both",
      );
    }
    const builder =
      config?.innerBuilder ??
      new DcaRequestBuilder({
        ...(config?.clientPublicKey === undefined
          ? {}
          : { clientPublicKey: config.clientPublicKey }),
        ...(config?.relayExactPeriod === undefined
          ? {}
          : { relayExactPeriod: config.relayExactPeriod }),
      });
    if (typeof builder?.build !== "function") {
      throw dcaError("bad_config", "a period-chain request innerBuilder needs build");
    }
    this.#builder = builder;
  }

  /**
   * @param {DcaData} page
   * @param {string} issuerName
   * @param {string[]} needed
   * @returns {PeriodChainRequest|import('../../../core-shared--client-issuer/DcaRequest.js').DcaRequest}
   */
  build(page, issuerName, needed) {
    if (!(page instanceof DcaData)) {
      throw dcaError(
        "bad_config",
        "a period-chain request is built from a DcaData; construct one first",
      );
    }
    const request = this.#builder.build(page, issuerName, needed);

    /** @type {Record<string, Record<string, string>>} */
    const periodChainKeys = {};
    /** @type {string[]} */
    const selectedGroups = [];
    const seen = new Set();
    for (const contentName of needed) {
      for (const accessGroup of page.accessGroupsFor(contentName)) {
        if (seen.has(accessGroup)) continue;
        seen.add(accessGroup);
        const chains = page.sealedPeriodChainKeysFor(issuerName, accessGroup);
        if (chains === null || typeof chains !== "object" || Array.isArray(chains)) continue;
        setOwn(periodChainKeys, accessGroup, { .../** @type {any} */ (chains) });
        selectedGroups.push(accessGroup);
      }
    }

    if (selectedGroups.length === 0) return request;
    return PeriodChainRequest.fromRequest(request, {
      periodChain: selectedContext(page, selectedGroups),
      periodChainKeys,
    });
  }
}

/** Browser/PageLoad-compatible factory for relay without chain derivation. */
export function periodChainRequestBuilderFactory(options = {}) {
  return new PeriodChainRequestBuilder(options);
}
