// @ts-check
//
// The browser client of the `dca-profile-html-content-map` profile. A host that
// selected the profile for this delivery calls this entry instead of opening
// items itself; a host that did not select it never calls it, and the base
// client ignores the map carrier (docs/spec-proposal--html-content-map.md Section 2:
// the carrier selects nothing by its presence).
//
// The entry composes the base browser client over the page and the content-map
// run over the same document:
//
// 1. `createBrowserClient` reads the page: base structural processing;
// 2. the run admits the map and its targets on the document as delivered;
// 3. only then does it ask the base client for keys, open the map items and
//    place them with the DOM's own setters.
//
// The profile adds no key path. Everything that reaches the issuer is the base
// request for the map items, built by the base request builder.

import { dcaError } from "../../../core-shared/errors.js";
import { createBrowserClient } from "../../../integration-client/createBrowserClient.js";
import { domTree } from "../adapter-client/domTree.js";
import {
  mapDeliveryOf,
  createContentMapSession,
  structuralFailure,
} from "../core-client/contentMapRun.js";

/**
 * @typedef {object} BrowserMapOptions
 * @property {Document} document - the page this client runs in, changed in place
 * @property {() => boolean} isEligible - host article/context lifetime check at actual placement
 * @property {Partial<import('../core-shared--client-publisher/contentMap.js').MapLimits>} [limits]
 */

/** @typedef {BrowserMapOptions & Omit<import('../../../integration-client/createBrowserClient.js').BrowserClientConfig, 'root'>} BrowserMapConfig */

/**
 * Reconstruct the protected slots of the page this client runs in.
 *
 * @param {BrowserMapConfig} config - the page, the map limits, and the
 *   `createBrowserClient` options (`issuerName`, `transport` and the rest)
 * @returns {Promise<import('../core-client/contentMapRun.js').MapRunResult>}
 */
export async function reconstructBrowserPage(config) {
  return createBrowserMapSession(config).run();
}

/**
 * Opt in to map placement and retain the session for an explicit retry.
 * A host's normal item handler can instead own placement without this wrapper.
 * @param {BrowserMapConfig} config
 * @returns {import('../core-client/contentMapRun.js').ContentMapSession}
 */
export function createBrowserMapSession(config) {
  const { document, limits, isEligible, ...clientOptions } = config;
  if (typeof isEligible !== "function")
    throw dcaError("bad_config", "browser map placement needs a host lifetime check");
  // The browser already decoded this document; it cannot recover malformed
  // source octets. Enforce its actual selected encoding without refetching.
  if (document.characterSet.toLowerCase() !== "utf-8") {
    return {
      dispose: () => {},
      run: async () => ({
        report: { outcome: "failed", failure: "source_refused" },
        reconstructed: false,
        targets: [],
      }),
      snapshot: () => {
        throw dcaError("source_refused", "the browser document is not UTF-8");
      },
    };
  }
  let client;
  try {
    client = createBrowserClient({ root: document, ...clientOptions });
    void client.dcaData.version;
  } catch (cause) {
    const failed = structuralFailure(cause);
    if (failed === null) throw cause;
    return {
      dispose: () => {},
      run: async () => ({ ...failed, report: { ...failed.report }, targets: [] }),
      snapshot: () => {
        throw dcaError("delivery_refused", "a refused delivery has no reconstructed output");
      },
    };
  }
  const opened = client;
  return createContentMapSession({
    tree: domTree(document),
    delivery: mapDeliveryOf(opened),
    keyClient: () => opened,
    isEligible,
    ...(limits === undefined ? {} : { limits }),
  });
}
