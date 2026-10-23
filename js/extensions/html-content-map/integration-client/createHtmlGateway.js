// @ts-check
//
// The server-side client of the `dca-profile-html-content-map` profile: a
// representation gateway that fetches a locked delivery, places the items its
// issuer grants and emits the resulting HTML (docs/spec-proposal--html-content-map.md
// Sections 2, 6 and 8). Its trusted configuration selects the profile; the
// caller only names a URL.
//
// One `reconstruct` call runs Section 6.1 with the Section 8 duties first:
//
// 1. admit the named URL under the source configuration, fetch it over HTTPS
//    and admit every redirect the same way;
// 2. parse the response with parse5 and run base structural processing
//    through the base markup reader;
// 3. verify the delivery's `resourceJWT` under the trusted registrations and
//    require the final URL's origin to equal the verified `origin`, on every
//    response, before any key is asked for, cached or not;
// 4. run the content map over the parsed tree, with a base client whose
//    reusable capability cache belongs to this caller context and the
//    registration that verified the token;
// 5. serialize the result with the HTML fragment serialization algorithm.
//
// The result names the fetched final URL as its identity. A gateway that
// caches the output keys it by that URL, never by `resourceId`, `renderId` or
// a canonical link the page names. The gateway reads the map, `dca-data` and
// ciphertext from that one response and takes no HTML from the caller.
//
// The capability cache is scoped by caller context and registration. The base
// period-key cache already files every key under the page's origin and family;
// the registration keeps two registered publishers on one origin apart, and
// the caller context keeps one caller's grant from opening an item for another
// caller whose context is mutually untrusted.
//
// A selected chain-key extension (Section 11) keeps its own retained chain
// keys, and a chain key derives period keys at or before its cutoff in its
// dated window.
// The gateway takes the chain cache the same way: a `chainCache` provider for one
// cache per caller context and registration, after the token verified. A
// static `clientOptions.chainCache` or `clientOptions.resolverFactory` would
// hand every caller one capability store, so the gateway refuses both.

import { MarkupDeliveryReader } from "../../../adapter-client/MarkupDeliveryReader.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { dcaError } from "../../../core-shared/errors.js";
import { createBrowserClient } from "../../../integration-client/createBrowserClient.js";
import { parseLockedDocument } from "../adapter-client/parse5Tree.js";
import { fetchLockedDelivery } from "../adapter-client/sourceFetch.js";
import { mapLimits } from "../core-shared--client-publisher/contentMap.js";
import {
  mapDeliveryOf,
  mapFailure,
  createContentMapSession,
  structuralFailure,
} from "../core-client/contentMapRun.js";
import {
  admitSourceUrl,
  sourceOrigin,
  sourceRefused,
  verifyResourceAssertion,
} from "../core-client/sourceProvenance.js";
import { treeDeliveryRoot } from "../core-client/treeDeliveryRoot.js";

/** The client options the gateway supplies itself and refuses from a host. */
const GATEWAY_OWNED_OPTIONS = Object.freeze([
  "cache",
  "storage",
  "cacheNamespace",
  "cacheKeyBy",
  "chainCache",
  "resolverFactory",
  "reader",
  "denialCache",
  "root",
  "transport",
  "issuerName",
  "unlockUrl",
]);

/**
 * @typedef {object} HtmlGatewayConfig
 * @property {readonly import('../core-client/sourceProvenance.js').PublisherSource[]} sources -
 *   the trusted publisher sources a caller's URL must fall under
 * @property {readonly import('../core-client/sourceProvenance.js').PublisherRegistration[]} registrations -
 *   the trusted publisher registrations and their verification keys
 * @property {import('../adapter-client/sourceFetch.js').SourceFetch} fetch -
 *   how the gateway reaches publisher sources; it follows no redirect itself
 * @property {string} issuerName - the issuer this gateway addresses
 * @property {string} issuerEndpoint - exact trusted HTTPS endpoint for this issuer and configured publishers
 * @property {(scope: {callerContext: string, registration: string}) => boolean|Promise<boolean>} admitCaller -
 *   trusted release policy, checked on every call before capability cache access
 * @property {import('../../../integration-client/createBrowserClient.js').BrowserEntryOptions['transport']} transport -
 *   how the gateway reaches that issuer, as `createBrowserClient` takes it
 * @property {(scope: { callerContext: string, registration: string }) => any} [capabilityCache] -
 *   the reusable capability cache for one scope; left out, the gateway keeps
 *   one in-memory `PeriodKeyCache` per scope
 * @property {(scope: { callerContext: string, registration: string }) => any} [chainCache] -
 *   the retained chain-key cache for one scope, for a gateway that selected
 *   the chain-key extension through `clientOptions.chainKeyProfile`;
 *   asked for once per reconstruction after the token verified, and expected to
 *   answer the same cache for the same scope. Left out, no chain cache.
 * @property {number} [maxRedirects] - left out, 5
 * @property {Partial<import('../core-shared--client-publisher/contentMap.js').MapLimits>} [limits]
 * @property {Omit<import('../../../integration-client/createBrowserClient.js').BrowserCompositionOptions, 'cache'|'storage'|'cacheNamespace'|'cacheKeyBy'|'chainCache'|'resolverFactory'|'denialCache'>} [clientOptions] -
 *   further stateless base client composition, such as `relayPeriodKeys`,
 *   `chainKeyProfile` or `requestBuilderFactory`. A cache, chain cache,
 *   resolver factory, storage, root, transport or issuer name here is refused
 *   with `bad_config`.
 */

/**
 * The gateway's answer for one call.
 *
 * @typedef {import('../core-client/contentMapRun.js').MapRunResult & {
 *   identity: string|null,
 *   html: string|null,
 * }} GatewayResult
 */

/**
 * @param {HtmlGatewayConfig} config
 * @returns {{ reconstruct: (call: { url: string, callerContext: string }) => Promise<GatewayResult> }}
 */
export function createHtmlGateway(config) {
  const {
    sources,
    registrations,
    fetch,
    issuerName,
    issuerEndpoint,
    admitCaller,
    transport,
    capabilityCache,
    chainCache,
    maxRedirects = 5,
    limits,
    clientOptions = {},
  } = config;
  if (!Array.isArray(sources) || !Array.isArray(registrations)) {
    throw dcaError("bad_config", "a gateway needs trusted sources and registrations");
  }
  if (typeof fetch !== "function") throw dcaError("bad_config", "a gateway needs a fetch");
  let endpointAdmitted = false;
  try {
    endpointAdmitted =
      typeof issuerEndpoint === "string" &&
      admitSourceUrl(issuerEndpoint, [{ origin: sourceOrigin(issuerEndpoint) }]) === issuerEndpoint;
  } catch {
    /* Invalid trusted configuration is refused below. */
  }
  if (typeof issuerName !== "string" || !issuerName.length || !endpointAdmitted) {
    throw dcaError("bad_config", "a gateway needs a trusted HTTPS issuer endpoint and alias");
  }
  if (typeof admitCaller !== "function")
    throw dcaError("bad_config", "a gateway needs an explicit caller admission policy");
  // The gateway wires these itself: a cache from clientOptions would serve
  // every caller from one capability store (Section 8). A shared denialCache
  // likewise has no per-caller owner. The root-derived reader, transport and
  // issuer come from this configuration. Refuse rather than
  // ignore, so a mistaken deployment fails at construction.
  for (const name of GATEWAY_OWNED_OPTIONS) {
    if (
      clientOptions !== null &&
      typeof clientOptions === "object" &&
      Object.hasOwn(clientOptions, name)
    ) {
      throw dcaError(
        "bad_config",
        `clientOptions.${name} is the gateway's own; capability caches are scoped per caller and registration`,
      );
    }
  }
  if (capabilityCache !== undefined && typeof capabilityCache !== "function") {
    throw dcaError("bad_config", "capabilityCache is a provider called with one caller scope");
  }
  if (chainCache !== undefined && typeof chainCache !== "function") {
    throw dcaError(
      "bad_config",
      "chainCache is a provider called with one caller scope, not a cache every caller shares",
    );
  }
  const admittedLimits = mapLimits(limits);

  /** @type {Map<string, any>} */
  const caches = new Map();
  /** @param {{ callerContext: string, registration: string }} scope */
  const cacheFor =
    capabilityCache ??
    ((scope) => {
      const key = JSON.stringify([scope.registration, scope.callerContext]);
      let cache = caches.get(key);
      if (cache === undefined) {
        cache = new PeriodKeyCache();
        caches.set(key, cache);
      }
      return cache;
    });

  /**
   * @param {{ url: string, callerContext: string }} call
   * @returns {Promise<GatewayResult>}
   */
  async function reconstruct({ url, callerContext }) {
    if (typeof callerContext !== "string" || callerContext.length === 0) {
      throw dcaError("bad_config", "a gateway call names its caller's logical client context");
    }

    let fetched;
    try {
      fetched = await fetchLockedDelivery({
        url,
        sources,
        fetch,
        maxRedirects,
        maxOctets: admittedLimits.documentOctets,
      });
    } catch (cause) {
      const failed = mapFailure(cause);
      if (failed === null) throw cause;
      return { ...failed, identity: null, html: null };
    }
    const identity = fetched.finalUrl;

    let text;
    try {
      const bytes = fetched.bytes;
      if ((bytes[0] === 0xff && bytes[1] === 0xfe) || (bytes[0] === 0xfe && bytes[1] === 0xff)) {
        throw sourceRefused("the source has a UTF-16 BOM");
      }
      const leadingBom = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
      const content = leadingBom ? bytes.subarray(3) : bytes;
      text = new globalThis.TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(content);
      if (text.startsWith("\uFEFF")) throw sourceRefused("the source has a second UTF-8 BOM");
    } catch {
      return {
        report: { outcome: "failed", failure: "source_refused" },
        reconstructed: false,
        targets: [],
        identity,
        html: null,
      };
    }
    const tree = parseLockedDocument(text);
    const root = treeDeliveryRoot(tree, fetched.finalOrigin);
    let delivery;
    try {
      const reader = new MarkupDeliveryReader(root);
      const dcaData = new DcaData(reader.dcaData, { publisherOrigin: reader.publisherOrigin });
      void dcaData.version;
      delivery = { reader, dcaData };
    } catch (cause) {
      const failed = structuralFailure(cause);
      if (failed === null) throw cause;
      return { ...failed, identity, html: null };
    }

    let verified;
    try {
      verified = await verifyResourceAssertion({
        token: delivery.dcaData.resourceJWT,
        registrations,
        finalOrigin: fetched.finalOrigin,
      });
    } catch (cause) {
      const failed = mapFailure(cause);
      if (failed === null) throw cause;
      return { ...failed, identity, html: null };
    }

    const scope = { callerContext, registration: verified.registration };
    try {
      if (!delivery.dcaData.hasIssuer(issuerName))
        throw sourceRefused("the delivery does not name the configured issuer");
      if ((await admitCaller(Object.freeze({ ...scope }))) !== true)
        throw sourceRefused("the caller context is not admitted");
    } catch {
      return {
        report: { outcome: "failed", failure: "source_refused" },
        reconstructed: false,
        targets: [],
        identity,
        html: null,
      };
    }
    const cache = cacheFor(scope);
    const scopedChain = chainCache === undefined ? {} : { chainCache: chainCache(scope) };
    const session = createContentMapSession({
      tree,
      delivery: mapDeliveryOf(delivery),
      keyClient: () =>
        createBrowserClient({
          ...clientOptions,
          ...scopedChain,
          root,
          issuerName,
          unlockUrl: issuerEndpoint,
          transport,
          cache,
        }),
      limits: admittedLimits,
    });
    const run = await session.run();
    if (!run.reconstructed) return { ...run, identity, html: null };
    try {
      const snapshot = session.snapshot();
      return { ...run, identity, ...snapshot };
    } catch (cause) {
      const failed = mapFailure(cause);
      if (failed === null) throw cause;
      return { ...failed, identity, html: null };
    }
  }

  return { reconstruct };
}
