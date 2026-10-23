// @ts-check
//
// The four pieces a client composition holds for as long as the client lives:
// the period-key cache, the content-key resolver, the request builder and the
// representation opener. `demo/actors/PageLoad.js` and
// `test-lib/harnesses/client.js` each built these by hand, and
// `integration-client/createBrowserClient.js` would have been a third copy, so
// one function builds them and each caller supplies its own ports.
//
// This function reads no page, calls nothing across the wire and holds no
// per-attempt state. A caller that reads a page builds the delivery reader and
// the page view itself, as `createBrowserClient.js` does; a request and its
// response association belong to one attempt and are built there too.
//
// The option names are the ones `demo/actors/Browser.js` and
// `test-lib/harnesses/client.js` already use, so a host that configured either
// of those configures this with the same words.

import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { ContentKeyResolver } from "../core-client/ContentKeyResolver.js";
import { ContentRepresentationOpener } from "../core-client/ContentRepresentationOpener.js";
import { DcaRequestBuilder } from "../core-client/DcaRequestBuilder.js";
import { dcaError } from "../core-shared/errors.js";

const OPTIONS = [
  "cache",
  "storage",
  "cacheNamespace",
  "cacheKeyBy",
  "chainCache",
  "chainKeyProfile",
  "clientBoundKeyCapability",
  "acceptDirectFallback",
  "persistRawPeriodKeys",
  "relayPeriodKeys",
  "resolverFactory",
  "recoverySources",
  "responseSections",
  "requestBuilderFactory",
  "contentDecoders",
];

/** @typedef {NonNullable<ConstructorParameters<typeof ContentKeyResolver>[0]> & { cache: ClientCache }} ResolverOptions */
/** @typedef {NonNullable<ConstructorParameters<typeof DcaRequestBuilder>[0]>} RequestBuilderOptions */
/**
 * Only the request duties composition and delivery consume. Extensions may
 * report additional routes without coupling this entry to their implementation.
 * @typedef {object} RequestBuilder
 * @property {(page: import('../core-client/DcaData.js').DcaData, issuerName: string, needed: string[]) => { toObject: () => object }} build
 * @property {NonNullable<ResolverOptions["periodKeyResponseCoordinate"]>} [acceptsPeriodKeyResponseCoordinate]
 * @property {import("../adapter-client/routeAttempts.js").RouteProjection} [routeProjection]
 * @property {(request: object) => import("../adapter-client/routeAttempts.js").ExtensionKeyFamilies} [keyFamilies]
 */
/** @typedef {import("../core-client/ContentKeyResolver.js").Cache & { clearReaderContext?: () => void|Promise<void> }} ClientCache */
/**
 * @template R
 * @typedef {{ cache: ClientCache, resolver: R, builder: RequestBuilder, opener: ContentRepresentationOpener }} ClientComposition
 */

/**
 * @template [R=ContentKeyResolver]
 * @typedef {object} ComposeClientOptions
 * @property {ClientCache} [cache] - the period-key cache this client already
 *   keeps. Left out, this function builds a `PeriodKeyCache` from the cache
 *   options below, which for a host that passed none is an in-memory Map. A
 *   host that evicts by clock builds that cache itself, since `PeriodKeyCache`
 *   takes the clock together with an eviction policy. Passed together with
 *   `storage`, `cacheNamespace` or `cacheKeyBy`, it is refused as `bad_config`.
 * @property {import("../adapter-client/PeriodKeyCache.js").CacheStorage} [storage] - what that cache is kept in
 * @property {string} [cacheNamespace] - the storage scope this client's
 *   period keys are filed under, when one backend serves several
 * @property {(context: { issuerName?: string, accessGroup: string }) => string} [cacheKeyBy] -
 *   how that cache names a family
 * @property {NonNullable<ResolverOptions>["chainCache"] & { clearReaderContext?: () => void|Promise<void> }} [chainCache] - the selected chain-key extension's
 *   cache. The resolver refuses one that arrives without a profile.
 * @property {NonNullable<ResolverOptions>["chainKeyProfile"]} [chainKeyProfile] - that extension's response geometry
 *   and candidate source. A client that relays chain keys without caching them
 *   passes the profile alone.
 * @property {{ publicKey: JsonWebKey } & NonNullable<NonNullable<ResolverOptions>["clientBoundKeyCapability"]>} [clientBoundKeyCapability] -
 *   the selected extension's client capability. With `chainCache`, the
 *   default resolver requires its synchronous `assertCanOpenChainKeys` duty.
 *   Left out, this client asks for nothing but direct transport.
 * @property {boolean} [acceptDirectFallback] - whether this composition
 *   accepts content keys in direct representation when it offered a
 *   client-bound capability
 * @property {boolean} [persistRawPeriodKeys] - separate permission for
 *   accepted, directly delivered period keys to enter this client's caches
 * @property {boolean} [relayPeriodKeys] - whether requests relay the sealed
 *   period keys authored for unresolved items
 * @property {(options: ResolverOptions) => R} [resolverFactory] - builds the
 *   selected resolver composition
 * @property {import("../core-client/ContentKeyResolver.js").RecoverySource[]} [recoverySources] - item-key recovery owners a
 *   selected extension registers, handed to the resolver factory. Base reads
 *   none; a browser client asserts each can clear its reader context.
 * @property {import("../core-client/ContentKeyResolver.js").ResponseSectionConsumer[]} [responseSections] - response-section consumers a
 *   selected extension registers, handed to the resolver factory. Base reads
 *   none; a browser client asserts each can clear its reader context.
 * @property {(options: RequestBuilderOptions) => RequestBuilder} [requestBuilderFactory] - builds the
 *   selected request composition independently of the resolver
 * @property {Record<string, import("../core-client/ContentRepresentationOpener.js").ContentDecoder>} [contentDecoders] -
 *   the representation decoders this client composition supports
 */

/** The composition selected when the host injects no other one. */
const BASE_RESOLVER_FACTORY = (/** @type {ResolverOptions} */ options) =>
  new ContentKeyResolver(options);
/** @returns {RequestBuilder} */
const BASE_REQUEST_BUILDER_FACTORY = (/** @type {RequestBuilderOptions} */ options) =>
  new DcaRequestBuilder(options);

/**
 * @template R
 * @overload
 * @param {ComposeClientOptions<R> & { resolverFactory: (options: ResolverOptions) => R }} config
 * @returns {ClientComposition<R>}
 */
/**
 * @overload
 * @param {ComposeClientOptions} [config]
 * @returns {ClientComposition<ContentKeyResolver>}
 */
/**
 * @template R
 * @overload
 * @param {ComposeClientOptions<R>} config
 * @returns {ClientComposition<R|ContentKeyResolver>}
 */
/**
 * @param {ComposeClientOptions<object>} [config]
 * @returns {ClientComposition<object>}
 */
export function composeClient(config = {}) {
  for (const name of Object.keys(config)) {
    if (!OPTIONS.includes(name)) {
      throw dcaError(
        "unsupported_option",
        `composeClient has no ${name} yet, and will not pretend to`,
      );
    }
  }
  // A supplied cache is used as handed, so an option that would only have
  // built one says the host expected something this composition would not do.
  // A misspelled `cacheKeyBy` beside a cache would otherwise go unreported.
  if (config.cache !== undefined) {
    for (const name of ["storage", "cacheNamespace", "cacheKeyBy"]) {
      if (Object.hasOwn(config, name)) {
        throw dcaError(
          "bad_config",
          `a supplied cache is used as handed; ${name} builds a cache and cannot join it`,
        );
      }
    }
  }
  // The host names the storage scope: two clients over one backend are told
  // apart by the name it hands each. Every cache option is passed on only when
  // the host gave it, so `PeriodKeyCache` applies its own default for the rest.
  const cache =
    config.cache ??
    new PeriodKeyCache({
      ...(config.storage === undefined ? {} : { storage: config.storage }),
      ...(config.cacheNamespace === undefined ? {} : { namespace: config.cacheNamespace }),
      ...(config.cacheKeyBy === undefined ? {} : { keyBy: config.cacheKeyBy }),
    });

  for (const [name, owners] of Object.entries({
    recoverySources: config.recoverySources,
    responseSections: config.responseSections,
  }))
    if (Object.hasOwn(config, name) && !Array.isArray(owners))
      throw dcaError("bad_config", `${name} is a list of extension owners`);

  // A client with no capability asks for direct transport only, and says so
  // by leaving the member out: the request builder offers no public half.
  /** @type {RequestBuilder} */
  const builder = (config.requestBuilderFactory ?? BASE_REQUEST_BUILDER_FACTORY)({
    ...(config.relayPeriodKeys === undefined ? {} : { relayPeriodKeys: config.relayPeriodKeys }),
    ...(config.clientBoundKeyCapability === undefined
      ? {}
      : { clientPublicKey: config.clientBoundKeyCapability.publicKey }),
  });
  if (typeof builder?.build !== "function") {
    throw dcaError("bad_config", "a requestBuilderFactory result needs build");
  }

  const resolver = (config.resolverFactory ?? BASE_RESOLVER_FACTORY)({
    cache,
    ...(typeof builder.acceptsPeriodKeyResponseCoordinate !== "function"
      ? {}
      : { periodKeyResponseCoordinate: builder.acceptsPeriodKeyResponseCoordinate.bind(builder) }),
    ...(config.recoverySources === undefined ? {} : { recoverySources: config.recoverySources }),
    ...(config.responseSections === undefined ? {} : { responseSections: config.responseSections }),
    ...(config.chainCache === undefined ? {} : { chainCache: config.chainCache }),
    ...(config.chainKeyProfile === undefined ? {} : { chainKeyProfile: config.chainKeyProfile }),
    ...(config.clientBoundKeyCapability === undefined
      ? {}
      : { clientBoundKeyCapability: config.clientBoundKeyCapability }),
    ...(config.acceptDirectFallback === undefined
      ? {}
      : { acceptDirectFallback: config.acceptDirectFallback }),
    ...(config.persistRawPeriodKeys === undefined
      ? {}
      : { persistRawPeriodKeys: config.persistRawPeriodKeys }),
  });

  return {
    cache,
    resolver,
    builder,
    opener: new ContentRepresentationOpener(config.contentDecoders),
  };
}
