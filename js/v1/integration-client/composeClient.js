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
  "periodChainProfile",
  "clientBoundKeyCapability",
  "acceptDirectFallback",
  "persistRawPeriodKeys",
  "relayExactPeriod",
  "resolverFactory",
  "requestBuilderFactory",
  "contentDecoders",
];

/** The composition selected when the host injects no other one. */
const BASE_RESOLVER_FACTORY = (/** @type {object} */ options) => new ContentKeyResolver(options);
const BASE_REQUEST_BUILDER_FACTORY = (/** @type {object} */ options) =>
  new DcaRequestBuilder(options);

/**
 * @param {object} [config]
 * @param {any} [config.cache] - the period-key cache this client already
 *   keeps. Left out, this function builds a `PeriodKeyCache` from the cache
 *   options below, which for a host that passed none is an in-memory Map. A
 *   host that evicts by clock builds that cache itself, since `PeriodKeyCache`
 *   takes the clock together with an eviction policy.
 * @param {any} [config.storage] - what that cache is kept in
 * @param {string} [config.cacheNamespace] - the storage scope this client's
 *   period keys are filed under, when one backend serves several
 * @param {(context: { issuerName?: string, accessGroup: string }) => string} [config.cacheKeyBy] -
 *   how that cache names a family
 * @param {any} [config.chainCache] - the selected period-chain extension's
 *   cache. The resolver refuses one that arrives without a profile.
 * @param {any} [config.periodChainProfile] - that extension's response geometry
 *   and candidate source. A client that relays chain keys without caching them
 *   passes the profile alone.
 * @param {{ publicKey: JsonWebKey, openDeliveredKeys: Function }} [config.clientBoundKeyCapability] -
 *   the selected extension's client capability. Left out, this client asks for
 *   nothing but direct.
 * @param {boolean} [config.acceptDirectFallback] - whether this composition
 *   accepts direct content keys when it offered a client-bound capability
 * @param {boolean} [config.persistRawPeriodKeys] - separate permission for
 *   accepted direct period capabilities to enter this client's caches
 * @param {boolean} [config.relayExactPeriod] - whether requests relay exact
 *   period material authored for unresolved items
 * @param {(options: object) => any} [config.resolverFactory] - builds the
 *   selected resolver composition
 * @param {(options: object) => any} [config.requestBuilderFactory] - builds the
 *   selected request composition independently of the resolver
 * @param {Record<string, (bytes: Uint8Array) => Promise<Uint8Array>|Uint8Array>} [config.contentDecoders] -
 *   the representation decoders this client composition supports
 * @returns {{ cache: any, resolver: any, builder: any, opener: ContentRepresentationOpener }}
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

  const resolver = (config.resolverFactory ?? BASE_RESOLVER_FACTORY)({
    cache,
    ...(config.chainCache === undefined ? {} : { chainCache: config.chainCache }),
    ...(config.periodChainProfile === undefined
      ? {}
      : { periodChainProfile: config.periodChainProfile }),
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
  // A client with no capability asks for direct only, and says so by leaving
  // the member out: the request builder offers no public half.
  const builder = (config.requestBuilderFactory ?? BASE_REQUEST_BUILDER_FACTORY)({
    ...(config.relayExactPeriod === undefined ? {} : { relayExactPeriod: config.relayExactPeriod }),
    ...(config.clientBoundKeyCapability === undefined
      ? {}
      : { clientPublicKey: config.clientBoundKeyCapability.publicKey }),
  });
  if (typeof builder?.build !== "function") {
    throw dcaError("bad_config", "a requestBuilderFactory result needs build");
  }

  return {
    cache,
    resolver,
    builder,
    opener: new ContentRepresentationOpener(config.contentDecoders),
  };
}
