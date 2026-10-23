import { composeClient, type ClientCache } from "../../integration-client/composeClient.js";
import {
  createDeliveryClient,
  type DeliveryResolver,
} from "../../integration-client/createDeliveryClient.js";
import { createBrowserClient } from "../../integration-client/createBrowserClient.js";
import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { DcaRequestBuilder } from "../../core-client/DcaRequestBuilder.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { ChainKeyCache } from "../../extensions/chain-keys/core-client/ChainKeyCache.js";
import { chainKeyClientProfileFor } from "../../extensions/chain-keys/core-client/chainKeyClientProfile.js";
import { ChainKeyRequestBuilder } from "../../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { createContentGroupClient } from "../../extensions/content-groups/core-client/client.js";

const basic = composeClient();
basic.resolver.resolve;
// @ts-expect-error cache has no invented method
basic.cache.invented();
// @ts-expect-error resolver has no invented method
basic.resolver.invented();
// @ts-expect-error builder has no invented method
basic.builder.invented();
// @ts-expect-error cache keys are bytes or handles
basic.cache.put("news", "261021T1200", 123);
// @ts-expect-error builders need a DcaData and string names
basic.builder.build({}, 123, [false]);
// @ts-expect-error factory must return a builder
composeClient({ requestBuilderFactory: () => ({}) });
// @ts-expect-error a builder must produce a request object
composeClient({ requestBuilderFactory: () => ({ build: () => ({ toObject: () => 123 }) }) });
declare const page: Parameters<typeof basic.builder.build>[0];
// @ts-expect-error the request document is opaque, not any
basic.builder.build(page, "issuer", ["article"]).toObject().invented();
composeClient({
  // @ts-expect-error callback result must describe key families
  requestBuilderFactory: () => ({ build: basic.builder.build, keyFamilies: () => 123 }),
});
// @ts-expect-error a factory cannot require options the entry does not pass
composeClient({ resolverFactory: (options: { invented: string }) => options });

// Independent structural collaborators: no subclass, cast or built-in fields.
const syncCache: ClientCache = {
  put(group, t, key, context) {
    void [group, t, key, context];
  },
  candidatesAt(group, t, context) {
    void [group, t, context];
    return [];
  },
  attempted(context) {
    void context.lease;
  },
};
const partial = composeClient({
  cache: syncCache,
  resolverFactory: ({ cache }) => ({ cache, custom: () => 7 }),
});
partial.resolver.custom();
// @ts-expect-error compose preserves the actual partial resolver
partial.resolver.resolve();

const syncResolver: DeliveryResolver = {
  applyResponse: () => ({ accepted: 0, errors: [], issues: [] }),
  resolve: (_page, names) => ({ covered: [], missing: names }),
  resolveDetailed: (_page, names) => ({ covered: [], missing: names, origins: [] }),
  contentKeyFor: () => null,
  contentKeyWithOriginFor: () => ({ key: null, origin: { kind: "missing" } }),
  resolveAuthenticated: (_page, names) => ({ covered: [], missing: names, origins: [] }),
};
const host = {
  reader: {
    dcaData: {},
    publisherOrigin: "https://publisher.example",
    extract: (_name: string) => null,
  },
  issuerName: "issuer",
  transport: { post: async () => ({ status: 403, contentType: null }) },
};
const delivery = createDeliveryClient({
  ...host,
  cache: syncCache,
  resolverFactory: () => syncResolver,
});
createDeliveryClient(host);
// @ts-expect-error delivery requires six duties even for a custom resolver
createDeliveryClient({ ...host, resolverFactory: () => partial.resolver });
const {
  applyResponse,
  resolve,
  resolveDetailed,
  contentKeyFor,
  contentKeyWithOriginFor,
  resolveAuthenticated,
} = syncResolver;
createDeliveryClient({
  ...host,
  // @ts-expect-error missing applyResponse
  resolverFactory: () => ({
    resolve,
    resolveDetailed,
    contentKeyFor,
    contentKeyWithOriginFor,
    resolveAuthenticated,
  }),
});
createDeliveryClient({
  ...host,
  // @ts-expect-error missing resolve
  resolverFactory: () => ({
    applyResponse,
    resolveDetailed,
    contentKeyFor,
    contentKeyWithOriginFor,
    resolveAuthenticated,
  }),
});
createDeliveryClient({
  ...host,
  // @ts-expect-error missing resolveDetailed
  resolverFactory: () => ({
    applyResponse,
    resolve,
    contentKeyFor,
    contentKeyWithOriginFor,
    resolveAuthenticated,
  }),
});
createDeliveryClient({
  ...host,
  // @ts-expect-error missing contentKeyFor
  resolverFactory: () => ({
    applyResponse,
    resolve,
    resolveDetailed,
    contentKeyWithOriginFor,
    resolveAuthenticated,
  }),
});
createDeliveryClient({
  ...host,
  // @ts-expect-error missing contentKeyWithOriginFor
  resolverFactory: () => ({
    applyResponse,
    resolve,
    resolveDetailed,
    contentKeyFor,
    resolveAuthenticated,
  }),
});
createDeliveryClient({
  ...host,
  // @ts-expect-error authenticated selection is required even without a route walk
  resolverFactory: () => ({
    applyResponse,
    resolve,
    resolveDetailed,
    contentKeyFor,
    contentKeyWithOriginFor,
  }),
});
createDeliveryClient({
  ...host,
  // @ts-expect-error invalid admitted result
  resolverFactory: () => ({ ...syncResolver, contentKeyFor: () => "key" }),
});
// @ts-expect-error delivery result retains the cache contract
delivery.cache.invented();
// @ts-expect-error delivery result retains the resolver contract
delivery.resolver.invented();
// @ts-expect-error delivery result retains the builder contract
delivery.builder.invented();

const browserHost = {
  issuerName: host.issuerName,
  transport: host.transport,
  root: { querySelectorAll: (_selector: string) => [] },
};
// @ts-expect-error browser entry owns the reader assembled from its root
createBrowserClient({ ...browserHost, reader: host.reader });
const browser = createBrowserClient(browserHost);
browser.cache.clearReaderContext();
browser.resolver.clearReaderContext();
createBrowserClient({
  ...browserHost,
  cache: { ...syncCache, clearReaderContext() {} },
  resolverFactory: () => ({ ...syncResolver, clearReaderContext() {} }),
});
// @ts-expect-error browser requires cache reset
createBrowserClient({ ...browserHost, cache: syncCache });
// @ts-expect-error browser requires resolver reset
createBrowserClient({ ...browserHost, resolverFactory: () => syncResolver });
createBrowserClient({
  ...browserHost,
  // @ts-expect-error browser requires registered recovery-owner reset
  recoverySources: [{ maxTrialsPerItem: 1, async *candidates() {} }],
});
// @ts-expect-error browser result remains typed
browser.builder.invented();

composeClient({
  chainCache: new ChainKeyCache(),
  chainKeyProfile: chainKeyClientProfileFor(),
  requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
});
const groups = createContentGroupClient({
  createPeriodKeyCache: (options) => new PeriodKeyCache(options),
  createChainKeyCache: (options) => new ChainKeyCache(options),
});
composeClient(groups.composeOptions);
createDeliveryClient({ ...host, ...groups.composeOptions });
// A custom factory receives useful options, and can construct stock owners.
composeClient({
  resolverFactory: (options) => new ContentKeyResolver(options),
  requestBuilderFactory: (options) => new DcaRequestBuilder(options),
});

// The entry consumes toObject, without requiring a built-in request instance.
const structuralBuilder = {
  build: (_page: Parameters<typeof basic.builder.build>[0], _issuer: string, _names: string[]) => ({
    toObject: () => ({ version: "1.0" }),
  }),
};
composeClient({ requestBuilderFactory: () => structuralBuilder });
createDeliveryClient({ ...host, requestBuilderFactory: () => structuralBuilder });
createDeliveryClient({
  ...host,
  // @ts-expect-error delivery also requires a builder that produces a request object
  requestBuilderFactory: () => ({ build: () => ({ toObject: () => 123 }) }),
});
// A typed application document needs no index signature or built-in class.
interface ApplicationRequest {
  version: string;
}
const applicationRequest: ApplicationRequest = { version: "1.0" };
const interfaceBuilder = { build: () => ({ toObject: () => applicationRequest }) };
composeClient({ requestBuilderFactory: () => interfaceBuilder });
createDeliveryClient({ ...host, requestBuilderFactory: () => interfaceBuilder });
createBrowserClient({ ...browserHost, ...groups.composeOptions });
createBrowserClient({
  ...browserHost,
  recoverySources: [{ maxTrialsPerItem: 1, async *candidates() {}, clearReaderContext() {} }],
});
composeClient({ storage: { get: () => undefined, set() {}, keys: () => [], remove() {} } });
composeClient({
  resolverFactory: (options) => {
    options.cache.candidatesAt("news", "261021T1200");
    return { selected: true };
  },
});
composeClient({ resolverFactory: (options: { cache: ClientCache }) => ({ cache: options.cache }) });

const responseOwner = {
  name: "custom",
  keyValues: (_section: unknown) => [],
  admit: async () => ({ accepted: 0, issues: [] }),
};
composeClient({ responseSections: [responseOwner] });
createBrowserClient({
  ...browserHost,
  responseSections: [{ ...responseOwner, clearReaderContext() {} }],
});
createBrowserClient({
  ...browserHost,
  // @ts-expect-error browser requires registered response-owner reset
  responseSections: [responseOwner],
});
// A generic with no factory cannot replace the default resolver's surface.
const honestDefault = composeClient<{ invented(): void }>({});
// @ts-expect-error the default resolver may be selected
honestDefault.resolver.invented();

// These awaited ports also accept synchronous application implementations.
const syncChains = {
  put(_group: string, _t: string, _key: Uint8Array) {},
  candidates: (_group: string, _t: string) => [],
  promote(_context: { lease: object }) {},
  attempted(_context: { lease: object }) {},
};
composeClient({ chainCache: syncChains, chainKeyProfile: chainKeyClientProfileFor() });
createBrowserClient({
  ...browserHost,
  chainCache: { ...syncChains, clearReaderContext() {} },
  chainKeyProfile: chainKeyClientProfileFor(),
});
createBrowserClient({
  ...browserHost,
  // @ts-expect-error browser requires chain-cache reset
  chainCache: syncChains,
  chainKeyProfile: chainKeyClientProfileFor(),
});
composeClient({
  clientBoundKeyCapability: {
    publicKey: {},
    openDeliveredKeys: (_transport: unknown) => ({
      open: (
        _value: unknown,
        _usages: KeyUsage[],
        _kind: "contentKey" | "periodKey" | "chainKey",
      ) => null,
    }),
  },
});

// Portable core collaborators remain compatible with assembled client contracts.
import type { MapKeyClient } from "../../extensions/html-content-map/core-client/mapItems.js";
import type { EvictionPolicy } from "../../extensions/chain-keys/core-client/ChainKeyCache.js";
import { evictAfterSixHours } from "../../adapter-client/periodKeyEviction.js";
import type { RouteProjection, ExtensionKeyFamilies } from "../../adapter-client/routeAttempts.js";
import { ContentGroupRequestBuilder } from "../../extensions/content-groups/core-client/ContentGroupRequestBuilder.js";

const mapUnlock: MapKeyClient["unlock"] = delivery.unlock;
const eviction: EvictionPolicy = evictAfterSixHours;
const groupBuilder = new ContentGroupRequestBuilder();
const projection: RouteProjection = groupBuilder.routeProjection;
const families: ExtensionKeyFamilies = groupBuilder.keyFamilies({});
void [mapUnlock, eviction, projection, families];
