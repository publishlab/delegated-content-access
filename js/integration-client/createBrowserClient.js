// @ts-check
// The HTML carrier wrapper over the carrier-independent delivery entry.
// A caller needing a platform report before any crypto module evaluates can
// import `browserCapabilities.js` separately.

import { requireBrowserCapabilities } from "./browserCapabilities.js";
import { createDeliveryClient } from "./createDeliveryClient.js";
import { MarkupDeliveryReader } from "../adapter-client/MarkupDeliveryReader.js";
import { dcaError } from "../core-shared/errors.js";

/**
 * @typedef {object} BrowserEntryOptions
 * @property {{ querySelectorAll: (selector: string) => any }} root
 * @property {string} issuerName
 * @property {{ post: (url: string, request: object, context: { origin: string }) => Promise<{ status: number, contentType: string|null, body?: any }> }} transport
 * @property {string|null} [unlockUrl]
 * @property {boolean} [developmentHttpOrigin]
 * @property {import("../adapter-client/DeniedUnlockCache.js").BrowserDenialCache|false} [denialCache] - Explicitly composed denial scheduling; omitted by default. Positive key retention is independent.
 * @property {boolean} [acceptDirectResponse]
 */
/** @typedef {{ clearReaderContext: () => void|Promise<void> }} ReaderReset */
/**
 * Browser setup validates recursive reset duties in addition to delivery.
 * @typedef {Omit<import("./createDeliveryClient.js").DeliveryCompositionOptions, 'cache'|'chainCache'|'resolverFactory'|'recoverySources'|'responseSections'> & {
 * cache?: import("./composeClient.js").ClientCache & ReaderReset,
 * chainCache?: NonNullable<import("./composeClient.js").ComposeClientOptions['chainCache']> & ReaderReset,
 * resolverFactory?: (options: import("./composeClient.js").ResolverOptions) => import("./createDeliveryClient.js").DeliveryResolver & ReaderReset,
 * recoverySources?: (import("../core-client/ContentKeyResolver.js").RecoverySource & ReaderReset)[],
 * responseSections?: (import("../core-client/ContentKeyResolver.js").ResponseSectionConsumer & ReaderReset)[]
 * }} BrowserCompositionOptions
 */
/** @typedef {BrowserEntryOptions & BrowserCompositionOptions} BrowserClientConfig */
/** @typedef {Omit<import("./createDeliveryClient.js").DeliveryClient, 'cache'|'resolver'> & { cache: import("./composeClient.js").ClientCache & ReaderReset, resolver: import("./createDeliveryClient.js").DeliveryResolver & ReaderReset, denialCache: import("../adapter-client/DeniedUnlockCache.js").BrowserDenialCache|null }} BrowserClient */

/** @param {BrowserClientConfig} config @returns {BrowserClient} */
export function createBrowserClient(config = /** @type {any} */ ({})) {
  if (Object.hasOwn(config, "reader"))
    throw dcaError("bad_config", "a browser client owns its reader; supply root");
  requireBrowserCapabilities();
  const { root, denialCache, ...rest } = config;
  if (
    denialCache !== undefined &&
    denialCache !== false &&
    ["capture", "deny", "invalidate", "setContext", "denyContext"].some(
      (name) => typeof (/** @type {any} */ (denialCache)?.[name]) !== "function",
    )
  )
    throw dcaError(
      "bad_config",
      "denialCache needs capture, deny, invalidate, setContext and denyContext",
    );
  if (typeof root?.querySelectorAll !== "function")
    throw dcaError("bad_config", "a browser client needs the page root it reads");
  const client = createDeliveryClient({
    reader: new MarkupDeliveryReader(root),
    ...rest,
    ...(denialCache === undefined || denialCache === false ? {} : { denialCache }),
  });
  if (typeof client.resolver.clearReaderContext !== "function")
    throw dcaError(
      "bad_config",
      "a browser resolver needs clearReaderContext for recursive cleanup",
    );
  // Validate the public caches selected by composition even when a custom
  // resolver wrapper does not expose the stock resolver's optional assertion.
  for (const cache of [client.cache, rest.chainCache])
    if (cache && typeof cache.clearReaderContext !== "function")
      throw dcaError("bad_config", "a browser retaining cache needs clearReaderContext");
  // Every owner an extension registered through composition retains reader
  // state the resolver must reach on reset, whatever resolver wraps it.
  for (const owner of [...(rest.recoverySources ?? []), ...(rest.responseSections ?? [])])
    if (typeof (/** @type {any} */ (owner)?.clearReaderContext) !== "function")
      throw dcaError("bad_config", "a registered extension owner needs clearReaderContext");
  client.resolver.assertReaderContextReset?.();
  return /** @type {BrowserClient} */ ({
    ...client,
    denialCache: denialCache === undefined || denialCache === false ? null : denialCache,
  });
}
