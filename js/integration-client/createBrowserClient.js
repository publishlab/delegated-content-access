// @ts-check
// The HTML carrier wrapper over the carrier-independent delivery entry.
// A caller needing a platform report before any crypto module evaluates can
// import `browserCapabilities.js` separately.

import { requireBrowserCapabilities } from "./browserCapabilities.js";
import { createDeliveryClient } from "./createDeliveryClient.js";
import { MarkupDeliveryReader } from "../adapter-client/MarkupDeliveryReader.js";
import { DeniedUnlockCache } from "../adapter-client/DeniedUnlockCache.js";
import { dcaError } from "../core-shared/errors.js";

/**
 * @typedef {object} BrowserEntryOptions
 * @property {{ querySelectorAll: (selector: string) => any }} root
 * @property {string} issuerName
 * @property {{ post: (url: string, request: object, context: { origin: string }) => Promise<{ status: number, contentType: string|null, body?: any }> }} transport
 * @property {string|null} [unlockUrl]
 * @property {boolean} [developmentHttpOrigin]
 * @property {import("../adapter-client/DeniedUnlockCache.js").BrowserDenialCache|false} [denialCache] - Defaults to a ten-minute in-memory cache.
 * @property {boolean} [acceptDirectResponse]
 */
/** @typedef {BrowserEntryOptions & import("./composeClient.js").ComposeClientOptions} BrowserClientConfig */

/** @param {BrowserClientConfig} config @returns {import("./createDeliveryClient.js").DeliveryClient & { denialCache: import("../adapter-client/DeniedUnlockCache.js").BrowserDenialCache|null }} */
export function createBrowserClient(config = /** @type {any} */ ({})) {
  requireBrowserCapabilities();
  const { root, denialCache = new DeniedUnlockCache(), ...rest } = config;
  if (
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
    ...(denialCache === false ? {} : { denialCache }),
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
  return { ...client, denialCache: denialCache === false ? null : denialCache };
}
