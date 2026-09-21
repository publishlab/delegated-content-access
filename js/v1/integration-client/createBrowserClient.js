// @ts-check
//
// One page, one issuer, one unlock attempt: what a browser client does on an
// article that carries sealed content. A host hands this entry the page root,
// the issuer it addresses and the transport that reaches that issuer, and gets
// back the pieces it reads the page through plus an `unlock` call.
//
// `requireBrowserCapabilities()` is the first statement this entry runs. On the
// browser page this entry serves, the one API that goes missing is
// `crypto.subtle`, which a plain-HTTP page does not carry; `TextEncoder`,
// `atob` and the rest are there wherever ES modules run. `cryptoProvider.js`
// reads `globalThis.crypto` when it evaluates and takes `subtle` off it, so on
// such a page the import chain below evaluates without a throw and the probe is
// the first thing that names the gap. A host that wants the refusal before any
// module evaluates imports `browserCapabilities.js` alone in a first script; it
// reads no global itself.
//
// `unlock` is one attempt against one issuer. It walks no route list, consults
// no circuit breaker and reads no status other than 200: a caller that wants a
// second issuer sends a second attempt, and the route walk this reference keeps
// is in `demo/actors/PageLoad.js`.

import { requireBrowserCapabilities } from "./browserCapabilities.js";
import { composeClient } from "./composeClient.js";
import { MarkupDeliveryReader } from "../adapter-client/MarkupDeliveryReader.js";
import { DcaData } from "../core-client/DcaData.js";
import { ResponseAssociation } from "../core-client/ResponseAssociation.js";
import { dcaError } from "../core-shared/errors.js";

/**
 * @param {object} [config]
 * @param {{ querySelectorAll: (selector: string) => any }} config.root - the
 *   page this client reads, the document in a browser
 * @param {string} config.issuerName - the issuer this client addresses
 * @param {{ post: (url: string, request: object, context: { origin: string }) => Promise<{ status: number, body: any }> }} config.transport -
 *   how the host reaches that issuer. There is no default: the supported
 *   consumer sends GET with query parameters because its front refuses POST.
 * @param {string} [config.unlockUrl] - where that issuer answers. Left out,
 *   this entry reads the URL the page names for `issuerName`.
 * @param {object} [config.*] - this entry passes every other member to
 *   `composeClient`; a page that keeps its period keys across reloads passes
 *   `storage` and `cacheNamespace` among them.
 * @returns {{ reader: any, dcaData: any, resolver: any, opener: any, unlock: (contentNames: string[]) => Promise<{ status: number, body: any, application: any }> }}
 *   A host calls `resolver.resolve(dcaData, contentNames)` before `unlock`, for
 *   what this client can already open, and
 *   `resolver.contentKeyFor(dcaData, contentName)` after it for one item's
 *   content key. It reads each item's ciphertext off the page with
 *   `reader.extract(contentName)`. `opener` decrypts one item and reverses the
 *   representation layers its record names, using the decoders the host passed
 *   as `contentDecoders`.
 */
export function createBrowserClient(config = /** @type {any} */ ({})) {
  requireBrowserCapabilities();

  const { root, issuerName, unlockUrl, transport, ...clientOptions } = config;
  if (typeof root?.querySelectorAll !== "function") {
    throw dcaError("bad_config", "a browser client needs the page root it reads");
  }
  if (typeof issuerName !== "string" || issuerName.length === 0) {
    throw dcaError("bad_config", "a browser client needs the issuerName it addresses");
  }
  if (typeof transport?.post !== "function") {
    throw dcaError("bad_config", "a browser client needs a transport that answers post");
  }

  const reader = new MarkupDeliveryReader(root);
  // The page origin is delivery context rather than a dca-data member, so it
  // travels from the reader to the page view by hand. A reusable period key
  // files under it, and an answer carrying one is refused without it.
  const dcaData = new DcaData(reader.dcaData, { publisherOrigin: reader.publisherOrigin });
  const named = unlockUrl ?? dcaData.unlockUrlFor(issuerName);
  if (typeof named !== "string" || named.length === 0) {
    throw dcaError("bad_config", `this page names no unlock URL for "${issuerName}"`);
  }
  // Bound again after the refusal so `unlock` below reads a string.
  const url = named;

  const { resolver, builder, opener } = composeClient(clientOptions);
  // This entry documents five resolver operations for its host and unlock
  // path. Validate that complete surface here; PageLoad accepts three.
  for (const method of [
    "applyResponse",
    "resolveDetailed",
    "resolve",
    "contentKeyFor",
    "contentKeyWithOriginFor",
  ]) {
    if (typeof resolver?.[method] !== "function") {
      throw dcaError("bad_config", `a resolverFactory result needs ${method}`);
    }
  }

  /**
   * Ask the issuer for the keys this page needs, once.
   *
   * @param {string[]} contentNames - what the caller could not open from what
   *   it already holds
   * @returns {Promise<{ status: number, body: any, application: any }>} the
   *   status and body the transport answered, and the resolver's application
   *   report when that status was 200
   */
  async function unlock(contentNames) {
    if (!Array.isArray(contentNames)) {
      throw dcaError("bad_config", "unlock asks for a list of content names");
    }

    const request = builder.build(dcaData, issuerName, contentNames).toObject();
    const association = new ResponseAssociation(dcaData, issuerName, request);
    const { status, body } = await transport.post(url, request, {
      origin: reader.publisherOrigin,
    });
    if (status !== 200) return { status, body, application: null };

    const application = await resolver.applyResponse(dcaData, issuerName, body, association);
    // The grant just applied may hold content keys for this render, and a
    // response's private exact capabilities are tried here or discarded.
    await resolver.resolveDetailed(dcaData, contentNames, application);
    return { status, body, application };
  }

  return { reader, dcaData, resolver, opener, unlock };
}
