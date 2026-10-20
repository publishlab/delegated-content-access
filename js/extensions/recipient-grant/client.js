// @ts-check

import { createBrowserClient } from "../../integration-client/createBrowserClient.js";
import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { decodeCompactJwt } from "../../core-shared/compactJwt.js";
import { dcaError } from "../../core-shared/errors.js";
import { isIssuerName, isContentName } from "../../core-shared/names.js";
import { signableOrigin } from "../../core-shared/publisherOrigin.js";
import { own } from "../../core-shared/wire.js";

/**
 * @typedef {object} RecipientGrantBrowserOptions
 * @property {{ querySelectorAll: (selector: string) => any }} root - current render
 * @property {{ issuerName: string, unlockUrl: string, publisherOrigin: string, resourceId: string }} issuer -
 *   trusted client-host configuration, obtained independently of delivery or
 *   link data. The issuer authenticates the publisher registration and JWT;
 *   this client compares decoded claims only to check applicability.
 * @property {string} grantReference - opaque issuer-issued bearer reference;
 *   neither a URL nor an instruction to choose an issuer
 * @property {(url: string, init: { method: string, headers: Record<string, string>, body: string, credentials: 'omit', redirect: 'error' }) => Promise<{ status: number, headers: { get: (name: string) => string|null }, json: () => Promise<any>, redirected?: boolean }>} fetch -
 *   browser Fetch, or a transport with the same HTTPS and redirect duties
 * @property {Record<string, (bytes: Uint8Array) => Promise<Uint8Array>|Uint8Array>} [contentDecoders]
 * @property {{ publicKey: JsonWebKey, openDeliveredKeys: Function }} [clientBoundKeyCapability]
 * @property {boolean} [acceptDirectFallback]
 * @property {boolean} [acceptDirectResponse]
 */

/** @param {unknown} value @returns {value is Record<string, any>} */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** @param {unknown} value @param {string[]} names @returns {void} */
function options(value, names) {
  if (!record(value)) throw dcaError("bad_config", "recipient-grant configuration is an object");
  for (const name of Object.keys(value)) {
    if (!names.includes(name)) {
      throw dcaError("unsupported_option", `recipient-grant configuration has no ${name}`);
    }
    if (value[name] === undefined) {
      throw dcaError("bad_config", `omit absent recipient-grant option ${name}`);
    }
  }
}

/**
 * Compose one browser recipient attempt through the ordinary browser entry.
 * Its request carries only the selected issuer's item envelopes. No reusable
 * cache, period relay, chain profile or request-builder override is accepted.
 * A refusal ends this attempt; the integrator chooses any subsequent attempt
 * separately. This function selects no grant issuance or link format.
 *
 * @param {RecipientGrantBrowserOptions} config
 * @returns {ReturnType<typeof createBrowserClient>}
 */
export function createRecipientGrantBrowserClient(config) {
  options(config, [
    "root",
    "issuer",
    "grantReference",
    "fetch",
    "contentDecoders",
    "clientBoundKeyCapability",
    "acceptDirectFallback",
    "acceptDirectResponse",
  ]);
  const { issuer, grantReference, fetch: fetchRequest } = config;
  options(issuer, ["issuerName", "unlockUrl", "publisherOrigin", "resourceId"]);
  if (!isIssuerName(issuer.issuerName)) {
    throw dcaError("bad_config", "recipient-grant configuration needs one issuerName");
  }
  if (
    typeof issuer.publisherOrigin !== "string" ||
    signableOrigin(issuer.publisherOrigin) !== issuer.publisherOrigin ||
    typeof issuer.resourceId !== "string" ||
    issuer.resourceId.length === 0
  ) {
    throw dcaError("bad_config", "recipient-grant configuration needs a publisher and resource");
  }
  if (typeof issuer.unlockUrl !== "string" || issuer.unlockUrl.length === 0) {
    throw dcaError("bad_config", "recipient-grant configuration needs its trusted unlock URL");
  }
  // RFC 6750 Section 2.1 b64token spelling; its opaque value is not decoded.
  // No whitespace, combined credential or secret appears in an error message.
  if (
    typeof grantReference !== "string" ||
    /^[A-Za-z0-9._~+/-]+=*$/.exec(grantReference)?.[0] !== grantReference
  ) {
    throw dcaError("bad_config", "recipient-grant reference is not one bearer field value");
  }
  if (typeof fetchRequest !== "function") {
    throw dcaError("bad_config", "recipient-grant browser client needs Fetch");
  }
  // Snapshot trusted selection: subsequent configuration edits cannot move a
  // credential to another endpoint or reinterpret the intended resource.
  const { issuerName, unlockUrl, publisherOrigin, resourceId } = issuer;

  const client = createBrowserClient({
    root: config.root,
    issuerName,
    unlockUrl,
    ...(Object.hasOwn(config, "contentDecoders")
      ? { contentDecoders: config.contentDecoders }
      : {}),
    ...(Object.hasOwn(config, "clientBoundKeyCapability")
      ? { clientBoundKeyCapability: config.clientBoundKeyCapability }
      : {}),
    ...(Object.hasOwn(config, "acceptDirectFallback")
      ? { acceptDirectFallback: config.acceptDirectFallback }
      : {}),
    ...(Object.hasOwn(config, "acceptDirectResponse")
      ? { acceptDirectResponse: config.acceptDirectResponse }
      : {}),
    relayPeriodKeys: false,
    resolverFactory(resolverOptions) {
      const resolver = new ContentKeyResolver(resolverOptions);
      return {
        /** @param {any} page @param {string} name @param {any} response @param {ResponseAssociation} association */
        async applyResponse(page, name, response, association) {
          if (!(association instanceof ResponseAssociation) || !association.matches(page, name)) {
            throw dcaError("bad_config", "a recipient result needs its request association");
          }
          const keys = own(response, "keys");
          if (
            Object.hasOwn(response, "periodGeometry") ||
            Object.hasOwn(response, "chainGeometry") ||
            (record(keys) &&
              ["periodKeys", "chainKeys"].some((section) => Object.hasOwn(keys, section)))
          ) {
            throw dcaError(
              "bad_response",
              "a recipient result must contain only item content keys",
            );
          }
          return resolver.applyResponse(page, name, response, association);
        },
        assertReaderContextReset: resolver.assertReaderContextReset.bind(resolver),
        clearReaderContext: resolver.clearReaderContext.bind(resolver),
        resolveDetailed: resolver.resolveDetailed.bind(resolver),
        resolve: resolver.resolve.bind(resolver),
        contentKeyFor: resolver.contentKeyFor.bind(resolver),
        contentKeyWithOriginFor: resolver.contentKeyWithOriginFor.bind(resolver),
      };
    },
    transport: {
      async post(url, request) {
        if (url !== unlockUrl || own(request, "issuerName") !== issuerName) {
          throw dcaError(
            "bad_config",
            "a recipient grant addresses only its configured issuer and endpoint",
          );
        }
        const answer = await fetchRequest(url, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${grantReference}`,
            "Content-Type": "application/json",
          },
          credentials: "omit",
          redirect: "error",
          body: JSON.stringify(request),
        });
        if (answer.redirected === true) {
          throw dcaError("bad_response", "recipient-grant Fetch followed a redirect");
        }
        const contentType = answer.headers.get("content-type") ?? "";
        // A refusal carries no DCA result, including any misleading body.
        if (answer.status !== 200) return { status: answer.status, contentType: null, body: null };
        let body;
        try {
          body = await answer.json();
        } catch {
          throw dcaError("bad_response", "recipient-grant response is not JSON");
        }
        return { status: answer.status, contentType, body };
      },
    },
  });

  /** @returns {void} */
  function assertApplicable() {
    const claims = decodeCompactJwt(client.dcaData.resourceJWT).payload;
    if (
      client.dcaData.publisherOrigin !== publisherOrigin ||
      own(claims, "origin") !== publisherOrigin ||
      own(claims, "resourceId") !== resourceId
    ) {
      throw dcaError("bad_page", "the current render is outside the configured recipient resource");
    }
  }
  assertApplicable();
  const baseUnlock = client.unlock;
  client.unlock = async (contentNames) => {
    if (!Array.isArray(contentNames) || !contentNames.every(isContentName)) {
      throw dcaError("bad_config", "recipient unlock needs named items");
    }
    assertApplicable();
    return baseUnlock(contentNames);
  };
  // A recipient credential has one selected endpoint. Any later ordinary
  // attempt is separately composed without replaying this bearer.
  client.unlockRoutes = async (contentNames, routes) => {
    void contentNames;
    void routes;
    throw dcaError("bad_config", "recipient grants do not support issuer route walks");
  };
  return client;
}
