// @ts-check
// One captured delivery, one configured issuer by default. Hosts choose the
// reader, transport, logical context, cache scope and output eligibility.

import { ReaderContext } from "../core-client/ReaderContext.js";
import { composeClient } from "./composeClient.js";
import { DcaData } from "../core-client/DcaData.js";
import { ResponseAssociation } from "../core-client/ResponseAssociation.js";
import {
  DcaError,
  dcaError,
  isTransportFailureCode,
  isIndeterminateTransportCode,
} from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";
import { signableOrigin } from "../core-shared/publisherOrigin.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { TAG_BYTES } from "../core-shared/aead.js";
import { openContent } from "../core-client/openContent.js";
import {
  hasEligibleCoordinates,
  projectEligibleIdentities,
  retryableUnavailableFamilies,
  routeIdentities,
  settleRouteProjection,
} from "../adapter-client/routeAttempts.js";

/**
 * One route selected by trusted host configuration. A later route is
 * conditional unless `independent` is true. Retry choices on a route govern
 * whether its outcome can activate the next conditional route.
 * @typedef {object} TrustedIssuerRoute
 * @property {string} issuerName
 * @property {string} unlockUrl
 * @property {boolean} [acceptDirectResponse]
 * @property {boolean} [independent]
 * @property {boolean} [retryOperational]
 * @property {boolean} [retryUnavailable]
 */

/** @typedef {{ contentName: string, contentType: string, bytes: Uint8Array }} OpenedContent */
/**
 * One used item after admission: the view captured once from the private
 * delivery copy, and the ciphertext captured with it.
 * @typedef {{ item: import('../core-client/DcaData.js').ContentItemView, ciphertext: string }} PreflightedItem
 */
/** @typedef {{ status: number, body: any, application: any|null }|{skipped: "no-eligible-route", application: null}|{skipped: "cached-denial", retryAt: number, application: null}} UnlockResult */
/**
 * The finite reference vocabulary for one visited route. It describes the
 * attempt, not the item: `answered` means an admitted HTTP answer that
 * qualified no family retry, not that any plaintext opened; the walk's
 * `missing` and `failed` lists give the final disposition. These are
 * reference API tokens, not wire values.
 *
 * - `not-on-page`: the delivery carries no block for this issuer; no request.
 * - `unsupported-retry-projection`: a conditional retry could not be narrowed
 *   to its eligible identities; no request.
 * - `no-eligible-route`: the request would present no coordinate; no request.
 * - `cached-denial`: a context-scoped denial hint suppresses this request.
 * - `indeterminate`: the transport could not observe the HTTP outcome.
 * - `unusable-response`: a 200 answer that is no usable DCA result.
 * - `offline`, `timeout`, `no_route`: a typed transport failure.
 * - `fault`: an HTTP status of 500 or above.
 * - `unavailable`: an admitted `unavailable` report that the route's
 *   `retryUnavailable` choice made eligible for conditional fallback.
 * - `answered`: any other HTTP answer, including denials and no-key 200s.
 *
 * @typedef {"not-on-page"|"unsupported-retry-projection"|"no-eligible-route"|"cached-denial"|"indeterminate"|"unusable-response"|"offline"|"timeout"|"no_route"|"fault"|"unavailable"|"answered"} RouteAttemptOutcome
 */
/**
 * `status` is present exactly when the attempt received an HTTP answer.
 * @typedef {{ issuerName: string, outcome: RouteAttemptOutcome, status?: number }} RouteAttempt
 */
/** @typedef {{ missing: string[], attempts: RouteAttempt[], failed: {name: string, code: string}[] }} RouteWalkResult */
/**
 * @typedef {object} DeliveryClient
 * @property {{ dcaData: any, publisherOrigin: string, extract: (name: string) => string|null }} reader
 * @property {DcaData} dcaData
 * @property {any} cache
 * @property {any} resolver
 * @property {any} builder
 * @property {import("../core-client/ContentRepresentationOpener.js").ContentRepresentationOpener} opener
 * @property {(contentNames: string[]) => Promise<{ covered: string[], missing: string[], origins: any[] }>} resolve
 * @property {(contentNames: string[]) => Promise<UnlockResult>} unlock
 * @property {(contentNames: string[], routes: TrustedIssuerRoute[]) => Promise<RouteWalkResult>} unlockRoutes
 * @property {(contentName: string) => Promise<OpenedContent>} openLocal
 * @property {(contentName: string) => Promise<OpenedContent>} open
 * @property {() => Promise<void>} clearAccessDecisions
 * @property {() => Promise<void>} clearReaderContext
 */

/** @param {unknown} value */
function isJsonMediaType(value) {
  if (typeof value !== "string") return false;
  return value.split(";", 1)[0].trim().toLowerCase() === "application/json";
}

/** @param {unknown} value */
function isHttpAnswer(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Number.isInteger(/** @type {any} */ (value).status) &&
    /** @type {any} */ (value).status >= 100 &&
    /** @type {any} */ (value).status <= 599
  );
}

/** @param {unknown} value */
function hasKeyFamilyEntries(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.keys(value).some((accessGroup) => {
    const family = own(value, accessGroup);
    return (
      family !== null &&
      typeof family === "object" &&
      !Array.isArray(family) &&
      Object.keys(family).length > 0
    );
  });
}

/** @param {string} value @param {boolean} developmentHttpOrigin */
function admittedUrl(value, developmentHttpOrigin) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return (
    (url.protocol === "https:" || url.protocol === "http:") &&
    url.username === "" &&
    url.password === "" &&
    url.hash === "" &&
    !url.href.endsWith("#") &&
    signableOrigin(url.origin, developmentHttpOrigin) === url.origin
  );
}

/**
 * A carrier-independent integration over the same reader contract implemented
 * by `JsonDeliveryReader` and `MarkupDeliveryReader`.
 * A browser transport that cannot observe a Fetch failure's HTTP response may
 * reject with an error carrying `code: "indeterminate_transport"`; route walks record
 * that outcome without making it eligible for conditional fallback. Untyped
 * transport errors remain visible to the caller.
 *
 * @param {import("./composeClient.js").ComposeClientOptions & {
 *   reader: { dcaData: any, publisherOrigin: string, extract: (name: string) => string|null },
 *   issuerName: string,
 *   transport: { post: (url: string, request: object, context: { origin: string }) => Promise<{ status: number, contentType: string|null, body?: any }> },
 *   unlockUrl?: string|null,
 *   developmentHttpOrigin?: boolean,
 *   acceptDirectResponse?: boolean,
 *   denialCache?: import("../adapter-client/DeniedUnlockCache.js").DenialAttemptCache,
 * }} config
 * @returns {DeliveryClient}
 */
export function createDeliveryClient(config) {
  if (config === null || typeof config !== "object")
    throw dcaError("bad_config", "a delivery client needs configuration");
  const {
    reader,
    issuerName,
    transport,
    unlockUrl,
    developmentHttpOrigin = false,
    acceptDirectResponse,
    denialCache,
    ...clientOptions
  } = config;
  if (
    reader === null ||
    typeof reader !== "object" ||
    typeof reader.extract !== "function" ||
    typeof reader.publisherOrigin !== "string"
  )
    throw dcaError("bad_config", "a delivery client needs a delivery reader");
  if (typeof issuerName !== "string" || issuerName.length === 0)
    throw dcaError("bad_config", "a delivery client needs the issuerName it addresses");
  if (typeof transport?.post !== "function")
    throw dcaError("bad_config", "a delivery client needs a transport that answers post");
  if (
    denialCache !== undefined &&
    (typeof denialCache?.capture !== "function" || typeof denialCache?.deny !== "function")
  )
    throw dcaError("bad_config", "denialCache needs capture and deny");
  const post = transport.post.bind(transport);
  const readerContext = new ReaderContext();
  if (typeof developmentHttpOrigin !== "boolean")
    throw dcaError("bad_config", "developmentHttpOrigin is a profile that is on or off");
  if (acceptDirectResponse !== undefined && typeof acceptDirectResponse !== "boolean")
    throw dcaError("bad_config", "acceptDirectResponse is boolean");

  // The reader contract supplies parsed JSON data. Copy it before any async
  // work, then capture each ciphertext once, so a host's later reader change
  // cannot redirect a pending operation to a different delivery.
  let capturedData;
  try {
    capturedData = JSON.parse(JSON.stringify(reader.dcaData));
  } catch {
    throw dcaError("bad_page", "a delivery reader needs JSON data");
  }
  const publisherOrigin = reader.publisherOrigin;
  const dcaData = new DcaData(capturedData, { publisherOrigin });
  const ciphertexts = new Map(dcaData.contentNames().map((name) => [name, reader.extract(name)]));
  const unusableUrl = () =>
    dcaError(
      "bad_config",
      `the unlock URL for "${issuerName}" is not absolute https without credentials or a fragment`,
    );
  // Only trusted host configuration supplies an acquisition endpoint.
  if (
    unlockUrl !== undefined &&
    unlockUrl !== null &&
    (typeof unlockUrl !== "string" || !admittedUrl(unlockUrl, developmentHttpOrigin))
  )
    throw unusableUrl();

  /** The selected issuer's endpoint, admitted when an acquisition needs it. */
  function selectedUrl() {
    if (typeof unlockUrl === "string") return unlockUrl;
    if (!dcaData.hasIssuer(issuerName))
      throw dcaError("unknown_issuer", `the page carries no issuer "${issuerName}"`);
    throw dcaError("bad_config", `no trusted unlock endpoint is configured for "${issuerName}"`);
  }

  const { cache, resolver, builder, opener } = composeClient(clientOptions);
  for (const method of [
    "applyResponse",
    "resolveDetailed",
    "resolve",
    "contentKeyFor",
    "contentKeyWithOriginFor",
  ])
    if (typeof resolver?.[method] !== "function")
      throw dcaError("bad_config", `a resolverFactory result needs ${method}`);
  // A selected extension builder reports the coordinates it adds and how to
  // narrow them for a conditional retry. The walk reads no extension member.
  const projection =
    builder.routeProjection === undefined ? null : settleRouteProjection(builder.routeProjection);
  if (builder.keyFamilies !== undefined && typeof builder.keyFamilies !== "function")
    throw dcaError("bad_config", "a request builder's keyFamilies answers for one request");
  /** @type {((request: any) => import("../adapter-client/routeAttempts.js").ExtensionKeyFamilies)|null} */
  const keyFamilies =
    typeof builder.keyFamilies === "function" ? builder.keyFamilies.bind(builder) : null;
  // A recovery source derives an item key from held material, and only an
  // authenticated opening tells which candidate is the key. A client with one
  // therefore opens through authenticated selection, as a route walk does.
  const recovers =
    Array.isArray(clientOptions.recoverySources) &&
    clientOptions.recoverySources.length > 0 &&
    typeof resolver.resolveAuthenticated === "function";

  /**
   * @param {{ issuerName: string, unlockUrl: string, acceptDirectResponse?: boolean }} route
   * @param {string[]} contentNames
   * @param {import("../adapter-client/routeAttempts.js").RouteIdentities|null} [eligible]
   * @param {boolean} [skipEmpty]
   * @param {boolean} [captureRouteFailure]
   * @param {(names: string[], application: object) => Promise<any>} [authenticate]
   * @returns {Promise<any>}
   */
  async function attempt(
    route,
    contentNames,
    eligible = null,
    skipEmpty = false,
    captureRouteFailure = false,
    authenticate,
  ) {
    const readerRevision = readerContext.capture();
    const request = builder.build(dcaData, route.issuerName, contentNames).toObject();
    const projected =
      eligible === null ? request : projectEligibleIdentities(request, eligible, projection);
    if (projected === null) return { skipped: "unsupported-retry-projection" };
    if (skipEmpty && !hasEligibleCoordinates(projected, keyFamilies))
      return { skipped: "no-eligible-route" };
    const attempted = routeIdentities(projected, projection);
    const association = new ResponseAssociation(dcaData, route.issuerName, projected, {
      acceptDirectResponse: route.acceptDirectResponse,
    });
    if (
      !association.acceptDirectResponse &&
      association.offeredClientBoundMethod === null &&
      hasEligibleCoordinates(projected, keyFamilies)
    ) {
      throw dcaError(
        "bad_config",
        "a strict endpoint needs a client-bound offer to return keys for this request",
      );
    }
    if (association.acceptDirectResponse) {
      const hasClientBoundCapability = clientOptions.clientBoundKeyCapability !== undefined;
      const acceptsDirectFallback = clientOptions.acceptDirectFallback ?? !hasClientBoundCapability;
      const persistsRawPeriodKeys =
        clientOptions.persistRawPeriodKeys ?? (!hasClientBoundCapability && acceptsDirectFallback);
      if (!acceptsDirectFallback) {
        throw dcaError(
          "bad_config",
          "a route accepting direct responses needs a resolver that accepts direct fallback",
        );
      }
      if (
        (hasKeyFamilyEntries(projected.sealed?.periodKeys) ||
          hasKeyFamilyEntries(projected.sealed?.chainKeys) ||
          keyFamilies?.(projected)?.familyKeys === true) &&
        !persistsRawPeriodKeys
      ) {
        throw dcaError(
          "bad_config",
          "a route accepting direct period or chain keys needs raw key custody enabled",
        );
      }
    }
    const denialAttempt = denialCache
      ? readerContext.accept(
          await denialCache.capture({
            publisherOrigin,
            issuerName: route.issuerName,
            unlockUrl: route.unlockUrl,
            request: projected,
          }),
          readerRevision,
        )
      : null;
    if (denialAttempt?.retryAt !== null && denialAttempt?.retryAt !== undefined)
      return { skipped: "cached-denial", retryAt: denialAttempt.retryAt, attempted };
    let answer;
    try {
      answer = readerContext.accept(
        await post(route.unlockUrl, projected, { origin: publisherOrigin }),
        readerRevision,
      );
    } catch (cause) {
      readerContext.check(readerRevision);
      const code = /** @type {any} */ (cause)?.code;
      if (captureRouteFailure && isTransportFailureCode(code))
        return { transportFailure: code, attempted };
      if (captureRouteFailure && isIndeterminateTransportCode(code))
        return { indeterminateTransport: true, attempted };
      throw cause;
    }
    if (!isHttpAnswer(answer)) {
      throw dcaError(
        "bad_response",
        "a transport answer needs an HTTP status from 100 through 599",
      );
    }
    if (answer.status !== 200)
      return {
        status: answer.status,
        body: answer.body,
        application: null,
        missing: contentNames,
        attempted,
      };
    let application;
    try {
      if (!isJsonMediaType(answer.contentType))
        throw dcaError(
          "bad_response",
          "a 200 answer without an application/json body is no result",
        );
      if (answer.body === null || typeof answer.body !== "object" || Array.isArray(answer.body))
        throw dcaError("bad_response", "a 200 answer's JSON value is not a non-array object");
      application = readerContext.accept(
        await resolver.applyResponse(dcaData, route.issuerName, answer.body, association),
        readerRevision,
      );
    } catch (cause) {
      readerContext.check(readerRevision);
      if (captureRouteFailure && cause instanceof DcaError && cause.code === "bad_response")
        return { unusableResponse: true, attempted, status: answer.status };
      throw cause;
    }
    if (
      Array.isArray(application?.issues) &&
      application.issues.some(
        (/** @type {{ code: string, section?: string }} */ issue) =>
          (issue.code === "malformed_response" &&
            (issue.section === undefined || issue.section === "response")) ||
          (issue.code === "invalid_transport" && issue.section === "response"),
      )
    ) {
      // A named member's admission issue is local to that member: independent
      // admitted keys still contribute authenticated progress. Shared response
      // association/representation/transport failures remain unusable and
      // cannot activate the conditional walk.
      if (captureRouteFailure) return { unusableResponse: true, attempted, status: answer.status };
    }
    // Missing output is never a denial. Only a complete, clean, admitted
    // family-denial report can suppress an equivalent later request.
    if (
      denialAttempt &&
      application?.accepted === 0 &&
      application?.issues?.length === 0 &&
      application?.errors?.length === 0 &&
      attempted.contentNames.length === 0 &&
      keyFamilies?.(projected)?.contentKeys !== true &&
      (attempted.routes ?? []).length === 0 &&
      attempted.accessGroups.length > 0 &&
      Object.keys(projected.sealed ?? {}).every((kind) =>
        ["contentKeys", "periodKeys", "chainKeys"].includes(kind),
      ) &&
      attempted.accessGroups.every((group) =>
        application.notDelivered?.some(
          (/** @type {any} */ entry) => entry.accessGroup === group && entry.reason === "denied",
        ),
      )
    )
      denialCache?.deny(denialAttempt);
    const resolved = authenticate
      ? readerContext.accept(await authenticate(contentNames, application), readerRevision)
      : readerContext.accept(
          await resolver.resolveDetailed(dcaData, contentNames, application),
          readerRevision,
        );
    return {
      status: 200,
      body: answer.body,
      application,
      missing: resolved.missing,
      decryptFailed: resolved.decryptFailed,
      attempted,
    };
  }

  /** Resolve before an issuer attempt, so cached capability stays useful. */
  /** @param {string[]} contentNames @returns {Promise<{ covered: string[], missing: string[], origins: any[] }>} */
  async function resolve(contentNames) {
    const readerRevision = readerContext.capture();
    if (!Array.isArray(contentNames))
      throw dcaError("bad_config", "resolve asks for a list of content names");
    return readerContext.accept(
      await resolver.resolveDetailed(dcaData, contentNames),
      readerRevision,
    );
  }

  /** One attempt against the selected issuer. */
  /** @param {string[]} contentNames @returns {Promise<UnlockResult>} */
  async function unlock(contentNames) {
    const readerRevision = readerContext.capture();
    if (!Array.isArray(contentNames))
      throw dcaError("bad_config", "unlock asks for a list of content names");
    const items = recovers ? preflightRouteItems(contentNames).items : null;
    const result = readerContext.accept(
      await attempt(
        { issuerName, unlockUrl: selectedUrl(), acceptDirectResponse },
        items === null ? [...contentNames] : [...items.keys()],
        null,
        true,
        false,
        items === null
          ? undefined
          : (names, application) => authenticatedCoverage(names, items, application),
      ),
      readerRevision,
    );
    if (result.skipped === "cached-denial")
      return { skipped: "cached-denial", retryAt: result.retryAt, application: null };
    if (result.skipped) return { skipped: "no-eligible-route", application: null };
    return { status: result.status, body: result.body, application: result.application };
  }

  /** Pure used-item admission; callers admit the delivery globally first. It
   * captures the item view an opening authenticates, decodes and hands off.
   * @param {string} contentName
   * @returns {PreflightedItem}
   */
  function preflightItem(contentName) {
    const item = dcaData.contentItemFor(contentName);
    const ciphertext = ciphertexts.get(contentName) ?? null;
    if (!item || typeof ciphertext !== "string")
      throw dcaError("bad_page", `this delivery carries no ciphertext for "${contentName}"`);
    const ciphertextBytes = binaryStringBytes(ciphertext);
    if (ciphertextBytes === null || ciphertextBytes.length < TAG_BYTES)
      throw dcaError("bad_page", `the ciphertext for "${contentName}" is malformed`);
    opener.preflight({ item });
    return { item, ciphertext };
  }

  /** @param {string[]} contentNames
   * @returns {{items: Map<string, PreflightedItem>, failed: {name: string, code: string}[]}}
   */
  function preflightRouteItems(contentNames) {
    // Global admission is outside the item-local refusal boundary.
    dcaData.version;
    const items = new Map();
    const failed = [];
    for (const contentName of contentNames) {
      try {
        items.set(contentName, preflightItem(contentName));
      } catch (cause) {
        if (cause instanceof DcaError && ["bad_page", "unsupported_encoding"].includes(cause.code))
          failed.push({ name: contentName, code: cause.code });
        else throw cause;
      }
    }
    return { items, failed };
  }

  /**
   * Which requested items have a key that authenticates their captured sealed
   * bytes? Decoder admission is checked by the opener before AEAD; decoder
   * effects remain reserved for normal open.
   * @param {string[]} contentNames
   * @param {Map<string, PreflightedItem>} items
   * @param {object} [application]
   * @returns {Promise<{ missing: string[], decryptFailed: string[] }>}
   */
  async function authenticatedCoverage(contentNames, items, application) {
    const readerRevision = readerContext.capture();
    const seen = new Set();
    const resolved = readerContext.accept(
      await resolver.resolveAuthenticated(
        dcaData,
        contentNames,
        /** @param {string} contentName @param {Uint8Array|CryptoKey} candidate */
        async (contentName, candidate) => {
          const preflighted = items.get(contentName);
          if (!preflighted)
            throw dcaError("bad_config", `route coverage has no preflight for "${contentName}"`);
          seen.add(contentName);
          const { item, ciphertext } = preflighted;
          try {
            const plaintext = readerContext.accept(
              await openContent(candidate, contentName, ciphertext, item.contentAad),
              readerRevision,
            );
            plaintext.fill(0);
            return true;
          } catch (cause) {
            if (cause instanceof DcaError && cause.code === "decrypt_failed") return false;
            throw cause;
          }
        },
        application,
      ),
      readerRevision,
    );
    return {
      missing: resolved.missing,
      decryptFailed: resolved.missing.filter((/** @type {string} */ name) => seen.has(name)),
    };
  }

  /**
   * An explicitly configured ordered walk. `independent` permits an attempt
   * regardless of the prior outcome. A conditional route follows an
   * operational failure only when that identity's earlier route selected
   * `retryOperational`, or an admitted useful unavailable family only when
   * its earlier route selected `retryUnavailable`.
   */
  /** @param {string[]} contentNames @param {TrustedIssuerRoute[]} routes @returns {Promise<RouteWalkResult>} */
  async function unlockRoutes(contentNames, routes) {
    const readerRevision = readerContext.capture();
    if (!Array.isArray(contentNames) || !Array.isArray(routes) || routes.length === 0)
      throw dcaError("bad_config", "unlockRoutes needs content names and trusted routes");
    if (typeof resolver?.resolveAuthenticated !== "function")
      throw dcaError(
        "bad_config",
        "unlockRoutes needs a resolver with authenticated item-key selection",
      );
    const selectedRoutes = routes.map((route) => {
      if (
        typeof route?.issuerName !== "string" ||
        typeof route?.unlockUrl !== "string" ||
        !admittedUrl(route.unlockUrl, developmentHttpOrigin) ||
        (route.acceptDirectResponse !== undefined &&
          typeof route.acceptDirectResponse !== "boolean") ||
        (route.independent !== undefined && typeof route.independent !== "boolean") ||
        (route.retryOperational !== undefined && typeof route.retryOperational !== "boolean") ||
        (route.retryUnavailable !== undefined && typeof route.retryUnavailable !== "boolean")
      )
        throw dcaError(
          "bad_config",
          "a trusted route needs an issuerName, admitted unlockUrl and boolean retry choices",
        );
      return {
        issuerName: route.issuerName,
        unlockUrl: route.unlockUrl,
        acceptDirectResponse: route.acceptDirectResponse,
        independent: route.independent === true,
        retryOperational: route.retryOperational === true,
        retryUnavailable: route.retryUnavailable === true,
      };
    });
    const { items: routeItems, failed } = preflightRouteItems(contentNames);
    const initialAuthentication = readerContext.accept(
      await authenticatedCoverage([...routeItems.keys()], routeItems),
      readerRevision,
    );
    let missing = [...initialAuthentication.missing];
    let decryptFailed = new Set(initialAuthentication.decryptFailed);
    /** @type {import("../adapter-client/routeAttempts.js").RouteIdentities} */
    let eligible = { contentNames: [], accessGroups: [], routes: [] };
    /** @type {import("../adapter-client/routeAttempts.js").RouteIdentities} */
    const none = { contentNames: [], accessGroups: [], routes: [] };
    /**
     * Only addressed identities receive a new outcome; other eligible
     * identities survive independent attempts. Held capability removes retry need.
     * @param {import("../adapter-client/routeAttempts.js").RouteIdentities} attempted
     * @param {import("../adapter-client/routeAttempts.js").RouteIdentities} next
     */
    function updateEligibility(attempted, next) {
      const usefulGroups = new Set(missing.flatMap((name) => dcaData.accessGroupsFor(name)));
      eligible = {
        contentNames: [
          ...new Set([
            ...eligible.contentNames.filter((name) => !attempted.contentNames.includes(name)),
            ...next.contentNames.filter((name) => attempted.contentNames.includes(name)),
          ]),
        ].filter((name) => missing.includes(name)),
        accessGroups: [
          ...new Set([
            ...eligible.accessGroups.filter((group) => !attempted.accessGroups.includes(group)),
            ...next.accessGroups.filter((group) => attempted.accessGroups.includes(group)),
          ]),
        ].filter((group) => usefulGroups.has(group)),
        routes: [
          ...new Set([
            ...(eligible.routes ?? []).filter((route) => !attempted.routes?.includes(route)),
            ...(next.routes ?? []).filter((route) => attempted.routes?.includes(route)),
          ]),
        ].filter((route) => projection !== null && projection.useful(route, missing)),
      };
    }
    /** @type {RouteAttempt[]} */
    const attempts = [];
    for (const [index, route] of selectedRoutes.entries()) {
      if (missing.length === 0) break;
      if (
        index > 0 &&
        !route.independent &&
        eligible.contentNames.length === 0 &&
        eligible.accessGroups.length === 0 &&
        (eligible.routes ?? []).length === 0
      )
        continue;
      const conditionalEligible = index > 0 && !route.independent ? eligible : null;
      const requestedNames = [...missing];
      let result;
      try {
        result = readerContext.accept(
          await attempt(route, missing, conditionalEligible, true, true, (names, application) =>
            authenticatedCoverage(names, routeItems, application),
          ),
          readerRevision,
        );
      } catch (cause) {
        readerContext.check(readerRevision);
        const code = /** @type {any} */ (cause)?.code;
        if (code === "unknown_issuer") {
          attempts.push({ issuerName: route.issuerName, outcome: "not-on-page" });
          continue;
        }
        throw cause;
      }
      if (result.skipped) {
        if (result.skipped === "cached-denial") updateEligibility(result.attempted, none);
        attempts.push({ issuerName: route.issuerName, outcome: result.skipped });
        continue;
      }
      if (result.indeterminateTransport || result.unusableResponse) {
        updateEligibility(result.attempted, none);
        attempts.push({
          issuerName: route.issuerName,
          ...(result.status === undefined ? {} : { status: result.status }),
          outcome: result.indeterminateTransport ? "indeterminate" : "unusable-response",
        });
        continue;
      }
      if (result.transportFailure) {
        updateEligibility(result.attempted, route.retryOperational ? result.attempted : none);
        attempts.push({ issuerName: route.issuerName, outcome: result.transportFailure });
        continue;
      }
      if (result.status >= 500) {
        updateEligibility(result.attempted, route.retryOperational ? result.attempted : none);
        attempts.push({ issuerName: route.issuerName, status: result.status, outcome: "fault" });
        continue;
      }
      const authentication =
        result.status === 200
          ? { missing: result.missing, decryptFailed: result.decryptFailed }
          : readerContext.accept(
              await authenticatedCoverage(requestedNames, routeItems),
              readerRevision,
            );
      missing = authentication.missing;
      decryptFailed = new Set(authentication.decryptFailed);
      const retryGroups =
        result.status === 200
          ? retryableUnavailableFamilies({
              application: result.application,
              missing: missing.filter((name) => !decryptFailed.has(name)),
              dcaData,
              retryUnavailable: route.retryUnavailable === true,
            })
          : [];
      updateEligibility(result.attempted, { ...none, accessGroups: retryGroups });
      attempts.push({
        issuerName: route.issuerName,
        status: result.status,
        outcome: retryGroups.length > 0 ? "unavailable" : "answered",
      });
      // A denial or silent no-key 200 cannot activate conditional fallback.
      // Independent later routes remain a separate host decision.
    }
    return { missing, attempts, failed };
  }

  /** Open bytes using capability already held by this client. */
  /** @param {string} contentName @returns {Promise<OpenedContent>} */
  async function openLocal(contentName) {
    const readerRevision = readerContext.capture();
    // The same pure admission as open and route preflight, before any key
    // lookup: an item's failure class must not depend on whether a key is held.
    dcaData.version;
    const preflighted = preflightItem(contentName);
    if (recovers)
      readerContext.accept(
        await authenticatedCoverage([contentName], new Map([[contentName, preflighted]])),
        readerRevision,
      );
    return openCaptured(preflighted, readerRevision);
  }

  /**
   * Open one item from the view captured when its operation started. The AAD,
   * the decoders and the handed-off type all come from that view, never from a
   * reread after an await.
   * @param {PreflightedItem} preflighted @param {number} readerRevision
   * @returns {Promise<OpenedContent>}
   */
  async function openCaptured({ item, ciphertext }, readerRevision) {
    const bytes = readerContext.accept(
      await opener.open({
        item,
        ciphertext,
        resolveKey: () => resolver.contentKeyFor(dcaData, item.contentName),
      }),
      readerRevision,
    );
    return { contentName: item.contentName, contentType: item.contentType, bytes };
  }

  /** Resolve, obtain a missing key from the selected issuer, and open one item. */
  /** @param {string} contentName @returns {Promise<OpenedContent>} */
  async function open(contentName) {
    const readerRevision = readerContext.capture();
    dcaData.version;
    const preflighted = preflightItem(contentName);
    if (recovers) {
      const items = new Map([[contentName, preflighted]]);
      const { missing } = readerContext.accept(
        await authenticatedCoverage([contentName], items),
        readerRevision,
      );
      // The attempt selects under the response's lease, so a key the
      // response files for later reuse also opens this item now.
      if (missing.length > 0)
        readerContext.accept(
          await attempt(
            { issuerName, unlockUrl: selectedUrl(), acceptDirectResponse },
            missing,
            null,
            true,
            false,
            (names, application) => authenticatedCoverage(names, items, application),
          ),
          readerRevision,
        );
    } else {
      const { missing } = readerContext.accept(await resolve([contentName]), readerRevision);
      if (missing.length > 0) readerContext.accept(await unlock(missing), readerRevision);
    }
    return readerContext.accept(await openCaptured(preflighted, readerRevision), readerRevision);
  }

  /** Clear only scheduling decisions; a valid same-context grant stays eligible.
   * @returns {Promise<void>}
   */
  async function clearAccessDecisions() {
    if (!denialCache) return;
    const participant = /** @type {any} */ (denialCache);
    const clear = participant.clearAccessDecisions ?? participant.invalidate;
    if (typeof clear !== "function")
      throw dcaError("bad_config", "a resettable denial cache needs invalidation");
    await clear.call(participant);
  }

  /** @type {Promise<void>|null} */
  let resettingReader = null;

  /** Synchronous retirement, then join all owner cleanup without waiting on
   * old network responses. Only key-owner failure detaches this client;
   * decision-only failure remains visible without retiring the new generation.
   * @returns {Promise<void>}
   */
  function clearReaderContext() {
    if (resettingReader) return resettingReader;
    let decisionsFailed = false;
    /** @type {unknown} */
    let decisionsFault;
    const clearingKeys = readerContext.clear(async () => {
      const pending = [
        () => {
          if (typeof resolver.clearReaderContext !== "function")
            throw dcaError("bad_config", "a resettable resolver needs clearReaderContext");
          return resolver.clearReaderContext();
        },
        clearAccessDecisions,
      ].map((clear) => {
        try {
          return clear();
        } catch (error) {
          return Promise.reject(error);
        }
      });
      const [keys, decisions] = await Promise.allSettled(pending);
      if (keys.status === "rejected") throw keys.reason;
      if (decisions.status === "rejected") {
        decisionsFailed = true;
        decisionsFault = decisions.reason;
      }
    });
    const reset = clearingKeys.then(() => {
      if (decisionsFailed)
        throw Object.assign(
          dcaError(
            "access_decisions_clear_failed",
            "reader keys cleared; access decisions cleanup failed",
          ),
          { cause: decisionsFault },
        );
    });
    resettingReader = reset;
    // Coalesce the whole public result, so concurrent callers share even an
    // advisory failure while the underlying generation may safely resume.
    reset.then(
      () => {
        resettingReader = null;
      },
      () => {
        resettingReader = null;
      },
    );
    return reset;
  }

  return {
    clearAccessDecisions,
    clearReaderContext,
    reader,
    dcaData,
    cache,
    resolver,
    builder,
    opener,
    resolve,
    unlock,
    unlockRoutes,
    openLocal,
    open,
  };
}
