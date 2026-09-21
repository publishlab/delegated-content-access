// @ts-check

// Browser-profile HTTP binding around one issuer-application unlock call. The
// host supplies the observed Origin after its TLS/proxy boundary. This adapter
// handles browser HTTP behavior as data; it is not an HTTP server.
//
// This adapter passes exactly one canonical origin to the application. A
// browser sends the ASCII serialization of its own origin, so the adapter
// refuses anything else here and does not pass it on: a header observed twice
// (the host hands over both values), one value that comma-joins two origins,
// and any spelling that is not `scheme://host[:non-default-port]`. Refusing them
// here lets the application compare the observed value with the signed
// `resourceJWT.origin` byte for byte instead of parsing it a second time.
//
// The preflight carries no JWT, so it admits a syntactically valid origin and
// grants nothing: the POST performs the verified equality check before the
// response cache, the access policy or any issuer private key.

import { dcaError } from "../core-shared/errors.js";
import { normalizePublisherOrigin } from "../core-shared/publisherOrigin.js";

const METHODS = ["OPTIONS", "POST"];

/** @typedef {{ status: number, headers?: Record<string, string>, body?: any }} HttpResponse */

/**
 * @typedef {object} OriginAdmission
 * @property {(origin: string) => boolean|Promise<boolean>} preflight
 * @property {(origin: string, body: any, hostContext: any) =>
 *   ({ kind: 'admitted', context?: any }|{ kind: 'refused', response?: HttpResponse, cors?: boolean })|
 *   Promise<{ kind: 'admitted', context?: any }|{ kind: 'refused', response?: HttpResponse, cors?: boolean }>}
 *   admit
 */

/** @param {string} origin @param {boolean} credentials @param {boolean} preflight */
function corsHeaders(origin, credentials, preflight) {
  return {
    "access-control-allow-origin": origin,
    ...(credentials ? { "access-control-allow-credentials": "true" } : {}),
    ...(preflight
      ? {
          "access-control-allow-methods": "POST",
          "access-control-allow-headers": "content-type",
        }
      : {}),
    vary: "Origin",
  };
}

/** @param {HttpResponse|undefined} response */
function refusal(response) {
  const source = response ?? { status: 403, body: { error: "origin_refused" } };
  if (!Number.isInteger(source.status)) {
    throw dcaError("bad_config", "an origin refusal needs an integer HTTP status");
  }
  return {
    ...source,
    headers: { ...(source.headers ?? {}), vary: "Origin" },
  };
}

/**
 * Returns the handler's headers with every spelling of the named fields removed.
 * HTTP field names are case-insensitive, so a handler that wrote `Content-Type`
 * beside the lowercase name this adapter writes would put the same field on the
 * wire twice and leave the reader to pick. Removing the other spellings first
 * leaves the mandatory value as the only one.
 *
 * @param {Record<string, string>|undefined} headers
 * @param {string[]} names - already lowercase
 * @returns {Record<string, string>}
 */
function withoutFields(headers, names) {
  if (headers === null || typeof headers !== "object") return {};
  if (names.length === 0) return { ...headers };
  return Object.fromEntries(
    Object.entries(headers).filter(([field]) => !names.includes(field.toLowerCase())),
  );
}

export class BrowserUnlockHttp {
  /** @type {OriginAdmission} */
  #originAdmission;

  /** @type {(body: any, context: { origin: string, admission: any, hostContext: any }) => HttpResponse|Promise<HttpResponse>} */
  #unlock;

  /** @type {boolean} */
  #credentials;

  /**
   * @param {object} config
   * @param {OriginAdmission} config.originAdmission
   * @param {(body: any, context: { origin: string, admission: any, hostContext: any }) => HttpResponse|Promise<HttpResponse>} config.unlock
   * @param {boolean} [config.credentials]
   */
  constructor({ originAdmission, unlock, credentials = false } = /** @type {any} */ ({})) {
    if (
      typeof originAdmission?.preflight !== "function" ||
      typeof originAdmission?.admit !== "function"
    ) {
      throw dcaError("bad_config", "BrowserUnlockHttp needs originAdmission.preflight and admit");
    }
    if (typeof unlock !== "function") {
      throw dcaError("bad_config", "BrowserUnlockHttp needs one unlock operation");
    }
    if (typeof credentials !== "boolean") {
      throw dcaError("bad_config", "BrowserUnlockHttp credentials is on or off");
    }
    this.#originAdmission = originAdmission;
    this.#unlock = unlock;
    this.#credentials = credentials;
  }

  /**
   * @param {{ method: string, origin?: string|null|string[], body?: any, hostContext?: any }} request
   * @returns {Promise<HttpResponse>}
   */
  async handle(request) {
    if (request === null || typeof request !== "object" || !METHODS.includes(request.method)) {
      return { status: 405, headers: { vary: "Origin" }, body: { error: "method_not_allowed" } };
    }

    const origin = request.origin;
    if (typeof origin !== "string" || normalizePublisherOrigin(origin) !== origin) {
      return refusal(undefined);
    }

    if (request.method === "OPTIONS") {
      if ((await this.#originAdmission.preflight(origin)) !== true) return refusal(undefined);
      return { status: 204, headers: corsHeaders(origin, this.#credentials, true) };
    }

    const admission = await this.#originAdmission.admit(origin, request.body, request.hostContext);
    if (admission?.kind === "refused") {
      const response = refusal(admission.response);
      if (admission.cors !== true) return response;
      return {
        ...response,
        headers: {
          ...(response.headers ?? {}),
          ...corsHeaders(origin, this.#credentials, false),
        },
      };
    }
    if (admission?.kind !== "admitted") {
      throw dcaError("bad_config", "originAdmission.admit must return admitted or refused");
    }

    const response = await this.#unlock(request.body, {
      origin,
      admission: admission.context,
      hostContext: request.hostContext,
    });
    if (response === null || typeof response !== "object" || !Number.isInteger(response.status)) {
      throw dcaError("bad_config", "the unlock operation needs an integer HTTP status");
    }
    /** @type {Record<string, string>} */
    const mandatory =
      response.status === 200
        ? { "content-type": "application/json", "cache-control": "no-store" }
        : {};
    return {
      ...response,
      headers: {
        ...withoutFields(response.headers, Object.keys(mandatory)),
        ...mandatory,
        ...corsHeaders(origin, this.#credentials, false),
      },
    };
  }
}
