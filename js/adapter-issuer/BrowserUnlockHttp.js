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
//
// A POST response carries CORS permission only once the resource assertion is
// verified and its signed origin equals the observed one. This adapter holds
// no assertion, so the injected admission says when that is: `admitted`, or a
// refusal marked `cors: true`, states that the admission has verified the
// assertion, matched its signed origin byte for byte and applied any
// registration origin limit. Every other refusal leaves without permission.
// The adapter owns every CORS field and the `Origin` member of `Vary`, so it
// removes every spelling a handler wrote of them before it writes its own.
//
// A preflight or admission collaborator that throws, or answers in a shape the
// adapter cannot send, gets an owned 500 with `Vary` and `no-store` and no CORS,
// so the host framework's default error page never stands in for it. A 405
// names the allowed methods in `Allow`. In bearer mode every 401 carries a
// `Bearer` challenge; without bearer mode no challenge scheme is named.

import { dcaError } from "../core-shared/errors.js";
import { normalizePublisherOrigin } from "../core-shared/publisherOrigin.js";
import { parseBearerAuthorization } from "./parseBearerAuthorization.js";

const METHODS = ["OPTIONS", "POST"];

/** @param {unknown} value */
function isJsonContentType(value) {
  return typeof value === "string" && /^\s*application\/json\s*(?:;.*)?$/i.test(value);
}

/** @typedef {{ status: number, headers?: Record<string, string>, body?: any }} HttpResponse */

/**
 * `admit` answers `admitted` only after it has verified the resource assertion,
 * found its signed origin equal to the observed one and applied any
 * registration origin limit. A refusal it makes after that point, such as an
 * application denial, may set `cors: true`; a refusal before it must not.
 *
 * @typedef {object} OriginAdmission
 * @property {(origin: string) => boolean|Promise<boolean>} preflight
 * @property {(origin: string, body: any, hostContext: any, authorization?: string) =>
 *   ({ kind: 'admitted', context?: any }|{ kind: 'refused', response?: HttpResponse, cors?: boolean })|
 *   Promise<{ kind: 'admitted', context?: any }|{ kind: 'refused', response?: HttpResponse, cors?: boolean }>}
 *   admit
 */

/** @param {string} origin @param {boolean} credentials @param {boolean} preflight @param {boolean} authorization */
function corsHeaders(origin, credentials, preflight, authorization) {
  return {
    "access-control-allow-origin": origin,
    ...(credentials ? { "access-control-allow-credentials": "true" } : {}),
    ...(preflight
      ? {
          "access-control-allow-methods": "POST",
          "access-control-allow-headers": authorization
            ? "content-type, authorization"
            : "content-type",
        }
      : {}),
    vary: "Origin",
  };
}

/** The fields this adapter writes on a POST or preflight answer, lowercase. */
const CORS_FIELDS = [
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "access-control-allow-methods",
  "access-control-allow-headers",
];

/**
 * The `Vary` members a handler listed, in every spelling of the field, with
 * `Origin` added once. The adapter owns only that member; the handler's others
 * still describe its own response.
 *
 * @param {Record<string, string>|undefined} headers
 * @returns {string}
 */
function varyWithOrigin(headers) {
  /** @type {string[]} */
  const members = [];
  if (headers !== null && typeof headers === "object") {
    for (const [field, value] of Object.entries(headers)) {
      if (field.toLowerCase() !== "vary" || typeof value !== "string") continue;
      for (const member of value.split(",")) {
        const name = member.trim();
        if (name.length > 0 && !members.some((seen) => seen.toLowerCase() === name.toLowerCase())) {
          members.push(name);
        }
      }
    }
  }
  if (!members.some((name) => name.toLowerCase() === "origin")) members.push("Origin");
  return members.join(", ");
}

/**
 * A refusal with no CORS permission: whatever the refusing component wrote
 * into any CORS field is removed, and `Vary` carries `Origin`. A POST refusal
 * also replaces every cache-control spelling with `no-store`.
 *
 * @param {HttpResponse|undefined} response
 * @param {boolean} post
 */
function refusal(response, post) {
  const source = response ?? { status: 403, body: { error: "origin_refused" } };
  if (!Number.isInteger(source.status)) {
    throw dcaError("bad_config", "an origin refusal needs an integer HTTP status");
  }
  return {
    ...source,
    headers: {
      ...withoutFields(source.headers, [
        ...CORS_FIELDS,
        "vary",
        ...(post ? ["cache-control"] : []),
      ]),
      ...(post ? { "cache-control": "no-store" } : {}),
      vary: varyWithOrigin(source.headers),
    },
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

  /** @type {(body: any, context: { origin: string, admission: any, hostContext: any, authorization?: string }) => HttpResponse|Promise<HttpResponse>} */
  #unlock;

  /** @type {boolean} */
  #credentials;

  /** @type {boolean} */
  #authorization;

  /** @type {(code: string) => object} */
  #errorBody;

  /**
   * @param {object} config
   * @param {OriginAdmission} config.originAdmission
   * @param {(body: any, context: { origin: string, admission: any, hostContext: any, authorization?: string }) => HttpResponse|Promise<HttpResponse>} config.unlock
   * @param {boolean} [config.credentials]
   * @param {boolean} [config.authorization] - select the explicit bearer header and its preflight allowance
   * @param {(code: string) => object} [config.errorBody] - host disclosure for adapter admission refusals
   */
  constructor(
    {
      originAdmission,
      unlock,
      credentials = false,
      authorization = false,
      errorBody = (code) => ({ error: code }),
    } = /** @type {any} */ ({}),
  ) {
    if (
      typeof originAdmission?.preflight !== "function" ||
      typeof originAdmission?.admit !== "function"
    ) {
      throw dcaError("bad_config", "BrowserUnlockHttp needs originAdmission.preflight and admit");
    }
    if (typeof unlock !== "function") {
      throw dcaError("bad_config", "BrowserUnlockHttp needs one unlock operation");
    }
    if (typeof credentials !== "boolean" || typeof authorization !== "boolean") {
      throw dcaError("bad_config", "BrowserUnlockHttp credentials and authorization are on or off");
    }
    if (typeof errorBody !== "function") {
      throw dcaError("bad_config", "BrowserUnlockHttp errorBody is a function");
    }
    this.#originAdmission = originAdmission;
    this.#unlock = unlock;
    this.#credentials = credentials;
    this.#authorization = authorization;
    this.#errorBody = errorBody;
  }

  /**
   * @param {{ method: string, origin?: string|null|string[], contentType?: string|null, body?: any, hostContext?: any, authorization?: string|string[] }} request
   * @returns {Promise<HttpResponse>}
   */
  async handle(request) {
    if (request === null || typeof request !== "object" || !METHODS.includes(request.method)) {
      return {
        status: 405,
        headers: { allow: METHODS.join(", "), vary: "Origin" },
        body: { error: "method_not_allowed" },
      };
    }

    const origin = request.origin;
    if (typeof origin !== "string" || normalizePublisherOrigin(origin) !== origin) {
      return refusal(undefined, request.method === "POST");
    }

    if (request.method === "OPTIONS") {
      let allowed;
      try {
        allowed = await this.#originAdmission.preflight(origin);
      } catch {
        return this.#hostFault();
      }
      if (allowed !== true) return refusal(undefined, false);
      return {
        status: 204,
        headers: corsHeaders(origin, this.#credentials, true, this.#authorization),
      };
    }

    return this.#challenged(await this.#post(request, origin));
  }

  /**
   * An unexpected host fault before the signed-origin gate: the collaborator
   * threw, or answered in a shape this adapter cannot send. The adapter still
   * owns the answer, so it carries `Vary` and `no-store` and earns no CORS.
   *
   * @returns {HttpResponse}
   */
  #hostFault() {
    return refusal({ status: 500, body: this.#errorBody("internal_error") }, true);
  }

  /**
   * RFC 9110 requires a challenge on every 401. In bearer mode the scheme is
   * Bearer (RFC 6750 Section 3). Without bearer mode no scheme is named here:
   * the cookie-mode authentication policy is not this adapter's to settle.
   *
   * @param {HttpResponse} response
   * @returns {HttpResponse}
   */
  #challenged(response) {
    if (!this.#authorization || response.status !== 401) return response;
    const headers = response.headers ?? {};
    if (Object.keys(headers).some((field) => field.toLowerCase() === "www-authenticate")) {
      return response;
    }
    return { ...response, headers: { ...headers, "www-authenticate": "Bearer" } };
  }

  /**
   * @param {{ method: string, origin?: string|null|string[], contentType?: string|null, body?: any, hostContext?: any, authorization?: string|string[] }} request
   * @param {string} origin - canonical
   * @returns {Promise<HttpResponse>}
   */
  async #post(request, origin) {
    // Media admission precedes JSON parsing, publisher lookup and the signed
    // origin gate. A refusal here never grants CORS permission.
    if (!isJsonContentType(request.contentType)) {
      return refusal({ status: 415, body: this.#errorBody("unsupported_media_type") }, true);
    }

    const reference = parseBearerAuthorization(request.authorization);
    if (this.#authorization && reference === null) {
      return refusal({ status: 401, body: this.#errorBody("denied") }, true);
    }

    let admission;
    try {
      admission = await this.#originAdmission.admit(
        origin,
        request.body,
        request.hostContext,
        this.#authorization ? /** @type {string} */ (reference) : undefined,
      );
    } catch {
      return this.#hostFault();
    }
    if (admission?.kind === "refused") {
      let response;
      try {
        response = refusal(admission.response, true);
      } catch {
        return this.#hostFault();
      }
      // Only an admission that has verified and matched the signed origin
      // marks its refusal `cors: true`.
      if (admission.cors !== true) return response;
      return {
        ...response,
        headers: {
          ...(response.headers ?? {}),
          ...corsHeaders(origin, this.#credentials, false, this.#authorization),
          vary: response.headers.vary,
        },
      };
    }
    if (admission?.kind !== "admitted") return this.#hostFault();

    let response;
    try {
      response = await this.#unlock(request.body, {
        origin,
        admission: admission.context,
        hostContext: request.hostContext,
        ...(this.#authorization
          ? { authorization: /** @type {string} */ (request.authorization) }
          : {}),
      });
    } catch {
      // The verified origin has already passed admission. Even an unexpected
      // host failure must be observable as a 5xx at that origin.
      response = { status: 500, body: this.#errorBody("internal_error") };
    }
    if (response === null || typeof response !== "object" || !Number.isInteger(response.status)) {
      response = { status: 500, body: this.#errorBody("internal_error") };
    }
    /** @type {Record<string, string>} */
    const mandatory = {
      ...(response.status === 200 ? { "content-type": "application/json" } : {}),
      "cache-control": "no-store",
    };
    return {
      ...response,
      headers: {
        ...withoutFields(response.headers, [...Object.keys(mandatory), ...CORS_FIELDS, "vary"]),
        ...mandatory,
        ...corsHeaders(origin, this.#credentials, false, this.#authorization),
        vary: varyWithOrigin(response.headers),
      },
    };
  }
}
