// @ts-check

// Shared browser POST admission. The HTTP host supplies the observed Origin
// from its trusted TLS/proxy boundary and owns registration and authentication.
// This function owns the protocol order between that boundary and the issuer
// engine. The original immutable verification result can accompany this request
// into the engine; a copied or mismatched result never waives verification.

import { admitHeader } from "../core-shared--publisher-issuer/jwt.js";
import { checkEnvelopes, publisherFor } from "../core-issuer/IssuerEngine.js";

/**
 * @typedef {{ status: number, headers?: Record<string, string>, body?: unknown }} HttpResponse
 */
/**
 * @typedef {{ kind: 'refused', status: number, code: string, response?: HttpResponse }} BrowserAdmissionRefusal
 */
/**
 * @template T
 * @typedef {{ kind: 'admitted', state: T }|BrowserAdmissionRefusal} BrowserPreverificationGate
 */
/**
 * @template T
 * @typedef {{ kind: 'admitted', request: import('../core-shared--client-issuer/DcaRequest.js').DcaRequest,
 *   registration: import('../core-issuer/IssuerEngine.js').PublisherRegistration,
 *   claims: Awaited<ReturnType<typeof checkEnvelopes>>, state: T|null }|
 *   BrowserAdmissionRefusal} BrowserAdmission
 */

/**
 * Freeze the parsed JSON tree before any await. JSON input is acyclic, but it
 * can be much deeper than the JavaScript call stack, so walk it iteratively.
 * @param {unknown} value
 */
function freezeJson(value) {
  const pending = [value];
  for (let index = 0; index < pending.length; index++) {
    const current = pending[index];
    if (current === null || typeof current !== "object" || Object.isFrozen(current)) continue;
    Object.freeze(current);
    for (const member of Object.values(current)) pending.push(member);
  }
  return value;
}

// The refusals the reference's own header, registration and signature checks
// own. A collaborator's thrown `code`, such as a store's ECONNREFUSED, is not one
// of them even when it is spelled like one, and a broken registration
// (`bad_config`) is the issuer's fault.
const REQUEST_REFUSALS = new Set([
  "bad_jwt",
  "bad_alg",
  "bad_signature",
  "binding_failed",
  "unknown_publisher_key",
]);

/** @returns {BrowserAdmissionRefusal} */
function internalFailure() {
  return { kind: "refused", status: 500, code: "internal_error" };
}

/**
 * @param {unknown} cause - thrown by a reference request check
 * @returns {BrowserAdmissionRefusal}
 */
function checkRefusal(cause) {
  const code = /** @type {any} */ (cause)?.code;
  return REQUEST_REFUSALS.has(code) ? { kind: "refused", status: 400, code } : internalFailure();
}

/**
 * Admit one raw browser POST through structural limits, one issuer-held
 * registration, verified publisher claims and the exact observed Origin.
 * `beforeVerify` may authenticate and capture bounded host context, but may
 * release no key or make a policy decision. It returns `{ kind: 'admitted',
 * state }`, or `{ kind: 'refused', status, code }`. Its state is opaque here.
 *
 * A successful result gives the host a request whose parsed document is
 * frozen, plus the registration it selected. The registration is host-owned.
 * The original immutable claims may be forwarded as invocation.verification.
 * The engine consumes their private provenance once for this request/token/key
 * and origin mode; without a matching result it verifies independently.
 *
 * @template T
 * @param {object} options
 * @param {import('../core-issuer/IssuerProcessor.js').IssuerProcessor} options.processor
 * @param {import('../ports/UnlockEndpoint.js').UnlockEndpoint} options.endpoint
 * @param {string} options.document - raw JSON body, so the byte cap is measured
 * @param {string} options.origin - canonical value from BrowserUnlockHttp
 * @param {(kid: string) => import('../core-issuer/IssuerEngine.js').PublisherRegistration|null|undefined|
 *   Promise<import('../core-issuer/IssuerEngine.js').PublisherRegistration|null|undefined>} options.registrationForKid
 * @param {((registration: import('../core-issuer/IssuerEngine.js').PublisherRegistration) =>
 *   BrowserPreverificationGate<T>|Promise<BrowserPreverificationGate<T>>)} [options.beforeVerify]
 * @param {boolean} [options.developmentHttpOrigin]
 * @returns {Promise<BrowserAdmission<T>>}
 */
export async function admitBrowserRequest({
  processor,
  endpoint,
  document,
  origin,
  registrationForKid,
  beforeVerify,
  developmentHttpOrigin = false,
}) {
  if (typeof document !== "string") {
    return { kind: "refused", status: 400, code: "invalid_json" };
  }
  // Admission checks supported version before version-specific member grammar,
  // publisher registration lookup, caller hooks or signature verification.
  const admission = processor.admit(document);
  if (admission.kind !== "admitted") {
    const mapped = endpoint.refusal(admission);
    return {
      kind: "refused",
      status: mapped.response.status,
      code: mapped.code ?? "internal_error",
      response: mapped.response,
    };
  }
  const request = admission.request;
  freezeJson(request.toObject());

  let kid;
  try {
    kid = admitHeader(request.resourceJWT);
  } catch (cause) {
    return checkRefusal(cause);
  }
  // The registration store and caller admission are host collaborators. Any
  // throw from them is an outage or a bug on this issuer, never a refusal of
  // the request, whatever its error carries.
  let registration;
  try {
    registration = await registrationForKid(kid);
  } catch {
    return internalFailure();
  }
  if (!registration) return { kind: "refused", status: 400, code: "unknown_publisher_key" };
  try {
    publisherFor(request, registration);
  } catch (cause) {
    return checkRefusal(cause);
  }

  /** @type {T|null} */
  let state = null;
  if (beforeVerify !== undefined) {
    let gate;
    try {
      gate = await beforeVerify(registration);
    } catch {
      return internalFailure();
    }
    if (gate?.kind === "refused") return gate;
    if (gate?.kind !== "admitted") {
      return { kind: "refused", status: 500, code: "internal_error" };
    }
    state = gate.state;
  }

  let claims;
  try {
    claims = await checkEnvelopes(request, registration.publicKey, developmentHttpOrigin);
  } catch (cause) {
    return checkRefusal(cause);
  }
  if (claims.resource.origin !== origin) {
    return { kind: "refused", status: 403, code: "origin_refused" };
  }
  if (
    registration.origins !== undefined &&
    (!Array.isArray(registration.origins) ||
      registration.origins.some((entry) => typeof entry !== "string"))
  ) {
    return internalFailure();
  }
  if (registration.origins !== undefined && !registration.origins.includes(origin)) {
    return { kind: "refused", status: 403, code: "origin_refused" };
  }
  return { kind: "admitted", request, registration, claims, state };
}
