// @ts-check

// Host composition for the dca-profile-recipient-grant-unlock profile. Grant
// issuance, reference encoding and storage stay with the host. This entry
// verifies the publisher before looking up a bearer, then gives issuer core
// only a grant-scoped policy decision. Issuer core still owns key opening.
//
// An envelope contribution, such as compact ECDH's, only adds a way to open
// the item keys a key entry permits. A contribution that would answer another
// section or admit another request coordinate is refused at construction, so
// no contribution widens the item-only grant scope.

import { createIssuerCore } from "../../integration-issuer/createIssuerCore.js";
import { BrowserUnlockHttp } from "../../adapter-issuer/BrowserUnlockHttp.js";
import { parseBearerAuthorization } from "../../adapter-issuer/parseBearerAuthorization.js";
import { checkEnvelopes, checkVersion, publisherFor } from "../../core-issuer/IssuerEngine.js";
import { normalizePublisherOrigin } from "../../core-shared/publisherOrigin.js";
import { dcaError } from "../../core-shared/errors.js";

/** @param {unknown} value @returns {value is Record<string, any>} */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const ENVELOPE_CONTRIBUTION_MEMBERS = Object.freeze(["name", "envelopeProcedures"]);

/** @param {unknown} contribution */
function isEnvelopeContribution(contribution) {
  return (
    record(contribution) &&
    Object.hasOwn(contribution, "envelopeProcedures") &&
    Object.keys(contribution).every((member) => ENVELOPE_CONTRIBUTION_MEMBERS.includes(member))
  );
}

/** @param {any} grant @param {string} issuerId @param {string} registrationId @param {string} resourceId @param {number} nowMs @returns {grant is GrantRecord} */
function admittedGrant(grant, issuerId, registrationId, resourceId, nowMs) {
  return (
    record(grant) &&
    grant.purpose === "recipient-unlock" &&
    grant.issuerId === issuerId &&
    grant.publisherRegistrationId === registrationId &&
    grant.resourceId === resourceId &&
    Number.isFinite(grant.notBeforeMs) &&
    Number.isFinite(grant.expiresAtMs) &&
    grant.notBeforeMs < grant.expiresAtMs &&
    grant.notBeforeMs <= nowMs &&
    nowMs < grant.expiresAtMs &&
    grant.revoked === false &&
    Array.isArray(grant.contentNames) &&
    grant.contentNames.length > 0 &&
    grant.contentNames.every(
      (/** @type {unknown} */ name) => typeof name === "string" && name.length > 0,
    )
  );
}

/**
 * The refusal code a pre-key request check threw, or the error itself when it is
 * a host fault: a broken registration (`bad_config`) or a throw that carries no
 * code is the issuer's failure, never the request's 400.
 *
 * @param {unknown} error
 * @returns {string}
 */
function requestRefusalCode(error) {
  const code = /** @type {any} */ (error)?.code;
  if (typeof code !== "string" || code === "bad_config") throw error;
  return code;
}

/**
 * @typedef {{ purpose: 'recipient-unlock', issuerId: string, publisherRegistrationId: string,
 *   resourceId: string, contentNames: string[], notBeforeMs: number,
 *   expiresAtMs: number, revoked: boolean }} GrantRecord
 */

/** @typedef {import('../../core-issuer/IssuerEngine.js').PublisherRegistration & { registrationId: string }} GrantRegistration */

/** @param {unknown} registration @returns {registration is GrantRegistration} */
function hasRegistrationId(registration) {
  return (
    record(registration) &&
    typeof registration.registrationId === "string" &&
    registration.registrationId.length > 0
  );
}

/**
 * @param {object} config
 * @param {string} config.issuerId - this endpoint's trusted issuer identity
 * @param {string[]} config.operatingIssuerNames - names this endpoint serves
 * @param {{ get: (reference: string, options: {nowMs: number}) => GrantRecord|null|undefined|Promise<GrantRecord|null|undefined> }} config.grants
 * @param {import('../../core-issuer/IssuerEngine.js').AccessPolicy} config.accessPolicy
 * @param {boolean} [config.developmentHttpOrigin]
 * @param {'code'|'uniform'} [config.errorDetail] - disclosure for grant and DCA request refusals
 * @param {() => number} [config.now]
 * @param {...{ name: string, envelopeProcedures: Record<string, any> }} contributions - envelope
 *   contributions for the base engine, such as `compactEcdhIssuerContribution()`
 */
export function createRecipientGrantIssuer(config, ...contributions) {
  if (!record(config)) {
    throw dcaError("bad_config", "recipient-grant issuer needs one configuration object");
  }
  if (!contributions.every(isEnvelopeContribution)) {
    throw dcaError(
      "bad_config",
      "a recipient-grant issuer takes envelope contributions only: a name and its envelopeProcedures",
    );
  }
  const {
    issuerId,
    operatingIssuerNames,
    grants,
    accessPolicy,
    developmentHttpOrigin = false,
    errorDetail = "code",
    now = Date.now,
  } = config;
  if (
    !issuerId ||
    typeof issuerId !== "string" ||
    !Array.isArray(operatingIssuerNames) ||
    operatingIssuerNames.length === 0 ||
    typeof grants?.get !== "function" ||
    typeof accessPolicy?.decide !== "function" ||
    typeof now !== "function"
  ) {
    throw dcaError("bad_config", "recipient-grant issuer needs identity, store, policy and clock");
  }

  /** @type {WeakMap<object, { contentNames: string[], policyContext: any }>} */
  const scope = new WeakMap();
  /** @type {import('../../core-issuer/IssuerEngine.js').AccessPolicy} */
  const scopedPolicy = {
    async decide(claims, requested, input) {
      const grant = scope.get(input.context);
      if (!grant) throw dcaError("bad_config", "recipient-grant policy has no admitted scope");
      const allowed = new Set(grant.contentNames);
      const names = requested.contentNames.filter((name) => allowed.has(name));
      const decision = await accessPolicy.decide(
        claims,
        { contentNames: names, accessGroups: [], periodCoordinates: {} },
        { ...input, context: grant.policyContext },
      );
      if (!record(decision)) return decision;
      return {
        ...decision,
        contentNames: Array.isArray(decision.contentNames)
          ? decision.contentNames.filter((name) => allowed.has(name))
          : decision.contentNames,
        periodGrants: [],
      };
    },
  };
  const { processor, endpoint } = createIssuerCore(
    {
      operatingIssuerNames,
      accessPolicy: scopedPolicy,
      developmentHttpOrigin,
      errorDetail,
    },
    ...contributions,
  );

  /** @param {string} code */
  function refusal(code = "denied") {
    return {
      status: code === "denied" ? 401 : 400,
      body: endpoint.admissionRefusalBody(code),
    };
  }

  /**
   * @param {object} input
   * @param {string} input.document - raw DCA JSON request
   * @param {GrantRegistration} input.registration - issuer-owned stable identity shared by signing-key entries
   * @param {string|string[]|undefined} input.authorization - one HTTP field value; arrays represent duplicates
   * @param {string} [input.observedOrigin] - present for a selected browser-origin request
   * @param {any} [input.policyContext] - trusted host context for current policy
   * @param {number} [input.capturedAtMs] - host-captured instant for grant validity and core
   * @returns {Promise<{ status: number, body: any }>}
   */
  async function unlock({
    document,
    registration,
    authorization,
    observedOrigin,
    policyContext,
    capturedAtMs,
  }) {
    if (!parseBearerAuthorization(authorization)) return refusal();
    const admission = processor.admit(document);
    if (admission.kind !== "admitted") return endpoint.refusal(admission).response;
    return unlockRequest({
      request: admission.request,
      registration,
      authorization,
      observedOrigin,
      policyContext,
      capturedAtMs,
    });
  }

  /**
   * Private handoff: only this composition can supply the request and its
   * verified claims. The public document entry never accepts a verification.
   *
   * @param {object} input
   * @param {import('../../core-shared--client-issuer/DcaRequest.js').DcaRequest} input.request
   * @param {import('../../core-issuer/IssuerEngine.js').VerifiedClaims} [input.verification]
   * @param {GrantRegistration} input.registration
   * @param {string|string[]|undefined} input.authorization
   * @param {string} [input.observedOrigin]
   * @param {any} [input.policyContext]
   * @param {number} [input.capturedAtMs]
   */
  async function unlockRequest({
    request,
    verification,
    registration,
    authorization,
    observedOrigin,
    policyContext,
    capturedAtMs,
  }) {
    const reference = parseBearerAuthorization(authorization);
    if (!reference) return refusal();
    if (!hasRegistrationId(registration)) return refusal("binding_failed");
    // Grant presentation forbids the wire presence of these four members, even
    // empty. The admitted request holds the one parsed document with explicit
    // empty sections intact, so check that value instead of reparsing the bytes,
    // which would also refuse the one initial BOM admission accepts.
    const presented = request.toObject();
    if (
      Object.hasOwn(presented.sealed ?? {}, "periodKeys") ||
      Object.hasOwn(presented.sealed ?? {}, "chainKeys") ||
      Object.hasOwn(presented, "periodGeometry") ||
      Object.hasOwn(presented, "chainGeometry") ||
      Object.hasOwn(presented, "requestedPeriodKeys")
    )
      return refusal("binding_failed");

    let claims;
    try {
      checkVersion(request);
      publisherFor(request, registration);
      claims =
        verification ??
        (await checkEnvelopes(request, registration.publicKey, developmentHttpOrigin));
    } catch (error) {
      return refusal(requestRefusalCode(error));
    }
    if (observedOrigin !== undefined) {
      if (
        normalizePublisherOrigin(observedOrigin) !== observedOrigin ||
        claims.resource.origin !== observedOrigin ||
        (registration.origins && !registration.origins.includes(observedOrigin))
      ) {
        return refusal("binding_failed");
      }
    }

    if (capturedAtMs !== undefined && !Number.isFinite(capturedAtMs))
      throw dcaError("bad_config", "captured grant clock must be finite");
    const instant = capturedAtMs ?? now();
    if (!Number.isFinite(instant)) throw dcaError("bad_config", "grant clock must be finite");
    const grant = await grants.get(reference, { nowMs: instant });
    if (
      !admittedGrant(
        grant,
        issuerId,
        registration.registrationId,
        claims.resource.resourceId,
        instant,
      )
    ) {
      return refusal();
    }
    const token = {};
    scope.set(token, { contentNames: [...grant.contentNames], policyContext });
    try {
      const outcome = await endpoint.handleRequest({
        request,
        registration,
        verification: claims,
        policyInput: { principal: { kind: "recipient-grant" }, context: token },
        capturedAtMs: instant,
      });
      // Core's content-key-only selection produces item content keys only. Guard
      // the port result too, so a later extension cannot widen this profile.
      const body = /** @type {any} */ (outcome.response.body);
      if (
        outcome.response.status === 200 &&
        (Object.hasOwn(body?.keys ?? {}, "periodKeys") ||
          Object.hasOwn(body?.keys ?? {}, "chainKeys") ||
          Object.hasOwn(body ?? {}, "periodGeometry") ||
          Object.hasOwn(body ?? {}, "chainGeometry"))
      )
        return refusal("binding_failed");
      return outcome.response;
    } finally {
      scope.delete(token);
    }
  }

  /**
   * Compose browser HTTP admission with this grant endpoint. The host selects
   * a publisher registration in `hostContext.registration` and supplies its
   * preflight origin policy. Signed-origin verification precedes CORS permission
   * and grant lookup. The admitted request and its verification stay private
   * to this call and are handed through to issuer core without repeating work.
   *
   * @param {(origin: string) => boolean|Promise<boolean>} preflightOrigin
   * @returns {BrowserUnlockHttp}
   */
  function browserHttp(preflightOrigin) {
    if (typeof preflightOrigin !== "function") {
      throw dcaError("bad_config", "browser grant profile needs a preflight origin policy");
    }
    return new BrowserUnlockHttp({
      authorization: true,
      errorBody: (code) => endpoint.admissionRefusalBody(code),
      originAdmission: {
        preflight: preflightOrigin,
        async admit(origin, document, hostContext) {
          const admission = processor.admit(document);
          if (admission.kind !== "admitted") {
            return { kind: "refused", response: endpoint.refusal(admission).response };
          }
          if (!hasRegistrationId(hostContext?.registration)) {
            return { kind: "refused", response: refusal("binding_failed") };
          }
          let claims;
          try {
            checkVersion(admission.request);
            publisherFor(admission.request, hostContext?.registration);
            claims = await checkEnvelopes(
              admission.request,
              hostContext.registration.publicKey,
              developmentHttpOrigin,
            );
            if (
              claims.resource.origin !== origin ||
              (hostContext.registration.origins &&
                !hostContext.registration.origins.includes(origin))
            ) {
              return { kind: "refused", response: refusal("binding_failed") };
            }
          } catch (error) {
            return { kind: "refused", response: refusal(requestRefusalCode(error)) };
          }
          return {
            kind: "admitted",
            context: { registration: hostContext.registration, request: admission.request, claims },
          };
        },
      },
      unlock(document, context) {
        return unlockRequest({
          request: context.admission.request,
          verification: context.admission.claims,
          registration: context.admission.registration,
          authorization: context.authorization,
          observedOrigin: context.origin,
          policyContext: context.hostContext?.policyContext,
          capturedAtMs: context.hostContext?.capturedAtMs,
        });
      },
    });
  }

  return Object.freeze({ unlock, browserHttp });
}
