// @ts-check

// The reference binding for the wire-only issuer-endpoint contract. It is
// deliberately the only contract-test module that knows today's class names.

import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { admitHeader } from "../../../core-shared--publisher-issuer/jwt.js";

const { subtle } = globalThis.crypto;

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

/**
 * The registration an admitted request's header `kid` selects. The `kid` is an
 * untrusted lookup hint; verification under the selected key decides.
 *
 * @param {import('../../../core-shared--client-issuer/DcaRequest.js').DcaRequest} request
 * @param {Map<string, any>} registrations
 */
function registrationFor(request, registrations) {
  try {
    return registrations.get(admitHeader(request.resourceJWT));
  } catch {
    // The engine refuses the same header again with its own code.
    return undefined;
  }
}

/** @type {import('../support/issuer-endpoint-contract.js').IssuerEndpointDriver} */
export const referenceIssuerEndpointDriver = {
  importIssuerPrivateKey(jwk) {
    return subtle.importKey("jwk", jwk, ECDH_P256, false, ["deriveBits"]);
  },

  importPublisherPublicKey(jwk) {
    return subtle.importKey("jwk", jwk, ECDSA_P256, true, ["verify"]);
  },

  createIssuerEndpoint(config) {
    const registrations =
      config.publisherRegistrations ??
      (config.publisherRegistration ? [config.publisherRegistration] : []);
    const engine = new IssuerEngine({
      operatingIssuerNames: config.operatingIssuerNames,
      accessPolicy: config.accessPolicy,
    });
    const openingKeys = {
      get(issuerName, keyId) {
        return issuerName === config.issuerName && keyId === config.keyId
          ? config.issuerKeys.get(issuerName, keyId)
          : undefined;
      },
    };
    const publisherRegistrations = new Map(
      registrations.map((entry) => [entry.kid, Object.freeze({ ...entry, openingKeys })]),
    );
    const processor = new IssuerProcessor(engine, {
      limits: config.limits,
      periodKeyInput: true,
    });
    const endpoint = new UnlockEndpoint(processor, {
      errorDetail: config.errorDetail,
    });

    return {
      // Core 6.2 order: admission measures, parses and checks the version of the
      // raw body once; only an admitted request selects a registration, and
      // that same admitted value is processed.
      async unlock(rawRequest, input = {}) {
        const admission = processor.admit(rawRequest);
        if (admission.kind !== "admitted") return endpoint.refusal(admission).response;
        const { response } = await endpoint.handleRequest({
          request: admission.request,
          registration: registrationFor(admission.request, publisherRegistrations),
          policyInput: { principal: input.principal, context: input.policyContext },
        });
        return response;
      },
    };
  },
};

/** @type {import('../support/issuer-endpoint-contract.js').IssuerEndpointBinding} */
export const dcaTestBinding = {
  targets: {
    "issuer-endpoint": {
      versions: ["1"],
      deliveryModes: ["direct"],
      contractProfiles: ["dca-profile-period-keys"],
      observations: [],
      driver: referenceIssuerEndpointDriver,
    },
  },
};
