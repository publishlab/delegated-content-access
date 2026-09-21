// @ts-check

// The reference binding for the wire-only issuer-endpoint contract. It is
// deliberately the only contract-test module that knows today's class names.

import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { decodeCompactJwt } from "../../../core-shared/compactJwt.js";

const { subtle } = globalThis.crypto;

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

function registrationFor(rawRequest, registrations) {
  try {
    const request = JSON.parse(rawRequest);
    const { header } = decodeCompactJwt(request.resourceJWT);
    return registrations.get(header.kid);
  } catch {
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
      exactPeriodInput: true,
    });
    const endpoint = new UnlockEndpoint(processor, {
      errorDetail: config.errorDetail,
    });

    return {
      async unlock(rawRequest, input = {}) {
        const registration = registrationFor(rawRequest, publisherRegistrations);
        const { response } = await endpoint.handleDocument(rawRequest, registration, {
          principal: input.principal,
          context: input.policyContext,
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
      contractProfiles: ["dca-v1-exact-period"],
      observations: [],
      driver: referenceIssuerEndpointDriver,
    },
  },
};
