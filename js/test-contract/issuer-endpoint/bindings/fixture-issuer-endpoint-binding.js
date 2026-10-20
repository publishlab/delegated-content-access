// @ts-check

// A second shape around the same reference endpoint. Its construction, call,
// and result container deliberately differ from the reference binding; the
// declared driver only translates those containers and never changes a result.

import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { admitHeader } from "../../../core-shared--publisher-issuer/jwt.js";

const { subtle } = globalThis.crypto;

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

/**
 * The registration an admitted request's header `kid` selects; the `kid` is
 * only a lookup hint.
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

/** @param {any} config */
function mountFixtureIssuer(config) {
  const registrations =
    config.publisherRegistrations ??
    (config.publisherRegistration ? [config.publisherRegistration] : []);
  const issuerCore = new IssuerEngine({
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
  const admission = new IssuerProcessor(issuerCore, {
    limits: config.limits,
    periodKeyInput: true,
  });
  const station = new UnlockEndpoint(admission, { errorDetail: config.errorDetail });

  return {
    // Core 6.2 order, as in the reference binding: admission caps, parses and
    // checks the version of the raw document once, and only that admitted
    // value selects a registration and is processed.
    async serveDocument(document, provisioning = {}) {
      const admitted = admission.admit(document);
      if (admitted.kind !== "admitted") {
        return { deliveredWire: station.refusal(admitted).response };
      }
      const envelope = await station.handleRequest({
        request: admitted.request,
        registration: registrationFor(admitted.request, publisherRegistrations),
        policyInput: {
          principal: provisioning.principal,
          context: provisioning.policyContext,
        },
      });
      return { deliveredWire: envelope.response };
    },
  };
}

/** @type {import('../support/issuer-endpoint-contract.js').IssuerEndpointDriver} */
const fixtureIssuerEndpointDriver = {
  importIssuerPrivateKey(jwk) {
    return subtle.importKey("jwk", jwk, ECDH_P256, false, ["deriveBits"]);
  },

  importPublisherPublicKey(jwk) {
    return subtle.importKey("jwk", jwk, ECDSA_P256, true, ["verify"]);
  },

  createIssuerEndpoint(config) {
    const fixture = mountFixtureIssuer(config);
    return {
      async unlock(rawRequest, input = {}) {
        const { deliveredWire } = await fixture.serveDocument(rawRequest, input);
        return deliveredWire;
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
      driver: fixtureIssuerEndpointDriver,
    },
  },
};
