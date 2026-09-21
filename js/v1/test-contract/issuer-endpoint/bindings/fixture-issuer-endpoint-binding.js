// @ts-check

// A second shape around the same reference endpoint. Its construction, call,
// and result container deliberately differ from the reference binding; the
// declared driver only translates those containers and never changes a result.

import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { decodeCompactJwt } from "../../../core-shared/compactJwt.js";

const { subtle } = globalThis.crypto;

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

function registrationFor(rawRequest, registrations) {
  try {
    const { header } = decodeCompactJwt(JSON.parse(rawRequest).resourceJWT);
    return registrations.get(header.kid);
  } catch {
    return undefined;
  }
}

/** @param {any} config */
function mountFixtureIssuer(config) {
  const registrations =
    config.publisherRegistrations ??
    (config.publisherRegistration ? [config.publisherRegistration] : []);
  const issuerCore = new IssuerEngine({
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
    exactPeriodInput: true,
  });
  const station = new UnlockEndpoint(admission, { errorDetail: config.errorDetail });

  return {
    async serveDocument(document, provisioning = {}) {
      const envelope = await station.handleDocument(
        document,
        registrationFor(document, publisherRegistrations),
        {
          principal: provisioning.principal,
          context: provisioning.policyContext,
        },
      );
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
      contractProfiles: ["dca-v1-exact-period"],
      observations: [],
      driver: fixtureIssuerEndpointDriver,
    },
  },
};
