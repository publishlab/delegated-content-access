// @ts-check

// Reference-only construction for endpoint-port tests. Its observers assert
// this implementation's adapter mapping, so it must not depend on the
// portable contract tree or be offered as a foreign binding.

import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";

const { subtle } = globalThis.crypto;

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

export const referenceIssuerEndpointPortDriver = {
  importIssuerPrivateKey(jwk) {
    return subtle.importKey("jwk", jwk, ECDH_P256, false, ["deriveBits"]);
  },

  importPublisherPublicKey(jwk) {
    return subtle.importKey("jwk", jwk, ECDSA_P256, true, ["verify"]);
  },

  createIssuerEndpoint(config) {
    const engine = new IssuerEngine({
      accessPolicy: config.accessPolicy,
    });
    const processor = new IssuerProcessor(engine, {
      limits: config.limits,
      exactPeriodInput: true,
    });
    const endpoint = new UnlockEndpoint(processor, { errorDetail: config.errorDetail });
    return {
      async unlock(rawRequest, input = {}) {
        const { response } = await endpoint.handleDocument(
          rawRequest,
          config.publisherRegistration,
          {
            principal: input.principal,
            context: input.policyContext,
          },
        );
        return response;
      },
    };
  },
};
