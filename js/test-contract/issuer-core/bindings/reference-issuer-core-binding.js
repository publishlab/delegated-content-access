// @ts-check

import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { decodeCompactJwt } from "../../../core-shared/compactJwt.js";

const { subtle } = globalThis.crypto;
const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

export const referenceIssuerCoreDriver = {
  importIssuerPrivateKey(jwk) {
    return subtle.importKey("jwk", jwk, ECDH_P256, false, ["deriveBits"]);
  },

  importPublisherPublicKey(jwk) {
    return subtle.importKey("jwk", jwk, ECDSA_P256, true, ["verify"]);
  },

  createIssuerCore(provisioning) {
    const keyStore = {
      get(issuerName, keyId) {
        return issuerName === provisioning.issuerKey.issuerName &&
          keyId === provisioning.issuerKey.keyId
          ? provisioning.issuerKey
          : undefined;
      },
    };
    const registrations = new Map(
      provisioning.publisherRegistrations.map((entry) => [
        entry.kid,
        Object.freeze({ ...entry, openingKeys: keyStore }),
      ]),
    );
    const engine = new IssuerEngine({
      operatingIssuerNames: [provisioning.issuerKey.issuerName],
      accessPolicy: {
        decide(claims, requested) {
          void claims;
          const policy = provisioning.policy;
          return {
            contentNames:
              policy.contentNames === "requested" ? requested.contentNames : policy.contentNames,
            periodGrants:
              policy.periodGrants === "requested"
                ? requested.accessGroups.map((accessGroup) => ({
                    accessGroup,
                    periods: requested.periodCoordinates[accessGroup] ?? [],
                  }))
                : policy.periodGrants,
            policyData: policy.policyData,
          };
        },
      },
    });
    const processor = new IssuerProcessor(engine, { periodKeyInput: true });
    return {
      admit(rawRequest) {
        const result = processor.admit(rawRequest);
        return result.kind === "admitted" ? { kind: "admitted", handle: result.request } : result;
      },
      processMiss(invocation) {
        const { request } = invocation;
        const { header } = decodeCompactJwt(request.resourceJWT);
        return processor.processMiss({
          ...invocation,
          registration: registrations.get(header.kid),
        });
      },
    };
  },
};

export const dcaTestBinding = {
  targets: {
    "issuer-core": {
      versions: ["1"],
      deliveryModes: ["direct"],
      contractProfiles: ["dca-profile-period-keys"],
      observations: [],
      driver: referenceIssuerCoreDriver,
    },
  },
};
