// @ts-check

import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { createBrowserIssuer } from "../../../integration-issuer/createBrowserIssuer.js";

/** @type {import('../support/issuer-browser-origin-contract.js').BrowserIssuerDriver} */
const driver = {
  importIssuerPrivateKey(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, [
      "deriveBits",
    ]);
  },
  importPublisherPublicKey(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, [
      "verify",
    ]);
  },
  createBrowserIssuer(config) {
    const core = createIssuerCore({
      operatingIssuerNames: config.operatingIssuerNames,
      accessPolicy: config.accessPolicy,
      periodKeyInput: false,
    });
    const browser = createBrowserIssuer({
      core,
      registrationForKid: config.registrationForKid,
      admitCaller: config.admitCaller,
      clock: config.clock,
      preflight: () => true,
    });
    return {
      unlock(rawRequest, input) {
        return browser.handle({
          method: "POST",
          contentType: input.contentType,
          body: rawRequest,
          origin: input.origin,
          hostContext: input.hostContext,
        });
      },
    };
  },
};

export const dcaTestBinding = {
  targets: {
    "issuer-browser-origin": {
      versions: ["1"],
      deliveryModes: ["direct"],
      contractProfiles: ["dca-profile-browser-origin"],
      observations: ["registration-policy-opening-order"],
      driver,
    },
  },
};
