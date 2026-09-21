// @ts-check

import { referenceIssuerEndpointDriver } from "./reference-issuer-endpoint-binding.js";

const wrongStatusDriver = {
  ...referenceIssuerEndpointDriver,
  createIssuerEndpoint(config) {
    const endpoint = referenceIssuerEndpointDriver.createIssuerEndpoint(config);
    return {
      async unlock(rawRequest, input) {
        const response = await endpoint.unlock(rawRequest, input);
        return response.status === 401 ? { ...response, status: 400 } : response;
      },
    };
  },
};

export const dcaTestBinding = {
  targets: {
    "issuer-endpoint": {
      versions: ["1"],
      deliveryModes: ["direct"],
      contractProfiles: ["dca-v1-exact-period"],
      observations: [],
      driver: wrongStatusDriver,
    },
  },
};
