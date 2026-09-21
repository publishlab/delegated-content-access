// @ts-check

import { referenceIssuerCoreDriver } from "./reference-issuer-core-binding.js";

const wrongResultDriver = {
  ...referenceIssuerCoreDriver,
  createIssuerCore(provisioning) {
    const core = referenceIssuerCoreDriver.createIssuerCore(provisioning);
    return {
      ...core,
      async processMiss(invocation) {
        const result = await core.processMiss(invocation);
        return result.kind === "success"
          ? { ...result, policyData: ["wrong-policy-data"] }
          : result;
      },
    };
  },
};

export const dcaTestBinding = {
  targets: {
    "issuer-core": {
      versions: ["1"],
      deliveryModes: ["direct"],
      contractProfiles: ["dca-v1-exact-period"],
      observations: [],
      driver: wrongResultDriver,
    },
  },
};
