// This composition selects compact envelopes for the ordinary chain-key case.
import { createScenario } from "./groups.js";
import { compactEcdhPublisherContribution } from "../../../../extensions/compact-ecdh/core-publisher/keySealing.js";
import { compactEcdhIssuerContribution } from "../../../../extensions/compact-ecdh/core-issuer/procedure.js";

export const scenario = createScenario({
  compactEcdhPublisherContribution,
  compactEcdhIssuerContribution,
  defaultVariant: "compact-ecdh",
});
