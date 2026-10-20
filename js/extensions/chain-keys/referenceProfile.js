// @ts-check

// The reference chain-key capability is composed outside the base role
// cores. It supplies one geometry to publisher, issuer and client without
// making a normal period-key deployment depend on chains.
//
// The publisher half generates the family. `familyGenerationFor` makes one
// immutable generation of the fixed `dca-construction-chain-keys` construction over a
// family root and a complete geometry, and `periodKeySupplyFor` narrows it to the
// `derive(accessGroup, t)` the base `Sealer` takes. The composition keeps the
// generation itself, which is what a later issuer-supply plan asks for a
// positioned capability; base receives the narrow supply and no way back to it.
// The client response/cache half consumes only explicit frozen-v1 geometry.

import { periodKeySupplyFor } from "./core-publisher/periodKeySupplyFor.js";
import { periodFamilyGeneration } from "./core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "./core-publisher/periodFamilySupply.js";
import { chainKeyIssuerEngine } from "./core-issuer/chainKeyIssuerEngine.js";
import {
  chainKeyClientProfileFor,
  explicitChainKeyClientProfile,
} from "./core-client/chainKeyClientProfile.js";
export { chainKeyClientProfileFor, explicitChainKeyClientProfile };
import {
  CHAIN_KEY_CONSTRUCTION,
  chainKeyConstructionProfile,
} from "./core-shared/chainKeyConstruction.js";
import { chainMemberLimit } from "../../core-shared/chainMemberLimit.js";
import { dcaError } from "../../core-shared/errors.js";

/** Refuse a conflicting trusted selection instead of silently rewriting it.
 * @param {any} config @param {string} member @param {string|number} value
 */
function pinned(config, member, value) {
  if (Object.hasOwn(config, member) && config[member] !== value)
    throw dcaError("bad_config", `profile requires ${member} ${value}`);
  return { ...config, [member]: value };
}

/**
 * The whole reference composition of one named construction profile: the
 * publisher generation, the issuer route and the client bundle, all on that one
 * profile. A composition naming none is on `dca-construction-chain-keys`, so every
 * existing caller composes what it always composed.
 *
 * @param {string} [construction]
 * @param {{ maxChainMembersPerMessage?: number }} [config] - trusted capacity, default 16
 * @returns {Readonly<ReturnType<typeof chainKeyClientProfileFor> & {
 * familyGenerationFor: (config: object) => ReturnType<typeof periodFamilyGeneration>,
 * periodKeySupplyFor: typeof periodKeySupplyFor, familySupplyFor: typeof periodFamilySupply,
 * issuerEngineFor: (config: object) => ReturnType<typeof chainKeyIssuerEngine>,
 * explicitIssuerEngineFor: (config: object) => ReturnType<typeof chainKeyIssuerEngine>
 * }>}
 */
export function referenceChainKeyProfileFor(
  construction = CHAIN_KEY_CONSTRUCTION,
  { maxChainMembersPerMessage } = {},
) {
  const maximum = chainMemberLimit(maxChainMembersPerMessage);
  const { name } = chainKeyConstructionProfile(construction);
  return Object.freeze({
    // The publisher half: one generation, and the period-key-only view of it
    // that base is handed.
    /** @param {object} config */
    familyGenerationFor: (config) => periodFamilyGeneration(pinned(config, "construction", name)),
    periodKeySupplyFor: periodKeySupplyFor,
    familySupplyFor: periodFamilySupply,
    ...chainKeyClientProfileFor(name, { maxChainMembersPerMessage: maximum }),
    // A deployment selects chain output only for chain-capable clients and
    // thereby authorizes stationary-window-start through cutoff reach.
    /** @param {object} config */
    issuerEngineFor: (config) =>
      chainKeyIssuerEngine(
        pinned(
          pinned(pinned(config, "maxChainMembersPerMessage", maximum), "construction", name),
          "representation",
          "chain-keys",
        ),
      ),

    // Relay-capable, period-key-only issuer projection.
    /** @param {object} config */
    explicitIssuerEngineFor: (config) =>
      chainKeyIssuerEngine(
        pinned(
          pinned(pinned(config, "maxChainMembersPerMessage", maximum), "construction", name),
          "representation",
          "period-keys",
        ),
      ),
  });
}

/** The reference composition of the construction a caller naming none is on. */
export const referenceChainKeyProfile = referenceChainKeyProfileFor(CHAIN_KEY_CONSTRUCTION);
