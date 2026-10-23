import { createPublisher } from "../../../../integration-publisher/createPublisher.js";
import { createIssuerCore } from "../../../../integration-issuer/createIssuerCore.js";
import { periodFamilyGeneration } from "../../../../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../../../../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { chainKeyCapabilitySource } from "../../../../extensions/chain-keys/core-issuer/chainKeyCapabilitySource.js";
import { requireChainRepresentation } from "../../../../extensions/chain-keys/core-issuer/chainKeyIssuerEngine.js";
import { chainKeyCapabilityEncoderFor } from "../../../../extensions/chain-keys/core-issuer/chainKeyCapabilityEncoder.js";
import { keys, registrationFor, random, ISSUER, FIXTURE_SECRET } from "../_shared/exchange.js";

export const REQUEST_LIMITS = Object.freeze({
  maxBodyBytes: 2_000_000,
  maxEntries: 4096,
  maxEntriesPerGroup: 512,
});

export async function assembleGroupRoles({
  p,
  i,
  observe,
  clock = { now: () => new Date(p.at) },
  representation = "chain-keys",
  compact = false,
  compactEcdhPublisherContribution,
  compactEcdhIssuerContribution,
}) {
  const maximum = p.maxChainMembersPerMessage;
  const groups = [...new Set(p.items.flatMap((item) => item.groups))];
  const generated = await keys();
  const registration = registrationFor(generated, compact);
  const families = Object.fromEntries(
    groups.map((group) => {
      observe.count("familyGeneration");
      const generation = periodFamilyGeneration({
        keyDerivationSecret: FIXTURE_SECRET,
        geometry: p.periodGeometry,
      });
      return [
        group,
        Object.freeze({
          ...generation,
          periodKey: (...args) =>
            observe.time("chain.periodKey", () => generation.periodKey(...args), {
              nested: true,
              step: true,
            }),
          chainCapability: (...args) =>
            observe.time("chain.chainCapability", () => generation.chainCapability(...args), {
              nested: true,
              step: true,
            }),
        }),
      ];
    }),
  );
  const publisher = createPublisher(
    {
      origin: p.origin,
      clock,
      random,
      signingKeys: { p1: generated.signing.privateKey },
      period: { length: p.periodGeometry.periodMinutes, slots: p.itemPeriods },
      periodKeySupply: periodFamilySupply({
        families,
        chainWindows: p.sourceWindows,
        chainItemSlots: p.itemPeriods,
      }),
      issuerSupplyPlanFor: (_issuer, render) => ({
        contentKeyNames: [],
        suppliedAccessGroups: render.accessGroups,
        reachableContentNames: render.contentNames,
        periodKeyDelivery: Object.fromEntries(
          render.accessGroups.map((group) => [group, ["period-keys", "chain-keys"]]),
        ),
      }),
      issuers: [
        {
          issuerName: ISSUER,
          keyId: "k1",
          algorithm: "ecdh-p256",
          publicKey: generated.opening.publicKey,
          limits: REQUEST_LIMITS,
          maxChainMembersPerMessage: maximum,
          ...(compact ? { envelope: "compact-ecdh" } : {}),
        },
      ],
    },
    ...(compact ? [compactEcdhPublisherContribution()] : []),
  );
  const issuer = createIssuerCore(
    {
      operatingIssuerNames: [ISSUER],
      limits: REQUEST_LIMITS,
      selectedExtensions: ["chain-keys"],
      capabilityEncoders: { "chain-keys": chainKeyCapabilityEncoderFor() },
      periodCapabilitySource: requireChainRepresentation(
        chainKeyCapabilitySource({
          representation,
          maxChainMembersPerMessage: maximum,
        }),
      ),
      accessPolicy: {
        decide: (_claims, requested) => ({
          contentNames: [],
          periodGrants: requested.accessGroups
            .filter((g) => i.authorizedGroups.includes(g))
            .map((accessGroup) => ({
              accessGroup,
              futurePeriodCount: i.horizon + 1,
              authorizePeriod: () => true,
            })),
        }),
      },
    },
    ...(compact ? [compactEcdhIssuerContribution()] : []),
  );
  return { publisher, issuer, registration };
}
