// @ts-check
// Hourly real publisher/issuer/client composition shared by the T0 witnesses
// and their saved wire-size comparison. No capability is seeded by this world.
import { actorWorld } from "../../../demo/scenarios/world.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { ISSUER_NAME, UNLOCK_URL, ORIGIN } from "../../../demo/scenarios/fixtures.js";
import { referenceChainKeyProfile } from "../referenceProfile.js";
import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";

export const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
export const TEXT = "<p>Hourly T0 article.</p>";
export const BEFORE = "2025-10-23T11:59:00Z";

export async function t0World({
  chainItemSlots = undefined,
  groups = ["premium"],
  ordinary = false,
  secretFill = 7,
  authorizePeriod = () => true,
  representation = "chain-keys",
} = {}) {
  const families = Object.fromEntries(
    groups.map((group, index) => [
      group,
      periodFamilyGeneration({
        keyDerivationSecret: new Uint8Array(32).fill(secretFill + index),
        geometry: GEOMETRY,
      }),
    ]),
  );
  const supply = periodFamilySupply({
    families,
    chainWindows: 2,
    periodKeySupply: {
      async derive() {
        return new Uint8Array(16).fill(31);
      },
    },
    ...(chainItemSlots === undefined ? {} : { chainItemSlots }),
  });
  const profile =
    representation === "period-keys"
      ? {
          ...referenceChainKeyProfile,
          issuerEngineFor: referenceChainKeyProfile.explicitIssuerEngineFor,
        }
      : referenceChainKeyProfile;
  const world = await actorWorld({
    at: BEFORE,
    period: { length: 60, slots: 2 },
    periodKeySupply: supply,
    issuerSupplyPlanFor: (_issuer, render) => ({
      contentKeyNames: [],
      suppliedAccessGroups: render.accessGroups,
      reachableContentNames: render.contentNames,
      periodKeyDelivery: Object.fromEntries(
        render.accessGroups.map((group) => [
          group,
          [group === "archive" ? "period-keys" : "chain-keys"],
        ]),
      ),
    }),
    accessPolicy: {
      decide(_claims, requested) {
        return {
          contentNames: [],
          periodGrants: requested.accessGroups.map((accessGroup) => ({
            accessGroup,
            ...(accessGroup === "archive"
              ? { periods: requested.periodCoordinates[accessGroup] }
              : { futurePeriodCount: 7, authorizePeriod }),
          })),
        };
      },
    },
    chainKeyProfile: profile,
    primary: { periodGrantKind: "chain-keys" },
  });
  return {
    world,
    families,
    async render(at = BEFORE, itemGroups = ["premium"]) {
      world.clock.set(at);
      return (
        await world.publisher.render({
          resourceId: "hourly-t0",
          data: {},
          items: [
            { name: "bodytext", value: TEXT, contentType: "text/html", accessGroups: itemGroups },
            ...(ordinary
              ? [
                  {
                    name: "ordinary",
                    value: "ordinary body",
                    contentType: "text/plain",
                    accessGroups: ["archive"],
                  },
                ]
              : []),
          ],
        })
      ).asJson();
    },
  };
}

export function t0Client(cache = new ChainKeyCache()) {
  const client = new Client({
    publisherOrigin: ORIGIN,
    cache: new PeriodKeyCache(),
    chainCache: cache,
    chainKeyProfile: referenceChainKeyProfile,
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
  });
  return { client, cache };
}

export async function exchange(world, client, page, names = ["bodytext"]) {
  const data = client.parse(page);
  const request = client.buildRequest(data, ISSUER_NAME, names);
  const response = await world.network.post(UNLOCK_URL, request, { origin: ORIGIN });
  if (response.status === 200)
    await client.applyResponse(data, ISSUER_NAME, response.body, request);
  return { data, request, response };
}
