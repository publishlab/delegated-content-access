import { assembleGroupRoles, REQUEST_LIMITS } from "./roles.js";
import { createIssuerCore } from "../../../../integration-issuer/createIssuerCore.js";
import { PeriodKeyCache } from "../../../../adapter-client/PeriodKeyCache.js";
import { ChainKeyCache } from "../../../../extensions/chain-keys/core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../../../../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import {
  chainKeyCoordinate,
  chainKeyLabelAt,
  settleChainGeometry,
} from "../../../../extensions/chain-keys/core-shared/chainKeyConstruction.js";
import { referenceChainKeyProfileFor } from "../../../../extensions/chain-keys/referenceProfile.js";
import { groupDefaults, resolveGroups } from "../_shared/workload.js";
import {
  ISSUER,
  stringStore,
  publishCapture,
  assembledClient,
  verifyItems,
  runClientStage,
  checkedEndpoint,
} from "../_shared/exchange.js";

const CACHE_LIMITS = Object.freeze({
  maxMembersPerMessage: 1024,
  maxMembersPerFamily: 2,
  maxWindows: 1024,
  maxMemoPeriodKeys: 4096,
});

// Root composition entries inject optional sibling contributions. The ordinary
// extension entry has no dependency on those siblings and refuses their variant.
export function createScenario({
  compactEcdhPublisherContribution,
  compactEcdhIssuerContribution,
  defaultVariant = "ordinary",
} = {}) {
  const compactEnabled =
    typeof compactEcdhPublisherContribution === "function" &&
    typeof compactEcdhIssuerContribution === "function";
  if (
    (compactEcdhPublisherContribution !== undefined ||
      compactEcdhIssuerContribution !== undefined) &&
    !compactEnabled
  )
    throw new Error("compact composition needs both publisher and issuer contributions");
  if (defaultVariant !== "ordinary" && (defaultVariant !== "compact-ecdh" || !compactEnabled))
    throw new Error("unsupported default scenario variant");
  const defaults = structuredClone(groupDefaults);
  defaults.publisher.variant = defaultVariant;
  defaults.publisher.maxChainMembersPerMessage = 16;
  const resolveInput = (input = {}) => {
    const resolved = resolveGroups(input, { compact: compactEnabled, chainMemberCapacity: true });
    if (!input.publisher || !Object.hasOwn(input.publisher, "variant"))
      resolved.publisher.variant = defaultVariant;
    return resolved;
  };
  async function execute({ input, observe, scope = "full" }) {
    const { publisher: p, issuer: i } = input;
    const compact = p.variant === "compact-ecdh";
    const maximum = p.maxChainMembersPerMessage;
    const chainProfile = referenceChainKeyProfileFor(undefined, {
      maxChainMembersPerMessage: maximum,
    });
    const groups = [...new Set(p.items.flatMap((item) => item.groups))];
    // A larger workload needs an explicit matching trusted capacity on every
    // role. The default remains the current specification's 16-member bound.
    if (groups.length * p.sourceWindows > maximum) {
      observe.check("chain-member-bound", false, {
        requested: groups.length * p.sourceWindows,
        maximum,
        reason:
          "ordinary chain supply exceeds the explicitly provisioned message capacity; no fallback or workload change was made",
      });
      return;
    }
    const setup = await observe.time("setup", () =>
      assembleGroupRoles({
        p,
        i,
        observe,
        compact,
        compactEcdhPublisherContribution,
        compactEcdhIssuerContribution,
      }),
    );
    const render = await observe.time("publisher", () =>
      setup.publisher.publish({
        resourceId: p.resourceId,
        data: p.data,
        items: p.items.map(({ groups: accessGroups, ...item }) => ({ ...item, accessGroups })),
      }),
    );
    const published = publishCapture(render, p.origin, observe);
    observe.count("resource");
    observe.count("items", p.items.length);
    observe.count("applicableGroups", groups.length);
    observe.snapshot("trusted-reference-limits", {
      kind: "configuration",
      request: REQUEST_LIMITS,
      cache: CACHE_LIMITS,
      maxChainMembersPerMessage: maximum,
      currentSpecificationMaximum: 16,
      exceedsCurrentSpecificationBound: maximum > 16,
    });
    if (scope === "publisher") return;
    function makeClient(builderFactory) {
      const store = stringStore();
      const period = new PeriodKeyCache({
        storage: store,
        namespace: "scenario",
        maxEntries: 4096,
        clock: { now: () => new Date(p.at) },
        evictionPolicy: () => false,
      });
      const chain = new ChainKeyCache({
        ...CACHE_LIMITS,
        storage: store,
        namespace: "scenario",
        strategy: "retain",
        clock: { now: () => new Date(p.at) },
        evictionPolicy: () => false,
      });
      return {
        store,
        caches: { period, chain },
        options: {
          cache: period,
          chainCache: chain,
          chainKeyProfile: chainProfile,
          relayPeriodKeys: true,
          requestBuilderFactory:
            builderFactory ??
            ((options) =>
              new ChainKeyRequestBuilder({ ...options, maxChainMembersPerMessage: maximum })),
        },
      };
    }
    const permitted = (item) => item.groups.some((g) => i.authorizedGroups.includes(g));
    const geometry = settleChainGeometry(p.periodGeometry);
    const renderMinute =
      Math.floor(Date.parse(p.at) / 60000 / geometry.periodMinutes) * geometry.periodMinutes;
    const coordinate = chainKeyCoordinate(chainKeyLabelAt(renderMinute), geometry);
    const cutoffs = Array.from(
      { length: p.sourceWindows },
      (_, n) => coordinate.windowStart + n * geometry.windowMinutes,
    ).flatMap((start) => {
      const last = Math.min(
        renderMinute + i.horizon * geometry.periodMinutes,
        start + geometry.windowMinutes - geometry.periodMinutes,
      );
      return last < start ? [] : [chainKeyLabelAt(last)];
    });
    const expected = groups
      .filter((group) => i.authorizedGroups.includes(group))
      .flatMap((group) => cutoffs.map((t) => JSON.stringify([group, t])));
    const endpoint = checkedEndpoint(
      setup.issuer.endpoint,
      observe,
      (body) =>
        (body.keys?.chainKeys ?? []).map(({ accessGroup, cutoff }) =>
          JSON.stringify([accessGroup, cutoff]),
        ),
      expected,
    );

    await runClientStage({
      input,
      observe,
      scope,
      published,
      endpoint,
      registration: setup.registration,
      makeClient,
      permitted,
      expectedChainCount: expected.length,
    });
    if (scope === "full" && input.client.routeProbes) {
      await observe.time("probe:all", async () => {
        for (const item of p.items)
          for (const group of item.groups)
            for (const route of ["period", "chain"]) {
              // Select just one authored group and supply route. This is local request
              // projection, never an entitlement grant. A separate client verifies it.
              const builderFactory = (options) => {
                const inner = new ChainKeyRequestBuilder({
                  ...options,
                  maxChainMembersPerMessage: maximum,
                });
                return {
                  build(page, issuerName, names) {
                    const request = inner.build(page, issuerName, names).toObject();
                    const kind = route === "period" ? "periodKeys" : "chainKeys";
                    const ofGroup = (records) =>
                      (records ?? []).filter(({ accessGroup }) => accessGroup === group);
                    const requestedPeriods = ofGroup(request.requestedPeriodKeys);
                    request.requestedPeriodKeys = requestedPeriods.length
                      ? requestedPeriods
                      : [{ accessGroup: group, periods: [] }];
                    request.sealed = { contentKeys: [], [kind]: ofGroup(request.sealed[kind]) };
                    return { toObject: () => request };
                  },
                };
              };
              const held = makeClient(builderFactory);
              // Period-only input goes through the ordinary issuer period input,
              // whereas the chain route proves chain output and client derivation.
              const endpoint =
                route === "period"
                  ? createIssuerCore(
                      {
                        operatingIssuerNames: [ISSUER],
                        limits: REQUEST_LIMITS,
                        periodKeyInput: true,
                        accessPolicy: {
                          decide: (_claims, requested) => ({
                            contentNames: [],
                            periodGrants: i.authorizedGroups.includes(group)
                              ? [
                                  {
                                    accessGroup: group,
                                    periods: requested.periodCoordinates[group] ?? [],
                                  },
                                ]
                              : [],
                          }),
                        },
                      },
                      ...(compact ? [compactEcdhIssuerContribution()] : []),
                    ).endpoint
                  : setup.issuer.endpoint;
              const label = `probe:${item.name}:${group}:${route}:`;
              const client = assembledClient({
                published,
                endpoint,
                registration: setup.registration,
                at: p.at,
                options: held.options,
                observe,
                label,
              });
              await observe.time(`${label}client`, () => client.unlock([item.name]));
              await verifyItems(
                client,
                [item],
                () => i.authorizedGroups.includes(group),
                observe,
                label,
              );
            }
      });
    }
  }

  return Object.freeze({
    id: "chain-keys",
    requestedProfiles: (input) => [
      "dca-profile-chain-keys",
      ...(input.publisher.variant === "compact-ecdh" ? ["dca-profile-compact-ecdh"] : []),
    ],
    profileDeclarations: (input) =>
      input.publisher.variant === "compact-ecdh"
        ? [
            {
              id: "dca-profile-compact-ecdh",
              dependsOn: ["dca-profile-baseline"],
              ref: "docs/spec-profile--compact-ecdh.md",
              status: "public-working-draft",
            },
          ]
        : [],
    defaults,
    resolveInput,
    execute,
  });
}

export const scenario = createScenario();
