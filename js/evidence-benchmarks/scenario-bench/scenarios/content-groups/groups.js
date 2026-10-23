import { createPublisher } from "../../../../integration-publisher/createPublisher.js";
import { createIssuerCore } from "../../../../integration-issuer/createIssuerCore.js";
import { PeriodKeyCache } from "../../../../adapter-client/PeriodKeyCache.js";
import { contentGroupsProfile } from "../../../../extensions/content-groups/referenceProfile.js";
import { ChainKeyCache } from "../../../../extensions/chain-keys/core-client/ChainKeyCache.js";
import {
  chainKeyCoordinate,
  chainKeyLabelAt,
  settleChainGeometry,
} from "../../../../extensions/chain-keys/core-shared/chainKeyConstruction.js";
import { periodFamilyGeneration } from "../../../../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { groupDefaults, resolveGroups } from "../_shared/workload.js";
import {
  keys,
  registrationFor,
  random,
  ISSUER,
  UNLOCK,
  FIXTURE_SECRET,
  stringStore,
  publishCapture,
  assembledClient,
  verifyItems,
  runClientStage,
  checkedEndpoint,
} from "../_shared/exchange.js";

export const resolveInput = (input) => {
  const resolved = resolveGroups(input);
  if (resolved.publisher.itemPeriods !== 1)
    throw new Error("content-groups authors one render-period connector; itemPeriods must be 1");
  return resolved;
};

// This extension owns the scenario and its required stock chain construction
// and cache composition. The wrappers below observe the real operations.
function createScenario() {
  function chainPort(observe) {
    return {
      coordinate: chainKeyCoordinate,
      labelAt: chainKeyLabelAt,
      settleGeometry: settleChainGeometry,
      familyGeneration(config) {
        observe.count("familyGeneration");
        const generation = periodFamilyGeneration(config);
        return Object.freeze({
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
        });
      },
    };
  }

  async function execute({ input, observe, scope = "full" }) {
    const { publisher: p, issuer: i } = input;
    const geometry = settleChainGeometry(p.periodGeometry);
    const renderMinute =
      Math.floor(Date.parse(p.at) / 60000 / geometry.periodMinutes) * geometry.periodMinutes;
    const coordinate = chainKeyCoordinate(chainKeyLabelAt(renderMinute), geometry);
    const windows = Array.from({ length: p.sourceWindows }, (_, n) =>
      chainKeyLabelAt(coordinate.windowStart + n * geometry.windowMinutes),
    );
    const chain = chainPort(observe);
    const setup = await observe.time("setup", async () => {
      const generated = await keys();
      const registration = registrationFor(generated);
      const publisher = createPublisher(
        {
          origin: p.origin,
          clock: { now: () => new Date(p.at) },
          random,
          signingKeys: { p1: generated.signing.privateKey },
          issuers: [
            {
              issuerName: ISSUER,
              keyId: "k1",
              algorithm: "ecdh-p256",
              publicKey: generated.opening.publicKey,
            },
          ],
          issuerSupplyPlanFor: () => ({ contentKeyNames: [], suppliedAccessGroups: [] }),
        },
        contentGroupsProfile.publisherContribution({
          retainedSecret: FIXTURE_SECRET,
          periodGeometry: p.periodGeometry,
          issuerSeedWindows: {
            [ISSUER]: Object.fromEntries(p.items.map((item) => [item.name, windows])),
          },
          chain,
        }),
      );
      const issuer = createIssuerCore(
        { operatingIssuerNames: [ISSUER], accessPolicy: { decide: () => ({ contentNames: [] }) } },
        contentGroupsProfile.issuerContribution({
          chain,
          policy: {
            decide(request) {
              return {
                grants: Object.entries(request.contentGroups).flatMap(([contentName, wanted]) =>
                  wanted.groups
                    .filter((g) => i.authorizedGroups.includes(g))
                    .flatMap((group) =>
                      wanted.windows.flatMap((windowStart) => {
                        const start = chainKeyCoordinate(windowStart, geometry).windowStart;
                        const last = Math.min(
                          renderMinute + i.horizon * geometry.periodMinutes,
                          start + geometry.windowMinutes - geometry.periodMinutes,
                        );
                        return last < start
                          ? []
                          : [
                              {
                                kind: "chain",
                                contentName,
                                group,
                                windowStart,
                                cutoffT: chainKeyLabelAt(last),
                              },
                            ];
                      }),
                    ),
                ),
                // Chain keys reach the window's prefix; this fixture authorizes that
                // entire reach for the named groups, rather than denying past periods.
                authorizePeriod: (_name, group) => i.authorizedGroups.includes(group),
              };
            },
          },
        }),
      );
      return { publisher, issuer, registration };
    });
    const render = await observe.time("publisher", () =>
      setup.publisher.publish({
        resourceId: p.resourceId,
        data: p.data,
        items: p.items.map(({ groups, ...item }) => ({ ...item, contentGroups: groups })),
      }),
    );
    const published = publishCapture(render, p.origin, observe);
    observe.count("resource");
    observe.count("items", p.items.length);
    observe.count("applicableGroups", new Set(p.items.flatMap((item) => item.groups)).size);
    if (scope === "publisher") return;
    function makeClient(narrowing) {
      const store = stringStore();
      const bundle = contentGroupsProfile.client({
        chain,
        storage: store,
        namespace: "scenario",
        createPeriodKeyCache: (config) =>
          new PeriodKeyCache({
            ...config,
            clock: { now: () => new Date(p.at) },
            evictionPolicy: () => false,
          }),
        createChainKeyCache: (config) =>
          new ChainKeyCache({
            ...config,
            clock: { now: () => new Date(p.at) },
            evictionPolicy: () => false,
          }),
        ...(narrowing ? { narrowing } : {}),
      });
      return {
        store,
        caches: { period: bundle.periodKeyCache, chain: bundle.chainKeyCache },
        options: bundle.composeOptions,
      };
    }
    const permitted = (item) => item.groups.some((g) => i.authorizedGroups.includes(g));
    const cutoffs = windows.flatMap((window) => {
      const start = chainKeyCoordinate(window, geometry).windowStart;
      const last = Math.min(
        renderMinute + i.horizon * geometry.periodMinutes,
        start + geometry.windowMinutes - geometry.periodMinutes,
      );
      return last < start ? [] : [chainKeyLabelAt(last)];
    });
    const expected = p.items.flatMap((item) =>
      item.groups
        .filter((group) => i.authorizedGroups.includes(group))
        .flatMap((group) => cutoffs.map((t) => JSON.stringify([item.name, group, t]))),
    );
    const endpoint = checkedEndpoint(
      setup.issuer.endpoint,
      observe,
      (body) =>
        (body.contentGroupKeys?.chainKeys ?? []).map(({ contentName, group, cutoff }) =>
          JSON.stringify([contentName, group, cutoff]),
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
      // Every authored connector is tested in isolation. These clients and
      // caches are independent of the measured main resource exchange.
      await observe.time("probe:all", async () => {
        for (const item of p.items)
          for (const group of item.groups) {
            const held = makeClient({
              requestedContentGroups: { [item.name]: [group] },
              requestedContentKeys: {},
            });
            const label = `probe:${item.name}:${group}:`;
            const client = assembledClient({
              published,
              endpoint: setup.issuer.endpoint,
              registration: setup.registration,
              at: p.at,
              options: held.options,
              observe,
              label,
            });
            await observe.time(`${label}client`, () =>
              client.unlockRoutes([item.name], [{ issuerName: ISSUER, unlockUrl: UNLOCK }]),
            );
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
    id: "content-groups",
    requestedProfiles: ["dca-profile-content-groups"],
    profileDeclarations: [
      {
        id: "dca-profile-content-groups",
        dependsOn: ["dca-profile-baseline"],
        ref: "docs/spec-profile--content-groups.md",
        status: "proposal",
      },
    ],
    defaults: groupDefaults,
    resolveInput,
    execute,
  });
}

export const scenario = createScenario();
