import { PeriodKeyCache } from "../../../../adapter-client/PeriodKeyCache.js";
import { evictAfterSixHours } from "../../../../adapter-client/periodKeyEviction.js";
import { ChainKeyCache } from "../../../../extensions/chain-keys/core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../../../../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { referenceChainKeyProfileFor } from "../../../../extensions/chain-keys/referenceProfile.js";
import { resolveGroups, known } from "../_shared/workload.js";
import {
  stringStore,
  publishCapture,
  assembledClient,
  verifyItems,
  cacheSnapshot,
  ISSUER,
  UNLOCK,
} from "../_shared/exchange.js";
import { assembleGroupRoles } from "./roles.js";

const steps = [
  { id: "first", at: "2026-10-14T23:20:00Z", resourceId: "article-one", expectedUnlocks: 1 },
  { id: "second", at: "2026-10-14T23:30:00Z", resourceId: "article-two", expectedUnlocks: 0 },
  { id: "saved", at: "2026-10-14T23:40:00Z", reopen: "first", expectedUnlocks: 0 },
  {
    id: "denied",
    at: "2026-10-14T23:45:00Z",
    reopen: "first",
    requestNames: ["restricted"],
    expectedUnlocks: 1,
  },
  {
    id: "next-window",
    at: "2026-10-15T00:20:00Z",
    resourceId: "article-three",
    expectedUnlocks: 1,
  },
  { id: "expiry", at: "2026-10-15T06:30:00Z", cleanup: true },
];
const defaults = {
  representation: "chain-keys",
  publisher: {
    groups: 2,
    sourceWindows: 1,
    items: [
      { name: "bodytext", value: "Allowed article text", groups: ["group0000"] },
      { name: "restricted", value: "Restricted article text", groups: ["group0001"] },
    ],
  },
  issuer: { horizon: 0, authorizedGroups: ["group0000"] },
  steps,
};

function resolveInput(input = {}) {
  known(input, ["representation", "publisher", "issuer", "steps"], "input");
  const representation = input.representation ?? defaults.representation;
  if (!["chain-keys", "period-keys"].includes(representation))
    throw new Error("unsupported representation");
  const resolved = resolveGroups(
    {
      publisher: { ...defaults.publisher, ...input.publisher },
      issuer: { ...defaults.issuer, ...input.issuer },
      client: { routeProbes: false },
    },
    { chainMemberCapacity: true },
  );
  if (
    resolved.publisher.maxChainMembersPerMessage !== 16 ||
    new Set(resolved.publisher.items.flatMap((item) => item.groups)).size *
      resolved.publisher.sourceWindows >
      16
  )
    throw new Error("retained reader uses the ordinary 16-member capacity");
  const ordered = structuredClone(input.steps ?? steps);
  if (!Array.isArray(ordered) || ordered.length === 0) throw new Error("steps must be nonempty");
  const seen = new Set();
  const saved = new Set();
  let previous = -Infinity;
  for (const step of ordered) {
    known(
      step,
      ["id", "at", "resourceId", "reopen", "cleanup", "requestNames", "expectedUnlocks"],
      "step",
    );
    if (typeof step.id !== "string" || !/^[a-zA-Z0-9_-]+$/.test(step.id) || seen.has(step.id))
      throw new Error("distinct safe step ids required");
    const time = Date.parse(step.at);
    if (
      typeof step.at !== "string" ||
      !step.at.endsWith("Z") ||
      !Number.isFinite(time) ||
      time < previous
    )
      throw new Error("steps need ordered UTC instants");
    previous = time;
    seen.add(step.id);
    if (
      [step.resourceId !== undefined, step.reopen !== undefined, step.cleanup !== undefined].filter(
        Boolean,
      ).length !== 1
    )
      throw new Error("step selects one resourceId, reopen or cleanup");
    if (step.cleanup !== undefined && step.cleanup !== true)
      throw new Error("cleanup must be true");
    if (step.reopen !== undefined && !saved.has(step.reopen))
      throw new Error("reopen needs an earlier render id");
    if (step.resourceId !== undefined) {
      if (typeof step.resourceId !== "string" || !step.resourceId)
        throw new Error("resourceId must be nonempty");
      saved.add(step.id);
    }
    if (
      step.requestNames !== undefined &&
      (!Array.isArray(step.requestNames) ||
        !step.requestNames.length ||
        step.requestNames.some(
          (name) => !resolved.publisher.items.some((item) => item.name === name),
        ))
    )
      throw new Error("requestNames must select authored items");
    if (step.expectedUnlocks !== undefined && ![0, 1].includes(step.expectedUnlocks))
      throw new Error("expectedUnlocks must be zero or one");
    if (step.cleanup && step.requestNames !== undefined)
      throw new Error("cleanup has no requestNames");
  }
  return { representation, publisher: resolved.publisher, issuer: resolved.issuer, steps: ordered };
}

async function execute({ input, observe, scope }) {
  if (scope !== "full") throw new Error("retained-reader workload requires full scope");
  const p = input.publisher;
  let instant = input.steps[0].at;
  const clock = { now: () => new Date(instant) };
  const roles = await observe.time("setup", () =>
    assembleGroupRoles({
      p,
      i: input.issuer,
      observe,
      clock,
      representation: input.representation,
    }),
  );
  const store = stringStore();
  const period = new PeriodKeyCache({
    storage: store,
    namespace: "retained-reader",
    maxEntries: 4096,
    clock,
    evictionPolicy: evictAfterSixHours,
  });
  const chain = new ChainKeyCache({
    storage: store,
    namespace: "retained-reader",
    strategy: "retain",
    maxMembersPerMessage: 16,
    maxMembersPerFamily: 2,
    maxWindows: 1024,
    maxMemoPeriodKeys: 4096,
    clock,
    evictionPolicy: evictAfterSixHours,
  });
  const options = {
    cache: period,
    chainCache: chain,
    chainKeyProfile: referenceChainKeyProfileFor(undefined, {
      maxChainMembersPerMessage: p.maxChainMembersPerMessage,
    }),
    relayPeriodKeys: true,
    requestBuilderFactory: (options) =>
      new ChainKeyRequestBuilder({
        ...options,
        maxChainMembersPerMessage: p.maxChainMembersPerMessage,
      }),
  };
  const saved = new Map();
  const clients = [];
  const permitted = (item) =>
    item.groups.some((group) => input.issuer.authorizedGroups.includes(group));
  async function snapshot(name) {
    const summary = await cacheSnapshot({ period, chain }, store);
    summary.observation =
      "Advancing injected clock; entries() explicitly runs the real six-hour coordinate eviction policy, chain entries() evicts memory; reconcile explicitly persists cleanup. No browser quota or heap measurement.";
    summary.rawKeyBytesFromFixed16OctetEntries =
      (summary.caches.period.entries + summary.caches.chain.entries) * 16;
    observe.snapshot(name, summary);
    return summary;
  }
  try {
    await snapshot("before");
    for (const step of input.steps) {
      instant = step.at;
      // This store-only observation does not enumerate caches or trigger eviction.
      observe.snapshot(`${step.id}:clock-advanced`, {
        at: instant,
        storage: store.summary(),
        observation: "Serialized storage before any cache read or cleanup at this instant",
      });
      if (step.cleanup) {
        await observe.time(`${step.id}:cleanup`, async () => {
          await snapshot(`${step.id}:after-enumeration`);
          await period.reconcile();
          await chain.reconcile();
          await snapshot(`${step.id}:after-cleanup`);
        });
        continue;
      }
      let published;
      if (step.reopen) {
        published = saved.get(step.reopen);
        observe.count("savedReread");
      } else {
        const render = await observe.time(`${step.id}:publisher`, () =>
          roles.publisher.publish({
            resourceId: step.resourceId,
            data: p.data,
            items: p.items.map(({ groups: accessGroups, ...item }) => ({ ...item, accessGroups })),
          }),
        );
        const prefix = {
          ...observe,
          capture: (name, document, options) =>
            observe.capture(`${step.id}:${name}`, document, options),
          check: (name, passed, details) => observe.check(`${step.id}:${name}`, passed, details),
        };
        published = publishCapture(render, p.origin, prefix);
        saved.set(step.id, published);
        observe.count("resource");
      }
      const names = step.requestNames ?? p.items.filter(permitted).map((item) => item.name);
      let unlocks = 0;
      const endpoint = {
        async handleDocument(...args) {
          unlocks++;
          const answer = await roles.issuer.endpoint.handleDocument(...args);
          const expectsGrant = p.items.some((item) => names.includes(item.name) && permitted(item));
          observe.check(
            `${step.id}:issuer-status`,
            answer.response.status === (expectsGrant ? 200 : 401),
            { status: answer.response.status },
          );
          return answer;
        },
      };
      const client = assembledClient({
        published,
        endpoint,
        registration: roles.registration,
        at: instant,
        options,
        observe,
        label: `${step.id}:`,
      });
      clients.push(client);
      await snapshot(`${step.id}:before-unlock`);
      if (names.length)
        await observe.time(`${step.id}:client`, () =>
          client.unlockRoutes(names, [{ issuerName: ISSUER, unlockUrl: UNLOCK }]),
        );
      await observe.time(`${step.id}:opening`, () =>
        verifyItems(client, p.items, permitted, observe, `${step.id}:item:`),
      );
      if (step.expectedUnlocks !== undefined)
        observe.check(`${step.id}:unlock-count`, unlocks === step.expectedUnlocks, {
          expected: step.expectedUnlocks,
          actual: unlocks,
        });
      await snapshot(`${step.id}:after`);
    }
    await snapshot("after");
  } finally {
    await observe.time("teardown", async () => {
      // Retire each delivery client as well as the shared reader-owned caches.
      for (const client of clients) await client.clearReaderContext();
      await Promise.all([period.clearReaderContext(), chain.clearReaderContext()]);
    });
    const final = await snapshot("teardown");
    observe.check(
      "reader-teardown",
      final.storage.entries === 0 &&
        final.caches.period.entries === 0 &&
        final.caches.chain.entries === 0,
    );
  }
}

export const scenario = Object.freeze({
  id: "retained-reader",
  requestedProfiles: ["dca-profile-chain-keys"],
  defaults,
  resolveInput,
  execute,
});
