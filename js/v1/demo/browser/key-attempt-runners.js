// @ts-check
//
// Two deliberately narrow demo-world runs, internal to the demo rather than
// a client API surface.  Each fixes the articles, time, transport, and
// operations it can dispatch, then records only safe observations of what the
// existing actors did.

import { actorWorld } from "../scenarios/world.js";
import { probeDirectArticleKeyMismatchForDemo } from "../actors/PageLoad.js";
import { rootFromPage } from "../support/queryableRoot.js";
import { utf8Decode } from "../../core-shared/codec.js";
import { dcaError } from "../../core-shared/errors.js";
import { own } from "../../core-shared/wire.js";
import { CONTENT_NAME, ISSUER_NAME } from "../scenarios/fixtures.js";

const ADVANCE = 50 * 60_000;

export const DIRECT_KEY_ATTEMPT_ACTIONS = Object.freeze({
  probe: "probe-a-held-ckey-against-b",
  open: "open-b-from-cached-period-key",
});

/**
 * Validate the selected declared world before creating any actors. The fixed
 * operation sequence lives in this demo runner; the executable
 * clock/seed/period/transport choices passed here come from the named world.
 *
 * @param {any} setup
 * @param {boolean} chain
 */
function directSetup(setup, chain) {
  if (setup === null || typeof setup !== "object" || Array.isArray(setup)) {
    throw dcaError("bad_config", "a direct key demo runner needs declared world setup");
  }
  const expected = chain
    ? [
        "at",
        "seed",
        "period",
        "transportMode",
        "fallback",
        "primaryOffline",
        "periodGrantKind",
        "periodChainStrategy",
      ]
    : ["at", "seed", "period", "transportMode", "fallback", "primaryOffline"];
  if (JSON.stringify(Object.keys(setup).sort()) !== JSON.stringify([...expected].sort())) {
    throw dcaError("bad_config", "the declared direct key demo setup has unsupported fields");
  }
  if (
    typeof setup.at !== "string" ||
    setup.seed !== 1 ||
    setup.transportMode !== "direct" ||
    setup.fallback !== false ||
    setup.primaryOffline !== false ||
    setup.period?.length !== 60 ||
    setup.period?.slots !== 2 ||
    (chain && (setup.periodGrantKind !== "chain" || setup.periodChainStrategy !== "retain"))
  ) {
    throw dcaError("bad_config", "the declared setup is not this fixed direct key demo world");
  }
  return Object.freeze({
    at: setup.at,
    seed: setup.seed,
    period: Object.freeze({ length: setup.period.length, slots: setup.period.slots }),
    transportMode: setup.transportMode,
    fallback: setup.fallback,
    primaryOffline: setup.primaryOffline,
    ...(chain
      ? { periodGrantKind: setup.periodGrantKind, periodChainStrategy: setup.periodChainStrategy }
      : {}),
  });
}

/** @param {any} value @returns {any} */
function copy(value) {
  return JSON.parse(JSON.stringify(value));
}

/** @param {any} value @returns {any} */
function freeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) freeze(member);
    Object.freeze(value);
  }
  return value;
}

/** @param {any} byGroup */
function coordinates(byGroup) {
  if (byGroup === null || typeof byGroup !== "object") return [];
  return Object.keys(byGroup)
    .sort()
    .map((accessGroup) => {
      const periods = own(byGroup, accessGroup);
      return {
        accessGroup,
        t: periods !== null && typeof periods === "object" ? Object.keys(periods).sort() : [],
      };
    });
}

/** @param {any} body */
function responseSummary(body) {
  const keys = own(body, "keys");
  const contentKeys = own(keys, "contentKeys");
  const periodKeys = own(keys, "periodKeys");
  const periodChainKeys = own(keys, "periodChainKeys");
  const contentKeyNames =
    contentKeys !== null && typeof contentKeys === "object" ? Object.keys(contentKeys).sort() : [];
  const exact = coordinates(periodKeys);
  const chains = coordinates(periodChainKeys);
  return {
    contentKeyNames,
    periodKeyCoordinates: exact,
    periodChainKeyCoordinates: chains,
    counts: {
      contentKeys: contentKeyNames.length,
      periodKeys: exact.reduce((count, entry) => count + entry.t.length, 0),
      periodChainKeys: chains.reduce((count, entry) => count + entry.t.length, 0),
    },
  };
}

/** @param {any} request */
function requestSummary(request) {
  const sealed = own(request, "sealed");
  const contentKeys = own(sealed, "contentKeys");
  return {
    contentKeyNames:
      contentKeys !== null && typeof contentKeys === "object"
        ? Object.keys(contentKeys).sort()
        : [],
    periodKeyCoordinates: coordinates(own(sealed, "periodKeys")),
    periodChainKeyCoordinates: coordinates(own(sealed, "periodChainKeys")),
  };
}

/**
 * The network still receives and returns the real bodies.  Only
 * coordinate/count summaries go into the retained trace, so a direct CKey
 * cannot leak out through it.
 *
 * @param {any} network
 * @param {any[]} calls
 */
function summarizingNetwork(network, calls) {
  return {
    async post(url, payload, options) {
      const answer = await network.post(url, payload, options);
      calls.push(
        Object.freeze({
          url,
          status: answer.status,
          request: freeze(requestSummary(payload)),
          response: freeze(responseSummary(answer.body)),
        }),
      );
      return answer;
    },
  };
}

/** @param {any} stats @param {'resolve'|'open'} operation */
function originFor(stats, operation) {
  const observed = [...stats.keyResolutions]
    .reverse()
    .find((entry) => entry.operation === operation);
  const origin = observed?.origins.find((entry) => entry.contentName === CONTENT_NAME);
  return origin === undefined ? null : { ...origin };
}

/** @param {any} page */
function renderSummary(page) {
  const json = page.asJson();
  const resource = own(json, "resource");
  return {
    renderId: own(resource, "renderId"),
    resourceId: own(resource, "resourceId"),
    contentName: CONTENT_NAME,
  };
}

/** @param {any} page */
function sealedChainArtifacts(page) {
  const json = page.asJson();
  const issuerData = own(json, "issuerData");
  const issuer = own(issuerData, ISSUER_NAME);
  const sealed = own(issuer, "sealed");
  const periodChainKeys = own(sealed, "periodChainKeys");
  // These are exact publisher-produced *sealed* terminal blobs.  Anchors and
  // intermediate derivation steps have no observed runtime artifact in this
  // run, so the name claims neither.
  return periodChainKeys !== null && typeof periodChainKeys === "object"
    ? copy(periodChainKeys)
    : {};
}

/**
 * Prepare the fixed A/B direct-delivery world and stop immediately before B's
 * resolve.  `dispatch` is intentionally a one-argument action allowlist; it
 * accepts no key, page, ciphertext, or target supplied by a caller.
 *
 * @param {{ at: string, seed: number, period: { length: number, slots: number }, transportMode: 'direct', fallback: false, primaryOffline: false }} setup
 * @returns {Promise<{
 *   trace: () => Readonly<object>,
 *   dispatch: (action: string) => Promise<Readonly<object>>,
 * }>}
 */
export async function createDirectKeyAttemptRunner(setup) {
  const worldSetup = directSetup(setup, false);
  const world = await actorWorld({
    at: worldSetup.at,
    seed: worldSetup.seed,
    period: worldSetup.period,
    transportMode: worldSetup.transportMode,
    fallback: worldSetup.fallback,
  });
  const calls = [];
  const browser = world.makeBrowser({ network: summarizingNetwork(world.network, calls) });
  const steps = [];

  const aPage = await world.render("A");
  const a = browser.load(rootFromPage(aPage));
  steps.push({
    kind: "render",
    label: "A",
    render: renderSummary(aPage),
    articleState: "protected",
  });
  const neededA = await a.resolve([CONTENT_NAME]);
  steps.push({ kind: "resolve", label: "A", ...neededA });
  const lockedA = await a.open(CONTENT_NAME);
  steps.push({
    kind: "open",
    label: "A",
    opened: false,
    error: lockedA.error,
    articleState: "protected",
  });
  const unlockA = await a.unlock();
  steps.push({
    kind: "unlock",
    label: "A",
    ok: unlockA.ok,
    issuerName: unlockA.issuerName,
    status: unlockA.status,
    transportMode: unlockA.transportMode,
    wire: calls.at(-1) ?? null,
  });
  const openedA = await a.open(CONTENT_NAME);
  const aStats = a.stats();
  steps.push({
    kind: "open",
    label: "A",
    opened: openedA.bytes !== null,
    error: openedA.error,
    origin: originFor(aStats, "open"),
    articleState: openedA.bytes === null ? "protected" : "open",
  });

  const before = world.clock.now();
  world.clock.advance(ADVANCE);
  steps.push({ kind: "advance", from: before.toISOString(), to: world.clock.now().toISOString() });

  const bPage = await world.render("B");
  const b = browser.load(rootFromPage(bPage));
  steps.push({
    kind: "render",
    label: "B",
    render: renderSummary(bPage),
    articleState: "protected",
  });

  let openedB = false;
  let probed = false;
  let dispatchInFlight = false;
  const trace = () => freeze(copy({ world: worldSetup, steps }));

  return Object.freeze({
    trace,
    async dispatch(action) {
      // Set before the first await.  This runner holds one stateful
      // session, so a concurrent click cannot turn one logical action into
      // two observations or race the paused-B guard.
      if (dispatchInFlight) {
        throw dcaError("bad_config", "a direct key-attempt action is already in flight");
      }
      dispatchInFlight = true;
      try {
        if (action === DIRECT_KEY_ATTEMPT_ACTIONS.probe) {
          if (probed || openedB) {
            throw dcaError(
              "bad_config",
              "the A-key-on-B probe is available only while B is protected",
            );
          }
          const beforeSource = a.stats();
          const beforeProbe = b.stats();
          const beforeCache = await browser.cache.entries();
          const probe = await probeDirectArticleKeyMismatchForDemo(a, b);
          const afterSource = a.stats();
          const afterProbe = b.stats();
          const afterCache = await browser.cache.entries();
          probed = true;
          const event = freeze({
            kind: "probe",
            action,
            label: "B",
            articleState: "protected",
            probe,
            sourceLoadUnchanged: JSON.stringify(beforeSource) === JSON.stringify(afterSource),
            targetLoadUnchanged: JSON.stringify(beforeProbe) === JSON.stringify(afterProbe),
            cacheUnchanged: JSON.stringify(beforeCache) === JSON.stringify(afterCache),
          });
          steps.push(event);
          return event;
        }

        if (action === DIRECT_KEY_ATTEMPT_ACTIONS.open) {
          if (openedB) throw dcaError("bad_config", "B has already been opened in this run");
          const resolution = await b.resolve([CONTENT_NAME]);
          const opened = await b.open(CONTENT_NAME);
          const stats = b.stats();
          openedB = opened.bytes !== null;
          const event = freeze({
            kind: "open",
            action,
            label: "B",
            covered: resolution.covered,
            missing: resolution.missing,
            resolutionOrigin: originFor(stats, "resolve"),
            origin: originFor(stats, "open"),
            opened: opened.bytes !== null,
            error: opened.error,
            text: opened.bytes === null ? null : utf8Decode(opened.bytes),
            articleState: opened.bytes === null ? "protected" : "open",
          });
          steps.push(event);
          return event;
        }

        throw dcaError(
          "unsupported_option",
          `the direct key-attempt runner has no action ${JSON.stringify(action)}`,
        );
      } finally {
        dispatchInFlight = false;
      }
    },
  });
}

/**
 * Execute the corresponding direct chain-delivery A/B run.  It records only
 * real page/wire/cache observations, with response values reduced to labels
 * and counts.  In particular, the trace carries only values the actors
 * emitted; a root or an intermediate derivation step would take an inference.
 *
 * @param {{ at: string, seed: number, period: { length: number, slots: number }, transportMode: 'direct', fallback: false, primaryOffline: false, periodGrantKind: 'chain', periodChainStrategy: 'retain' }} setup
 * @param {{ periodKeySupply: object, periodChainProfile: object, periodChainCacheFactory: (options: object) => object, requestBuilderFactory: (options: object) => object }} periodChain
 * @returns {Promise<Readonly<object>>}
 */
export async function runDirectPeriodChainTrace(setup, periodChain) {
  const worldSetup = directSetup(setup, true);
  if (
    !periodChain?.periodKeySupply ||
    !periodChain.periodChainProfile ||
    typeof periodChain.periodChainCacheFactory !== "function" ||
    typeof periodChain.requestBuilderFactory !== "function"
  ) {
    throw dcaError(
      "bad_config",
      "the chain trace needs an injected supply, profile, cache and request builder",
    );
  }
  const world = await actorWorld({
    at: worldSetup.at,
    seed: worldSetup.seed,
    period: worldSetup.period,
    transportMode: worldSetup.transportMode,
    primary: { periodGrantKind: worldSetup.periodGrantKind },
    periodChainProfile: periodChain.periodChainProfile,
    periodChainCacheFactory: periodChain.periodChainCacheFactory,
    issuerSupplyPlanFor: (_issuer, { accessGroups }) => ({
      periodKeyDelivery: Object.fromEntries(
        accessGroups.map((accessGroup) => [accessGroup, ["chain"]]),
      ),
    }),
  });
  world.publisher.rotatePeriodKeySupply(periodChain.periodKeySupply);

  const calls = [];
  const browser = world.makeBrowser({
    network: summarizingNetwork(world.network, calls),
    periodChainStrategy: worldSetup.periodChainStrategy,
    requestBuilderFactory: periodChain.requestBuilderFactory,
  });
  const steps = [];

  const aPage = await world.render("A");
  const a = browser.load(rootFromPage(aPage));
  steps.push({
    kind: "render",
    label: "A",
    render: renderSummary(aPage),
    articleState: "protected",
    publisherSealedTerminalKeys: sealedChainArtifacts(aPage),
  });
  const neededA = await a.resolve([CONTENT_NAME]);
  steps.push({ kind: "resolve", label: "A", ...neededA });
  const unlocked = await a.unlock();
  steps.push({
    kind: "unlock",
    label: "A",
    ok: unlocked.ok,
    issuerName: unlocked.issuerName,
    status: unlocked.status,
    transportMode: unlocked.transportMode,
    wire: calls.at(-1) ?? null,
  });

  const before = world.clock.now();
  world.clock.advance(ADVANCE);
  steps.push({ kind: "advance", from: before.toISOString(), to: world.clock.now().toISOString() });
  const bPage = await world.render("B");
  const b = browser.load(rootFromPage(bPage));
  steps.push({
    kind: "render",
    label: "B",
    render: renderSummary(bPage),
    articleState: "protected",
    publisherSealedTerminalKeys: sealedChainArtifacts(bPage),
  });
  const resolution = await b.resolve([CONTENT_NAME]);
  const opened = await b.open(CONTENT_NAME);
  const stats = b.stats();
  steps.push({
    kind: "open",
    label: "B",
    covered: resolution.covered,
    missing: resolution.missing,
    resolutionOrigin: originFor(stats, "resolve"),
    origin: originFor(stats, "open"),
    opened: opened.bytes !== null,
    error: opened.error,
    text: opened.bytes === null ? null : utf8Decode(opened.bytes),
    articleState: opened.bytes === null ? "protected" : "open",
  });

  return freeze({
    world: worldSetup,
    steps,
  });
}
