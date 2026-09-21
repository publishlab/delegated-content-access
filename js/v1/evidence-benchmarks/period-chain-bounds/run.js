// @ts-check
//
// This run measures what the period-chain bounds cost, on the real reference
// paths rather than on a substitute hash loop. `spec--period-key-chains.md`
// **Bounds** fixes five peer-visible maxima in its protocol-maxima table, and the
// reference adds two local retention settings. This script measures the operations those
// limits bound, at the ceiling each one names, and reports construction, issuer
// expansion, client trial, request bytes and response bytes separately.
//
// Run it from the repository root, with no arguments and no network:
//
//     node js/v1/evidence-benchmarks/period-chain-bounds/run.js
//
// This script prints its results and does nothing else: no assertions, no files
// written, and no lane runs it, because `package.json` does not name it.
// `./measure.js` explains how one reading is taken; `./README.md` holds the dated
// result and compares it against the limits.
//
// Every world below is built through the real publisher, issuer and client
// paths: `core-publisher/Sealer.js` with
// `extensions/period-chain/core-publisher/periodFamilySupply.js`,
// `extensions/period-chain/core-issuer/periodChainIssuerEngine.js` behind
// `core-issuer/IssuerProcessor.js` and `ports/UnlockEndpoint.js`, and
// `extensions/period-chain/core-client/PeriodChainRequestBuilder.js` and
// `extensions/period-chain/core-client/PeriodChainCache.js`.

import os from "node:os";

import { Sealer } from "../../core-publisher/Sealer.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { parseDcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";
import { utf8Encode } from "../../core-shared/codec.js";
import { DcaData } from "../../core-client/DcaData.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import { ObjectDeliveryReader } from "../../demo/support/ObjectDeliveryReader.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../demo/support/PublisherRegistrations.js";
import { PeriodChainRequestBuilder } from "../../extensions/period-chain/core-client/PeriodChainRequestBuilder.js";
import { PeriodChainCache } from "../../extensions/period-chain/core-client/PeriodChainCache.js";
import { periodFamilyGeneration } from "../../extensions/period-chain/core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../../extensions/period-chain/core-publisher/periodFamilySupply.js";
import { periodChainIssuerEngine } from "../../extensions/period-chain/core-issuer/periodChainIssuerEngine.js";
import { periodChainExpansionFromState } from "../../extensions/period-chain/core-shared/periodChainConstruction.js";
import { derivations, environment, grouped, readings, spread } from "./measure.js";

const { subtle } = globalThis.crypto;

const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const NAME = "bodytext";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";

/**
 * The geometry at the `N = 288` per-window ceiling: 1440 minutes a day, one chain a day,
 * five-minute periods.
 */
const FULL = Object.freeze({ chainsPerDay: 1, periodMinutes: 5 });

/** Two windows a day over fifteen-minute periods, `N = 48`, as the period-chain tests use. */
const HALF_DAY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

/** The terminal of the window starting 2025-10-23T00:00Z under `FULL`. */
const FULL_TERMINAL_T = "251023T2355";

/** Position 0 of that same window: the far end of a full backward walk. */
const FULL_START_T = "251023T0000";

/** @param {number} fill */
const secret = (fill) => new Uint8Array(32).fill(fill);

/**
 * One publisher render, one registration and one wire-shaped request, through
 * the paths a deployment uses. `chainWindows` sets how many stationary window
 * terminals the publisher supplies per family, and those members count against
 * `maxChainMembersPerMessage`.
 *
 * @param {object} config
 * @param {{ chainsPerDay: number, periodMinutes: number }} config.geometry
 * @param {string[]} config.groups
 * @param {number} config.chainWindows
 * @param {string} config.at - the render moment
 * @returns {Promise<{ requestDocument: string, registration: any, memberCount: number }>}
 */
async function issuerWorld({ geometry, groups, chainWindows, at }) {
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const families = Object.fromEntries(
    groups.map((group, index) => [
      group,
      periodFamilyGeneration({ keyDerivationSecret: secret(7 + index), geometry }),
    ]),
  );
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(at),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: periodFamilySupply({ families, chainWindows }),
    issuerSupplyPlanFor: () => ({
      periodKeyDelivery: Object.fromEntries(groups.map((group) => [group, ["chain"]])),
    }),
    issuers: [
      {
        issuerName: ISSUER,
        keyId: KEY_ID,
        algorithm: "ECDH-P256",
        publicKey: issuerKeys.publicKey,
        unlockUrl: "https://api.example.com/unlock",
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(NAME, ARTICLE, "text/html", { accessGroups: groups });
  const rendered = await sealer.seal();
  const page = JSON.parse(
    JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
  );

  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(
        {
          get: (/** @type {string} */ issuerName, /** @type {string} */ keyId) =>
            issuerName === ISSUER && keyId === KEY_ID
              ? { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey }
              : undefined,
        },
        [{ issuerName: ISSUER, keyId: KEY_ID }],
      ),
    },
  ]).get(SIGNING_KID);

  const dcaData = new DcaData(new ObjectDeliveryReader(page, { publisherOrigin: PUB }).dcaData, {
    publisherOrigin: PUB,
  });
  const requestDocument = JSON.stringify(
    new PeriodChainRequestBuilder().build(dcaData, ISSUER, [NAME]).toObject(),
  );
  const carrier = page.issuerData[ISSUER].sealed.periodChainKeys;
  const memberCount = Object.values(carrier).reduce(
    (total, family) => total + Object.keys(/** @type {object} */ (family)).length,
    0,
  );

  return { requestDocument, registration, memberCount };
}

/** @param {number} periodCount */
function policy(periodCount) {
  return {
    decide: (/** @type {any} */ unusedClaims, /** @type {any} */ requested) => ({
      contentNames: [],
      periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
        accessGroup,
        periodCount,
      })),
    }),
  };
}

/** @param {object} body */
const wireBytes = (body) => utf8Encode(JSON.stringify(body)).length;

/** @param {any} body */
function leafCounts(body) {
  const families = body?.keys?.periodKeys ?? {};
  return {
    families: Object.keys(families),
    leaves: Object.values(families).reduce(
      (total, family) => total + Object.keys(/** @type {object} */ (family)).length,
      0,
    ),
  };
}

/** @type {string[]} */
const out = [];
/** @param {string} line */
const say = (line) => out.push(line);

say(
  `Measured ${new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Europe/Oslo",
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date())} Oslo.`,
);
say(environment(os));
say("");

// 1. Terminal construction at N = 288, cold: the publisher handle with its
//    cache off, so every iteration derives from the family root again.
{
  const cold = () =>
    periodFamilyGeneration({
      keyDerivationSecret: secret(7),
      geometry: FULL,
      cache: false,
    }).chainCapability("premium", FULL_TERMINAL_T);
  const taken = await readings(cold);
  const { count } = await derivations(cold);
  say("1. N = 288 terminal construction from the family root, cold");
  say(`   periodFamilyGeneration({ cache: false }).chainCapability at ${FULL_TERMINAL_T}`);
  say(`   ${spread(taken)}, ${grouped(count)} HKDF`);
  say("");
}

// 2. Full 288-leaf projection from that terminal state: one reverse walk,
//    `2N - 1` derivations, the cost the spec models for one expansion.
{
  const terminal = await periodFamilyGeneration({
    keyDerivationSecret: secret(7),
    geometry: FULL,
    cache: false,
  }).chainCapability("premium", FULL_TERMINAL_T);
  const project = () =>
    periodChainExpansionFromState({
      state: terminal.key,
      accessGroup: "premium",
      suppliedT: FULL_TERMINAL_T,
      cutoffT: FULL_TERMINAL_T,
      geometry: FULL,
    });
  const taken = await readings(project);
  const { value, count } = await derivations(project);
  say("2. Full 288-leaf projection of one member, periodChainExpansionFromState");
  say(
    `   ${spread(taken)}, ${grouped(count)} HKDF for ${/** @type {any[]} */ (value).length} leaves`,
  );
  say("");
}

// 3. The client walk from a cutoff, at one and at four rival chain candidates.
//    Each iteration files rivals into a fresh cache, because once a leaf is memoized
//    the second read of a coordinate returns without walking at all. The generation
//    handles are built once and hold their own terminal states, and the default
//    retain strategy derives nothing while filing, so the count below covers the
//    trial alone.
for (const rivals of [1, 4]) {
  const generations = Array.from({ length: rivals }, (unused, index) =>
    periodFamilyGeneration({
      keyDerivationSecret: secret(61 + index),
      geometry: FULL,
    }),
  );
  const context = { publisher: PUB, ...FULL };
  const walk = async () => {
    const cache = new PeriodChainCache();
    for (const generation of generations) {
      const capability = await generation.chainCapability("premium", FULL_TERMINAL_T);
      await cache.put("premium", FULL_TERMINAL_T, capability.key, context);
    }
    return cache.candidates("premium", FULL_START_T, context);
  };
  const taken = await readings(walk);
  const { value, count } = await derivations(walk);
  say(
    `3${rivals === 1 ? "a" : "b"}. Client walk from the ${FULL_TERMINAL_T} cutoff back to ${FULL_START_T}, ` +
      `${rivals} rival chain candidate${rivals === 1 ? "" : "s"}`,
  );
  say(`   PeriodChainCache.candidates answered ${/** @type {any[]} */ (value).length}`);
  say(`   ${spread(taken)}, ${grouped(count)} HKDF, ${grouped(count / rivals)} per candidate`);
  say("");
}

// 4. One message at the 16-member ceiling: eight families of two distinct
//    window terminals, which is what `chainWindows: 2` supplies. The block then
//    measures what the reference issuer does with that message, at its default
//    admission limits and with explicitly sufficient local capacity.
{
  const at = "2025-10-23T14:20:00Z";
  const groups = ["fam_a", "fam_b", "fam_c", "fam_d", "fam_e", "fam_f", "fam_g", "fam_h"];
  const { requestDocument, registration, memberCount } = await issuerWorld({
    geometry: HALF_DAY,
    groups,
    chainWindows: 2,
    at,
  });
  const engine = periodChainIssuerEngine({ accessPolicy: policy(2), clock: new Clock(at) });
  const defaults = new IssuerProcessor(engine, {
    capabilityEncoders: engine.capabilityEncoders,
    selectedExtensions: engine.selectedExtensions,
  });
  const relaxed = new IssuerProcessor(engine, {
    capabilityEncoders: engine.capabilityEncoders,
    selectedExtensions: engine.selectedExtensions,
    limits: { maxEntries: 17 },
  });
  const refused = defaults.admit(requestDocument);
  const admitted = relaxed.admit(requestDocument);
  const endpoint = new UnlockEndpoint(relaxed);
  const request = parseDcaRequest(requestDocument);
  const serve = () =>
    endpoint.handleRequest({ request, registration, capturedAtMs: Date.parse(at) });
  const taken = await readings(serve);
  const answer = /** @type {any} */ (taken.last);

  say(
    `4. One message at the 16-member ceiling: ${groups.length} families of ` +
      `${memberCount / groups.length}, ${memberCount} chain members`,
  );
  say(`   request document ${grouped(utf8Encode(requestDocument).length)} UTF-8 bytes`);
  say(`   default IssuerProcessor limits: ${refused.kind} ${refused.code ?? ""}`.trimEnd());
  say(`   explicit maxEntries 17: ${admitted.kind}, endpoint answered ${answer.response.status}`);
  say(`   ${spread(taken)}`);
  say(
    `   response body ${grouped(wireBytes(answer.response.body))} UTF-8 bytes, ` +
      `${leafCounts(answer.response.body).leaves} leaves`,
  );
  say("");
}

// 5. One exact response at the 512-leaf ceiling: three identically provisioned
//    families at N = 288, each requesting 600 leaves, past both the 288 per-family
//    ceiling and the 512 per-response ceiling.
{
  const at = "2025-10-23T00:00:00Z";
  const groups = ["premium", "archive", "legacy"];
  const { requestDocument, registration } = await issuerWorld({
    geometry: FULL,
    groups,
    chainWindows: 2,
    at,
  });
  const engine = periodChainIssuerEngine({ accessPolicy: policy(600), clock: new Clock(at) });
  const processor = new IssuerProcessor(engine, {
    capabilityEncoders: engine.capabilityEncoders,
    selectedExtensions: engine.selectedExtensions,
  });
  const endpoint = new UnlockEndpoint(processor);
  const request = parseDcaRequest(requestDocument);
  const serve = () =>
    endpoint.handleRequest({ request, registration, capturedAtMs: Date.parse(at) });
  const taken = await readings(serve, { runs: 5 });
  const answer = /** @type {any} */ (taken.last);
  const counted = leafCounts(answer.response.body);
  const document = JSON.stringify(answer.response.body);

  say(
    `5. One 512-leaf exact response through UnlockEndpoint.handleRequest, ` +
      `${groups.length} families asked, admission ${processor.admit(requestDocument).kind}`,
  );
  say(
    `   status ${answer.response.status}, ${counted.leaves} leaves in ${counted.families.join(", ")}`,
  );
  say(`   errors member ${answer.response.body.errors === undefined ? "absent" : "present"}`);
  say(`   ${spread(taken)}`);
  say(
    `   response body ${grouped(document.length)} JSON characters, ` +
      `${grouped(wireBytes(answer.response.body))} UTF-8 bytes`,
  );
  say("");
}

// 6. The same families under `representation: 'chain'`: the issuer returns one
//    cutoff state per selected member instead of exact leaves, which is what the
//    direct chain representation puts on the wire.
{
  const at = "2025-10-23T00:00:00Z";
  const groups = ["premium", "archive", "legacy"];
  const { requestDocument, registration } = await issuerWorld({
    geometry: FULL,
    groups,
    chainWindows: 2,
    at,
  });
  const engine = periodChainIssuerEngine({
    accessPolicy: policy(600),
    clock: new Clock(at),
    representation: "chain",
  });
  const endpoint = new UnlockEndpoint(
    new IssuerProcessor(engine, {
      capabilityEncoders: engine.capabilityEncoders,
      selectedExtensions: engine.selectedExtensions,
    }),
  );
  const request = parseDcaRequest(requestDocument);
  const serve = () =>
    endpoint.handleRequest({ request, registration, capturedAtMs: Date.parse(at) });
  const taken = await readings(serve);
  const answer = /** @type {any} */ (taken.last);
  const chainKeys = answer.response.body.keys?.periodChainKeys ?? {};
  const members = Object.values(chainKeys).reduce(
    (total, family) => total + Object.keys(/** @type {object} */ (family)).length,
    0,
  );

  say(`6. The same three families as direct chain state, representation: 'chain'`);
  say(
    `   status ${answer.response.status}, ${members} chain members in ` +
      `${Object.keys(chainKeys).length} families`,
  );
  say(`   ${spread(taken)}`);
  say(`   response body ${grouped(wireBytes(answer.response.body))} UTF-8 bytes`);
  say("");
}

process.stdout.write(`${out.join("\n")}\n`);
