// @ts-check
//
// A delivery's `periodGeometry.accessGroups` map is admitted whole before any
// family reads from it. A rejected map, one that is not a non-array object or
// that carries a name outside the access-group grammar, supplies no geometry to
// any chain family of that delivery (docs/spec-profile--chain-keys.md Section 12.1 (#document-member)). The
// relay therefore sends no chain member for that delivery: forwarding the map
// would make a selecting issuer refuse the whole request, base content and
// period sections included. A malformed override inside an admitted map stays
// family-local and travels as written, so the issuer fails only that family.

import test from "node:test";
import assert from "node:assert/strict";

import { createBrowserClient } from "../../../integration-client/createBrowserClient.js";
import { writeMarkupDelivery } from "../../../adapter-publisher/writeMarkupDelivery.js";
import { domOver } from "../../../test-lib/helpers/domOver.js";
import { unlockThroughAdmission } from "../../../test-lib/harnesses/unlockThroughAdmission.js";
import { Storage } from "../../../demo/actors/Storage.js";
import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { parseDcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { chainKeyCandidateSource } from "../core-client/chainKeyCandidateSource.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { chainKeyIssuerEngine } from "../core-issuer/chainKeyIssuerEngine.js";
import { chainKeyRequestInput } from "../core-issuer/chainKeyRequestInput.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";
import { periodsOn } from "../../../test-lib/helpers/inspect.js";

const { subtle } = globalThis.crypto;
const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const AT = "2025-10-23T14:20:00Z";
const BODY = "<p>The council voted 7-2 to rezone the harbour.</p>";
const SIDEBAR = "<p>Ferry timetable for the winter season.</p>";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

/** The rejected maps: one invalid name beside valid overrides, and non-objects. */
const REJECTED_MAPS = [
  [
    "an invalid name beside valid overrides",
    () => ({ ...GEOMETRY, accessGroups: { premium: GEOMETRY } }),
  ],
  ["an array", () => [{ chainsPerDay: 2, periodMinutes: 15 }]],
  ["null", () => null],
  ["a string", () => "premium"],
];

/**
 * The issuer grants `bodytext` by content key and every presented access
 * group by period. `bodytext` is wrapped under the chain family `premium`,
 * `sidebar` under the chain family `vault`, so the content-key route and the
 * vault family are each independent of the premium family.
 */
const accessPolicy = {
  decide(/** @type {any} */ _claims, /** @type {any} */ requested) {
    return {
      contentNames: requested.contentNames.filter(
        (/** @type {string} */ name) => name === "bodytext",
      ),
      periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
        accessGroup,
        futurePeriodCount: 2,
        authorizePeriod: () => true,
      })),
    };
  },
};

async function world() {
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const generation = (/** @type {number} */ fill) =>
    periodFamilyGeneration({
      keyDerivationSecret: new Uint8Array(32).fill(fill),
      geometry: GEOMETRY,
    });
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 5 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: periodFamilySupply({
      families: { premium: generation(7), vault: generation(8) },
      chainWindows: 2,
    }),
    issuerSupplyPlanFor: (issuer, render) => ({
      ...wholeRenderIssuerSupplyPlan(issuer, render),
      periodKeyDelivery: { premium: ["chain-keys"], vault: ["chain-keys"] },
    }),
    issuers: [
      {
        issuerName: ISSUER,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content("bodytext", BODY, "text/html", { accessGroups: ["premium"] });
  sealer.content("sidebar", SIDEBAR, "text/html", { accessGroups: ["vault"] });
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
              ? { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey }
              : undefined,
        },
        [{ issuerName: ISSUER, keyId: KEY_ID }],
      ),
    },
  ]).get(SIGNING_KID);
  const client = new Client({
    publisherOrigin: PUB,
    cache: new PeriodKeyCache(),
    chainKeyProfile: explicitChainKeyClientProfile,
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
  });
  return { client, page, registration };
}

/**
 * Relay one page, post the request to a selecting chain issuer and apply its
 * answer. Returns what each item opens to, or null when it has no key.
 *
 * @param {Awaited<ReturnType<typeof world>>} rendered
 */
async function unlockAndOpen({ client, page, registration }) {
  const clientData = client.parse(page);
  const wire = client.buildRequest(clientData, ISSUER, ["bodytext", "sidebar"]);
  const engine = chainKeyIssuerEngine({
    operatingIssuerNames: [ISSUER],
    accessPolicy,
    clock: new Clock(AT),
  });
  const answer = await new UnlockEndpoint(
    new IssuerProcessor(engine, { periodKeyInput: true }),
  ).handleRequest({ request: parseDcaRequest(JSON.stringify(wire)), registration });
  if (answer.response.status === 200) {
    await client.applyResponse(clientData, ISSUER, answer.response.body);
  }
  /** @param {string} name */
  const opened = async (name) => {
    try {
      return utf8Decode(await client.decrypt(clientData, name, client.extract(page, name)));
    } catch {
      return null;
    }
  };
  return {
    wire,
    status: answer.response.status,
    body: answer.response.body,
    bodytext: await opened("bodytext"),
    sidebar: await opened("sidebar"),
  };
}

for (const [name, map] of REJECTED_MAPS) {
  test(`invalid root geometry (${name}) keeps the base content-key route`, async () => {
    const rendered = await world();
    rendered.page.periodGeometry = map();
    const outcome = await unlockAndOpen(rendered);
    assert.equal(outcome.status, 200);
    assert.equal(outcome.bodytext, BODY);
    assert.equal(outcome.sidebar, null);
    assert.equal(Object.hasOwn(outcome.wire, "periodGeometry"), false);
    assert.equal(Object.hasOwn(outcome.wire.sealed, "chainKeys"), false);
  });
}

test("a partial root pair cannot borrow values from another group", async () => {
  const rendered = await world();
  rendered.page.periodGeometry = { chainsPerDay: 2 };
  const outcome = await unlockAndOpen(rendered);
  assert.equal(outcome.bodytext, BODY);
  assert.equal(outcome.sidebar, null);
  assert.equal(Object.hasOwn(outcome.wire.sealed, "chainKeys"), false);
});

test("one complete root pair relays both families", async () => {
  const outcome = await unlockAndOpen(await world());
  assert.equal(outcome.status, 200, JSON.stringify(outcome.body));
  assert.equal(outcome.bodytext, BODY);
  assert.equal(outcome.sidebar, SIDEBAR);
  assert.deepEqual(outcome.wire.periodGeometry, GEOMETRY);
  const input = chainKeyRequestInput(parseDcaRequest(JSON.stringify(outcome.wire)));
  assert.deepEqual([...input.presented].sort(), ["premium", "vault"]);
  assert.equal(input.family("premium").kind, "valid");
  assert.equal(input.family("vault").kind, "valid");
});

test("cached chain candidates require a complete root pair", async () => {
  const { page } = await world();
  const t = periodsOn(page, "bodytext", "premium")[0];
  const cache = { candidates: async () => [new Uint8Array(16).fill(9)] };
  const offered = async (data) => {
    const yielded = [];
    for await (const attempt of chainKeyCandidateSource(cache).attempts({
      dcaData: new DcaData(data),
      accessGroup: "premium",
      entries: [{ t, nonce: "n", key: "k" }],
      publisher: PUB,
      issuerNames: [ISSUER],
      chainIssuerNames: [ISSUER],
    }))
      yielded.push(attempt);
    return yielded;
  };
  assert.equal((await offered(page)).length, 1);
  for (const [name, map] of REJECTED_MAPS) {
    const rejected = structuredClone(page);
    rejected.periodGeometry = map();
    assert.deepEqual(await offered(rejected), [], name);
  }
});

function resetBoundary() {
  let release;
  const promise = new Promise((resolve) => {
    release = resolve;
  });
  return { promise, release: () => release() };
}

for (const strategy of ["retain", "expand"]) {
  for (const releaseAt of ["during cleanup", "after successor refusal"]) {
    test(`${strategy} browser chain derivation ${releaseAt} cannot open for the refused successor`, async () => {
      const { page, registration } = await world();
      let entitled = true;
      const decisions = [];
      const engine = chainKeyIssuerEngine({
        operatingIssuerNames: [ISSUER],
        clock: new Clock(AT),
        representation: "chain-keys",
        accessPolicy: {
          decide(_claims, requested) {
            decisions.push(entitled);
            return {
              contentNames: [],
              periodGrants: entitled
                ? requested.accessGroups.map((accessGroup) => ({
                    accessGroup,
                    futurePeriodCount: 2,
                    authorizePeriod: () => true,
                  }))
                : [],
            };
          },
        },
      });
      const processor = new IssuerProcessor(engine, {
        periodKeyInput: true,
        selectedExtensions: [...engine.selectedExtensions],
        capabilityEncoders: engine.capabilityEncoders,
      });
      const endpoint = new UnlockEndpoint(processor);
      const { sealedContent, ...dcaData } = page;
      const entered = resetBoundary(),
        deriveHeld = resetBoundary(),
        cleanupEntered = resetBoundary(),
        cleanupHeld = resetBoundary();
      let armed = false,
        paused = false,
        holdCleanup = false;
      const storage = new Storage({
        gate({ op }) {
          if (holdCleanup && op === "keys") {
            holdCleanup = false;
            cleanupEntered.release();
            return cleanupHeld.promise;
          }
        },
      });
      const chainCache = new ChainKeyCache({ strategy });
      const client = createBrowserClient({
        root: domOver(writeMarkupDelivery({ dcaData, sealedContent }), { publisherOrigin: PUB }),
        issuerName: ISSUER,
        unlockUrl: "https://issuer.example/unlock",
        acceptDirectResponse: true,
        relayPeriodKeys: true,
        storage,
        cacheNamespace: "reader",
        chainCache,
        chainKeyProfile: explicitChainKeyClientProfile,
        requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
        transport: {
          async post(_url, request) {
            const answer = await unlockThroughAdmission(processor, endpoint, request, registration);
            if (entitled) {
              assert.ok(
                answer.body.keys.chainKeys.length,
                "real issuer delivers a chain capability",
              );
              armed = true;
            }
            return { ...answer, contentType: "application/json" };
          },
        },
      });
      const original = subtle.deriveBits;
      subtle.deriveBits = async function (...args) {
        if (armed && !paused) {
          paused = true;
          entered.release();
          await deriveHeld.promise;
        }
        return original.apply(this, args);
      };
      try {
        const old = assert.rejects(client.open("sidebar"), { code: "context_retired" });
        await entered.promise;
        entitled = false;
        holdCleanup = releaseAt === "during cleanup";
        const clearing = client.clearReaderContext();
        if (holdCleanup) {
          await cleanupEntered.promise;
          deriveHeld.release();
          await old;
          await assert.rejects(client.open("sidebar"), { code: "context_retired" });
          cleanupHeld.release();
        }
        await clearing;
        await assert.rejects(client.open("sidebar"), { code: "no_key" });
        deriveHeld.release();
        await old;
        await assert.rejects(client.openLocal("sidebar"), { code: "no_key" });
        assert.deepEqual(chainCache.entries(), []);
        assert.deepEqual(await client.cache.entries(), []);
        assert.deepEqual(await storage.keys(), []);
        assert.equal(decisions[0], true);
        assert.ok(decisions.slice(1).every((value) => value === false));
        entitled = true;
        assert.equal(
          utf8Decode((await client.open("sidebar")).bytes),
          SIDEBAR,
          "same actual article opens with a newly authorized chain grant",
        );
        assert.ok(chainCache.entries().length);
      } finally {
        deriveHeld.release();
        cleanupHeld.release();
        subtle.deriveBits = original;
      }
    });
  }
}
