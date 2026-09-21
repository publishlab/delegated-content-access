// @ts-check
//
// The request and the response carry the same chain collection under different
// member names, so the Capability collection rule in
// spec--period-key-chains.md holds on both sides.
// These cases fix the two readings that had drifted apart and the count of
// times each carrier is read.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { DcaRequest, parseDcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { PeriodChainRequestBuilder } from "../core-client/PeriodChainRequestBuilder.js";
import { periodChainResponseInput } from "../core-client/periodChainResponseInput.js";
import { periodChainCarrierReader } from "../core-shared--client-issuer/periodChainCarrierReader.js";
import { periodChainCapabilitySource } from "../core-issuer/periodChainCapabilitySource.js";
import { requireChainRepresentation } from "../core-issuer/periodChainIssuerEngine.js";
import { periodChainRequestInput } from "../core-issuer/periodChainRequestInput.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { explicitPeriodChainClientProfile } from "../referenceProfile.js";

const GROUP = "premium";
const OTHER = "archive";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const EARLY_T = "251023T1145";
const LATE_T = "251023T2345";
const STATE = base64urlEncode(new Uint8Array(16).fill(3));

function associated(page, request) {
  return new ResponseAssociation(page, ISSUER, {
    version: page.version,
    issuerName: ISSUER,
    resourceJWT: page.resourceJWT,
    keyId: page.keyIdFor(ISSUER),
    ...request,
  });
}

/** @param {unknown} collection @param {unknown} periodChain */
function requestCarrier(collection, periodChain = GEOMETRY) {
  return new DcaRequest({
    version: "dca/1",
    issuerName: "issuer.example",
    sealed: { contentKeys: {}, periodChainKeys: collection },
    periodChain,
  });
}

/** @param {unknown} collection @param {unknown} periodChain */
function responseCarrier(collection, periodChain = GEOMETRY) {
  return { keys: { periodChainKeys: collection }, periodChain };
}

/**
 * Each carrier's own vocabulary over the one reading. `sharedRead` enters the
 * reader with the container the wrapper would have handed it, so one case can
 * state a rule that holds on both sides even for a collection the request
 * wrapper refuses outright: the issuer decides request admission of the
 * collection itself, and `carrier-corrections.test.js` holds that.
 */
const CARRIERS = [
  {
    carrier: "request",
    valueName: "sealed",
    read: (/** @type {unknown} */ collection, /** @type {unknown} */ periodChain = GEOMETRY) =>
      periodChainRequestInput(requestCarrier(collection, periodChain)),
    sharedRead: (
      /** @type {unknown} */ collection,
      /** @type {unknown} */ periodChain = GEOMETRY,
    ) =>
      periodChainCarrierReader({
        container: { contentKeys: {}, periodChainKeys: collection },
        context: periodChain,
        valueName: "sealed",
      }),
  },
  {
    carrier: "response",
    valueName: "value",
    read: (/** @type {unknown} */ collection, /** @type {unknown} */ periodChain = GEOMETRY) =>
      periodChainResponseInput(responseCarrier(collection, periodChain)),
    sharedRead: (
      /** @type {unknown} */ collection,
      /** @type {unknown} */ periodChain = GEOMETRY,
    ) =>
      periodChainCarrierReader({
        container: { periodChainKeys: collection },
        context: periodChain,
        valueName: "value",
      }),
  },
];

describe("one decided reading of both chain carriers", () => {
  for (const { carrier, valueName, read, sharedRead } of CARRIERS) {
    test(`${carrier}: a non-string member value invalidates that family alone`, () => {
      const input = read({
        [GROUP]: { [LATE_T]: { key: STATE } },
        [OTHER]: { [LATE_T]: STATE },
      });

      assert.equal(
        input.family(GROUP).kind,
        "invalid",
        "the grammar spells every member value as a string",
      );
      assert.equal(
        input.family(OTHER).kind,
        "valid",
        "a malformed family does not reach its neighbour",
      );
      assert.equal(input.family(OTHER).members[0][valueName], STATE);
    });

    test(`${carrier}: member order follows the label, not the wire`, () => {
      /** @type {Record<string, string>} */
      const family = {};
      family[LATE_T] = STATE;
      family[EARLY_T] = STATE;

      const view = read({ [GROUP]: family }).family(GROUP);

      assert.equal(view.kind, "valid");
      assert.deepEqual(
        view.members.map((/** @type {any} */ member) => member.t),
        [EARLY_T, LATE_T],
        "wire member order changes no derived byte and decides no member order",
      );
    });

    test(`${carrier}: invalid stays distinct from absent`, () => {
      const input = read({ [GROUP]: { [LATE_T]: STATE } });

      assert.deepEqual([...input.presented], [GROUP]);
      assert.equal(input.family(GROUP).kind, "valid");
      assert.equal(
        input.family(OTHER).kind,
        "absent",
        "a family nobody presented is absent, never invalid",
      );

      const malformed = sharedRead("not-a-collection");
      assert.deepEqual([...malformed.presented], []);
      assert.equal(
        malformed.family(GROUP).kind,
        "invalid",
        "a malformed collection invalidates every family it could have carried",
      );
    });

    test(`${carrier}: geometry resolves as a whole pair or the family fails`, () => {
      const partial = read(
        { [GROUP]: { [LATE_T]: STATE } },
        {
          ...GEOMETRY,
          accessGroups: { [GROUP]: { chainsPerDay: 4 } },
        },
      );
      assert.equal(
        partial.family(GROUP).kind,
        "invalid",
        "an applicable partial override fails its family instead of merging",
      );

      const override = read(
        { [GROUP]: { [LATE_T]: STATE } },
        {
          ...GEOMETRY,
          accessGroups: { [GROUP]: { chainsPerDay: 4, periodMinutes: 5 } },
        },
      );
      assert.deepEqual(override.family(GROUP).geometry, {
        chainsPerDay: 4,
        periodMinutes: 5,
        windowMinutes: 360,
        positionsPerWindow: 72,
      });

      const unresolved = read({ [GROUP]: { [LATE_T]: STATE } }, null);
      assert.equal(
        unresolved.family(GROUP).kind,
        "invalid",
        "a chain-bearing family without a resolvable pair is invalid",
      );
    });

    test(`${carrier}: one window holds one member, within both bounds`, () => {
      const collision = read({ [GROUP]: { [LATE_T]: STATE, "251023T2330": STATE } });
      assert.equal(
        collision.family(GROUP).kind,
        "invalid",
        "two positions from one window invalidate the family collection",
      );

      const two = ["251023T1145", "251023T2345"];
      const full = read({ [GROUP]: Object.fromEntries(two.map((t) => [t, STATE])) });
      assert.equal(full.family(GROUP).kind, "valid");
      assert.equal(full.family(GROUP).members.length, 2);

      const overFamily = read({
        [GROUP]: Object.fromEntries([...two, "251024T1145"].map((t) => [t, STATE])),
        [OTHER]: { [LATE_T]: STATE },
      });
      assert.equal(overFamily.family(GROUP).kind, "invalid", "maxChainMembersPerFamily is 2");
      assert.equal(
        overFamily.family(OTHER).kind,
        "valid",
        "an over-limit family does not suppress its valid sibling",
      );

      const atMessageLimit = read(
        Object.fromEntries(
          Array.from({ length: 16 }, (_, index) => [`g${index}`, { [LATE_T]: STATE }]),
        ),
      );
      assert.ok(
        atMessageLimit.presented.every(
          (/** @type {string} */ accessGroup) =>
            atMessageLimit.family(accessGroup).kind === "valid",
        ),
        "maxChainMembersPerMessage admits 16 across all access groups",
      );

      const overMessage = read(
        Object.fromEntries(
          Array.from({ length: 17 }, (_, index) => [`g${index}`, { [LATE_T]: STATE }]),
        ),
      );
      assert.ok(
        overMessage.presented.every(
          (/** @type {string} */ accessGroup) => overMessage.family(accessGroup).kind === "invalid",
        ),
        "maxChainMembersPerMessage refuses the whole 17-member collection",
      );
    });
  }
});

test("explicit local ingress capacity admits 16 chain members with ordinary base companions", () => {
  const chainGroups = Object.fromEntries(
    Array.from({ length: 8 }, (_, index) => [`g${index}`, { [EARLY_T]: STATE, [LATE_T]: STATE }]),
  );
  const document = JSON.stringify(
    new DcaRequest({
      version: "1",
      issuerName: "paywall",
      keyId: "2025-10",
      sealed: {
        contentKeys: { bodytext: "sealed-content-key" },
        periodKeys: { ordinary: { [LATE_T]: "sealed-exact-key" } },
        periodChainKeys: chainGroups,
      },
      periodChain: GEOMETRY,
    }).toObject(),
  );
  const engine = { unlock: async () => ({ contentKeys: {}, periodKeys: {}, errors: {} }) };

  assert.equal(
    new IssuerProcessor(engine, {
      limits: { maxEntries: 18, maxEntriesPerGroup: 2 },
    }).admit(document).kind,
    "admitted",
    "16 chain members plus two base entries fit the provisioned cap",
  );
  assert.deepEqual(
    new IssuerProcessor(engine).admit(document),
    {
      kind: "failure",
      code: "too_many_entries",
    },
    "the stricter finite reference default may reject before the protocol maximum",
  );
});

const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const NAME = "bodytext";
const AT = "2025-10-23T14:20:00Z";

/** @param {object} payload */
function token(payload) {
  return `e30.${base64urlEncode(utf8Encode(JSON.stringify(payload)))}.x`;
}

/** @param {number} periodCount */
function policy(periodCount) {
  return {
    decide(/** @type {any} */ _claims, /** @type {any} */ requested) {
      return {
        contentNames: [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
          accessGroup,
          periodCount,
        })),
      };
    },
  };
}

/** One sealed page, its registration and a relay client, as the issuer lane builds them. */
async function world() {
  const { subtle } = globalThis.crypto;
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: GEOMETRY,
  });
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: periodFamilySupply({ families: { [GROUP]: generation }, chainWindows: 2 }),
    issuerSupplyPlanFor: () => ({ periodKeyDelivery: { [GROUP]: ["chain"] } }),
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
  sealer.content(NAME, "<p>The council voted 7-2 to rezone the harbour.</p>", "text/html", {
    accessGroups: [GROUP],
  });
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
  const client = new Client({
    publisherOrigin: PUB,
    cache: new PeriodKeyCache(),
    requestBuilderFactory: (/** @type {any} */ options) => new PeriodChainRequestBuilder(options),
  });
  return {
    registration,
    request: parseDcaRequest(
      JSON.stringify(client.buildRequest(client.parse(page), ISSUER, [NAME])),
    ),
  };
}

describe("each carrier is read once per message", () => {
  test("the issuer reads one request once, for presentation, selection and capability production", async () => {
    const { registration, request } = await world();
    let reads = 0;
    const document = request.toObject();
    const periodChain = document.periodChain;
    Object.defineProperty(document, "periodChain", {
      enumerable: true,
      get() {
        reads++;
        return periodChain;
      },
    });
    const engine = new IssuerEngine({
      accessPolicy: policy(2),
      periodCapabilitySource: requireChainRepresentation(periodChainCapabilitySource()),
    });

    const result = await engine.unlock(request, registration, {}, { capturedAtMs: Date.parse(AT) });

    assert.deepEqual(result.errors, {});
    assert.deepEqual(Object.keys(result.periodKeys[GROUP]), ["251023T1415", "251023T1430"]);
    assert.equal(reads, 1, "one unlock resolves the request carrier once");
  });

  test("the client reads one response once, for every access group it files", async () => {
    const groups = ["premium", "archive", "sport"];
    let reads = 0;
    const response = {
      keys: {
        periodChainKeys: Object.fromEntries(groups.map((group) => [group, { [LATE_T]: STATE }])),
      },
    };
    Object.defineProperty(response, "periodChain", {
      enumerable: true,
      get() {
        reads++;
        return GEOMETRY;
      },
    });
    /** @type {any[][]} */
    const filed = [];
    const resolver = new ContentKeyResolver({
      chainCache: {
        put(/** @type {any[]} */ ...args) {
          filed.push(args);
        },
        candidates: () => [],
      },
      periodChainProfile: explicitPeriodChainClientProfile,
    });
    const page = new DcaData(
      {
        version: "1",
        resourceJWT: token({ renderId: "render-chain-carrier-reader" }),
        issuerData: {
          [ISSUER]: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: {} },
        },
        contentData: {},
      },
      { publisherOrigin: PUB },
    );

    const request = {
      sealed: {
        periodChainKeys: Object.fromEntries(groups.map((group) => [group, { [LATE_T]: STATE }])),
      },
      periodChain: GEOMETRY,
    };
    const applied = await resolver.applyResponse(page, ISSUER, response, associated(page, request));

    assert.deepEqual(applied, { accepted: 3, errors: [], issues: [] });
    assert.deepEqual(
      filed.map(([accessGroup]) => accessGroup),
      groups,
    );
    assert.equal(reads, 1, "one response resolves once, whatever the number of access groups");
  });
});

describe("the reading decides what the client files", () => {
  test("a family with a non-string member files none of its members", async () => {
    /** @type {any[][]} */
    const filed = [];
    const resolver = new ContentKeyResolver({
      chainCache: {
        put(/** @type {any[]} */ ...args) {
          filed.push(args);
        },
        candidates: () => [],
      },
      periodChainProfile: explicitPeriodChainClientProfile,
    });
    const page = new DcaData(
      {
        version: "1",
        resourceJWT: token({ renderId: "render-chain-family-drop" }),
        issuerData: {
          [ISSUER]: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: {} },
        },
        contentData: {},
      },
      { publisherOrigin: PUB },
    );

    const request = {
      sealed: {
        periodChainKeys: { [GROUP]: { [LATE_T]: STATE }, [OTHER]: { [LATE_T]: STATE } },
      },
      periodChain: GEOMETRY,
    };
    const applied = await resolver.applyResponse(
      page,
      ISSUER,
      {
        keys: {
          periodChainKeys: {
            [GROUP]: { [EARLY_T]: STATE, [LATE_T]: { key: STATE } },
            [OTHER]: { [LATE_T]: STATE },
          },
        },
        periodChain: GEOMETRY,
      },
      associated(page, request),
    );

    assert.deepEqual(
      filed.map(([accessGroup, cutoffT]) => [accessGroup, cutoffT]),
      [[OTHER, LATE_T]],
      "the well-formed member goes down with the non-string member of its family",
    );
    assert.deepEqual(
      applied,
      {
        accepted: 1,
        errors: [],
        issues: [
          { section: "periodChainKeys", code: "malformed_key" },
          { section: "periodChainKeys", code: "malformed_key" },
        ],
      },
      "the invalid family answers no geometry, so every one of its entries is a malformed key",
    );
  });
});
