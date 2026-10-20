// @ts-check
//
// The request and the response carry the same chain collection under different
// member names, so the Capability collection rule in
// spec-profile--chain-keys.md holds on both sides.
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
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { chainKeyResponseInput } from "../core-client/chainKeyResponseInput.js";
import { chainKeyCarrierReader } from "../core-shared--client-issuer/chainKeyCarrierReader.js";
import { chainKeyCapabilitySource } from "../core-issuer/chainKeyCapabilitySource.js";
import { requireChainRepresentation } from "../core-issuer/chainKeyIssuerEngine.js";
import { chainKeyRequestInput } from "../core-issuer/chainKeyRequestInput.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";

const GROUP = "premium";
const OTHER = "archive";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const EARLY_T = "251023T1145";
const LATE_T = "251023T2345";
const CHAIN_KEY = base64urlEncode(new Uint8Array(16).fill(3));

function associated(page, request) {
  return new ResponseAssociation(page, ISSUER, {
    version: page.version,
    issuerName: ISSUER,
    resourceJWT: page.resourceJWT,
    keyId: page.keyIdFor(ISSUER),
    ...request,
  });
}

/** @param {unknown} collection @param {unknown} geometry @param {unknown} requestedPeriodKeys */
function requestCarrier(collection, geometry = GEOMETRY, requestedPeriodKeys) {
  return new DcaRequest({
    version: "dca/1",
    issuerName: "issuer.example",
    sealed: { contentKeys: {}, chainKeys: collection },
    periodGeometry: geometry,
    ...(requestedPeriodKeys === undefined ? {} : { requestedPeriodKeys }),
  });
}

/** @param {unknown} collection @param {unknown} geometry */
function responseCarrier(collection, geometry = GEOMETRY) {
  return { keys: { chainKeys: collection }, periodGeometry: geometry };
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
    read: (/** @type {unknown} */ collection, /** @type {unknown} */ geometry = GEOMETRY) =>
      chainKeyRequestInput(requestCarrier(collection, geometry)),
    sharedRead: (/** @type {unknown} */ collection, /** @type {unknown} */ geometry = GEOMETRY) =>
      chainKeyCarrierReader({
        container: { contentKeys: {}, chainKeys: collection },
        context: geometry,
        valueName: "sealed",
      }),
  },
  {
    carrier: "response",
    valueName: "value",
    read: (/** @type {unknown} */ collection, /** @type {unknown} */ geometry = GEOMETRY) =>
      chainKeyResponseInput(responseCarrier(collection), { periodGeometry: geometry }),
    sharedRead: (/** @type {unknown} */ collection, /** @type {unknown} */ geometry = GEOMETRY) =>
      chainKeyCarrierReader({
        container: { chainKeys: collection },
        context: geometry,
        valueName: "value",
      }),
  },
];

test("requestedPeriodKeys normalizes order and duplicates without presenting hint-only groups", () => {
  const input = chainKeyRequestInput(
    requestCarrier({ premium: { "251023T1415": CHAIN_KEY } }, GEOMETRY, {
      premium: ["251023T1415", "251023T1200", "251023T1415", "251023T1400"],
      absent: ["251023T1000"],
    }),
  );
  assert.deepEqual(input.requestedPeriodKeys, {
    premium: ["251023T1200", "251023T1400", "251023T1415"],
    absent: ["251023T1000"],
  });
  assert.deepEqual(input.presented, ["premium"]);
  assert.equal(input.family("absent").kind, "absent");
});

test("requestedPeriodKeys checks raw bounds and grid before source selection", () => {
  const duplicated = Array(289).fill("251023T1415");
  assert.throws(
    () =>
      chainKeyRequestInput(
        requestCarrier({ premium: { "251023T1415": CHAIN_KEY } }, GEOMETRY, {
          premium: duplicated,
        }),
      ),
    (/** @type {any} */ error) => error.code === "binding_failed",
  );

  assert.throws(
    () =>
      chainKeyRequestInput(
        requestCarrier({ premium: { "251023T1415": CHAIN_KEY } }, GEOMETRY, {
          premium: ["251023T1415", "251023T1410"],
        }),
      ),
    (/** @type {any} */ error) => error.code === "binding_failed",
    "a label off the admitted family grid is a request-structure failure",
  );

  const exactlyBounded = chainKeyRequestInput(
    requestCarrier({ premium: { "251023T1415": CHAIN_KEY } }, GEOMETRY, {
      premium: Array(288).fill("251023T1415"),
      archive: Array(224).fill("251023T1400"),
    }),
  );
  assert.deepEqual(exactlyBounded.requestedPeriodKeys, {
    premium: ["251023T1415"],
    archive: ["251023T1400"],
  });
  assert.throws(
    () =>
      chainKeyRequestInput(
        requestCarrier({ premium: { "251023T1415": CHAIN_KEY } }, GEOMETRY, {
          premium: Array(288).fill("251023T1415"),
          archive: Array(225).fill("251023T1400"),
        }),
      ),
    (/** @type {any} */ error) => error.code === "binding_failed",
    "the total raw input is bounded before duplicate normalization",
  );
});

test("requestedPeriodKeys cannot repair an already invalid source family", () => {
  const input = chainKeyRequestInput(
    requestCarrier({ premium: { "251023T1415": CHAIN_KEY, "251023T1400": CHAIN_KEY } }, GEOMETRY, {
      premium: ["251023T1415"],
    }),
  );
  assert.equal(input.family("premium").kind, "invalid");
  assert.deepEqual(input.requestedPeriodKeys, { premium: ["251023T1415"] });
  for (const family of [null, "x", 7, [], {}]) {
    const failed = chainKeyRequestInput(
      requestCarrier({ [GROUP]: family }, GEOMETRY, { [GROUP]: ["251023T1410"] }),
    );
    assert.equal(
      failed.family(GROUP).kind,
      "invalid",
      "off-grid hints do not widen family failure",
    );
  }
});

describe("one decided reading of both chain carriers", () => {
  for (const { carrier, valueName, read, sharedRead } of CARRIERS) {
    test(`${carrier}: a non-string member is dropped while valid siblings survive`, () => {
      const input = read({
        [GROUP]: { [LATE_T]: { key: 7 }, [EARLY_T]: CHAIN_KEY },
        [OTHER]: { [LATE_T]: CHAIN_KEY },
      });

      assert.equal(input.family(GROUP).kind, "valid", "one malformed value costs only that member");
      assert.deepEqual(
        input.family(GROUP).members.map((/** @type {any} */ member) => member.t),
        [EARLY_T],
      );
      assert.equal(
        input.family(OTHER).kind,
        "valid",
        "a malformed family does not reach its neighbour",
      );
      assert.equal(input.family(OTHER).members[0][valueName], CHAIN_KEY);
    });

    test(`${carrier}: positioned duplicates void a family before envelope admission`, () => {
      for (const value of ["AQ==", "AQ"]) {
        const input = read({
          [GROUP]: { "251023T2330": value, [LATE_T]: CHAIN_KEY },
          [OTHER]: { [LATE_T]: CHAIN_KEY },
        });
        assert.equal(input.family(GROUP).kind, "invalid");
        assert.equal(input.family(OTHER).kind, "valid");
      }
    });

    test(`${carrier}: an invalid label costs one member and keeps a valid sibling`, () => {
      const input = read({
        [GROUP]: { "251023T1410": CHAIN_KEY, [EARLY_T]: CHAIN_KEY },
        [OTHER]: { [LATE_T]: CHAIN_KEY },
      });

      assert.equal(input.family(GROUP).kind, "valid");
      assert.deepEqual(
        input.family(GROUP).members.map((/** @type {any} */ member) => member.t),
        [EARLY_T],
      );
      assert.equal(input.family(OTHER).kind, "valid");
    });

    test(`${carrier}: member order follows the label, not the wire`, () => {
      /** @type {Record<string, string>} */
      const family = {};
      family[LATE_T] = CHAIN_KEY;
      family[EARLY_T] = CHAIN_KEY;

      const view = read({ [GROUP]: family }).family(GROUP);

      assert.equal(view.kind, "valid");
      assert.deepEqual(
        view.members.map((/** @type {any} */ member) => member.t),
        [EARLY_T, LATE_T],
        "wire member order changes no derived byte and decides no member order",
      );
    });

    test(`${carrier}: invalid stays distinct from absent`, () => {
      const input = read({ [GROUP]: { [LATE_T]: CHAIN_KEY } });

      assert.deepEqual([...input.presented], [GROUP]);
      assert.equal(input.family(GROUP).kind, "valid");
      assert.equal(
        input.family(OTHER).kind,
        "absent",
        "a family nobody presented is absent, never invalid",
      );

      for (const family of [null, "x", 7, [], {}]) {
        const failed = read({ [GROUP]: family, [OTHER]: { [LATE_T]: CHAIN_KEY } });
        assert.deepEqual([...failed.presented], [GROUP, OTHER]);
        assert.equal(failed.family(GROUP).kind, "invalid");
        assert.equal(failed.family(OTHER).kind, "valid");
      }
      for (const collection of ["not-a-collection", null]) {
        const malformed = sharedRead(collection);
        assert.deepEqual([...malformed.presented], []);
        assert.equal(
          malformed.family(GROUP).kind,
          "invalid",
          "a malformed collection invalidates every family it could have carried",
        );
      }
    });

    test(`${carrier}: geometry resolves as a whole pair or the family fails`, () => {
      const partial = read({ [GROUP]: { [LATE_T]: CHAIN_KEY } }, { chainsPerDay: 2 });
      assert.equal(
        partial.family(GROUP).kind,
        "invalid",
        "a partial root pair fails the family instead of inferring",
      );

      const reordered = read(
        { [GROUP]: { [LATE_T]: CHAIN_KEY } },
        { periodMinutes: 15, chainsPerDay: 2 },
      );
      assert.deepEqual(reordered.family(GROUP).geometry, {
        chainsPerDay: 2,
        periodMinutes: 15,
        windowMinutes: 720,
        positionsPerWindow: 48,
      });

      const unresolved = read({ [GROUP]: { [LATE_T]: CHAIN_KEY } }, null);
      assert.equal(
        unresolved.family(GROUP).kind,
        "invalid",
        "a chain-bearing family without a resolvable pair is invalid",
      );
    });

    test(`${carrier}: one window holds one member, within both bounds`, () => {
      const collision = read({ [GROUP]: { [LATE_T]: CHAIN_KEY, "251023T2330": CHAIN_KEY } });
      assert.equal(
        collision.family(GROUP).kind,
        "invalid",
        "two positions from one window invalidate the family collection",
      );

      const two = ["251023T1145", "251023T2345"];
      const full = read({ [GROUP]: Object.fromEntries(two.map((t) => [t, CHAIN_KEY])) });
      assert.equal(full.family(GROUP).kind, "valid");
      assert.equal(full.family(GROUP).members.length, 2);

      const overFamily = read({
        [GROUP]: {
          [two[0]]: CHAIN_KEY,
          [two[1]]: CHAIN_KEY,
          "251024T1145": { malformed: true },
        },
        [OTHER]: { [LATE_T]: CHAIN_KEY },
      });
      assert.equal(overFamily.family(GROUP).kind, "invalid", "raw maxChainMembersPerFamily is 2");
      assert.equal(
        overFamily.family(OTHER).kind,
        "valid",
        "an over-limit family does not suppress its valid sibling",
      );

      const atMessageLimit = read(
        Object.fromEntries(
          Array.from({ length: 16 }, (_, index) => [`g${index}`, { [LATE_T]: CHAIN_KEY }]),
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
          Array.from({ length: 17 }, (_, index) => [`g${index}`, { [LATE_T]: CHAIN_KEY }]),
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

test("the response reader marks a grammar-failing family name invalid rather than absent", () => {
  const input = chainKeyResponseInput(
    responseCarrier({ "bad name": { [LATE_T]: CHAIN_KEY }, [OTHER]: { [LATE_T]: CHAIN_KEY } }),
    { periodGeometry: GEOMETRY },
  );
  assert.ok(input.presented.includes("bad name"));
  assert.equal(input.family("bad name").kind, "invalid");
});

test("the response carrier leaves wrapped ciphertext spelling to transport admission", () => {
  const input = chainKeyResponseInput(
    {
      keys: { chainKeys: { [GROUP]: { "251023T2330": { key: "AQ==" } } } },
    },
    { periodGeometry: GEOMETRY },
  );

  assert.equal(input.family(GROUP).kind, "valid");
  assert.deepEqual(input.family(GROUP).members[0].value, { key: "AQ==" });
});

test("explicit local ingress capacity admits 16 chain members with ordinary base companions", () => {
  const chainGroups = Object.fromEntries(
    Array.from({ length: 8 }, (_, index) => [
      `g${index}`,
      { [EARLY_T]: CHAIN_KEY, [LATE_T]: CHAIN_KEY },
    ]),
  );
  const document = JSON.stringify(
    new DcaRequest({
      version: "1",
      issuerName: "paywall",
      keyId: "2025-10",
      sealed: {
        contentKeys: { bodytext: "sealed-content-key" },
        periodKeys: { ordinary: { [LATE_T]: "sealed-period-key" } },
        chainKeys: chainGroups,
      },
      periodGeometry: GEOMETRY,
    }).toObject(),
  );
  const engine = {
    checkOperatingIssuerName() {},
    unlock: async () => ({ contentKeys: {}, periodKeys: {}, errors: {} }),
  };

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
  return `e30.${base64urlEncode(utf8Encode(JSON.stringify(payload)))}.c2lnbmF0dXJl`;
}

/** @param {number} futurePeriodCount */
function policy(futurePeriodCount) {
  return {
    decide(/** @type {any} */ _claims, /** @type {any} */ requested) {
      return {
        contentNames: [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
          accessGroup,
          futurePeriodCount,
          authorizePeriod: () => true,
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
    issuerSupplyPlanFor: (issuer, render) => ({
      ...wholeRenderIssuerSupplyPlan(issuer, render),
      periodKeyDelivery: { [GROUP]: ["chain-keys"] },
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
    requestBuilderFactory: (/** @type {any} */ options) => new ChainKeyRequestBuilder(options),
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
    const geometry = document.periodGeometry;
    Object.defineProperty(document, "periodGeometry", {
      enumerable: true,
      get() {
        reads++;
        return geometry;
      },
    });
    const engine = new IssuerEngine({
      operatingIssuerNames: [ISSUER],
      accessPolicy: policy(2),
      periodCapabilitySource: requireChainRepresentation(chainKeyCapabilitySource()),
    });

    const result = await engine.unlock(request, registration, {}, { capturedAtMs: Date.parse(AT) });

    assert.deepEqual(result.errors, {});
    assert.deepEqual(Object.keys(result.periodKeys[GROUP]), ["251023T1415", "251023T1430"]);
    assert.equal(reads, 1, "one unlock resolves the request carrier once");
  });

  test("the client never reads response geometry while filing access groups", async () => {
    const groups = ["premium", "archive", "sport"];
    let reads = 0;
    const response = {
      keys: {
        chainKeys: Object.fromEntries(groups.map((group) => [group, { [LATE_T]: CHAIN_KEY }])),
      },
    };
    Object.defineProperty(response, "periodGeometry", {
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
      chainKeyProfile: explicitChainKeyClientProfile,
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
        chainKeys: Object.fromEntries(groups.map((group) => [group, { [LATE_T]: CHAIN_KEY }])),
      },
      periodGeometry: GEOMETRY,
    };
    const applied = await resolver.applyResponse(page, ISSUER, response, associated(page, request));

    assert.deepEqual(applied, { accepted: 3, errors: [], issues: [] });
    assert.deepEqual(
      filed.map(([accessGroup]) => accessGroup),
      groups,
    );
    assert.equal(reads, 0, "response metadata supplies no chain context");
  });
});

describe("the reading decides what the client files", () => {
  /** @param {unknown} lateMember */
  async function applyFamilies(lateMember) {
    /** @type {any[][]} */
    const filed = [];
    const resolver = new ContentKeyResolver({
      chainCache: {
        put(/** @type {any[]} */ ...args) {
          filed.push(args);
        },
        candidates: () => [],
      },
      chainKeyProfile: explicitChainKeyClientProfile,
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
        chainKeys: { [GROUP]: { [LATE_T]: CHAIN_KEY }, [OTHER]: { [LATE_T]: CHAIN_KEY } },
      },
      periodGeometry: GEOMETRY,
    };
    const applied = await resolver.applyResponse(
      page,
      ISSUER,
      {
        keys: {
          chainKeys: {
            [GROUP]: { [EARLY_T]: CHAIN_KEY, [LATE_T]: lateMember },
            [OTHER]: { [LATE_T]: CHAIN_KEY },
          },
        },
        periodGeometry: GEOMETRY,
      },
      associated(page, request),
    );
    return { applied, filed };
  }

  test("a family with a non-string member files none of its members", async () => {
    // EARLY_T lies outside the reach the request presented; the number is a
    // malformed member of an otherwise valid family. Neither is a string or
    // an object, so the other family's direct member is still filed.
    const { applied, filed } = await applyFamilies(7);

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
          { section: "chainKeys", code: "malformed_key" },
          { section: "chainKeys", code: "malformed_key" },
        ],
      },
      "the unpresented cutoff and the malformed member are each a malformed key",
    );
  });

  test("an object member beside a direct member rejects the representation", async () => {
    // Response binding Section 3 classifies by JSON type: `{ key: 7 }` is a
    // client-bound object entry even though its key member is malformed, and
    // a string beside it in a supported section rejects the representation.
    const { applied, filed } = await applyFamilies({ key: 7 });

    assert.deepEqual(filed, [], "no family is filed from a rejected representation");
    assert.deepEqual(applied, {
      accepted: 0,
      errors: [],
      issues: [{ section: "response", code: "invalid_transport" }],
    });
  });
});

test("chain opening errors report only the presented source member while an item key survives", async () => {
  const page = new DcaData({
    version: "1",
    resourceJWT: token({ renderId: "render-chain-error-association" }),
    issuerData: { [ISSUER]: { keyId: "k1", sealed: {} } },
    contentData: {},
  });
  const resolver = new ContentKeyResolver({ chainKeyProfile: explicitChainKeyClientProfile });
  const application = await resolver.applyResponse(
    page,
    ISSUER,
    {
      keys: { contentKeys: { bodytext: CHAIN_KEY } },
      errors: {
        [`${GROUP}|${LATE_T}`]: { error: "unseal_failed" },
        [`${GROUP}|${EARLY_T}`]: { error: "unseal_failed" },
      },
    },
    associated(page, {
      sealed: {
        contentKeys: { bodytext: "sealed-item" },
        chainKeys: { [GROUP]: { [LATE_T]: CHAIN_KEY } },
      },
      periodGeometry: GEOMETRY,
    }),
  );
  assert.deepEqual(application, {
    accepted: 1,
    errors: [{ coordinate: `${GROUP}|${LATE_T}`, error: "unseal_failed" }],
    issues: [{ section: "errors", code: "unsolicited_coordinate" }],
  });
  assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), new Uint8Array(16).fill(3));
});
