// @ts-check
//
// The chain-key request relay carries supplied capability over the wire and
// derives nothing. These tests pin its selection and composition without a
// chain profile or cache anywhere in the client.

import test from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { Browser } from "../../../demo/actors/Browser.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { rootFromPage } from "../../../demo/support/queryableRoot.js";
import { normalizeRequestedPeriodKeys } from "../core-shared--client-issuer/requestedPeriodKeys.js";
import { settleChainGeometry } from "../core-shared/chainKeyConstruction.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { chainKeyRequestView } from "../core-shared--client-issuer/ChainKeyRequest.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { referenceChainKeyProfile } from "../referenceProfile.js";
import { chainKeyRequestInput } from "../core-issuer/chainKeyRequestInput.js";
import { assertIssuerRequestBudget } from "../../../core-publisher/issuerRequestBudget.js";
import { requestEntryCounts, requestLimits } from "../../../core-shared/requestLimits.js";
import { world, BODYTEXT } from "../../../test-lib/fixtures/wire-policy-world.js";
import { ISSUER_NAME } from "../../../demo/scenarios/fixtures.js";
import { contentRecordOf, issuerBlockOf } from "../../../test-lib/helpers/inspect.js";
import { keyAt, setKeyAt } from "../../../test-reference/support/namedRecords.js";

/**
 * The labels one group's requestedPeriodKeys records carry, in wire order.
 *
 * @param {any} requested
 * @param {string} accessGroup
 * @returns {string[]|undefined}
 */
function hintsFor(requested, accessGroup) {
  const records = requested.filter(
    (/** @type {any} */ record) => record.accessGroup === accessGroup,
  );
  return records.length === 0
    ? undefined
    : records.flatMap((/** @type {any} */ record) => record.periods);
}

const ISSUER_A = "issuer-a";
const ISSUER_B = "issuer-b";

function pageData() {
  return {
    version: "1",
    resourceJWT: `e30.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "relay-render" })))}.c2lnbmF0dXJl`,
    periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
    contentData: [
      {
        contentName: "bodytext",
        contentType: "text/html",
        nonce: "n",
        keys: [
          { accessGroup: "premium", period: "251023T1400", nonce: "pn", key: "pk" },
          {
            accessGroup: "vault",
            period: "251023T1400",
            nonce: "vn",
            key: "vk",
            bind: "dca-bind-seal-omission",
          },
        ],
      },
      {
        contentName: "other",
        contentType: "text/html",
        nonce: "n2",
        keys: [{ accessGroup: "unused", period: "251023T1400", nonce: "un", key: "uk" }],
      },
      {
        contentName: "second",
        contentType: "text/html",
        nonce: "n3",
        keys: [
          { accessGroup: "premium", period: "251023T1415", nonce: "p2n", key: "p2k" },
          { accessGroup: "premium", period: "251023T1400", nonce: "p3n", key: "p3k" },
        ],
      },
    ],
    issuerData: [
      {
        issuerName: ISSUER_A,
        keyId: "a-key",
        unlockUrl: "https://a.example/unlock",
        sealed: {
          contentKeys: [{ contentName: "bodytext", key: "AQ" }],
          periodKeys: [{ accessGroup: "premium", period: "251023T1400", key: "Ag" }],
          chainKeys: [
            { accessGroup: "premium", cutoff: "251023T2345", key: "Aw" },
            { accessGroup: "vault", cutoff: "251023T1755", key: "BA" },
            { accessGroup: "vault", cutoff: "251023T2355", key: "BQ" },
            { accessGroup: "unused", cutoff: "251023T2345", key: "Bg" },
          ],
        },
      },
      {
        issuerName: ISSUER_B,
        keyId: "b-key",
        unlockUrl: "https://b.example/unlock",
        sealed: {
          contentKeys: [{ contentName: "bodytext", key: "CA" }],
          chainKeys: [{ accessGroup: "premium", cutoff: "251023T2345", key: "CQ" }],
        },
      },
    ],
  };
}

function build(
  data,
  issuerName = ISSUER_A,
  needed = ["bodytext"],
  builder = new ChainKeyRequestBuilder({ relayPeriodKeys: true }),
) {
  return builder.build(new DcaData(data), issuerName, needed);
}

test("publisher budget covers the real chain relay plus bounded client hints", async () => {
  const fixture = await world();
  const { dcaData } = await fixture.render();
  dcaData.periodGeometry = {
    chainsPerDay: 2,
    periodMinutes: 15,
  };
  issuerBlockOf(dcaData, ISSUER_NAME).sealed.chainKeys = [
    { accessGroup: "premium", cutoff: "251023T2345", key: "Aw" },
  ];
  const chain = new ChainKeyRequestBuilder({ relayPeriodKeys: true })
    .build(new DcaData(dcaData), ISSUER_NAME, [BODYTEXT.name])
    .toObject();
  assert.equal(requestEntryCounts(chain.sealed).entries, 4);
  assert.equal(requestEntryCounts(chain.sealed).groups.get("premium"), 3);
  assert.deepEqual(chain.sealed.chainKeys, issuerBlockOf(dcaData, ISSUER_NAME).sealed.chainKeys);

  // requestedPeriodKeys is client-added metadata outside the publication.
  const { requestedPeriodKeys, ...withoutHints } = chain;
  assert.ok(hintsFor(requestedPeriodKeys, "premium")?.length);
  const lowerBoundBytes = utf8Encode(JSON.stringify(withoutHints)).length;
  const fullBytes = utf8Encode(JSON.stringify(chain)).length;
  const hintBytes = fullBytes - lowerBoundBytes;
  assert.ok(hintBytes > 0);
  const extraBytes = hintBytes + 32;
  const limits = { maxEntries: 4, maxEntriesPerGroup: 3 };
  assert.doesNotThrow(() =>
    assertIssuerRequestBudget(dcaData, {
      issuerName: ISSUER_NAME,
      limits: requestLimits({ ...limits, maxBodyBytes: fullBytes + 32 }),
      clientRequestExtraBytes: extraBytes,
    }),
  );
  assert.throws(
    () =>
      assertIssuerRequestBudget(dcaData, {
        issuerName: ISSUER_NAME,
        limits: requestLimits({ ...limits, maxBodyBytes: fullBytes + 31 }),
        clientRequestExtraBytes: extraBytes,
      }),
    { code: "bad_config", message: /maxBodyBytes/ },
  );
});

test("base emits neither chain-key member while relay copies only selected issuer families", () => {
  const data = pageData();
  const page = new DcaData(data);
  const base = new DcaRequestBuilder({ relayPeriodKeys: true })
    .build(page, ISSUER_A, ["bodytext"])
    .toObject();
  assert.equal(Object.hasOwn(base, "periodGeometry"), false);
  assert.equal(Object.hasOwn(base.sealed, "chainKeys"), false);

  const request = build(data).toObject();
  assert.deepEqual(request.sealed.chainKeys, [
    { accessGroup: "premium", cutoff: "251023T2345", key: "Aw" },
    { accessGroup: "vault", cutoff: "251023T1755", key: "BA" },
    { accessGroup: "vault", cutoff: "251023T2355", key: "BQ" },
  ]);
  assert.equal(JSON.stringify(request).includes("CQ"), false);
  assert.equal(JSON.stringify(request).includes("Bg"), false);
  assert.deepEqual(request.periodGeometry, {
    chainsPerDay: 2,
    periodMinutes: 15,
  });
  assert.deepEqual(request.sealed.periodKeys, [
    { accessGroup: "premium", period: "251023T1400", key: "Ag" },
  ]);
  assert.deepEqual(request.requestedPeriodKeys, [
    { accessGroup: "premium", periods: ["251023T1400"] },
    { accessGroup: "vault", periods: ["251023T1400"] },
  ]);
});

test("article-coordinate hints union actual wraps across only unresolved items", () => {
  const request = build(pageData(), ISSUER_A, ["second", "bodytext"]).toObject();
  assert.deepEqual(request.requestedPeriodKeys, [
    { accessGroup: "premium", periods: ["251023T1400", "251023T1415"] },
    { accessGroup: "vault", periods: ["251023T1400"] },
  ]);
  assert.equal(hintsFor(request.requestedPeriodKeys, "unused"), undefined);
});

test("the wrapper relays period keys only when its base selector is explicitly true", () => {
  const page = new DcaData(pageData());
  for (const [config, relaysPeriodKeys] of [
    [{}, false],
    [{ relayPeriodKeys: false }, false],
    [{ relayPeriodKeys: true }, true],
  ]) {
    const request = new ChainKeyRequestBuilder(config)
      .build(page, ISSUER_A, ["bodytext"])
      .toObject();
    assert.equal(
      Object.hasOwn(request.sealed, "periodKeys"),
      relaysPeriodKeys,
      JSON.stringify(config),
    );
  }
});

test("one supplied member relays and empty selection remains an ordinary request", () => {
  const one = pageData();
  const item = contentRecordOf(one, "bodytext");
  item.keys = item.keys.filter((/** @type {any} */ wrap) => wrap.accessGroup !== "vault");
  assert.deepEqual(build(one).toObject().sealed.chainKeys, [
    { accessGroup: "premium", cutoff: "251023T2345", key: "Aw" },
  ]);

  const empty = build(pageData(), ISSUER_A, []).toObject();
  assert.equal(Object.hasOwn(empty, "periodGeometry"), false);
  assert.equal(Object.hasOwn(empty.sealed, "chainKeys"), false);
});

test("relay omits chain supply under malformed or missing root geometry", () => {
  const data = pageData();
  data.periodGeometry = /** @type {any} */ ({ chainsPerDay: 2 });
  const request = build(data).toObject();
  assert.equal(Object.hasOwn(request, "periodGeometry"), false);
  assert.equal(Object.hasOwn(request.sealed, "chainKeys"), false);

  delete data.periodGeometry;
  const missing = build(data).toObject();
  assert.equal(Object.hasOwn(missing, "periodGeometry"), false);
  assert.equal(Object.hasOwn(missing.sealed, "chainKeys"), false);
});

test("relay neither repairs nor forwards an invalid full geometry map", () => {
  // The rejected map supplies no geometry to any family of this delivery, so
  // projecting away its bad name would repair it, and forwarding it would
  // make a selecting issuer refuse the base sections too.
  const data = pageData();
  data.periodGeometry.accessGroups = JSON.parse(
    '{"vault":{"chainsPerDay":4,"periodMinutes":5},"2invalid":{"chainsPerDay":1,"periodMinutes":30}}',
  );

  const request = build(data).toObject();
  const base = new DcaRequestBuilder({ relayPeriodKeys: true })
    .build(new DcaData(data), ISSUER_A, ["bodytext"])
    .toObject();

  assert.equal(Object.hasOwn(request, "periodGeometry"), false);
  assert.equal(Object.hasOwn(request.sealed, "chainKeys"), false);
  assert.equal(Object.hasOwn(request, "requestedPeriodKeys"), false);
  assert.deepEqual(request, base);
  assert.deepEqual(request.sealed.periodKeys, [
    { accessGroup: "premium", period: "251023T1400", key: "Ag" },
  ]);
});

test("relay preserves noncanonical chain values and filters invalid wrap labels before hints", () => {
  const data = pageData();
  const sealed = issuerBlockOf(data, ISSUER_A).sealed;
  sealed.chainKeys = [
    { accessGroup: "premium", cutoff: "251023T2345", key: "Aw" },
    { accessGroup: "premium", cutoff: "251023T2330", key: "not-base64!" },
    ...sealed.chainKeys.filter((/** @type {any} */ record) => record.accessGroup !== "premium"),
  ];
  contentRecordOf(data, "bodytext").keys.push(
    { accessGroup: "premium", period: "251023T14", nonce: "n", key: "k" },
    { accessGroup: "premium", period: "251302T1415", nonce: "n", key: "k" },
  );

  const request = build(data).toObject();

  assert.deepEqual(
    request.sealed.chainKeys.filter(
      (/** @type {any} */ record) => record.accessGroup === "premium",
    ),
    [
      { accessGroup: "premium", cutoff: "251023T2345", key: "Aw" },
      { accessGroup: "premium", cutoff: "251023T2330", key: "not-base64!" },
    ],
  );
  assert.deepEqual(hintsFor(request.requestedPeriodKeys, "premium"), ["251023T1400"]);
});

test("off-grid wrap hints cannot poison base siblings or an on-grid family hint", () => {
  const data = pageData();
  contentRecordOf(data, "bodytext").keys.push(
    { accessGroup: "premium", period: "251023T1401", nonce: "n", key: "k" },
    { accessGroup: "vault", period: "251023T1401", nonce: "n", key: "k" },
  );
  const request = build(data, ISSUER_A, ["bodytext", "second"]).toObject();

  assert.deepEqual(request.sealed.contentKeys, [{ contentName: "bodytext", key: "AQ" }]);
  assert.deepEqual(request.sealed.periodKeys, [
    { accessGroup: "premium", period: "251023T1400", key: "Ag" },
  ]);
  assert.deepEqual(request.requestedPeriodKeys, [
    { accessGroup: "premium", periods: ["251023T1400", "251023T1415"] },
    { accessGroup: "vault", periods: ["251023T1400"] },
  ]);
  assert.deepEqual(chainKeyRequestInput(new DcaRequest(request)).requestedPeriodKeys, {
    premium: ["251023T1400", "251023T1415"],
    vault: ["251023T1400"],
  });

  // A directly authored invalid hint still refuses issuer extension admission.
  // Filtering a relay hint is not permission to relax issuer admission.
  request.requestedPeriodKeys
    .find((/** @type {any} */ record) => record.accessGroup === "premium")
    .periods.push("251023T1401");
  assert.throws(
    () => chainKeyRequestInput(new DcaRequest(request)),
    (/** @type {any} */ error) => error.code === "binding_failed",
  );
});

test("the request snapshots selected chain records and geometry without mutating the page", () => {
  const data = pageData();
  const request = build(data).toObject();
  const premiumCutoff = { accessGroup: "premium", cutoff: "251023T2345" };
  setKeyAt(request.sealed.chainKeys, premiumCutoff, "changed");
  request.periodGeometry.periodMinutes = 99;
  assert.equal(keyAt(issuerBlockOf(data, ISSUER_A).sealed.chainKeys, premiumCutoff), "Aw");
  assert.equal(data.periodGeometry.periodMinutes, 15);
});

test("an inherited-word access group survives chain record selection", () => {
  // `constructor` is a name the grammar admits and every object also answers
  // to. A record carries it as a value, but a relay that indexes records by
  // accessGroup in a plain object would read the prototype's member instead
  // of an own family of that name.
  const data = pageData();
  contentRecordOf(data, "bodytext").keys = [
    { accessGroup: "constructor", period: "251023T1400", nonce: "n", key: "k" },
  ];
  issuerBlockOf(data, ISSUER_A).sealed.chainKeys = [
    { accessGroup: "constructor", cutoff: "251023T2345", key: "Y2hhaW4" },
  ];

  const request = build(data).toObject();
  assert.deepEqual(request.sealed.chainKeys, [
    { accessGroup: "constructor", cutoff: "251023T2345", key: "Y2hhaW4" },
  ]);
  assert.deepEqual(hintsFor(request.requestedPeriodKeys, "constructor"), ["251023T1400"]);
  assert.deepEqual(request.periodGeometry, { chainsPerDay: 2, periodMinutes: 15 });
});

test("PageLoad can select relay without a chain profile, derivation cache, or resolver change", async () => {
  const sent = [];
  const browser = new Browser({
    clock: new Clock("2025-10-23T14:20:00Z"),
    network: {
      post: async (_url, request) => {
        sent.push(request);
        return { status: 403, body: {} };
      },
    },
    issuers: [{ issuerName: ISSUER_A, unlockUrl: "https://a.example/unlock" }],
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
  });
  const data = pageData();
  const load = browser.load(
    rootFromPage({
      publisherOrigin: "https://news.example",
      asJson: () => ({ ...data, sealedContent: [] }),
    }),
  );

  assert.equal((await load.unlock({ issuerName: ISSUER_A })).ok, false);
  assert.equal(sent.length, 1);
  assert.ok(sent[0].periodGeometry);
  assert.ok(
    sent[0].sealed.chainKeys.some((/** @type {any} */ record) => record.accessGroup === "premium"),
  );
});

test("relay refuses invalid or conflicting composition and its issuer view keeps the parsed object", () => {
  for (const config of [
    { innerBuilder: {} },
    { innerBuilder: new DcaRequestBuilder(), clientPublicKey: {} },
  ]) {
    assert.throws(
      () => new ChainKeyRequestBuilder(/** @type {any} */ (config)),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  }

  const conflicting = {
    build: () => DcaRequest.fromParts({ version: "1", issuerName: ISSUER_A }),
  };
  const first = build(
    pageData(),
    ISSUER_A,
    ["bodytext"],
    new ChainKeyRequestBuilder({ innerBuilder: conflicting }),
  );
  const parsed = new DcaRequest(first.toObject());
  assert.equal(chainKeyRequestView(parsed).toObject(), parsed.toObject());

  const alreadyContributed = { build: () => first };
  assert.throws(
    () =>
      build(
        pageData(),
        ISSUER_A,
        ["bodytext"],
        new ChainKeyRequestBuilder({ innerBuilder: alreadyContributed }),
      ),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
});

test("a relay issuer admits chain-only supply although it encodes no chain response", () => {
  const accessPolicy = { decide: () => ({ contentNames: [], periodGrants: [] }) };
  const relay = referenceChainKeyProfile.explicitIssuerEngineFor({
    operatingIssuerNames: ["paywall"],
    accessPolicy,
    clock: new Clock("2025-10-23T14:20:00Z"),
  });

  // Selection and response encoding are separate deployment statements: this
  // issuer projects the supplied families to period keys and sends back no
  // chain section at all.
  assert.deepEqual(relay.capabilityEncoders, {});
  assert.deepEqual([...relay.selectedExtensions], ["chain-keys"]);

  const processor = new IssuerProcessor(relay, {
    capabilityEncoders: relay.capabilityEncoders,
    selectedExtensions: relay.selectedExtensions,
  });
  const chainOnly = JSON.stringify({
    version: "1",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: {
      contentKeys: [],
      chainKeys: [{ accessGroup: "premium", cutoff: "251023T1400", key: "AAAA" }],
    },
    periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  assert.equal(processor.admit(chainOnly).kind, "admitted");

  // The same supply to an issuer that selected nothing leaves no coordinate.
  assert.deepEqual(new IssuerProcessor(relay).admit(chainOnly), {
    kind: "failure",
    code: "binding_failed",
  });
});

test("relay emits a deterministic selector subset within family and request bounds", () => {
  const data = pageData();
  data.periodGeometry = { chainsPerDay: 5, periodMinutes: 1 };
  const labels = Array.from({ length: 300 }, (_, index) => {
    const date = new Date(Date.UTC(2025, 9, 1) + index * 60_000);
    return `${date.toISOString().slice(2, 10).replaceAll("-", "")}T${date.toISOString().slice(11, 16).replace(":", "")}`;
  });
  contentRecordOf(data, "bodytext").keys = ["vault", "premium", "unused"].flatMap((accessGroup) =>
    [...labels].reverse().map((period) => ({ accessGroup, period, nonce: "n", key: "k" })),
  );
  const requested = build(data).toObject().requestedPeriodKeys;
  assert.deepEqual(hintsFor(requested, "premium"), labels.slice(0, 288));
  assert.deepEqual(hintsFor(requested, "unused"), labels.slice(0, 224));
  assert.equal(hintsFor(requested, "vault"), undefined);
  assert.deepEqual(
    normalizeRequestedPeriodKeys(requested, () => ({
      kind: "valid",
      geometry: settleChainGeometry(data.periodGeometry),
    })),
    { premium: labels.slice(0, 288), unused: labels.slice(0, 224) },
  );
  assert.equal(
    requested.reduce(
      (/** @type {number} */ n, /** @type {any} */ record) => n + record.periods.length,
      0,
    ),
    512,
  );
});

test("an unknown sealed member supplies no known request coordinates", () => {
  const futureKeys = { premium: { "251023T1400": "AAAA" } };
  const request = new DcaRequest({ sealed: { futureKeys } });
  assert.equal(request.sealedContentKeys, undefined);
  assert.equal(request.sealedPeriodKeys, undefined);
  assert.equal(request.sealedChainKeys, undefined);
  assert.deepEqual(request.toObject().sealed.futureKeys, futureKeys);
});

test("unknown-only sealed supply cannot admit a request to a selecting chain issuer", () => {
  const engine = referenceChainKeyProfile.explicitIssuerEngineFor({
    operatingIssuerNames: ["paywall"],
    accessPolicy: {
      decide: () => {
        throw new Error("must not reach policy");
      },
    },
    clock: new Clock("2025-10-23T14:20:00Z"),
  });
  const processor = new IssuerProcessor(engine, { selectedExtensions: engine.selectedExtensions });
  assert.deepEqual(
    processor.admit(
      JSON.stringify({
        version: "1",
        issuerName: "paywall",
        keyId: "2025-10",
        sealed: { contentKeys: [], futureKeys: { premium: { "251023T1400": "AAAA" } } },
      }),
    ),
    { kind: "failure", code: "binding_failed" },
  );
});

test("chain relay preserves the selected builder's request-family and projection ports", () => {
  const data = pageData();
  delete issuerBlockOf(data, ISSUER_A).sealed.chainKeys;
  const projection = {
    members: ["innerCoordinates"],
    sealedMembers: [],
    identities: () => ["inner-route"],
    project: () => ({ members: { innerCoordinates: ["inner-route"] } }),
    useful: () => true,
  };
  const inner = {
    marker: true,
    routeProjection: projection,
    build: (
      /** @type {DcaData} */ page,
      /** @type {string} */ issuerName,
      /** @type {string[]} */ needed,
    ) => new DcaRequestBuilder().build(page, issuerName, needed),
    keyFamilies(/** @type {any} */ request) {
      assert.equal(this.marker, true);
      assert.equal(request.issuerName, ISSUER_A);
      return { contentKeys: true, familyKeys: false };
    },
  };
  const builder = new ChainKeyRequestBuilder({ innerBuilder: inner });
  const request = build(data, ISSUER_A, ["bodytext"], builder).toObject();
  assert.ok(builder.keyFamilies);
  assert.deepEqual(builder.keyFamilies(request), { contentKeys: true, familyKeys: false });
  assert.equal(builder.routeProjection, projection);
});

test("chain relay preserves rivals while omitting unknown delivery members", () => {
  const data = pageData();
  const block = data.issuerData[0];
  const original = block.sealed.chainKeys[0];
  block.sealed.chainKeys = [
    { ...original, publisherOnly: "do-not-relay" },
    { ...original, key: "CQ", publisherOnly: "also-private" },
  ];
  const request = build(data);
  assert.deepEqual(request.sealed.chainKeys, [original, { ...original, key: "CQ" }]);
});
