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

const ISSUER_A = "issuer-a";
const ISSUER_B = "issuer-b";

function pageData() {
  return {
    version: "1",
    resourceJWT: `e30.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "relay-render" })))}.c2lnbmF0dXJl`,
    periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
    contentData: {
      bodytext: {
        contentType: "text/html",
        nonce: "n",
        keys: {
          premium: [{ t: "251023T1400", nonce: "pn", key: "pk" }],
          vault: [{ t: "251023T1400", nonce: "vn", key: "vk", bind: "dca-bind-seal-omission" }],
        },
      },
      other: {
        contentType: "text/html",
        nonce: "n2",
        keys: { unused: [{ t: "251023T1400", nonce: "un", key: "uk" }] },
      },
      second: {
        contentType: "text/html",
        nonce: "n3",
        keys: {
          premium: [
            { t: "251023T1415", nonce: "p2n", key: "p2k" },
            { t: "251023T1400", nonce: "p3n", key: "p3k" },
          ],
        },
      },
    },
    issuerData: {
      [ISSUER_A]: {
        keyId: "a-key",
        unlockUrl: "https://a.example/unlock",
        sealed: {
          contentKeys: { bodytext: "AQ" },
          periodKeys: { premium: { "251023T1400": "Ag" } },
          chainKeys: {
            premium: { "251023T2345": "Aw" },
            vault: { "251023T1755": "BA", "251023T2355": "BQ" },
            unused: { "251023T2345": "Bg" },
          },
        },
      },
      [ISSUER_B]: {
        keyId: "b-key",
        unlockUrl: "https://b.example/unlock",
        sealed: {
          contentKeys: { bodytext: "CA" },
          chainKeys: { premium: { "251023T2345": "CQ" } },
        },
      },
    },
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
  dcaData.issuerData[ISSUER_NAME].sealed.chainKeys = {
    premium: { "251023T2345": "Aw" },
  };
  const chain = new ChainKeyRequestBuilder({ relayPeriodKeys: true })
    .build(new DcaData(dcaData), ISSUER_NAME, [BODYTEXT.name])
    .toObject();
  assert.equal(requestEntryCounts(chain.sealed).entries, 4);
  assert.equal(requestEntryCounts(chain.sealed).groups.get("premium"), 3);
  assert.deepEqual(chain.sealed.chainKeys, dcaData.issuerData[ISSUER_NAME].sealed.chainKeys);

  // requestedPeriodKeys is client-added metadata outside the publication.
  const { requestedPeriodKeys, ...withoutHints } = chain;
  assert.ok(requestedPeriodKeys.premium.length > 0);
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
  assert.deepEqual(request.sealed.chainKeys, {
    premium: { "251023T2345": "Aw" },
    vault: { "251023T1755": "BA", "251023T2355": "BQ" },
  });
  assert.equal(JSON.stringify(request).includes("CQ"), false);
  assert.equal(JSON.stringify(request).includes("Bg"), false);
  assert.deepEqual(request.periodGeometry, {
    chainsPerDay: 2,
    periodMinutes: 15,
  });
  assert.deepEqual(request.sealed.periodKeys, { premium: { "251023T1400": "Ag" } });
  assert.deepEqual(request.requestedPeriodKeys, {
    premium: ["251023T1400"],
    vault: ["251023T1400"],
  });
});

test("article-coordinate hints union actual wraps across only unresolved items", () => {
  const request = build(pageData(), ISSUER_A, ["second", "bodytext"]).toObject();
  assert.deepEqual(request.requestedPeriodKeys, {
    premium: ["251023T1400", "251023T1415"],
    vault: ["251023T1400"],
  });
  assert.equal(Object.hasOwn(request.requestedPeriodKeys, "unused"), false);
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
  delete one.contentData.bodytext.keys.vault;
  assert.deepEqual(build(one).toObject().sealed.chainKeys, {
    premium: { "251023T2345": "Aw" },
  });

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
  assert.deepEqual(request.sealed.periodKeys, { premium: { "251023T1400": "Ag" } });
});

test("relay preserves noncanonical chain values and filters invalid wrap labels before hints", () => {
  const data = pageData();
  data.issuerData[ISSUER_A].sealed.chainKeys.premium = {
    "251023T2345": "Aw",
    "251023T2330": "not-base64!",
  };
  data.contentData.bodytext.keys.premium.push(
    { t: "251023T14", nonce: "n", key: "k" },
    { t: "251302T1415", nonce: "n", key: "k" },
  );

  const request = build(data).toObject();

  assert.deepEqual(request.sealed.chainKeys.premium, {
    "251023T2345": "Aw",
    "251023T2330": "not-base64!",
  });
  assert.deepEqual(request.requestedPeriodKeys.premium, ["251023T1400"]);
});

test("off-grid wrap hints cannot poison base siblings or an on-grid family hint", () => {
  const data = pageData();
  data.contentData.bodytext.keys.premium.push({ t: "251023T1401", nonce: "n", key: "k" });
  data.contentData.bodytext.keys.vault.push({ t: "251023T1401", nonce: "n", key: "k" });
  const request = build(data, ISSUER_A, ["bodytext", "second"]).toObject();

  assert.deepEqual(request.sealed.contentKeys, { bodytext: "AQ" });
  assert.deepEqual(request.sealed.periodKeys, { premium: { "251023T1400": "Ag" } });
  assert.deepEqual(request.requestedPeriodKeys, {
    premium: ["251023T1400", "251023T1415"],
    vault: ["251023T1400"],
  });
  assert.deepEqual(
    chainKeyRequestInput(new DcaRequest(request)).requestedPeriodKeys,
    request.requestedPeriodKeys,
  );

  // A directly authored invalid hint still refuses issuer extension admission.
  // Filtering a relay hint is not permission to relax issuer admission.
  request.requestedPeriodKeys.premium.push("251023T1401");
  assert.throws(
    () => chainKeyRequestInput(new DcaRequest(request)),
    (/** @type {any} */ error) => error.code === "binding_failed",
  );
});

test("the request snapshots selected chain maps and geometry without mutating the page", () => {
  const data = pageData();
  const request = build(data).toObject();
  request.sealed.chainKeys.premium["251023T2345"] = "changed";
  request.periodGeometry.periodMinutes = 99;
  assert.equal(data.issuerData[ISSUER_A].sealed.chainKeys.premium["251023T2345"], "Aw");
  assert.equal(data.periodGeometry.periodMinutes, 15);
});

test("an own inherited-word family survives the selected extension map", () => {
  // `constructor` is a name the grammar admits and every object also answers
  // to, so a plain `map[name]` read cannot tell an own member of that name
  // apart from the prototype's. The identifier rule rejects a map keyed by a
  // name outside the grammar, so an accessGroup map can still carry this
  // hazard and no other.
  const data = pageData();
  data.contentData.bodytext.keys = JSON.parse(
    '{"constructor":[{"t":"251023T1400","nonce":"n","key":"k"}]}',
  );
  data.issuerData[ISSUER_A].sealed.chainKeys = JSON.parse(
    '{"constructor":{"251023T2345":"Y2hhaW4"}}',
  );

  const request = build(data).toObject();
  assert.equal(Object.hasOwn(request.sealed.chainKeys, "constructor"), true);
  assert.deepEqual(request.sealed.chainKeys.constructor, { "251023T2345": "Y2hhaW4" });
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
      asJson: () => ({ ...data, sealedContent: {} }),
    }),
  );

  assert.equal((await load.unlock({ issuerName: ISSUER_A })).ok, false);
  assert.equal(sent.length, 1);
  assert.ok(sent[0].periodGeometry);
  assert.ok(sent[0].sealed.chainKeys.premium);
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
    sealed: { contentKeys: {}, chainKeys: { premium: { "251023T1400": "AAAA" } } },
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
  for (const group of ["vault", "premium", "unused"]) {
    data.contentData.bodytext.keys[group] = [...labels]
      .reverse()
      .map((t) => ({ t, nonce: "n", key: "k" }));
  }
  const requested = build(data).toObject().requestedPeriodKeys;
  assert.deepEqual(requested.premium, labels.slice(0, 288));
  assert.deepEqual(requested.unused, labels.slice(0, 224));
  assert.equal(requested.vault, undefined);
  assert.deepEqual(
    normalizeRequestedPeriodKeys(requested, () => ({
      kind: "valid",
      geometry: settleChainGeometry(data.periodGeometry),
    })),
    requested,
  );
  assert.equal(
    Object.values(requested).reduce((n, entries) => n + entries.length, 0),
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
        sealed: { contentKeys: {}, futureKeys: { premium: { "251023T1400": "AAAA" } } },
      }),
    ),
    { kind: "failure", code: "binding_failed" },
  );
});

test("chain relay preserves the selected builder's request-family and projection ports", () => {
  const data = pageData();
  delete data.issuerData[ISSUER_A].sealed.chainKeys;
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
