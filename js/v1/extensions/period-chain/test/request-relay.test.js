// @ts-check
//
// The period-chain request relay carries supplied capability over the wire and
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
import { PeriodChainRequestBuilder } from "../core-client/PeriodChainRequestBuilder.js";
import { periodChainRequestView } from "../core-shared--client-issuer/PeriodChainRequest.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { referencePeriodChainProfile } from "../referenceProfile.js";

const ISSUER_A = "issuer-a";
const ISSUER_B = "issuer-b";

function pageData() {
  return {
    version: "1",
    resourceJWT: `e30.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "relay-render" })))}.signature`,
    periodChain: {
      chainsPerDay: 2,
      periodMinutes: 15,
      accessGroups: {
        vault: { chainsPerDay: 4, periodMinutes: 5 },
        unused: { chainsPerDay: 1, periodMinutes: 30 },
      },
    },
    contentData: {
      bodytext: {
        contentType: "text/html",
        nonce: "n",
        aad: "a",
        keys: {
          premium: [{ t: "251023T1400", nonce: "pn", key: "pk" }],
          vault: [{ t: "251023T1400", nonce: "vn", key: "vk", bind: "dca-seal-omission-bind-v1" }],
        },
      },
      other: {
        contentType: "text/html",
        nonce: "n2",
        aad: "a2",
        keys: { unused: [{ t: "251023T1400", nonce: "un", key: "uk" }] },
      },
    },
    issuerData: {
      [ISSUER_A]: {
        keyId: "a-key",
        unlockUrl: "https://a.example/unlock",
        sealed: {
          contentKeys: { bodytext: "a-content" },
          periodKeys: { premium: { "251023T1400": "a-exact" } },
          periodChainKeys: {
            premium: { "251023T2345": "a-premium-now" },
            vault: { "251023T1755": "a-vault-now", "251023T2355": "a-vault-next" },
            unused: { "251023T2345": "a-unused" },
          },
        },
      },
      [ISSUER_B]: {
        keyId: "b-key",
        unlockUrl: "https://b.example/unlock",
        sealed: {
          contentKeys: { bodytext: "b-content" },
          periodChainKeys: { premium: { "251023T2345": "b-premium" } },
        },
      },
    },
  };
}

function build(
  data,
  issuerName = ISSUER_A,
  needed = ["bodytext"],
  builder = new PeriodChainRequestBuilder({ relayExactPeriod: true }),
) {
  return builder.build(new DcaData(data), issuerName, needed);
}

test("base emits neither period-chain member while relay copies only selected issuer families", () => {
  const data = pageData();
  const page = new DcaData(data);
  const base = new DcaRequestBuilder({ relayExactPeriod: true })
    .build(page, ISSUER_A, ["bodytext"])
    .toObject();
  assert.equal(Object.hasOwn(base, "periodChain"), false);
  assert.equal(Object.hasOwn(base.sealed, "periodChainKeys"), false);

  const request = build(data).toObject();
  assert.deepEqual(request.sealed.periodChainKeys, {
    premium: { "251023T2345": "a-premium-now" },
    vault: { "251023T1755": "a-vault-now", "251023T2355": "a-vault-next" },
  });
  assert.equal(JSON.stringify(request).includes("b-premium"), false);
  assert.equal(JSON.stringify(request).includes("a-unused"), false);
  assert.deepEqual(request.periodChain, {
    chainsPerDay: 2,
    periodMinutes: 15,
    accessGroups: { vault: { chainsPerDay: 4, periodMinutes: 5 } },
  });
  assert.deepEqual(request.sealed.periodKeys, { premium: { "251023T1400": "a-exact" } });
});

test("the wrapper relays exact material only when its base selector is explicitly true", () => {
  const page = new DcaData(pageData());
  for (const [config, relaysExact] of [
    [{}, false],
    [{ relayExactPeriod: false }, false],
    [{ relayExactPeriod: true }, true],
  ]) {
    const request = new PeriodChainRequestBuilder(config)
      .build(page, ISSUER_A, ["bodytext"])
      .toObject();
    assert.equal(Object.hasOwn(request.sealed, "periodKeys"), relaysExact, JSON.stringify(config));
  }
});

test("one supplied member relays and empty selection remains an ordinary request", () => {
  const one = pageData();
  delete one.contentData.bodytext.keys.vault;
  assert.deepEqual(build(one).toObject().sealed.periodChainKeys, {
    premium: { "251023T2345": "a-premium-now" },
  });

  const empty = build(pageData(), ISSUER_A, []).toObject();
  assert.equal(Object.hasOwn(empty, "periodChain"), false);
  assert.equal(Object.hasOwn(empty.sealed, "periodChainKeys"), false);
});

test("relay retains malformed applicable geometry instead of falling back or inferring", () => {
  const data = pageData();
  data.periodChain.accessGroups.vault = /** @type {any} */ ({ chainsPerDay: 4 });
  const request = build(data).toObject();
  assert.deepEqual(request.periodChain.accessGroups.vault, { chainsPerDay: 4 });
  assert.equal(Object.hasOwn(request.periodChain.accessGroups.vault, "periodMinutes"), false);

  delete data.periodChain;
  const missing = build(data).toObject();
  assert.equal(Object.hasOwn(missing, "periodChain"), false);
  assert.ok(
    missing.sealed.periodChainKeys,
    "missing context is forwarded as invalid input, never inferred",
  );
});

test("the request snapshots selected chain maps and geometry without mutating the page", () => {
  const data = pageData();
  const request = build(data).toObject();
  request.sealed.periodChainKeys.premium["251023T2345"] = "changed";
  request.periodChain.accessGroups.vault.periodMinutes = 99;
  assert.equal(
    data.issuerData[ISSUER_A].sealed.periodChainKeys.premium["251023T2345"],
    "a-premium-now",
  );
  assert.equal(data.periodChain.accessGroups.vault.periodMinutes, 5);
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
  data.issuerData[ISSUER_A].sealed.periodChainKeys = JSON.parse(
    '{"constructor":{"251023T2345":"chain"}}',
  );
  data.periodChain.accessGroups = JSON.parse(
    '{"constructor":{"chainsPerDay":2,"periodMinutes":15}}',
  );

  const request = build(data).toObject();
  assert.equal(Object.hasOwn(request.sealed.periodChainKeys, "constructor"), true);
  assert.deepEqual(request.sealed.periodChainKeys.constructor, { "251023T2345": "chain" });
  assert.equal(Object.hasOwn(request.periodChain.accessGroups, "constructor"), true);
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
    requestBuilderFactory: (options) => new PeriodChainRequestBuilder(options),
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
  assert.ok(sent[0].periodChain);
  assert.ok(sent[0].sealed.periodChainKeys.premium);
});

test("relay refuses invalid or conflicting composition and its issuer view keeps the parsed object", () => {
  for (const config of [
    { innerBuilder: {} },
    { innerBuilder: new DcaRequestBuilder(), clientPublicKey: {} },
  ]) {
    assert.throws(
      () => new PeriodChainRequestBuilder(/** @type {any} */ (config)),
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
    new PeriodChainRequestBuilder({ innerBuilder: conflicting }),
  );
  const parsed = new DcaRequest(first.toObject());
  assert.equal(periodChainRequestView(parsed).toObject(), parsed.toObject());

  const alreadyContributed = { build: () => first };
  assert.throws(
    () =>
      build(
        pageData(),
        ISSUER_A,
        ["bodytext"],
        new PeriodChainRequestBuilder({ innerBuilder: alreadyContributed }),
      ),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
});

test("a relay issuer admits chain-only supply although it encodes no chain response", () => {
  const accessPolicy = { decide: () => ({ contentNames: [], periodGrants: [] }) };
  const relay = referencePeriodChainProfile.explicitIssuerEngineFor({
    accessPolicy,
    clock: new Clock("2025-10-23T14:20:00Z"),
  });

  // Selection and response encoding are separate deployment statements: this
  // issuer projects the supplied families to exact leaves and sends back no
  // chain section at all.
  assert.deepEqual(relay.capabilityEncoders, {});
  assert.deepEqual([...relay.selectedExtensions], ["period-chain"]);

  const processor = new IssuerProcessor(relay, {
    capabilityEncoders: relay.capabilityEncoders,
    selectedExtensions: relay.selectedExtensions,
  });
  const chainOnly = JSON.stringify({
    version: "1",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: { contentKeys: {}, periodChainKeys: { premium: { "251023T1400": "AAAA" } } },
    periodChain: { chainsPerDay: 2, periodMinutes: 15 },
  });
  assert.equal(processor.admit(chainOnly).kind, "admitted");

  // The same supply to an issuer that selected nothing leaves no coordinate.
  assert.deepEqual(new IssuerProcessor(relay).admit(chainOnly), {
    kind: "failure",
    code: "binding_failed",
  });
});
