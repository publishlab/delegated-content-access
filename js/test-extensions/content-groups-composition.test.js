// @ts-check
//
// The selected content-groups composition end to end, across the extensions it
// needs: the stock chain-key derivation and chain-key cache from chain-keys,
// and the ECDH-P256 and RSA-OAEP methods from client-bound-transport. A real
// `createPublisher` page is serialized as JSON or as the HTML carrier, the
// composed delivery client reads it back, sends its request to a real
// `createIssuerCore` endpoint (through `KeyDelivery` under client-bound
// transport) and opens authenticated plaintext through its plain `open()`.
// Denials are shown with real decryption attempts: the test derives the best
// key a reader holds for the denied item and the AEAD refuses it.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { composeClient } from "../integration-client/composeClient.js";
import { ResponseAssociation } from "../core-client/ResponseAssociation.js";
import { ContentGroupRequestBuilder } from "../extensions/content-groups/core-client/ContentGroupRequestBuilder.js";
import { OmissionRequestBuilder } from "../extensions/content-key-seal-omission/core-client/OmissionRequestBuilder.js";

import { contentGroupsProfile } from "../extensions/content-groups/referenceProfile.js";
import {
  chainKeyPartition,
  itemPad,
  xor16,
} from "../extensions/content-groups/core-shared/construction.js";
import { createPublisher } from "../integration-publisher/createPublisher.js";
import { composePublisherConfig } from "../core-publisher/publisherComposition.js";
import { Sealer } from "../core-publisher/Sealer.js";
import { CompressingSealer } from "../extensions/content-compression/core-publisher/CompressingSealer.js";
import { createIssuerCore } from "../integration-issuer/createIssuerCore.js";
import { createBrowserIssuer } from "../integration-issuer/createBrowserIssuer.js";
import { createDeliveryClient } from "../integration-client/createDeliveryClient.js";
import { KeyDelivery } from "../adapter-issuer/KeyDelivery.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { JsonDeliveryReader } from "../adapter-client/JsonDeliveryReader.js";
import { MarkupDeliveryReader } from "../adapter-client/MarkupDeliveryReader.js";
import { writeJsonDelivery } from "../adapter-publisher/writeJsonDelivery.js";
import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";
import { DcaData } from "../core-client/DcaData.js";
import { openContent } from "../core-client/openContent.js";
import { attemptContentKeyWrap } from "../core-client/contentKeyWrapAttempt.js";
import { encrypt } from "../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Decode } from "../core-shared/codec.js";
import { Storage } from "../demo/actors/Storage.js";
import { domOver } from "../test-lib/helpers/domOver.js";
import { Client } from "../test-lib/harnesses/client.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { explicitChainKeyClientProfile } from "../extensions/chain-keys/referenceProfile.js";
import { requireChainRepresentation } from "../extensions/chain-keys/core-issuer/chainKeyIssuerEngine.js";
import { chainKeyCapabilitySource } from "../extensions/chain-keys/core-issuer/chainKeyCapabilitySource.js";
import { chainKeyCapabilityEncoderFor } from "../extensions/chain-keys/core-issuer/chainKeyCapabilityEncoder.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilyContribution } from "../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import {
  chainKeyCoordinate,
  chainKeyFromChainKey,
  chainKeyLabelAt,
  periodKeyFromChainKey,
  settleChainGeometry,
} from "../extensions/chain-keys/core-shared/chainKeyConstruction.js";
import * as ecdhMethod from "../extensions/client-bound-transport/ecdhP256.js";
import * as rsaMethod from "../extensions/client-bound-transport/rsaOaep.js";
import { clientBoundKeyCapability } from "../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";
import {
  agreeTransport,
  importPeer,
} from "../extensions/client-bound-transport/core-shared--client-issuer/ecdhP256.js";
import { keyKindContext } from "../extensions/client-bound-transport/core-shared--client-issuer/keyKind.js";
import { compactEcdhPublisherContribution } from "../extensions/compact-ecdh/core-publisher/keySealing.js";
import { COMPACT_ECDH } from "../extensions/compact-ecdh/core-shared--publisher-issuer/selector.js";

const subtle = globalThis.crypto.subtle;
const ORIGIN = "https://news.example";
const OTHER_ORIGIN = "https://other.example";
const UNLOCK = "https://issuer.example/unlock";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
const SECRET = Uint8Array.from({ length: 32 }, (_, i) => i);
const W12 = "261014T1200";
const W00 = "261015T0000";
const T14 = "261014T1400";
const T15 = "261014T1500";
const T18 = "261014T1800";
/** The chain cutoff the default policy grants in each window. */
const CUTOFF = Object.freeze({ [W12]: T18, [W00]: "261015T0300" });
/** Render instants: each renders at the period its name gives. */
const AT = Object.freeze({
  T13: "2026-10-14T13:20:00Z",
  T14: "2026-10-14T14:20:00Z",
  T15: "2026-10-14T15:20:00Z",
  T17: "2026-10-14T17:20:00Z",
  T19: "2026-10-14T19:20:00Z",
  T01: "2026-10-15T01:20:00Z",
});
const random = {
  bytes: (/** @type {number} */ n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
};
const CHAIN_KIND = "contentGroupChainKey";
const PERIOD_KIND = "contentGroupPeriodKey";

/** The host's stock chain port: the chain-keys construction, nothing invented. */
const CHAIN = Object.freeze({
  coordinate: chainKeyCoordinate,
  labelAt: chainKeyLabelAt,
  settleGeometry: settleChainGeometry,
  familyGeneration: periodFamilyGeneration,
  fromChain: chainKeyFromChainKey,
  periodFromChain: periodKeyFromChainKey,
});

/** @param {string} code @param {RegExp} [message] */
const coded =
  (code, message) =>
  /** @param {any} error */
  (error) =>
    error?.code === code && (message === undefined || message.test(error.message));

// ---------------------------------------------------------------------------
// Roles

/** Publisher signing and issuer opening keys. Two issuer names may share one opening key. */
async function roleKeys() {
  const signing = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const opening = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  return { signing, opening };
}

const ALL_WINDOWS = Object.freeze({
  bodytext: [W12, W00],
  headline: [W12, W00],
  shoppingAd: [W12, W00],
  sportsNews: [W12, W00],
});

/**
 * One publisher composed with the content-groups contribution.
 *
 * @param {any} keys
 * @param {{ origin?: string, at: string, geometry?: any, issuers?: string[],
 *   issuerSeedWindows?: Record<string, Record<string, string[]>>,
 *   purchaseIssuers?: string[] }} options - `purchaseIssuers` receive purchase's
 *   ordinary envelope; every issuer by default
 */
function publisherFor(
  keys,
  { origin = ORIGIN, at, geometry = GEOMETRY, issuers, issuerSeedWindows, purchaseIssuers },
) {
  const names = issuers ?? ["issuerA"];
  return createPublisher(
    /** @type {any} */ ({
      origin,
      clock: { now: () => new Date(at) },
      random,
      signingKeys: { p1: keys.signing.privateKey },
      issuers: names.map((issuerName) => ({
        issuerName,
        keyId: `${issuerName}-k1`,
        algorithm: "ecdh-p256",
        publicKey: keys.opening.publicKey,
      })),
      issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ page) => ({
        contentKeyNames: (purchaseIssuers ?? names).includes(issuer.issuerName)
          ? page.contentNames.filter((/** @type {string} */ n) => n === "purchase")
          : [],
        suppliedAccessGroups: [],
      }),
    }),
    contentGroupsProfile.publisherContribution({
      retainedSecret: SECRET,
      periodGeometry: geometry,
      issuerSeedWindows:
        issuerSeedWindows ?? Object.fromEntries(names.map((name) => [name, ALL_WINDOWS])),
      chain: CHAIN,
    }),
  );
}

/**
 * The mixed page: bodytext (politics, sports), headline (politics), shoppingAd
 * (sports, opened by its item key), sportsNews (sports) and the ordinary
 * purchase item.
 */
const MIXED_ITEMS = Object.freeze([
  {
    name: "bodytext",
    value: "body text",
    contentType: "text/plain",
    contentGroups: ["politics", "sports"],
  },
  {
    name: "headline",
    value: "<h1>head line</h1>",
    contentType: "text/html",
    contentGroups: ["politics"],
  },
  { name: "shoppingAd", value: "ad", contentType: "text/plain", contentGroups: ["sports"] },
  { name: "sportsNews", value: "score", contentType: "text/plain", contentGroups: ["sports"] },
  { name: "purchase", value: "buy", contentType: "text/plain" },
]);

/** @param {any} publisher @param {string} [resourceId] */
async function render(publisher, resourceId = "story1") {
  return publisher.publish({ resourceId, data: {}, items: structuredClone(MIXED_ITEMS) });
}

/** The period label an ISO instant renders at, on the hourly grid. @param {string} issuedAt */
function renderPeriodOf(issuedAt) {
  const at = new Date(issuedAt);
  at.setUTCMinutes(0, 0, 0);
  return chainKeyLabelAt(at.getTime() / 60_000);
}

/**
 * The default policy: a chain to the render window's cutoff for bodytext/politics, a
 * period key at the render period for headline/politics, and every requested
 * item key. It never grants sportsNews.
 *
 * @param {any} input
 */
function grantAll(input) {
  /** @type {any[]} */
  const grants = [];
  const scopes = /** @type {Record<string, { groups: string[], windows: string[] }>} */ (
    input.contentGroups
  );
  const t = renderPeriodOf(input.claims.issuedAt);
  const window = chainKeyCoordinate(t, GEOMETRY).startT;
  for (const [contentName, { groups, windows }] of Object.entries(scopes)) {
    if (contentName === "bodytext" && groups.includes("politics") && windows.includes(window))
      grants.push({
        kind: "chain",
        contentName,
        group: "politics",
        windowStart: window,
        cutoffT: CUTOFF[/** @type {keyof typeof CUTOFF} */ (window)],
      });
    if (contentName === "headline" && groups.includes("politics"))
      grants.push({ kind: "period", contentName, group: "politics", t });
  }
  for (const contentName of input.items) grants.push({ kind: "item", contentName });
  return grants;
}

/**
 * One issuer core composed with the content-groups contribution, and the
 * HTTP-like host around it: admission, client-bound agreement through
 * `KeyDelivery`, the endpoint and the prepared body. `policy` and the
 * rewrites can change between requests.
 *
 * @param {any} keys
 * @param {{ method?: any, keyDelivery?: (method: any) => object, profile?: any,
 *   issuers?: string[] }} [options]
 */
function issuerFor(keys, options = {}) {
  const { method, issuers = ["issuerA"] } = options;
  const policy = {
    /** @type {(input: any) => any[]} */
    grants: grantAll,
    /** @type {(contentName: string, group: string, t: string, windowStart: string) => boolean} */
    authorize: () => true,
  };
  const calls = {
    posts: 0,
    /** @type {{ status: number, body: any }[]} */
    responses: [],
  };
  const core = createIssuerCore(
    {
      operatingIssuerNames: issuers,
      accessPolicy: {
        decide: (/** @type {any} */ _c, /** @type {any} */ r) => ({ contentNames: r.contentNames }),
      },
    },
    contentGroupsProfile.issuerContribution({
      chain: CHAIN,
      policy: {
        decide: (/** @type {any} */ input) => ({
          grants: policy.grants(input),
          authorizePeriod: (
            /** @type {string} */ contentName,
            /** @type {string} */ group,
            /** @type {string} */ t,
            /** @type {string} */ windowStart,
          ) => policy.authorize(contentName, group, t, windowStart),
        }),
      },
    }),
  );
  const registration = {
    kid: "p1",
    publicKey: keys.signing.publicKey,
    openingKeys: {
      get: (/** @type {string} */ issuerName) =>
        issuers.includes(issuerName)
          ? { algorithm: "ecdh-p256", privateKey: keys.opening.privateKey }
          : undefined,
    },
  };
  const delivery =
    method === undefined
      ? null
      : new KeyDelivery({
          random,
          profile: options.profile ?? method,
          ...(options.keyDelivery?.(method) ??
            contentGroupsProfile.keyDeliveryMembers(settledKinds(method))),
        });
  /** @type {((request: any) => any)|null} */
  let rewriteRequest = null;
  /** @type {((body: any) => any)|null} */
  let rewriteResponse = null;
  /** @type {(() => Promise<void>)|null} */
  let hold = null;
  /** @param {number} status @param {any} body */
  const answer = (status, body) => {
    const wire = JSON.parse(JSON.stringify(body));
    calls.responses.push({ status, body: wire });
    return { status, contentType: "application/json", body: wire };
  };
  const transport = {
    /** @param {string} _url @param {object} sent */
    async post(_url, sent) {
      calls.posts++;
      if (hold) await hold();
      const document = JSON.parse(JSON.stringify(sent));
      const request = rewriteRequest ? rewriteRequest(document) : document;
      const admission = core.processor.admit(new DcaRequest(request));
      if (admission.kind !== "admitted") {
        const { response } = core.endpoint.refusal(admission);
        return answer(response.status, response.body);
      }
      const view =
        delivery === null ? null : await delivery.preflight("client-bound", admission.request);
      const { response } = await core.endpoint.handleRequest({
        request: admission.request,
        registration: /** @type {any} */ (registration),
      });
      let body =
        response.status === 200 && delivery !== null && view !== null
          ? await delivery.prepare(response.body, view)
          : response.body;
      if (response.status === 200 && rewriteResponse) body = rewriteResponse(structuredClone(body));
      return answer(response.status, body);
    },
  };
  return {
    calls,
    policy,
    transport,
    /** @param {((request: any) => any)|null} change */
    rewriteRequests(change) {
      rewriteRequest = change;
    },
    /** @param {((body: any) => any)|null} change */
    rewriteResponses(change) {
      rewriteResponse = change;
    },
    /** @param {(() => Promise<void>)|null} gateOpen */
    holdRequests(gateOpen) {
      hold = gateOpen;
    },
    /** The last answer the host sent. */
    get last() {
      return calls.responses[calls.responses.length - 1];
    },
  };
}

/** One step held open: `arrived` settles when the step waits, `release` lets it go. */
function gate() {
  /** @type {() => void} */
  let release = () => {};
  /** @type {() => void} */
  let reached = () => {};
  const arrived = new Promise((resolve) => {
    reached = () => resolve(undefined);
  });
  const held = new Promise((resolve) => {
    release = () => resolve(undefined);
  });
  return {
    arrived,
    release,
    async wait() {
      reached();
      await held;
    },
  };
}

// ---------------------------------------------------------------------------
// Clients

/** @param {'ecdh'|'rsa'} kind @param {KeyUsage[]} [rsaUsages] */
async function clientKeys(kind, rsaUsages = ["unwrapKey", "decrypt"]) {
  if (kind === "ecdh") {
    const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
      "deriveKey",
    ]);
    const jwk = await subtle.exportKey("jwk", pair.publicKey);
    return {
      privateKey: pair.privateKey,
      publicKey: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    };
  }
  const pair = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["wrapKey", "unwrapKey", "encrypt", "decrypt"],
  );
  const privateKey = await subtle.importKey(
    "jwk",
    await subtle.exportKey("jwk", pair.privateKey),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    rsaUsages,
  );
  const jwk = await subtle.exportKey("jwk", pair.publicKey);
  return { privateKey, publicKey: { kty: "RSA", n: jwk.n, e: jwk.e } };
}

/** @param {any} method */
function settledKinds(method) {
  return method.settleKindDescriptors(contentGroupsProfile.kindDescriptors);
}

/**
 * A reader over the serialized page: the JSON document or the HTML carrier.
 * @param {any} page @param {'json'|'html'} carrier @param {string} [origin]
 */
function readerOf(page, carrier, origin = ORIGIN) {
  if (carrier === "json")
    return new JsonDeliveryReader(writeJsonDelivery(page), { publisherOrigin: origin });
  return new MarkupDeliveryReader(domOver(writeMarkupDelivery(page), { publisherOrigin: origin }));
}

/**
 * The composed delivery client for one serialized page, with the dedicated
 * content-group caches over `storage` and ordinary caches the test can read.
 *
 * @param {any} page
 * @param {{ transport: any, storage?: Storage, carrier?: 'json'|'html', origin?: string,
 *   narrowing?: Record<string, unknown>, limits?: Record<string, number>,
 *   capability?: any, issuerName?: string, directFallback?: boolean,
 *   wrapChainCache?: (cache: ChainKeyCache) => any }} options
 */
function clientFor(page, options) {
  const storage = options.storage ?? new Storage();
  /** @type {{ chain: ChainKeyCache|null, period: PeriodKeyCache|null }} */
  const groupCaches = { chain: null, period: null };
  const bundle = contentGroupsProfile.client({
    chain: CHAIN,
    ...(options.limits === undefined ? {} : { limits: options.limits }),
    narrowing: options.narrowing ?? { requestedContentKeys: { shoppingAd: "sports" } },
    storage,
    createPeriodKeyCache: (config) => (groupCaches.period = new PeriodKeyCache(config)),
    createChainKeyCache: (config) => {
      groupCaches.chain = new ChainKeyCache(config);
      return options.wrapChainCache ? options.wrapChainCache(groupCaches.chain) : groupCaches.chain;
    },
  });
  // The ordinary period-key cache shares the storage backend under its own namespace.
  const ordinary = { period: new PeriodKeyCache({ storage, namespace: "ordinary" }) };
  const client = createDeliveryClient({
    reader: readerOf(page, options.carrier ?? "json", options.origin),
    issuerName: options.issuerName ?? "issuerA",
    unlockUrl: UNLOCK,
    transport: options.transport,
    cache: ordinary.period,
    ...(options.capability === undefined ? {} : { clientBoundKeyCapability: options.capability }),
    // The route accepts a direct answer and the resolver may file it raw.
    ...(options.directFallback
      ? { acceptDirectResponse: true, acceptDirectFallback: true, persistRawPeriodKeys: true }
      : {}),
    ...bundle.composeOptions,
  });
  return { client, bundle, storage, ordinary, groupCaches };
}

/** @param {any} client @param {string} name */
async function text(client, name) {
  return utf8Decode((await client.open(name)).bytes);
}

/** @param {any} method @param {'ecdh'|'rsa'} kind @param {KeyUsage[]} [usages] */
async function capabilityFor(method, kind, usages) {
  return clientBoundKeyCapability(
    await clientKeys(kind, usages),
    method,
    contentGroupsProfile.capabilityOptions(settledKinds(method)),
  );
}

// ---------------------------------------------------------------------------
// Real decryption attempts

/** The serialized item a reader holds. @param {any} page @param {string} name @param {string} [origin] */
function pageItem(page, name, origin = ORIGIN) {
  const reader = readerOf(page, "json", origin);
  const raw = JSON.parse(JSON.stringify(reader.dcaData));
  const data = new DcaData(raw, { publisherOrigin: origin });
  return {
    item: /** @type {any} */ (data.contentItemFor(name)),
    ciphertext: /** @type {string} */ (reader.extract(name)),
    renderId: /** @type {string} */ (data.renderId),
    connectors: /** @type {Record<string, string>} */ (raw.contentData[name].connectors ?? {}),
  };
}

/** The sealed seed envelopes one issuer's page carries. @param {any} page @param {string} [issuerName] */
function pageSeeds(page, issuerName = "issuerA") {
  return readerOf(page, "json").dcaData.issuerData[issuerName].sealed.contentWindowSeeds;
}

/**
 * Try one period key against one item route: pad, XOR the page's connector and
 * open the sealed bytes. A denied item answers `decrypt_failed`.
 *
 * @param {any} page @param {string} name @param {string} group @param {Uint8Array} periodKey
 * @param {string} [origin]
 */
async function tryPeriodKey(page, name, group, periodKey, origin) {
  const { item, ciphertext, renderId, connectors } = pageItem(page, name, origin);
  const pad = await itemPad(periodKey, { renderId, contentName: name });
  const contentKey = xor16(base64urlDecode(connectors[group]), pad);
  return openContent(contentKey, name, ciphertext, item.contentAad);
}

/**
 * The period key a delivered chain key derives at `t`. Past its reach the
 * chain derives nothing, so the attempt uses its own cutoff period instead.
 *
 * @param {Uint8Array} chainKey @param {string} group @param {string} cutoffT @param {string} t
 */
async function periodFromDelivered(chainKey, group, cutoffT, t) {
  const target = chainKeyCoordinate(t, GEOMETRY);
  const cutoff = chainKeyCoordinate(cutoffT, GEOMETRY);
  const reach =
    target.windowStart === cutoff.windowStart && target.position <= cutoff.position ? t : cutoffT;
  const atReach = await chainKeyFromChainKey({
    chainKey,
    accessGroup: group,
    suppliedT: cutoffT,
    targetT: reach,
    geometry: GEOMETRY,
  });
  return periodKeyFromChainKey({
    chainKey: atReach,
    accessGroup: group,
    t: reach,
    geometry: GEOMETRY,
  });
}

/** The first delivered chain key in a recorded direct answer. @param {any} body */
function deliveredChain(body) {
  for (const [contentName, groups] of Object.entries(body?.contentGroups?.chainKeys ?? {}))
    for (const [group, entries] of Object.entries(/** @type {any} */ (groups)))
      for (const [cutoffT, key] of Object.entries(/** @type {any} */ (entries)))
        return { contentName, group, cutoffT, key: base64urlDecode(key) };
  return null;
}

/** The first delivered period key in a recorded direct answer. @param {any} body */
function deliveredPeriod(body) {
  for (const [contentName, groups] of Object.entries(body?.contentGroups?.periodKeys ?? {}))
    for (const [group, entries] of Object.entries(/** @type {any} */ (groups)))
      for (const [t, key] of Object.entries(/** @type {any} */ (entries)))
        return { contentName, group, t, key: base64urlDecode(/** @type {string} */ (key)) };
  return null;
}

/** Every storage key, to show what a step wrote. @param {Storage} storage */
async function storedKeys(storage) {
  return [...(await storage.keys())].sort();
}

// ---------------------------------------------------------------------------
// Evidence 1: serialized publication, existing issuer, composed client, plaintext

describe("publish, unlock and read through the composed roles", () => {
  for (const carrier of /** @type {const} */ (["json", "html"]))
    test(`${carrier}: plain open() reads chain-, period- and item-key items beside an ordinary one`, async () => {
      const keys = await roleKeys();
      const page = await render(publisherFor(keys, { at: AT.T14 }));
      const issuer = issuerFor(keys);
      const { client } = clientFor(page, { transport: issuer.transport, carrier });

      assert.equal(await text(client, "bodytext"), "body text");
      assert.ok(deliveredChain(issuer.last.body), "bodytext opened from a delivered chain key");
      assert.equal(await text(client, "headline"), "<h1>head line</h1>");
      assert.ok(deliveredPeriod(issuer.last.body), "headline opened from a delivered period key");
      assert.equal(await text(client, "shoppingAd"), "ad");
      assert.deepEqual(
        Object.keys(issuer.last.body.contentGroups.contentKeys),
        ["shoppingAd"],
        "shoppingAd opened from its recovered item key",
      );
      assert.equal(await text(client, "purchase"), "buy");
      assert.equal(issuer.calls.posts, 4);
    });

  test("an omission wrapper preserves the seed-only content-group route", async () => {
    const keys = await roleKeys();
    const page = await render(publisherFor(keys, { at: AT.T14 }));
    const issuer = issuerFor(keys);
    const bundle = contentGroupsProfile.client({
      createPeriodKeyCache: (config) => new PeriodKeyCache(config),
      createChainKeyCache: (config) => new ChainKeyCache(config),
    });
    const client = createDeliveryClient({
      reader: readerOf(page, "json"),
      issuerName: "issuerA",
      unlockUrl: UNLOCK,
      transport: issuer.transport,
      ...bundle.composeOptions,
      requestBuilderFactory: (options) =>
        new OmissionRequestBuilder({
          innerBuilder: bundle.requestBuilderFactory(options),
        }),
    });
    const result = await client.unlock(["shoppingAd"]);
    assert.equal(result.skipped, undefined);
    assert.equal(issuer.calls.posts, 1);
    assert.equal(utf8Decode((await client.openLocal("shoppingAd")).bytes), "ad");
  });

  test("a render-scoped content-group item key opens without a reusable-cache origin", async () => {
    const keys = await roleKeys();
    const page = await render(publisherFor(keys, { at: AT.T14 }));
    const issuer = issuerFor(keys);
    const reader = readerOf(page, "json");
    // The signed JWT still carries the publisher origin for issuer admission.
    // This low-level client deliberately supplies no host cache partition.
    const data = new DcaData(reader.dcaData);
    assert.equal(data.publisherOrigin, undefined);
    const bundle = contentGroupsProfile.client({
      createPeriodKeyCache: (config) => new PeriodKeyCache(config),
      createChainKeyCache: (config) => new ChainKeyCache(config),
    });
    const { builder, resolver } = composeClient(bundle.composeOptions);
    const request = builder.build(data, "issuerA", ["shoppingAd"]);
    const response = await issuer.transport.post(UNLOCK, request.toObject());
    const body = response.body;
    assert.equal(response.status, 200);
    assert.deepEqual(Object.keys(body.contentGroups), ["contentKeys"]);
    await resolver.applyResponse(
      data,
      "issuerA",
      body,
      new ResponseAssociation(data, "issuerA", request),
    );
    const key = await resolver.contentKeyFor(data, "shoppingAd");
    assert.ok(key);
    assert.equal(
      utf8Decode(
        await openContent(
          key,
          "shoppingAd",
          reader.extract("shoppingAd"),
          data.contentItemFor("shoppingAd").contentAad,
        ),
      ),
      "ad",
    );
    // Reusable keys still require an explicit host partition; do not infer it
    // from the JWT or relax the cache boundary to repair the item-key path.
    const chainRequest = builder.build(data, "issuerA", ["bodytext"]);
    const chainAnswer = await issuer.transport.post(UNLOCK, chainRequest.toObject());
    assert.ok(chainAnswer.body.contentGroups.chainKeys.bodytext);
    await assert.rejects(
      resolver.applyResponse(
        data,
        "issuerA",
        chainAnswer.body,
        new ResponseAssociation(data, "issuerA", chainRequest),
      ),
      { code: "bad_page" },
    );
  });

  test("one route walk covers every item, and openLocal reads them without another request", async () => {
    const keys = await roleKeys();
    const page = await render(publisherFor(keys, { at: AT.T14 }));
    const issuer = issuerFor(keys);
    const { client } = clientFor(page, { transport: issuer.transport, carrier: "html" });
    const walk = await client.unlockRoutes(
      ["bodytext", "headline", "shoppingAd", "purchase"],
      [{ issuerName: "issuerA", unlockUrl: UNLOCK }],
    );
    assert.deepEqual(walk.missing, []);
    assert.equal(issuer.calls.posts, 1);
    for (const [name, value] of [
      ["bodytext", "body text"],
      ["headline", "<h1>head line</h1>"],
      ["shoppingAd", "ad"],
      ["purchase", "buy"],
    ])
      assert.equal(utf8Decode((await client.openLocal(name)).bytes), value, name);
    assert.equal(issuer.calls.posts, 1);
  });

  test("after one issuer denies a narrowed name, an issuer without its seed still opens the ordinary sibling", async () => {
    // issuerA seeds every connector item and denies bodytext; issuerB holds
    // purchase's ordinary envelope and no seed. The host narrows bodytext to
    // politics, which grants nothing: issuerB's request carries purchase alone.
    const keys = await roleKeys();
    const issuers = ["issuerA", "issuerB"];
    const page = await render(
      publisherFor(keys, {
        at: AT.T14,
        issuers,
        issuerSeedWindows: { issuerA: ALL_WINDOWS },
        purchaseIssuers: ["issuerB"],
      }),
    );
    const issuerA = issuerFor(keys, { issuers: ["issuerA"] });
    issuerA.policy.grants = () => [];
    const issuerB = issuerFor(keys, { issuers: ["issuerB"] });
    /** @type {any[]} */
    const sent = [];
    const { client } = clientFor(page, {
      narrowing: { requestedContentGroups: { bodytext: ["politics"] } },
      transport: {
        /** @param {string} url @param {any} request */
        post(url, request) {
          sent.push(JSON.parse(JSON.stringify(request)));
          const issuer = request.issuerName === "issuerA" ? issuerA : issuerB;
          return issuer.transport.post(url, request);
        },
      },
    });
    const walk = await client.unlockRoutes(
      ["bodytext", "purchase"],
      [
        { issuerName: "issuerA", unlockUrl: UNLOCK },
        { issuerName: "issuerB", unlockUrl: UNLOCK, independent: true },
      ],
    );
    assert.deepEqual(
      walk.attempts.map((a) => [a.issuerName, a.outcome]),
      [
        ["issuerA", "answered"],
        ["issuerB", "answered"],
      ],
    );
    assert.deepEqual(walk.missing, ["bodytext"]);
    assert.deepEqual(Object.keys(sent[0].sealed.contentWindowSeeds), ["bodytext"]);
    assert.deepEqual(Object.keys(sent[1].sealed), ["contentKeys"]);
    assert.deepEqual(Object.keys(sent[1].sealed.contentKeys), ["purchase"]);
    assert.equal(utf8Decode((await client.openLocal("purchase")).bytes), "buy");
    await assert.rejects(client.openLocal("bodytext"), coded("no_key"));
  });
});

// ---------------------------------------------------------------------------
// Evidence 2: reuse inside the grant, denial outside it

describe("reuse across articles and denial outside the grant", () => {
  /** A reader that opened story1 at T14 and holds bodytext's chain to T18. */
  async function readerWithChain() {
    const keys = await roleKeys();
    const issuer = issuerFor(keys);
    const storage = new Storage();
    const first = await render(publisherFor(keys, { at: AT.T14 }));
    const { client } = clientFor(first, { transport: issuer.transport, storage });
    assert.equal(await text(client, "bodytext"), "body text");
    const chain = /** @type {NonNullable<ReturnType<typeof deliveredChain>>} */ (
      deliveredChain(issuer.last.body)
    );
    assert.equal(chain.cutoffT, T18);
    return { keys, issuer, storage, chain };
  }

  test("two later bodytext articles in the window open from the stored chain without a request", async () => {
    const { keys, issuer, storage } = await readerWithChain();
    const posts = issuer.calls.posts;
    for (const [at, resourceId] of [
      [AT.T15, "story2"],
      [AT.T17, "story3"],
    ]) {
      const page = await render(publisherFor(keys, { at }), resourceId);
      const { client } = clientFor(page, { transport: issuer.transport, storage });
      assert.equal(await text(client, "bodytext"), "body text", resourceId);
    }
    assert.equal(issuer.calls.posts, posts, "reuse sends no request");
  });

  test("the stored chain opens no other name, publisher, group, geometry, window or later period", async () => {
    const { keys, issuer, storage, chain } = await readerWithChain();
    issuer.policy.grants = () => [];
    /**
     * @param {string} label @param {any} page @param {string} name @param {string} group
     * @param {string} t @param {string} [origin]
     */
    const denied = async (label, page, name, group, t, origin) => {
      const posts = issuer.calls.posts;
      const { client } = clientFor(page, {
        transport: issuer.transport,
        storage,
        ...(origin === undefined ? {} : { origin }),
      });
      await assert.rejects(client.open(name), coded("no_key"), label);
      assert.equal(issuer.calls.posts, posts + 1, `${label}: the stored chain did not cover it`);
      assert.equal(issuer.last.status, 401, `${label}: the issuer denied it`);
      const best = await periodFromDelivered(chain.key, "politics", chain.cutoffT, t);
      await assert.rejects(
        tryPeriodKey(page, name, group, best, origin),
        coded("decrypt_failed"),
        `${label}: the held chain's best period key does not decrypt`,
      );
    };
    const at15 = await render(publisherFor(keys, { at: AT.T15 }), "story2");
    // Scope isolation: the stored chain answers bodytext's partition and no
    // other name's, before any decryption is tried.
    const { groupCaches } = clientFor(at15, { transport: issuer.transport, storage });
    /** @param {string} contentName */
    const scope = (contentName) => ({
      partition: chainKeyPartition(ORIGIN, GEOMETRY, contentName, "politics"),
      ...GEOMETRY,
    });
    const cache = /** @type {ChainKeyCache} */ (groupCaches.chain);
    assert.equal((await cache.candidates("politics", T15, scope("bodytext"))).length, 1);
    assert.deepEqual(
      await cache.candidates("politics", T15, scope("headline")),
      [],
      "bodytext's chain derives nothing under headline's partition",
    );
    await denied("another content name", at15, "headline", "politics", T15);
    await denied("another group", at15, "sportsNews", "sports", T15);
    await denied(
      "another publisher",
      await render(publisherFor(keys, { at: AT.T15, origin: OTHER_ORIGIN }), "story2"),
      "bodytext",
      "politics",
      T15,
      OTHER_ORIGIN,
    );
    await denied(
      "another geometry",
      await render(
        publisherFor(keys, { at: AT.T15, geometry: { chainsPerDay: 4, periodMinutes: 60 } }),
        "story2",
      ),
      "bodytext",
      "politics",
      T15,
    );
    await denied(
      "another window",
      await render(publisherFor(keys, { at: AT.T01 }), "story4"),
      "bodytext",
      "politics",
      "261015T0100",
    );
    await denied(
      "a later period",
      await render(publisherFor(keys, { at: AT.T19 }), "story5"),
      "bodytext",
      "politics",
      "261014T1900",
    );
  });

  test("a denied period between two granted periods stays closed", async () => {
    const keys = await roleKeys();
    const issuer = issuerFor(keys);
    const storage = new Storage();
    issuer.policy.authorize = (_name, _group, t) => t !== T14;
    /** @type {Uint8Array[]} */
    const held = [];
    for (const [at, resourceId] of [
      [AT.T13, "early"],
      [AT.T15, "late"],
    ]) {
      const page = await render(publisherFor(keys, { at }), resourceId);
      const { client } = clientFor(page, { transport: issuer.transport, storage });
      assert.equal(await text(client, "headline"), "<h1>head line</h1>", resourceId);
      held.push(/** @type {any} */ (deliveredPeriod(issuer.last.body)).key);
    }
    const middle = await render(publisherFor(keys, { at: AT.T14 }), "middle");
    // A period grant at T14 and a chain to T15 both need T14 authorized.
    for (const grants of [
      () => [{ kind: "period", contentName: "headline", group: "politics", t: T14 }],
      () => [
        {
          kind: "chain",
          contentName: "headline",
          group: "politics",
          windowStart: W12,
          cutoffT: T15,
        },
      ],
    ]) {
      issuer.policy.grants = grants;
      const { client } = clientFor(middle, { transport: issuer.transport, storage });
      await assert.rejects(
        client.open("headline"),
        coded("no_key"),
        "a grant that reaches the denied T14 is refused, so T14 stays closed",
      );
      assert.notEqual(issuer.last.status, 200, "the issuer refuses the grant");
    }
    for (const key of held)
      await assert.rejects(
        tryPeriodKey(middle, "headline", "politics", key),
        coded("decrypt_failed"),
        "neither neighbouring period key decrypts T14",
      );
  });
});

// ---------------------------------------------------------------------------
// Evidence 3: substitutions, association and kinds

describe("the composed exchange refuses substitutions and unbound answers", () => {
  /** @param {{ issuers?: string[] }} [options] */
  async function world(options = {}) {
    const keys = await roleKeys();
    const issuer = issuerFor(keys, options);
    const publisher = publisherFor(keys, { at: AT.T14, ...options });
    const page = await render(publisher);
    const other = await render(publisher, "story2");
    return { keys, issuer, page, other };
  }

  /**
   * Run `open(name)` once with the rewrite and once without it: the positive
   * control shares the path and opens.
   * @param {any} issuer @param {any} page @param {string} name @param {string} value
   * @param {(request: any) => any} change @param {{ issuerName?: string }} [options]
   */
  async function refusedRequest(issuer, page, name, value, change, options = {}) {
    issuer.rewriteRequests(change);
    const refused = clientFor(page, { transport: issuer.transport, ...options }).client;
    await assert.rejects(refused.open(name), coded("no_key"));
    const refusal = issuer.last;
    issuer.rewriteRequests(null);
    const control = clientFor(page, { transport: issuer.transport, ...options }).client;
    assert.equal(await text(control, name), value, "the unchanged request opens");
    return refusal;
  }

  test("a seed envelope of another content name does not open at this name's coordinate", async () => {
    const { issuer, page } = await world();
    const refusal = await refusedRequest(issuer, page, "bodytext", "body text", (request) => {
      request.sealed.contentWindowSeeds.bodytext[W12] = pageSeeds(page).headline[W12];
      return request;
    });
    assert.equal(refusal.status, 400);
    assert.equal(refusal.body.error, "binding_failed");
  });

  test("a seed envelope sealed for another issuer does not open at this issuer's coordinate", async () => {
    const { issuer, page } = await world({ issuers: ["issuerA", "issuerB"] });
    const refusal = await refusedRequest(
      issuer,
      page,
      "bodytext",
      "body text",
      (request) => {
        request.sealed.contentWindowSeeds.bodytext[W12] = pageSeeds(page, "issuerA").bodytext[W12];
        return request;
      },
      { issuerName: "issuerB" },
    );
    assert.equal(refusal.body.error, "binding_failed");
  });

  test("another render's signed claims do not accept this render's seeds", async () => {
    const { issuer, page, other } = await world();
    const refusal = await refusedRequest(issuer, page, "bodytext", "body text", (request) => {
      request.resourceJWT = readerOf(other, "json").dcaData.resourceJWT;
      return request;
    });
    assert.equal(refusal.body.error, "binding_failed");
  });

  test("a substituted connector returns a candidate but cannot open genuine content", async () => {
    const { issuer, page } = await world();
    issuer.rewriteRequests((request) => {
      request.requestedContentKeys.shoppingAd.connector = pageItem(
        page,
        "bodytext",
      ).connectors.sports;
      return request;
    });
    const changed = clientFor(page, { transport: issuer.transport }).client;
    await assert.rejects(changed.open("shoppingAd"), coded("decrypt_failed"));
    const refusal = issuer.last;
    issuer.rewriteRequests(null);
    const control = clientFor(page, { transport: issuer.transport }).client;
    assert.equal(await text(control, "shoppingAd"), "ad", "the unchanged request opens");
    assert.equal(refusal.status, 200);
    const candidate = refusal.body.contentGroups.contentKeys.shoppingAd;
    assert.equal(typeof candidate, "string");
    const { item, ciphertext } = pageItem(page, "shoppingAd");
    await assert.rejects(
      openContent(base64urlDecode(candidate), "shoppingAd", ciphertext, item.contentAad),
      coded("decrypt_failed"),
    );
  });

  test("an item with no seed for this issuer sends no request and opens nothing", async () => {
    const keys = await roleKeys();
    const issuers = ["issuerA", "issuerB"];
    const issuer = issuerFor(keys, { issuers });
    const page = await render(
      publisherFor(keys, {
        at: AT.T14,
        issuers,
        issuerSeedWindows: { issuerA: ALL_WINDOWS, issuerB: { headline: [W12] } },
      }),
    );
    const { client } = clientFor(page, {
      transport: issuer.transport,
      issuerName: "issuerB",
      narrowing: {},
    });
    await assert.rejects(client.open("bodytext"), coded("no_key"));
    assert.equal(issuer.calls.posts, 0, "no route, no request");
    assert.equal(await text(client, "headline"), "<h1>head line</h1>", "a routed item opens");
    assert.equal(await text(client, "purchase"), "buy", "the ordinary item opens");
  });

  const malformed = { section: "contentGroups", code: "malformed_response" };
  // Each case names the issue the client reports: a refused content-group
  // section, or the whole response when the declared key table is broken.
  const responseCases = /** @type {[string, string, (body: any) => void, object][]} */ ([
    [
      "a chain key for a name the request did not carry",
      "bodytext",
      (body) => {
        body.contentGroups.chainKeys.headline = body.contentGroups.chainKeys.bodytext;
      },
      malformed,
    ],
    [
      "a chain key for a group the request did not carry",
      "bodytext",
      (body) => {
        const chains = body.contentGroups.chainKeys.bodytext;
        chains.culture = chains.politics;
      },
      malformed,
    ],
    [
      "a chain key for a window the page did not supply",
      "bodytext",
      (body) => {
        body.contentGroups.chainKeys.bodytext.politics["261015T1200"] = base64urlEncode(
          new Uint8Array(16),
        );
      },
      malformed,
    ],
    [
      "a chain key inside a redundant wrapper",
      "bodytext",
      (body) => {
        body.contentGroups.chainKeys.bodytext.politics[T18] = {
          position: 5,
          key: body.contentGroups.chainKeys.bodytext.politics[T18],
        };
      },
      { section: "response", code: "invalid_transport" },
    ],
    [
      "a chain key of 15 bytes",
      "bodytext",
      (body) => {
        body.contentGroups.chainKeys.bodytext.politics[T18] = base64urlEncode(new Uint8Array(15));
      },
      { section: "contentGroups", code: "malformed_key" },
    ],
    [
      "a chain member answered under periodKeys",
      "bodytext",
      (body) => {
        const chain = body.contentGroups.chainKeys.bodytext.politics[T18];
        body.contentGroups.periodKeys = { bodytext: { politics: { [T14]: chain } } };
        delete body.contentGroups.chainKeys;
      },
      null,
    ],
    [
      "a period key answered under chainKeys",
      "headline",
      (body) => {
        const key = body.contentGroups.periodKeys.headline.politics[T14];
        body.contentGroups.chainKeys = { headline: { politics: { [T14]: key } } };
        delete body.contentGroups.periodKeys;
      },
      null,
    ],
    [
      "an unknown content-group member",
      "headline",
      (body) => {
        body.contentGroups.windowSeeds = {};
      },
      malformed,
    ],
  ]);
  for (const [label, name, change, issue] of responseCases)
    test(`the client refuses ${label}`, async () => {
      const keys = await roleKeys();
      const issuer = issuerFor(keys);
      const page = await render(publisherFor(keys, { at: AT.T14 }));
      issuer.rewriteResponses((body) => {
        if (body.contentGroups) change(body);
        return body;
      });
      const { client } = clientFor(page, { transport: issuer.transport });
      const { application } = await client.unlock([name, "purchase"]);
      assert.deepEqual(application.issues, issue === null ? [] : [issue]);
      await assert.rejects(client.openLocal(name), coded("no_key"));
      assert.equal(await text(client, "purchase"), "buy", "the ordinary item opens by its own key");
      issuer.rewriteResponses(null);
      const control = clientFor(page, { transport: issuer.transport }).client;
      assert.equal(
        await text(control, name),
        name === "bodytext" ? "body text" : "<h1>head line</h1>",
        "the unchanged answer opens",
      );
    });
});

// ---------------------------------------------------------------------------
// Evidence 4: storage, eviction, rivals and reset

describe("shared client storage", () => {
  test("a malformed family report preserves content-group opening and promotion", async () => {
    const keys = await roleKeys();
    const issuer = issuerFor(keys);
    const storage = new Storage();
    const page = await render(publisherFor(keys, { at: AT.T14 }));
    issuer.rewriteResponses((body) => {
      body.notDelivered = [];
      return body;
    });
    const first = clientFor(page, { transport: issuer.transport, storage });
    const { application } = await first.client.unlock(["bodytext", "purchase"]);
    assert.equal(
      application.accepted,
      2,
      "independent content-group and ordinary item grants survive",
    );
    assert.deepEqual(application.issues, [{ section: "notDelivered", code: "malformed_response" }]);
    assert.equal(await text(first.client, "bodytext"), "body text");
    assert.equal(await text(first.client, "purchase"), "buy");
    assert.deepEqual(
      first.groupCaches.chain.entries().map(({ kind }) => kind),
      ["chain-key"],
      "successful body authentication promotes the admitted content-group chain",
    );
    const posts = issuer.calls.posts;
    const later = await render(publisherFor(keys, { at: AT.T15 }), "story-after-malformed-report");
    const reloaded = clientFor(later, { transport: issuer.transport, storage });
    assert.equal(await text(reloaded.client, "bodytext"), "body text");
    assert.equal(
      issuer.calls.posts,
      posts,
      "the promoted chain opens another render without requesting",
    );
  });

  test("a new client over the same storage opens chain- and period-derived items without a request", async () => {
    const keys = await roleKeys();
    const issuer = issuerFor(keys);
    const storage = new Storage();
    const page = await render(publisherFor(keys, { at: AT.T14 }));
    const first = clientFor(page, { transport: issuer.transport, storage });
    assert.equal(await text(first.client, "bodytext"), "body text");
    assert.equal(await text(first.client, "headline"), "<h1>head line</h1>");
    const posts = issuer.calls.posts;

    const reloaded = clientFor(page, { transport: issuer.transport, storage });
    assert.equal(await text(reloaded.client, "bodytext"), "body text");
    assert.equal(await text(reloaded.client, "headline"), "<h1>head line</h1>");
    assert.equal(issuer.calls.posts, posts, "the reload reads storage, not the issuer");

    // The ordinary cache over the same backend holds nothing of this, and the
    // dedicated chain cache keeps chains only, no derived period view.
    assert.deepEqual(await reloaded.ordinary.period.entries(), []);
    assert.deepEqual(await new PeriodKeyCache({ storage, namespace: "ordinary" }).entries(), []);
    assert.deepEqual(
      first.groupCaches.chain?.entries().map(({ kind }) => kind),
      ["chain-key"],
      "one chain, no derived period entry",
    );
  });

  test("a full cache evicts the older window, and that window's next article asks again", async () => {
    const keys = await roleKeys();
    const issuer = issuerFor(keys);
    const storage = new Storage();
    const limits = { maxCachedWindows: 1 };
    for (const [at, resourceId] of [
      [AT.T14, "noon"],
      [AT.T01, "night"],
    ]) {
      const page = await render(publisherFor(keys, { at }), resourceId);
      const { client } = clientFor(page, { transport: issuer.transport, storage, limits });
      assert.equal(await text(client, "bodytext"), "body text", resourceId);
    }
    const posts = issuer.calls.posts;
    const again = await render(publisherFor(keys, { at: AT.T15 }), "afternoon");
    const { client } = clientFor(again, { transport: issuer.transport, storage, limits });
    assert.equal(await text(client, "bodytext"), "body text");
    assert.equal(issuer.calls.posts, posts + 1, "the evicted window needed the issuer again");
  });

  test("a bogus rival chain does not displace the true one", async () => {
    const keys = await roleKeys();
    const issuer = issuerFor(keys);
    const storage = new Storage();
    const page = await render(publisherFor(keys, { at: AT.T14 }));
    issuer.rewriteResponses((body) => {
      body.contentGroups.chainKeys.bodytext.politics[T18] = base64urlEncode(random.bytes(16));
      return body;
    });
    const fooled = clientFor(page, { transport: issuer.transport, storage }).client;
    await assert.rejects(fooled.open("bodytext"), coded("no_key"), "a bogus chain opens nothing");
    issuer.rewriteResponses(null);
    const honest = clientFor(page, { transport: issuer.transport, storage }).client;
    assert.equal(await text(honest, "bodytext"), "body text");
    const posts = issuer.calls.posts;
    const later = await render(publisherFor(keys, { at: AT.T15 }), "story2");
    const reader = clientFor(later, { transport: issuer.transport, storage }).client;
    assert.equal(await text(reader, "bodytext"), "body text");
    assert.equal(issuer.calls.posts, posts, "the stored true chain serves the next article");
  });

  /**
   * Reset the client while one step is held, then release it: the open fails
   * as retired, nothing reaches storage after the reset, and a new client over
   * the same storage must ask the issuer again.
   *
   * @param {string} label @param {'answer'|'write'|'unwrap'} held
   * @param {string} [item] @param {string} [value]
   */
  async function resetWhileHeld(label, held, item = "bodytext", value = "body text") {
    const keys = await roleKeys();
    const step = gate();
    // The unwrap case runs client-bound over ECDH-P256 and holds the chain
    // key's unwrap, so the reset lands between decode and filing.
    const method = held === "unwrap" ? ecdhMethod : undefined;
    const issuer = issuerFor(keys, method === undefined ? {} : { method });
    const capability = method === undefined ? undefined : await capabilityFor(method, "ecdh");
    const delayed =
      capability === undefined
        ? undefined
        : {
            ...capability,
            /** @param {unknown} transport */
            async openDeliveredKeys(transport) {
              const opener = await capability.openDeliveredKeys(transport);
              return {
                /** @param {any} value @param {KeyUsage[]} usages @param {string} keyKind */
                async open(value, usages, keyKind) {
                  const key = await opener.open(value, usages, keyKind);
                  if (keyKind === (item === "headline" ? PERIOD_KIND : CHAIN_KIND))
                    await step.wait();
                  return key;
                },
              };
            },
          };
    let holdWrites = held === "write";
    const storage = new Storage({
      gate: async ({ op }) => {
        if (holdWrites && op === "set") await step.wait();
      },
    });
    if (held === "answer") issuer.holdRequests(() => step.wait());
    const page = await render(publisherFor(keys, { at: AT.T14 }));
    const { client } = clientFor(page, {
      transport: issuer.transport,
      storage,
      ...(delayed === undefined ? {} : { capability: delayed }),
    });
    const opening = client.open(item);
    await step.arrived;
    // The reset waits for a cache write in flight, so the held step is released
    // after the reset began and before it is awaited.
    const resetting = client.clearReaderContext();
    step.release();
    await resetting;
    const after = await storedKeys(storage);
    await assert.rejects(opening, coded("context_retired"), `${label}: no plaintext after reset`);
    holdWrites = false;
    issuer.holdRequests(null);
    assert.deepEqual(await storedKeys(storage), after, `${label}: no write after reset`);
    const posts = issuer.calls.posts;
    const fresh = clientFor(page, {
      transport: issuer.transport,
      storage,
      ...(capability === undefined ? {} : { capability }),
    }).client;
    assert.equal(await text(fresh, item), value);
    assert.equal(issuer.calls.posts, posts + 1, `${label}: nothing was promoted for reuse`);
  }

  test("reset while the issuer answer is in flight", async () => {
    await resetWhileHeld("delayed answer", "answer");
  });

  test("reset while the chain key is being filed", async () => {
    await resetWhileHeld("delayed storage write", "write");
  });

  test("reset while a client-bound chain key is unwrapped", async () => {
    await resetWhileHeld("delayed unwrap", "unwrap");
  });

  test("reset while a client-bound period key is unwrapped", async () => {
    await resetWhileHeld("delayed period unwrap", "unwrap", "headline", "<h1>head line</h1>");
  });

  test("a reset drops a held item key: the same client asks the issuer again", async () => {
    const keys = await roleKeys();
    const issuer = issuerFor(keys);
    const page = await render(publisherFor(keys, { at: AT.T14 }));
    const { client } = clientFor(page, { transport: issuer.transport });
    assert.equal(await text(client, "shoppingAd"), "ad");
    const posts = issuer.calls.posts;
    await client.clearReaderContext();
    assert.equal(await text(client, "shoppingAd"), "ad");
    assert.equal(issuer.calls.posts, posts + 1, "the held item key did not survive the reset");
  });

  test("reset while a stored chain derives a period key", async () => {
    const keys = await roleKeys();
    const issuer = issuerFor(keys);
    const storage = new Storage();
    const first = await render(publisherFor(keys, { at: AT.T14 }));
    const opener = clientFor(first, { transport: issuer.transport, storage }).client;
    assert.equal(await text(opener, "bodytext"), "body text");
    const step = gate();
    const page = await render(publisherFor(keys, { at: AT.T15 }), "story2");
    const { client } = clientFor(page, {
      transport: issuer.transport,
      storage,
      wrapChainCache: (cache) =>
        new Proxy(cache, {
          get(target, name) {
            const value = Reflect.get(target, name, target);
            if (typeof value !== "function") return value;
            if (name !== "candidates") return value.bind(target);
            return async (/** @type {any[]} */ ...args) => {
              const derived = await value.apply(target, args);
              if (derived.length > 0) await step.wait();
              return derived;
            };
          },
        }),
    });
    const posts = issuer.calls.posts;
    const opening = client.open("bodytext");
    await step.arrived;
    const resetting = client.clearReaderContext();
    step.release();
    await resetting;
    await assert.rejects(opening, coded("context_retired"), "the late candidate opens nothing");
    assert.equal(issuer.calls.posts, posts, "the retired open asked nobody");
  });
});

// ---------------------------------------------------------------------------
// Evidence 5: client-bound transport

/**
 * A profile that seals the way a faulty issuer would, behind the stock
 * method's transport agreement: content-group keys under the other kind, or
 * 32 bytes under their own kind.
 *
 * @param {any} method
 * @param {'swap-kinds'|'wide'} fault
 */
function faultyProfile(method, fault) {
  const kinds = settledKinds(method);
  /** @type {Record<string, string>} */
  const swapped = { [CHAIN_KIND]: PERIOD_KIND, [PERIOD_KIND]: CHAIN_KIND };
  return {
    METHOD: method.METHOD,
    settleKindDescriptors: method.settleKindDescriptors,
    /** @param {any} clientPublicKey @param {any} options */
    async seal(clientPublicKey, options) {
      const ephemeralKeyPair = await subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveKey"],
      );
      const stock = await method.seal(clientPublicKey, {
        ...options,
        ...(method === ecdhMethod ? { ephemeralKeyPair } : {}),
      });
      /** @param {Uint8Array} bytes @param {string} kind */
      async function wide(bytes, kind) {
        const doubled = new Uint8Array(32);
        doubled.set(bytes);
        doubled.set(bytes, 16);
        const label = keyKindContext(kind, kinds);
        if (method === ecdhMethod) {
          const transportKey = await agreeTransport(
            await importPeer(clientPublicKey, "bad_client_key"),
            ephemeralKeyPair.privateKey,
          );
          const nonce = random.bytes(12);
          return {
            key: base64urlEncode(await encrypt(transportKey, nonce, doubled, label, 32)),
            nonce: base64urlEncode(nonce),
          };
        }
        const publicKey = await subtle.importKey(
          "jwk",
          clientPublicKey,
          { name: "RSA-OAEP", hash: "SHA-256" },
          false,
          ["encrypt"],
        );
        return {
          key: base64urlEncode(
            new Uint8Array(await subtle.encrypt({ name: "RSA-OAEP", label }, publicKey, doubled)),
          ),
        };
      }
      return {
        transport: stock.transport,
        /** @param {Uint8Array} bytes @param {string} kind */
        wrap(bytes, kind) {
          if (kind !== CHAIN_KIND && kind !== PERIOD_KIND) return stock.wrap(bytes, kind);
          return fault === "swap-kinds" ? stock.wrap(bytes, swapped[kind]) : wide(bytes, kind);
        },
      };
    },
  };
}

for (const [name, method, kind] of /** @type {const} */ ([
  ["ECDH-P256", ecdhMethod, "ecdh"],
  ["RSA-OAEP", rsaMethod, "rsa"],
]))
  describe(`client-bound transport over ${name}`, () => {
    test("opens chain-derived, period-derived, item-key and ordinary items, all wrapped", async () => {
      const keys = await roleKeys();
      const issuer = issuerFor(keys, { method });
      const page = await render(publisherFor(keys, { at: AT.T14 }));
      const capability = await capabilityFor(method, kind);
      const { client } = clientFor(page, {
        transport: issuer.transport,
        capability,
        carrier: "html",
      });
      for (const [item, value] of [
        ["bodytext", "body text"],
        ["headline", "<h1>head line</h1>"],
        ["shoppingAd", "ad"],
        ["purchase", "buy"],
      ]) {
        assert.equal(await text(client, item), value, item);
        const { body } = issuer.last;
        assert.equal(Object.hasOwn(body.transport, "mode"), false);
        assert.equal(Object.hasOwn(body, "periodGeometry"), false);
        assert.equal(body.transport.method, method.METHOD);
        for (const member of ["chainKeys", "periodKeys"])
          for (const groups of Object.values(body.contentGroups?.[member] ?? {}))
            for (const entries of Object.values(/** @type {any} */ (groups)))
              for (const entry of Object.values(/** @type {any} */ (entries)))
                assert.equal(typeof entry, "object", `${member} leave wrapped`);
        for (const entry of Object.values(body.contentGroups?.contentKeys ?? {}))
          assert.equal(typeof entry, "object", "a recovered item key leaves wrapped");
      }
    });

    for (const fault of /** @type {const} */ (["swap-kinds", "wide"]))
      test(`refuses content-group keys sealed ${fault === "wide" ? "32 bytes wide" : "under the other kind"}`, async () => {
        const keys = await roleKeys();
        const issuer = issuerFor(keys, { method, profile: faultyProfile(method, fault) });
        const page = await render(publisherFor(keys, { at: AT.T14 }));
        const capability = await capabilityFor(method, kind);
        const { client } = clientFor(page, { transport: issuer.transport, capability });
        for (const item of ["bodytext", "headline"])
          await assert.rejects(client.open(item), coded("no_key"), item);
        assert.equal(await text(client, "purchase"), "buy", "the base kind still opens");
      });

    test("never downgrades: a direct answer or an unwrapped content-group section opens nothing", async () => {
      const keys = await roleKeys();
      const page = await render(publisherFor(keys, { at: AT.T14 }));
      const capability = await capabilityFor(method, kind);
      const issuer = issuerFor(keys);
      const { client } = clientFor(page, { transport: issuer.transport, capability });
      for (const item of ["bodytext", "headline"])
        await assert.rejects(client.open(item), coded("no_key"), `direct answer: ${item}`);
    });

    test("an undeclared content-group section fails at the issuer; no raw key leaves", async () => {
      const keys = await roleKeys();
      const page = await render(publisherFor(keys, { at: AT.T14 }));
      const capability = await capabilityFor(method, kind);
      const issuer = issuerFor(keys, { method, keyDelivery: () => ({}) });
      const { client } = clientFor(page, { transport: issuer.transport, capability });
      for (const item of ["bodytext", "headline", "shoppingAd"])
        await assert.rejects(client.open(item), undefined, item);
      assert.ok(issuer.calls.posts > 0, "the client asked");
      assert.deepEqual(
        issuer.calls.responses.filter(({ body }) => Object.hasOwn(body, "contentGroups")),
        [],
        "no body carried the undeclared section",
      );
    });

    test("a partial content-group declaration fails at the issuer before raw keys leave", async () => {
      const keys = await roleKeys();
      const page = await render(publisherFor(keys, { at: AT.T14 }));
      const capability = await capabilityFor(method, kind);
      const issuer = issuerFor(keys, {
        method,
        keyDelivery: () => {
          const members = contentGroupsProfile.keyDeliveryMembers(settledKinds(method));
          return { ...members, composedSections: members.composedSections.slice(0, 1) };
        },
      });
      const { client } = clientFor(page, { transport: issuer.transport, capability });
      await assert.rejects(client.open("headline"), { code: "bad_config" });
      assert.ok(issuer.calls.posts > 0);
      assert.deepEqual(
        issuer.calls.responses.filter(({ body }) => Object.hasOwn(body, "contentGroups")),
        [],
      );
    });

    test("with direct fallback on, a wholly direct section opens and a mixed body does not", async () => {
      const keys = await roleKeys();
      const page = await render(publisherFor(keys, { at: AT.T14 }));
      const capability = await capabilityFor(method, kind);
      const direct = issuerFor(keys);
      const opened = clientFor(page, {
        transport: direct.transport,
        capability,
        directFallback: true,
      }).client;
      for (const [item, value] of [
        ["bodytext", "body text"],
        ["headline", "<h1>head line</h1>"],
      ])
        assert.equal(await text(opened, item), value, `wholly direct: ${item}`);
      assert.ok(
        direct.calls.responses.some(
          ({ body }) => Object.hasOwn(body, "contentGroups") && !Object.hasOwn(body, "transport"),
        ),
        "the keys came in a wholly direct content-group section",
      );
      const mixed = issuerFor(keys, { method });
      // Keep the transport and the wrapped base keys; spell each content-group
      // key directly with the true bytes the direct issuer sent, as a
      // downgrading issuer would, so only the mixed-body refusal stops it.
      /** @type {any} */
      const raw = { chainKeys: {}, periodKeys: {} };
      for (const { body } of direct.calls.responses)
        for (const member of ["chainKeys", "periodKeys"])
          for (const [name, groups] of Object.entries(body.contentGroups?.[member] ?? {}))
            for (const [group, entries] of Object.entries(/** @type {any} */ (groups)))
              for (const [label, entry] of Object.entries(/** @type {any} */ (entries)))
                raw[member][`${name}/${group}/${label}`] = entry;
      mixed.rewriteResponses((body) => {
        for (const member of ["chainKeys", "periodKeys"])
          for (const [name, groups] of Object.entries(body.contentGroups?.[member] ?? {}))
            for (const [group, entries] of Object.entries(/** @type {any} */ (groups)))
              for (const label of Object.keys(entries)) {
                const value = raw[member][`${name}/${group}/${label}`];
                assert.equal(typeof value, "string", "the direct issuer sent this key");
                entries[label] = value;
              }
        return body;
      });
      const refused = clientFor(page, {
        transport: mixed.transport,
        capability,
        directFallback: true,
      }).client;
      for (const item of ["bodytext", "headline"])
        await assert.rejects(refused.open(item), coded("no_key"), `mixed body: ${item}`);
      assert.equal(mixed.last.body.transport.method, method.METHOD);
    });
  });

test("RSA-OAEP without decrypt usage is refused at setup for the raw content-group kinds", async () => {
  await assert.rejects(
    capabilityFor(rsaMethod, "rsa", ["unwrapKey"]),
    coded("bad_config", /decrypt usage/),
  );
});

test("the client-bound members refuse a kind set the transport did not settle", () => {
  assert.throws(
    () => contentGroupsProfile.keyDeliveryMembers({ ...contentGroupsProfile.kindDescriptors }),
    coded("bad_config"),
  );
  assert.throws(
    () => contentGroupsProfile.capabilityOptions(ecdhMethod.settleKindDescriptors({})),
    coded("bad_config"),
  );
});

describe("compression beside content groups", () => {
  /** A raw Sealer configuration composed with the content-groups contribution. @param {any} keys */
  function composedConfig(keys) {
    return composePublisherConfig(
      /** @type {any} */ ({
        origin: ORIGIN,
        clock: { now: () => new Date(AT.T13) },
        random,
        signingKeys: { p1: keys.signing.privateKey },
        issuers: [
          {
            issuerName: "issuerA",
            keyId: "issuerA-k1",
            algorithm: "ecdh-p256",
            publicKey: keys.opening.publicKey,
          },
        ],
        issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ page) => ({
          contentKeyNames: page.contentNames.filter((/** @type {string} */ n) => n === "purchase"),
          suppliedAccessGroups: [],
        }),
      }),
      contentGroupsProfile.publisherContribution({
        retainedSecret: SECRET,
        periodGeometry: GEOMETRY,
        issuerSeedWindows: { issuerA: ALL_WINDOWS },
        chain: CHAIN,
      }),
    ).config;
  }

  /** @param {any} sealer */
  async function sealed(sealer) {
    sealer.resource("story1", {});
    sealer.content("bodytext", "body text", "text/plain", {
      contentGroups: ["politics", "sports"],
    });
    sealer.content("purchase", "buy", "text/plain", {});
    const { dcaData } = await sealer.seal();
    const claims = JSON.parse(utf8Decode(base64urlDecode(dcaData.resourceJWT.split(".")[1])));
    return {
      encodings: dcaData.contentData.bodytext.contentEncodings,
      connectors: Object.keys(dcaData.contentData.bodytext.connectors ?? {}),
      seeds: Object.keys(dcaData.issuerData.issuerA.sealed.contentWindowSeeds ?? {}),
      claims: Object.keys(claims).filter(
        (name) => !["renderId", "origin", "issuedAt", "resourceId", "data"].includes(name),
      ),
      geometry: dcaData.periodGeometry,
    };
  }

  test("CompressingSealer writes the connectors and seeds that Sealer writes for a grouped item", async () => {
    const keys = await roleKeys();
    const plain = await sealed(new Sealer(composedConfig(keys)));
    const compressed = await sealed(new CompressingSealer(composedConfig(keys)));
    assert.deepEqual(plain.connectors, ["politics", "sports"]);
    assert.deepEqual(plain.seeds, ["bodytext"]);
    assert.deepEqual(plain.claims, []);
    assert.deepEqual(compressed.encodings, ["gzip"]);
    assert.deepEqual({ ...compressed, encodings: undefined }, { ...plain, encodings: undefined });
  });

  test("CompressingSealer seals an item routed by its content groups alone", async () => {
    const keys = await roleKeys();
    const sealer = new CompressingSealer(composedConfig(keys));
    sealer.resource("story1", {});
    sealer.content("shoppingAd", "ad", "text/plain", { contentGroups: ["sports"] });
    const { dcaData } = await sealer.seal();
    assert.deepEqual(Object.keys(dcaData.contentData.shoppingAd.connectors), ["sports"]);
    assert.deepEqual(dcaData.contentData.shoppingAd.contentEncodings, ["gzip"]);
  });
});

describe("a chain-keys family supply beside content groups", () => {
  /**
   * A raw Sealer configuration with the chain-keys family supply (geometry 2/60
   * for premium) and the content-groups contribution (2/60).
   *
   * @param {any} keys
   * @param {(issuer: any, page: any) => any} planner
   */
  function composedConfig(keys, planner) {
    return composePublisherConfig(
      /** @type {any} */ ({
        origin: ORIGIN,
        clock: { now: () => new Date(AT.T13) },
        random,
        signingKeys: { p1: keys.signing.privateKey },
        issuers: [
          {
            issuerName: "issuerA",
            keyId: "issuerA-k1",
            algorithm: "ecdh-p256",
            publicKey: keys.opening.publicKey,
          },
        ],
        issuerSupplyPlanFor: planner,
      }),
      periodFamilyContribution({
        families: {
          premium: periodFamilyGeneration({
            keyDerivationSecret: new Uint8Array(32).fill(1),
            geometry: GEOMETRY,
          }),
        },
        chainWindows: 1,
      }),
      contentGroupsProfile.publisherContribution({
        retainedSecret: SECRET,
        periodGeometry: GEOMETRY,
        issuerSeedWindows: { issuerA: ALL_WINDOWS },
        chain: CHAIN,
      }),
    ).config;
  }

  test("a page with no chain-delivered group carries the content-groups pair", async () => {
    const keys = await roleKeys();
    const connectorOnly = new Sealer(
      composedConfig(keys, () => ({ contentKeyNames: [], suppliedAccessGroups: [] })),
    );
    connectorOnly.resource("story1", {});
    connectorOnly.content("bodytext", "body text", "text/plain", { contentGroups: ["politics"] });
    const first = (await connectorOnly.seal()).dcaData;
    assert.deepEqual(first.periodGeometry, GEOMETRY);
    assert.deepEqual(Object.keys(first.contentData.bodytext.connectors), ["politics"]);

    // premium rides period keys only, so base alone would write its minutes alone.
    const periodOnly = new Sealer(
      composedConfig(keys, () => ({ contentKeyNames: [], suppliedAccessGroups: ["premium"] })),
    );
    periodOnly.resource("story1", {});
    periodOnly.content("body", "<p>body</p>", "text/html", { accessGroups: ["premium"] });
    periodOnly.content("bodytext", "body text", "text/plain", { contentGroups: ["politics"] });
    const second = (await periodOnly.seal()).dcaData;
    assert.deepEqual(second.periodGeometry, GEOMETRY);
    assert.deepEqual(Object.keys(second.issuerData.issuerA.sealed.periodKeys), ["premium"]);
    assert.deepEqual(Object.keys(second.issuerData.issuerA.sealed.contentWindowSeeds), [
      "bodytext",
    ]);
  });
});

describe("compact ECDH beside content groups", () => {
  /**
   * A publisher with an ordinary issuer and a compact-selecting one, which
   * receives every item's content key. Seeds go where `issuerSeedWindows` says.
   *
   * @param {any} keys
   * @param {Record<string, Record<string, string[]>>} issuerSeedWindows
   */
  function publisher(keys, issuerSeedWindows) {
    return createPublisher(
      /** @type {any} */ ({
        origin: ORIGIN,
        clock: { now: () => new Date(AT.T13) },
        random,
        signingKeys: { p1: keys.signing.privateKey },
        issuers: ["issuerA", "compact"].map((issuerName) => ({
          issuerName,
          keyId: `${issuerName}-k1`,
          algorithm: "ecdh-p256",
          publicKey: keys.opening.publicKey,
          ...(issuerName === "compact" ? { envelope: COMPACT_ECDH } : {}),
        })),
        issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ page) => ({
          contentKeyNames: issuer.issuerName === "compact" ? page.contentNames : [],
          suppliedAccessGroups: [],
        }),
      }),
      contentGroupsProfile.publisherContribution({
        retainedSecret: SECRET,
        periodGeometry: GEOMETRY,
        issuerSeedWindows,
        chain: CHAIN,
      }),
      compactEcdhPublisherContribution(),
    );
  }

  const ITEMS = [
    {
      name: "bodytext",
      value: "body text",
      contentType: "text/plain",
      contentGroups: ["politics"],
    },
  ];

  test("seeds for an ordinary issuer publish beside a compact block that carries none", async () => {
    const keys = await roleKeys();
    const { dcaData } = await publisher(keys, { issuerA: { bodytext: [W12] } }).publish({
      resourceId: "story1",
      data: {},
      items: structuredClone(ITEMS),
    });
    assert.equal(dcaData.issuerData.compact.envelope, COMPACT_ECDH);
    assert.deepEqual(Object.keys(dcaData.issuerData.compact.sealed), ["contentKeys"]);
    assert.equal(Object.hasOwn(dcaData.issuerData.issuerA, "envelope"), false);
    assert.deepEqual(Object.keys(dcaData.issuerData.issuerA.sealed.contentWindowSeeds), [
      "bodytext",
    ]);
  });

  test("seeds for the compact issuer are refused, whatever the ordinary issuer receives", async () => {
    const keys = await roleKeys();
    for (const issuerSeedWindows of [
      { compact: { bodytext: [W12] } },
      { issuerA: { bodytext: [W12] }, compact: { bodytext: [W12] } },
    ]) {
      await assert.rejects(
        publisher(keys, issuerSeedWindows).publish({
          resourceId: "story1",
          data: {},
          items: structuredClone(ITEMS),
        }),
        coded("bad_config", /issuer "compact" selects compact-ecdh.*content-groups does not seal/),
        JSON.stringify(issuerSeedWindows),
      );
    }
  });
});

// ---------------------------------------------------------------------------
// Chain keys and content groups in one base issuer engine

describe("one base issuer engine composing chain keys with content groups", () => {
  // The host composes the lower-level chain pieces into the base engine:
  // `chainKeyCapabilitySource` as `periodCapabilitySource`, `chain-keys` as a
  // selected extension and its encoder, beside the content-groups contribution.
  // The stock `chainKeyIssuerEngine` arrives as an injected engine instead, and
  // nothing here exercises it.

  /** bodytext rides the premium chain family, sportsNews a connector, headline its item key. */
  const ITEMS = Object.freeze([
    {
      name: "bodytext",
      value: "premium body",
      contentType: "text/plain",
      accessGroups: ["premium"],
    },
    {
      name: "sportsNews",
      value: "sports score",
      contentType: "text/plain",
      contentGroups: ["sports"],
    },
    { name: "headline", value: "head line", contentType: "text/plain" },
  ]);

  /**
   * One page from a publisher with the chain-keys family supply and the
   * content-groups contribution, rendered at 14:20.
   *
   * @param {any} keys
   * @param {('period-keys'|'chain-keys')[]} [delivery] how premium travels to the issuer
   */
  async function chainPage(keys, delivery = ["chain-keys"]) {
    const publisher = createPublisher(
      /** @type {any} */ ({
        origin: ORIGIN,
        clock: { now: () => new Date(AT.T14) },
        random,
        signingKeys: { p1: keys.signing.privateKey },
        issuers: [
          {
            issuerName: "issuerA",
            keyId: "issuerA-k1",
            algorithm: "ecdh-p256",
            publicKey: keys.opening.publicKey,
          },
        ],
        issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ page) => ({
          contentKeyNames: page.contentNames.filter((/** @type {string} */ n) => n === "headline"),
          suppliedAccessGroups: [...page.accessGroups],
          periodKeyDelivery: Object.fromEntries(
            page.accessGroups.map((/** @type {string} */ g) => [g, delivery]),
          ),
        }),
      }),
      periodFamilyContribution({
        families: {
          premium: periodFamilyGeneration({
            keyDerivationSecret: new Uint8Array(32).fill(7),
            geometry: GEOMETRY,
          }),
        },
        chainWindows: 2,
      }),
      contentGroupsProfile.publisherContribution({
        retainedSecret: SECRET,
        periodGeometry: GEOMETRY,
        issuerSeedWindows: { issuerA: { sportsNews: [W12] } },
        chain: CHAIN,
      }),
    );
    return publisher.publish({ resourceId: "story1", data: {}, items: structuredClone(ITEMS) });
  }

  /**
   * The request a chain-relaying client builds for `names`, with the members a
   * content-groups client adds beside it.
   *
   * @param {any} page
   * @param {{ names?: string[], groups?: Record<string, string[]> }} [options]
   */
  function chainRequest(
    page,
    { names = ["bodytext", "headline"], groups = { sportsNews: ["sports"] } } = {},
  ) {
    const dcaData = JSON.parse(JSON.stringify(readerOf(page, "json").dcaData));
    const client = new Client({
      publisherOrigin: ORIGIN,
      cache: new PeriodKeyCache(),
      chainKeyProfile: explicitChainKeyClientProfile,
      requestBuilderFactory: (/** @type {any} */ options) => new ChainKeyRequestBuilder(options),
    });
    const base = JSON.parse(
      JSON.stringify(client.buildRequest(client.parse(dcaData), "issuerA", names)),
    );
    return {
      ...base,
      sealed: { ...base.sealed, contentWindowSeeds: pageSeeds(page) },
      renderPeriod: dcaData.renderPeriod,
      requestedContentGroups: groups,
    };
  }

  /**
   * Base policy: an independent grant for each requested family in `granted`,
   * an item key for each requested name in `purchased`.
   */
  function basePolicy({ granted = ["premium"], purchased = ["headline"] } = {}) {
    return {
      decide: (/** @type {any} */ _claims, /** @type {any} */ requested) => ({
        contentNames: requested.contentNames.filter((/** @type {string} */ n) =>
          purchased.includes(n),
        ),
        periodGrants: requested.accessGroups
          .filter((/** @type {string} */ g) => granted.includes(g))
          .map((/** @type {string} */ accessGroup) => ({
            accessGroup,
            futurePeriodCount: 2,
            authorizePeriod: () => true,
          })),
      }),
    };
  }

  /** Content-groups policy: a chain to 18:00 for every requested group in `granted`. */
  function groupPolicy({ granted = ["sports"] } = {}) {
    return {
      decide: (/** @type {any} */ input) => ({
        grants: Object.entries(
          /** @type {Record<string, { groups: string[], windows: string[] }>} */ (
            input.contentGroups
          ),
        ).flatMap(([contentName, { groups, windows }]) =>
          windows.includes(W12)
            ? groups
                .filter((group) => granted.includes(group))
                .map((group) => ({
                  kind: "chain",
                  contentName,
                  group,
                  windowStart: W12,
                  cutoffT: T18,
                }))
            : [],
        ),
        authorizePeriod: () => true,
      }),
    };
  }

  /**
   * The issuer core with both extensions in the base engine.
   *
   * Host duty: wrap the chain source in `requireChainRepresentation`. An
   * independent grant for a family the request relays as period keys is a
   * clean chain miss; unwrapped, the engine refuses to fall back to the base
   * period-key prefix and the whole answer is a 500. `requireChainRepresentation`
   * turns that miss into an unavailable family beside the other routes.
   *
   * @param {{ representation?: 'period-keys'|'chain-keys', accessPolicy?: any, policy?: any,
   *   requireChain?: boolean, periodKeyInput?: boolean }} [options]
   */
  function baseEngineIssuer({
    representation = "period-keys",
    accessPolicy = basePolicy(),
    policy = groupPolicy(),
    requireChain = true,
    periodKeyInput = undefined,
  } = {}) {
    const chainSource = chainKeyCapabilitySource({ representation });
    return createIssuerCore(
      {
        operatingIssuerNames: ["issuerA"],
        accessPolicy,
        periodCapabilitySource: requireChain
          ? requireChainRepresentation(chainSource)
          : chainSource,
        ...(periodKeyInput === undefined ? {} : { periodKeyInput }),
        selectedExtensions: ["chain-keys"],
        capabilityEncoders:
          representation === "chain-keys" ? { "chain-keys": chainKeyCapabilityEncoderFor() } : {},
      },
      contentGroupsProfile.issuerContribution({ chain: CHAIN, policy }),
    );
  }

  /** @param {any} keys */
  function registrationFor(keys) {
    return {
      kid: "p1",
      publicKey: keys.signing.publicKey,
      origins: [ORIGIN],
      openingKeys: {
        get: (/** @type {string} */ issuerName, /** @type {string} */ keyId) =>
          issuerName === "issuerA" && keyId === "issuerA-k1"
            ? { algorithm: "ecdh-p256", privateKey: keys.opening.privateKey }
            : undefined,
      },
    };
  }

  /**
   * One unlock as the host runs it.
   *
   * Host duty: capture one instant per unlock and pass it in, whether or not
   * the request reaches a chain grant. The chain source reads no clock of its
   * own; `createBrowserIssuer` captures the instant from its clock.
   *
   * @param {any} core @param {any} registration @param {any} document
   * @param {number} [capturedAtMs]
   */
  async function unlock(core, registration, document, capturedAtMs = Date.parse(AT.T14)) {
    const { response } = await core.endpoint.handleDocument(
      JSON.stringify(document),
      registration,
      {},
      capturedAtMs,
    );
    return { status: response.status, body: JSON.parse(JSON.stringify(response.body)) };
  }

  /**
   * Every key an answer hands a reader, as bytes at the period `t`, with the
   * section it came from. A chain key derives forward to `t`.
   *
   * @param {any} body @param {string} t
   */
  async function readerKeysAt(body, t) {
    /** @type {{ origin: string, key: Uint8Array }[]} */
    const found = [];
    for (const [g, family] of Object.entries(body?.keys?.periodKeys ?? {}))
      for (const [label, key] of Object.entries(/** @type {any} */ (family)))
        found.push({ origin: `periodKeys.${g}.${label}`, key: base64urlDecode(key) });
    for (const [g, family] of Object.entries(body?.keys?.chainKeys ?? {}))
      for (const [cutoffT, key] of Object.entries(/** @type {any} */ (family)))
        found.push({
          origin: `chainKeys.${g}.${cutoffT}`,
          key: await periodFromDelivered(base64urlDecode(key), g, cutoffT, t),
        });
    for (const [name, groups] of Object.entries(body?.contentGroups?.chainKeys ?? {}))
      for (const [g, entries] of Object.entries(/** @type {any} */ (groups)))
        for (const [cutoffT, key] of Object.entries(/** @type {any} */ (entries)))
          found.push({
            origin: `contentGroups.chainKeys.${name}.${g}.${cutoffT}`,
            key: await periodFromDelivered(base64urlDecode(key), g, cutoffT, t),
          });
    for (const [name, groups] of Object.entries(body?.contentGroups?.periodKeys ?? {}))
      for (const [g, entries] of Object.entries(/** @type {any} */ (groups)))
        for (const [label, key] of Object.entries(/** @type {any} */ (entries)))
          found.push({
            origin: `contentGroups.periodKeys.${name}.${g}.${label}`,
            key: base64urlDecode(key),
          });
    return found;
  }

  /**
   * Open `name`'s access-group wrap with a period key (bytes or handle). Null
   * when no wrap opens or the AEAD refuses.
   *
   * @param {any} page @param {string} name @param {string} accessGroup
   * @param {Uint8Array|CryptoKey} periodKey
   */
  async function openWrapped(page, name, accessGroup, periodKey) {
    const data = new DcaData(JSON.parse(JSON.stringify(readerOf(page, "json").dcaData)), {
      publisherOrigin: ORIGIN,
    });
    const { item, ciphertext } = pageItem(page, name);
    for (const entry of data.sealedEntriesFor(name, accessGroup)) {
      const contentKey = await attemptContentKeyWrap(entry, periodKey, undefined);
      if (contentKey === null) continue;
      try {
        return utf8Decode(await openContent(contentKey, name, ciphertext, item.contentAad));
      } catch {
        return null;
      }
    }
    return null;
  }

  /**
   * Try every key an answer delivers against every route of `name` at 14:00;
   * the routes that open it, by the section the key came from.
   *
   * @param {any} page @param {any} body @param {string} name
   */
  async function routesOpening(page, body, name) {
    /** @type {string[]} */
    const opened = [];
    const { item, ciphertext, connectors } = pageItem(page, name);
    for (const [section, keys] of /** @type {const} */ ([
      ["contentKeys", body?.keys?.contentKeys],
      ["contentGroups.contentKeys", body?.contentGroups?.contentKeys],
    ]))
      if (
        keys?.[name] !== undefined &&
        (await openContent(base64urlDecode(keys[name]), name, ciphertext, item.contentAad).then(
          () => true,
          () => false,
        ))
      )
        opened.push(`${section}.${name}`);
    const data = new DcaData(JSON.parse(JSON.stringify(readerOf(page, "json").dcaData)), {
      publisherOrigin: ORIGIN,
    });
    for (const { origin, key } of await readerKeysAt(body, T14)) {
      for (const accessGroup of data.accessGroupsFor(name))
        if ((await openWrapped(page, name, accessGroup, key)) !== null)
          opened.push(`${origin}->wrap.${accessGroup}`);
      for (const group of Object.keys(connectors))
        if (
          await tryPeriodKey(page, name, group, key).then(
            () => true,
            () => false,
          )
        )
          opened.push(`${origin}->connector.${group}`);
    }
    return opened;
  }

  test("a content-group wrapper admits a requested period projected from its inner chain relay", async () => {
    const keys = await roleKeys();
    const page = await chainPage(keys);
    const client = new Client({
      publisherOrigin: ORIGIN,
      cache: new PeriodKeyCache(),
      requestBuilderFactory: (options) =>
        new ContentGroupRequestBuilder({
          innerBuilder: new ChainKeyRequestBuilder(options),
        }),
    });
    const data = client.parse(JSON.parse(JSON.stringify(readerOf(page, "json").dcaData)));
    const request = client.buildRequest(data, "issuerA", ["bodytext"]);
    assert.equal(Object.hasOwn(request.sealed, "periodKeys"), false);
    assert.ok(request.sealed.chainKeys.premium);
    const answer = await unlock(baseEngineIssuer(), registrationFor(keys), request);
    assert.equal(answer.status, 200, JSON.stringify(answer.body));
    assert.ok(answer.body.keys.periodKeys.premium[T14]);
    // Forwarding the hook preserves its admission bounds: an unrequested
    // family and a period outside the presented chain window remain refused.
    answer.body.keys.periodKeys.unasked = { [T14]: base64urlEncode(new Uint8Array(16)) };
    answer.body.keys.periodKeys.premium["261016T0000"] = base64urlEncode(new Uint8Array(16));
    const applied = await client.applyResponse(data, "issuerA", answer.body);
    assert.deepEqual(applied.issues, [
      { section: "periodKeys", code: "unsolicited_coordinate" },
      { section: "periodKeys", code: "unsolicited_coordinate" },
    ]);
    assert.equal(
      utf8Decode(await client.decrypt(data, "bodytext", pageItem(page, "bodytext").ciphertext)),
      "premium body",
    );
  });

  for (const representation of /** @type {const} */ (["period-keys", "chain-keys"]))
    test(`${representation}: a full grant opens all three routes; each denial closes exactly its route`, async () => {
      const keys = await roleKeys();
      const page = await chainPage(keys);
      const registration = registrationFor(keys);
      const request = chainRequest(page);

      const full = await unlock(baseEngineIssuer({ representation }), registration, request);
      assert.equal(full.status, 200, JSON.stringify(full.body));
      const fullRoutes = {
        bodytext: await routesOpening(page, full.body, "bodytext"),
        sportsNews: await routesOpening(page, full.body, "sportsNews"),
        headline: await routesOpening(page, full.body, "headline"),
      };
      assert.deepEqual(fullRoutes, {
        bodytext:
          representation === "chain-keys"
            ? [`chainKeys.premium.${T15}->wrap.premium`]
            : [`periodKeys.premium.${T14}->wrap.premium`],
        sportsNews: [`contentGroups.chainKeys.sportsNews.sports.${T18}->connector.sports`],
        headline: ["contentKeys.headline"],
      });

      // premium denied, sports granted
      const noPremium = await unlock(
        baseEngineIssuer({ representation, accessPolicy: basePolicy({ granted: [] }) }),
        registration,
        request,
      );
      assert.equal(noPremium.status, 200, JSON.stringify(noPremium.body));
      assert.deepEqual(await routesOpening(page, noPremium.body, "bodytext"), []);
      assert.deepEqual(
        await routesOpening(page, noPremium.body, "sportsNews"),
        fullRoutes.sportsNews,
      );
      assert.deepEqual(await routesOpening(page, noPremium.body, "headline"), fullRoutes.headline);

      // sports denied, premium granted
      const noSports = await unlock(
        baseEngineIssuer({ representation, policy: groupPolicy({ granted: [] }) }),
        registration,
        request,
      );
      assert.equal(noSports.status, 200, JSON.stringify(noSports.body));
      assert.deepEqual(await routesOpening(page, noSports.body, "sportsNews"), []);
      assert.deepEqual(await routesOpening(page, noSports.body, "bodytext"), fullRoutes.bodytext);
      assert.deepEqual(await routesOpening(page, noSports.body, "headline"), fullRoutes.headline);

      // everything denied
      const none = await unlock(
        baseEngineIssuer({
          representation,
          accessPolicy: basePolicy({ granted: [], purchased: [] }),
          policy: groupPolicy({ granted: [] }),
        }),
        registration,
        request,
      );
      assert.equal(none.status, 401, JSON.stringify(none.body));
    });

  test("a content-group-only request is admitted and answered", async () => {
    const keys = await roleKeys();
    const page = await chainPage(keys);
    // The chain relay leaves out periodGeometry when no family travels; the
    // content-groups request builder sends it.
    const request = { ...chainRequest(page, { names: ["sportsNews"] }), periodGeometry: GEOMETRY };
    delete request.sealed.chainKeys;
    const answer = await unlock(baseEngineIssuer(), registrationFor(keys), request);
    assert.equal(answer.status, 200, JSON.stringify(answer.body));
    assert.deepEqual(await routesOpening(page, answer.body, "sportsNews"), [
      `contentGroups.chainKeys.sportsNews.sports.${T18}->connector.sports`,
    ]);
    assert.deepEqual(await routesOpening(page, answer.body, "bodytext"), []);
  });

  test("host duty: every unlock needs a captured instant, with or without a chain grant", async () => {
    const keys = await roleKeys();
    const page = await chainPage(keys);
    const registration = registrationFor(keys);
    const chainGranted = chainRequest(page);
    const chainFree = { ...chainRequest(page, { names: ["headline"] }), periodGeometry: GEOMETRY };
    delete chainFree.sealed.chainKeys;
    for (const [label, request, accessPolicy] of /** @type {const} */ ([
      ["chain grant", chainGranted, basePolicy()],
      ["no chain grant", chainFree, basePolicy({ granted: [] })],
    ])) {
      // A bare handleDocument(document, registration) passes no instant: the
      // chain source refuses its selection and the whole answer is a 500.
      const core = baseEngineIssuer({ accessPolicy });
      const bare = await core.endpoint.handleDocument(JSON.stringify(request), registration);
      assert.equal(bare.response.status, 500, label);
      assert.deepEqual(bare.response.body, { error: "internal_error" }, label);
      const captured = await unlock(core, registration, request, Date.parse(AT.T14));
      assert.equal(captured.status, 200, `${label}: ${JSON.stringify(captured.body)}`);
      assert.deepEqual(await routesOpening(page, captured.body, "headline"), [
        "contentKeys.headline",
      ]);
    }
  });

  test("host duty: requireChainRepresentation keeps an independent grant off the period-key prefix", async () => {
    const keys = await roleKeys();
    // premium travels as relayed period keys, which the processor reads, and the
    // base policy still grants it independently.
    const page = await chainPage(keys, ["period-keys"]);
    const registration = registrationFor(keys);
    const request = { ...chainRequest(page), periodGeometry: GEOMETRY };
    assert.deepEqual(Object.keys(request.sealed.periodKeys), ["premium"]);
    assert.equal(Object.hasOwn(request.sealed, "chainKeys"), false);

    const unwrapped = await unlock(
      baseEngineIssuer({ requireChain: false, periodKeyInput: true }),
      registration,
      request,
    );
    assert.equal(unwrapped.status, 500, JSON.stringify(unwrapped.body));

    const wrapped = await unlock(baseEngineIssuer({ periodKeyInput: true }), registration, request);
    assert.equal(wrapped.status, 200, JSON.stringify(wrapped.body));
    assert.deepEqual(await routesOpening(page, wrapped.body, "bodytext"), []);
    assert.deepEqual(await routesOpening(page, wrapped.body, "sportsNews"), [
      `contentGroups.chainKeys.sportsNews.sports.${T18}->connector.sports`,
    ]);
    assert.deepEqual(await routesOpening(page, wrapped.body, "headline"), ["contentKeys.headline"]);
  });

  test("browser composition: Origin is compared before policy and opening-key work", async () => {
    const keys = await roleKeys();
    const page = await chainPage(keys);
    const request = chainRequest(page);
    const registration = registrationFor(keys);
    const counts = { decide: 0, group: 0, openingKeys: 0 };
    const base = basePolicy();
    const group = groupPolicy();
    const core = baseEngineIssuer({
      accessPolicy: { decide: (/** @type {any[]} */ ...a) => (counts.decide++, base.decide(...a)) },
      policy: {
        decide: (/** @type {any} */ input) => (counts.group++, group.decide(input)),
      },
    });
    const spied = {
      ...registration,
      openingKeys: {
        get: (/** @type {string} */ issuerName, /** @type {string} */ keyId) => (
          counts.openingKeys++,
          registration.openingKeys.get(issuerName, keyId)
        ),
      },
    };
    // The browser issuer captures one instant per request from its clock.
    const http = createBrowserIssuer({
      core,
      registrationForKid: (/** @type {string} */ kid) => (kid === "p1" ? spied : null),
      preflight: (/** @type {string} */ origin) => origin === ORIGIN,
      admitCaller: () => ({ kind: "admitted", principal: null }),
      clock: { now: () => new Date(AT.T14) },
    });
    /** @param {string} origin */
    const post = (origin) =>
      http.handle({
        method: "POST",
        origin,
        contentType: "application/json",
        body: JSON.stringify(request),
        hostContext: {},
      });

    const copySite = await post(OTHER_ORIGIN);
    assert.equal(copySite.status, 403, JSON.stringify(copySite.body));
    assert.deepEqual(counts, { decide: 0, group: 0, openingKeys: 0 });

    const own = await post(ORIGIN);
    assert.equal(own.status, 200, JSON.stringify(own.body));
    assert.equal(own.headers["access-control-allow-origin"], ORIGIN);
    const body = JSON.parse(JSON.stringify(own.body));
    assert.deepEqual(await routesOpening(page, body, "bodytext"), [
      `periodKeys.premium.${T14}->wrap.premium`,
    ]);
    assert.deepEqual(await routesOpening(page, body, "sportsNews"), [
      `contentGroups.chainKeys.sportsNews.sports.${T18}->connector.sports`,
    ]);
    assert.deepEqual(await routesOpening(page, body, "headline"), ["contentKeys.headline"]);
  });

  for (const representation of /** @type {const} */ (["period-keys", "chain-keys"]))
    test(`${representation}: client-bound, no raw key leaves and the capability opens both sections`, async () => {
      const keys = await roleKeys();
      const page = await chainPage(keys);
      const core = baseEngineIssuer({ representation });
      assert.deepEqual(
        [...core.responseSections].map((s) => s.path.join(".")).sort(),
        [...contentGroupsProfile.responseSections].map((s) => s.path.join(".")).sort(),
      );
      const delivery = new KeyDelivery({
        random,
        profile: ecdhMethod,
        ...contentGroupsProfile.keyDeliveryMembers(settledKinds(ecdhMethod)),
      });
      const capability = await capabilityFor(ecdhMethod, "ecdh");
      const request = { ...chainRequest(page), clientPublicKey: capability.publicKey };
      const admission = core.processor.admit(new DcaRequest(request));
      assert.equal(admission.kind, "admitted");
      const view = await delivery.preflight("client-bound", admission.request);
      const direct = await core.endpoint.handleRequest({
        request: admission.request,
        registration: /** @type {any} */ (registrationFor(keys)),
        capturedAtMs: Date.parse(AT.T14),
      });
      assert.equal(direct.response.status, 200, JSON.stringify(direct.response.body));
      const raw = JSON.parse(JSON.stringify(direct.response.body));
      const bound = JSON.parse(JSON.stringify(await delivery.prepare(direct.response.body, view)));
      const text = JSON.stringify(bound);
      for (const family of Object.values(raw.keys.chainKeys ?? raw.keys.periodKeys))
        for (const key of Object.values(/** @type {any} */ (family)))
          assert.ok(!text.includes(key), "a raw base chain or period key left");
      for (const groups of Object.values(raw.contentGroups.chainKeys))
        for (const entries of Object.values(/** @type {any} */ (groups)))
          for (const { key } of Object.values(/** @type {any} */ (entries)))
            assert.ok(!text.includes(key), "a raw content-group chain key left");
      assert.ok(!text.includes(raw.keys.contentKeys.headline), "the raw content key left");

      const opener = await capability.openDeliveredKeys(bound.transport);
      if (representation === "chain-keys") {
        const chainKey = await opener.open(bound.keys.chainKeys.premium[T15], [], "chainKey");
        assert.ok(chainKey instanceof Uint8Array && chainKey.length === 16);
        const t14 = await periodFromDelivered(chainKey, "premium", T15, T14);
        assert.equal(await openWrapped(page, "bodytext", "premium", t14), "premium body");
      } else {
        // The delivery client opens period keys for unwrapping content-key wraps.
        const handle = await opener.open(
          bound.keys.periodKeys.premium[T14],
          ["unwrapKey"],
          "periodKey",
        );
        assert.ok(handle instanceof globalThis.CryptoKey);
        assert.equal(await openWrapped(page, "bodytext", "premium", handle), "premium body");
      }
      const groupKey = await opener.open(
        bound.contentGroups.chainKeys.sportsNews.sports[T18],
        [],
        CHAIN_KIND,
      );
      assert.ok(groupKey instanceof Uint8Array && groupKey.length === 16);
      const t14 = await periodFromDelivered(groupKey, "sports", T18, T14);
      assert.equal(
        utf8Decode(await tryPeriodKey(page, "sportsNews", "sports", t14)),
        "sports score",
      );
    });

  test("a seed relabelled as a chain member opens nothing; a chain member as a seed is refused", async () => {
    const keys = await roleKeys();
    const page = await chainPage(keys);
    const core = baseEngineIssuer();
    const registration = registrationFor(keys);
    const request = chainRequest(page);
    const seed = request.sealed.contentWindowSeeds.sportsNews[W12];
    const [chainLabel, chainBlob] = Object.entries(request.sealed.chainKeys.premium)[0];

    const seedAsChain = structuredClone(request);
    seedAsChain.sealed.chainKeys.premium[chainLabel] = seed;
    const first = await unlock(core, registration, seedAsChain);
    assert.deepEqual(await routesOpening(page, first.body, "bodytext"), []);

    const chainAsSeed = structuredClone(request);
    chainAsSeed.sealed.contentWindowSeeds.sportsNews[W12] = chainBlob;
    const second = await unlock(core, registration, chainAsSeed);
    assert.notEqual(second.status, 200, JSON.stringify(second.body));
  });

  test("a period-only relay keeps complete chain geometry for retained opening and rejects a conflicting contributed pair", async () => {
    // A canonical family keeps its complete pair even on a period-only relay,
    // so retained chain capabilities still open it. Contributions share that pair.
    const OTHER = Object.freeze({ chainsPerDay: 4, periodMinutes: 60 });
    const keys = await roleKeys();
    const registration = registrationFor(keys);
    /** @param {('period-keys'|'chain-keys')[]} delivery @param {any[]} items */
    const publish = (delivery, items, groupGeometry = GEOMETRY) =>
      createPublisher(
        /** @type {any} */ ({
          origin: ORIGIN,
          clock: { now: () => new Date(AT.T14) },
          random,
          signingKeys: { p1: keys.signing.privateKey },
          issuers: [
            {
              issuerName: "issuerA",
              keyId: "issuerA-k1",
              algorithm: "ecdh-p256",
              publicKey: keys.opening.publicKey,
            },
          ],
          issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ page) => ({
            contentKeyNames: page.contentNames.filter(
              (/** @type {string} */ n) => n === "headline",
            ),
            suppliedAccessGroups: [...page.accessGroups],
            periodKeyDelivery: Object.fromEntries(
              page.accessGroups.map((/** @type {string} */ g) => [g, delivery]),
            ),
          }),
        }),
        periodFamilyContribution({
          families: {
            premium: periodFamilyGeneration({
              keyDerivationSecret: new Uint8Array(32).fill(7),
              geometry: OTHER,
            }),
          },
          chainWindows: 2,
        }),
        contentGroupsProfile.publisherContribution({
          retainedSecret: SECRET,
          periodGeometry: groupGeometry,
          issuerSeedWindows: { issuerA: { sportsNews: [W12] } },
          chain: CHAIN,
        }),
      ).publish({ resourceId: "story1", data: {}, items: structuredClone(items) });
    const client = new Client({
      publisherOrigin: ORIGIN,
      cache: new PeriodKeyCache(),
      chainCache: new ChainKeyCache(),
      chainKeyProfile: explicitChainKeyClientProfile,
      requestBuilderFactory: (/** @type {any} */ options) => new ChainKeyRequestBuilder(options),
    });
    /** @param {any} page */
    const parsed = (page) =>
      client.parse(JSON.parse(JSON.stringify(readerOf(page, "json").dcaData)));
    /** @param {any} page @param {any} dcaData */
    const bodytext = async (page, dcaData) =>
      utf8Decode(await client.decrypt(dcaData, "bodytext", pageItem(page, "bodytext").ciphertext));

    const chained = await publish(
      ["chain-keys"],
      ITEMS.filter((item) => item.contentGroups === undefined),
    );
    const first = /** @type {any} */ (parsed(chained));
    assert.deepEqual(first.periodGeometry, OTHER);
    const chainRequest = client.buildRequest(first, "issuerA", ["bodytext"]);
    assert.deepEqual(Object.keys(chainRequest.sealed.chainKeys), ["premium"]);
    const chainAnswer = await unlock(
      baseEngineIssuer({ representation: "chain-keys" }),
      registration,
      chainRequest,
    );
    assert.equal(chainAnswer.status, 200, JSON.stringify(chainAnswer.body));
    await client.applyResponse(first, "issuerA", chainAnswer.body);
    assert.equal(await bodytext(chained, first), "premium body");

    await assert.rejects(publish(["period-keys"], ITEMS), /one periodGeometry applies to the page/);
    const relayed = await publish(["period-keys"], ITEMS, OTHER);
    const second = /** @type {any} */ (parsed(relayed));
    assert.deepEqual(second.periodGeometry, OTHER, "the canonical family keeps its complete pair");
    assert.equal(
      await bodytext(relayed, second),
      "premium body",
      "the retained chain opens a period-only relay",
    );
    const periodRequest = client.buildRequest(second, "issuerA", ["bodytext"]);
    assert.deepEqual(Object.keys(periodRequest.sealed.periodKeys), ["premium"]);
    assert.equal(Object.hasOwn(periodRequest.sealed, "chainKeys"), false);
    const periodIssuer = createIssuerCore(
      {
        operatingIssuerNames: ["issuerA"],
        periodKeyInput: true,
        // An ordinary grant for every relayed premium period.
        accessPolicy: {
          decide: (/** @type {any} */ _claims, /** @type {any} */ requested) => ({
            contentNames: [],
            periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
              accessGroup,
              periods: requested.periodCoordinates[accessGroup],
            })),
          }),
        },
      },
      contentGroupsProfile.issuerContribution({ chain: CHAIN, policy: groupPolicy() }),
    );
    const periodAnswer = await unlock(periodIssuer, registration, periodRequest);
    assert.equal(periodAnswer.status, 200, JSON.stringify(periodAnswer.body));
    await client.applyResponse(second, "issuerA", periodAnswer.body);
    assert.equal(await bodytext(relayed, second), "premium body");
  });
});

test("content-group unlock preserves an admitted item beside malformed sibling ciphertext", async () => {
  const keys = await roleKeys();
  const issuer = issuerFor(keys);
  const page = await render(publisherFor(keys, { at: AT.T14 }));
  const reader = readerOf(page, "json");
  const bundle = contentGroupsProfile.client({
    chain: CHAIN,
    storage: new Storage(),
    createPeriodKeyCache: (config) => new PeriodKeyCache(config),
    createChainKeyCache: (config) => new ChainKeyCache(config),
  });
  const client = createDeliveryClient({
    reader: {
      dcaData: reader.dcaData,
      publisherOrigin: reader.publisherOrigin,
      extract: (name) => (name === "purchase" ? "!" : reader.extract(name)),
    },
    issuerName: "issuerA",
    unlockUrl: UNLOCK,
    transport: issuer.transport,
    ...bundle.composeOptions,
  });
  const result = await client.unlock(["bodytext", "purchase"]);
  assert.equal(result.status, 200);
  assert.equal(utf8Decode((await client.openLocal("bodytext")).bytes), "body text");
  assert.ok(issuer.calls.posts > 0, "the admitted item was requested, not silently skipped");
});
