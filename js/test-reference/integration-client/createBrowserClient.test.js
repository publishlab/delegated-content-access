// @ts-check
//
// The copyable browser entry, over one page and one issuer. The world below is
// the one `test-reference/adapter-client/periodkeys.test.js` builds: a publisher
// that seals an article and an issuer that holds the opening key, sharing
// nothing else. The page crosses the markup seam as a string and comes back
// through `test-lib/helpers/domOver.js`, so the entry reads a root the way a
// browser hands it one.
//
// Pinned here: what the probe refuses, which option reaches which piece, and
// the single unlock attempt, once by an item content key and once by a
// period key. Expected keys are the publisher's own: the period keys its supply
// was given and the content key those unwrap. The walk, the breaker and the
// route list belong to `demo/actors/PageLoad.js` and are asserted there.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { createDeliveryClient } from "../../integration-client/createDeliveryClient.js";
import { encrypt } from "../../core-shared/aead.js";
import { utf8Encode } from "../../core-shared/codec.js";
import { DeniedUnlockCache } from "../../adapter-client/DeniedUnlockCache.js";
import { createBrowserClient } from "../../integration-client/createBrowserClient.js";
import {
  missingBrowserCapabilities,
  requireBrowserCapabilities,
} from "../../integration-client/browserCapabilities.js";
import { composeClient } from "../../integration-client/composeClient.js";
import { MarkupDeliveryReader } from "../../adapter-client/MarkupDeliveryReader.js";
import { Storage } from "../../demo/actors/Storage.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { writeMarkupDelivery } from "../../adapter-publisher/writeMarkupDelivery.js";
import { Sealer } from "../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../demo/support/PublisherRegistrations.js";
import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { domOver } from "../../test-lib/helpers/domOver.js";
import { refuses } from "../../test-lib/helpers/refuses.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import { utf8Decode } from "../../core-shared/codec.js";
import { dcaError } from "../../core-shared/errors.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";
import { contentAadOctets } from "../support/contentAadOctets.js";

const ISSUER_NAME = "paywall_subscription_service";
const BACKUP_ISSUER = "backup_issuer";
const THIRD_ISSUER = "third_issuer";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const PUB = "https://www.news-site.example";
const UNLOCK_URL = "https://api.example.com/unlock";
const AT = "2025-10-23T14:20:00Z";
const CONTENT_NAME = "bodytext";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const GROUP = "premium";
const SIBLING_GROUP = "sport";

// An hourly, two-slot render at AT wraps under the hour AT falls in and the
// next one, spelled YYMMDDTHHMM (docs/spec-profile--period-keys.md, 5.5).
const T_NOW = "251023T1400";
const T_NEXT = "251023T1500";

/** The period keys the publisher's supply holds, fixed before any run. */
const PERIOD_KEYS = Object.freeze({
  [T_NOW]: Uint8Array.from({ length: 16 }, (_, i) => 0x40 + i),
  [T_NEXT]: Uint8Array.from({ length: 16 }, (_, i) => 0x60 + i),
});
const SIBLING_PERIOD_KEYS = Object.freeze({
  [T_NOW]: Uint8Array.from({ length: 16 }, (_, i) => 0x80 + i),
  [T_NEXT]: Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i),
});

/** @param {Uint8Array} bytes */
const encoded = (bytes) => Buffer.from(bytes).toString("base64url");

/**
 * The item's content key as the publisher wrapped it: the `contentData` entry
 * at `T_NOW`, opened with WebCrypto under that period key and no additional
 * data (docs/spec--content-protection.md, 4). No issuer and no client code
 * takes part.
 *
 * @param {any} dcaData
 */
async function wrappedContentKey(dcaData) {
  const wrap = dcaData.contentData[CONTENT_NAME].keys[GROUP].find(
    (/** @type {any} */ entry) => entry.t === T_NOW,
  );
  const { subtle } = globalThis.crypto;
  const key = await subtle.importKey("raw", PERIOD_KEYS[T_NOW], "AES-GCM", false, ["decrypt"]);
  const opened = await subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(wrap.nonce, "base64url") },
    key,
    Buffer.from(wrap.key, "base64url"),
  );
  return encoded(new Uint8Array(opened));
}

/**
 * One publisher, one issuer, and the markup a reader's browser receives.
 *
 * @param {object} [page]
 * @param {boolean} [page.contentKeys] - whether the publisher seals the
 *   content key to the issuer beside the period keys; on when left out
 * @param {boolean} [page.periodKeyInput] - whether the issuer deployment
 *   selects period-key input; off when left out
 * @param {{ decide: (claims: any, requested: any) => any }} [page.accessPolicy] -
 *   the issuer's decision, `AllowAllPolicy` when left out
 * @param {'none'|'partial'|'complete'} [page.notDeliveredReport] - the issuer's
 *   not-delivered disclosure setting, the engine default when left out
 * @param {string[]} [page.accessGroups] - groups wrapping the item
 * @param {string[]} [page.issuerNames] - issuers independently entrusted with the item
 * @param {(issuer: { issuerName: string }) => { contentKeyNames: string[], suppliedAccessGroups: string[] }} [page.issuerSupplyPlanFor]
 * @param {string[]} [page.contentEncodings] - descriptor layers carried by the item
 * @returns {Promise<{ markup: string, contentKey: string, unlock: (request: object) => Promise<{ status: number, body: any }>, calls: { count: number } }>}
 */
async function world({
  contentKeys = true,
  periodKeyInput = false,
  accessPolicy = new AllowAllPolicy(),
  notDeliveredReport,
  accessGroups = [GROUP],
  issuerNames = [ISSUER_NAME],
  issuerSupplyPlanFor,
  contentEncodings,
} = {}) {
  const issuerKeys = await issuerKeypair();
  const signingKeys = await signingKeypair();

  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: randomPeriodKeySupply({
      random: new Random({ seed: 7 }),
      keys: { [GROUP]: { ...PERIOD_KEYS }, [SIBLING_GROUP]: { ...SIBLING_PERIOD_KEYS } },
    }),
    period: { length: 60, slots: 2 },
    issuerSupplyPlanFor:
      issuerSupplyPlanFor ??
      (() => ({
        contentKeyNames: contentKeys ? [CONTENT_NAME] : [],
        suppliedAccessGroups: accessGroups,
      })),
    issuers: issuerNames.map((issuerName) => ({
      issuerName,
      keyId: KEY_ID,
      algorithm: "ecdh-p256",
      publicKey: issuerKeys.publicKey,
    })),
  });
  sealer.resource("123456", { section: "politics" });
  if (contentEncodings === undefined) {
    sealer.content(CONTENT_NAME, ARTICLE, "text/html", { accessGroups });
  } else {
    sealer.content(
      CONTENT_NAME,
      {
        bytes: new TextEncoder().encode(ARTICLE),
        contentType: "text/html",
        contentEncodings,
      },
      { accessGroups },
    );
  }
  const rendered = await sealer.seal();
  const markup = writeMarkupDelivery({
    dcaData: rendered.dcaData,
    sealedContent: rendered.sealedContent,
  });

  const keyStore = {
    /** @param {string} issuerName @param {string} keyId */
    get(issuerName, keyId) {
      if (!issuerNames.includes(issuerName) || keyId !== KEY_ID) return undefined;
      return { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey };
    },
  };
  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(
        keyStore,
        issuerNames.map((issuerName) => ({ issuerName, keyId: KEY_ID })),
      ),
    },
  ]).get(SIGNING_KID);

  const processor = new IssuerProcessor(
    new IssuerEngine({
      operatingIssuerNames: issuerNames,
      accessPolicy,
      ...(notDeliveredReport === undefined ? {} : { notDeliveredReport }),
    }),
    { periodKeyInput },
  );
  const endpoint = new UnlockEndpoint(processor);
  const calls = { count: 0 };

  return {
    markup,
    contentKey: await wrappedContentKey(rendered.dcaData),
    calls,
    /** @param {object} request */
    async unlock(request) {
      calls.count++;
      return unlockThroughAdmission(processor, endpoint, request, registration);
    },
  };
}

/** The platform the probe reads, with every API this client uses on it. */
function fullPlatform() {
  return {
    crypto: globalThis.crypto,
    TextEncoder: globalThis.TextEncoder,
    TextDecoder: globalThis.TextDecoder,
    atob: globalThis.atob,
    btoa: globalThis.btoa,
  };
}

describe("The platform probe under the browser entry", () => {
  test("the runtime this suite runs on carries every API the client reads", () => {
    assert.deepEqual(missingBrowserCapabilities(), []);
    assert.deepEqual(missingBrowserCapabilities(fullPlatform()), []);
  });

  test("a platform short of one API is refused by that API's name", async () => {
    /** @type {[string, any][]} */
    const cases = [
      ["crypto", { ...fullPlatform(), crypto: undefined }],
      ["crypto.subtle", { ...fullPlatform(), crypto: {} }],
      ["TextEncoder", { ...fullPlatform(), TextEncoder: undefined }],
      ["TextDecoder", { ...fullPlatform(), TextDecoder: undefined }],
      ["atob", { ...fullPlatform(), atob: undefined }],
      ["btoa", { ...fullPlatform(), btoa: undefined }],
    ];
    for (const [name, platform] of cases) {
      assert.ok(
        missingBrowserCapabilities(platform).includes(name),
        `${name}: the probe reports it missing`,
      );
      await refuses(
        () => requireBrowserCapabilities(platform),
        { code: "unsupported_platform", message: new RegExp(name.replace(".", "\\.")) },
        `${name}: the refusal names the API the platform does not carry`,
      );
    }
  });

  test("a platform with no crypto at all lacks its subtle half too", () => {
    assert.deepEqual(missingBrowserCapabilities({ ...fullPlatform(), crypto: undefined }), [
      "crypto",
      "crypto.subtle",
    ]);
  });
});

describe("Which piece each composition option reaches", () => {
  test("the resolver options arrive at the resolver factory", () => {
    /** @type {any} */
    let seen = null;
    const capability = {
      publicKey: /** @type {any} */ ({ kty: "EC" }),
      openDeliveredKeys: () => [],
    };
    const chainCache = { put: () => undefined, candidates: () => [] };
    const chainKeyProfile = {
      parametersForResponse: () => ({}),
      candidateSourceFor: () => ({ attempts: () => [] }),
      acceptsPeriodKeyResponseCoordinate: () => true,
      acceptsResponseCoordinate: () => true,
    };
    const cache = { put: () => undefined, candidatesAt: () => [], attempted: () => undefined };

    composeClient({
      cache,
      chainCache,
      chainKeyProfile,
      clientBoundKeyCapability: capability,
      acceptDirectFallback: true,
      persistRawPeriodKeys: false,
      resolverFactory: (options) => {
        seen = options;
        return {
          applyResponse: () => undefined,
          resolveDetailed: () => undefined,
          resolve: () => undefined,
          contentKeyFor: () => undefined,
          contentKeyWithOriginFor: () => undefined,
        };
      },
    });

    assert.equal(seen.cache, cache);
    assert.equal(seen.chainCache, chainCache);
    assert.equal(seen.chainKeyProfile, chainKeyProfile);
    assert.equal(seen.clientBoundKeyCapability, capability);
    assert.equal(seen.acceptDirectFallback, true);
    assert.equal(seen.persistRawPeriodKeys, false);
  });

  test("the client's public half, and nothing else, arrives at the request builder", () => {
    /** @type {any} */
    let seen = null;
    const publicKey = /** @type {any} */ ({ kty: "EC", crv: "P-256" });
    composeClient({
      clientBoundKeyCapability: { publicKey, openDeliveredKeys: () => [] },
      acceptDirectFallback: true,
      requestBuilderFactory: (options) => {
        seen = options;
        return { build: () => undefined };
      },
    });
    assert.deepEqual(seen, { clientPublicKey: publicKey });

    composeClient({
      requestBuilderFactory: (options) => {
        seen = options;
        return { build: () => undefined };
      },
    });
    assert.deepEqual(
      seen,
      {},
      "a baseline client offers no public half or optional relay selection",
    );
  });

  test("the cache options arrive at the period-key cache", async () => {
    await refuses(
      () => composeClient({ storage: /** @type {any} */ ({ get: () => undefined }) }),
      { code: "bad_config", message: /storage answers get, set, keys and remove/ },
      "storage reaches the cache",
    );
    await refuses(
      () => composeClient({ cacheNamespace: "" }),
      { code: "bad_config", message: /namespace/ },
      "cacheNamespace reaches the cache",
    );
    await refuses(
      () => composeClient({ cacheKeyBy: /** @type {any} */ ("by-issuer") }),
      { code: "bad_config", message: /keyBy/ },
      "cacheKeyBy reaches the cache",
    );
    await refuses(
      () => composeClient(/** @type {any} */ ({ clock: { now: () => new Date(AT) } })),
      { code: "unsupported_option", message: /clock/ },
      "a clock has no eviction policy to pair with here, so a host builds that cache itself",
    );
  });

  test("the shared composition does not fuse its consumers' resolver surfaces", () => {
    const resolver = {
      clearReaderContext: async () => {},
      applyResponse: () => undefined,
      resolveDetailed: () => undefined,
      contentKeyWithOriginFor: () => undefined,
    };
    assert.equal(composeClient({ resolverFactory: () => resolver }).resolver, resolver);
  });

  test("a supplied cache is used as handed, and no cache is built beside it", () => {
    const cache = { put: () => undefined, candidatesAt: () => [], attempted: () => undefined };
    assert.equal(composeClient({ cache }).cache, cache);
  });

  test("a supplied cache beside an option that builds one is refused, not ignored", async () => {
    const cache = { put: () => undefined, candidatesAt: () => [], attempted: () => undefined };
    const storage = {
      get: () => null,
      set: () => undefined,
      keys: () => [],
      remove: () => undefined,
    };
    /** @type {[string, object][]} */
    const cases = [
      ["storage", { storage }],
      ["cacheNamespace", { cacheNamespace: "one" }],
      ["cacheKeyBy", { cacheKeyBy: () => "premium" }],
      // The misspelled partition the construction path refuses on its own.
      ["cacheKeyBy", { cacheKeyBy: /** @type {any} */ ("by-issuer") }],
    ];
    for (const [name, options] of cases) {
      await refuses(
        () => composeClient({ cache, ...options }),
        { code: "bad_config", message: new RegExp(`cache.*${name}`) },
        `${name} beside a supplied cache would build nothing, so it is refused`,
      );
    }
  });

  test("without an injected cache, each composition uses its own in-memory period-key cache", async () => {
    const first = composeClient();
    const second = composeClient();
    assert.ok(first.cache instanceof PeriodKeyCache);
    assert.notEqual(first.cache, second.cache);

    await first.cache.put("premium", "250101T0000", new Uint8Array([1]), { publisher: PUB });
    assert.deepEqual(
      await second.cache.candidatesAt("premium", "250101T0000", { publisher: PUB }),
      [],
    );
  });

  test("the content decoders arrive at the representation opener", async () => {
    await refuses(
      () => composeClient({ contentDecoders: /** @type {any} */ ({ gzip: "inflate" }) }),
      { code: "bad_config", message: /"gzip" is a function/ },
      "contentDecoders reach the opener",
    );
  });

  test("a chain cache reaches the resolver, which refuses one with no profile", async () => {
    await refuses(
      () => composeClient({ chainCache: { put: () => undefined, candidates: () => [] } }),
      { code: "bad_config", message: /chainCache needs an injected chainKeyProfile/ },
      "a chain cache without its profile is refused where the profile is read",
    );
  });

  test("an option this composition does not have is refused by name", async () => {
    await refuses(
      () => composeClient(/** @type {any} */ ({ network: {} })),
      { code: "unsupported_option", message: /network/ },
      "an unknown option is named",
    );
  });
});

/**
 * The item this client opens with the key it now holds, read as text.
 *
 * @param {ReturnType<typeof createBrowserClient>} client
 */
async function openedText(client) {
  const item = client.dcaData.contentItemFor(CONTENT_NAME);
  assert.ok(item);
  const bytes = await client.opener.open({
    item,
    ciphertext: client.reader.extract(CONTENT_NAME),
    resolveKey: async () =>
      (await client.resolver.contentKeyWithOriginFor(client.dcaData, CONTENT_NAME)).key,
  });
  return utf8Decode(bytes);
}

/**
 * A transport over `answer` that keeps a JSON copy of each request it posts
 * and each body it gets back.
 *
 * @param {(request: object) => Promise<{ status: number, body: any }>} answer
 */
function recordingExchange(answer) {
  /** @type {{ url: string, context: any, request: any, body: any }[]} */
  const exchanges = [];
  return {
    exchanges,
    transport: {
      /** @param {string} url @param {object} request @param {any} context */
      async post(url, request, context) {
        const response = await answer(request);
        exchanges.push({
          url,
          context,
          request: JSON.parse(JSON.stringify(request)),
          body: JSON.parse(JSON.stringify(response.body)),
        });
        return { ...response, contentType: "application/json" };
      },
    },
  };
}

describe("One page, one issuer, one unlock attempt", () => {
  test("an offered client-bound method admits keys in direct representation only under this endpoint's agreement", async () => {
    const { markup, unlock: answer } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    const transport = {
      async post(url, request) {
        void url;
        return { ...(await answer(request)), contentType: "application/json" };
      },
    };
    const options = {
      unlockUrl: UNLOCK_URL,
      root,
      issuerName: ISSUER_NAME,
      transport,
      clientBoundKeyCapability: {
        publicKey: { kty: "EC", crv: "P-256" },
        openDeliveredKeys() {
          throw new Error("the direct answer needs no opener");
        },
      },
      acceptDirectFallback: true,
    };

    const strict = createBrowserClient(options);
    assert.deepEqual((await strict.unlock([CONTENT_NAME])).application, {
      accepted: 0,
      errors: [],
      issues: [{ section: "response", code: "invalid_transport" }],
    });
    assert.equal(await strict.resolver.contentKeyFor(strict.dcaData, CONTENT_NAME), null);

    const direct = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      ...options,
      acceptDirectResponse: true,
    });
    assert.deepEqual((await direct.unlock([CONTENT_NAME])).application, {
      accepted: 1,
      errors: [],
      issues: [],
    });
    assert.equal(await openedText(direct), ARTICLE);
  });

  test("a direct period-key agreement requires explicit raw-key custody before transport", async () => {
    const { markup } = await world({ periodKeyInput: true });
    const root = domOver(markup, { publisherOrigin: PUB });
    let posts = 0;
    const transport = {
      async post() {
        posts++;
        return { status: 200, contentType: "application/json", body: { keys: {} } };
      },
    };
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root,
      issuerName: ISSUER_NAME,
      transport,
      clientBoundKeyCapability: {
        publicKey: { kty: "EC", crv: "P-256" },
        openDeliveredKeys() {
          throw new Error("the configuration refusal precedes transport");
        },
      },
      acceptDirectFallback: true,
      persistRawPeriodKeys: false,
      relayPeriodKeys: true,
    });
    const projected = client.builder.build(client.dcaData, ISSUER_NAME, [CONTENT_NAME]).toObject();
    assert.ok(Object.keys(projected.sealed.periodKeys?.[GROUP] ?? {}).length > 0);

    await refuses(
      () =>
        client.unlockRoutes(
          [CONTENT_NAME],
          [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, acceptDirectResponse: true }],
        ),
      {
        code: "bad_config",
        message: /direct period or chain keys needs raw key custody enabled/,
      },
      "resolver custody and route agreement are checked before a request is sent",
    );
    assert.equal(posts, 0);

    const strictWithoutOffer = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root,
      issuerName: ISSUER_NAME,
      transport,
      relayPeriodKeys: false,
    });
    await refuses(
      () =>
        strictWithoutOffer.unlockRoutes(
          [CONTENT_NAME],
          [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, acceptDirectResponse: false }],
        ),
      { code: "bad_config", message: /strict endpoint needs a client-bound offer/ },
      "a strict endpoint needs a usable wrapped-key response mode",
    );
    assert.equal(posts, 0);

    const chainOnly = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root,
      issuerName: ISSUER_NAME,
      transport,
      clientBoundKeyCapability: {
        publicKey: { kty: "EC", crv: "P-256" },
        openDeliveredKeys() {
          throw new Error("the configuration refusal precedes transport");
        },
      },
      acceptDirectFallback: true,
      persistRawPeriodKeys: false,
      relayPeriodKeys: false,
    });
    const originalBuild = chainOnly.builder.build.bind(chainOnly.builder);
    chainOnly.builder.build = /** @param {any[]} args */ (...args) => {
      const request = originalBuild(...args).toObject();
      request.sealed.chainKeys = { [GROUP]: { [T_NOW]: encoded(Uint8Array.of(1)) } };
      request.periodGeometry = {
        accessGroups: { [GROUP]: { chainsPerDay: 2, periodMinutes: 15 } },
      };
      return { toObject: () => request };
    };
    const chainProjection = chainOnly.builder
      .build(chainOnly.dcaData, ISSUER_NAME, [CONTENT_NAME])
      .toObject();
    assert.equal(chainProjection.sealed.periodKeys, undefined);
    assert.ok(Object.keys(chainProjection.sealed.chainKeys?.[GROUP] ?? {}).length > 0);
    await refuses(
      () =>
        chainOnly.unlockRoutes(
          [CONTENT_NAME],
          [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, acceptDirectResponse: true }],
        ),
      { code: "bad_config", message: /direct period or chain keys needs raw key custody enabled/ },
      "chain requests can receive direct period or chain key material",
    );
    assert.equal(posts, 0);

    const noFallback = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root,
      issuerName: ISSUER_NAME,
      transport,
      clientBoundKeyCapability: {
        publicKey: { kty: "EC", crv: "P-256" },
        openDeliveredKeys() {
          throw new Error("the configuration refusal precedes transport");
        },
      },
      acceptDirectFallback: false,
      relayPeriodKeys: false,
    });
    await refuses(
      () =>
        noFallback.unlockRoutes(
          [CONTENT_NAME],
          [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, acceptDirectResponse: true }],
        ),
      { code: "bad_config", message: /resolver that accepts direct fallback/ },
      "a direct endpoint agreement cannot claim a resolver fallback it has disabled",
    );
    assert.equal(posts, 0);
  });

  test(
    "the entry unlocks the article the publisher sealed",
    {
      tags: [
        "dca-profile-baseline/client/direct-admission",
        "dca-profile-html-carrier/client/markup-extraction",
      ],
    },
    async () => {
      const { markup, contentKey, unlock: answer, calls } = await world();
      const root = domOver(markup, { publisherOrigin: PUB });
      const { transport, exchanges } = recordingExchange(answer);

      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root,
        issuerName: ISSUER_NAME,
        transport,
      });

      const result = await client.unlock([CONTENT_NAME]);
      assert.equal(result.status, 200);
      assert.deepEqual(result.application, { accepted: 1, errors: [], issues: [] });
      assert.equal(calls.count, 1);
      const [{ url, context, request, body }] = exchanges;
      assert.deepEqual({ url, context }, { url: UNLOCK_URL, context: { origin: PUB } });

      // A client that selects no period-key relay presents the content name
      // alone, and the issuer answers that name with the key the publisher
      // wrapped, and nothing beside it.
      assert.deepEqual(Object.keys(request.sealed), ["contentKeys"]);
      assert.deepEqual(Object.keys(request.sealed.contentKeys), [CONTENT_NAME]);
      assert.deepEqual(body, { keys: { contentKeys: { [CONTENT_NAME]: contentKey } } });

      assert.equal(
        await openedText(client),
        ARTICLE,
        "the plaintext is the article that was sealed",
      );
    },
  );

  test("a status other than 200 comes back as it arrived, after one call", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    const body = { error: "not_entitled" };
    let posts = 0;

    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root,
      issuerName: ISSUER_NAME,
      transport: {
        async post() {
          posts++;
          return { status: 403, body };
        },
      },
    });

    const result = await client.unlock([CONTENT_NAME]);
    assert.deepEqual(result, { status: 403, body, application: null });
    assert.equal(posts, 1, "the entry sends one attempt and walks nowhere");
  });

  test("the host selects and rotates its endpoint without changing the delivery", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    /** @type {string[]} */
    const urls = [];
    const transport = {
      /** @param {string} url */
      async post(url) {
        urls.push(url);
        return { status: 503, body: null };
      },
    };

    const page = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root,
      issuerName: ISSUER_NAME,
      transport,
    });
    await page.unlock([CONTENT_NAME]);
    const host = createBrowserClient({
      root,
      issuerName: ISSUER_NAME,
      unlockUrl: "https://edge.example/unlock",
      transport,
    });
    await host.unlock([CONTENT_NAME]);

    assert.deepEqual(urls, [UNLOCK_URL, "https://edge.example/unlock"]);
  });

  test("the entry refuses a missing root, issuer name or transport, and acquisition from an absent issuer", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    const transport = {
      async post() {
        return { status: 200, body: {} };
      },
    };

    await refuses(
      () =>
        createBrowserClient(
          /** @type {any} */ ({ unlockUrl: UNLOCK_URL, issuerName: ISSUER_NAME, transport }),
        ),
      { code: "bad_config", message: /page root/ },
      "the entry reads one page and is told which",
    );
    await refuses(
      () => createBrowserClient(/** @type {any} */ ({ unlockUrl: UNLOCK_URL, root, transport })),
      { code: "bad_config", message: /issuerName/ },
      "the entry addresses one issuer and is told which",
    );
    await refuses(
      () =>
        createBrowserClient(
          /** @type {any} */ ({ unlockUrl: UNLOCK_URL, root, issuerName: ISSUER_NAME }),
        ),
      { code: "bad_config", message: /transport/ },
      "the host supplies the transport that reaches the issuer",
    );
    // The page's issuer set is not host configuration: held capability and
    // other routes stay usable, and only an acquisition from the absent
    // issuer is refused.
    const absent = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root,
      issuerName: "another_issuer",
      transport,
    });
    await refuses(
      () => absent.unlock([CONTENT_NAME]),
      { code: "unknown_issuer" },
      "a page carrying no block for that issuer has no route to it",
    );
  });

  test("the entry refuses a resolver missing any operation its facade needs", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    const transport = { post: async () => ({ status: 503, body: null }) };
    const resolver = {
      clearReaderContext: async () => {},
      applyResponse: () => undefined,
      resolveDetailed: () => undefined,
      resolve: () => undefined,
      contentKeyFor: () => undefined,
      contentKeyWithOriginFor: () => undefined,
    };

    for (const method of Object.keys(resolver)) {
      const { [method]: dropped, ...partial } = resolver;
      await refuses(
        () =>
          createBrowserClient({
            unlockUrl: UNLOCK_URL,
            root,
            issuerName: ISSUER_NAME,
            transport,
            resolverFactory: () => partial,
          }),
        { code: "bad_config", message: new RegExp(`needs ${method}`) },
        `the browser entry refuses a resolver without ${method}`,
      );
    }

    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root,
      issuerName: ISSUER_NAME,
      transport,
      resolverFactory: () => resolver,
    });
    await refuses(
      () =>
        client.unlockRoutes([CONTENT_NAME], [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL }]),
      { code: "bad_config", message: /authenticated item-key selection/ },
      "only the optional route-walk helper requires authenticated candidate selection",
    );
  });
});

describe("One page, one issuer, one period key", () => {
  test("a period key the issuer returns opens the article and is filed for reuse", async () => {
    // The publisher seals no content key to the issuer, so the article opens
    // only through a period key the issuer returned.
    const { markup, unlock: answer } = await world({
      contentKeys: false,
      periodKeyInput: true,
    });
    const { transport, exchanges } = recordingExchange(answer);
    const cache = new PeriodKeyCache();
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport,
      relayPeriodKeys: true,
      cache,
    });

    const result = await client.unlock([CONTENT_NAME]);
    assert.equal(result.status, 200);
    assert.deepEqual(result.application, { accepted: 2, errors: [], issues: [] });
    assert.equal(exchanges.length, 1);
    const [{ request, body }] = exchanges;

    assert.deepEqual(request.sealed.contentKeys, {});
    assert.deepEqual(Object.keys(request.sealed.periodKeys), [GROUP]);
    assert.deepEqual(Object.keys(request.sealed.periodKeys[GROUP]).sort(), [T_NOW, T_NEXT]);
    assert.deepEqual(body, {
      keys: {
        contentKeys: {},
        periodKeys: {
          [GROUP]: { [T_NOW]: encoded(PERIOD_KEYS[T_NOW]), [T_NEXT]: encoded(PERIOD_KEYS[T_NEXT]) },
        },
      },
    });

    for (const t of [T_NOW, T_NEXT]) {
      assert.deepEqual(
        await cache.candidatesAt(GROUP, t, { publisher: PUB }),
        [PERIOD_KEYS[t]],
        `${t}: the period key is filed under the page's publisher, group and label`,
      );
    }
    assert.equal(await openedText(client), ARTICLE);
  });

  test("a decision narrower than the access group returns the content key and no period key", async () => {
    // The page presents both routes. The issuer grants the one article and
    // not its group, so the answer holds the content key alone and the client
    // keeps nothing that would open another article in the group
    // (docs/spec--security-model.md, Enforcement boundary).
    const articleOnly = {
      /** @param {any} claims @param {{ contentNames: string[] }} requested */
      decide(claims, requested) {
        void claims;
        return { contentNames: [...requested.contentNames], periodGrants: [], policyData: [] };
      },
    };
    const {
      markup,
      contentKey,
      unlock: answer,
    } = await world({
      periodKeyInput: true,
      accessPolicy: articleOnly,
    });
    const { transport, exchanges } = recordingExchange(answer);
    const cache = new PeriodKeyCache();
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport,
      relayPeriodKeys: true,
      cache,
    });

    const result = await client.unlock([CONTENT_NAME]);
    assert.equal(result.status, 200);
    const [{ request, body }] = exchanges;
    assert.deepEqual(Object.keys(request.sealed.contentKeys), [CONTENT_NAME]);
    assert.deepEqual(Object.keys(request.sealed.periodKeys[GROUP]).sort(), [T_NOW, T_NEXT]);

    assert.deepEqual(body, { keys: { contentKeys: { [CONTENT_NAME]: contentKey } } });
    assert.deepEqual(await cache.entries(), [], "no period key is retained");
    assert.equal(await openedText(client), ARTICLE);
  });

  test("a wrong key from A leaves the item open to independent B without running its decoder", async () => {
    const { markup, unlock: answer } = await world({
      issuerNames: [ISSUER_NAME, BACKUP_ISSUER],
      contentEncodings: ["identity-test"],
    });
    const wrongKey = encoded(new Uint8Array(16).fill(0xa5));
    const sent = [];
    let decoderCalls = 0;
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      contentDecoders: {
        "identity-test"(bytes) {
          decoderCalls += 1;
          return bytes;
        },
      },
      transport: {
        async post(_url, request) {
          sent.push(request.issuerName);
          if (request.issuerName === ISSUER_NAME)
            return {
              status: 200,
              contentType: "application/json",
              body: { keys: { contentKeys: { [CONTENT_NAME]: wrongKey } } },
            };
          return { ...(await answer(request)), contentType: "application/json" };
        },
      },
    });

    const result = await client.unlockRoutes(
      [CONTENT_NAME],
      [
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
        { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL, independent: true },
      ],
    );
    assert.deepEqual(sent, [ISSUER_NAME, BACKUP_ISSUER]);
    assert.deepEqual(result.missing, []);
    assert.equal(decoderCalls, 0, "route authentication does not run representation decoders");
    assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
    assert.equal(decoderCalls, 1, "normal opening runs the admitted decoder once");
  });

  test("a wrong item key from A can yield to B's cached period-key alternative", async () => {
    const { markup, unlock: answer } = await world({
      periodKeyInput: true,
      issuerNames: [ISSUER_NAME, BACKUP_ISSUER],
      issuerSupplyPlanFor: ({ issuerName }) =>
        issuerName === ISSUER_NAME
          ? { contentKeyNames: [CONTENT_NAME], suppliedAccessGroups: [] }
          : { contentKeyNames: [], suppliedAccessGroups: [GROUP] },
    });
    const sent = [];
    const cache = new PeriodKeyCache();
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      relayPeriodKeys: true,
      cache,
      transport: {
        async post(_url, request) {
          sent.push(request);
          if (request.issuerName === ISSUER_NAME)
            return {
              status: 200,
              contentType: "application/json",
              body: {
                keys: { contentKeys: { [CONTENT_NAME]: encoded(new Uint8Array(16).fill(0xc1)) } },
              },
            };
          return { ...(await answer(request)), contentType: "application/json" };
        },
      },
    });
    const result = await client.unlockRoutes(
      [CONTENT_NAME],
      [
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
        { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL, independent: true },
      ],
    );
    assert.deepEqual(
      sent.map(({ issuerName }) => issuerName),
      [ISSUER_NAME, BACKUP_ISSUER],
    );
    assert.deepEqual(Object.keys(sent[0].sealed.contentKeys), [CONTENT_NAME]);
    assert.deepEqual(Object.keys(sent[1].sealed.periodKeys), [GROUP]);
    assert.deepEqual(result.missing, []);
    assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
    assert.ok((await cache.entries()).length > 0, "B's period-key alternative remains cached");
  });

  test("a valid first route and a previously held valid key stop before independent B", async () => {
    const { markup, unlock: answer } = await world({ issuerNames: [ISSUER_NAME, BACKUP_ISSUER] });
    const sent = [];
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport: {
        async post(_url, request) {
          sent.push(request.issuerName);
          return { ...(await answer(request)), contentType: "application/json" };
        },
      },
    });
    const first = await client.unlockRoutes(
      [CONTENT_NAME],
      [
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
        { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL, independent: true },
      ],
    );
    assert.deepEqual(first.missing, []);
    assert.deepEqual(sent, [ISSUER_NAME], "successful authenticated opening stops the walk");

    sent.length = 0;
    const cached = await client.unlockRoutes(
      [CONTENT_NAME],
      [{ issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL, independent: true }],
    );
    assert.deepEqual(cached.missing, []);
    assert.deepEqual(sent, [], "the held key is authenticated before contacting another issuer");
  });

  test("decrypt_failed does not activate a conditional route", async () => {
    const { markup } = await world({ issuerNames: [ISSUER_NAME, BACKUP_ISSUER] });
    const sent = [];
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport: {
        async post(_url, request) {
          sent.push(request.issuerName);
          return {
            status: 200,
            contentType: "application/json",
            body: {
              keys: { contentKeys: { [CONTENT_NAME]: encoded(new Uint8Array(16).fill(0x36)) } },
              notDelivered: { [GROUP]: { reason: "unavailable" } },
            },
          };
        },
      },
    });
    const result = await client.unlockRoutes(
      [CONTENT_NAME],
      [
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, retryUnavailable: true },
        { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL },
      ],
    );
    assert.deepEqual(sent, [ISSUER_NAME]);
    assert.deepEqual(result.missing, [CONTENT_NAME]);
  });

  test("a later independent operational failure can activate its own conditional route", async () => {
    const names = [ISSUER_NAME, BACKUP_ISSUER, THIRD_ISSUER];
    const { markup, unlock: answer } = await world({ issuerNames: names });
    const sent = [];
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport: {
        async post(_url, request) {
          sent.push(request.issuerName);
          if (request.issuerName === ISSUER_NAME)
            return {
              status: 200,
              contentType: "application/json",
              body: {
                keys: { contentKeys: { [CONTENT_NAME]: encoded(new Uint8Array(16).fill(0x71)) } },
              },
            };
          if (request.issuerName === BACKUP_ISSUER)
            throw Object.assign(new Error("offline"), { code: "timeout" });
          return { ...(await answer(request)), contentType: "application/json" };
        },
      },
    });
    const result = await client.unlockRoutes(
      [CONTENT_NAME],
      [
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
        {
          issuerName: BACKUP_ISSUER,
          unlockUrl: UNLOCK_URL,
          independent: true,
          retryOperational: true,
        },
        { issuerName: THIRD_ISSUER, unlockUrl: UNLOCK_URL },
      ],
    );
    assert.deepEqual(sent, names);
    assert.deepEqual(result.missing, []);
    assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
  });

  test("representation admission precedes route AEAD authentication", async () => {
    for (const scenario of [
      { label: "unsupported encoding", expected: "unsupported_encoding", encodings: ["unknown"] },
      { label: "malformed encoding list", expected: "bad_page", encodings: [] },
    ]) {
      const { markup } = await world({
        issuerNames: [ISSUER_NAME, BACKUP_ISSUER],
        contentEncodings: ["test-layer"],
      });
      const page = markup.replace(
        '"contentEncodings":["test-layer"]',
        `"contentEncodings":${JSON.stringify(scenario.encodings)}`,
      );
      assert.notEqual(page, markup, `${scenario.label}: fixture changed the page record`);
      const sent = [];
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root: domOver(page, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        contentDecoders:
          scenario.expected === "unsupported_encoding" ? {} : { "test-layer": (bytes) => bytes },
        transport: {
          async post(_url, request) {
            sent.push(request.issuerName);
            return {
              status: 200,
              contentType: "application/json",
              body: {
                keys: { contentKeys: { [CONTENT_NAME]: encoded(new Uint8Array(16).fill(0x84)) } },
              },
            };
          },
        },
      });
      assert.deepEqual(
        await client.unlockRoutes(
          [CONTENT_NAME],
          [
            { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
            { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL, independent: true },
          ],
        ),
        { missing: [], attempts: [], failed: [{ name: CONTENT_NAME, code: scenario.expected }] },
      );
      assert.deepEqual(
        sent,
        [],
        `${scenario.label}: bad representation is rejected before issuer transport`,
      );
    }
  });

  test("route representation preflight precedes cached period-key unwrap", async () => {
    const { markup } = await world({
      periodKeyInput: true,
      contentEncodings: ["unsupported-route-layer"],
    });
    const backing = new PeriodKeyCache();
    await backing.put(GROUP, T_NOW, PERIOD_KEYS[T_NOW], { publisher: PUB });
    let cacheReads = 0;
    const cache = {
      put: (...args) => backing.put(.../** @type {[any, any, any, any]} */ (args)),
      async candidatesAt(...args) {
        cacheReads += 1;
        return backing.candidatesAt(.../** @type {[any, any, any]} */ (args));
      },
      clearReaderContext: () => backing.clearReaderContext(),
      attempted: (...args) => backing.attempted(.../** @type {[any]} */ (args)),
    };
    let posts = 0;
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      relayPeriodKeys: true,
      cache,
      transport: {
        async post() {
          posts += 1;
          return { status: 403, body: null };
        },
      },
    });
    assert.deepEqual(
      await client.unlockRoutes(
        [CONTENT_NAME],
        [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL }],
      ),
      { missing: [], attempts: [], failed: [{ name: CONTENT_NAME, code: "unsupported_encoding" }] },
    );
    assert.equal(cacheReads, 0, "encoding admission runs before cached item-key unwrapping");
    assert.equal(posts, 0, "bad representation is refused before issuer transport");
  });

  test("under partial reporting the withheld family reaches the application beside the content key", async () => {
    const articleOnly = {
      /** @param {any} claims @param {{ contentNames: string[] }} requested */
      decide(claims, requested) {
        void claims;
        return { contentNames: [...requested.contentNames] };
      },
    };
    const {
      markup,
      contentKey,
      unlock: answer,
    } = await world({
      periodKeyInput: true,
      accessPolicy: articleOnly,
      notDeliveredReport: "partial",
    });
    const { transport, exchanges } = recordingExchange(answer);
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport,
      relayPeriodKeys: true,
      cache: new PeriodKeyCache(),
    });

    const result = await client.unlock([CONTENT_NAME]);
    assert.equal(result.status, 200);
    const [{ body }] = exchanges;
    assert.deepEqual(body, {
      keys: { contentKeys: { [CONTENT_NAME]: contentKey } },
      notDelivered: { [GROUP]: { reason: "denied" } },
    });
    assert.deepEqual(result.application, {
      accepted: 1,
      errors: [],
      issues: [],
      notDelivered: [{ accessGroup: GROUP, reason: "denied" }],
    });
    assert.equal(await openedText(client), ARTICLE);
  });

  test("a complete denial the issuer answers with a no-key report reaches the application", async () => {
    // The page presents the item and its group. The issuer denies both and,
    // under its "complete" disclosure setting, answers with a no-key result
    // naming the family instead of refusing the whole request.
    const denyAll = {
      /** @param {any} claims */
      decide(claims) {
        void claims;
        return {};
      },
    };
    const { markup, unlock: answer } = await world({
      periodKeyInput: true,
      accessPolicy: denyAll,
      notDeliveredReport: "complete",
    });
    const { transport, exchanges } = recordingExchange(answer);
    const cache = new PeriodKeyCache();
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport,
      relayPeriodKeys: true,
      cache,
    });

    const result = await client.unlock([CONTENT_NAME]);
    assert.equal(result.status, 200);
    const [{ body }] = exchanges;
    assert.deepEqual(body, {
      keys: { contentKeys: {} },
      notDelivered: { [GROUP]: { reason: "denied" } },
    });
    assert.deepEqual(result.application, {
      accepted: 0,
      errors: [],
      issues: [],
      notDelivered: [{ accessGroup: GROUP, reason: "denied" }],
    });
    assert.deepEqual(await cache.entries(), [], "no period key is retained");
    assert.equal(await client.resolver.contentKeyFor(client.dcaData, CONTENT_NAME), null);
  });

  test("an admitted unavailable family retries only that family through the reusable route workflow", async () => {
    const { markup, unlock: answer } = await world({ periodKeyInput: true });
    const sent = [];
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      relayPeriodKeys: true,
      transport: {
        async post(_url, request) {
          sent.push(request);
          if (sent.length === 1)
            return {
              status: 200,
              contentType: "application/json",
              body: {
                keys: { contentKeys: {} },
                notDelivered: { [GROUP]: { reason: "unavailable" } },
              },
            };
          return { ...(await answer(request)), contentType: "application/json" };
        },
      },
    });
    const result = await client.unlockRoutes(
      [CONTENT_NAME],
      [
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, retryUnavailable: true },
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
      ],
    );
    assert.equal(sent.length, 2);
    assert.deepEqual(result.missing, []);
    assert.deepEqual(
      Object.keys(sent[1].sealed.contentKeys),
      [],
      "item route did not inherit family retry",
    );
    assert.deepEqual(Object.keys(sent[1].sealed.periodKeys), [GROUP]);
    assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
  });

  test("an operational failure during a family retry does not revive a denied sibling", async () => {
    const { markup, unlock: answer } = await world({
      periodKeyInput: true,
      accessGroups: [GROUP, SIBLING_GROUP],
      issuerNames: [ISSUER_NAME, BACKUP_ISSUER, THIRD_ISSUER],
    });
    for (const failure of ["status", "transport"]) {
      const sent = [];
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root: domOver(markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        relayPeriodKeys: true,
        transport: {
          async post(_url, request) {
            sent.push(request);
            if (sent.length === 1)
              return {
                status: 200,
                contentType: "application/json",
                body: {
                  keys: { contentKeys: {} },
                  notDelivered: {
                    [GROUP]: { reason: "unavailable" },
                    [SIBLING_GROUP]: { reason: "denied" },
                  },
                },
              };
            if (sent.length === 2) {
              if (failure === "transport")
                throw Object.assign(new Error("timeout"), { code: "timeout" });
              return { status: 503, body: null };
            }
            return { ...(await answer(request)), contentType: "application/json" };
          },
        },
      });
      const result = await client.unlockRoutes(
        [CONTENT_NAME],
        [
          { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, retryUnavailable: true },
          { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL, retryOperational: true },
          { issuerName: THIRD_ISSUER, unlockUrl: UNLOCK_URL },
        ],
      );
      assert.equal(sent.length, 3);
      assert.deepEqual(
        sent.map((request) => request.issuerName),
        [ISSUER_NAME, BACKUP_ISSUER, THIRD_ISSUER],
      );
      assert.deepEqual(
        Object.keys(sent[0].sealed.periodKeys).sort(),
        [GROUP, SIBLING_GROUP].sort(),
      );
      assert.deepEqual(result.missing, []);
      for (const request of sent.slice(1)) {
        assert.deepEqual(Object.keys(request.sealed.contentKeys), []);
        assert.deepEqual(Object.keys(request.sealed.periodKeys), [GROUP]);
      }
      assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
    }
  });

  for (const status of [200, 403]) {
    test(`an independent same-identity ${status === 200 ? "silent answer" : "denial"} removes earlier operational eligibility`, async () => {
      const { markup } = await world({ issuerNames: [ISSUER_NAME, BACKUP_ISSUER, THIRD_ISSUER] });
      const sent = [];
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root: domOver(markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        transport: {
          async post(_url, request) {
            sent.push(request);
            if (sent.length === 1) throw Object.assign(new Error("offline"), { code: "offline" });
            return { status, contentType: "application/json", body: { keys: { contentKeys: {} } } };
          },
        },
      });
      const result = await client.unlockRoutes(
        [CONTENT_NAME],
        [
          { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, retryOperational: true },
          { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL, independent: true },
          { issuerName: THIRD_ISSUER, unlockUrl: UNLOCK_URL },
        ],
      );
      assert.deepEqual(
        sent.map((request) => request.issuerName),
        [ISSUER_NAME, BACKUP_ISSUER],
      );
      assert.deepEqual(
        sent.map((request) => Object.keys(request.sealed.contentKeys)),
        [[CONTENT_NAME], [CONTENT_NAME]],
      );
      assert.deepEqual(result.missing, [CONTENT_NAME]);
    });
  }

  test("an independent item_b result preserves the failed item_a route for conditional recovery", async () => {
    const names = [ISSUER_NAME, BACKUP_ISSUER, THIRD_ISSUER];
    const keys = await Promise.all(names.map(() => issuerKeypair()));
    const signing = await signingKeypair();
    const sealer = new Sealer({
      origin: PUB,
      clock: new Clock(AT),
      random: new Random({ seed: 19 }),
      signingKeys: { [SIGNING_KID]: signing.privateKey },
      issuerSupplyPlanFor: ({ issuerName }) => ({
        contentKeyNames:
          issuerName === ISSUER_NAME
            ? ["item_a"]
            : issuerName === BACKUP_ISSUER
              ? ["item_b"]
              : ["item_a", "item_b"],
        suppliedAccessGroups: [],
      }),
      issuers: names.map((issuerName, index) => ({
        issuerName,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: keys[index].publicKey,
      })),
    });
    sealer.resource("distinct-route-identities", {});
    sealer.content("item_a", "article A", "text/plain");
    sealer.content("item_b", "article B", "text/plain");
    const rendered = await sealer.seal();
    const registration = new PublisherRegistrations([
      {
        kid: SIGNING_KID,
        publicKey: signing.publicKey,
        origin: PUB,
        openingKeys: openingKeysOver(
          {
            get(issuerName, keyId) {
              const index = names.indexOf(issuerName);
              return index >= 0 && keyId === KEY_ID
                ? { algorithm: "ecdh-p256", privateKey: keys[index].privateKey }
                : undefined;
            },
          },
          names.map((issuerName) => ({ issuerName, keyId: KEY_ID })),
        ),
      },
    ]).get(SIGNING_KID);
    const processor = new IssuerProcessor(
      new IssuerEngine({ operatingIssuerNames: names, accessPolicy: new AllowAllPolicy() }),
      { periodKeyInput: false },
    );
    const endpoint = new UnlockEndpoint(processor);
    for (const itemBMode of ["valid", "wrong-key"]) {
      const sent = [];
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root: domOver(writeMarkupDelivery(rendered), { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        transport: {
          async post(url, request) {
            sent.push({ url, request });
            if (request.issuerName === ISSUER_NAME)
              throw Object.assign(new Error("offline"), { code: "offline" });
            if (request.issuerName === BACKUP_ISSUER && itemBMode === "wrong-key")
              return {
                status: 200,
                contentType: "application/json",
                body: {
                  keys: { contentKeys: { item_b: encoded(new Uint8Array(16).fill(0x93)) } },
                },
              };
            return {
              ...(await unlockThroughAdmission(processor, endpoint, request, registration)),
              contentType: "application/json",
            };
          },
        },
      });
      const result = await client.unlockRoutes(
        ["item_a", "item_b"],
        names.map((issuerName, index) => ({
          issuerName,
          unlockUrl: `https://${issuerName}.example/unlock`,
          ...(index === 0 ? { retryOperational: true } : {}),
          ...(index === 1 ? { independent: true } : {}),
        })),
      );
      assert.deepEqual(
        sent.map(({ request }) => request.issuerName),
        names,
      );
      assert.deepEqual(
        sent.map(({ request }) => Object.keys(request.sealed.contentKeys)),
        [["item_a"], ["item_b"], ["item_a"]],
      );
      for (const { url, request } of sent) {
        assert.equal(url, `https://${request.issuerName}.example/unlock`);
        assert.deepEqual(Object.keys(request.sealed), ["contentKeys"]);
        assert.equal(Object.hasOwn(request, "requestedPeriodKeys"), false);
      }
      assert.deepEqual(result.missing, itemBMode === "valid" ? [] : ["item_b"]);
      assert.equal(utf8Decode((await client.openLocal("item_a")).bytes), "article A");
      if (itemBMode === "valid") {
        assert.equal(utf8Decode((await client.openLocal("item_b")).bytes), "article B");
      } else {
        await assert.rejects(client.openLocal("item_b"), { code: "decrypt_failed" });
      }
    }
  });

  test("an initial operational failure cannot offer identities the first issuer never received", async () => {
    const { markup, unlock: answer } = await world({
      periodKeyInput: true,
      accessGroups: [GROUP, SIBLING_GROUP],
      issuerNames: [ISSUER_NAME, BACKUP_ISSUER],
      issuerSupplyPlanFor: (issuer) =>
        issuer.issuerName === ISSUER_NAME
          ? { contentKeyNames: [], suppliedAccessGroups: [GROUP] }
          : { contentKeyNames: [CONTENT_NAME], suppliedAccessGroups: [GROUP, SIBLING_GROUP] },
    });
    for (const failure of ["status", "transport"]) {
      const sent = [];
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root: domOver(markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        relayPeriodKeys: true,
        transport: {
          async post(_url, request) {
            sent.push(request);
            if (sent.length === 1) {
              if (failure === "transport")
                throw Object.assign(new Error("timeout"), { code: "timeout" });
              return { status: 503, body: null };
            }
            return { ...(await answer(request)), contentType: "application/json" };
          },
        },
      });
      const result = await client.unlockRoutes(
        [CONTENT_NAME],
        [
          { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, retryOperational: true },
          { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL },
        ],
      );
      assert.deepEqual(
        sent.map((request) => request.issuerName),
        [ISSUER_NAME, BACKUP_ISSUER],
      );
      assert.deepEqual(Object.keys(sent[0].sealed.contentKeys), []);
      assert.deepEqual(Object.keys(sent[0].sealed.periodKeys), [GROUP]);
      assert.deepEqual(
        Object.keys(sent[1].sealed.contentKeys),
        [],
        "B's extra item route is excluded",
      );
      assert.deepEqual(
        Object.keys(sent[1].sealed.periodKeys),
        [GROUP],
        "B's extra family is excluded",
      );
      assert.deepEqual(result.missing, []);
      assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
    }
  });

  test("an indeterminate transport result is terminal for fallback but permits an independent route", async () => {
    const names = [ISSUER_NAME, BACKUP_ISSUER, THIRD_ISSUER];
    const { markup } = await world({ issuerNames: names });
    const sent = [];
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport: {
        async post(_url, request) {
          sent.push(request);
          if (request.issuerName === ISSUER_NAME)
            throw Object.assign(new Error("Fetch did not expose a response"), {
              code: "indeterminate_transport",
            });
          return { status: 403, body: {} };
        },
      },
    });

    const result = await client.unlockRoutes(
      [CONTENT_NAME],
      names.map((issuerName, index) => ({
        issuerName,
        unlockUrl: UNLOCK_URL,
        ...(index === 0 ? { retryOperational: true } : {}),
        ...(index === 2 ? { independent: true } : {}),
      })),
    );

    assert.deepEqual(
      sent.map((request) => request.issuerName),
      [ISSUER_NAME, THIRD_ISSUER],
      "indeterminate failure cannot activate the conditional second route",
    );
    assert.deepEqual(Object.keys(sent[1].sealed.contentKeys), [CONTENT_NAME]);
    assert.deepEqual(result.missing, [CONTENT_NAME]);
    assert.deepEqual(result.attempts, [
      { issuerName: ISSUER_NAME, outcome: "indeterminate" },
      { issuerName: THIRD_ISSUER, status: 403, outcome: "answered" },
    ]);
  });

  test("malformed route responses are contained, while untyped transport errors remain visible", async () => {
    const names = [ISSUER_NAME, BACKUP_ISSUER, THIRD_ISSUER];
    for (const malformed of [
      { label: "non-JSON 200", answer: { status: 200, contentType: "text/plain", body: {} } },
      {
        label: "resolver response refusal",
        answer: {
          status: 200,
          contentType: "application/json",
          body: { keys: { contentKeys: {} } },
        },
        resolverFailure: dcaError("bad_response", "test malformed protocol response"),
      },
      {
        label: "malformed family report",
        outcome: "answered",
        answer: {
          status: 200,
          contentType: "application/json",
          body: {
            keys: { contentKeys: {} },
            notDelivered: { [GROUP]: { reason: "unknown" } },
          },
        },
      },
    ]) {
      const { markup } = await world({ issuerNames: names });
      const sent = [];
      const { resolverFactory: makeResolver } = countingResolver();
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root: domOver(markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        transport: {
          async post(_url, request) {
            sent.push(request);
            if (request.issuerName === ISSUER_NAME) return malformed.answer;
            return { status: 403, body: {} };
          },
        },
        ...(malformed.resolverFailure
          ? {
              resolverFactory(options) {
                const resolver = makeResolver(options);
                return {
                  ...resolver,
                  applyResponse() {
                    throw malformed.resolverFailure;
                  },
                };
              },
            }
          : {}),
      });
      const result = await client.unlockRoutes(
        [CONTENT_NAME],
        names.map((issuerName, index) => ({
          issuerName,
          unlockUrl: UNLOCK_URL,
          ...(index === 0 ? { retryUnavailable: true } : {}),
          ...(index === 2 ? { independent: true } : {}),
        })),
      );

      assert.deepEqual(
        sent.map((request) => request.issuerName),
        [ISSUER_NAME, THIRD_ISSUER],
        `${malformed.label}: unusable response does not activate a conditional route`,
      );
      assert.deepEqual(Object.keys(sent[1].sealed.contentKeys), [CONTENT_NAME]);
      assert.deepEqual(result.missing, [CONTENT_NAME]);
      assert.deepEqual(result.attempts[0], {
        issuerName: ISSUER_NAME,
        status: malformed.answer.status,
        outcome: malformed.outcome ?? "unusable-response",
      });
    }

    for (const malformedAnswer of [undefined, { status: 600 }]) {
      const { markup } = await world({ issuerNames: names });
      const sent = [];
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root: domOver(markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        transport: {
          async post(_url, request) {
            sent.push(request);
            return request.issuerName === ISSUER_NAME ? malformedAnswer : { status: 403, body: {} };
          },
        },
      });
      await assert.rejects(
        client.unlockRoutes(
          [CONTENT_NAME],
          names.map((issuerName) => ({ issuerName, unlockUrl: UNLOCK_URL, independent: true })),
        ),
        { code: "bad_response" },
        "a malformed host transport answer is a visible adapter contract failure",
      );
      assert.deepEqual(
        sent.map((request) => request.issuerName),
        [ISSUER_NAME],
      );
    }

    const { markup } = await world({ issuerNames: names });
    let posts = 0;
    const client = createBrowserClient({
      unlockUrl: UNLOCK_URL,
      root: domOver(markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport: {
        async post() {
          posts++;
          throw new TypeError("host transport programming error");
        },
      },
    });
    await assert.rejects(
      client.unlockRoutes(
        [CONTENT_NAME],
        names.map((issuerName) => ({ issuerName, unlockUrl: UNLOCK_URL, independent: true })),
      ),
      (error) => error instanceof TypeError && /programming error/.test(error.message),
    );
    assert.equal(posts, 1, "an untyped adapter/programming error is not hidden by another route");
  });
});

/**
 * A resolver that counts what the entry hands it and forwards to the one the
 * composition built, so a test can see whether an answer reached it.
 *
 * @returns {{ resolverFactory: (options: object) => any, seen: { applyResponse: number, resolveDetailed: number } }}
 */
function countingResolver() {
  const seen = { applyResponse: 0, resolveDetailed: 0 };
  return {
    seen,
    resolverFactory(options) {
      const inner = new ContentKeyResolver(/** @type {any} */ (options));
      return {
        clearReaderContext: () => inner.clearReaderContext(),
        /** @param {any[]} args */
        applyResponse(...args) {
          seen.applyResponse++;
          return inner.applyResponse(.../** @type {[any, any, any, any]} */ (args));
        },
        /** @param {any[]} args */
        resolveDetailed(...args) {
          seen.resolveDetailed++;
          return inner.resolveDetailed(.../** @type {[any, any, any]} */ (args));
        },
        /** @param {any[]} args */
        resolve: (...args) => inner.resolve(.../** @type {[any, any]} */ (args)),
        /** @param {any[]} args */
        contentKeyFor: (...args) => inner.contentKeyFor(.../** @type {[any, any]} */ (args)),
        /** @param {any[]} args */
        contentKeyWithOriginFor: (...args) =>
          inner.contentKeyWithOriginFor(.../** @type {[any, any]} */ (args)),
        /** @param {any[]} args */
        /** @param {any[]} args */
        resolveAuthenticated: (...args) =>
          inner.resolveAuthenticated(.../** @type {[any, any, any, any]} */ (args)),
        contentKeyForAuthenticatedItem: (...args) =>
          inner.contentKeyForAuthenticatedItem(.../** @type {[any, any, any]} */ (args)),
      };
    },
  };
}

describe("What the entry admits from the issuer's answer", () => {
  test("a 200 whose JSON value is not a non-array object is refused before the resolver", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    /** @type {[string, { body?: any }][]} */
    const cases = [
      ["a string", { body: "keys" }],
      ["a number", { body: 42 }],
      ["a boolean", { body: true }],
      ["an array", { body: [] }],
      ["null", { body: null }],
      ["no body at all", {}],
    ];
    for (const [kind, answer] of cases) {
      const { resolverFactory, seen } = countingResolver();
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root,
        issuerName: ISSUER_NAME,
        transport: {
          async post() {
            return { status: 200, contentType: "application/json", ...answer };
          },
        },
        resolverFactory,
      });
      await refuses(
        () => client.unlock([CONTENT_NAME]),
        { code: "bad_response", message: /non-array object/ },
        `${kind} at 200 is a malformed answer, and the entry says so`,
      );
      assert.deepEqual(
        seen,
        { applyResponse: 0, resolveDetailed: 0 },
        `${kind} at 200 never reaches the resolver`,
      );
      assert.equal(
        (await client.resolver.contentKeyWithOriginFor(client.dcaData, CONTENT_NAME)).key,
        null,
        `${kind} at 200 leaves no key behind`,
      );
    }
  });

  test("a 200 without a JSON media type supplies no DCA result, even when its body is a grant", async () => {
    const { markup, unlock: answer } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    /** @type {[string, { contentType?: any }][]} */
    const cases = [
      ["no content type", {}],
      ["text/html", { contentType: "text/html" }],
      ["text/json", { contentType: "text/json" }],
      ["application/json-seq", { contentType: "application/json-seq" }],
      ["application/jsonx", { contentType: "application/jsonx" }],
      ["an empty content type", { contentType: "" }],
      ["a content type that is not a string", { contentType: ["application/json"] }],
    ];
    for (const [kind, media] of cases) {
      const { resolverFactory, seen } = countingResolver();
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root,
        issuerName: ISSUER_NAME,
        transport: {
          /** @param {string} url @param {object} request */
          async post(url, request) {
            const { status, body } = await answer(request);
            return { status, body, ...media };
          },
        },
        resolverFactory,
      });
      await refuses(
        () => client.unlock([CONTENT_NAME]),
        { code: "bad_response", message: /application\/json/ },
        `${kind}: the answer is not a DCA result`,
      );
      assert.deepEqual(
        seen,
        { applyResponse: 0, resolveDetailed: 0 },
        `${kind}: the grant in the body never reaches the resolver`,
      );
      assert.equal(
        (await client.resolver.contentKeyWithOriginFor(client.dcaData, CONTENT_NAME)).key,
        null,
        `${kind}: the grant in the body leaves no key behind`,
      );
    }
  });

  test("application/json is read by type and subtype, whatever its case and parameters", async () => {
    for (const contentType of [
      "application/json",
      "Application/JSON",
      "application/json; charset=utf-8",
      "application/json;charset=UTF-8",
    ]) {
      const { markup, unlock: answer } = await world();
      const root = domOver(markup, { publisherOrigin: PUB });
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root,
        issuerName: ISSUER_NAME,
        transport: {
          /** @param {string} url @param {object} request */
          async post(url, request) {
            return { ...(await answer(request)), contentType };
          },
        },
      });
      const result = await client.unlock([CONTENT_NAME]);
      assert.equal(result.status, 200, contentType);
      assert.ok(result.application.accepted > 0, `${contentType}: the grant is applied`);
    }
  });

  test("a redirect comes back as the status it is, and nothing is applied", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    for (const status of [301, 302, 303, 307, 308]) {
      const { resolverFactory, seen } = countingResolver();
      const body = { keys: { contentKeys: {} } };
      let posts = 0;
      const client = createBrowserClient({
        unlockUrl: UNLOCK_URL,
        root,
        issuerName: ISSUER_NAME,
        transport: {
          async post() {
            posts++;
            return { status, contentType: "application/json", body };
          },
        },
        resolverFactory,
      });
      const result = await client.unlock([CONTENT_NAME]);
      assert.deepEqual(result, { status, body, application: null }, `${status}`);
      assert.equal(posts, 1, `${status}: the entry follows nothing`);
      assert.deepEqual(seen, { applyResponse: 0, resolveDetailed: 0 }, `${status}`);
    }
  });
});

/**
 * A transport that records each URL it is handed and answers 503, so a test
 * can see whether a refused URL ever reached it.
 *
 * @returns {{ transport: { post: (url: string) => Promise<{ status: number, body: null }> }, urls: string[] }}
 */
function recordingTransport() {
  /** @type {string[]} */
  const urls = [];
  return {
    urls,
    transport: {
      /** @param {string} url */
      async post(url) {
        urls.push(url);
        return { status: 503, body: null };
      },
    },
  };
}

describe("Which unlock URL the entry admits", () => {
  test("a URL that is not absolute https is refused before the transport", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    /** @type {[string, string][]} */
    const cases = [
      ["production http", "http://api.example.com/unlock"],
      ["a path with no scheme or host", "/unlock"],
      ["a host with no scheme", "api.example.com/unlock"],
      ["a user and password", "https://reader:secret@api.example.com/unlock"],
      ["a user alone", "https://reader@api.example.com/unlock"],
      ["a fragment", "https://api.example.com/unlock#grant"],
      ["an empty fragment", "https://api.example.com/unlock#"],
      ["ftp", "ftp://api.example.com/unlock"],
      ["wss", "wss://api.example.com/unlock"],
      ["a blob URL over an https origin", "blob:https://api.example.com/0f1e"],
      ["javascript", "javascript:void(0)"],
      ["data", "data:application/json,{}"],
    ];
    for (const [kind, unlockUrl] of cases) {
      const { transport, urls } = recordingTransport();
      await refuses(
        () => createBrowserClient({ root, issuerName: ISSUER_NAME, unlockUrl, transport }),
        { code: "bad_config", message: /unlock URL/ },
        `${kind}: ${unlockUrl} is no unlock URL`,
      );
      assert.deepEqual(urls, [], `${kind}: the transport is never called`);
    }
  });

  test("no host endpoint sends no request, regardless of a carried URL", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    const { transport, urls } = recordingTransport();
    for (const unlockUrl of [undefined, null]) {
      const client = createBrowserClient({ root, issuerName: ISSUER_NAME, unlockUrl, transport });
      await refuses(() => client.unlock([CONTENT_NAME]), {
        code: "bad_config",
        message: /no trusted unlock endpoint/,
      });
      assert.deepEqual(urls, []);
    }
  });

  test("loopback http is refused unless the host selects the development profile", async () => {
    const loopback = [
      "http://localhost/unlock",
      "http://localhost:8787/unlock",
      "http://issuer.localhost:8787/unlock",
      "http://127.0.0.1:8787/unlock?site=news",
    ];
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    for (const unlockUrl of loopback) {
      for (const selection of [{}, { developmentHttpOrigin: false }]) {
        const { transport, urls } = recordingTransport();
        await refuses(
          () =>
            createBrowserClient({
              root,
              issuerName: ISSUER_NAME,
              unlockUrl,
              transport,
              ...selection,
            }),
          { code: "bad_config", message: /unlock URL/ },
          `${unlockUrl} with ${JSON.stringify(selection)}: production refuses http`,
        );
        assert.deepEqual(urls, [], `${unlockUrl}: the transport is never called`);
      }

      const { transport, urls } = recordingTransport();
      const client = createBrowserClient({
        root,
        issuerName: ISSUER_NAME,
        unlockUrl,
        transport,
        developmentHttpOrigin: true,
      });
      await client.unlock([CONTENT_NAME]);
      assert.deepEqual(urls, [unlockUrl], `${unlockUrl}: the development profile admits it`);
    }
  });

  test("the development profile admits http for a loopback host and for nothing else", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    for (const unlockUrl of [
      "http://api.example.com/unlock",
      "http://localhost.example/unlock",
      "http://127.0.0.2/unlock",
      "http://10.0.0.1/unlock",
      "http://[::1]/unlock",
      "http://reader:secret@localhost/unlock",
      "http://localhost/unlock#grant",
    ]) {
      const { transport, urls } = recordingTransport();
      await refuses(
        () =>
          createBrowserClient({
            root,
            issuerName: ISSUER_NAME,
            unlockUrl,
            transport,
            developmentHttpOrigin: true,
          }),
        { code: "bad_config", message: /unlock URL/ },
        `${unlockUrl}: the development profile does not widen past loopback`,
      );
      assert.deepEqual(urls, [], `${unlockUrl}: the transport is never called`);
    }
  });

  test("an https URL keeps its path and query", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    const unlockUrl = "https://api.example.com:8443/v1/unlock?site=news&edition=nordic";
    const { transport, urls } = recordingTransport();
    const client = createBrowserClient({ root, issuerName: ISSUER_NAME, unlockUrl, transport });
    await client.unlock([CONTENT_NAME]);
    assert.deepEqual(urls, [unlockUrl]);
  });

  test("the development profile is on or off, and nothing else", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    for (const developmentHttpOrigin of ["true", 1, 0, null, {}]) {
      const { transport, urls } = recordingTransport();
      await refuses(
        () =>
          createBrowserClient({
            unlockUrl: UNLOCK_URL,
            root,
            issuerName: ISSUER_NAME,
            transport,
            developmentHttpOrigin: /** @type {any} */ (developmentHttpOrigin),
          }),
        { code: "bad_config", message: /developmentHttpOrigin/ },
        `${JSON.stringify(developmentHttpOrigin)} is no profile selection`,
      );
      assert.deepEqual(urls, [], "the transport is never called");
    }
  });
});

/**
 * Real item ciphertext and wraps with a controlled issuer response boundary.
 * Each item is sealed under its derived content AAD, so a declared encoding
 * list belongs in `bodytextEncodings` rather than in a later edit.
 *
 * @param {{ bodytextEncodings?: string[] }} [options]
 */
async function obtainingFixture({ bodytextEncodings } = {}) {
  const key = new Uint8Array(16).fill(31);
  const nonce = new Uint8Array(12).fill(23);
  const names = ["bodytext", "teaser"];
  const ciphertexts = new Map();
  const contentData = {};
  const contentKeys = {};
  const resource = { origin: PUB, resourceId: "article", renderId: "AAAAAAAAAAAAAAAAAAAAAA" };
  const jwt = `${encoded(utf8Encode(JSON.stringify({ alg: "ES256", kid: "k1" })))}.${encoded(utf8Encode(JSON.stringify(resource)))}.c2lnbmF0dXJl`;
  for (const [i, name] of names.entries()) {
    const contentKey = new Uint8Array(16).fill(42 + i);
    contentKeys[name] = encoded(contentKey);
    contentData[name] = {
      contentType: "text/plain",
      nonce: encoded(nonce),
      ...(name === "bodytext" && bodytextEncodings ? { contentEncodings: bodytextEncodings } : {}),
      keys: {
        [GROUP]: [
          { t: T_NOW, nonce: encoded(nonce), key: encoded(await encrypt(key, nonce, contentKey)) },
        ],
      },
    };
    const aad = contentAadOctets({ resourceJWT: jwt, contentData }, name);
    ciphertexts.set(
      name,
      encoded(await encrypt(contentKey, new Uint8Array(12), utf8Encode(name), aad)),
    );
  }
  const raw = {
    version: "1",
    resource,
    resourceJWT: jwt,
    contentData,
    issuerData: Object.fromEntries(
      [ISSUER_NAME, BACKUP_ISSUER].map((name) => [
        name,
        {
          keyId: KEY_ID,
          unlockUrl: UNLOCK_URL,
          sealed: {
            contentKeys: Object.fromEntries(names.map((item) => [item, "AA"])),
            periodKeys: { [GROUP]: { [T_NOW]: "AA" } },
          },
        },
      ]),
    ),
  };
  return {
    raw,
    key,
    contentKeys,
    reader: {
      dcaData: raw,
      publisherOrigin: PUB,
      extract: (name) => ciphertexts.get(name) ?? null,
    },
  };
}

test("wrong held grant then evicted period response authenticates every obtaining item", async () => {
  const fixture = await obtainingFixture();
  const posts = [];
  const cache = new PeriodKeyCache({ clock: new Clock(AT), evictionPolicy: () => true });
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: fixture.reader,
    issuerName: ISSUER_NAME,
    cache,
    relayPeriodKeys: true,
    transport: {
      async post(_url, request) {
        posts.push(request);
        return {
          status: 200,
          contentType: "application/json",
          body: {
            keys:
              request.issuerName === ISSUER_NAME
                ? {
                    contentKeys: {
                      bodytext: encoded(new Uint8Array(16).fill(9)),
                      teaser: encoded(new Uint8Array(16).fill(10)),
                    },
                  }
                : { periodKeys: { [GROUP]: { [T_NOW]: encoded(fixture.key) } } },
          },
        };
      },
    },
  });
  const result = await client.unlockRoutes(
    ["bodytext", "teaser"],
    [
      { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
      { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL, independent: true },
    ],
  );
  assert.deepEqual(result.missing, []);
  assert.deepEqual(result.failed, []);
  assert.equal(posts.length, 2);
  assert.deepEqual(await cache.entries(), [], "reusable material is immediately evicted");
  for (const name of ["bodytext", "teaser"])
    assert.equal(utf8Decode((await client.openLocal(name)).bytes), name);
});

test("item-local route preflight preserves valid siblings and excludes failed request coordinates", async () => {
  for (const fault of ["unsupported", "record", "cipher-width"]) {
    const fixture = await obtainingFixture();
    if (fault === "unsupported") fixture.raw.contentData.bodytext.contentEncodings = ["unknown"];
    if (fault === "record") fixture.raw.contentData.bodytext.contentType = null;
    const reader = {
      ...fixture.reader,
      extract: (name) =>
        fault === "cipher-width" && name === "bodytext" ? "AA" : fixture.reader.extract(name),
    };
    const posts = [];
    const client = createDeliveryClient({
      unlockUrl: UNLOCK_URL,
      reader,
      issuerName: ISSUER_NAME,
      transport: {
        async post(_url, request) {
          posts.push(request);
          return {
            status: request.issuerName === ISSUER_NAME ? 403 : 200,
            contentType: "application/json",
            body:
              request.issuerName === ISSUER_NAME
                ? {}
                : { keys: { contentKeys: { teaser: fixture.contentKeys.teaser } } },
          };
        },
      },
    });
    const result = await client.unlockRoutes(
      ["bodytext", "teaser"],
      [
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
        { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL, independent: true },
      ],
    );
    assert.deepEqual(result.failed, [
      { name: "bodytext", code: fault === "unsupported" ? "unsupported_encoding" : "bad_page" },
    ]);
    assert.deepEqual(result.missing, []);
    assert.equal(posts.length, 2);
    for (const request of posts)
      assert.deepEqual(Object.keys(request.sealed.contentKeys), ["teaser"]);
    assert.equal(utf8Decode((await client.openLocal("teaser")).bytes), "teaser");
  }
});

test("ordinary unlock skips a request with no eligible coordinates without inventing HTTP", async () => {
  const fixture = await obtainingFixture();
  let posts = 0;
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: fixture.reader,
    issuerName: ISSUER_NAME,
    transport: {
      async post() {
        posts++;
        return { status: 403 };
      },
    },
  });
  assert.deepEqual(await client.unlock([]), { skipped: "no-eligible-route", application: null });
  assert.deepEqual(await client.unlock(["absent"]), {
    skipped: "no-eligible-route",
    application: null,
  });
  assert.equal(posts, 0);
});

test("route coverage ignores malformed wrap labels before cache access and preserves storage faults", async () => {
  const fixture = await obtainingFixture();
  for (const record of Object.values(fixture.raw.contentData)) {
    const wrap = record.keys[GROUP][0];
    record.keys[GROUP] = [{ ...wrap, t: "" }, wrap, { ...wrap, t: "bogus" }];
  }
  const reads = [];
  let posts = 0;
  const cache = {
    put() {},
    attempted() {},
    candidatesAt(_group, t) {
      reads.push(t);
      return [fixture.key];
    },
  };
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: fixture.reader,
    issuerName: ISSUER_NAME,
    cache,
    transport: {
      async post() {
        posts++;
        return { status: 403 };
      },
    },
  });
  const result = await client.unlockRoutes(
    ["bodytext", "teaser"],
    [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL }],
  );
  assert.deepEqual(result, { missing: [], attempts: [], failed: [] });
  assert.deepEqual(reads, [T_NOW, T_NOW]);
  assert.equal(posts, 0);
  const fault = dcaError("bad_storage", "unreadable backing");
  const faulty = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: fixture.reader,
    issuerName: ISSUER_NAME,
    cache: {
      put() {},
      attempted() {},
      candidatesAt() {
        throw fault;
      },
    },
    transport: {
      async post() {
        posts++;
        return { status: 403 };
      },
    },
  });
  await assert.rejects(
    faulty.unlockRoutes(
      ["bodytext", "teaser"],
      [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL }],
    ),
    (cause) => cause === fault,
  );
  assert.equal(posts, 0);
});

test("ordinary open preflights its used item before its own cache or acquisition work", async () => {
  for (const fault of ["unsupported", "list", "record", "ciphertext"]) {
    const fixture = await obtainingFixture();
    let decodes = 0,
      reads = 0,
      posts = 0;
    fixture.raw.contentData.bodytext.contentEncodings = ["known", "unknown"];
    if (fault !== "unsupported") fixture.raw.contentData.bodytext.contentEncodings = ["known"];
    if (fault === "list") fixture.raw.contentData.bodytext.contentEncodings = [];
    if (fault === "record") fixture.raw.contentData.bodytext.contentType = null;
    const client = createDeliveryClient({
      unlockUrl: UNLOCK_URL,
      reader: {
        ...fixture.reader,
        extract: (name) =>
          fault === "ciphertext" && name === "bodytext" ? "AA" : fixture.reader.extract(name),
      },
      issuerName: ISSUER_NAME,
      contentDecoders: {
        known(bytes) {
          decodes++;
          return bytes;
        },
      },
      cache: {
        put() {},
        attempted() {},
        candidatesAt() {
          reads++;
          return [];
        },
      },
      transport: {
        async post() {
          posts++;
          return { status: 403 };
        },
      },
    });
    await assert.rejects(client.open("bodytext"), {
      code: fault === "unsupported" ? "unsupported_encoding" : "bad_page",
    });
    assert.deepEqual({ reads, posts, decodes }, { reads: 0, posts: 0, decodes: 0 }, fault);
  }
});

test("ordinary open keeps pure admission and later decoding separate; host faults remain visible", async () => {
  const fixture = await obtainingFixture({ bodytextEncodings: ["known"] });
  let decodes = 0,
    posts = 0;
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: fixture.reader,
    issuerName: ISSUER_NAME,
    contentDecoders: {
      known(bytes) {
        decodes++;
        return bytes;
      },
    },
    transport: {
      async post() {
        posts++;
        assert.equal(decodes, 0);
        return {
          status: 200,
          contentType: "application/json",
          body: { keys: { contentKeys: { bodytext: fixture.contentKeys.bodytext } } },
        };
      },
    },
  });
  assert.equal(utf8Decode((await client.open("bodytext")).bytes), "bodytext");
  assert.equal(posts, 1);
  assert.equal(decodes, 1);
  for (const code of ["bad_storage", "bad_config"]) {
    const fault = dcaError(code, "host fault");
    const faulty = createDeliveryClient({
      unlockUrl: UNLOCK_URL,
      reader: fixture.reader,
      issuerName: ISSUER_NAME,
      contentDecoders: { known: (bytes) => bytes },
      cache: {
        put() {},
        attempted() {},
        candidatesAt() {
          throw fault;
        },
      },
      transport: {
        async post() {
          throw new Error("no acquisition after fault");
        },
      },
    });
    await assert.rejects(faulty.open("bodytext"), (cause) => cause === fault);
  }
});

describe("Browser denied unlock scheduling", () => {
  const noAccess = { decide: () => ({ contentNames: [], periodGrants: [] }) };
  const storage = () => {
    const values = new Map();
    return {
      getItem: (key) => values.get(key) ?? null,
      setItem: (key, value) => {
        values.set(key, value);
      },
      removeItem: (key) => {
        values.delete(key);
      },
    };
  };

  test("a complete denial survives reload, expires and clears on access-context change", async () => {
    const page = await world({
      contentKeys: false,
      periodKeyInput: true,
      accessPolicy: noAccess,
      notDeliveredReport: "complete",
    });
    let now = 1000;
    const held = storage();
    const cache = () =>
      new DeniedUnlockCache({ storage: held, context: "reader-a", now: () => now });
    const make = (denialCache = cache()) =>
      createBrowserClient({
        root: domOver(page.markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        unlockUrl: UNLOCK_URL,
        acceptDirectResponse: true,
        relayPeriodKeys: true,
        transport: {
          post: async (_url, request) => ({
            ...(await page.unlock(request)),
            contentType: "application/json",
          }),
        },
        denialCache,
      });
    assert.equal((await make().unlock([CONTENT_NAME])).status, 200);
    assert.equal((await make().unlock([CONTENT_NAME])).skipped, "cached-denial");
    assert.equal(page.calls.count, 1);
    now += 600000;
    assert.equal((await make().unlock([CONTENT_NAME])).status, 200);
    const changed = cache();
    changed.setContext("reader-b");
    assert.equal((await make(changed).unlock([CONTENT_NAME])).status, 200);
    changed.invalidate();
    assert.equal((await make(changed).unlock([CONTENT_NAME])).status, 200);
    assert.equal(page.calls.count, 4);
  });

  test("HTTP refusals, failures, empty, unavailable and malformed results never imply denial", async () => {
    const page = await world({ contentKeys: false });
    for (const answer of [
      { status: 401 },
      { status: 403 },
      { status: 429 },
      { status: 503 },
      { status: 200, body: {} },
      { status: 200, body: { notDelivered: { [GROUP]: { reason: "unavailable" } } } },
      { status: 200, body: { notDelivered: { invented: { reason: "denied" } } } },
    ]) {
      let calls = 0;
      const client = createBrowserClient({
        root: domOver(page.markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        unlockUrl: UNLOCK_URL,
        acceptDirectResponse: true,
        relayPeriodKeys: true,
        transport: {
          post: async () => {
            calls++;
            return { ...answer, contentType: "application/json" };
          },
        },
      });
      await client.unlock([CONTENT_NAME]);
      await client.unlock([CONTENT_NAME]);
      assert.equal(calls, 2);
    }
  });

  test("partial denial cannot suppress an independent item-key request", async () => {
    const page = await world();
    let calls = 0;
    const client = createBrowserClient({
      root: domOver(page.markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      acceptDirectResponse: true,
      relayPeriodKeys: true,
      transport: {
        post: async () => {
          calls++;
          return {
            status: 200,
            contentType: "application/json",
            body: { notDelivered: { [GROUP]: { reason: "denied" } } },
          };
        },
      },
    });
    await client.unlock([CONTENT_NAME]);
    await client.unlock([CONTENT_NAME]);
    assert.equal(calls, 2);
  });

  test("lower-level delivery clients have no automatic denial cache", async () => {
    const page = await world({ contentKeys: false });
    let calls = 0;
    const reader = new MarkupDeliveryReader(domOver(page.markup, { publisherOrigin: PUB }));
    const client = createDeliveryClient({
      reader,
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      acceptDirectResponse: true,
      relayPeriodKeys: true,
      transport: {
        post: async () => {
          calls++;
          return {
            status: 200,
            contentType: "application/json",
            body: { notDelivered: { [GROUP]: { reason: "denied" } } },
          };
        },
      },
    });
    await client.unlock([CONTENT_NAME]);
    await client.unlock([CONTENT_NAME]);
    assert.equal(calls, 2);
  });

  test("a cached denial does not block local keys or activate conditional fallback", async () => {
    const page = await world({
      contentKeys: false,
      periodKeyInput: true,
      accessPolicy: noAccess,
      notDeliveredReport: "complete",
    });
    const client = createBrowserClient({
      root: domOver(page.markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      acceptDirectResponse: true,
      relayPeriodKeys: true,
      transport: {
        post: async (_url, request) => ({
          ...(await page.unlock(request)),
          contentType: "application/json",
        }),
      },
    });
    await client.unlock([CONTENT_NAME]);
    const walked = await client.unlockRoutes(
      [CONTENT_NAME],
      [
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, acceptDirectResponse: true },
        { issuerName: BACKUP_ISSUER, unlockUrl: UNLOCK_URL, acceptDirectResponse: true },
      ],
    );
    assert.deepEqual(walked.attempts, [{ issuerName: ISSUER_NAME, outcome: "cached-denial" }]);
    assert.equal(page.calls.count, 1);
    await client.cache.put(GROUP, T_NOW, PERIOD_KEYS[T_NOW], {
      publisher: PUB,
      issuerName: ISSUER_NAME,
    });
    assert.equal(utf8Decode((await client.open(CONTENT_NAME)).bytes), ARTICLE);
    assert.equal(page.calls.count, 1);
  });

  test("storage failures, finite capacity, expiry and explicit disabling remain usable", async () => {
    let now = 1000;
    const broken = {
      getItem() {
        throw new Error("blocked");
      },
      setItem() {
        throw new Error("quota");
      },
      removeItem() {
        throw new Error("blocked");
      },
    };
    const cache = new DeniedUnlockCache({ storage: broken, maxEntries: 1, now: () => now });
    const first = {
      publisherOrigin: PUB,
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      request: { id: 1 },
    };
    const second = { ...first, request: { id: 2 } };
    cache.deny(await cache.capture(first));
    assert.ok((await cache.capture(first)).retryAt);
    cache.deny(await cache.capture(second));
    assert.equal((await cache.capture(first)).retryAt, null);
    assert.ok((await cache.capture(second)).retryAt);
    now += 600000;
    assert.equal((await cache.capture(second)).retryAt, null);
    cache.invalidate();
    const page = await world({ contentKeys: false });
    let calls = 0;
    const client = createBrowserClient({
      root: domOver(page.markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      relayPeriodKeys: true,
      acceptDirectResponse: true,
      denialCache: false,
      transport: {
        post: async () => {
          calls++;
          return {
            status: 200,
            contentType: "application/json",
            body: { notDelivered: { [GROUP]: { reason: "denied" } } },
          };
        },
      },
    });
    await client.unlock([CONTENT_NAME]);
    await client.unlock([CONTENT_NAME]);
    assert.equal(calls, 2);
    assert.equal(client.denialCache, null);
  });

  test("shared storage invalidation prevents an older instance from refiling a pending denial", async () => {
    const held = storage();
    const old = new DeniedUnlockCache({ storage: held });
    const current = new DeniedUnlockCache({ storage: held });
    const input = {
      publisherOrigin: PUB,
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      request: { resourceJWT: "one" },
    };
    const pending = await old.capture(input);
    current.invalidate();
    old.deny(pending);
    assert.equal((await current.capture(input)).retryAt, null);
    old.deny(await old.capture(input));
    assert.ok((await current.capture(input)).retryAt);
    current.invalidate();
    assert.equal((await old.capture(input)).retryAt, null);
  });

  test("trusted host no-access marker suppresses different articles and clears on login/logout", async () => {
    const held = storage();
    let now = 1000;
    const cache = new DeniedUnlockCache({ context: "anonymous", storage: held, now: () => now });
    const scope = { publisherOrigin: PUB, issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL };
    await cache.denyContext(scope);
    for (const render of ["article-one", "article-two"])
      assert.equal(
        (await cache.capture({ ...scope, request: { resourceJWT: render } })).retryAt,
        601000,
      );
    for (const changed of [
      { ...scope, publisherOrigin: "https://other.example" },
      { ...scope, issuerName: BACKUP_ISSUER },
      { ...scope, unlockUrl: "https://other.example/unlock" },
    ])
      assert.equal((await cache.capture({ ...changed, request: {} })).retryAt, null);
    const reloaded = new DeniedUnlockCache({ context: "anonymous", storage: held, now: () => now });
    assert.ok((await reloaded.capture({ ...scope, request: { resourceJWT: "third" } })).retryAt);
    now += 600000;
    assert.equal((await reloaded.capture({ ...scope, request: {} })).retryAt, null);
    await cache.denyContext(scope);
    cache.setContext("logged-in-reader");
    assert.equal((await cache.capture({ ...scope, request: {} })).retryAt, null);
    await cache.denyContext(scope);
    cache.setContext("anonymous-after-logout");
    assert.equal((await cache.capture({ ...scope, request: {} })).retryAt, null);
    const pending = cache.denyContext(scope);
    cache.invalidate();
    await pending;
    assert.equal((await cache.capture({ ...scope, request: {} })).retryAt, null);
  });

  test("host marker skips real browser unlocks across separate deliveries and supports structural collaborators", async () => {
    const first = await world();
    const second = await world();
    const backing = new DeniedUnlockCache({ context: "anonymous" });
    const custom = {
      capture: backing.capture.bind(backing),
      deny: backing.deny.bind(backing),
      invalidate: backing.invalidate.bind(backing),
      setContext: backing.setContext.bind(backing),
      denyContext: backing.denyContext.bind(backing),
    };
    const scope = { publisherOrigin: PUB, issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL };
    await custom.denyContext(scope);
    let posts = 0;
    const make = (page) =>
      createBrowserClient({
        root: domOver(page.markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        unlockUrl: UNLOCK_URL,
        acceptDirectResponse: true,
        denialCache: custom,
        transport: {
          post: async (_url, request) => {
            posts++;
            return { ...(await page.unlock(request)), contentType: "application/json" };
          },
        },
      });
    assert.equal((await make(first).unlock([CONTENT_NAME])).skipped, "cached-denial");
    assert.equal((await make(second).unlock([CONTENT_NAME])).skipped, "cached-denial");
    assert.equal(posts, 0);
    custom.setContext("reader-after-login");
    assert.equal((await make(second).unlock([CONTENT_NAME])).status, 200);
    assert.equal(posts, 1);
  });

  test("storage write/read failures cannot resurrect a marker after local invalidation", async () => {
    for (const broad of [false, true]) {
      const held = storage();
      let failWrites = false;
      let failReads = false;
      const backend = {
        getItem: (key) => {
          if (failReads) throw new Error("blocked");
          return held.getItem(key);
        },
        setItem: (key, value) => {
          if (failWrites) throw new Error("quota");
          held.setItem(key, value);
        },
        removeItem: held.removeItem,
      };
      const cache = new DeniedUnlockCache({ storage: backend });
      const scope = { publisherOrigin: PUB, issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL };
      const input = { ...scope, request: { id: 1 } };
      if (broad) await cache.denyContext(scope);
      else cache.deny(await cache.capture(input));
      assert.ok((await cache.capture(input)).retryAt);
      failWrites = true;
      cache.invalidate();
      assert.equal((await cache.capture(input)).retryAt, null);
      failWrites = false;
      assert.equal((await cache.capture(input)).retryAt, null);
      const another = new DeniedUnlockCache({ storage: backend });
      assert.ok((await another.capture(input)).retryAt);
      failReads = true;
      assert.ok((await another.capture(input)).retryAt);
      another.invalidate();
      failReads = false;
      assert.equal((await another.capture(input)).retryAt, null);
    }
  });

  test("persisted eviction is authoritative across live cache instances", async () => {
    const held = storage();
    const first = new DeniedUnlockCache({ storage: held, maxEntries: 1 });
    const second = new DeniedUnlockCache({ storage: held, maxEntries: 1 });
    const scope = { publisherOrigin: PUB, issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL };
    const one = { ...scope, request: { id: 1 } };
    const two = { ...scope, request: { id: 2 } };
    first.deny(await first.capture(one));
    assert.ok((await second.capture(one)).retryAt);
    first.deny(await first.capture(two));
    assert.equal((await second.capture(one)).retryAt, null);
    assert.ok((await second.capture(two)).retryAt);
  });

  test("context invalidation rejects an old in-flight denial, and request changes keep separate hints", async () => {
    const cache = new DeniedUnlockCache();
    const input = {
      publisherOrigin: PUB,
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      request: { resourceJWT: "render-one", sealed: { periodKeys: { premium: { t: "seal" } } } },
    };
    const old = await cache.capture(input);
    cache.invalidate();
    cache.deny(old);
    assert.equal((await cache.capture(input)).retryAt, null);
    const current = await cache.capture(input);
    cache.deny(current);
    assert.ok((await cache.capture(input)).retryAt > 0);
    for (const changed of [
      { ...input, issuerName: BACKUP_ISSUER },
      { ...input, publisherOrigin: "https://other.example" },
      { ...input, unlockUrl: "https://other.example/unlock" },
      { ...input, request: { ...input.request, resourceJWT: "render-two" } },
    ])
      assert.equal((await cache.capture(changed)).retryAt, null);
  });
});

/** Controlled asynchronous boundary; tests wait for entry, never elapsed time. */
function resetBoundary() {
  let release;
  const promise = new Promise((resolve) => {
    release = resolve;
  });
  return { promise, release: (value = undefined) => release(value) };
}

describe("Browser reader lifecycle", () => {
  test("decision clear removes suppression without requesting or discarding granted keys", async () => {
    const page = await world({ contentKeys: false, periodKeyInput: true });
    let posts = 0;
    const denied = { notDelivered: { [GROUP]: { reason: "denied" } } };
    const gates = [resetBoundary(), resetBoundary()];
    const starts = [resetBoundary(), resetBoundary()];
    const client = createBrowserClient({
      root: domOver(page.markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      relayPeriodKeys: true,
      acceptDirectResponse: true,
      transport: {
        async post() {
          const index = posts++;
          if (index === 0) return { status: 200, contentType: "application/json", body: denied };
          if (index <= 2) {
            starts[index - 1].release();
            return {
              status: 200,
              contentType: "application/json",
              body: await gates[index - 1].promise,
            };
          }
          return { status: 200, contentType: "application/json", body: {} };
        },
      },
    });
    await client.unlock([CONTENT_NAME]);
    assert.equal((await client.unlock([CONTENT_NAME])).skipped, "cached-denial");
    await client.clearAccessDecisions();
    assert.equal(posts, 1);
    const lateDenial = client.unlock([CONTENT_NAME]);
    const positive = client.unlock([CONTENT_NAME]);
    await Promise.all(starts.map((entry) => entry.promise));
    await client.clearAccessDecisions();
    gates[0].release(denied);
    gates[1].release({
      keys: { periodKeys: { [GROUP]: { [T_NOW]: encoded(PERIOD_KEYS[T_NOW]) } } },
    });
    await Promise.all([lateDenial, positive]);
    assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
    await client.clearAccessDecisions();
    assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
    await client.unlock([CONTENT_NAME]);
    assert.equal(posts, 4, "late denial did not restore suppression");
  });

  for (const denialCache of [false, undefined]) {
    test(`full reset clears held item and period keys with denial cache ${denialCache === false ? "disabled" : "enabled"}`, async () => {
      const page = await world({ periodKeyInput: true });
      let posts = 0;
      const client = createBrowserClient({
        root: domOver(page.markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        unlockUrl: UNLOCK_URL,
        relayPeriodKeys: true,
        acceptDirectResponse: true,
        ...(denialCache === false ? { denialCache } : {}),
        transport: {
          async post(_url, request) {
            posts++;
            return { ...(await page.unlock(request)), contentType: "application/json" };
          },
        },
      });
      assert.equal(utf8Decode((await client.open(CONTENT_NAME)).bytes), ARTICLE);
      assert.ok((await client.cache.entries()).length);
      const reset = client.clearReaderContext();
      assert.equal(client.clearReaderContext(), reset, "concurrent resets join");
      await assert.rejects(client.openLocal(CONTENT_NAME), { code: "context_retired" });
      await reset;
      assert.deepEqual(await client.cache.entries(), []);
      assert.equal(await client.resolver.contentKeyFor(client.dcaData, CONTENT_NAME), null);
      await assert.rejects(client.openLocal(CONTENT_NAME), { code: "no_key" });
      await client.clearReaderContext();
      assert.equal(posts, 1, "resets do not request");
      assert.equal(utf8Decode((await client.open(CONTENT_NAME)).bytes), ARTICLE);
      assert.equal(posts, 2);
    });
  }

  for (const oldOutcome of ["outage", "rejection"]) {
    test(`reset fences an old ${oldOutcome} and its fallback while new work succeeds`, async () => {
      const page = await world({ issuerNames: [ISSUER_NAME, BACKUP_ISSUER] });
      const started = resetBoundary(),
        release = resetBoundary();
      const urls = [];
      const client = createBrowserClient({
        root: domOver(page.markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        unlockUrl: UNLOCK_URL,
        acceptDirectResponse: true,
        transport: {
          async post(url, request) {
            urls.push(url);
            if (urls.length === 1) {
              started.release();
              await release.promise;
              if (oldOutcome === "rejection") throw dcaError("offline", "old failure");
              if (oldOutcome === "outage") return { status: 503 };
            }
            return { ...(await page.unlock(request)), contentType: "application/json" };
          },
        },
      });
      const old = client.unlockRoutes(
        [CONTENT_NAME],
        [
          {
            issuerName: ISSUER_NAME,
            unlockUrl: UNLOCK_URL,
            acceptDirectResponse: true,
            retryOperational: true,
          },
          {
            issuerName: BACKUP_ISSUER,
            unlockUrl: "https://backup.example/unlock",
            acceptDirectResponse: true,
            independent: true,
          },
        ],
      );
      const refused = assert.rejects(old, { code: "context_retired" });
      await started.promise;
      await client.clearReaderContext();
      assert.equal(
        utf8Decode((await client.open(CONTENT_NAME)).bytes),
        ARTICLE,
        "reset did not wait for old network",
      );
      release.release();
      await refused;
      assert.deepEqual(urls, [UNLOCK_URL, UNLOCK_URL], "old route never continued fallback");
    });
  }

  for (const operation of ["open", "openLocal"]) {
    test(`reset fences plaintext from an already-running ${operation} decoder`, async () => {
      const fixture = await obtainingFixture({ bodytextEncodings: ["paused"] });
      const entered = resetBoundary(),
        gate = resetBoundary();
      let decode = 0;
      const client = createDeliveryClient({
        reader: fixture.reader,
        issuerName: ISSUER_NAME,
        unlockUrl: UNLOCK_URL,
        acceptDirectResponse: true,
        contentDecoders: {
          async paused(bytes) {
            if (++decode === 1) {
              entered.release();
              await gate.promise;
            }
            return bytes;
          },
        },
        transport: {
          post: async () => ({
            status: 200,
            contentType: "application/json",
            body: { keys: { contentKeys: fixture.contentKeys } },
          }),
        },
      });
      if (operation === "openLocal") await client.unlock(["bodytext"]);
      const old = assert.rejects(client[operation]("bodytext"), { code: "context_retired" });
      await entered.promise;
      await client.clearReaderContext();
      gate.release();
      await old;
      assert.equal(utf8Decode((await client.open("bodytext")).bytes), "bodytext");
    });
  }

  test("structural cleanup starts every owner, blocks until settled and reports hint-only failure", async () => {
    const fixture = await obtainingFixture();
    const gate = resetBoundary();
    const fault = new Error("durable clear failed");
    let resolverClears = 0,
      decisions = 0;
    const client = createDeliveryClient({
      reader: fixture.reader,
      issuerName: ISSUER_NAME,
      transport: {
        post: async () => {
          throw new Error("no requests");
        },
      },
      resolverFactory(options) {
        const inner = new ContentKeyResolver(options);
        return {
          applyResponse: inner.applyResponse.bind(inner),
          resolveDetailed: inner.resolveDetailed.bind(inner),
          resolve: inner.resolve.bind(inner),
          contentKeyFor: inner.contentKeyFor.bind(inner),
          contentKeyWithOriginFor: inner.contentKeyWithOriginFor.bind(inner),
          clearReaderContext() {
            resolverClears++;
            return gate.promise;
          },
        };
      },
      denialCache: {
        capture: async () => ({}),
        deny() {},
        invalidate() {
          decisions++;
          throw fault;
        },
      },
    });
    const clearing = client.clearReaderContext();
    const rejected = assert.rejects(clearing, decisionClearFailure(fault));
    assert.equal(resolverClears, 1);
    assert.equal(decisions, 1);
    await assert.rejects(client.resolve(["bodytext"]), { code: "context_retired" });
    gate.release();
    await rejected;
    await assert.rejects(client.clearReaderContext(), decisionClearFailure(fault));
    await assert.rejects(client.openLocal("bodytext"), { code: "no_key" });
    assert.equal(resolverClears, 2);
  });

  test("browser refuses a custom retaining cache without its reset duty", async () => {
    const page = await world();
    assert.throws(
      () =>
        createBrowserClient({
          root: domOver(page.markup, { publisherOrigin: PUB }),
          issuerName: ISSUER_NAME,
          transport: { post: async () => ({ status: 403 }) },
          cache: { put() {}, candidatesAt: async () => [], attempted() {} },
        }),
      { code: "bad_config" },
    );
  });

  test("strict lifecycle clearing surfaces an earlier denial persistence detachment", async () => {
    const page = await world();
    const fault = new Error("denial snapshot inaccessible");
    const denialCache = new DeniedUnlockCache({
      storage: {
        getItem() {
          throw fault;
        },
        setItem() {
          throw fault;
        },
        removeItem() {
          throw fault;
        },
      },
    });
    await denialCache.capture({
      publisherOrigin: PUB,
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      request: {},
    });
    const client = createBrowserClient({
      root: domOver(page.markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      acceptDirectResponse: true,
      transport: {
        post: async (_url, request) => ({
          ...(await page.unlock(request)),
          contentType: "application/json",
        }),
      },
      denialCache,
    });
    assert.equal(utf8Decode((await client.open(CONTENT_NAME)).bytes), ARTICLE);
    await assert.rejects(client.clearAccessDecisions(), (error) => error === fault);
    assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
    await assert.rejects(client.clearReaderContext(), decisionClearFailure(fault));
    await assert.rejects(client.clearReaderContext(), decisionClearFailure(fault));
    await assert.rejects(client.openLocal(CONTENT_NAME), { code: "no_key" });
    assert.equal(
      utf8Decode((await client.open(CONTENT_NAME)).bytes),
      ARTICLE,
      "a previous hint-store fault no longer wedges successor access",
    );
  });
});

for (const fault of [null, undefined]) {
  for (const phase of ["read", "write"]) {
    test(`strict lifecycle preserves ${String(fault)} denial-storage ${phase} failure`, async () => {
      const page = await world();
      const snapshot = JSON.stringify({ epoch: "older", entries: [["old-hint", 999999]] });
      let durable = snapshot;
      const denialCache = new DeniedUnlockCache({
        storage: {
          getItem() {
            if (phase === "read") throw fault;
            return durable;
          },
          setItem() {
            throw fault;
          },
          removeItem() {
            durable = "";
          },
        },
      });
      if (phase === "read")
        await denialCache.capture({
          publisherOrigin: PUB,
          issuerName: ISSUER_NAME,
          unlockUrl: UNLOCK_URL,
          request: {},
        });
      const client = createBrowserClient({
        root: domOver(page.markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        transport: { post: async () => ({ status: 403 }) },
        denialCache,
      });
      await assert.rejects(client.clearAccessDecisions(), (error) => error === fault);
      assert.equal(durable, snapshot, "failed cleanup leaves the unresolved durable snapshot");
      // Decision-only failure has not retired the reader generation.
      const result = await client.resolve([CONTENT_NAME]);
      assert.ok(result.missing.includes(CONTENT_NAME));
      await assert.rejects(client.clearReaderContext(), decisionClearFailure(fault));
      await assert.rejects(client.clearReaderContext(), decisionClearFailure(fault));
      assert.deepEqual((await client.resolve([CONTENT_NAME])).missing, [CONTENT_NAME]);
    });
  }
}

/** Preserve even a non-Error thrown value as the advisory failure's cause. */
function decisionClearFailure(fault) {
  return (error) =>
    error?.code === "access_decisions_clear_failed" &&
    Object.hasOwn(error, "cause") &&
    error.cause === fault;
}

for (const kind of ["period", "chain"]) {
  test(`browser validates its composed ${kind} cache through a wrapper without an assertion`, async () => {
    const page = await world();
    const config = {
      root: domOver(page.markup, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport: { post: async () => ({ status: 403 }) },
      resolverFactory(options) {
        // This wrapper need not forward an optional stock assertion method.
        const inner = new ContentKeyResolver({ cache: options.cache });
        return {
          applyResponse: inner.applyResponse.bind(inner),
          resolveDetailed: inner.resolveDetailed.bind(inner),
          resolve: inner.resolve.bind(inner),
          contentKeyFor: inner.contentKeyFor.bind(inner),
          contentKeyWithOriginFor: inner.contentKeyWithOriginFor.bind(inner),
          clearReaderContext: inner.clearReaderContext.bind(inner),
        };
      },
    };
    const unsupported = { put() {}, candidatesAt: async () => [], attempted() {} };
    assert.throws(
      () =>
        createBrowserClient({
          ...config,
          [kind === "period" ? "cache" : "chainCache"]: unsupported,
        }),
      { code: "bad_config" },
    );
    // null selects composeClient's stock period cache rather than a custom owner.
    const good = createBrowserClient({ ...config, cache: null });
    await good.clearReaderContext();
    assert.deepEqual((await good.resolve([CONTENT_NAME])).missing, [CONTENT_NAME]);
  });
}

test("a denial capture finishing after reset sends no old request", async () => {
  const page = await world();
  const entered = resetBoundary(),
    held = resetBoundary();
  let posts = 0;
  const client = createBrowserClient({
    root: domOver(page.markup, { publisherOrigin: PUB }),
    issuerName: ISSUER_NAME,
    unlockUrl: UNLOCK_URL,
    acceptDirectResponse: true,
    denialCache: {
      async capture() {
        entered.release();
        await held.promise;
        return { retryAt: null };
      },
      deny() {},
      invalidate() {},
      setContext() {},
      async denyContext() {},
    },
    transport: {
      async post() {
        posts++;
        return { status: 403 };
      },
    },
  });
  const old = assert.rejects(client.unlock([CONTENT_NAME]), { code: "context_retired" });
  await entered.promise;
  await client.clearReaderContext();
  held.release();
  await old;
  assert.equal(posts, 0);
  await assert.rejects(client.openLocal(CONTENT_NAME), { code: "no_key" });
});

for (const contentKeys of [true, false]) {
  for (const releaseAt of ["during cleanup", "after reset", "after successor refusal"]) {
    test(`late ${contentKeys ? "item" : "period"} grant ${releaseAt} cannot open for a refused successor`, async () => {
      let entitled = true;
      const decisions = [];
      const allow = new AllowAllPolicy();
      const page = await world({
        contentKeys,
        periodKeyInput: true,
        accessPolicy: {
          decide(claims, requested) {
            decisions.push(entitled);
            return entitled
              ? allow.decide(claims, requested)
              : { contentNames: [], periodGrants: [] };
          },
        },
      });
      const started = resetBoundary(),
        oldAnswer = resetBoundary(),
        cleanupStarted = resetBoundary(),
        cleanupHeld = resetBoundary();
      let holdCleanup = false,
        posts = 0;
      const storage = new Storage({
        gate({ op }) {
          if (holdCleanup && op === "keys") {
            holdCleanup = false;
            cleanupStarted.release();
            return cleanupHeld.promise;
          }
        },
      });
      const client = createBrowserClient({
        root: domOver(page.markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_NAME,
        unlockUrl: UNLOCK_URL,
        relayPeriodKeys: true,
        acceptDirectResponse: true,
        storage,
        cacheNamespace: "reader",
        transport: {
          async post(_url, request) {
            const answer = { ...(await page.unlock(request)), contentType: "application/json" };
            if (++posts === 1) {
              started.release();
              await oldAnswer.promise;
            }
            return answer;
          },
        },
      });
      const old = assert.rejects(client.open(CONTENT_NAME), { code: "context_retired" });
      await started.promise;
      entitled = false;
      holdCleanup = releaseAt === "during cleanup";
      const clearing = client.clearReaderContext();
      if (holdCleanup) {
        await cleanupStarted.promise;
        oldAnswer.release();
        await old;
        await assert.rejects(client.open(CONTENT_NAME), { code: "context_retired" });
        cleanupHeld.release();
      }
      await clearing;
      if (releaseAt === "after successor refusal")
        await assert.rejects(client.open(CONTENT_NAME), { code: "no_key" });
      oldAnswer.release();
      await old;
      await assert.rejects(client.openLocal(CONTENT_NAME), { code: "no_key" });
      await assert.rejects(client.open(CONTENT_NAME), { code: "no_key" });
      assert.deepEqual(await client.cache.entries(), []);
      assert.equal(await client.resolver.contentKeyFor(client.dcaData, CONTENT_NAME), null);
      assert.equal(decisions[0], true);
      assert.ok(
        decisions.slice(1).every((value) => value === false),
        "successor actually denied at the issuer",
      );
      entitled = true;
      assert.equal(
        utf8Decode((await client.open(CONTENT_NAME)).bytes),
        ARTICLE,
        "same actual grant opens only when the successor is authorized",
      );
    });
  }
}

test("a synchronously throwing key cleanup still waits for hints and permanently retires the client", async () => {
  const fixture = await obtainingFixture();
  const hintGate = resetBoundary();
  const fault = new Error("synchronous key cleanup failed");
  let hints = 0;
  const client = createDeliveryClient({
    reader: fixture.reader,
    issuerName: ISSUER_NAME,
    transport: { post: async () => ({ status: 403 }) },
    resolverFactory(options) {
      const inner = new ContentKeyResolver(options);
      return {
        applyResponse: inner.applyResponse.bind(inner),
        resolveDetailed: inner.resolveDetailed.bind(inner),
        resolve: inner.resolve.bind(inner),
        contentKeyFor: inner.contentKeyFor.bind(inner),
        contentKeyWithOriginFor: inner.contentKeyWithOriginFor.bind(inner),
        clearReaderContext() {
          throw fault;
        },
      };
    },
    denialCache: {
      capture: async () => ({}),
      deny() {},
      async invalidate() {
        hints++;
        await hintGate.promise;
      },
    },
  });
  const clearing = client.clearReaderContext();
  assert.equal(client.clearReaderContext(), clearing);
  let settled = false;
  const rejected = assert
    .rejects(clearing, (error) => error === fault)
    .then(() => {
      settled = true;
    });
  assert.equal(hints, 1);
  await assert.rejects(client.resolve(["bodytext"]), { code: "context_retired" });
  assert.equal(settled, false, "the reset waits for its separately started hint owner");
  hintGate.release();
  await rejected;
  await assert.rejects(client.resolve(["bodytext"]), { code: "context_retired" });
  await assert.rejects(client.clearReaderContext(), (error) => error === fault);
});

for (const fatalKeys of [false, true]) {
  test(`concurrent full resets share ${fatalKeys ? "fatal key" : "advisory hint"} cleanup failure and wait for both owners`, async () => {
    const fixture = await obtainingFixture();
    const keyGate = resetBoundary(),
      hintGate = resetBoundary();
    const fault = new Error("hint cleanup failed"),
      keyFault = new Error("key cleanup failed");
    let keys = 0,
      hints = 0;
    const client = createDeliveryClient({
      reader: fixture.reader,
      issuerName: ISSUER_NAME,
      transport: { post: async () => ({ status: 403 }) },
      resolverFactory(options) {
        const inner = new ContentKeyResolver(options);
        return {
          applyResponse: inner.applyResponse.bind(inner),
          resolveDetailed: inner.resolveDetailed.bind(inner),
          resolve: inner.resolve.bind(inner),
          contentKeyFor: inner.contentKeyFor.bind(inner),
          contentKeyWithOriginFor: inner.contentKeyWithOriginFor.bind(inner),
          async clearReaderContext() {
            keys++;
            await inner.clearReaderContext();
            await keyGate.promise;
            if (fatalKeys) throw keyFault;
          },
        };
      },
      denialCache: {
        capture: async () => ({}),
        deny() {},
        async invalidate() {
          hints++;
          await hintGate.promise;
          throw fault;
        },
      },
    });
    const first = client.clearReaderContext(),
      second = client.clearReaderContext();
    assert.equal(first, second, "the entire public reset result is coalesced");
    const failure = fatalKeys ? (error) => error === keyFault : decisionClearFailure(fault);
    const a = assert.rejects(first, failure),
      b = assert.rejects(second, failure);
    assert.equal(keys, 1);
    assert.equal(hints, 1);
    keyGate.release();
    await assert.rejects(client.resolve(["bodytext"]), { code: "context_retired" });
    hintGate.release();
    await Promise.all([a, b]);
    if (fatalKeys) {
      await assert.rejects(client.resolve(["bodytext"]), { code: "context_retired" });
      await assert.rejects(client.clearReaderContext(), (error) => error === keyFault);
      assert.equal(keys, 1);
      assert.equal(hints, 1);
    } else {
      assert.deepEqual((await client.resolve(["bodytext"])).missing, ["bodytext"]);
      await assert.rejects(client.clearReaderContext(), decisionClearFailure(fault));
      assert.equal(keys, 2);
      assert.equal(hints, 2);
    }
  });
}
