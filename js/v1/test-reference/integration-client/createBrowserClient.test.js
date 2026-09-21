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
// the single unlock attempt. The walk, the breaker and the route list belong to
// `demo/actors/PageLoad.js` and are asserted there.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { createBrowserClient } from "../../integration-client/createBrowserClient.js";
import {
  missingBrowserCapabilities,
  requireBrowserCapabilities,
} from "../../integration-client/browserCapabilities.js";
import { composeClient } from "../../integration-client/composeClient.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
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
import { exactPeriodKeySupply } from "../../demo/support/exactPeriodKeySupply.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { domOver } from "../../test-lib/helpers/domOver.js";
import { refuses } from "../../test-lib/helpers/refuses.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import { utf8Decode } from "../../core-shared/codec.js";
import { own } from "../../core-shared/wire.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const PUB = "https://www.news-site.example";
const UNLOCK_URL = "https://api.example.com/unlock";
const AT = "2025-10-23T14:20:00Z";
const CONTENT_NAME = "bodytext";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";

/**
 * One publisher, one issuer, and the markup a reader's browser receives.
 *
 * @returns {Promise<{ markup: string, unlock: (request: object) => Promise<{ status: number, body: any }>, calls: { count: number } }>}
 */
async function world() {
  const issuerKeys = await issuerKeypair();
  const signingKeys = await signingKeypair();

  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: exactPeriodKeySupply({ random: new Random({ seed: 7 }) }),
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ECDH-P256",
        publicKey: issuerKeys.publicKey,
        unlockUrl: UNLOCK_URL,
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(CONTENT_NAME, ARTICLE, "text/html", { accessGroups: ["premium"] });
  const rendered = await sealer.seal();
  const markup = writeMarkupDelivery({
    dcaData: rendered.dcaData,
    sealedContent: rendered.sealedContent,
  });

  const keyStore = {
    /** @param {string} issuerName @param {string} keyId */
    get(issuerName, keyId) {
      if (issuerName !== ISSUER_NAME || keyId !== KEY_ID) return undefined;
      return { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey };
    },
  };
  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]),
    },
  ]).get(SIGNING_KID);

  const processor = new IssuerProcessor(new IssuerEngine({ accessPolicy: new AllowAllPolicy() }));
  const endpoint = new UnlockEndpoint(processor);
  const calls = { count: 0 };

  return {
    markup,
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
    const periodChainProfile = {
      parametersForResponse: () => ({}),
      candidateSourceFor: () => ({ attempts: () => [] }),
      acceptsExactResponseCoordinate: () => true,
      acceptsResponseCoordinate: () => true,
    };
    const cache = { put: () => undefined, candidatesAt: () => [], attempted: () => undefined };

    composeClient({
      cache,
      chainCache,
      periodChainProfile,
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
    assert.equal(seen.periodChainProfile, periodChainProfile);
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

  test("without an injected cache, each composition uses its own in-memory period-key cache", async () => {
    const first = composeClient();
    const second = composeClient();
    assert.ok(first.cache instanceof PeriodKeyCache);
    assert.notEqual(first.cache, second.cache);

    await first.cache.put("premium", "250101T00", new Uint8Array([1]), { publisher: PUB });
    assert.deepEqual(
      await second.cache.candidatesAt("premium", "250101T00", { publisher: PUB }),
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
      { code: "bad_config", message: /chainCache needs an injected periodChainProfile/ },
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

describe("One page, one issuer, one unlock attempt", () => {
  test("the entry unlocks the article the publisher sealed", async () => {
    const { markup, unlock: answer, calls } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    /** @type {{ url: string, context: any }[]} */
    const posted = [];

    const client = createBrowserClient({
      root,
      issuerName: ISSUER_NAME,
      transport: {
        /** @param {string} url @param {object} request @param {any} context */
        async post(url, request, context) {
          posted.push({ url, context });
          return answer(request);
        },
      },
    });

    const result = await client.unlock([CONTENT_NAME]);
    assert.equal(result.status, 200);
    assert.ok(result.application.accepted > 0, "the issuer granted what the page asked");
    assert.deepEqual(posted, [{ url: UNLOCK_URL, context: { origin: PUB } }]);
    assert.equal(calls.count, 1);

    const record = client.dcaData.contentDataFor(CONTENT_NAME);
    const bytes = await client.opener.open({
      record,
      contentName: CONTENT_NAME,
      ciphertext: client.reader.extract(CONTENT_NAME),
      aad: own(record, "aad"),
      resolveKey: async () =>
        (await client.resolver.contentKeyWithOriginFor(client.dcaData, CONTENT_NAME)).key,
    });
    assert.equal(utf8Decode(bytes), ARTICLE, "the plaintext is the article that was sealed");
  });

  test("a status other than 200 comes back as it arrived, after one call", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    const body = { error: "not_entitled" };
    let posts = 0;

    const client = createBrowserClient({
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

  test("the entry reads the unlock URL off the page, and takes one instead", async () => {
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

    const page = createBrowserClient({ root, issuerName: ISSUER_NAME, transport });
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

  test("the entry refuses a missing root, issuer name, transport or unlock URL", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    const transport = {
      async post() {
        return { status: 200, body: {} };
      },
    };

    await refuses(
      () => createBrowserClient(/** @type {any} */ ({ issuerName: ISSUER_NAME, transport })),
      { code: "bad_config", message: /page root/ },
      "the entry reads one page and is told which",
    );
    await refuses(
      () => createBrowserClient(/** @type {any} */ ({ root, transport })),
      { code: "bad_config", message: /issuerName/ },
      "the entry addresses one issuer and is told which",
    );
    await refuses(
      () => createBrowserClient(/** @type {any} */ ({ root, issuerName: ISSUER_NAME })),
      { code: "bad_config", message: /transport/ },
      "the host supplies the transport that reaches the issuer",
    );
    await refuses(
      () => createBrowserClient({ root, issuerName: "another_issuer", transport }),
      { code: "bad_config", message: /no unlock URL/ },
      "a page naming no URL for that issuer is refused",
    );
  });

  test("the entry refuses a resolver missing any operation its facade needs", async () => {
    const { markup } = await world();
    const root = domOver(markup, { publisherOrigin: PUB });
    const transport = { post: async () => ({ status: 503, body: null }) };
    const resolver = {
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
            root,
            issuerName: ISSUER_NAME,
            transport,
            resolverFactory: () => partial,
          }),
        { code: "bad_config", message: new RegExp(`needs ${method}`) },
        `the browser entry refuses a resolver without ${method}`,
      );
    }
  });
});
