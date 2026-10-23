// @ts-check
//
// The delivery client's route walk and local open, with real AES-GCM items
// and wraps and a scripted issuer. Pinned here: `openLocal` admits the used
// item before any key resolution; the finite `RouteAttempt` outcome
// vocabulary; which identity a later outcome re-scopes; and which continuation
// an admitted family report permits.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { createDeliveryClient } from "../../integration-client/createDeliveryClient.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { DcaRequestBuilder } from "../../core-client/DcaRequestBuilder.js";
import { encrypt } from "../../core-shared/aead.js";
import { base64urlEncode, utf8Decode, utf8Encode } from "../../core-shared/codec.js";
import { dcaError } from "../../core-shared/errors.js";
import { contentAadOctets } from "../support/contentAadOctets.js";
import { wrapNonceOf } from "../support/contentKeyWrapNonceOctets.js";
import { issuerBlockOf } from "../../test-lib/helpers/inspect.js";

const PUB = "https://www.news-site.example";
const UNLOCK_URL = "https://api.example.com/unlock";
const T_NOW = "251023T1400";
const A = "issuer_a";
const B = "issuer_b";
const C = "issuer_c";

/** The reference walk's documented outcome tokens, and nothing else. */
const ROUTE_ATTEMPT_OUTCOMES = Object.freeze([
  "not-on-page",
  "unsupported-retry-projection",
  "no-eligible-route",
  "indeterminate",
  "unusable-response",
  "offline",
  "timeout",
  "no_route",
  "fault",
  "unavailable",
  "answered",
]);

/** @param {Uint8Array} bytes */
const encoded = (bytes) => base64urlEncode(bytes);

/** @param {any} body */
const ok = (body) => ({ status: 200, contentType: "application/json", body });

/**
 * Items keyed by access group, sealed for every listed issuer. An issuer named
 * in `only` presents just those items and their families.
 * @param {Record<string, string>} groupOf - item name to access group
 * @param {{ issuers?: string[], only?: Record<string, string[]>, mutate?: (raw: any, ciphertexts: Map<string, string>) => void }} [options]
 */
async function fixture(groupOf, options = {}) {
  const { issuers = [A, B, C], only = {}, mutate } = options;
  const nonce = new Uint8Array(12).fill(23);
  /** @type {Record<string, Uint8Array>} */
  const periodKeys = {};
  /** @type {Record<string, string>} */
  const contentKeys = {};
  /** @type {any[]} */
  const contentData = [];
  const ciphertexts = new Map();
  let seed = 40;
  const resource = { origin: PUB, resourceId: "article", renderId: "AAAAAAAAAAAAAAAAAAAAAA" };
  const jwt = `${encoded(utf8Encode(JSON.stringify({ alg: "ES256", kid: "k1" })))}.${encoded(utf8Encode(JSON.stringify(resource)))}.c2lnbmF0dXJl`;
  for (const [name, group] of Object.entries(groupOf)) {
    periodKeys[group] ??= new Uint8Array(16).fill(seed++);
    const contentKey = new Uint8Array(16).fill(seed++);
    contentKeys[name] = encoded(contentKey);
    contentData.push({
      contentName: name,
      contentType: "text/plain",
      nonce: encoded(nonce),
      keys: [
        {
          accessGroup: group,
          period: T_NOW,
          key: encoded(
            await encrypt(
              periodKeys[group],
              wrapNonceOf({ resourceJWT: jwt }, name, group, T_NOW),
              contentKey,
            ),
          ),
        },
      ],
    });
    const aad = contentAadOctets({ resourceJWT: jwt, contentData }, name);
    ciphertexts.set(
      name,
      encoded(await encrypt(contentKey, new Uint8Array(12), utf8Encode(name), aad)),
    );
  }
  /** @param {string} issuer */
  const sealedFor = (issuer) => {
    const names = only[issuer] ?? Object.keys(groupOf);
    return {
      contentKeys: names.map((name) => ({ contentName: name, key: "AA" })),
      periodKeys: [...new Set(names.map((name) => groupOf[name]))].map((group) => ({
        accessGroup: group,
        period: T_NOW,
        key: "AA",
      })),
    };
  };
  const raw = {
    version: "1",
    resource,
    resourceJWT: jwt,
    contentData,
    issuerData: issuers.map((issuer) => ({
      issuerName: issuer,
      keyId: "kid",
      unlockUrl: UNLOCK_URL,
      sealed: sealedFor(issuer),
    })),
  };
  mutate?.(raw, ciphertexts);
  return {
    raw,
    periodKeys,
    contentKeys,
    reader: {
      dcaData: raw,
      publisherOrigin: PUB,
      extract: (/** @type {string} */ name) => ciphertexts.get(name) ?? null,
    },
  };
}

/** A cache double that counts reads and holds the given period keys. */
function countingCache(/** @type {Record<string, Uint8Array>} */ held = {}) {
  const counts = { reads: 0 };
  return {
    counts,
    cache: {
      put() {},
      attempted() {},
      candidatesAt(/** @type {string} */ group) {
        counts.reads++;
        return held[group] ? [held[group]] : [];
      },
    },
  };
}

describe("openLocal admits its used item before key resolution", () => {
  for (const [fault, mutate] of [
    [
      "a ciphertext shorter than the tag",
      (/** @type {any} */ _raw, /** @type {Map<string, string>} */ ct) =>
        ct.set("bad", encoded(new Uint8Array(15))),
    ],
  ]) {
    test(`${fault} is bad_page before key resolution, held key or not; siblings still open`, async () => {
      const fx = await fixture({ bad: "premium", teaser: "premium" }, { mutate });
      /** @param {Record<string, Uint8Array>} held */
      const clientHolding = (held) => {
        const { counts, cache } = countingCache(held);
        const seen = { resolutions: 0, posts: 0 };
        const client = createDeliveryClient({
          unlockUrl: UNLOCK_URL,
          reader: fx.reader,
          issuerName: A,
          cache,
          resolverFactory: (options) => {
            const resolver = new ContentKeyResolver(options);
            const contentKeyFor = resolver.contentKeyFor.bind(resolver);
            resolver.contentKeyFor = async (/** @type {any[]} */ ...args) => {
              seen.resolutions++;
              return contentKeyFor(...args);
            };
            return resolver;
          },
          transport: {
            async post() {
              seen.posts++;
              return { status: 403 };
            },
          },
        });
        return { client, counts, seen };
      };

      // No key anywhere: the item's own fault is reported, not a missing key
      // the host would answer with a standalone unlock.
      const empty = clientHolding({});
      await assert.rejects(empty.client.openLocal("bad"), { code: "bad_page" });
      assert.deepEqual(
        { ...empty.seen, reads: empty.counts.reads },
        { resolutions: 0, posts: 0, reads: 0 },
      );

      // A held family key changes nothing for the bad item and opens its sibling.
      const holding = clientHolding({ premium: fx.periodKeys.premium });
      await assert.rejects(holding.client.openLocal("bad"), { code: "bad_page" });
      assert.deepEqual(
        { ...holding.seen, reads: holding.counts.reads },
        { resolutions: 0, posts: 0, reads: 0 },
      );
      assert.equal(utf8Decode((await holding.client.openLocal("teaser")).bytes), "teaser");
      assert.equal(holding.seen.posts, 0, "openLocal never asks an issuer");
    });
  }

  test("an unsupported delivery version refuses before any cache read", async () => {
    const fx = await fixture({ teaser: "premium" });
    const { counts, cache } = countingCache({ premium: fx.periodKeys.premium });
    const client = createDeliveryClient({
      unlockUrl: UNLOCK_URL,
      reader: fx.reader,
      issuerName: A,
      cache,
      transport: {
        async post() {
          throw new Error("openLocal never posts");
        },
      },
    });
    // The client captured the delivery; a later version change in its own
    // captured view is what a version refusal at open time looks like.
    /** @type {any} */ (client.dcaData).toObject().version = "2";
    await assert.rejects(client.openLocal("teaser"), { code: "bad_page" });
    assert.equal(counts.reads, 0);
  });

  test("a well-formed item with no key is still no_key, and host faults stay visible", async () => {
    const fx = await fixture({ teaser: "premium" });
    const quiet = createDeliveryClient({
      unlockUrl: UNLOCK_URL,
      reader: fx.reader,
      issuerName: A,
      cache: countingCache().cache,
      transport: {
        async post() {
          throw new Error("openLocal never posts");
        },
      },
    });
    await assert.rejects(quiet.openLocal("teaser"), { code: "no_key" });
    const fault = dcaError("bad_storage", "unreadable backing");
    const faulty = createDeliveryClient({
      unlockUrl: UNLOCK_URL,
      reader: fx.reader,
      issuerName: A,
      cache: {
        put() {},
        attempted() {},
        candidatesAt() {
          throw fault;
        },
      },
      transport: {
        async post() {
          throw new Error("openLocal never posts");
        },
      },
    });
    await assert.rejects(faulty.openLocal("teaser"), (cause) => cause === fault);
  });
});

test("the walk reports each attempt with one token from the finite outcome vocabulary", async () => {
  const issuers = [
    "issuer_empty",
    "issuer_offline",
    "issuer_timeout",
    "issuer_noroute",
    "issuer_opaque",
    "issuer_text",
    "issuer_fault",
    "issuer_denies",
    "issuer_unavailable",
    "issuer_projected",
    "issuer_grants",
  ];
  const fx = await fixture({ teaser: "premium" }, { issuers, only: { issuer_empty: [] } });
  /** @type {Record<string, () => any>} */
  const answers = {
    issuer_offline: () => {
      throw Object.assign(new Error("offline"), { code: "offline" });
    },
    issuer_timeout: () => {
      throw Object.assign(new Error("timeout"), { code: "timeout" });
    },
    issuer_noroute: () => {
      throw Object.assign(new Error("no route"), { code: "no_route" });
    },
    issuer_opaque: () => {
      throw Object.assign(new Error("opaque"), { code: "indeterminate_transport" });
    },
    issuer_text: () => ({ status: 200, contentType: "text/plain", body: "granted" }),
    issuer_fault: () => ({ status: 500 }),
    issuer_denies: () => ({ status: 403 }),
    issuer_unavailable: () =>
      ok({
        keys: { contentKeys: [] },
        notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
      }),
    issuer_grants: () =>
      ok({ keys: { contentKeys: [{ contentName: "teaser", key: fx.contentKeys.teaser }] } }),
  };
  const posts = [];
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: fx.reader,
    issuerName: "issuer_grants",
    relayPeriodKeys: true,
    // An extension member the projection cannot narrow makes a conditional
    // retry unsupported rather than forwarded.
    requestBuilderFactory: (options) => {
      const base = new DcaRequestBuilder(options);
      return {
        build: (/** @type {any[]} */ ...args) => {
          const request = base.build(...args).toObject();
          return { toObject: () => ({ ...request, unprojectable: true }) };
        },
      };
    },
    transport: {
      async post(_url, request) {
        posts.push(request.issuerName);
        return answers[request.issuerName]();
      },
    },
  });
  const independent = (/** @type {string} */ issuerName) => ({
    issuerName,
    unlockUrl: UNLOCK_URL,
    independent: true,
  });
  const result = await client.unlockRoutes(
    ["teaser"],
    [
      { issuerName: "issuer_absent", unlockUrl: UNLOCK_URL },
      independent("issuer_empty"),
      independent("issuer_offline"),
      independent("issuer_timeout"),
      independent("issuer_noroute"),
      independent("issuer_opaque"),
      independent("issuer_text"),
      independent("issuer_fault"),
      independent("issuer_denies"),
      { ...independent("issuer_unavailable"), retryUnavailable: true },
      { issuerName: "issuer_projected", unlockUrl: UNLOCK_URL },
      independent("issuer_grants"),
    ],
  );
  assert.deepEqual(result.attempts, [
    { issuerName: "issuer_absent", outcome: "not-on-page" },
    { issuerName: "issuer_empty", outcome: "no-eligible-route" },
    { issuerName: "issuer_offline", outcome: "offline" },
    { issuerName: "issuer_timeout", outcome: "timeout" },
    { issuerName: "issuer_noroute", outcome: "no_route" },
    { issuerName: "issuer_opaque", outcome: "indeterminate" },
    { issuerName: "issuer_text", status: 200, outcome: "unusable-response" },
    { issuerName: "issuer_fault", status: 500, outcome: "fault" },
    { issuerName: "issuer_denies", status: 403, outcome: "answered" },
    { issuerName: "issuer_unavailable", status: 200, outcome: "unavailable" },
    { issuerName: "issuer_projected", outcome: "unsupported-retry-projection" },
    { issuerName: "issuer_grants", status: 200, outcome: "answered" },
  ]);
  assert.deepEqual(
    [...new Set(result.attempts.map((attempt) => attempt.outcome))].sort(),
    [...ROUTE_ATTEMPT_OUTCOMES].sort(),
    "the walk emits exactly the documented vocabulary",
  );
  assert.equal(posts.includes("issuer_empty"), false);
  assert.equal(posts.includes("issuer_projected"), false);
  assert.deepEqual(result.missing, []);
});

test("a later independent indeterminate outcome clears only the identities it addressed", async () => {
  const fx = await fixture({ teaser: "premium", third: "sport" }, { only: { [B]: ["teaser"] } });
  /** @type {any[]} */
  const posts = [];
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: fx.reader,
    issuerName: A,
    relayPeriodKeys: true,
    transport: {
      async post(_url, request) {
        posts.push(request);
        if (request.issuerName === A) throw Object.assign(new Error("off"), { code: "offline" });
        if (request.issuerName === B)
          throw Object.assign(new Error("opaque"), { code: "indeterminate_transport" });
        return ok({ keys: { contentKeys: [{ contentName: "third", key: fx.contentKeys.third }] } });
      },
    },
  });
  const result = await client.unlockRoutes(
    ["teaser", "third"],
    [
      { issuerName: A, unlockUrl: UNLOCK_URL, retryOperational: true },
      { issuerName: B, unlockUrl: UNLOCK_URL, independent: true },
      { issuerName: C, unlockUrl: UNLOCK_URL },
    ],
  );
  assert.deepEqual(
    posts.map((request) => request.issuerName),
    [A, B, C],
  );
  assert.deepEqual(
    posts[1].sealed.contentKeys.map((record) => record.contentName),
    ["teaser"],
    "B addressed teaser only",
  );
  assert.deepEqual(
    posts[2].sealed.contentKeys.map((record) => record.contentName),
    ["third"],
    "teaser lost eligibility",
  );
  assert.deepEqual(
    (posts[2].sealed.periodKeys ?? []).map((record) => record.accessGroup),
    ["sport"],
  );
  assert.deepEqual(result.missing, ["teaser"]);
  assert.deepEqual(
    result.attempts.map((attempt) => attempt.outcome),
    ["offline", "indeterminate", "answered"],
  );
});

test("a cached denial clears retry eligibility inherited from an earlier issuer", async () => {
  const fx = await fixture({ bodytext: "premium" });
  /** @type {string[]} */
  const posts = [];
  const client = createDeliveryClient({
    reader: fx.reader,
    issuerName: A,
    unlockUrl: UNLOCK_URL,
    relayPeriodKeys: true,
    denialCache: {
      capture: async (input) => ({ retryAt: input.issuerName === B ? 1000 : null }),
      deny() {},
    },
    transport: {
      async post(_url, request) {
        posts.push(request.issuerName);
        if (request.issuerName === A) throw Object.assign(new Error("off"), { code: "offline" });
        return ok({});
      },
    },
  });
  const result = await client.unlockRoutes(
    ["bodytext"],
    [
      { issuerName: A, unlockUrl: UNLOCK_URL, retryOperational: true },
      { issuerName: B, unlockUrl: UNLOCK_URL, independent: true },
      { issuerName: C, unlockUrl: UNLOCK_URL },
    ],
  );
  assert.deepEqual(posts, [A], "the cached denial prevents the inherited conditional retry");
  assert.deepEqual(
    result.attempts.map((attempt) => attempt.outcome),
    ["offline", "cached-denial"],
  );
  assert.deepEqual(result.missing, ["bodytext"]);
});

test("a non-200 answer rereads a permitted period key retained during the request", async () => {
  const fx = await fixture({ bodytext: "premium" });
  const cache = new PeriodKeyCache();
  let posts = 0;
  const client = createDeliveryClient({
    reader: fx.reader,
    issuerName: A,
    unlockUrl: UNLOCK_URL,
    relayPeriodKeys: true,
    cache,
    transport: {
      async post() {
        posts++;
        // Model another authorized exchange filing a key while this request waits.
        await cache.put("premium", T_NOW, fx.periodKeys.premium, { publisher: PUB });
        return { status: 403 };
      },
    },
  });
  const result = await client.unlockRoutes(
    ["bodytext"],
    [{ issuerName: A, unlockUrl: UNLOCK_URL }],
  );
  assert.equal(posts, 1);
  assert.deepEqual(result.missing, []);
  assert.deepEqual(result.attempts, [{ issuerName: A, status: 403, outcome: "answered" }]);
  assert.equal(utf8Decode((await client.openLocal("bodytext")).bytes), "bodytext");
});

describe("a route-level family report activates only its permitted continuation", () => {
  for (const [label, firstAnswer, retryUnavailable, expected] of [
    [
      "an empty family beside unavailable, retry selected",
      {
        keys: { contentKeys: [], periodKeys: [] },
        notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
      },
      true,
      { posts: [A, B], outcome: "unavailable" },
    ],
    [
      "the same report without the retry choice",
      {
        keys: { contentKeys: [], periodKeys: [] },
        notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
      },
      false,
      { posts: [A], outcome: "answered" },
    ],
    [
      "a denied family, retry selected",
      { keys: { contentKeys: [] }, notDelivered: [{ accessGroup: "premium", reason: "denied" }] },
      true,
      { posts: [A], outcome: "answered" },
    ],
    [
      "a keyed family beside the report",
      {
        keys: {
          contentKeys: [],
          periodKeys: [{ accessGroup: "premium", period: T_NOW, key: "!!" }],
        },
        notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
      },
      true,
      { posts: [A], outcome: "answered" },
    ],
  ]) {
    test(label, async () => {
      const fx = await fixture({ teaser: "premium", third: "sport" });
      /** @type {any[]} */
      const posts = [];
      const client = createDeliveryClient({
        unlockUrl: UNLOCK_URL,
        reader: fx.reader,
        issuerName: A,
        cache: new PeriodKeyCache(),
        relayPeriodKeys: true,
        transport: {
          async post(_url, request) {
            posts.push(request);
            if (request.issuerName === A) return ok(firstAnswer);
            return ok({
              keys: {
                periodKeys: [
                  { accessGroup: "premium", period: T_NOW, key: encoded(fx.periodKeys.premium) },
                ],
              },
            });
          },
        },
      });
      const result = await client.unlockRoutes(
        ["teaser", "third"],
        [
          { issuerName: A, unlockUrl: UNLOCK_URL, retryUnavailable },
          { issuerName: B, unlockUrl: UNLOCK_URL },
        ],
      );
      assert.deepEqual(
        posts.map((request) => request.issuerName),
        expected.posts,
      );
      assert.equal(result.attempts[0].outcome, expected.outcome);
      if (expected.posts.length === 2) {
        // The report qualifies its family only: no item coordinate and no
        // unreported sibling family travels to the conditional route.
        assert.deepEqual(posts[1].sealed.contentKeys, []);
        assert.deepEqual(
          posts[1].sealed.periodKeys.map((record) => record.accessGroup),
          ["premium"],
        );
        assert.deepEqual(result.missing, ["third"]);
      } else {
        assert.deepEqual(result.missing, ["teaser", "third"]);
      }
    });
  }

  // A rejected key entry keeps an admitted report's meaning (period keys
  // Section 5.6), so the retry still runs for the reported family.
  for (const [label, firstAnswer, names, missing] of [
    [
      "a malformed item key beside an admitted unavailable report, retry selected",
      () => ({
        keys: { contentKeys: [{ contentName: "third", key: "!!" }] },
        notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
      }),
      ["teaser", "third"],
      ["third"],
    ],
    [
      "an unsolicited item key beside an admitted unavailable report, retry selected",
      (/** @type {any} */ fx) => ({
        keys: { contentKeys: [{ contentName: "third", key: fx.contentKeys.third }] },
        notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
      }),
      ["teaser"],
      [],
    ],
  ]) {
    test(label, async () => {
      const fx = await fixture({ teaser: "premium", third: "sport" });
      /** @type {any[]} */
      const posts = [];
      const client = createDeliveryClient({
        unlockUrl: UNLOCK_URL,
        reader: fx.reader,
        issuerName: A,
        cache: new PeriodKeyCache(),
        relayPeriodKeys: true,
        transport: {
          async post(_url, request) {
            posts.push(request);
            if (request.issuerName === A) return ok(firstAnswer(fx));
            return ok({
              keys: {
                periodKeys: [
                  { accessGroup: "premium", period: T_NOW, key: encoded(fx.periodKeys.premium) },
                ],
              },
            });
          },
        },
      });
      const result = await client.unlockRoutes(names, [
        { issuerName: A, unlockUrl: UNLOCK_URL, retryUnavailable: true },
        { issuerName: B, unlockUrl: UNLOCK_URL },
      ]);
      assert.deepEqual(
        posts.map((request) => request.issuerName),
        [A, B],
      );
      assert.equal(result.attempts[0].outcome, "unavailable");
      assert.deepEqual(posts[1].sealed.contentKeys, []);
      assert.deepEqual(
        posts[1].sealed.periodKeys.map((record) => record.accessGroup),
        ["premium"],
      );
      assert.deepEqual(result.missing, missing);
      assert.equal(utf8Decode((await client.openLocal("teaser")).bytes), "teaser");
    });
  }
});

test("an admitted wrong key does not turn family unavailability into conditional recovery", async () => {
  const fx = await fixture({ teaser: "premium" });
  const posts = [];
  const client = createDeliveryClient({
    reader: fx.reader,
    issuerName: A,
    unlockUrl: UNLOCK_URL,
    relayPeriodKeys: true,
    transport: {
      async post(_url, request) {
        posts.push(request.issuerName);
        return request.issuerName === A
          ? ok({
              keys: {
                contentKeys: [{ contentName: "teaser", key: encoded(new Uint8Array(16).fill(99)) }],
              },
              notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
            })
          : ok({
              keys: {
                periodKeys: [
                  { accessGroup: "premium", period: T_NOW, key: encoded(fx.periodKeys.premium) },
                ],
              },
            });
      },
    },
  });
  const routes = [
    { issuerName: A, unlockUrl: UNLOCK_URL, retryUnavailable: true },
    { issuerName: B, unlockUrl: UNLOCK_URL },
  ];
  const unresolved = await client.unlockRoutes(["teaser"], routes);
  assert.deepEqual(posts, [A]);
  assert.deepEqual(unresolved.missing, ["teaser"]);
  assert.deepEqual(unresolved.attempts, [{ issuerName: A, status: 200, outcome: "answered" }]);
  const recovered = await client.unlockRoutes(
    ["teaser"],
    [...routes, { issuerName: C, unlockUrl: UNLOCK_URL, independent: true }],
  );
  assert.deepEqual(posts, [A, A, C]);
  assert.deepEqual(recovered.missing, []);
  assert.equal(utf8Decode((await client.openLocal("teaser")).bytes), "teaser");
});

test("unlock hands the host a report kept beside a rejected client-bound transport", async () => {
  const fx = await fixture({ teaser: "premium" });
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: fx.reader,
    issuerName: A,
    relayPeriodKeys: true,
    transport: {
      async post() {
        return ok({
          keys: { contentKeys: [{ contentName: "teaser", key: { key: "wrapped" } }] },
          transport: { method: "ECDH-P256" },
          notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
        });
      },
    },
  });
  const result = await client.unlock(["teaser"]);
  assert.equal(result.status, 200);
  assert.deepEqual(result.application, {
    accepted: 0,
    errors: [],
    issues: [{ code: "invalid_transport" }],
    notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
  });
  assert.deepEqual((await client.resolve(["teaser"])).missing, ["teaser"], "no direct retry");
});

test("a rejected whole-response transport is unusable and does not activate conditional fallback", async () => {
  const fx = await fixture({ teaser: "premium", third: "sport" });
  const posted = [];
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: fx.reader,
    issuerName: A,
    relayPeriodKeys: true,
    transport: {
      async post(_url, request) {
        posted.push(request.issuerName);
        return ok({
          keys: {
            contentKeys: [
              { contentName: "teaser", key: fx.contentKeys.teaser },
              { contentName: "third", key: { key: "wrapped" } },
            ],
          },
        });
      },
    },
  });
  const result = await client.unlockRoutes(
    ["teaser", "third"],
    [
      { issuerName: A, unlockUrl: "https://a.example/unlock", retryOperational: true },
      { issuerName: "backup", unlockUrl: "https://backup.example/unlock" },
    ],
  );
  assert.deepEqual(posted, [A]);
  assert.equal(result.attempts[0].outcome, "unusable-response");
});

describe("a configured issuer the page carries no usable route for", () => {
  // The page carries B only, or carries A with an endpoint the client does
  // not admit. The host still configures A. Held capability and an explicitly
  // independent route stay usable; only an acquisition from A has no route.
  const absentA = () => fixture({ teaser: "premium" }, { issuers: [B] });
  const httpA = () =>
    fixture(
      { teaser: "premium" },
      {
        issuers: [A, B],
        mutate: (raw) => {
          issuerBlockOf(raw, A).unlockUrl = "http://api.example.com/unlock";
        },
      },
    );

  /** @param {Awaited<ReturnType<typeof fixture>>} fx @param {object} [options] */
  function clientFor(fx, options = {}) {
    /** @type {{ url: string, issuerName: string }[]} */
    const posts = [];
    const client = createDeliveryClient({
      unlockUrl: UNLOCK_URL,
      reader: fx.reader,
      issuerName: A,
      relayPeriodKeys: true,
      transport: {
        async post(url, request) {
          posts.push({ url, issuerName: request.issuerName });
          return ok({
            keys: {
              contentKeys: [],
              periodKeys: [
                { accessGroup: "premium", period: T_NOW, key: encoded(fx.periodKeys.premium) },
              ],
            },
          });
        },
      },
      ...options,
    });
    return { client, posts };
  }

  // A route walk posts only to the URLs of its trusted routes, so a page whose
  // carried A endpoint is unusable still lets the host's own A route answer.
  for (const [label, page, posted] of /** @type {const} */ ([
    ["carries only another issuer", absentA, [B]],
    ["names an endpoint the client does not admit", httpA, [A]],
  ])) {
    test(`a held period key opens the item when the page ${label}`, async () => {
      const fx = await page();
      const { counts, cache } = countingCache({ premium: fx.periodKeys.premium });
      const { client, posts } = clientFor(fx, { cache });

      assert.equal(utf8Decode((await client.openLocal("teaser")).bytes), "teaser");
      assert.equal(utf8Decode((await client.open("teaser")).bytes), "teaser");
      assert.ok(counts.reads > 0, "the key came from the host's cache");
      assert.deepEqual(posts, [], "no issuer is contacted");
    });

    test(`a trusted route walk opens the item when the page ${label}`, async () => {
      const fx = await page();
      const { client, posts } = clientFor(fx);
      const result = await client.unlockRoutes(
        ["teaser"],
        [
          { issuerName: A, unlockUrl: "https://a.example/unlock" },
          { issuerName: B, unlockUrl: "https://b.example/unlock", independent: true },
        ],
      );
      assert.deepEqual(result.missing, []);
      assert.equal(utf8Decode((await client.openLocal("teaser")).bytes), "teaser");
      assert.deepEqual(
        posts.map((post) => post.issuerName),
        posted,
      );
      assert.ok(posts.every((post) => post.url !== "http://api.example.com/unlock"));
    });
  }

  test("acquisition from the absent issuer sends nothing and names the missing route", async () => {
    const fx = await absentA();
    const { client, posts } = clientFor(fx);
    await assert.rejects(client.unlock(["teaser"]), { code: "unknown_issuer" });
    await assert.rejects(client.open("teaser"), { code: "unknown_issuer" });
    assert.deepEqual(posts, []);
  });

  test("a hostile carried endpoint is ignored in favor of the trusted endpoint", async () => {
    const fx = await httpA();
    const { client, posts } = clientFor(fx);
    await client.unlock(["teaser"]);
    assert.equal(posts.length, 1);
    assert.equal(posts[0].url, UNLOCK_URL);
  });

  test("an absent route activates no conditional route after it", async () => {
    const fx = await absentA();
    const { client, posts } = clientFor(fx);
    const result = await client.unlockRoutes(
      ["teaser"],
      [
        { issuerName: A, unlockUrl: "https://a.example/unlock", retryOperational: true },
        { issuerName: B, unlockUrl: "https://b.example/unlock" },
      ],
    );
    assert.deepEqual(result.attempts, [{ issuerName: A, outcome: "not-on-page" }]);
    assert.deepEqual(result.missing, ["teaser"]);
    assert.deepEqual(posts, []);
  });

  test("an unusable unlock URL the host supplies is still refused at construction", async () => {
    const fx = await absentA();
    for (const unlockUrl of ["http://api.example.com/unlock", "", 7]) {
      assert.throws(() => clientFor(fx, { unlockUrl }), { code: "bad_config" }, String(unlockUrl));
    }
  });

  test("a host-supplied unlock URL is used for a page that carries the issuer", async () => {
    const fx = await httpA();
    const { client, posts } = clientFor(fx, { unlockUrl: "https://edge.example/unlock" });
    await client.unlock(["teaser"]);
    assert.deepEqual(posts, [{ url: "https://edge.example/unlock", issuerName: A }]);
  });
});

test("a malformed family report preserves real item opening but no reusable key or conditional retry", async () => {
  const fx = await fixture({ granted: "premium", denied: "premium" });
  const posts = [];
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: fx.reader,
    issuerName: A,
    cache: new PeriodKeyCache(),
    relayPeriodKeys: true,
    transport: {
      async post(_url, request) {
        posts.push(request.issuerName);
        assert.equal(request.issuerName, A, "a contradictory report authorizes no fallback");
        return ok({
          keys: {
            contentKeys: [{ contentName: "granted", key: fx.contentKeys.granted }],
            periodKeys: [
              { accessGroup: "premium", period: T_NOW, key: encoded(fx.periodKeys.premium) },
            ],
          },
          notDelivered: [{ accessGroup: "premium", reason: "unavailable" }],
        });
      },
    },
  });
  const result = await client.unlockRoutes(
    ["granted", "denied"],
    [
      { issuerName: A, unlockUrl: UNLOCK_URL, retryUnavailable: true },
      { issuerName: B, unlockUrl: UNLOCK_URL },
    ],
  );
  assert.deepEqual(posts, [A]);
  assert.deepEqual(result.missing, ["denied"]);
  assert.equal(result.attempts[0].outcome, "answered");
  assert.equal(utf8Decode((await client.openLocal("granted")).bytes), "granted");
  await assert.rejects(() => client.openLocal("denied"), { code: "no_key" });
});

test("an invalid optional report does not clear previously held period capability", async () => {
  const fx = await fixture({ granted: "standard", retained: "premium" });
  const cache = new PeriodKeyCache();
  await cache.put("premium", T_NOW, fx.periodKeys.premium, { publisher: PUB });
  const client = createDeliveryClient({
    reader: fx.reader,
    issuerName: A,
    unlockUrl: UNLOCK_URL,
    cache,
    transport: {
      async post() {
        return ok({
          keys: { contentKeys: [{ contentName: "granted", key: fx.contentKeys.granted }] },
          notDelivered: [],
        });
      },
    },
  });
  await client.unlock(["granted"]);
  assert.equal(utf8Decode((await client.openLocal("granted")).bytes), "granted");
  assert.equal(utf8Decode((await client.openLocal("retained")).bytes), "retained");
});

test("reset during an independent issuer answer retires its walk before a later route and requires fresh authorization", async () => {
  const fx = await fixture({ teaser: "premium" });
  const entered = Promise.withResolvers();
  const released = Promise.withResolvers();
  let hold = true;
  let entitled = true;
  const posts = [];
  const route = (issuerName) => ({
    issuerName,
    unlockUrl: UNLOCK_URL,
    acceptDirectResponse: true,
    independent: true,
  });
  const client = createDeliveryClient({
    reader: fx.reader,
    issuerName: A,
    unlockUrl: UNLOCK_URL,
    acceptDirectResponse: true,
    transport: {
      async post(_url, request) {
        posts.push(request.issuerName);
        if (request.issuerName === A) return { status: 403 };
        const response = entitled
          ? ok({ keys: { contentKeys: [{ contentName: "teaser", key: fx.contentKeys.teaser }] } })
          : { status: 401 };
        if (hold) {
          hold = false;
          entered.resolve();
          await released.promise;
        }
        return response;
      },
    },
  });
  const pending = client.unlockRoutes(["teaser"], [route(A), route(B), route(C)]);
  const retired = assert.rejects(pending, { code: "context_retired" });
  await entered.promise;
  await client.clearReaderContext();
  entitled = false;
  const successor = await client.unlockRoutes(["teaser"], [route(B)]);
  assert.deepEqual(successor.missing, ["teaser"]);
  released.resolve();
  await retired;
  await assert.rejects(client.openLocal("teaser"), { code: "no_key" });
  assert.deepEqual(posts, [A, B, B], "the retired walk never contacts C");
  entitled = true;
  await client.unlockRoutes(["teaser"], [route(B)]);
  assert.equal(utf8Decode((await client.openLocal("teaser")).bytes), "teaser");
});

test("a failed recovered guess preserves configured unavailable retry", async () => {
  const fx = await fixture({ teaser: "premium" });
  const posts = [];
  const client = createDeliveryClient({
    reader: fx.reader,
    issuerName: A,
    unlockUrl: UNLOCK_URL,
    relayPeriodKeys: true,
    recoverySources: [
      {
        maxTrialsPerItem: 4,
        async *candidates() {
          yield { contentKey: new Uint8Array(16).fill(99), origin: { source: "stale-guess" } };
        },
        async clearReaderContext() {},
      },
    ],
    transport: {
      async post(_url, request) {
        posts.push(request.issuerName);
        return request.issuerName === A
          ? ok({ keys: {}, notDelivered: [{ accessGroup: "premium", reason: "unavailable" }] })
          : ok({
              keys: {
                periodKeys: [
                  { accessGroup: "premium", period: T_NOW, key: encoded(fx.periodKeys.premium) },
                ],
              },
            });
      },
    },
  });
  const result = await client.unlockRoutes(
    ["teaser"],
    [
      { issuerName: A, unlockUrl: UNLOCK_URL, retryUnavailable: true },
      { issuerName: B, unlockUrl: UNLOCK_URL },
    ],
  );
  assert.deepEqual(posts, [A, B]);
  assert.equal(result.attempts[0].outcome, "unavailable");
  assert.deepEqual(result.missing, []);
  assert.equal(utf8Decode((await client.openLocal("teaser")).bytes), "teaser");
});
