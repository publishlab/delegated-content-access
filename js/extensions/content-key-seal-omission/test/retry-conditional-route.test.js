// @ts-check
//
// The omission client through the real delivery client: its route walk, the
// conditional-retry projection and the resolver's response admission, against
// issuers that run the real processor and omission engine. Pinned here: an
// item content key the omission issuer returns is admitted and opens; one
// item's failure leaves its sibling's answer standing; a conditional retry
// never carries the original request's bound candidates; and a marked wrap is
// opened only with its binding, never retried without it.

import test from "node:test";
import assert from "node:assert/strict";

import { createBrowserClient } from "../../../integration-client/createBrowserClient.js";
import { writeMarkupDelivery } from "../../../adapter-publisher/writeMarkupDelivery.js";
import { domOver } from "../../../test-lib/helpers/domOver.js";
import { createDeliveryClient } from "../../../integration-client/createDeliveryClient.js";
import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";
import { base64urlEncode, utf8Decode } from "../../../core-shared/codec.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import {
  BoundContentKeyResolver,
  omissionContentKeyResolverFactory,
} from "../core-client/BoundContentKeyResolver.js";
import { omissionEntryInterpretation } from "../core-client/omissionEntryInterpretation.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import { EXTENSION_NAME, OMISSION_BIND_IDENTIFIER } from "../core-shared/omissionBind.js";
import {
  ARTICLE,
  ISSUER_A,
  ISSUER_B,
  PERIODS,
  PUB,
  SIDEBAR,
  contentOnlyPolicy,
  render,
  world,
} from "../test-lib/world.js";

const { subtle } = globalThis.crypto;
const ITEMS = ["bodytext", "sidebar"];

/** @param {string} issuerName */
const routeTo = (issuerName) => ({
  issuerName,
  unlockUrl: `https://${issuerName}.example.com/unlock`,
});

/**
 * A render with both issuers active, and a delivery client composed with the
 * omission builder and resolver. Each issuer is the real processor over the
 * omission engine; `fault` names issuers whose transport answers 500 first.
 *
 * @param {{
 *   policies: Record<string, { decide: Function }>,
 *   fault?: string[],
 *   mutate?: (delivery: any) => void,
 *   rewrite?: (body: any) => any,
 *   resolverFactory?: (options: object) => any,
 * }} options
 */
async function walkWorld({
  policies,
  fault = [],
  mutate,
  rewrite = (body) => body,
  resolverFactory = omissionContentKeyResolverFactory,
}) {
  const { issuerConfig, registration, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [
          issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] }),
          issuerConfig(ISSUER_B, { extensions: [EXTENSION_NAME] }),
        ],
      }),
    ),
    { items: ITEMS },
  );
  const { sealedContent, ...delivery } = page;
  mutate?.(delivery);
  /** @type {Record<string, UnlockEndpoint>} */
  const endpoints = Object.fromEntries(
    Object.entries(policies).map(([issuerName, accessPolicy]) => [
      issuerName,
      new UnlockEndpoint(
        new IssuerProcessor(
          omissionIssuerEngine({ operatingIssuerNames: [issuerName], accessPolicy }),
          { periodKeyInput: true },
        ),
      ),
    ]),
  );
  /** @type {any[]} */
  const posts = [];
  /** @type {any[]} */
  const answers = [];
  const client = createDeliveryClient({
    unlockUrl: "https://issuer.example/unlock",
    reader: {
      dcaData: delivery,
      publisherOrigin: PUB,
      extract: (/** @type {string} */ name) => sealedContent[name] ?? null,
    },
    issuerName: ISSUER_A,
    relayPeriodKeys: true,
    requestBuilderFactory: (options) => new OmissionRequestBuilder(options),
    resolverFactory,
    transport: {
      async post(_url, request) {
        posts.push(structuredClone(request));
        if (fault.includes(request.issuerName)) return { status: 500, contentType: null };
        const { response } = await endpoints[request.issuerName].handleDocument(
          JSON.stringify(request),
          registration,
        );
        answers.push(structuredClone(response.body));
        return { ...response, body: rewrite(response.body), contentType: "application/json" };
      },
    },
  });
  return { page, client, posts, answers };
}

test("an item content key from the omission issuer is admitted, and a failed sibling stays its own", async () => {
  // A grants both items but may open only premium coordinates, so sidebar's
  // forwarded candidates reach nothing: one per-item error beside bodytext's key.
  const { client, posts, answers } = await walkWorld({
    policies: {
      [ISSUER_A]: contentOnlyPolicy(ITEMS, {
        sourceGrants: [{ accessGroup: "premium", periods: PERIODS }],
      }),
      [ISSUER_B]: contentOnlyPolicy(["sidebar"]),
    },
  });

  const result = await client.unlockRoutes(ITEMS, [
    routeTo(ISSUER_A),
    { ...routeTo(ISSUER_B), independent: true },
  ]);

  assert.deepEqual(Object.keys(answers[0].keys.contentKeys), ["bodytext"]);
  assert.deepEqual(Object.keys(answers[0].errors), ["sidebar"]);
  assert.deepEqual(
    posts.map((request) => request.issuerName),
    [ISSUER_A, ISSUER_B],
  );
  // The later route asks only for what is still missing: one item's bound
  // candidates and that item's period family, never the original request.
  assert.deepEqual(Object.keys(posts[1].boundCandidates), ["sidebar"]);
  assert.deepEqual(Object.keys(posts[1].sealed.periodKeys), ["free"]);
  assert.deepEqual(posts[1].sealed.contentKeys, {});
  assert.deepEqual(result, {
    missing: [],
    attempts: [
      { issuerName: ISSUER_A, status: 200, outcome: "answered" },
      { issuerName: ISSUER_B, status: 200, outcome: "answered" },
    ],
    failed: [],
  });
  assert.equal(utf8Decode((await client.openLocal("bodytext")).bytes), ARTICLE);
  assert.equal(utf8Decode((await client.openLocal("sidebar")).bytes), SIDEBAR);
});

test("the exported BoundContentKeyResolver answers every public resolver method", () => {
  // The class stands in for the base resolver through resolverFactory, so a
  // route walk or a later caller must not find a base method missing.
  const bound = new BoundContentKeyResolver();
  const methods = Object.getOwnPropertyNames(ContentKeyResolver.prototype).filter(
    (name) => name !== "constructor",
  );
  assert.ok(methods.includes("resolveAuthenticated"));
  assert.deepEqual(
    methods.filter((name) => typeof (/** @type {any} */ (bound)[name]) !== "function"),
    [],
  );
});

test("a client composed with BoundContentKeyResolver walks routes as the factory resolver does", async () => {
  const { client, posts } = await walkWorld({
    policies: {
      [ISSUER_A]: contentOnlyPolicy(ITEMS, {
        sourceGrants: [{ accessGroup: "premium", periods: PERIODS }],
      }),
      [ISSUER_B]: contentOnlyPolicy(["sidebar"]),
    },
    resolverFactory: (options) => new BoundContentKeyResolver(options),
  });

  const result = await client.unlockRoutes(ITEMS, [
    routeTo(ISSUER_A),
    { ...routeTo(ISSUER_B), independent: true },
  ]);

  assert.deepEqual(
    posts.map((request) => request.issuerName),
    [ISSUER_A, ISSUER_B],
  );
  assert.deepEqual(Object.keys(posts[1].boundCandidates), ["sidebar"]);
  assert.deepEqual(result, {
    missing: [],
    attempts: [
      { issuerName: ISSUER_A, status: 200, outcome: "answered" },
      { issuerName: ISSUER_B, status: 200, outcome: "answered" },
    ],
    failed: [],
  });
  assert.equal(utf8Decode((await client.openLocal("bodytext")).bytes), ARTICLE);
  assert.equal(utf8Decode((await client.openLocal("sidebar")).bytes), SIDEBAR);
  await client.clearAccessDecisions();
  assert.equal(utf8Decode((await client.openLocal("bodytext")).bytes), ARTICLE);
  await client.clearReaderContext();
  await assert.rejects(client.openLocal("bodytext"), { code: "no_key" });
  await assert.rejects(client.openLocal("sidebar"), { code: "no_key" });
});

test("an omission error names the item it failed, and the resolver admits it as that item's", async () => {
  const { client } = await walkWorld({
    policies: {
      [ISSUER_A]: contentOnlyPolicy(ITEMS, {
        sourceGrants: [{ accessGroup: "premium", periods: PERIODS }],
      }),
    },
  });
  const { application } = /** @type {any} */ (await client.unlock(ITEMS));
  assert.deepEqual(application.issues, [], "neither the key nor the error is unsolicited");
  assert.equal(application.accepted, 1);
  assert.equal(application.errors.length, 1, "sidebar's error is admitted as its own");
  assert.deepEqual((await client.resolve(ITEMS)).missing, ["sidebar"]);
});

test("a key for an item the omission request did not present stays unsolicited", async () => {
  // The request presents bodytext alone; the answer adds a key named sidebar.
  const { client } = await walkWorld({
    policies: { [ISSUER_A]: contentOnlyPolicy(ITEMS) },
    rewrite: (body) => ({
      ...body,
      keys: { contentKeys: { ...body.keys.contentKeys, sidebar: body.keys.contentKeys.bodytext } },
    }),
  });
  const { application } = /** @type {any} */ (await client.unlock(["bodytext"]));
  assert.equal(application.accepted, 1);
  assert.deepEqual(application.issues, [
    { section: "contentKeys", code: "unsolicited_coordinate" },
  ]);
  assert.deepEqual((await client.resolve(ITEMS)).missing, ["sidebar"]);
});

test("the presentation reading is the composition's own, and a broken one is configuration", async () => {
  assert.throws(() => new ContentKeyResolver({ presentedContentNames: ["bodytext"] }), {
    code: "bad_config",
  });
  assert.throws(() => omissionContentKeyResolverFactory({ presentedContentNames: () => [] }), {
    code: "unsupported_option",
  });
  const { client } = await walkWorld({
    policies: { [ISSUER_A]: contentOnlyPolicy(ITEMS) },
    resolverFactory: (options) =>
      new ContentKeyResolver({
        ...options,
        entryInterpretation: omissionEntryInterpretation,
        presentedContentNames: () => "bodytext",
      }),
  });
  await assert.rejects(client.unlock(["bodytext"]), { code: "bad_config" });
});

for (const [label, routes, expectedOutcome] of /** @type {const} */ ([
  [
    "an operational failure selected for retry",
    [{ ...routeTo(ISSUER_A), retryOperational: true }, routeTo(ISSUER_B)],
    "unsupported-retry-projection",
  ],
  [
    "an operational failure without the retry choice",
    [routeTo(ISSUER_A), routeTo(ISSUER_B)],
    undefined,
  ],
])) {
  test(`a conditional route after ${label} never forwards the original omission request`, async () => {
    const { client, posts } = await walkWorld({
      policies: { [ISSUER_A]: contentOnlyPolicy(ITEMS), [ISSUER_B]: contentOnlyPolicy(ITEMS) },
      fault: [ISSUER_A],
    });
    const result = await client.unlockRoutes(ITEMS, [...routes]);
    assert.deepEqual(
      posts.map((request) => request.issuerName),
      [ISSUER_A],
      "only the first issuer is contacted",
    );
    assert.deepEqual(result.missing, ITEMS);
    assert.deepEqual(result.attempts, [
      { issuerName: ISSUER_A, status: 500, outcome: "fault" },
      ...(expectedOutcome ? [{ issuerName: ISSUER_B, outcome: expectedOutcome }] : []),
    ]);
  });
}

test("a conditional route after a per-item failure is not activated", async () => {
  const { client, posts } = await walkWorld({
    policies: {
      [ISSUER_A]: contentOnlyPolicy(ITEMS, {
        sourceGrants: [{ accessGroup: "premium", periods: PERIODS }],
      }),
      [ISSUER_B]: contentOnlyPolicy(ITEMS),
    },
  });
  const result = await client.unlockRoutes(ITEMS, [
    { ...routeTo(ISSUER_A), retryOperational: true, retryUnavailable: true },
    routeTo(ISSUER_B),
  ]);
  assert.deepEqual(
    posts.map((request) => request.issuerName),
    [ISSUER_A],
  );
  assert.deepEqual(result.missing, ["sidebar"]);
  // A route activated and then refused as unsupported-retry-projection posts
  // nothing either; only the attempts list shows B was never reached.
  assert.deepEqual(result.attempts, [{ issuerName: ISSUER_A, status: 200, outcome: "answered" }]);
});

test("the walk opens marked wraps only with their binding and skips an unknown marker", async () => {
  const { client, page } = await walkWorld({
    policies: { [ISSUER_A]: new AllowAllPolicy() },
    // One sidebar entry carries a marker this composition does not own.
    mutate: (delivery) => {
      delivery.contentData.sidebar.keys.free[0].bind = "another-binding";
    },
  });
  assert.equal(page.contentData.bodytext.keys.premium[0].bind, OMISSION_BIND_IDENTIFIER);

  /** @type {{ bytes: string, bound: boolean }[]} */
  const decrypts = [];
  const originalDecrypt = subtle.decrypt;
  subtle.decrypt = function (algorithm, key, data) {
    const view = /** @type {ArrayBufferView} */ (data);
    decrypts.push({
      bytes: base64urlEncode(new Uint8Array(view.buffer, view.byteOffset, view.byteLength)),
      bound: /** @type {any} */ (algorithm).additionalData !== undefined,
    });
    return originalDecrypt.call(subtle, algorithm, key, data);
  };
  let result;
  try {
    result = await client.unlockRoutes(ITEMS, [routeTo(ISSUER_A)]);
  } finally {
    subtle.decrypt = originalDecrypt;
  }

  // Content-key wraps are the only decrypts whose bytes sit in contentData keys.
  const entryOf = new Map(
    ITEMS.flatMap((name) =>
      Object.values(page.contentData[name].keys)
        .flat()
        .map((/** @type {any} */ entry) => [`${entry.nonce}|${entry.key}`, entry]),
    ),
  );
  const keyBytes = new Set([...entryOf.values()].map((entry) => entry.key));
  const wraps = decrypts.filter((call) => keyBytes.has(call.bytes));
  assert.ok(wraps.length > 0, "the walk tried the bound wraps");
  assert.equal(
    wraps.some((call) => call.bytes === page.contentData.sidebar.keys.free[0].key),
    false,
    "the entry with an unknown marker is never tried",
  );
  assert.deepEqual(
    wraps.filter((call) => !call.bound),
    [],
    "no wrap is ever tried without its binding",
  );
  assert.deepEqual(result.missing, []);
  assert.equal(utf8Decode((await client.openLocal("bodytext")).bytes), ARTICLE);
});

test("browser construction rejects an omission wrapper over an unsupported retaining cache", async () => {
  const { client } = await walkWorld({ policies: { [ISSUER_A]: new AllowAllPolicy() } });
  const markup = writeMarkupDelivery({
    dcaData: client.reader.dcaData,
    sealedContent: Object.fromEntries(ITEMS.map((name) => [name, client.reader.extract(name)])),
  });
  assert.throws(
    () =>
      createBrowserClient({
        root: domOver(markup, { publisherOrigin: PUB }),
        issuerName: ISSUER_A,
        transport: { post: async () => ({ status: 403, contentType: null }) },
        cache: { put() {}, candidatesAt: async () => [], attempted() {} },
        resolverFactory: (options) => new BoundContentKeyResolver(options),
      }),
    { code: "bad_config" },
  );
});
