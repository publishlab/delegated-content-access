// @ts-check
//
// One selected chain-key profile through publisher, request relay, issuer
// and client. Requested: dca-profile-chain-keys, with dca-profile-html-carrier for the
// carrier. Resolved: dca-profile-baseline, dca-profile-html-carrier, dca-profile-period-keys
// and dca-profile-chain-keys. The issuer's two selected response forms need
// different client capabilities, so each runs end to end.
// A third scenario supplies period-key and chain-key members to an issuer that
// selected period-key input only; publisher supply, client relay, issuer input and client
// response acceptance are configured separately there.
//
// The prefix scenarios near the end follow one returned cutoff key through its
// whole reach: every item from the window start through the cutoff opens to its
// own text from one unlock, while a later position in the same window and both
// adjacent windows open nothing. A policy that authorizes no period and three chain
// results the request cannot associate stand beside it as refusals.
//
// Carrier as run: the demo browser reads each delivery with
// `MarkupDeliveryReader` over a root of fabricated carrier elements
// (`rootFromPage`), so the client side runs HTML-carrier extraction. No markup
// string is written or parsed here, and no test in this file crosses the
// serialized JSON document.
// The tags name the chain-key duties only.

import test from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { URL } from "node:url";

import { ContentKeyResolver } from "../core-client/ContentKeyResolver.js";
import { base64urlEncode } from "../core-shared/codec.js";
import { Clock } from "../demo/actors/Clock.js";
import { rootFromPage } from "../demo/support/queryableRoot.js";
import { actorWorld, readArticle } from "../demo/scenarios/world.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  CONTENT_NAME,
  CONTENT_TYPE,
  ISSUER_NAME,
  keyDerivationSecret,
} from "../demo/scenarios/fixtures.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import {
  explicitChainKeyClientProfile,
  referenceChainKeyProfile,
} from "../extensions/chain-keys/referenceProfile.js";
import {
  GEOMETRY,
  chainGeneration,
  chainPartition,
  chainSupply,
  coordinatesOf,
  deliveryPlan,
  periodOnlyPolicy,
} from "../extensions/chain-keys/test/world.js";

/** @param {"period-keys"|"chain-keys"} responseForm */
async function selectedWorld(responseForm) {
  const generation = chainGeneration(7);
  const chainCache = new ChainKeyCache({ strategy: "retain" });
  const basePlan = deliveryPlan(() => ["chain-keys"]);
  const issuerSupplyPlanFor = (/** @type {any} */ issuer, /** @type {any} */ render) => ({
    ...basePlan(issuer, render),
    contentKeyNames: [],
  });
  const issuerProfile =
    responseForm === "chain-keys"
      ? referenceChainKeyProfile
      : {
          ...referenceChainKeyProfile,
          issuerEngineFor: referenceChainKeyProfile.explicitIssuerEngineFor,
        };
  const world = await actorWorld({
    periodKeySupply: chainSupply(generation),
    issuerSupplyPlanFor,
    accessPolicy: periodOnlyPolicy(1),
    chainKeyProfile: issuerProfile,
    chainKeyCacheFactory: () => chainCache,
    primary: { periodGrantKind: "chain-keys" },
  });
  const exchanges = [];
  const network = {
    async post(url, request, options) {
      const answer = await world.network.post(url, request, options);
      exchanges.push({
        request: JSON.parse(JSON.stringify(request)),
        response: JSON.parse(JSON.stringify(answer.body)),
      });
      return answer;
    },
  };
  const requestBuilderFactory = (/** @type {object} */ options) =>
    new ChainKeyRequestBuilder(options);
  const browser =
    responseForm === "chain-keys"
      ? world.makeBrowser({ network, chainKeyStrategy: "retain", requestBuilderFactory })
      : world.makeBrowser({
          // Relay the chain keys and admit projected period keys without a chain-key cache.
          network,
          chainKeyProfile: undefined,
          chainKeyCacheFactory: undefined,
          requestBuilderFactory,
          resolverFactory: (/** @type {object} */ options) =>
            new ContentKeyResolver({
              ...options,
              chainKeyProfile: explicitChainKeyClientProfile,
            }),
        });
  return { world, browser, generation, chainCache, network, exchanges };
}

/** @param {any} delivery */
function suppliedChainOnly(delivery) {
  const sealed = delivery.issuerData[ISSUER_NAME].sealed;
  assert.equal(sealed.contentKeys, undefined);
  assert.equal(sealed.periodKeys, undefined);
  assert.ok(sealed.chainKeys[ACCESS_GROUP]);
  assert.ok(delivery.contentData[CONTENT_NAME].keys[ACCESS_GROUP].length > 0);
  assert.ok(delivery.periodGeometry);
}

test(
  "chain-key-only publisher supply projects a period key for a relay-only client",
  {
    tags: [
      "dca-profile-chain-keys/publisher/chain-supply",
      "dca-profile-chain-keys/client/chain-relay",
      "dca-profile-chain-keys/issuer/chain-input",
      "dca-profile-chain-keys/client/projected-period-key-admission",
    ],
  },
  async () => {
    const { world, browser, generation, exchanges } = await selectedWorld("period-keys");
    const page = await world.render("A");
    suppliedChainOnly(page.asJson());

    const read = await readArticle(browser, page, [CONTENT_NAME]);
    assert.equal(read.unlock.ok, true);
    assert.equal(read.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(exchanges.length, 1);

    const [{ request, response }] = exchanges;
    assert.deepEqual(request.sealed.contentKeys, {});
    assert.equal(request.sealed.periodKeys, undefined);
    assert.deepEqual(
      request.sealed.chainKeys,
      page.asJson().issuerData[ISSUER_NAME].sealed.chainKeys,
    );
    assert.deepEqual(request.periodGeometry, page.asJson().periodGeometry);
    assert.equal(response.keys.chainKeys, undefined, "this route never sends a chain key");
    assert.equal(response.periodGeometry, undefined);
    assert.deepEqual(response.keys.contentKeys, {});
    const periodKeys = response.keys.periodKeys[ACCESS_GROUP];
    const labels = ["251023T1415"];
    assert.deepEqual(Object.keys(periodKeys), labels);
    for (const t of labels) {
      assert.equal(periodKeys[t], base64urlEncode(await generation.periodKey(ACCESS_GROUP, t)));
    }
  },
);

test(
  "chain-key-only publisher supply returns a positioned chain key for a chain-aware client",
  {
    tags: [
      "dca-profile-chain-keys/publisher/chain-supply",
      "dca-profile-chain-keys/client/chain-relay",
      "dca-profile-chain-keys/issuer/chain-input",
      "dca-profile-chain-keys/issuer/chain-output",
      "dca-profile-chain-keys/client/chain-derivation",
    ],
  },
  async () => {
    const { world, browser, generation, chainCache, exchanges } = await selectedWorld("chain-keys");
    const page = await world.render("A");
    suppliedChainOnly(page.asJson());

    const read = await readArticle(browser, page, [CONTENT_NAME]);
    assert.equal(read.unlock.ok, true);
    assert.equal(read.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(exchanges.length, 1);

    const [{ request, response }] = exchanges;
    assert.deepEqual(
      request.sealed.chainKeys,
      page.asJson().issuerData[ISSUER_NAME].sealed.chainKeys,
    );
    assert.deepEqual(request.periodGeometry, page.asJson().periodGeometry);
    assert.deepEqual(response.keys.contentKeys, {});
    assert.equal(response.keys.periodKeys, undefined);
    const chainKeys = response.keys.chainKeys[ACCESS_GROUP];
    const [cutoff] = Object.keys(chainKeys);
    assert.equal(Object.keys(chainKeys).length, 1);
    assert.equal(Object.hasOwn(response, "periodGeometry"), false);
    assert.equal(
      chainKeys[cutoff],
      base64urlEncode((await generation.chainCapability(ACCESS_GROUP, cutoff)).key),
    );
    const derived = await chainCache.candidates(ACCESS_GROUP, cutoff, {
      publisher: world.publisher.origin,
      ...request.periodGeometry,
    });
    const expectedPeriodKey = base64urlEncode(await generation.periodKey(ACCESS_GROUP, cutoff));
    assert.ok(derived.some((periodKey) => base64urlEncode(periodKey) === expectedPeriodKey));
  },
);

test(
  "relay-only client refuses a chain key from an issuer configured for chain-key clients",
  { tags: ["dca-profile-chain-keys/client/projected-period-key-admission"] },
  async () => {
    const { world, generation, network, exchanges } = await selectedWorld("chain-keys");
    // This mismatched deployment selection violates the issuer's trusted route
    // condition; the client must still refuse the chain result it cannot admit.
    const browser = world.makeBrowser({
      network,
      chainKeyProfile: undefined,
      chainKeyCacheFactory: undefined,
      requestBuilderFactory: (/** @type {object} */ options) => new ChainKeyRequestBuilder(options),
    });
    const page = await world.render("A");
    suppliedChainOnly(page.asJson());

    const read = await readArticle(browser, page, [CONTENT_NAME]);
    assert.equal(read.unlock.ok, false);
    assert.deepEqual(
      read.unlock.attempts.map((/** @type {any} */ attempt) => attempt.outcome),
      ["unsupported_section"],
    );
    assert.equal(read.texts[CONTENT_NAME], null);
    assert.deepEqual(await browser.cache.entries(), []);
    assert.equal(exchanges.length, 1);

    const [{ request, response }] = exchanges;
    assert.deepEqual(
      request.sealed.chainKeys,
      page.asJson().issuerData[ISSUER_NAME].sealed.chainKeys,
    );
    assert.equal(Object.hasOwn(response, "periodGeometry"), false);
    assert.equal(response.keys.periodKeys, undefined);
    const [cutoff] = Object.keys(response.keys.chainKeys[ACCESS_GROUP]);
    assert.equal(
      response.keys.chainKeys[ACCESS_GROUP][cutoff],
      base64urlEncode((await generation.chainCapability(ACCESS_GROUP, cutoff)).key),
    );
  },
);

test("an unknown member in a chain-key response is ignored and supplies no chain key", async () => {
  const { world, chainCache } = await selectedWorld("chain-keys");
  /** @type {string[]} */
  const issuedLabels = [];
  // The unknown member carries a different key at every label `chainKeys` answers.
  const decoy = base64urlEncode(new Uint8Array(16));
  const browser = world.makeBrowser({
    network: {
      async post(
        /** @type {string} */ url,
        /** @type {any} */ request,
        /** @type {any} */ options,
      ) {
        const answer = await world.network.post(url, request, options);
        const body = JSON.parse(JSON.stringify(answer.body));
        const labels = Object.keys(body.keys?.chainKeys?.[ACCESS_GROUP] ?? {});
        issuedLabels.push(...labels);
        const futureKeys = {
          [ACCESS_GROUP]: Object.fromEntries(labels.map((t) => [t, decoy])),
        };
        return { ...answer, body: { ...body, keys: { ...body.keys, futureKeys } } };
      },
    },
    chainKeyStrategy: "retain",
    requestBuilderFactory: (/** @type {object} */ options) => new ChainKeyRequestBuilder(options),
  });
  const page = await world.render("A");

  const read = await readArticle(browser, page, [CONTENT_NAME]);
  assert.equal(read.unlock.ok, true);
  assert.equal(read.texts[CONTENT_NAME], ARTICLES.A);
  assert.equal(issuedLabels.length, 1, "the issuer answered one chain key");
  const geometry = page.asJson().periodGeometry;
  const cached = await chainCache.candidates(ACCESS_GROUP, issuedLabels[0], {
    publisher: world.publisher.origin,
    ...(geometry.accessGroups?.[ACCESS_GROUP] ?? geometry),
  });
  assert.ok(cached.length > 0, "the client cached the chain key from `chainKeys`");
  for (const candidate of cached) {
    const key = candidate.kind === "chain-key" ? candidate.chainKey : candidate.key;
    assert.notEqual(base64urlEncode(key), decoy, "and none from the unknown member");
  }
});

test("period-key and chain-key supply reach a period-key-only issuer that grants by its own policy", async () => {
  const generation = chainGeneration(7);
  const basePlan = deliveryPlan(() => ["period-keys", "chain-keys"]);
  /** @type {{ user: string|null, accessGroups: string[] }[]} */
  const asked = [];
  const world = await actorWorld({
    // Publisher supply: period-key and chain-key members of one family generation.
    periodKeySupply: chainSupply(generation),
    issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) => ({
      ...basePlan(issuer, render),
      contentKeyNames: [],
    }),
    // Issuer input: period keys only. The primary gets no chainKeyProfile and no
    // periodGrantKind "chain-keys", so it composes no chain-key input or output
    // handler.
    periodKeyInput: true,
    accessPolicy: {
      decide(
        /** @type {any} */ _claims,
        /** @type {{ accessGroups: string[], periodCoordinates: Record<string, string[]> }} */ requested,
        /** @type {any} */ input,
      ) {
        asked.push({ user: input.principal?.user ?? null, accessGroups: requested.accessGroups });
        const entitled = input.principal?.entitlements?.includes("premium-reader") === true;
        return {
          contentNames: [],
          periodGrants: entitled
            ? requested.accessGroups.map((accessGroup) => ({
                accessGroup,
                periods: (requested.periodCoordinates[accessGroup] ?? []).slice(0, 1),
              }))
            : [],
        };
      },
    },
  });
  world.servers.primary.grant("subscriber", { entitlements: ["premium-reader"] });
  world.servers.primary.grant("lapsed", { entitlements: [] });

  /** @param {any[]} exchanges */
  const recording = (exchanges) => ({
    async post(/** @type {string} */ url, /** @type {any} */ request, /** @type {any} */ options) {
      const answer = await world.network.post(url, request, options);
      exchanges.push({
        request: JSON.parse(JSON.stringify(request)),
        status: answer.status,
        response: JSON.parse(JSON.stringify(answer.body)),
      });
      return answer;
    },
  });
  // Client relay: period-key relay selected, and chain-key members relayed
  // unchanged beside them. Client response acceptance: period-key results only.
  // The browser clears chainKeyProfile and the chain-key cache itself, so a
  // later world setting cannot select chain-key acceptance for it.
  const periodKeyClient = (/** @type {any[]} */ exchanges) =>
    world.makeBrowser({
      network: recording(exchanges),
      chainKeyProfile: undefined,
      chainKeyCacheFactory: undefined,
      relayPeriodKeys: true,
      requestBuilderFactory: (/** @type {object} */ options) => new ChainKeyRequestBuilder(options),
    });

  const page = await world.render("A");
  const delivery = page.asJson();
  const supplied = delivery.issuerData[ISSUER_NAME].sealed;
  assert.equal(supplied.contentKeys, undefined);
  assert.ok(Object.keys(supplied.periodKeys[ACCESS_GROUP]).length > 0);
  assert.ok(Object.keys(supplied.chainKeys[ACCESS_GROUP]).length > 0);
  assert.ok(delivery.periodGeometry);

  const exchanges = [];
  const subscriber = periodKeyClient(exchanges);
  const read = await readArticle(subscriber, page, [CONTENT_NAME], { credential: "subscriber" });
  assert.equal(read.unlock.ok, true);
  assert.equal(read.texts[CONTENT_NAME], ARTICLES.A);
  assert.equal(exchanges.length, 1);
  assert.ok((await subscriber.cache.entries()).length > 0, "the period key is retained");

  const [{ request, response }] = exchanges;
  // The request keeps the period-key members beside the chain-key members:
  // chain-key presence does not replace the period keys.
  assert.deepEqual(request.sealed.contentKeys, {});
  assert.deepEqual(request.sealed.periodKeys, supplied.periodKeys);
  assert.deepEqual(request.sealed.chainKeys, supplied.chainKeys);
  assert.deepEqual(request.periodGeometry, delivery.periodGeometry);
  // The issuer answers only the first explicit period label its policy granted and
  // returns no chain key.
  assert.equal(response.keys.chainKeys, undefined);
  assert.equal(response.periodGeometry, undefined);
  assert.deepEqual(response.keys.contentKeys, {});
  const periodKeys = response.keys.periodKeys[ACCESS_GROUP];
  const [firstSupplied] = Object.keys(supplied.periodKeys[ACCESS_GROUP]).sort();
  assert.deepEqual(Object.keys(periodKeys), [firstSupplied]);
  assert.equal(
    periodKeys[firstSupplied],
    base64urlEncode(await generation.periodKey(ACCESS_GROUP, firstSupplied)),
  );

  // Entitlement stays the issuer's policy decision: a reader the policy denies
  // presents both supplied forms and receives no capability.
  const deniedExchanges = [];
  const denied = await readArticle(periodKeyClient(deniedExchanges), page, [CONTENT_NAME], {
    credential: "lapsed",
  });
  assert.equal(denied.unlock.ok, false);
  assert.equal(denied.texts[CONTENT_NAME], null);
  assert.equal(deniedExchanges.length, 1);
  const [refused] = deniedExchanges;
  assert.deepEqual(refused.request.sealed.periodKeys, supplied.periodKeys);
  assert.deepEqual(refused.request.sealed.chainKeys, supplied.chainKeys);
  assert.equal(refused.status, 401);
  assert.equal(refused.response.keys, undefined);

  assert.deepEqual(asked, [
    { user: "subscriber", accessGroups: [ACCESS_GROUP] },
    { user: "lapsed", accessGroups: [ACCESS_GROUP] },
  ]);
  assert.equal(world.servers.primary.stats().grants, 1);
});

// The frozen canonical-construction vectors come from a direct WebCrypto
// generator that does not import the extension
// (js/extensions/chain-keys/tools/regenerate-canonical-vectors.mjs). Their case
// c1 is this world's family, so its cutoff chain key and period keys are a witness the
// code under test did not produce.
const WITNESS = JSON.parse(
  readFileSync(
    new URL(
      "../extensions/chain-keys/test/fixtures/dca-profile-chain-keys.vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
).cases.find((/** @type {any} */ entry) => entry.id === "c1");

/** The issuer's and client's clock for every prefix scenario. */
const ISSUER_NOW = "2025-10-23T14:20:00Z";

/**
 * The window start through the cutoff, spelled out rather than derived, so the
 * reach is pinned to the labels and not to the code that computes them.
 */
const PREFIX = [
  "251023T1200",
  "251023T1215",
  "251023T1230",
  "251023T1245",
  "251023T1300",
  "251023T1315",
  "251023T1330",
  "251023T1345",
  "251023T1400",
  "251023T1415",
];
const CUTOFF = "251023T1415";

/** Coordinates the cutoff key cannot reach, one per reason. */
const OUT_OF_REACH = [
  { t: "251023T1430", why: "a later position in the cutoff's window" },
  { t: "251023T1145", why: "the preceding window" },
  { t: "251024T0000", why: "the next window" },
];

/** @param {string} t - a fixed-form label, as the instant it starts */
const instant = (t) =>
  `20${t.slice(0, 2)}-${t.slice(2, 4)}-${t.slice(4, 6)}T${t.slice(7, 9)}:${t.slice(9, 11)}:00Z`;

/** @param {string} t - the known text the item sealed at `t` carries */
const bulletin = (t) => `<p>Harbour bulletin for period ${t}.</p>`;

/**
 * A chain-output world whose issuer and client clock stays at ISSUER_NOW. A
 * separate publisher clock renders each item at its own coordinate, so no step
 * moves the issuer's captured time and every probe asks what the one returned
 * cutoff key reaches, never what a later grant would add.
 *
 * @param {{ futurePeriodCount: number, rewrite?: (body: any) => any, authorizePeriod?: (t: string) => boolean }} options -
 *   `rewrite` changes the issuer's answer before the client reads it
 */
async function prefixWorld({
  futurePeriodCount,
  rewrite = (body) => body,
  authorizePeriod = () => true,
}) {
  const chainCache = new ChainKeyCache({ strategy: "retain" });
  const basePlan = deliveryPlan(() => ["chain-keys"]);
  const policy = periodOnlyPolicy(futurePeriodCount, authorizePeriod);
  /** @type {any[]} */
  const decisions = [];
  const world = await actorWorld({
    at: ISSUER_NOW,
    // One wrap per render: each item opens at its own coordinate and no other.
    period: { slots: 1 },
    periodKeySupply: chainSupply(chainGeneration(7)),
    issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) => ({
      ...basePlan(issuer, render),
      contentKeyNames: [],
    }),
    accessPolicy: {
      decide(/** @type {any} */ claims, /** @type {any} */ requested) {
        const answer = policy.decide(claims, requested);
        decisions.push({
          contentNames: [...answer.contentNames],
          periodGrants: answer.periodGrants.map(
            ({ accessGroup, futurePeriodCount, authorizePeriod }) => ({
              accessGroup,
              futurePeriodCount,
              authorizedAtCutoff: authorizePeriod(CUTOFF),
            }),
          ),
        });
        return answer;
      },
    },
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => chainCache,
    primary: { periodGrantKind: "chain-keys" },
  });

  // Every chain envelope opens under the issuer's key store, so its reads
  // count the chain members the issuer opened.
  const keyStore = world.keyStores.primary;
  const read = keyStore.get.bind(keyStore);
  let openingKeyReads = 0;
  Object.defineProperty(keyStore, "get", {
    configurable: true,
    value: (/** @type {any[]} */ ...args) => {
      openingKeyReads++;
      return read(...args);
    },
  });

  /** @type {{ request: any, status: number, response: any }[]} */
  const exchanges = [];
  const browser = world.makeBrowser({
    network: {
      async post(
        /** @type {string} */ url,
        /** @type {any} */ request,
        /** @type {any} */ options,
      ) {
        const answer = await world.network.post(url, request, options);
        const body = JSON.parse(JSON.stringify(answer.body));
        exchanges.push({
          request: JSON.parse(JSON.stringify(request)),
          status: answer.status,
          response: body,
        });
        return { ...answer, body: rewrite(JSON.parse(JSON.stringify(body))) };
      },
    },
    chainKeyStrategy: "retain",
    requestBuilderFactory: (/** @type {object} */ options) => new ChainKeyRequestBuilder(options),
  });

  const publisherClock = new Clock(ISSUER_NOW);
  const publisher = world.publisherWith({ clock: publisherClock });
  /** @param {string} t */
  const renderAt = (t) => {
    publisherClock.set(instant(t));
    return publisher.render({
      resourceId: `bulletin-${t}`,
      data: { section: "harbour" },
      items: [
        {
          name: CONTENT_NAME,
          value: bulletin(t),
          contentType: CONTENT_TYPE,
          accessGroups: [ACCESS_GROUP],
        },
      ],
    });
  };
  return {
    world,
    browser,
    chainCache,
    exchanges,
    decisions,
    renderAt,
    openingKeyReads: () => openingKeyReads,
  };
}

/** What the client holds: chain keys, their memoized period keys and base period keys. */
async function retainedBy(/** @type {any} */ browser, /** @type {any} */ chainCache) {
  return { chainKeys: chainCache.entries(), periodKeys: await browser.cache.entries() };
}

test("the frozen construction vectors' case c1 is the prefix world's family", () => {
  assert.equal(WITNESS.accessGroup, ACCESS_GROUP);
  assert.deepEqual(
    { chainsPerDay: WITNESS.chainsPerDay, periodMinutes: WITNESS.periodMinutes },
    GEOMETRY,
  );
  assert.equal(WITNESS.secretHex, Buffer.from(keyDerivationSecret(7)).toString("hex"));
  assert.equal(WITNESS.label, CUTOFF);
  assert.equal(WITNESS.position, PREFIX.length - 1);
  assert.equal(WITNESS.windowStart * 60_000, Date.parse(instant(PREFIX[0])));
});

test(
  "one chain cutoff opens every item from the window start through the cutoff and nothing beyond",
  {
    tags: [
      "dca-profile-chain-keys/publisher/chain-supply",
      "dca-profile-chain-keys/client/chain-relay",
      "dca-profile-chain-keys/issuer/chain-input",
      "dca-profile-chain-keys/issuer/chain-output",
      "dca-profile-chain-keys/client/chain-derivation",
    ],
  },
  async () => {
    const { world, browser, chainCache, exchanges, decisions, renderAt, openingKeyReads } =
      await prefixWorld({ futurePeriodCount: 0 });
    /** @type {Map<string, any>} */
    const pages = new Map();
    for (const t of [...PREFIX, ...OUT_OF_REACH.map((probe) => probe.t)]) {
      const page = await renderAt(t);
      suppliedChainOnly(page.asJson());
      assert.deepEqual(coordinatesOf(page), [t], `${t}: the item is wrapped at its own coordinate`);
      pages.set(t, page);
    }

    // One unlock, for the item at the issuer's current coordinate.
    const first = await readArticle(browser, pages.get(CUTOFF), [CONTENT_NAME]);
    assert.equal(first.unlock.ok, true);
    assert.equal(first.texts[CONTENT_NAME], bulletin(CUTOFF));
    assert.equal(exchanges.length, 1);
    assert.equal(openingKeyReads(), 1, "the issuer opened the one relayed chain member");

    const [{ request, response }] = exchanges;
    const delivery = pages.get(CUTOFF).asJson();
    // Relay: the publisher's chain members and geometry, unchanged, and no
    // content-key or period-key member for the issuer to answer from instead.
    assert.deepEqual(request.sealed.contentKeys, {});
    assert.equal(request.sealed.periodKeys, undefined);
    assert.deepEqual(request.sealed.chainKeys, delivery.issuerData[ISSUER_NAME].sealed.chainKeys);
    assert.deepEqual(request.periodGeometry, delivery.periodGeometry);
    // Result form: one positioned chain key under the family's own geometry,
    // with no period key and no content key beside it.
    assert.deepEqual(response.keys.contentKeys, {});
    assert.equal(response.keys.periodKeys, undefined);
    assert.deepEqual(response.keys.chainKeys, {
      [ACCESS_GROUP]: { [CUTOFF]: WITNESS.cutoffChainKeys[CUTOFF] },
    });
    assert.equal(Object.hasOwn(response, "periodGeometry"), false);
    assert.deepEqual(request.periodGeometry, GEOMETRY);

    // The requested article coordinate establishes the cutoff independently
    // of the zero future horizon. The issuer's period policy authorizes every
    // position from the window start through that cutoff; accepting chain
    // output does not grant access.
    assert.deepEqual(decisions, [
      {
        contentNames: [],
        periodGrants: [
          { accessGroup: ACCESS_GROUP, futurePeriodCount: 0, authorizedAtCutoff: true },
        ],
      },
    ]);

    // Every earlier item opens from the retained cutoff key, with no unlock.
    for (const t of PREFIX.filter((label) => label !== CUTOFF)) {
      const read = await readArticle(browser, pages.get(t), [CONTENT_NAME]);
      assert.equal(read.unlock, null, `${t}: resolved from the retained cutoff key`);
      assert.equal(read.texts[CONTENT_NAME], bulletin(t), `${t}: the item opens to its own text`);
    }
    assert.equal(exchanges.length, 1, "retained reuse makes no further issuer exchange");
    assert.equal(world.servers.primary.stats().requests, 1);
    // The period key the client derived at each position is the frozen vectors' period key.
    for (const [position, t] of PREFIX.entries()) {
      const periodKeys = (await chainPartition(chainCache, world, t)).map(base64urlEncode);
      assert.ok(periodKeys.includes(WITNESS.expansion[position]), `${t}: the canonical period key`);
    }

    // Absence of reach: the retained cutoff key cannot derive these period keys. The
    // client tries its own resolver and opener without an unlock, so the
    // issuer's clock and policy stay as they were and no new grant can answer.
    const retained = await retainedBy(browser, chainCache);
    assert.ok(
      retained.chainKeys.some((entry) => entry.kind === "chain-key" && entry.t === CUTOFF),
      "the cutoff key is still held, so a refusal below is about reach",
    );
    for (const { t, why } of OUT_OF_REACH) {
      const load = browser.load(rootFromPage(pages.get(t)));
      const { missing } = await load.resolve([CONTENT_NAME]);
      assert.deepEqual(missing, [CONTENT_NAME], `${t}, ${why}: no retained key covers it`);
      assert.deepEqual(await load.open(CONTENT_NAME), { bytes: null, error: "no_key" }, t);
      assert.deepEqual(
        await chainPartition(chainCache, world, t),
        [],
        `${t}: no period key derives`,
      );
      assert.deepEqual(await retainedBy(browser, chainCache), retained, `${t}: nothing retained`);
    }
    assert.equal(exchanges.length, 1);
    assert.equal(world.servers.primary.stats().requests, 1);
  },
);

test(
  "a policy that authorizes no period opens no chain member and gives the chain-aware client nothing",
  { tags: ["dca-profile-chain-keys/issuer/chain-input"] },
  async () => {
    const { browser, chainCache, exchanges, decisions, renderAt, openingKeyReads } =
      await prefixWorld({ futurePeriodCount: 0, authorizePeriod: () => false });
    const read = await readArticle(browser, await renderAt(CUTOFF), [CONTENT_NAME]);

    // Grant refusal, not absence of reach: the same route, client and supply
    // open this item when authorizePeriod explicitly authorizes its coordinate, so the client's
    // chain capability alone grants nothing.
    assert.deepEqual(decisions, [
      {
        contentNames: [],
        periodGrants: [
          { accessGroup: ACCESS_GROUP, futurePeriodCount: 0, authorizedAtCutoff: false },
        ],
      },
    ]);
    assert.equal(exchanges.length, 1);
    assert.ok(exchanges[0].request.sealed.chainKeys[ACCESS_GROUP], "the chain member was relayed");
    assert.equal(exchanges[0].status, 401);
    assert.deepEqual(exchanges[0].response, { error: "denied" });
    assert.equal(openingKeyReads(), 0, "the denial opened no chain member");
    assert.equal(read.unlock.ok, false);
    assert.equal(read.texts[CONTENT_NAME], null);
    assert.deepEqual(await retainedBy(browser, chainCache), { chainKeys: [], periodKeys: [] });
  },
);

test("response geometry metadata cannot change a captured request's chain grant", async () => {
  for (const geometry of [undefined, { chainsPerDay: 4, periodMinutes: 15 }]) {
    const { browser, chainCache, renderAt } = await prefixWorld({
      futurePeriodCount: 1,
      rewrite: (body) => ({ ...body, periodGeometry: geometry }),
    });
    const page = await renderAt(PREFIX[0]);
    const read = await readArticle(browser, page, [CONTENT_NAME]);
    assert.equal(read.texts[CONTENT_NAME], bulletin(PREFIX[0]));
    assert.deepEqual(
      chainCache
        .entries()
        .filter(({ kind }) => kind === "chain-key")
        .map(({ t }) => t),
      [CUTOFF],
    );
  }
});

test(
  "a chain result the request cannot associate is refused at the open, with nothing retained",
  { tags: ["dca-profile-chain-keys/client/chain-derivation"] },
  async () => {
    const cases = [
      {
        // The request presented the 12:00 window and the next day's first
        // window; the preceding window was never presented.
        why: "the cutoff sits in a window the request did not present",
        rewrite: (/** @type {any} */ body) => ({
          ...body,
          keys: {
            ...body.keys,
            chainKeys: {
              [ACCESS_GROUP]: { "251023T1145": body.keys.chainKeys[ACCESS_GROUP][CUTOFF] },
            },
          },
        }),
      },
    ];
    for (const { why, rewrite } of cases) {
      // Only the first answer is changed; the second reaches the client as sent.
      let answers = 0;
      const { browser, chainCache, exchanges, renderAt } = await prefixWorld({
        futurePeriodCount: 1,
        rewrite: (body) => (answers++ === 0 ? rewrite(body) : body),
      });
      const page = await renderAt(PREFIX[0]);
      const read = await readArticle(browser, page, [CONTENT_NAME]);
      // The issuer granted the canonical cutoff; only the client's view changed.
      assert.deepEqual(
        exchanges[0].response.keys.chainKeys,
        { [ACCESS_GROUP]: { [CUTOFF]: WITNESS.cutoffChainKeys[CUTOFF] } },
        why,
      );
      assert.deepEqual(
        read.unlock.attempts.map((/** @type {any} */ attempt) => attempt.outcome),
        ["malformed_key"],
        why,
      );
      assert.equal(read.texts[CONTENT_NAME], null, why);
      assert.deepEqual(
        await retainedBy(browser, chainCache),
        { chainKeys: [], periodKeys: [] },
        why,
      );

      // The refused answer left nothing behind: the next unlock opens the item
      // and the client holds only the cutoff the issuer actually returned.
      const again = await readArticle(browser, page, [CONTENT_NAME]);
      assert.equal(again.texts[CONTENT_NAME], bulletin(PREFIX[0]), why);
      assert.equal(exchanges.length, 2, why);
      assert.deepEqual(
        chainCache
          .entries()
          .filter((/** @type {any} */ entry) => entry.kind === "chain-key")
          .map((/** @type {any} */ { t, kind }) => ({ t, kind })),
        [{ t: CUTOFF, kind: "chain-key" }],
        why,
      );
    }
  },
);

test("an unknown sealed member alongside chain supply changes no issued grant", async () => {
  const { world } = await selectedWorld("chain-keys");
  let compared = false;
  const browser = world.makeBrowser({
    network: {
      async post(url, request, options) {
        const known = await world.network.post(url, request, options);
        const withUnknown = await world.network.post(
          url,
          {
            ...request,
            sealed: { ...request.sealed, futureKeys: ["malformed unknown capability"] },
          },
          options,
        );
        assert.deepEqual(withUnknown.body, known.body);
        compared = true;
        return withUnknown;
      },
    },
    chainKeyStrategy: "retain",
    requestBuilderFactory: (/** @type {object} */ options) => new ChainKeyRequestBuilder(options),
  });
  const page = await world.render("A");
  const read = await readArticle(browser, page, [CONTENT_NAME]);
  assert.equal(compared, true);
  assert.equal(read.unlock.ok, true);
  assert.equal(read.texts[CONTENT_NAME], ARTICLES.A);
});
