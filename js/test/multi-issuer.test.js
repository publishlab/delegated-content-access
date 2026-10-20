//
// Two issuers over one publisher, and what the client carries between them.
//
// Elsewhere in the suite one issuer decides, or two decide the same way. Here
// the same markup reaches a lax partner issuer and a strict subscription
// issuer, and they answer differently because they were configured with
// different rules (a broken issuer is access-policy.test.js's naive policy).
// The page is one render; the decision is the issuer's.
//
// This file runs the cross-issuer cache leak. The client's periodKey cache is
// keyed by (publisher, accessGroup, t) and no issuer, so a key the lax issuer
// handed over opens an article the publisher only sealed for the strict one -
// the client never asks, and the strict issuer never sees the read. The
// mitigation is one argument: a cache that composes its family name with the
// issuer the key came from, and reads under the issuers the page entrusts that
// group to. The leak runs first, then the same story with the cache keyed by
// issuer.
//
// The partner issuer runs as a second primary. It answers on its own url with
// rules of its own and never stands in for anyone. The actor family in
// `demo/scenarios/world.js` does the wiring, and this file stands the second
// issuer up on the same bag - the fallback knob covers the failover role and
// would decide from the primary's health rather than from its own
// configuration.
//
// Pinned: one clock, one seed, a network that is up and fast, and one publisher
// with one period-key supply. What varies is which issuers a render is sealed for,
// what each issuer's rules say, and how the client's cache is keyed.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Storage } from "../demo/actors/Storage.js";
import { IssuerServer } from "../demo/actors/IssuerServer.js";
import { IssuerKeyStore } from "../demo/support/IssuerKeyStore.js";
import { PublisherRegistrations, openingKeysOver } from "../demo/support/PublisherRegistrations.js";
import { PeriodKeyCache, keyByIssuer } from "../adapter-client/PeriodKeyCache.js";
import { AccessPolicy } from "../demo/support/AccessPolicy.js";
import { open } from "../core-shared--publisher-issuer/keySealing.js";
import { actorWorld, readArticle } from "../demo/scenarios/world.js";
import {
  ALGORITHM,
  ARTICLES as BODYTEXTS,
  CONTENT_NAME as BODYTEXT,
  CONTENT_TYPE,
  DOMAIN,
  ISSUER_NAME as STRICT,
  KEY_ID,
  T_NEXT,
  T_NOW,
  UNLOCK_URL as STRICT_UNLOCK,
  article,
} from "../demo/scenarios/fixtures.js";
import { held } from "../test-lib/helpers/inspect.js";
import { requestFor } from "../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";
import { periodKey } from "../test-reference/support/keys.js";

/**
 * The publisher every render in this file names, folded the way the resolver
 * folds it before the cache files a key under it. The family a browser holds is
 * this publisher and then its accessGroup, so the coordinates below carry it.
 */
const PUB = `https://${DOMAIN}`;

/**
 * The family name one delivered key files under. Every render here is on the
 * period-key route a caller naming none is on. The cache partitions by
 * publisher and access group outside whatever a `keyBy` composes.
 *
 * @param {string} name - the accessGroup, or what a `keyBy` made of it
 * @returns {string}
 */
function family(name) {
  return `${PUB}|${name}`;
}

/** The partner issuer, onboarded for a promotion and lax about it. */
const WEAK = "promo_partner_service";
const WEAK_UNLOCK = "https://promo.example.com/unlock";

/** The second contentName, and the two families the two of them are sealed under. */
const PREMIUM = "premium";
const ARTICLE_GROUP = "article";
const VAULT_GROUP = "premium-vault";

/**
 * The bodytext is the suite's own; the vault item is this file's second family.
 * Two items under two accessGroups is what makes "granted one family and not
 * the other" a thing a test can see at all.
 */
const ARTICLES = {
  A: {
    [BODYTEXT]: BODYTEXTS.A,
    [PREMIUM]: "<p>Two councillors hold shares in the developer.</p>",
  },
  B: {
    [BODYTEXT]: BODYTEXTS.B,
    [PREMIUM]: "<p>The second reading was moved twice already.</p>",
  },
};

/** The subscription issuer's rules: the vault needs an entitlement. */
const STRICT_RULES = {
  contentNames: {
    [PUB]: {
      [BODYTEXT]: { public: true },
      [PREMIUM]: { entitlement: "premium" },
    },
  },
  accessGroups: {
    [PUB]: {
      [ARTICLE_GROUP]: { public: true },
      [VAULT_GROUP]: { entitlement: "premium" },
    },
  },
};

/** The partner's rules: everything the promotion covers, to anyone. */
const WEAK_RULES = {
  contentNames: {
    [PUB]: {
      [BODYTEXT]: { public: true },
      [PREMIUM]: { public: true },
    },
  },
  accessGroups: {
    [PUB]: {
      [ARTICLE_GROUP]: { public: true },
      [VAULT_GROUP]: { public: true },
    },
  },
};

/** The same partner, granted the bodytext family and nothing else. */
const BODYTEXT_ONLY_RULES = {
  contentNames: { [PUB]: { [BODYTEXT]: { public: true } } },
  accessGroups: { [PUB]: { [ARTICLE_GROUP]: { public: true } } },
};

/**
 * One article as this file renders it. The resourceId and the data are the
 * shared fixture's; the items are not, because both of them sit in families of
 * this file's own - `article()` seals its bodytext under the suite's `premium`,
 * and here that name is a contentName inside the vault family.
 *
 * @param {'A'|'B'} label
 * @returns {import('../demo/actors/Publisher.js').Article}
 */
function articleOf(label) {
  return {
    ...article(label),
    items: [
      {
        name: BODYTEXT,
        value: ARTICLES[label][BODYTEXT],
        contentType: CONTENT_TYPE,
        accessGroups: [ARTICLE_GROUP],
      },
      {
        name: PREMIUM,
        value: ARTICLES[label][PREMIUM],
        contentType: CONTENT_TYPE,
        accessGroups: [VAULT_GROUP],
      },
    ],
  };
}

/**
 * One world: the subscription issuer as the deployment's primary, the partner
 * stood up beside it, and a publisher that seals for whichever issuers a render
 * names.
 *
 * @param {object} [config]
 * @param {any} [config.weakRules] - what the partner issuer was configured with
 * @param {any} [config.strictRules]
 * @returns {Promise<any>}
 */
async function world(config = {}) {
  const bag = await actorWorld({
    accessPolicy: new AccessPolicy(config.strictRules ?? STRICT_RULES),
  });
  const partner = await bag.standUp(WEAK, WEAK_UNLOCK, {
    accessPolicy: new AccessPolicy(config.weakRules ?? WEAK_RULES),
  });

  const [strictIssuer] = bag.issuers;
  /** The private half the tests below unseal with directly. */
  const strictKey = /** @type {CryptoKey} */ (bag.keyStores.primary.privateKeyOf(STRICT, KEY_ID));

  return {
    clock: bag.clock,
    network: bag.network,
    publisherRegistrations: bag.publisherRegistrations,
    publisherRegistration: bag.publisherRegistration,
    weakPublisherRegistration: partner.publisherRegistrations.get(bag.publisherRegistration.kid),
    strictIssuer,
    strictKey,
    servers: { strict: bag.servers.primary, weak: partner.server },
    both: bag.issuers,
    /**
     * One render, sealed for the issuers named. Both articles carry the same
     * two contentNames under the same two accessGroups, so what differs
     * between two pages is the render and the issuers on it, nothing else.
     *
     * @param {'A'|'B'} label
     * @param {any[]} issuers - the issuer configs this render seals for
     * @returns {Promise<import('../demo/support/Page.js').Page>}
     */
    render: (label, issuers) => bag.publisherWith({ issuers }).render(articleOf(label)),
    // A browser walks every issuer standing when it is built, so the partner
    // stood up above is one of them.
    makeBrowser: bag.makeBrowser,
  };
}

describe("Two issuers, one render, two answers", () => {
  test("one render, two issuers, two decisions - and the difference is configuration", async () => {
    const { servers, both, render, makeBrowser } = await world();
    const page = await render("A", both);

    // One reader, known to both issuers, entitled to nothing.
    servers.strict.grant("alice", {});
    servers.weak.grant("alice", {});

    const strict = await readArticle(makeBrowser(), page, [BODYTEXT, PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });
    const weak = await readArticle(makeBrowser(), page, [BODYTEXT, PREMIUM], {
      issuerName: WEAK,
      credential: "alice",
    });

    // Both answered the same page whole, and neither refused the request.
    assert.equal(strict.unlock.status, 200);
    assert.equal(weak.unlock.status, 200);
    assert.equal(strict.load.dcaData.resource.renderId, weak.load.dcaData.resource.renderId);

    // The public item is the same on both sides; the vault is not.
    assert.equal(strict.texts[BODYTEXT], ARTICLES.A[BODYTEXT]);
    assert.equal(weak.texts[BODYTEXT], ARTICLES.A[BODYTEXT]);

    assert.equal(strict.texts[PREMIUM], null, "the subscription issuer wants an entitlement");
    assert.equal(strict.errors[PREMIUM], "no_key");
    assert.equal(
      weak.texts[PREMIUM],
      ARTICLES.A[PREMIUM],
      "the partner grants the promotion to anyone",
    );

    // The two answers differ and neither issuer is broken: both ran the same
    // verification and the same policy class, over rules that differ.
    assert.equal(servers.strict.stats().denials, 0);
    assert.equal(servers.weak.stats().denials, 0);
    assert.equal(servers.strict.stats().grants, 1);
    assert.equal(servers.weak.stats().grants, 1);
  });
});

describe("the cross-issuer cache leak, then the mitigation", () => {
  test("a partner issuer periodKey opens the subscription issuer article", async () => {
    const { servers, strictIssuer, both, render, makeBrowser } = await world();

    // The promotion article is sealed for both issuers. The next one is sealed
    // for the subscription issuer alone - the publisher never gave the partner
    // a key to it.
    const promo = await render("A", both);
    const subscriberOnly = await render("B", [strictIssuer]);

    servers.weak.grant("alice", {});
    servers.strict.grant("alice", {});

    const browser = makeBrowser();

    const first = await readArticle(browser, promo, [PREMIUM], {
      issuerName: WEAK,
      credential: "alice",
    });
    assert.equal(first.unlock.status, 200);
    assert.equal(first.texts[PREMIUM], ARTICLES.A[PREMIUM]);

    // What the partner handed over is a family key, not an article key.
    assert.deepEqual(await held(browser.cache, { as: "accessGroup" }), [family(VAULT_GROUP)]);

    // The second article: the client's cache answers it, so nothing is asked of
    // anyone. The subscription issuer never hears about a read of its content.
    const second = await readArticle(browser, subscriberOnly, [PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });

    assert.deepEqual(second.load.stats().resolved, { covered: [PREMIUM], missing: [] });
    assert.equal(second.unlock, null, "nothing was missing, so nobody was asked");
    assert.equal(
      second.texts[PREMIUM],
      ARTICLES.B[PREMIUM],
      "the leak: a key from one issuer opened another issuer article",
    );
    assert.equal(servers.strict.stats().requests, 0);
  });

  test("a cache keyed by issuer will not reuse a partner key elsewhere", async () => {
    const { servers, strictIssuer, both, render, makeBrowser } = await world();

    const promo = await render("A", both);
    const subscriberOnly = await render("B", [strictIssuer]);

    servers.weak.grant("alice", {});
    servers.strict.grant("alice", {});

    // The one difference from the leak above: the cache composes its family name
    // with the issuer the key came from, and reads under the issuers the page
    // entrusts that accessGroup to.
    const browser = makeBrowser({ cacheKeyBy: keyByIssuer });

    const first = await readArticle(browser, promo, [PREMIUM], {
      issuerName: WEAK,
      credential: "alice",
    });
    assert.equal(first.unlock.status, 200);
    assert.equal(first.texts[PREMIUM], ARTICLES.A[PREMIUM]);

    // Both of the render's periods are held, under the issuer that granted them.
    assert.deepEqual(await held(browser.cache, "coordinate"), [
      `${family(`${WEAK}|${VAULT_GROUP}`)}/${T_NEXT}`,
      `${family(`${WEAK}|${VAULT_GROUP}`)}/${T_NOW}`,
    ]);

    const second = await readArticle(browser, subscriberOnly, [PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });

    assert.deepEqual(second.load.stats().resolved, { covered: [], missing: [PREMIUM] });
    assert.equal(second.unlock.status, 401, "the client had to ask, and alice is not entitled");
    assert.equal(second.texts[PREMIUM], null);
    assert.equal(second.errors[PREMIUM], "no_key");
    assert.equal(
      servers.strict.stats().requests,
      1,
      "the read the leak hid now reaches the issuer",
    );

    // The mitigation keeps caching. Another promotion article, sealed
    // for the partner again, still opens out of the cache with no second unlock.
    const promoAgain = await render("A", both);
    const third = await readArticle(browser, promoAgain, [PREMIUM], {
      issuerName: WEAK,
      credential: "alice",
    });
    assert.equal(third.unlock, null, "the partner key still covers the partner pages");
    assert.equal(third.texts[PREMIUM], ARTICLES.A[PREMIUM]);
    assert.equal(servers.weak.stats().requests, 1);
  });

  test("the cache key is a scenario knob, and it is refused when it says nothing", async () => {
    const cache = new PeriodKeyCache({ keyBy: keyByIssuer, storage: new Storage() });

    const key = periodKey(3);
    await cache.put(ARTICLE_GROUP, T_NOW, key, { publisher: PUB, issuerName: WEAK });

    // The same coordinate, asked for under another issuer, is a miss - and the
    // key is still there for the issuer that granted it.
    assert.deepEqual(
      await cache.candidatesAt(ARTICLE_GROUP, T_NOW, { publisher: PUB, issuerNames: [STRICT] }),
      [],
    );
    assert.deepEqual(
      await cache.candidatesAt(ARTICLE_GROUP, T_NOW, { publisher: PUB, issuerNames: [WEAK] }),
      [key],
    );
    assert.deepEqual(
      await cache.candidatesAt(ARTICLE_GROUP, T_NOW, {
        publisher: PUB,
        issuerNames: [STRICT, WEAK],
      }),
      [key],
    );
    assert.deepEqual(
      await cache.candidatesAt(ARTICLE_GROUP, T_NOW, { publisher: PUB, issuerNames: [] }),
      [],
    );

    // A read that names no issuer at all is a caller that has not said what it
    // is asking for, and an issuer-keyed cache will not guess.
    await assert.rejects(
      () => cache.candidatesAt(ARTICLE_GROUP, T_NOW, { publisher: PUB }),
      (/** @type {any} */ err) => err.code === "bad_key",
    );
    await assert.rejects(
      () => cache.put(ARTICLE_GROUP, T_NEXT, key, { publisher: PUB }),
      (/** @type {any} */ err) => err.code === "bad_key",
    );
    await assert.rejects(
      () => cache.candidatesAt(ARTICLE_GROUP, T_NOW, { publisher: PUB, issuerNames: [WEAK, null] }),
      (/** @type {any} */ err) => err.code === "bad_key",
    );

    // A composer that answers with something that cannot name a family is a
    // configuration fault, not a silent bucket.
    const broken = new PeriodKeyCache({ keyBy: () => "" });
    await assert.rejects(
      () => broken.put(ARTICLE_GROUP, T_NOW, key, { publisher: PUB, issuerName: WEAK }),
      (/** @type {any} */ err) => err.code === "bad_key",
    );
    assert.throws(
      () => new PeriodKeyCache({ keyBy: "issuerName" }),
      (/** @type {any} */ err) => err.code === "bad_config",
    );

    // With no composer the family is the accessGroup under its publisher,
    // whoever granted it - the default, and the leak above.
    const flat = new PeriodKeyCache();
    await flat.put(ARTICLE_GROUP, T_NOW, key, { publisher: PUB, issuerName: WEAK });
    assert.deepEqual(
      await flat.candidatesAt(ARTICLE_GROUP, T_NOW, { publisher: PUB, issuerNames: [STRICT] }),
      [key],
    );
    assert.deepEqual(await flat.candidatesAt(ARTICLE_GROUP, T_NOW, { publisher: PUB }), [key]);
  });
});

describe("A blob sealed for one issuer, presented to another", () => {
  test("one issuer sealed block presented to another opens nothing, and the keypair is what says so", async () => {
    const { network, servers, strictKey, both, render } = await world();
    const page = await render("A", both);

    const renderId = page.asJson().resource.renderId;
    const forWeak = requestFor(page, WEAK, [BODYTEXT, PREMIUM]);
    const forStrict = requestFor(page, STRICT, [BODYTEXT, PREMIUM]);

    // Across the wire rather than into the port directly: the deployment is
    // what counts a request, a grant and a denial, and what a substituted blob
    // costs is only worth asserting where those counters move. It is also the
    // seam that refuses a payload JSON cannot carry.
    /** @param {any} payload */
    const toStrict = (payload) => network.post(STRICT_UNLOCK, payload, { origin: PUB });

    // The partner's whole request, posted to the subscription issuer. Nothing
    // about it is forged - it is honestly addressed to the partner - and this
    // server's operating issuer scope excludes that name. Scope admission
    // refuses it before opening-key lookup or unseal.
    const misrouted = await toStrict(forWeak);
    assert.equal(misrouted.status, 400);
    assert.equal(misrouted.body.error, "out_of_scope_issuer");
    assert.equal(misrouted.body.keys, undefined);

    // The same blobs re-addressed, so the lookup lands on a key this server
    // does hold. Past the door and into the crypto: the render is one render
    // and its resourceJWT verifies, so the request is answered - and not one of
    // the partner's blobs opens under the subscription issuer's private key.
    const readdressed = await toStrict({ ...forWeak, issuerName: STRICT });
    assert.equal(readdressed.status, 200);
    assert.deepEqual(readdressed.body.keys.contentKeys, {}, "nothing was handed over");
    assert.equal(readdressed.body.keys.periodKeys, undefined);
    assert.deepEqual(
      Object.fromEntries(
        Object.entries(readdressed.body.errors).map(([label, e]) => [
          label,
          /** @type {any} */ (e).error,
        ]),
      ),
      {
        [BODYTEXT]: "unseal_failed",
        [`${ARTICLE_GROUP}|${T_NOW}`]: "unseal_failed",
        [`${ARTICLE_GROUP}|${T_NEXT}`]: "unseal_failed",
      },
    );

    // The subscription issuer's own request with the partner's contentKeys
    // dropped into it. Per item: the substituted coordinate fails and the
    // periodKeys beside it, which are this issuer's own, still come back.
    const swapped = await toStrict({
      ...forStrict,
      sealed: { ...forStrict.sealed, contentKeys: forWeak.sealed.contentKeys },
    });
    assert.equal(swapped.status, 200);
    assert.deepEqual(swapped.body.keys.contentKeys, {});
    assert.deepEqual(Object.keys(swapped.body.keys.periodKeys), [ARTICLE_GROUP]);
    assert.deepEqual(Object.keys(swapped.body.errors), [BODYTEXT]);

    // The sharpest form of the same swap, and the one that says what is doing
    // the work. This periodKey blob is moved to the coordinate it already sits
    // at: same render, same accessGroup, same t. The binding the subscription
    // issuer rebuilds is byte-identical to the one the partner's blob was
    // sealed under, so the binding has nothing to disagree with - and the blob
    // still does not open, because it was sealed to the partner's public key.
    const partnerArticle = forWeak.sealed.periodKeys[ARTICLE_GROUP];
    const t = Object.keys(partnerArticle)[0];
    const relabeled = await toStrict({
      ...forStrict,
      sealed: {
        ...forStrict.sealed,
        periodKeys: { ...forStrict.sealed.periodKeys, [ARTICLE_GROUP]: { [t]: partnerArticle[t] } },
      },
    });
    assert.equal(relabeled.status, 200);
    assert.equal(
      relabeled.body.keys.periodKeys,
      undefined,
      "the one period asked for did not open",
    );
    assert.deepEqual(Object.keys(relabeled.body.errors), [`${ARTICLE_GROUP}|${t}`]);
    assert.deepEqual(
      Object.keys(relabeled.body.keys.contentKeys),
      [BODYTEXT],
      "and the honest coordinate beside it did",
    );

    // Under the wire, with the binding held constant across both calls: one
    // private key, one coordinate, two blobs. The subscription issuer's own
    // blob opens and the partner's does not, which is the whole separation
    // between two issuers over one render.
    const binding = { renderId, contentName: BODYTEXT };
    assert.equal(
      (await open(forStrict.sealed.contentKeys[BODYTEXT], strictKey, ALGORITHM, { binding }))
        .length,
      16,
    );
    await assert.rejects(
      () => open(forWeak.sealed.contentKeys[BODYTEXT], strictKey, ALGORITHM, { binding }),
      (/** @type {any} */ err) => err.code === "unseal_failed",
    );

    // Four requests served. Two of them handed over the coordinates this issuer
    // had sealed itself and nothing else, five substituted blobs failed to
    // open, and no reader was turned away - a blob that will not unseal is not
    // a denial.
    assert.deepEqual(
      (({ requests, grants, denials, unsealFailures }) => ({
        requests,
        grants,
        denials,
        unsealFailures,
      }))(servers.strict.stats()),
      { requests: 4, grants: 2, denials: 0, unsealFailures: 5 },
    );
  });

  test("two issuerNames over one keypair are one issuer, and there is nothing there to refuse", async () => {
    const { clock, network, publisherRegistration, strictKey, both, render } = await world();
    const page = await render("A", both);

    // The same private key, served under a second name at a second URL - a
    // region, a rename, a second deployment of one issuer. The request an
    // issuerName addresses is the request its keys answer, so the name is a
    // lookup coordinate and never a boundary: a blob is sealed to a public
    // key, and one keypair is one trust domain however many names front
    // it. The blobs below were sealed for STRICT and nobody re-sealed them.
    const OTHER = "paywall_subscription_service_eu";
    const OTHER_UNLOCK = "https://eu.example.com/unlock";
    const otherKeyStore = new IssuerKeyStore([
      {
        issuerName: OTHER,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        privateKey: strictKey,
      },
    ]);
    const otherRegistrations = new PublisherRegistrations([
      {
        ...publisherRegistration,
        openingKeys: openingKeysOver(otherKeyStore, [{ issuerName: OTHER, keyId: KEY_ID }]),
      },
    ]);
    new IssuerServer({
      clock,
      network,
      issuerName: OTHER,
      unlockUrl: OTHER_UNLOCK,
      publisherRegistrations: otherRegistrations,
      accessPolicy: new AccessPolicy(STRICT_RULES),
      keyStore: otherKeyStore,
      periodKeyInput: true,
    });

    const forStrict = requestFor(page, STRICT, [BODYTEXT, PREMIUM]);

    const answer = await network.post(
      OTHER_UNLOCK,
      { ...forStrict, issuerName: OTHER },
      { origin: PUB },
    );

    assert.equal(answer.status, 200);
    assert.deepEqual(Object.keys(answer.body.keys.contentKeys), [BODYTEXT]);
    assert.deepEqual(Object.keys(answer.body.keys.periodKeys), [ARTICLE_GROUP]);
    assert.equal(answer.body.errors, undefined);
  });
});

describe("Per-issuer grants", () => {
  test("an issuer granted the bodytext family never hands out a premium key", async () => {
    const { servers, both, render, makeBrowser, weakPublisherRegistration } = await world({
      weakRules: BODYTEXT_ONLY_RULES,
    });
    const page = await render("A", both);

    servers.weak.grant("alice", { entitlements: ["premium"] });

    const browser = makeBrowser();
    const read = await readArticle(browser, page, [BODYTEXT, PREMIUM], {
      issuerName: WEAK,
      credential: "alice",
    });

    // The page seals both items for this issuer and it opens one of them. An
    // entitlement it was never configured to honour buys nothing: the grant is
    // an allow-list, and `premium` is not on it.
    assert.equal(read.unlock.status, 200);
    assert.equal(read.texts[BODYTEXT], ARTICLES.A[BODYTEXT]);
    assert.equal(read.texts[PREMIUM], null);
    assert.equal(read.errors[PREMIUM], "no_key");

    // The vault family never reached the client, so no later article of that
    // family is opened by this issuer's answer either.
    assert.deepEqual(await held(browser.cache, { as: "accessGroup" }), [family(ARTICLE_GROUP)]);

    // What came back, at the wire: one contentKey, one accessGroup, and nothing
    // reported as failed - a coordinate that was not granted was never opened.
    const answer = await unlockThroughAdmission(
      servers.weak.processor,
      servers.weak.endpoint,
      requestFor(page, WEAK, [BODYTEXT, PREMIUM]),
      weakPublisherRegistration,
    );

    assert.equal(answer.status, 200);
    assert.deepEqual(Object.keys(answer.body.keys.contentKeys), [BODYTEXT]);
    assert.deepEqual(Object.keys(answer.body.keys.periodKeys), [ARTICLE_GROUP]);
    assert.equal(answer.body.errors, undefined);

    // The strict issuer, same page, same items: what one issuer is granted says
    // nothing about the other.
    servers.strict.grant("alice", { entitlements: ["premium"] });
    const strictRead = await readArticle(makeBrowser(), page, [BODYTEXT, PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });
    assert.equal(strictRead.texts[PREMIUM], ARTICLES.A[PREMIUM]);
  });
});
