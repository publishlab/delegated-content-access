//
// Who may read what. An issuer that verifies a request and then opens whatever
// it carried - the shape the rest of the suite runs - has checked the paperwork
// and never asked who is standing there.
//
// The policy is injected and holds no key material. Rules live in it, the
// entitlement lives in the server state it is handed, and it decides nothing
// about integrity - by the time it is called the envelopes and the proof have
// already passed, so a denial here is a 401 and never a 400.
//
// Two policies run side by side. The strict one decides from the verified
// claims and the caller's entitlement. The naive one grants every requested
// name - the client asked for it, so the client must be allowed to have it.
// Both issuers verify identically, both reject a relabeled blob, and only one
// of them hands over the premium article.
//
// Every onboarded publisher gets its own keypair. Exact kid registrations keep
// the publishers' verification keys, canonical origins, policy coordinates and
// opening-key views apart. A test that moves one of those starts with two real
// registrations.
//
// Pinned: every world here is the same clock, the same seed and a network that
// is up and fast. What varies is the rules the strict issuer was configured
// with and who the credential resolves to - and, in the two stories where a
// grant outlives what made it, the clock, which moves there because the period
// bounds how far a grant already made still reaches.
//
// The second of those stories runs from a scenario module. Two readers over two
// stores, a key crossing between them and a request posted twice is wiring no
// other test here stands up, and `demo/scenarios/periodSharing.js` takes those
// steps carrying no assertions, so the demo page can run the identical one.
// What is asserted here is the trace it hands back.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { AccessPolicy, NaiveAccessPolicy } from "../demo/support/AccessPolicy.js";
import { actorWorld, originForHost, readArticle } from "../demo/scenarios/world.js";
import { randomPeriodKeySupply } from "../demo/support/randomPeriodKeySupply.js";
import { rootFromPage } from "../demo/support/queryableRoot.js";
import { run as periodSharing, heldForPeriod } from "../demo/scenarios/periodSharing.js";
import { DcaError } from "../core-shared/errors.js";
import * as keySealing from "../core-shared--publisher-issuer/keySealing.js";
import {
  ACCESS_GROUP,
  ARTICLES as BODYTEXTS,
  CONTENT_NAME as BODYTEXT,
  CONTENT_TYPE,
  DOMAIN,
  ISSUER_NAME as STRICT,
  KEY_ID,
  T_NEXT,
  T_NOW,
  article,
} from "../demo/scenarios/fixtures.js";
import { held } from "../test-lib/helpers/inspect.js";
import {
  contentKeyMap,
  errorMap,
  keyAt,
  periodKeyMap,
} from "../test-reference/support/namedRecords.js";
import { seededRandom } from "../test-reference/support/keys.js";
import { requestFor } from "../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";

/** The second publisher: another paper, onboarded at the same issuer. */
const OTHER_DOMAIN = "www.other-paper.example";

/**
 * Two hours, which is past both periods an hourly render ships. A page made
 * after this much of the clock has moved names periods the client holds no key
 * for, whatever it collected before.
 */
const PAST_THE_OVERLAP = 2 * 60 * 60_000;

/** The issuer that decides from the request rather than from the reader. */
const NAIVE = "paywall_naive_service";
const NAIVE_UNLOCK = "https://naive.example.com/unlock";

/** The names beside the suite's bodytext, and the three families they sit in. */
const PREMIUM = "premium";
const VIDEO = "premium-video";

const ARTICLE_GROUP = "article";
const VAULT_GROUP = "premium-vault";
const VIDEO_GROUP = "video";

/**
 * The default publisher origin. A family a full read leaves in the client
 * cache is this canonical origin and then its accessGroup.
 */
const PUB = originForHost(DOMAIN);
const OTHER_ORIGIN = originForHost(OTHER_DOMAIN);
/**
 * The bodytext is the suite's own; the two names beside it are this file's.
 * Three items over three families is what a decision that grants some of them
 * and withholds the rest needs to be visible at all.
 */
const ARTICLES = {
  A: {
    [BODYTEXT]: BODYTEXTS.A,
    [PREMIUM]: "<p>Two councillors hold shares in the developer.</p>",
    [VIDEO]: "<p>Nine minutes from the committee room.</p>",
  },
  B: {
    [BODYTEXT]: BODYTEXTS.B,
    [PREMIUM]: "<p>The second reading was moved twice already.</p>",
    [VIDEO]: "<p>The developer answers questions.</p>",
  },
  C: {
    [BODYTEXT]: BODYTEXTS.C,
    [PREMIUM]: "<p>Who filed the first four objections.</p>",
    [VIDEO]: "<p>Outside the town hall on Friday.</p>",
  },
};

/**
 * What the strict issuer is configured with unless a test says otherwise. Both
 * allow-lists are filed under the publisher whose names they are.
 */
const RULES = {
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

/**
 * The same rules with no accessGroup granted at all. Nothing reaches the
 * client's cache, so every load has to ask - which is what makes an
 * entitlement that expires between two loads visible at all.
 */
const CONTENT_KEY_ONLY_RULES = {
  contentNames: RULES.contentNames,
  accessGroups: {},
};

/** A metered bodytext, content keys only: every view costs a request. */
const METERED_RULES = {
  contentNames: { [PUB]: { [BODYTEXT]: { meter: 2 } } },
  accessGroups: {},
};

/** The same meter with the accessGroup granted, so the cache can answer. */
const CACHED_METER_RULES = {
  contentNames: { [PUB]: { [BODYTEXT]: { meter: 2 } } },
  accessGroups: { [PUB]: { [ARTICLE_GROUP]: { public: true } } },
};

/**
 * Both publishers sell a tier they call `premium`, and the two tiers are not
 * one another's: each is a subscription sold by one of them to its own
 * readers. One issuer holds both sets of rules.
 */
const TWO_PUBLISHER_RULES = {
  contentNames: {
    [PUB]: { [PREMIUM]: { entitlement: "news-site-premium" } },
    [OTHER_ORIGIN]: { [PREMIUM]: { entitlement: "other-paper-premium" } },
  },
  accessGroups: {},
};

/**
 * One article as this file renders it. The resourceId and the data are the
 * shared fixture's; the items are not, because `article()` puts its bodytext in
 * the entitled family and appends whatever else is asked for beside it. Here it
 * is the bodytext that is open to anyone and the names after it that are
 * vaulted, so the whole list is this file's.
 *
 * @param {'A'|'B'|'C'} label
 * @param {boolean} [video] - ship the premium name the issuer has never been
 *   configured with
 * @returns {import('../demo/actors/Publisher.js').Article}
 */
function articleOf(label, video = false) {
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
      ...(video
        ? [
            {
              name: VIDEO,
              value: ARTICLES[label][VIDEO],
              contentType: CONTENT_TYPE,
              accessGroups: [VIDEO_GROUP],
            },
          ]
        : []),
    ],
  };
}

/**
 * One world: the strict issuer, the naive one stood up beside it, a signing
 * keypair per onboarded domain, and a publisher per render.
 *
 * @param {object} [config]
 * @param {any} [config.rules] - what the strict issuer's AccessPolicy is built from
 * @param {any} [config.policy] - a policy object outright, for the broken-policy case
 * @param {string[]} [config.publishers] - the domains onboarded here, spelled
 *   the way the store files them
 * @returns {Promise<any>}
 */
async function world(config = {}) {
  // Two publishers onboarded at one issuer, each with its own signing
  // keypair. That is the ordinary deployment - the issuer sells to both and
  // neither of them onboarded the other.
  const onboarded = config.publishers ?? [DOMAIN, OTHER_DOMAIN];
  const periodKeySupplies = Object.fromEntries(
    onboarded.map((domain, index) => [
      domain,
      randomPeriodKeySupply({ random: seededRandom(700 + index) }),
    ]),
  );
  const stage = await actorWorld({
    domains: onboarded,
    accessPolicy: config.policy ?? new AccessPolicy(config.rules ?? RULES),
  });
  const naive = await stage.standUp(NAIVE, NAIVE_UNLOCK, { accessPolicy: new NaiveAccessPolicy() });

  /**
   * @param {'A'|'B'|'C'} label
   * @param {object} [options]
   * @param {boolean} [options.video]
   * @param {string} [options.domain] - which publisher rendered this
   * @param {string} [options.signedBy] - whose key signed it, when that is
   *   not the publisher the payload names
   * @returns {Promise<import('../demo/support/Page.js').Page>}
   */
  const render = (label, options = {}) => {
    const domain = options.domain ?? DOMAIN;
    // A publisher per render rather than one held. The domain and its
    // period-key supply are publisher configuration.
    return stage
      .publisherWith({
        domain,
        periodKeySupply: periodKeySupplies[domain],
        ...(options.signedBy === undefined
          ? {}
          : {
              signingKeys: {
                [options.signingKid ?? Object.keys(stage.signingKeyPairs[options.signedBy])[0]]:
                  stage.signingKeyPairs[options.signedBy][
                    Object.keys(stage.signingKeyPairs[options.signedBy])[0]
                  ].privateKey,
              },
              signingKid:
                options.signingKid ?? Object.keys(stage.signingKeyPairs[options.signedBy])[0],
            }),
      })
      .render(articleOf(label, options.video));
  };

  const { clock, network, signingKeyPairs, makeBrowser, browser } = stage;
  return {
    clock,
    network,
    signingKeyPairs,
    issuers: stage.issuers,
    publisherRegistration: stage.publisherRegistration,
    naivePublisherRegistration: naive.publisherRegistrations.get(
      Object.keys(stage.signingKeyPairs[DOMAIN])[0],
    ),
    publisherRegistrations: stage.publisherRegistrations,
    registrationFor: (domain) =>
      stage.publisherRegistrations.get(Object.keys(stage.signingKeyPairs[domain])[0]),
    servers: { strict: stage.servers.primary, naive: naive.server },
    render,
    makeBrowser,
    browser,
  };
}

describe("Which publisher the names belong to", () => {
  test("a reader entitled at one publisher is denied the other publisher's premium", async () => {
    const { servers, render, makeBrowser } = await world({ rules: TWO_PUBLISHER_RULES });

    // One reader, one subscription, bought at the news site.
    servers.strict.grant("alice", { entitlements: ["news-site-premium"] });

    const own = await readArticle(makeBrowser(), await render("A"), [PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });
    assert.equal(own.unlock.status, 200);
    assert.equal(own.texts[PREMIUM], ARTICLES.A[PREMIUM]);

    // The other paper's article, same issuer, same reader, same name on the
    // wire. Nothing about the request is dishonest and every integrity check
    // passes; the coordinate the decision is keyed on is what says no.
    const other = await readArticle(
      makeBrowser(),
      await render("B", { domain: OTHER_DOMAIN }),
      [PREMIUM],
      {
        issuerName: STRICT,
        credential: "alice",
      },
    );
    assert.equal(other.unlock.status, 401);
    assert.equal(other.texts[PREMIUM], null);
    assert.equal(other.errors[PREMIUM], "no_key");
    assert.equal(servers.strict.stats().denials, 1);
  });

  test("a resource naming a publisher other than its signing key is refused whole", async () => {
    // The token payload selects the candidate key, so signing another
    // publisher's domain with this publisher's key fails verification.
    const { servers, render, registrationFor, signingKeyPairs } = await world({
      rules: TWO_PUBLISHER_RULES,
    });

    const page = await render("A", {
      domain: OTHER_DOMAIN,
      signedBy: DOMAIN,
      signingKid: Object.keys(signingKeyPairs[OTHER_DOMAIN])[0],
    });
    const request = requestFor(page, STRICT, [PREMIUM]);

    const answer = await unlockThroughAdmission(
      servers.strict.processor,
      servers.strict.endpoint,
      request,
      registrationFor(OTHER_DOMAIN),
    );

    assert.equal(answer.status, 400);
    assert.equal(answer.body.error, "bad_signature");
    assert.equal(answer.body.keys, undefined, "nothing partial comes back");
    assert.equal(servers.strict.stats().denials, 0, "an integrity failure, not a decision");
  });
});

describe("the naive issuer, run rather than described", () => {
  test("the naive issuer discloses the premium article the strict one withholds", async () => {
    const { servers, render, makeBrowser, naivePublisherRegistration } = await world();
    const page = await render("A");

    // One user, known to both issuers, entitled to nothing.
    servers.strict.grant("alice", {});
    servers.naive.grant("alice", {});

    const strict = await readArticle(makeBrowser(), page, [BODYTEXT, PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });

    // The request was verified whole and answered, with the one item the
    // caller may have: a partial grant, 200 with omissions.
    assert.equal(strict.unlock.status, 200);
    assert.equal(strict.texts[BODYTEXT], ARTICLES.A[BODYTEXT]);
    assert.equal(strict.texts[PREMIUM], null);
    assert.equal(strict.errors[PREMIUM], "no_key");

    const naive = await readArticle(makeBrowser(), page, [BODYTEXT, PREMIUM], {
      issuerName: NAIVE,
      credential: "alice",
    });

    assert.equal(naive.unlock.status, 200);
    assert.equal(
      naive.texts[PREMIUM],
      ARTICLES.A[PREMIUM],
      "the same caller, the same page, the article disclosed",
    );

    // The naive issuer got only its access decision wrong. It runs the
    // identical unseal, and the premium blob presented under `bodytext` does
    // not open.
    const request = requestFor(page, NAIVE, [BODYTEXT, PREMIUM]);
    const relabeled = {
      ...request,
      sealed: {
        ...request.sealed,
        contentKeys: [
          {
            contentName: BODYTEXT,
            key: keyAt(request.sealed.contentKeys, { contentName: PREMIUM }),
          },
        ],
      },
    };
    // One bad blob, answered as one: an error at the coordinate it was presented
    // at, no contentKey beside it, and everything else the request carried
    // answered anyway.
    const relabeledAnswer = await unlockThroughAdmission(
      servers.naive.processor,
      servers.naive.endpoint,
      relabeled,
      naivePublisherRegistration,
    );
    assert.equal(relabeledAnswer.status, 200);
    assert.deepEqual(relabeledAnswer.body.keys.contentKeys, []);
    assert.equal(errorMap(relabeledAnswer.body.errors)[BODYTEXT].error, "unseal_failed");

    // Every grant on both sides was a policy decision, never an integrity one.
    assert.equal(servers.strict.stats().denials, 0);
    assert.equal(servers.naive.stats().grants, 1);
  });

  test("a grant is a copy, so the caller's object and arrays stop mattering the moment it is made", async () => {
    const { servers, browser, render, makeBrowser } = await world();
    const page = await render("A");

    // The entitlement is granted and then vandalised in the caller's hands:
    // the array loses the entitlement it carried. What the server answers is
    // what was said at grant time, not what the caller holds now.
    const entitlement = { entitlements: ["premium"] };
    servers.strict.grant("alice", entitlement);
    entitlement.entitlements.length = 0;

    const read = await readArticle(browser, page, [PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });
    assert.equal(read.unlock.status, 200);
    assert.equal(read.texts[PREMIUM], ARTICLES.A[PREMIUM]);

    // And the other direction: what authenticate hands back is a copy too, so
    // nobody writes an entitlement in through it.
    servers.strict.grant("bob", { entitlements: [] });
    /** @type {any} */ (servers.strict.authenticate("bob")).entitlements.push("premium");

    const bob = await readArticle(makeBrowser(), page, [PREMIUM], {
      issuerName: STRICT,
      credential: "bob",
    });
    assert.equal(bob.texts[PREMIUM], null);
    assert.equal(bob.errors[PREMIUM], "no_key");
  });

  /**
   * A network that keeps what crossed it, so the composed walk's posted
   * unlocks can be read back. Copied from client-bound.test.js; hoisting it
   * into test-lib/ is a separate call.
   *
   * @param {any} network
   * @returns {any}
   */
  function wiretap(network) {
    /** @type {any[]} */
    const posted = [];
    return {
      posted,
      /**
       * @param {string} url
       * @param {any} request
       * @param {any} [options]
       * @returns {Promise<{ status: number, body: any }>}
       */
      post: async (url, request, options) => {
        const record = { url, request };
        posted.push(record);
        const answer = await network.post(url, request, options);
        Object.assign(record, answer);
        return answer;
      },
    };
  }

  test("a multi-item partial grant ends ok, keeps the remainder, and the upgrade re-walks for only that", async () => {
    const { servers, network, render, makeBrowser } = await world();
    const wire = wiretap(network);
    const browser = makeBrowser({ network: wire });

    // Entitled to nothing: the strict issuer grants the public bodytext and
    // withholds the premium name and its family.
    servers.strict.grant("alice", {});

    const first = await readArticle(browser, await render("A"), [BODYTEXT, PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });

    // The partial grant ends the walk as success, not failure: a key was
    // handed over, and `#needed` becomes the still-missing remainder.
    assert.equal(first.unlock.ok, true, "a partial grant ends the walk ok");
    assert.equal(first.unlock.status, 200);
    assert.equal(first.unlock.attempts.at(-1).outcome, "answered");

    assert.equal(first.texts[BODYTEXT], ARTICLES.A[BODYTEXT], "the public bodytext opens");
    assert.equal(first.texts[PREMIUM], null, "the withheld name does not");
    assert.equal(first.errors[PREMIUM], "no_key");

    // The remainder is still tracked. A re-resolve over the same ask reads
    // `#needed` back: bodytext is now covered by the cached ARTICLE_GROUP
    // period key, and only premium is still missing.
    const stillMissing = await first.load.resolve([BODYTEXT, PREMIUM]);
    assert.deepEqual(stillMissing.missing, [PREMIUM], "premium is the tracked remainder");

    // The entitlement is upgraded and a second article of the same period is
    // read on the same browser.
    servers.strict.grant("alice", { entitlements: ["premium"] });
    const posts = wire.posted.length;

    const second = await readArticle(browser, await render("B"), [BODYTEXT, PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });

    // The follow-up walk asks for only the remainder. The already-held
    // ARTICLE_GROUP family never crosses the wire: the second load posts one
    // unlock, and it carries premium and its vault alone.
    assert.equal(wire.posted.length - posts, 1, "one unlock for the remainder");
    const { request } = wire.posted.at(-1);
    assert.deepEqual(Object.keys(contentKeyMap(request.sealed.contentKeys)), [PREMIUM]);
    assert.deepEqual(Object.keys(periodKeyMap(request.sealed.periodKeys)), [VAULT_GROUP]);

    assert.equal(second.unlock.ok, true);
    assert.equal(
      second.texts[BODYTEXT],
      ARTICLES.B[BODYTEXT],
      "the held bodytext opens with no new ask",
    );
    assert.equal(second.texts[PREMIUM], ARTICLES.B[PREMIUM], "and premium now opens too");
  });
});

describe("The allow-list, and a publisher moving first", () => {
  test("a premium name shipped before the issuer knows it is denied, not rejected", async () => {
    const { servers, browser, render } = await world();
    const page = await render("A", { video: true });

    servers.strict.grant("alice", { entitlements: ["premium"] });

    const read = await readArticle(browser, page, [BODYTEXT, PREMIUM, VIDEO], {
      issuerName: STRICT,
      credential: "alice",
    });

    // The whole request is verified and answered - a name the issuer has never
    // heard of is a denial of that item, not a 400 for the request.
    assert.equal(read.unlock.status, 200);
    assert.equal(read.texts[BODYTEXT], ARTICLES.A[BODYTEXT]);
    assert.equal(read.texts[PREMIUM], ARTICLES.A[PREMIUM]);
    assert.equal(read.texts[VIDEO], null, "the new name defaulted to deny");
    assert.equal(read.errors[VIDEO], "no_key");

    // The issuer catching up is configuration, not code: the same page, the
    // same client, the name added to the allow-list.
    const caughtUp = await world({
      rules: {
        contentNames: {
          [PUB]: { ...RULES.contentNames[PUB], [VIDEO]: { entitlement: "premium" } },
        },
        accessGroups: {
          [PUB]: { ...RULES.accessGroups[PUB], [VIDEO_GROUP]: { entitlement: "premium" } },
        },
      },
    });
    caughtUp.servers.strict.grant("alice", { entitlements: ["premium"] });

    const after = await readArticle(
      caughtUp.browser,
      await caughtUp.render("A", { video: true }),
      [BODYTEXT, PREMIUM, VIDEO],
      { issuerName: STRICT, credential: "alice" },
    );
    assert.equal(after.texts[VIDEO], ARTICLES.A[VIDEO]);
  });
});

describe("An entitlement that ends between two loads", () => {
  test("the same markup read twice, denied on the second when the entitlement expired", async () => {
    const { servers, browser, render } = await world({ rules: CONTENT_KEY_ONLY_RULES });
    const page = await render("A");

    servers.strict.grant("alice", { entitlements: ["premium"] });

    const first = await readArticle(browser, page, [PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });
    assert.equal(first.unlock.status, 200);
    assert.equal(first.texts[PREMIUM], ARTICLES.A[PREMIUM]);

    servers.strict.expire("alice");

    const second = await readArticle(browser, page, [PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });

    assert.equal(second.unlock.status, 401, "nothing was granted, so the whole request was denied");
    assert.equal(second.texts[PREMIUM], null);
    assert.equal(second.errors[PREMIUM], "no_key");

    // The markup did not move. Same render, same renderId, same blobs - only
    // the entitlement behind the credential changed.
    assert.equal(first.load.dcaData.resource.renderId, second.load.dcaData.resource.renderId);
    assert.equal(servers.strict.stats().requests, 2);
    assert.equal(servers.strict.stats().denials, 1);
  });

  test("the periodKey a live entitlement bought opens the next article until `t` rolls", async () => {
    // The same expiry against rules that grant the accessGroup, which is
    // the deployment the design argues for: a grant hands over the periods
    // the render ships, and the client reads every article of those periods
    // out of its own cache. So a subscription that ends mid-period ends at
    // the issuer, and the reader keeps reading until the period rolls.
    const { clock, servers, browser, render } = await world();

    servers.strict.grant("alice", { entitlements: ["premium"] });

    const first = await readArticle(browser, await render("A"), [PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });
    assert.equal(first.unlock.status, 200);
    assert.equal(first.texts[PREMIUM], ARTICLES.A[PREMIUM]);
    assert.equal(first.load.stats().answeredBy, STRICT, "the issuer answered this one");

    // What the grant left behind: the vault's key for both periods the
    // render shipped, held by the client rather than asked for again.
    assert.deepEqual(await held(browser.cache, "coordinate"), [
      `${PUB}|${VAULT_GROUP}/${T_NEXT}`,
      `${PUB}|${VAULT_GROUP}/${T_NOW}`,
    ]);
    assert.equal(servers.strict.stats().requests, 1);

    servers.strict.expire("alice");

    const second = await readArticle(browser, await render("B"), [PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });

    // A second article of the same period, read by a reader the issuer no
    // longer holds an entitlement for. The period is the unit the grant was
    // made in and this article is inside it, so the client opens it without
    // asking anyone - that reach is what a period buys, and it ends at the
    // next period, which is what choosing a period length picks.
    assert.equal(second.unlock, null, "nothing was missing, so nothing was asked");
    assert.equal(second.load.stats().attempts, 0);
    assert.deepEqual(second.load.stats().resolved, { covered: [PREMIUM], missing: [] });
    assert.equal(second.texts[PREMIUM], ARTICLES.B[PREMIUM]);
    assert.equal(servers.strict.stats().requests, 1, "the issuer never heard of this read");

    // And the far end of the reach. An article rendered past the overlap
    // names periods this cache holds nothing for, so the client goes out -
    // and the expiry that could not reach the second read is waiting there.
    clock.advance(PAST_THE_OVERLAP);

    const third = await readArticle(browser, await render("C"), [PREMIUM], {
      issuerName: STRICT,
      credential: "alice",
    });

    assert.equal(third.load.stats().attempts, 1, "nothing held covered it, so the walk went out");
    assert.equal(third.unlock.status, 401);
    assert.equal(third.texts[PREMIUM], null);
    assert.equal(third.errors[PREMIUM], "no_key");
    assert.equal(servers.strict.stats().requests, 2);
    assert.equal(servers.strict.stats().denials, 1);
  });
});

describe("Two readers, one period", () => {
  test("a subscriber's periodKey opens an unentitled reader's article until the period rolls", async () => {
    const { steps, summary } = await periodSharing();

    assert.deepEqual(
      steps.map((step) => step.kind),
      ["read", "replay", "share", "read", "advance", "read", "replay", "read"],
      "the subscriber reads, the request is replayed, the key crosses, the period rolls",
    );

    const [bought, shared, afterTheRoll, control] = steps.filter((step) => step.kind === "read");
    const [replayed, again] = steps.filter((step) => step.kind === "replay");

    // The grant: the subscription opens the article and leaves both periods
    // the render shipped in this reader's cache.
    assert.equal(bought.status, 200);
    assert.equal(bought.text, BODYTEXTS.A);
    assert.deepEqual(
      bought.cache.map((/** @type {any} */ entry) => entry.t),
      [T_NEXT, T_NOW],
    );

    // The same request posted again, byte for byte, is answered with the
    // same keys: this issuer keeps no per-request state, so what a captured
    // request buys is whatever it bought the first time.
    assert.equal(replayed.status, 200);
    assert.deepEqual(Object.keys(periodKeyMap(replayed.body.keys.periodKeys)[ACCESS_GROUP]), [
      T_NOW,
      T_NEXT,
    ]);

    // The key itself crossing, which is the other way a period reaches a
    // second reader: one entry, filed at the coordinate it was granted at -
    // the publisher both are reading, and then the accessGroup.
    assert.deepEqual(shared.cache, [{ accessGroup: `${PUB}|${ACCESS_GROUP}`, t: T_NOW }]);

    // And the reach that buys: an article of the same period, opened by a
    // reader this issuer sells nothing to, without the issuer hearing about
    // the read at all. This is what the cached path is for - a grant is made
    // per period, and every article of that period opens against it.
    assert.equal(shared.text, BODYTEXTS.B);
    assert.equal(shared.status, null, "nothing was missing, so nobody was asked");
    assert.equal(shared.calls, 0);
    assert.deepEqual(shared.resolved, { covered: [BODYTEXT], missing: [] });
    assert.equal(shared.server.requests, 2, "the two the subscriber made, and no more");

    // It ends at the next period. The article rendered past the
    // overlap names periods this cache holds nothing for, so the walk goes
    // out - and the issuer answers the question it was never asked before.
    assert.equal(afterTheRoll.calls, 1);
    assert.equal(afterTheRoll.status, 401);
    assert.equal(afterTheRoll.text, null);
    assert.equal(afterTheRoll.error, "no_key");
    assert.equal(afterTheRoll.server.denials, 1);
    assert.deepEqual(
      afterTheRoll.cache,
      shared.cache,
      "a denial hands over nothing, so nothing was written",
    );

    // The replay after the roll is the same answer again, keys and all: what
    // bounds it is the labels rolling out from under it, and nothing the
    // issuer does.
    assert.deepEqual(again.body, replayed.body);
    assert.equal(again.status, 200);

    // The control. A live subscription reads across the same roll, so the
    // 401 above is what this issuer says about that reader rather than what
    // a rolled period does to everyone.
    assert.equal(control.status, 200);
    assert.equal(control.text, BODYTEXTS.D);

    assert.deepEqual(
      summary.cache.reader.map((/** @type {any} */ entry) => entry.t),
      [T_NOW],
    );
    assert.equal(summary.server.grants, 4);
    assert.equal(summary.server.denials, 1);
  });

  test("sharing a period the subscriber holds nothing for is refused, not a bare TypeError", () => {
    // `share` reaches for the subscriber's key for the period both readers
    // are in. If it is not there the story was played out of order, and the
    // absence is named - which actor, which period - rather than surfacing
    // three frames down as `entry.t` on undefined.
    assert.throws(
      () => heldForPeriod([{ t: "251023T1400" }], "251023T1500", "alice"),
      (/** @type {any} */ e) =>
        e instanceof DcaError &&
        e.code === "bad_scenario" &&
        e.message.includes("alice") &&
        e.message.includes("251023T1500"),
    );

    // A period it does hold is handed back as it stands.
    const entry = { t: "251023T1500", key: "k" };
    assert.equal(heldForPeriod([{ t: "251023T1400" }, entry], "251023T1500", "alice"), entry);
  });
});

describe("Metering", () => {
  test("a delivered own inherited-name coordinate debits its metered grant", async () => {
    // `constructor` is an inherited member name that the identifier grammar
    // admits, and a reader can present it as a record's contentName. Seal a
    // real key under that exact coordinate so delivery, rather than a failed
    // unseal, decides whether the pending view is applied. Any lookup that
    // indexed a plain object by that name would answer out of Object.prototype
    // with a function here.
    //
    // `__proto__` is the neighbouring name the grammar refuses, and a record
    // with a bad contentName refuses the whole request: the second half of
    // this test is that it never reaches a decision at all.
    const meter = {
      decide(claims, requested, input) {
        return {
          contentNames: requested.contentNames,
          periodGrants: [],
          policyData: [
            { type: "view", user: input.principal.user, renderId: claims.resource.renderId },
          ],
        };
      },
    };
    const { servers, network, render, issuers } = await world({
      policy: meter,
    });
    servers.strict.grant("reader", {});
    const page = await render("A");
    const request = requestFor(page, STRICT, [BODYTEXT]);
    const renderId = page.asJson().resource.renderId;
    const blob = await keySealing.seal(
      new Uint8Array(16).fill(7),
      issuers[0].publicKey,
      "ecdh-p256",
      {
        binding: { renderId, contentName: "constructor" },
        random: seededRandom(26),
      },
    );
    request.sealed.contentKeys = [{ contentName: "constructor", key: blob }];

    const answer = await network.post(servers.strict.unlockUrl, request, {
      credential: "reader",
      origin: page.publisherOrigin,
    });

    assert.equal(answer.status, 200);
    assert.equal(
      typeof keyAt(answer.body.keys.contentKeys, { contentName: "constructor" }),
      "string",
      JSON.stringify(answer.body),
    );
    assert.equal(servers.strict.stats().grants, 1, "an own delivered coordinate is a grant");
    assert.deepEqual(
      servers.strict.views("reader"),
      [renderId],
      "delivery applies the pending debit",
    );

    // The name beside it. `__proto__` is not letter-initial, so identifier
    // admission refuses the record and with it the whole request, and the
    // meter sees nothing: no second grant and no second view.
    const hostile = requestFor(page, STRICT, [BODYTEXT]);
    hostile.sealed.contentKeys.push({ contentName: "__proto__", key: blob });

    const refused = await network.post(servers.strict.unlockUrl, hostile, {
      credential: "reader",
      origin: page.publisherOrigin,
    });

    assert.equal(refused.status, 400);
    assert.equal(refused.body.error, "binding_failed");
    assert.equal(servers.strict.stats().grants, 1, "the refused request added no grant");
    assert.deepEqual(servers.strict.views("reader"), [renderId], "and no view");
  });

  test("metered views are counted per renderId, and the third one is denied", async () => {
    const { servers, browser, render } = await world({ rules: METERED_RULES });
    servers.strict.grant("reader", {});

    const a = await render("A");
    const b = await render("B");
    const c = await render("C");

    const first = await readArticle(browser, a, [BODYTEXT], {
      issuerName: STRICT,
      credential: "reader",
    });
    assert.equal(first.texts[BODYTEXT], ARTICLES.A[BODYTEXT]);
    assert.equal(servers.strict.views("reader").length, 1);

    const second = await readArticle(browser, b, [BODYTEXT], {
      issuerName: STRICT,
      credential: "reader",
    });
    assert.equal(second.texts[BODYTEXT], ARTICLES.B[BODYTEXT]);
    assert.equal(servers.strict.views("reader").length, 2);

    const third = await readArticle(browser, c, [BODYTEXT], {
      issuerName: STRICT,
      credential: "reader",
    });
    assert.equal(third.unlock.status, 401);
    assert.equal(third.texts[BODYTEXT], null);

    // A render already counted is free to read again: the meter counts renders,
    // not requests, so a reader who reloads the page they paid for is not
    // charged twice.
    const again = await readArticle(browser, a, [BODYTEXT], {
      issuerName: STRICT,
      credential: "reader",
    });
    assert.equal(again.unlock.status, 200);
    assert.equal(again.texts[BODYTEXT], ARTICLES.A[BODYTEXT]);
    assert.deepEqual(
      servers.strict.views("reader").length,
      2,
      "a re-read of a counted render buys nothing",
    );

    // The renderId the meter counts by comes out of the verified resource. A
    // client that rewrites the unsigned copy to one already counted changes
    // nothing - and the request still verifies, so this is a 401 and not a 400.
    const load = browser.load(rootFromPage(c));
    await load.resolve([BODYTEXT]);
    load.dcaData.resource.renderId = a.asJson().resource.renderId;
    const forged = await load.unlock({ issuerName: STRICT, credential: "reader" });
    assert.equal(forged.status, 401);
    assert.equal(servers.strict.views("reader").length, 2);
  });

  test("a meter needs someone to count against, so an unknown caller gets nothing", async () => {
    const { servers, browser, render } = await world({ rules: METERED_RULES });

    const read = await readArticle(browser, await render("A"), [BODYTEXT], { issuerName: STRICT });

    assert.equal(read.unlock.status, 401);
    assert.equal(read.texts[BODYTEXT], null);
    assert.equal(servers.strict.stats().denials, 1);
  });

  test("a 200 that opened nothing leaves the meter where it was", async () => {
    const { servers, browser, render } = await world({ rules: METERED_RULES });
    servers.strict.grant("reader", {});

    const first = await readArticle(browser, await render("A"), [BODYTEXT], {
      issuerName: STRICT,
      credential: "reader",
    });
    assert.equal(first.texts[BODYTEXT], ARTICLES.A[BODYTEXT]);
    assert.equal(servers.strict.views("reader").length, 1);

    // The keyId the page names is one this issuer has since let go, and the
    // decision is made before anything is opened: the reader is inside the
    // meter, so the policy says yes and names the view to record. Every
    // coordinate then comes back an error and the body carries no key at all.
    // Debiting the view there spends one of two free articles on content
    // nobody opened.
    servers.strict.retireKey(KEY_ID);

    const second = await readArticle(browser, await render("B"), [BODYTEXT], {
      issuerName: STRICT,
      credential: "reader",
    });

    assert.equal(second.unlock.attempts[0].status, 200);
    assert.equal(second.unlock.attempts[0].outcome, "key_retired");
    assert.equal(servers.strict.stats().grants, 1, "the first read, and nothing since");
    assert.equal(
      servers.strict.views("reader").length,
      1,
      "a response that handed nothing over costs nothing",
    );
  });

  test("a view the cache resolved never reaches the issuer to be counted", async () => {
    const { servers, browser, render } = await world({ rules: CACHED_METER_RULES });
    servers.strict.grant("reader", {});

    const first = await readArticle(browser, await render("A"), [BODYTEXT], {
      issuerName: STRICT,
      credential: "reader",
    });
    assert.equal(first.texts[BODYTEXT], ARTICLES.A[BODYTEXT]);
    assert.equal(servers.strict.views("reader").length, 1);

    // Second article of the same period. The periodKey the first unlock
    // granted opens it, so the meter never hears about the view.
    const second = await readArticle(browser, await render("B"), [BODYTEXT], {
      issuerName: STRICT,
      credential: "reader",
    });
    assert.equal(second.unlock, null, "nothing was missing, so nothing was asked");
    assert.equal(second.texts[BODYTEXT], ARTICLES.B[BODYTEXT]);

    assert.equal(servers.strict.stats().requests, 1);
    assert.equal(
      servers.strict.views("reader").length,
      1,
      "a cached read is a view the issuer cannot see",
    );
  });
});

/**
 * A reader configured with only the strict issuer. These fault tests weigh the
 * strict issuer answering 500 and granting nothing, and a 500 is a fault that
 * walks on: the naive fallback the shared `world` stands up would answer
 * past it and open the article, which is the transport ruling working and not
 * what is under test here. With the strict issuer alone, the walk has nowhere to
 * go, so its fault is the whole answer.
 *
 * @param {any} stage - a `world()` result
 * @returns {any} a browser walking the strict issuer alone
 */
function strictReader(stage) {
  return stage.makeBrowser({
    issuers: [{ issuerName: STRICT, unlockUrl: stage.servers.strict.unlockUrl }],
  });
}

describe("A policy that does not answer", () => {
  test("a policy that answers with nothing is a server fault, not a grant", async () => {
    const stage = await world({ policy: { decide: () => undefined } });
    const { servers, render } = stage;

    const read = await readArticle(strictReader(stage), await render("A"), [BODYTEXT], {
      issuerName: STRICT,
      credential: "alice",
    });

    assert.equal(
      read.unlock.status,
      500,
      "an unreadable decision is never read as a permissive one",
    );
    assert.equal(read.texts[BODYTEXT], null);
    assert.equal(servers.strict.stats().grants, 0);
  });

  test("a decision section that is not a list of names is a fault, not a grant", async () => {
    // A policy that answers with a bare name where a list belongs has said
    // something the engine cannot read. Read loosely, `'bodytext'` contains
    // 'bodytext' and the typo becomes a grant, so it is refused instead. A
    // list is read whole: one entry that is no name refuses the names beside it.
    for (const contentNames of [BODYTEXT, [BODYTEXT, 5]]) {
      const stage = await world({
        policy: { decide: () => ({ contentNames, periodGrants: [], policyData: [] }) },
      });
      const { servers, render } = stage;

      const read = await readArticle(strictReader(stage), await render("A"), [BODYTEXT], {
        issuerName: STRICT,
        credential: "alice",
      });

      const label = JSON.stringify(contentNames);
      assert.equal(read.unlock.status, 500, label);
      assert.equal(read.texts[BODYTEXT], null, label);
      assert.equal(servers.strict.stats().grants, 0, label);
    }
  });

  test("policy data this demo server cannot apply is a fault after delivery", async () => {
    // The issuer core carries host data without interpreting it. This demo
    // server expects pending view records, so one handed over bare is a host
    // configuration fault rather than bookkeeping it may silently skip.
    const bare = {
      decide: () => ({
        contentNames: [BODYTEXT],
        periodGrants: [],
        policyData: { type: "view", user: "reader", renderId: "render-a" },
      }),
    };
    const stage = await world({ policy: bare });
    const { servers, render } = stage;

    const read = await readArticle(strictReader(stage), await render("A"), [BODYTEXT], {
      issuerName: STRICT,
    });

    assert.equal(read.unlock.status, 500, "bookkeeping the host cannot apply is not a no-op");
    assert.equal(read.texts[BODYTEXT], null);
    assert.deepEqual(servers.strict.views("reader"), []);
    assert.equal(servers.strict.stats().grants, 0);

    // Omitted host data means there is no post-delivery work.
    const silent = { decide: () => ({ contentNames: [BODYTEXT], periodGrants: [] }) };
    const quiet = await world({ policy: silent });

    const answered = await readArticle(quiet.browser, await quiet.render("A"), [BODYTEXT], {
      issuerName: STRICT,
    });
    assert.equal(answered.unlock.status, 200);
    assert.equal(answered.texts[BODYTEXT], ARTICLES.A[BODYTEXT]);
  });

  test("malformed policy data is an internal host fault on the wire", async () => {
    const malformed = {
      decide: () => ({
        contentNames: [BODYTEXT],
        periodGrants: [],
        policyData: [null],
      }),
    };
    const { servers, network, render } = await world({ policy: malformed });
    const page = await render("A");

    const answer = await network.post(
      servers.strict.unlockUrl,
      requestFor(page, STRICT, [BODYTEXT]),
      {
        origin: page.publisherOrigin,
      },
    );

    assert.deepEqual(answer, {
      status: 500,
      body: { error: "internal_error", issuerName: STRICT },
    });
    assert.equal(servers.strict.stats().faults, 1);
    assert.equal(servers.strict.stats().grants, 0);
  });

  test("policy data is not applied when the final response delivers no key", async () => {
    const pendingUnknownWork = {
      decide: () => ({
        contentNames: [BODYTEXT],
        periodGrants: [],
        policyData: { type: "unknown-host-action" },
      }),
    };
    const { servers, browser, render } = await world({ policy: pendingUnknownWork });
    const page = await render("A");

    // The policy says yes, but the retired issuer key leaves only a
    // per-item error in the final response. No delivery means this host has
    // no policy data to interpret or apply.
    servers.strict.retireKey(KEY_ID);
    const read = await readArticle(browser, page, [BODYTEXT], { issuerName: STRICT });

    assert.equal(read.unlock.status, 200);
    assert.equal(read.unlock.attempts[0].outcome, "key_retired");
    assert.equal(servers.strict.stats().faults, 0);
    assert.equal(servers.strict.stats().grants, 0);
  });

  test("a policy naming coordinates the request never carried opens nothing extra", async () => {
    // The decision is an allow-list over what arrived, never a shopping list.
    // A policy naming a blob nobody sent must not turn into an attempt to open
    // one - which would report a per-item failure for an item the client never
    // asked about, and index the request's own maps by a name the policy chose.
    const generous = {
      decide: (_claims, requested) => ({
        contentNames: [BODYTEXT, PREMIUM, "ghost", "constructor"],
        periodGrants: [VAULT_GROUP, "ghost-group"].map((accessGroup) => ({
          accessGroup,
          periods: requested.periodCoordinates[accessGroup] ?? [],
        })),
        policyData: [],
      }),
    };
    const { servers, render, publisherRegistration } = await world({ policy: generous });
    const page = await render("A");

    // One name asked for, so one contentKey and its own group are on the wire.
    const answer = await unlockThroughAdmission(
      servers.strict.processor,
      servers.strict.endpoint,
      requestFor(page, STRICT, [BODYTEXT]),
      publisherRegistration,
    );

    assert.equal(answer.status, 200);
    assert.deepEqual(Object.keys(contentKeyMap(answer.body.keys.contentKeys)), [BODYTEXT]);
    assert.equal(
      answer.body.keys.periodKeys,
      undefined,
      "no group the request carried was granted",
    );
    assert.equal(answer.body.errors, undefined, "nothing was attempted that was never sent");
  });

  test("the server records a view once per render, however often it is told", async () => {
    // A policy that says the same thing on every request. What it records is a
    // coordinate, not an increment, so telling the server twice cannot make
    // two views out of one render.
    const repeating = {
      decide: () => ({
        contentNames: [BODYTEXT],
        periodGrants: [],
        policyData: [{ type: "view", user: "reader", renderId: "render-a" }],
      }),
    };
    const { servers, browser, render } = await world({ policy: repeating });

    await readArticle(browser, await render("A"), [BODYTEXT], { issuerName: STRICT });
    await readArticle(browser, await render("B"), [BODYTEXT], { issuerName: STRICT });

    assert.equal(servers.strict.stats().requests, 2);
    assert.deepEqual(servers.strict.views("reader"), ["render-a"]);
  });

  test("a policy record this server cannot apply is a fault, not a silent no-op", async () => {
    const inventive = {
      decide: () => ({
        contentNames: [BODYTEXT],
        periodGrants: [],
        policyData: [{ type: "invoice", user: "reader", amount: 3 }],
      }),
    };
    const stage = await world({ policy: inventive });
    const { servers, render } = stage;

    const read = await readArticle(strictReader(stage), await render("A"), [BODYTEXT], {
      issuerName: STRICT,
    });

    assert.equal(read.unlock.status, 500);
    assert.equal(servers.strict.stats().grants, 0);
  });
});
