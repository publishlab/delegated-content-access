//
// The actors that hold configuration rather than a story: the two injected
// sources, the store an issuer keeps its keypairs in, and the publisher that
// turns an article into a page.
//
// This file wires them by hand, deliberately. `demo/scenarios/world.js` builds both of the
// last two, so a test of them that went through it would be checking the
// builder as much as the class. The names and the key material still come from
// `demo/scenarios/fixtures.js` and `test-reference/support/keys.js`: hand-wired means this file
// assembles the actors itself, on the suite's one issuer and one publisher.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Random } from "../../demo/actors/Random.js";
import { Clock } from "../../demo/actors/Clock.js";
import { IssuerKeyStore } from "../../demo/support/IssuerKeyStore.js";
import {
  PublisherRegistrations,
  openingKeysOver,
} from "../../demo/support/PublisherRegistrations.js";
import { Publisher } from "../../demo/actors/Publisher.js";
import { Browser } from "../../demo/actors/Browser.js";
import { PageLoad } from "../../demo/actors/PageLoad.js";
import { Network } from "../../demo/actors/Network.js";
import { Storage } from "../../demo/actors/Storage.js";
import { IssuerServer } from "../../demo/actors/IssuerServer.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { FailoverGate } from "../../demo/actors/issuer/FailoverGate.js";
import { trimToCurrentPeriod } from "../../demo/actors/issuer/trimToCurrentPeriod.js";
import { IssuerBusinessData } from "../../demo/actors/issuer/IssuerBusinessData.js";
import { KeyDelivery } from "../../adapter-issuer/KeyDelivery.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { DcaRequestBuilder } from "../../core-client/DcaRequestBuilder.js";
import { decodeHeader } from "../../core-shared--publisher-issuer/jwt.js";
import { formatT } from "../../core-shared--publisher-issuer/periodKeys.js";
import { dcaError } from "../../core-shared/errors.js";
import { PERIOD_KEY_PROFILE, periodKeyProfile } from "../../core-shared/periodKeyProfiles.js";
import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
import { Sealer } from "../../core-publisher/Sealer.js";
import { utf8Decode } from "../../core-shared/codec.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { actorWorld, readArticle } from "../../demo/scenarios/world.js";
import { rootFromPage } from "../../demo/support/queryableRoot.js";
import { SEALED_SELECTOR } from "../../core-shared/markupPlacement.js";
import { requestFor } from "../../test-lib/harnesses/issuer-endpoint.js";
import {
  ACCESS_GROUP,
  ALGORITHM,
  ARTICLES,
  AT,
  CONTENT_NAME,
  DOMAIN,
  FALLBACK_ISSUER_NAME,
  HEALTH_URL,
  ISSUER_NAME,
  KEY_ID,
  SIGNING_KID,
  UNLOCK_URL,
  article,
  periodSecret,
  ungroupedArticle,
} from "../../demo/scenarios/fixtures.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";
import { keyAt } from "../support/namedRecords.js";
import {
  contentRecordOf,
  issuerBlockOf,
  issuerNamesOn,
  periodsOn,
} from "../../test-lib/helpers/inspect.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";

const clientBoundProfileStub = {
  METHOD: "test-only-client-bound",
  RANDOM_REQUIRED: false,
  seal() {
    throw new Error("client-bound profile stub reached");
  },
};

/**
 * The keyId and kid a rotation moves to. The fixtures name one of each, which is
 * what a render carries; the far side of a rotation is only ever two of them in
 * one place, and this file is the only one that holds both.
 */
const KEY_NEXT = "2025-11";
const KID_NEXT = "sign-2025-11";
const PUBLISHER_ORIGIN = `https://${DOMAIN}`;

/**
 * One publisher holding both sides of all three rotations from the start, which is
 * what a rotation needs: a second key, and a choice about which one is used.
 *
 * @returns {Promise<any>}
 */
async function publisherHoldingTwoOfEverything() {
  const clock = new Clock(AT);
  const issuerKeys = { [KEY_ID]: await issuerKeypair(), [KEY_NEXT]: await issuerKeypair() };
  const signingKeys = { [SIGNING_KID]: await signingKeypair(), [KID_NEXT]: await signingKeypair() };

  const keyStore = new IssuerKeyStore(
    Object.entries(issuerKeys).map(([keyId, pair]) => ({
      issuerName: ISSUER_NAME,
      keyId,
      algorithm: ALGORITHM,
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
    })),
  );

  const periodKeySupply = randomPeriodKeySupply();
  const publisher = new Publisher({
    origin: PUBLISHER_ORIGIN,
    clock,
    random: new Random({ seed: 1 }),
    signingKeys: {
      [SIGNING_KID]: signingKeys[SIGNING_KID].privateKey,
      [KID_NEXT]: signingKeys[KID_NEXT].privateKey,
    },
    signingKid: SIGNING_KID,
    periodKeySupply,
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        publicKey: keyStore.publicKey(ISSUER_NAME, KEY_ID),
      },
    ],
  });

  return { clock, keyStore, publisher, periodKeySupply, issuerKeys, signingKeys };
}

/**
 * What one render says about each of the three axes, read off the wire.
 *
 * @param {any} page
 * @returns {{ kid: string, keyId: string, periods: string[] }}
 */
function axesOf(page) {
  const rendered = page.asJson();
  return {
    kid: decodeHeader(rendered.resourceJWT).kid,
    keyId: issuerBlockOf(rendered).keyId,
    periods: periodsOn(rendered),
  };
}

/**
 * Whether a client holding one periodKey opens this render's item. Period-key
 * material never travels on the wire, so the only honest reading of
 * "the cached path moved" is that the old key stops covering.
 *
 * @param {any} page
 * @param {Uint8Array} key
 * @param {string} t
 * @returns {Promise<string[]>} the names it covered
 */
async function coveredWith(page, key, t) {
  const cache = new PeriodKeyCache();
  const dcaData = page.asJson();
  // The resolver reads candidates back under the page's own publisher, so a key
  // seeded straight in has to be filed under it too.
  await cache.put(ACCESS_GROUP, t, key, { publisher: page.publisherOrigin });

  const unsealer = new Client({ cache, publisherOrigin: page.publisherOrigin });
  const { covered } = await unsealer.resolve(unsealer.parse(dcaData), [CONTENT_NAME]);
  return covered;
}

describe("Random", () => {
  test("returns the asked-for byte count", () => {
    const random = new Random();
    assert.equal(random.bytes(12).length, 12);
    assert.equal(random.bytes(32).length, 32);
    assert.equal(random.bytes(0).length, 0);
    assert.ok(random.bytes(4) instanceof Uint8Array);
  });

  test("is real by default, so two draws differ", () => {
    const random = new Random();
    assert.notDeepEqual(random.bytes(32), random.bytes(32));
  });

  test("two Randoms on one seed replay the same run", () => {
    const first = new Random({ seed: 42 });
    const second = new Random({ seed: 42 });

    assert.deepEqual(first.bytes(32), second.bytes(32));
    assert.deepEqual(first.bytes(12), second.bytes(12));
  });

  test("a seeded Random still moves between draws", () => {
    const random = new Random({ seed: 42 });
    assert.notDeepEqual(random.bytes(32), random.bytes(32));
  });

  test("different seeds diverge", () => {
    assert.notDeepEqual(new Random({ seed: 1 }).bytes(32), new Random({ seed: 2 }).bytes(32));
  });

  test("refuses a count that is not a non-negative integer, as a coded error", () => {
    assert.throws(
      () => new Random().bytes(-1),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.throws(
      () => new Random().bytes(2.5),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });
});

describe("Clock", () => {
  test("reports the moment it was set to", () => {
    const clock = new Clock("2025-10-23T14:00:00Z");
    assert.equal(clock.now().toISOString(), "2025-10-23T14:00:00.000Z");
  });

  test("stands still until moved", () => {
    const clock = new Clock("2025-10-23T14:00:00Z");
    const first = clock.now();
    const second = clock.now();

    assert.equal(first.getTime(), second.getTime());
    assert.notEqual(first, second, "each read is its own Date, so a caller cannot move the clock");
  });

  test("advances by milliseconds and resets to an instant", () => {
    const clock = new Clock("2025-10-23T14:00:00Z");

    clock.advance(3_600_000);
    assert.equal(clock.now().toISOString(), "2025-10-23T15:00:00.000Z");

    clock.set("2025-10-24T00:00:00Z");
    assert.equal(clock.now().toISOString(), "2025-10-24T00:00:00.000Z");
  });

  test("refuses an unreadable instant, as a coded error", () => {
    assert.throws(
      () => new Clock("not-a-time"),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.throws(
      () => new Clock("2025-10-23T14:00:00Z").set("also-not-a-time"),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("refuses a non-finite advance, as a coded error", () => {
    assert.throws(
      () => new Clock("2025-10-23T14:00:00Z").advance(NaN),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });
});

describe("IssuerKeyStore", () => {
  test("answers a coordinate it holds, and nothing at all for one it never had", async () => {
    const pair = await issuerKeypair();
    const store = new IssuerKeyStore([
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
      },
    ]);

    assert.deepEqual(store.get(ISSUER_NAME, KEY_ID), {
      algorithm: ALGORITHM,
      privateKey: pair.privateKey,
    });

    // Both coordinates select, and either one being wrong is the same answer:
    // a request that came to the wrong door, with nothing to report per item.
    assert.equal(store.get(ISSUER_NAME, "2019-01"), undefined);
    assert.equal(store.get("some_other_issuer", KEY_ID), undefined);
  });

  test("hands the publisher the public half, and being asked for it is not a reach", async () => {
    const pair = await issuerKeypair();
    const store = new IssuerKeyStore([
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
      },
    ]);

    assert.equal(store.publicKey(ISSUER_NAME, KEY_ID), pair.publicKey);
    assert.equal(store.publicKey(ISSUER_NAME, "2019-01"), undefined);

    // Onboarding stops short of an unlock. Nothing about the private key was
    // consulted, so a refusal that only ever handed out public halves still reads
    // as having reached no key.
    assert.equal(store.reachCount, 0);
    assert.equal(store.privateKeyReached, false);

    // What `get` hands the engine never carries the public half with it: a key
    // about to unseal should not travel beside the one a publisher seals with.
    assert.equal(
      Object.hasOwn(/** @type {any} */ (store.get(ISSUER_NAME, KEY_ID)), "publicKey"),
      false,
    );
  });

  test("a retired keyId is an answer and not a miss, and its public half still resolves", async () => {
    const pair = await issuerKeypair();
    const store = new IssuerKeyStore([
      { issuerName: ISSUER_NAME, keyId: KEY_ID, retired: true, publicKey: pair.publicKey },
    ]);

    assert.deepEqual(store.get(ISSUER_NAME, KEY_ID), { retired: true });

    // The retirement is about the private half. Markup an edge cache is still
    // serving was sealed under the public one, which is why it stays readable
    // here: the page still exists.
    assert.equal(store.publicKey(ISSUER_NAME, KEY_ID), pair.publicKey);
  });

  test("counts what reached the private key, which an absorbed unseal failure cannot show", async () => {
    const pair = await issuerKeypair();
    const store = new IssuerKeyStore([
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
      },
    ]);

    assert.equal(store.reachCount, 0);
    assert.equal(store.privateKeyReached, false, "a fresh store has been asked nothing");

    store.get(ISSUER_NAME, KEY_ID);
    assert.equal(store.reachCount, 1);
    assert.equal(store.privateKeyReached, true);

    // A miss counts too. The count tracks how far into the issuer a request got,
    // and a request that reached the store and was told "no such keyId" got past
    // everything in front of it.
    store.get(ISSUER_NAME, "2019-01");
    assert.equal(store.reachCount, 2);
  });

  test("hands a test the private half without counting a reach", async () => {
    const pair = await issuerKeypair();
    const store = new IssuerKeyStore([
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
      },
      { issuerName: ISSUER_NAME, keyId: KEY_NEXT, retired: true, publicKey: pair.publicKey },
    ]);

    assert.equal(store.privateKeyOf(ISSUER_NAME, KEY_ID), pair.privateKey);
    assert.equal(store.privateKeyOf(ISSUER_NAME, "2019-01"), undefined);
    assert.equal(store.privateKeyOf("some_other_issuer", KEY_ID), undefined);

    // A retirement takes the private half, and only that half goes: the public
    // one still answers for the markup sealed under it.
    assert.equal(store.privateKeyOf(ISSUER_NAME, KEY_NEXT), undefined);
    assert.equal(store.publicKey(ISSUER_NAME, KEY_NEXT), pair.publicKey);

    // Four reads of the private side, and the count every "nothing was touched"
    // claim rests on has not moved: this is a test doing the unsealing itself,
    // and no request reached the issuer.
    assert.equal(store.reachCount, 0);
    assert.equal(store.privateKeyReached, false);

    store.get(ISSUER_NAME, KEY_ID);
    assert.equal(store.reachCount, 1, "the engine path is the one that counts");
  });

  test("refuses an entry that is both held and retired, or neither", async () => {
    const pair = await issuerKeypair();

    for (const [entry, what] of /** @type {any[][]} */ ([
      [{ algorithm: ALGORITHM }, "neither a private key nor a retirement"],
      [
        { algorithm: ALGORITHM, retired: true, privateKey: pair.privateKey },
        "both held and retired",
      ],
    ])) {
      assert.throws(
        () => new IssuerKeyStore([{ issuerName: ISSUER_NAME, keyId: KEY_ID, ...entry }]),
        (/** @type {any} */ error) => error.code === "bad_config" && error.message.includes(what),
        what,
      );
    }

    // An entry holding a key has to say which algorithm it is for: the engine
    // reads that off the entry and there is nowhere else for it to come from.
    assert.throws(
      () =>
        new IssuerKeyStore([
          { issuerName: ISSUER_NAME, keyId: KEY_ID, privateKey: pair.privateKey },
        ]),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("key lifecycle replaces a key, retires one, or forgets its coordinate", async () => {
    const first = await issuerKeypair();
    const second = await issuerKeypair();
    const store = new IssuerKeyStore([
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        privateKey: first.privateKey,
        publicKey: first.publicKey,
      },
    ]);

    store.rotate(ISSUER_NAME, KEY_NEXT, {
      algorithm: ALGORITHM,
      privateKey: second.privateKey,
      publicKey: second.publicKey,
    });
    assert.equal(
      /** @type {any} */ (store.get(ISSUER_NAME, KEY_NEXT)).privateKey,
      second.privateKey,
    );
    assert.equal(
      /** @type {any} */ (store.get(ISSUER_NAME, KEY_ID)).privateKey,
      first.privateKey,
      "the key the served markup names is still resolvable, which is the point of a rotation",
    );

    store.rotate(ISSUER_NAME, KEY_NEXT, { retired: true });
    assert.deepEqual(store.get(ISSUER_NAME, KEY_NEXT), { retired: true });
    assert.equal(
      store.publicKey(ISSUER_NAME, KEY_NEXT),
      second.publicKey,
      "the legacy form delegates safely",
    );

    store.retire(ISSUER_NAME, KEY_ID);
    assert.deepEqual(store.get(ISSUER_NAME, KEY_ID), { retired: true });
    assert.equal(
      store.publicKey(ISSUER_NAME, KEY_ID),
      first.publicKey,
      "retirement keeps the public half",
    );

    // Repeating the operation leaves the same tombstone. A coordinate this
    // store never held cannot be made to look retired after the fact.
    store.retire(ISSUER_NAME, KEY_ID);
    assert.throws(
      () => store.retire(ISSUER_NAME, "2019-01"),
      (/** @type {any} */ error) => error.code === "bad_config",
    );

    store.rotate(ISSUER_NAME, KEY_ID, null);
    assert.equal(
      store.get(ISSUER_NAME, KEY_ID),
      undefined,
      "forgetting a keyId is the third thing, and it is not a retirement",
    );

    // A rotation says where it lands in its arguments. An entry naming another
    // coordinate inside itself is two answers to one question.
    assert.throws(
      () =>
        store.rotate(
          ISSUER_NAME,
          KEY_NEXT,
          /** @type {any} */ ({
            issuerName: "some_other_issuer",
            algorithm: ALGORITHM,
            privateKey: second.privateKey,
          }),
        ),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });
});

describe("IssuerBusinessData", () => {
  test("copies grants in and principals out", () => {
    const businessData = new IssuerBusinessData();
    const entitlement = { contentNames: ["bodytext"] };
    businessData.grant("alice", entitlement);

    entitlement.contentNames.push("premiumtext");
    assert.deepEqual(businessData.authenticate("alice"), {
      user: "alice",
      contentNames: ["bodytext"],
    });

    const principal = /** @type {any} */ (businessData.authenticate({ user: "alice" }));
    principal.contentNames.push("premiumtext");
    assert.deepEqual(businessData.authenticate("alice"), {
      user: "alice",
      contentNames: ["bodytext"],
    });

    businessData.expire("alice");
    assert.equal(businessData.authenticate("alice"), null);
  });

  test("copies views into snapshots and applies pending records once", () => {
    const businessData = new IssuerBusinessData();
    const now = new Date(AT);
    businessData.apply([
      { type: "view", user: "alice", renderId: "render-a" },
      { type: "view", user: "alice", renderId: "render-a" },
    ]);

    const snapshot = businessData.snapshot(now);
    assert.strictEqual(snapshot.now, now);
    assert.deepEqual(snapshot.views.alice, ["render-a"]);
    snapshot.views.alice.push("render-b");
    assert.deepEqual(businessData.views("alice"), ["render-a"]);
  });

  test("validates all policy data before changing business data", () => {
    const businessData = new IssuerBusinessData();

    assert.throws(
      () => businessData.apply([{ type: "view", user: "alice", renderId: "render-a" }, null]),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.deepEqual(businessData.views("alice"), []);
  });
});

describe("transport-mode selection is the issuer application's", () => {
  // The mode is chosen by the issuer application (IssuerServer), not by the
  // KeyDelivery adapter it hands the chosen mode to. Constructed on stub
  // interfaces: this asserts the configured selection, not a served request.
  // Per-request selection under a policy and a policy that answers with
  // something that is not a mode are exercised
  // end to end in client-bound.test.js and transport.test.js.
  const stand = (/** @type {any} */ extra = {}) =>
    new IssuerServer({
      clock: new Clock(AT),
      network: new Network({ clock: new Clock(AT) }),
      issuerName: ISSUER_NAME,
      operatingIssuerNames: [ISSUER_NAME],
      unlockUrl: UNLOCK_URL,
      keyStore: { get: () => undefined },
      publisherRegistrations: { get: () => undefined, allowsOrigin: () => false },
      accessPolicy: new AllowAllPolicy(),
      ...extra,
    });

  test("a pinned mode is the deployment's, a policy leaves no single mode it is in", () => {
    assert.equal(stand().stats().transportMode, "direct", "the default is direct");
    assert.equal(
      stand({
        transportMode: "client-bound",
        clientBoundProfile: clientBoundProfileStub,
        random: new Random({ seed: 1 }),
      }).stats().transportMode,
      "client-bound",
    );
    assert.equal(
      stand({
        transportPolicy: { modeFor: () => "direct" },
        clientBoundProfile: clientBoundProfileStub,
        random: new Random({ seed: 1 }),
      }).stats().transportMode,
      null,
      "a policy decides per request, so there is no one mode the deployment is in",
    );
  });

  test("declared response sections reach the server's KeyDelivery with their kinds", () => {
    const clientBound = {
      transportMode: "client-bound",
      clientBoundProfile: clientBoundProfileStub,
      random: new Random({ seed: 1 }),
    };
    const responseSections = [
      { path: ["extraKeys"], fields: ["contentName"], keyKind: "extraKey" },
    ];
    assert.equal(
      stand({
        ...clientBound,
        responseSections,
        composedKinds: { extraKey: { width: 16 } },
      }).stats().transportMode,
      "client-bound",
    );
    for (const extra of [
      { responseSections },
      { responseSections: [{ path: ["keys"], fields: ["contentName"], keyKind: "contentKey" }] },
      { responseSections: "extraKeys" },
    ])
      assert.throws(
        () => stand({ ...clientBound, ...extra }),
        (/** @type {any} */ error) => error.code === "bad_config",
        JSON.stringify(extra),
      );
  });

  test("a mode and a policy are not both, an unknown mode is refused, client-bound needs a Random", () => {
    assert.throws(
      () => stand({ retries: 3 }),
      (/** @type {any} */ error) =>
        error.code === "unsupported_option" && /retries/.test(error.message),
    );
    assert.throws(
      () =>
        stand({
          transportMode: "direct",
          transportPolicy: { modeFor: () => "direct" },
          random: new Random({ seed: 1 }),
        }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.throws(
      () => stand({ transportMode: "sealed-envelope" }),
      (/** @type {any} */ error) => error.code === "unsupported_option",
    );
    assert.throws(
      () => stand({ transportPolicy: { decide: () => "direct" } }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.throws(
      () => stand({ transportMode: "client-bound" }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });
});

describe("FailoverGate", () => {
  test("an HTTP 200 probe reporting unhealthy allows the fallback", async () => {
    const clock = new Clock(AT);
    const network = new Network({ clock });
    network.serve(HEALTH_URL, () => ({ status: 200, body: { healthy: false } }));
    const gate = new FailoverGate({ clock, network, healthCheckUrl: HEALTH_URL, caller: {} });

    assert.equal(await gate.allows(), true);
    assert.equal(gate.stats().probes, 1);
  });

  test("probes as its owner and caches the result from when the answer arrived", async () => {
    const clock = new Clock("2025-10-23T14:00:00Z");
    const network = new Network({ clock });
    const caller = { role: "fallback" };
    const healthUrl = "https://primary.example.com/health";
    network.serve(healthUrl, () => ({ status: 200, body: { healthy: true } }));

    const gate = new FailoverGate({
      clock,
      network,
      healthCheckUrl: healthUrl,
      healthTtl: 10,
      caller,
    });
    assert.equal(await gate.allows(), false);

    network.offline(healthUrl, { from: caller });
    assert.equal(await gate.allows(), false, "the cached healthy answer still holds");
    clock.advance(11);
    assert.equal(
      await gate.allows(),
      true,
      "the next probe sees the outage from the owner's vantage",
    );
    assert.deepEqual(gate.stats(), { probes: 2, healthReads: 1 });
  });

  test("trims each accessGroup independently without inventing availability", () => {
    const body = {
      keys: {
        contentKeys: [{ contentName: "bodytext", key: "content-key" }],
        periodKeys: [
          { accessGroup: "article", period: "251023T1300", key: "old" },
          { accessGroup: "article", period: "251023T1400", key: "current" },
          { accessGroup: "article", period: "251023T1500", key: "future" },
          { accessGroup: "future", period: "251023T1500", key: "not-started" },
        ],
      },
    };

    assert.deepEqual(trimToCurrentPeriod(body, new Date("2025-10-23T14:30:00Z")), {
      keys: {
        contentKeys: [{ contentName: "bodytext", key: "content-key" }],
        periodKeys: [{ accessGroup: "article", period: "251023T1400", key: "current" }],
      },
    });
  });

  test("the trim keeps every rival record at the current label", () => {
    // Two records at one coordinate are separate candidates, and the trim is
    // not the place that picks between them: the client keeps the one that
    // opens.
    const body = {
      keys: {
        periodKeys: [
          { accessGroup: "article", period: "251023T1300", key: "old" },
          { accessGroup: "article", period: "251023T1400", key: "current-a" },
          { accessGroup: "article", period: "251023T1400", key: "current-b" },
        ],
      },
    };

    assert.deepEqual(trimToCurrentPeriod(body, new Date("2025-10-23T14:30:00Z")), {
      keys: {
        periodKeys: [
          { accessGroup: "article", period: "251023T1400", key: "current-a" },
          { accessGroup: "article", period: "251023T1400", key: "current-b" },
        ],
      },
    });
  });

  test("the trim preserves the engine's notDelivered report and errors without adding a reason", () => {
    const body = {
      keys: { periodKeys: [{ accessGroup: "future", period: "251023T1500", key: "not-started" }] },
      errors: [{ coordinate: "article|251023T1400", error: "unseal_failed" }],
      notDelivered: [{ accessGroup: "premium", reason: "denied" }],
    };

    assert.deepEqual(trimToCurrentPeriod(body, new Date("2025-10-23T14:30:00Z")), {
      keys: {},
      errors: [{ coordinate: "article|251023T1400", error: "unseal_failed" }],
      notDelivered: [{ accessGroup: "premium", reason: "denied" }],
    });
  });

  test("a family that carries a period-coordinate error loses its unstarted keys but gets no notDelivered entry", () => {
    // The client refuses a whole response that names a family in
    // notDelivered beside an error on one of that family's periods, so the
    // trim leaves the coordinate error to speak for the family.
    const body = {
      keys: { periodKeys: [{ accessGroup: "future", period: "251023T1500", key: "not-started" }] },
      errors: [{ coordinate: "future|251023T1400", error: "unseal_failed" }],
    };

    assert.deepEqual(trimToCurrentPeriod(body, new Date("2025-10-23T14:30:00Z")), {
      keys: {},
      errors: [{ coordinate: "future|251023T1400", error: "unseal_failed" }],
    });
  });
});

describe("IssuerServer composition injects business data, versions, and one decision view", () => {
  // These stand a full issuer up through `actorWorld`, on purpose: what an
  // injected businessData, a narrowed supportedVersions, or the single
  // per-request decision view does is only visible on the served path, which
  // the stub-wired stands above never walk.

  test("one #unlock takes one business-state snapshot, and the same view reaches mode selection and the miss", async () => {
    // A store that answers the business-data contract and counts the one
    // thing this test is about: how many times a request reads it.
    class RecordingBusinessData {
      snapshotCalls = 0;
      /** @type {any} */
      lastSnapshot = null;
      /** @param {Date} now */
      snapshot(now) {
        this.snapshotCalls++;
        this.lastSnapshot = { taken: this.snapshotCalls, now };
        return this.lastSnapshot;
      }
      authenticate() {
        return null;
      }
      grant() {}
      expire() {}
      apply() {}
      views() {
        return [];
      }
    }

    /** @type {any[]} The decision view mode selection was handed. */
    const modeStates = [];
    /** @type {any[]} The context the access policy was handed on the miss. */
    const missContexts = [];
    const transportPolicy = {
      /** @param {any} _request @param {any} state */
      modeFor(_request, state) {
        modeStates.push(state);
        return "direct";
      },
    };
    const accessPolicy = {
      /** @param {any} _claims @param {any} requested @param {any} input */
      decide(_claims, requested, input) {
        missContexts.push(input.context);
        return {
          contentNames: [...requested.contentNames],
          periodGrants: requested.accessGroups.map((accessGroup) => ({
            accessGroup,
            periods: requested.periodCoordinates[accessGroup] ?? [],
          })),
          policyData: [],
        };
      },
    };

    const businessData = new RecordingBusinessData();
    const world = await actorWorld({
      accessPolicy,
      transportPolicy,
      clientBoundProfile: clientBoundProfileStub,
      primary: { businessData },
    });
    const read = await readArticle(world.makeBrowser(), await world.render("A"), [CONTENT_NAME], {
      issuerName: ISSUER_NAME,
    });

    assert.equal(read.unlock.status, 200);
    assert.equal(
      businessData.snapshotCalls,
      1,
      "one request reads the business state exactly once",
    );
    assert.equal(modeStates.length, 1);
    assert.equal(missContexts.length, 1);
    assert.equal(
      modeStates[0].context,
      businessData.lastSnapshot,
      "mode selection reads the one snapshot",
    );
    assert.equal(
      missContexts[0],
      businessData.lastSnapshot,
      "the miss reads that same snapshot object",
    );
    assert.equal(
      modeStates[0].principal,
      null,
      "the decision view carries the principal beside the context",
    );
  });

  test("two servers share one injected businessData while their stats and role stay their own", async () => {
    const shared = new IssuerBusinessData();

    // A policy that grants and records one metered view per granted name, so
    // a grant made through the served path leaves state the peer can read.
    const meterPolicy = {
      /** @param {any} _claims @param {any} requested @param {any} input */
      decide(_claims, requested, input) {
        const user = input?.principal?.user ?? null;
        return {
          contentNames: [...requested.contentNames],
          periodGrants: requested.accessGroups.map((accessGroup) => ({
            accessGroup,
            periods: requested.periodCoordinates[accessGroup] ?? [],
          })),
          policyData:
            user === null
              ? []
              : requested.contentNames.map((renderId) => ({ type: "view", user, renderId })),
        };
      },
    };

    const world = await actorWorld({
      accessPolicy: meterPolicy,
      primary: { businessData: shared },
    });

    // A second server handed the very same business-state instance. It serves
    // no traffic of its own here: it proves that the identities and metered views
    // written through the primary are the ones it reads.
    const observer = new IssuerServer({
      clock: world.clock,
      network: world.network,
      issuerName: "observer_service",
      operatingIssuerNames: ["observer_service"],
      unlockUrl: "https://observer.example/unlock",
      keyStore: world.keyStores.primary,
      publisherRegistrations: world.publisherRegistrations,
      accessPolicy: new AllowAllPolicy(),
      role: "fallback",
      healthCheckUrl: HEALTH_URL,
      businessData: shared,
    });

    // A grant written through the primary is visible through the observer.
    world.servers.primary.grant("alice", { entitlements: ["news-site-premium"] });
    assert.deepEqual(
      observer.authenticate("alice"),
      { user: "alice", entitlements: ["news-site-premium"] },
      "the grant is in the store both servers hold",
    );

    // A granted unlock through the primary records a view into the shared
    // store, and the observer reads that view back out of it.
    const read = await readArticle(world.makeBrowser(), await world.render("A"), [CONTENT_NAME], {
      issuerName: ISSUER_NAME,
      credential: "alice",
    });
    assert.equal(read.unlock.status, 200);
    assert.deepEqual(
      observer.views("alice"),
      [CONTENT_NAME],
      "the metered view crossed to the peer",
    );

    // Endpoint-local counters and the failover role are each server's own.
    assert.equal(world.servers.primary.stats().grants, 1);
    assert.equal(observer.stats().grants, 0);
    assert.equal(world.servers.primary.stats().requests, 1);
    assert.equal(
      observer.stats().requests,
      0,
      "the peer served nothing, though it shares the state",
    );
    assert.equal(world.servers.primary.stats().role, "primary");
    assert.equal(observer.stats().role, "fallback");
  });

  test("an injected supportedVersions refuses an excluded version and counts it a refusal", async () => {
    // The engine defaults to reading version '1'; narrowing the set to one it
    // will never carry makes every request fail the version check.
    const world = await actorWorld({ primary: { supportedVersions: ["99"] } });
    const page = await world.render("A");

    // Posted through the network so the refusal runs on the served path,
    // where the whole-request stat is kept. The version check is the first
    // thing `IssuerEngine.unlock` does, ahead of the signature, so a fully
    // valid request still leaves on it.
    const answer = await world.network.post(UNLOCK_URL, requestFor(page), {
      origin: page.publisherOrigin,
    });
    assert.equal(answer.status, 400);
    assert.equal(answer.body.error, "bad_version");
    assert.equal(world.servers.primary.stats().refusals, 1, "the miss-path refusal is counted");
  });

  test("a denied request is reconsidered after policy grants access", async () => {
    let allowed = false;
    let decisions = 0;
    const accessPolicy = {
      decide(_claims, requested) {
        decisions++;
        return { contentNames: allowed ? [...requested.contentNames] : [], periodGrants: [] };
      },
    };
    const world = await actorWorld({ accessPolicy });
    const request = requestFor(await world.render("A"));
    const post = () => world.network.post(UNLOCK_URL, request, { origin: PUBLISHER_ORIGIN });

    const denied = await post();
    assert.equal(denied.status, 401);
    assert.equal(denied.body.error, "denied");
    assert.equal(denied.body.keys, undefined);

    // Same request, principal and clock instant; only the issuer's access
    // decision has changed.
    allowed = true;
    const granted = await post();
    assert.equal(granted.status, 200);
    assert.equal(
      typeof keyAt(granted.body.keys.contentKeys, { contentName: CONTENT_NAME }),
      "string",
    );
    assert.equal(granted.body.error, undefined);
    assert.equal(decisions, 2, "the second attempt reaches the access policy");
    assert.equal(world.servers.primary.stats().grants, 1);
  });

  test("a previously allowed request is denied after policy changes on the next call", async () => {
    let allowed = true;
    let decisions = 0;
    const accessPolicy = {
      decide(_claims, requested) {
        decisions++;
        return { contentNames: allowed ? [...requested.contentNames] : [], periodGrants: [] };
      },
    };
    const world = await actorWorld({ accessPolicy });
    const request = requestFor(await world.render("A"));
    const post = () => world.network.post(UNLOCK_URL, request, { origin: PUBLISHER_ORIGIN });

    const granted = await post();
    assert.equal(granted.status, 200);
    assert.equal(
      typeof keyAt(granted.body.keys.contentKeys, { contentName: CONTENT_NAME }),
      "string",
    );
    // The clock does not advance; this identical request is inside the
    // former response cache's 10-second TTL.
    allowed = false;
    const denied = await post();
    assert.equal(denied.status, 401);
    assert.equal(denied.body.error, "denied");
    assert.equal(denied.body.keys, undefined, "the issuer emits no new key after denial");
    assert.equal(decisions, 2, "the second attempt reaches current access policy");
  });

  test("a legacy capability fault reaches neither debit nor transport preparation", async () => {
    const originalUnlock = IssuerEngine.prototype.unlock;
    const originalPrepare = KeyDelivery.prototype.prepare;
    let engineCalls = 0;
    let preparations = 0;
    let applies = 0;
    IssuerEngine.prototype.unlock = async function (...args) {
      engineCalls++;
      const result = await originalUnlock.apply(this, args);
      return { ...result, periodCapabilities: { premium: { t: "legacy-key" } } };
    };
    KeyDelivery.prototype.prepare = async function (...args) {
      preparations++;
      return originalPrepare.apply(this, args);
    };

    try {
      const businessData = {
        snapshot() {
          return {};
        },
        authenticate() {
          return null;
        },
        grant() {},
        expire() {},
        apply() {
          applies++;
        },
        views() {
          return [];
        },
      };
      const accessPolicy = {
        decide(_claims, requested) {
          return {
            contentNames: [...requested.contentNames],
            periodGrants: requested.accessGroups.map((accessGroup) => ({
              accessGroup,
              periods: requested.periodCoordinates[accessGroup] ?? [],
            })),
            policyData: [{ type: "would-have-applied" }],
          };
        },
      };
      const world = await actorWorld({
        accessPolicy,
        primary: { businessData },
      });
      const request = requestFor(await world.render("A"));
      const post = () => world.network.post(UNLOCK_URL, request, { origin: PUBLISHER_ORIGIN });

      assert.deepEqual(await post(), { status: 500, body: { error: "internal_error" } });
      assert.deepEqual(await post(), { status: 500, body: { error: "internal_error" } });
      assert.equal(engineCalls, 2, "each request reaches the engine");
      assert.equal(preparations, 0, "no partial body reaches final transport preparation");
      assert.equal(applies, 0, "policy data is never debited after an encoding fault");
      const stats = world.servers.primary.stats();
      assert.equal(stats.grants, 0);
      assert.equal(stats.faults, 2);
    } finally {
      IssuerEngine.prototype.unlock = originalUnlock;
      KeyDelivery.prototype.prepare = originalPrepare;
    }
  });

  test("a final client-bound delivery failure is an internal whole-request fault", async () => {
    const originalPrepare = KeyDelivery.prototype.prepare;
    KeyDelivery.prototype.prepare = async function (body, view) {
      if (view.mode === "client-bound") {
        throw dcaError("bad_config", "test-only malformed issuer result");
      }
      return originalPrepare.call(this, body, view);
    };

    try {
      for (const [errorDetail, expectedBody] of [
        ["code", { error: "internal_error", issuerName: ISSUER_NAME }],
        ["uniform", { error: "rejected" }],
      ]) {
        let applies = 0;
        const refused = [];
        const businessData = {
          snapshot() {
            return {};
          },
          authenticate() {
            return null;
          },
          grant() {},
          expire() {},
          apply() {
            applies++;
          },
          views() {
            return [];
          },
        };
        const accessPolicy = {
          decide(_claims, requested) {
            return {
              contentNames: [...requested.contentNames],
              periodGrants: requested.accessGroups.map((accessGroup) => ({
                accessGroup,
                periods: requested.periodCoordinates[accessGroup] ?? [],
              })),
              policyData: [{ type: "would-have-applied" }],
            };
          },
        };
        const world = await actorWorld({
          accessPolicy,
          transportMode: "client-bound",
          clientBoundProfile: clientBoundProfileStub,
          primary: {
            businessData,
            errorDetail,
            log: { refused: (record) => refused.push(record) },
          },
        });
        const pair = /** @type {CryptoKeyPair} */ (
          await globalThis.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
            "deriveBits",
          ])
        );
        const clientPublicKey = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
        const answer = await world.network.post(
          UNLOCK_URL,
          {
            ...requestFor(await world.render("A")),
            clientPublicKey,
          },
          { origin: PUBLISHER_ORIGIN },
        );

        assert.deepEqual(answer, { status: 500, body: expectedBody });
        assert.deepEqual(refused, [{ status: 500, code: "internal_error" }]);
        assert.equal(applies, 0, "the endpoint policy data is not applied after a delivery fault");
        assert.deepEqual(world.servers.primary.stats(), {
          requests: 1,
          grants: 0,
          denials: 0,
          refusals: 0,
          faults: 1,
          unsealFailures: 0,
          probes: 0,
          healthReads: 0,
          transportMode: "client-bound",
          role: "primary",
        });
      }
    } finally {
      KeyDelivery.prototype.prepare = originalPrepare;
    }
  });
});

describe("PageLoad", () => {
  test("refuses a legacy or incomplete period-key cache before building its counting wrapper", () => {
    const config = {
      delivery: {},
      clock: {},
      network: {},
      issuers: [],
      breaker: {},
      caller: {},
      resolverFactory: () => {
        throw new Error("a malformed cache must stop before resolver construction");
      },
      requestBuilderFactory: () => {
        throw new Error("a malformed cache must stop before builder construction");
      },
    };
    for (const cache of [
      { put() {}, candidates() {}, attempted() {} },
      { put() {}, candidatesAt() {} },
      { candidatesAt() {}, attempted() {} },
    ]) {
      assert.throws(
        () => new PageLoad({ ...config, cache }),
        (/** @type {any} */ error) =>
          error.code === "bad_config" && /period-key cache needs/.test(error.message),
      );
    }
  });

  test("the default request builder preserves base bytes and omits optional chain carriers", async () => {
    const world = await actorWorld();
    const page = await world.render("A");
    for (const kind of ["ordinary", "chain-bearing", "client-bound"]) {
      const delivered = page.asJson();
      if (kind === "chain-bearing") {
        issuerBlockOf(delivered).sealed.chainKeys = [
          { accessGroup: ACCESS_GROUP, cutoff: "251023T2300", key: "opaque-chain-carrier" },
        ];
      }
      const capability =
        kind === "client-bound"
          ? {
              publicKey: { kty: "test-only" },
              openDeliveredKeys() {
                throw new Error("the refusal carries no keys");
              },
            }
          : undefined;
      const requests = [];
      const browser = world.makeBrowser({
        ...(capability === undefined ? {} : { clientBoundKeyCapability: capability }),
        network: {
          post: async (_url, request) => {
            requests.push(JSON.stringify(request));
            return { status: 403, body: {} };
          },
        },
      });
      const load = browser.load(
        rootFromPage({
          publisherOrigin: page.publisherOrigin,
          asJson: () => delivered,
        }),
      );
      // The expectation is read off the delivered page, not built with the
      // builder under test: a builder that drops a member, forwards a chain
      // carrier or rewrites a blob disagrees with the bytes the publisher put
      // in the markup.
      const block = issuerBlockOf(delivered);
      const expected = {
        version: delivered.version,
        issuerName: ISSUER_NAME,
        resourceJWT: delivered.resourceJWT,
        keyId: block.keyId,
        sealed: {
          contentKeys: block.sealed.contentKeys.filter(
            (/** @type {any} */ record) => record.contentName === CONTENT_NAME,
          ),
          periodKeys: block.sealed.periodKeys,
        },
        ...(capability === undefined ? {} : { clientPublicKey: capability.publicKey }),
      };

      await load.unlock({ issuerName: ISSUER_NAME });

      assert.equal(requests.length, 1, kind);
      const sent = JSON.parse(requests[0]);
      if (kind === "chain-bearing") {
        assert.equal(Object.hasOwn(sent.sealed, "chainKeys"), false);
        assert.equal(Object.hasOwn(sent, "periodGeometry"), false);
      }
      assert.equal(Object.hasOwn(sent, "clientPublicKey"), capability !== undefined);
      assert.deepEqual(sent, expected, kind);
    }
  });

  test("an unsolicited response error cannot steer the issuer walk", async () => {
    const world = await actorWorld();
    const page = await world.render("A");
    const browser = world.makeBrowser({
      network: {
        post: async () => ({
          status: 200,
          body: {
            keys: { contentKeys: [] },
            errors: [
              { coordinate: "bodytext", error: "key_retired" },
              { coordinate: "ghost", error: "invented_availability_error" },
            ],
          },
        }),
      },
    });
    const result = await browser.load(rootFromPage(page)).unlock({ issuerName: ISSUER_NAME });

    assert.equal(result.ok, false);
    assert.equal(result.attempts[0].outcome, "key_retired+unsolicited_coordinate");
    assert.ok(
      result.attempts.every(({ outcome }) => !outcome.includes("invented_availability_error")),
    );
  });

  test("Browser selects one request builder per load independently of the resolver and chain cache", async () => {
    const world = await actorWorld();
    const page = await world.render("A");
    for (const capability of [
      undefined,
      {
        publicKey: { kty: "test-only" },
        openDeliveredKeys() {
          throw new Error("the direct answer must not use the capability");
        },
      },
    ]) {
      const factoryOptions = [];
      const builders = [];
      const built = [];
      const sent = [];
      const browser = world.makeBrowser({
        issuers: world.routes.map(({ issuerName, unlockUrl }) => ({
          issuerName,
          unlockUrl,
          acceptDirectResponse: true,
        })),
        ...(capability === undefined ? {} : { clientBoundKeyCapability: capability }),
        ...(capability === undefined ? {} : { acceptDirectFallback: true }),
        requestBuilderFactory(options) {
          factoryOptions.push(options);
          const real = new DcaRequestBuilder(options);
          const builder = {
            build(...args) {
              const request = real.build(...args);
              built.push(JSON.stringify(request.toObject()));
              return request;
            },
          };
          builders.push(builder);
          return builder;
        },
        network: {
          post: async (...args) => {
            sent.push(JSON.stringify(args[1]));
            return world.network.post(...args);
          },
        },
      });
      const load = browser.load(rootFromPage(page));
      assert.deepEqual(factoryOptions, [
        capability === undefined
          ? { relayPeriodKeys: true }
          : { relayPeriodKeys: true, clientPublicKey: capability.publicKey },
      ]);
      if (capability !== undefined)
        assert.equal(factoryOptions[0].clientPublicKey, capability.publicKey);
      assert.deepEqual(await load.resolve([CONTENT_NAME]), {
        covered: [],
        missing: [CONTENT_NAME],
      });
      assert.equal((await load.unlock({ issuerName: ISSUER_NAME })).ok, true);
      assert.equal(utf8Decode((await load.open(CONTENT_NAME)).bytes), ARTICLES.A);
      assert.equal(built.length, 1, "unlock uses the returned builder");
      assert.deepEqual(sent, built, "the selected builder supplies exactly the posted request");
      assert.equal(factoryOptions.length, 1, "resolve, unlock, and open reuse the builder");
      browser.load(rootFromPage(page));
      assert.equal(factoryOptions.length, 2);
      assert.notEqual(builders[0], builders[1], "each load receives its own builder");
    }
  });

  test("invalid request-builder factories and results fail before protocol work", async () => {
    const world = await actorWorld();
    const page = await world.render("A");
    assert.throws(
      () => world.makeBrowser({ requestBuilderFactory: {} }),
      (error) => error.code === "bad_config",
    );
    for (const result of [null, {}, { build: 42 }]) {
      const browser = world.makeBrowser({ requestBuilderFactory: () => result });
      assert.throws(
        () => browser.load(rootFromPage(page)),
        (error) => error.code === "bad_config",
      );
    }
    assert.equal(
      Object.keys(world.network.stats()).length,
      0,
      "no invalid composition reaches the network",
    );
  });

  test("carried aad and type edits preserve opening; unsupported encodings stay refused", async () => {
    const world = await actorWorld();
    const page = await world.render("A");

    for (const [label, mangle, expected] of [
      [
        "former string aad",
        (/** @type {any} */ record) => (record.aad = "123456|1|bodytext"),
        null,
      ],
      ["numeric aad", (/** @type {any} */ record) => (record.aad = 42), null],
      ["object aad", (/** @type {any} */ record) => (record.aad = { bytes: "AA" }), null],
      ["unpaired-surrogate aad", (/** @type {any} */ record) => (record.aad = "x\ud800"), null],
      [
        "changed contentType",
        (/** @type {any} */ record) => (record.contentType = "text/plain"),
        null,
      ],
      [
        "added contentEncodings",
        (/** @type {any} */ record) => (record.contentEncodings = ["identity"]),
        "unsupported_encoding",
      ],
    ]) {
      const delivered = page.asJson();
      mangle(contentRecordOf(delivered));
      const browser = world.makeBrowser();
      const load = browser.load(
        rootFromPage({
          publisherOrigin: page.publisherOrigin,
          asJson: () => delivered,
        }),
      );

      assert.equal(
        (await load.unlock({ issuerName: ISSUER_NAME })).ok,
        true,
        `${label}: the key still arrives`,
      );
      const opened = await load.open(CONTENT_NAME);
      assert.equal(opened.error, expected, label);
      assert.equal(opened.bytes === null, expected !== null, label);
    }
  });

  test("Browser selects one resolver per load and that resolver drives the client flow", async () => {
    const world = await actorWorld();
    const page = await world.render("A");
    const chainKeyProfile = {
      // The bundle names the construction it was composed on. This one is
      // a double, so the record is written here rather than taken from
      // the extension these actor tests do not import.
      constructionProfile: {
        name: "dca-profile-chain-keys",
        constructionId: "dca-construction-chain-keys",
        chainKeyBytes: 16,
        periodKeyProfile: periodKeyProfile(PERIOD_KEY_PROFILE),
      },
      parametersForResponse: () => null,
      acceptsPeriodKeyResponseCoordinate: () => true,
      acceptsResponseCoordinate: () => true,
      candidateSourceFor: () => ({ async *attempts() {} }),
    };
    const chainCache = {
      put: async () => undefined,
      putPeriodKey: async () => undefined,
      candidates: async () => [],
    };
    const clientBoundKeyCapability = {
      publicKey: { kty: "test-only" },
      assertCanOpenChainKeys() {},
      openDeliveredKeys: () => {
        throw new Error("the direct answer must not use the capability");
      },
    };
    /** @type {object[]} */
    const factoryOptions = [];
    /** @type {{ resolveDetailed: number, applyResponse: number, resolveAuthenticated: number }[]} */
    const resolverCalls = [];
    const builderOptions = [];

    const browser = world.makeBrowser({
      issuers: world.routes.map(({ issuerName, unlockUrl }) => ({
        issuerName,
        unlockUrl,
        acceptDirectResponse: true,
      })),
      chainKeyProfile,
      chainKeyCacheFactory: () => chainCache,
      clientBoundKeyCapability,
      acceptDirectFallback: true,
      requestBuilderFactory(options) {
        builderOptions.push(options);
        return new DcaRequestBuilder(options);
      },
      resolverFactory(options) {
        factoryOptions.push(options);
        const real = new ContentKeyResolver(options);
        const calls = { resolveDetailed: 0, applyResponse: 0, resolveAuthenticated: 0 };
        resolverCalls.push(calls);
        return {
          async resolveDetailed(...args) {
            calls.resolveDetailed++;
            return real.resolveDetailed(...args);
          },
          async applyResponse(...args) {
            calls.applyResponse++;
            return real.applyResponse(...args);
          },
          async resolveAuthenticated(...args) {
            calls.resolveAuthenticated++;
            return real.resolveAuthenticated(...args);
          },
          async contentKeyWithOriginFor(...args) {
            return real.contentKeyWithOriginFor(...args);
          },
        };
      },
    });

    const load = browser.load(rootFromPage(page));
    assert.equal(factoryOptions.length, 1, "the factory runs once when this load is built");
    assert.deepEqual(
      Object.keys(factoryOptions[0]).sort(),
      [
        "acceptDirectFallback",
        "cache",
        "chainCache",
        "chainKeyProfile",
        "clientBoundKeyCapability",
      ],
      "the selected resolver receives exactly the existing composition inputs",
    );
    assert.equal(factoryOptions[0].chainKeyProfile, chainKeyProfile);
    assert.equal(factoryOptions[0].clientBoundKeyCapability, clientBoundKeyCapability);
    assert.notEqual(
      factoryOptions[0].cache,
      browser.cache,
      "PageLoad retains its counting cache proxy",
    );
    assert.notEqual(
      factoryOptions[0].chainCache,
      chainCache,
      "PageLoad retains its counting chain-cache proxy",
    );
    assert.deepEqual(
      builderOptions,
      [{ relayPeriodKeys: true, clientPublicKey: clientBoundKeyCapability.publicKey }],
      "the independent builder receives only the public key, once, beside the full resolver composition",
    );
    assert.equal(builderOptions[0].clientPublicKey, clientBoundKeyCapability.publicKey);

    assert.deepEqual(await load.resolve([CONTENT_NAME]), { covered: [], missing: [CONTENT_NAME] });
    assert.equal((await load.unlock()).ok, true);
    const opened = await load.open(CONTENT_NAME);
    assert.equal(utf8Decode(/** @type {Uint8Array} */ (opened.bytes)), ARTICLES.A);
    assert.deepEqual(resolverCalls[0], {
      resolveDetailed: 2,
      applyResponse: 1,
      resolveAuthenticated: 1,
    });
    assert.equal(
      load.stats().trials,
      2,
      "the initial resolve reads its two authored coordinates; held content keys are not trials",
    );
    assert.equal(factoryOptions.length, 1, "resolve, apply, and open reuse this load's resolver");
    assert.equal(
      builderOptions.length,
      1,
      "the same operations reuse this load's independently selected builder",
    );

    browser.load(rootFromPage(page));
    assert.equal(factoryOptions.length, 2, "a second load receives a new resolver");
    assert.equal(builderOptions.length, 2, "a second load also creates its own builder");
    assert.notEqual(
      factoryOptions[1].cache,
      factoryOptions[0].cache,
      "each load owns its counting proxy",
    );
  });

  test("invalid resolver factories and resolver surfaces are typed configuration failures", async () => {
    const world = await actorWorld();
    const page = await world.render("A");

    assert.throws(
      () => world.makeBrowser({ resolverFactory: /** @type {any} */ ({}) }),
      (/** @type {any} */ error) =>
        error.code === "bad_config" && /resolverFactory/.test(error.message),
    );

    for (const missing of [
      "applyResponse",
      "resolveDetailed",
      "contentKeyWithOriginFor",
      "resolveAuthenticated",
    ]) {
      const methods = {
        applyResponse() {},
        resolveDetailed() {},
        contentKeyWithOriginFor() {},
        resolveAuthenticated() {},
      };
      delete methods[missing];
      const browser = world.makeBrowser({ resolverFactory: () => methods });
      assert.throws(
        () => browser.load(rootFromPage(page)),
        (/** @type {any} */ error) =>
          error.code === "bad_config" && error.message.includes(missing),
        `a resolver without ${missing} is refused`,
      );
    }
    assert.equal(
      Object.keys(world.network.stats()).length,
      0,
      "no invalid composition reaches the protocol",
    );
  });

  test("stats() hands back a snapshot: mutating resolved does not reach a later report", async () => {
    const world = await actorWorld({});
    const read = await readArticle(world.makeBrowser(), await world.render("A"), [CONTENT_NAME], {
      issuerName: ISSUER_NAME,
    });

    const first = read.load.stats().resolved;
    assert.deepEqual(
      first.missing,
      [CONTENT_NAME],
      "the one name resolved to a miss before the unlock",
    );
    first.missing.push("smuggled");
    first.covered.push("smuggled");

    const again = read.load.stats().resolved;
    assert.deepEqual(
      again.missing,
      [CONTENT_NAME],
      "a caller mutating the snapshot cannot change a later report",
    );
    assert.deepEqual(again.covered, [], "covered stays what the resolve found");
  });

  test("an unknown item and a declared item with no delivered ciphertext are typed content misses", async () => {
    const world = await actorWorld();
    const page = await world.render("A");
    const browser = world.makeBrowser();

    const unknown = browser.load(rootFromPage(page));
    assert.deepEqual(await unknown.open("not-on-this-page"), {
      bytes: null,
      error: "unknown_content",
    });

    const ordinary = rootFromPage(page);
    const withoutCiphertext = {
      location: ordinary.location,
      querySelectorAll(selector) {
        return selector === SEALED_SELECTOR
          ? [{ tagName: "script", textContent: "[]", getAttribute: () => "application/json" }]
          : ordinary.querySelectorAll(selector);
      },
    };
    const deferred = browser.load(withoutCiphertext);
    assert.deepEqual(await deferred.open(CONTENT_NAME), { bytes: null, error: "unknown_content" });
  });
});

describe("Publisher", () => {
  test("renders a Page a Browser opens", async () => {
    const clock = new Clock(AT);
    const network = new Network({ clock });
    const pair = await issuerKeypair();
    const signing = await signingKeypair();

    const keyStore = new IssuerKeyStore([
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
      },
    ]);

    new IssuerServer({
      clock,
      network,
      issuerName: ISSUER_NAME,
      operatingIssuerNames: [ISSUER_NAME],
      unlockUrl: UNLOCK_URL,
      keyStore,
      publisherRegistrations: new PublisherRegistrations([
        {
          kid: SIGNING_KID,
          publicKey: signing.publicKey,
          origin: PUBLISHER_ORIGIN,
          openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]),
        },
      ]),
      accessPolicy: new AllowAllPolicy(),
    });

    const publisher = new Publisher({
      origin: PUBLISHER_ORIGIN,
      clock,
      random: new Random({ seed: 1 }),
      signingKeys: { [SIGNING_KID]: signing.privateKey },
      signingKid: SIGNING_KID,
      periodKeySupply: randomPeriodKeySupply(),
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: ALGORITHM,
          publicKey: keyStore.publicKey(ISSUER_NAME, KEY_ID),
        },
      ],
    });

    const browser = new Browser({
      clock,
      network,
      storage: new Storage(),
      issuers: [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL }],
    });

    const load = browser.load(rootFromPage(await publisher.render(article("A"))));
    await load.resolve([CONTENT_NAME]);
    const unlock = await load.unlock();
    const { bytes } = await load.open(CONTENT_NAME);

    assert.equal(unlock.ok, true);
    assert.equal(utf8Decode(/** @type {Uint8Array} */ (bytes)), ARTICLES.A);
    assert.equal(publisher.stats().renders, 1);
    assert.ok(
      keyStore.privateKeyReached,
      "the issuer opened the blobs, so it went to its own store for the key",
    );

    // A second render is a second page, off the same configuration.
    const second = await publisher.render(article("B"));
    assert.notDeepEqual(second.asJson().resource.renderId, undefined);
    assert.equal(publisher.stats().renders, 2);
  });

  test("validates and carries its origin profile before the first render", async () => {
    const signing = await signingKeypair();
    const issuer = await issuerKeypair();
    const base = {
      clock: new Clock(AT),
      random: new Random({ seed: 1 }),
      signingKeys: { [SIGNING_KID]: signing.privateKey },
      signingKid: SIGNING_KID,
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: ALGORITHM,
          publicKey: issuer.publicKey,
        },
      ],
    };

    for (const config of [
      { origin: "http://publisher.example" },
      { origin: "http://publisher.example", developmentHttpOrigin: true },
      { origin: "http://localhost:8080" },
    ]) {
      assert.throws(
        () => new Publisher({ ...base, ...config }),
        (/** @type {any} */ error) => error.code === "bad_config" && /origin/.test(error.message),
      );
    }
    assert.throws(
      () =>
        new Publisher(
          /** @type {any} */ ({ ...base, origin: PUBLISHER_ORIGIN, developmentHttpOrigin: "yes" }),
        ),
      (/** @type {any} */ error) => error.code === "bad_config" && /profile/.test(error.message),
    );

    const development = new Publisher({
      ...base,
      origin: "http://localhost:8080",
      developmentHttpOrigin: true,
    });
    // The base config holds no period-key supply, so the render is the
    // item-key-only article: a named group would be refused, not wrapped.
    assert.equal(
      (await development.render(ungroupedArticle("A"))).publisherOrigin,
      "http://localhost:8080",
    );
    assert.doesNotThrow(
      () =>
        new Publisher({
          ...base,
          origin: PUBLISHER_ORIGIN,
          developmentHttpOrigin: true,
        }),
    );
  });

  test("seals for the issuers its list held when it was built", async () => {
    const clock = new Clock(AT);
    const signing = await signingKeypair();
    const first = await issuerKeypair();
    const second = await issuerKeypair();

    // The list a world grows: an issuer stood up after the world was made pushes
    // onto this array.
    const issuers = [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        publicKey: first.publicKey,
      },
    ];

    /** @param {number} seed */
    const build = (seed) =>
      new Publisher({
        origin: PUBLISHER_ORIGIN,
        clock,
        random: new Random({ seed }),
        signingKeys: { [SIGNING_KID]: signing.privateKey },
        signingKid: SIGNING_KID,
        periodKeySupply: randomPeriodKeySupply(),
        issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
        issuers,
      });

    const early = build(1);
    issuers.push({
      issuerName: FALLBACK_ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      publicKey: second.publicKey,
    });
    const late = build(2);

    assert.deepEqual(
      early.issuers.map((issuer) => issuer.issuerName),
      [ISSUER_NAME],
      "the copy is taken at construction, so the push never reached this one",
    );
    assert.deepEqual(
      issuerNamesOn((await early.render(article("A"))).asJson()),
      [ISSUER_NAME],
      "and every render it makes is sealed for the issuers it was built with",
    );

    // So `demo/scenarios/world.js` builds its publisher and its browser the
    // first time they are asked for: a caller that stands an issuer up gets one
    // that seals for it, without having to know it was building anything.
    assert.deepEqual(
      issuerNamesOn((await late.render(article("A"))).asJson()),
      [ISSUER_NAME, FALLBACK_ISSUER_NAME],
      "a publisher built after the list grew carries the issuer added to it",
    );
  });

  test("rotateSigningKey moves the kid on the envelope and leaves the other two axes where they were", async () => {
    const { publisher } = await publisherHoldingTwoOfEverything();

    const before = axesOf(await publisher.render(article("A")));
    publisher.rotateSigningKey(KID_NEXT);
    const after = axesOf(await publisher.render(article("B")));

    assert.equal(before.kid, SIGNING_KID);
    assert.equal(after.kid, KID_NEXT, "the render after the rotation is the first one to carry it");
    assert.equal(after.keyId, before.keyId);
    assert.deepEqual(after.periods, before.periods);

    assert.throws(
      () => publisher.rotateSigningKey("sign-2099-01"),
      (/** @type {any} */ error) => error.code === "bad_config",
      "a kid this publisher does not hold is not a rotation",
    );
  });

  test("rotatePeriodKeySupply moves what the cached path opens and leaves the other two axes where they were", async () => {
    const { clock, publisher, periodKeySupply } = await publisherHoldingTwoOfEverything();
    const t = formatT(clock.now());

    const before = await publisher.render(article("A"));
    // Rotating the cached path hands over a distinct period-key registry.
    const rotatedSupply = randomPeriodKeySupply();
    publisher.rotatePeriodKeySupply(rotatedSupply);
    const after = await publisher.render(article("B"));

    const old = await periodKeySupply.derive(ACCESS_GROUP, t);
    const rotated = await rotatedSupply.derive(ACCESS_GROUP, t);

    assert.deepEqual(await coveredWith(before, old, t), [CONTENT_NAME]);
    assert.deepEqual(
      await coveredWith(after, old, t),
      [],
      "the key from before the rotation opens nothing after it",
    );
    assert.deepEqual(
      await coveredWith(after, rotated, t),
      [CONTENT_NAME],
      "the rotated supply opens under its newly assigned period key",
    );

    assert.equal(axesOf(after).kid, axesOf(before).kid);
    assert.equal(axesOf(after).keyId, axesOf(before).keyId);

    assert.throws(
      () => publisher.rotatePeriodKeySupply(/** @type {any} */ ("not-a-supply")),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("rotateIssuerKey moves the keyId the render names and leaves the other two axes where they were", async () => {
    const { keyStore, publisher } = await publisherHoldingTwoOfEverything();

    const before = axesOf(await publisher.render(article("A")));
    publisher.rotateIssuerKey(ISSUER_NAME, KEY_NEXT, keyStore.publicKey(ISSUER_NAME, KEY_NEXT));
    const after = axesOf(await publisher.render(article("B")));

    assert.equal(before.keyId, KEY_ID);
    assert.equal(
      after.keyId,
      KEY_NEXT,
      "the keyId is what the issuer selects on, so it moves with the key",
    );
    assert.equal(after.kid, before.kid);
    assert.deepEqual(after.periods, before.periods);

    assert.throws(
      () =>
        publisher.rotateIssuerKey(
          "not_onboarded",
          KEY_NEXT,
          keyStore.publicKey(ISSUER_NAME, KEY_NEXT),
        ),
      (/** @type {any} */ error) => error.code === "bad_config",
      "a new issuer arrives with an unlockUrl, which this call has none of",
    );
  });

  test("refuses a knob it does not have, and an article that is not one", async () => {
    const { publisher } = await publisherHoldingTwoOfEverything();

    assert.throws(
      () => new Publisher(/** @type {any} */ ({ origin: PUBLISHER_ORIGIN, retries: 3 })),
      (/** @type {any} */ error) => error.code === "unsupported_option",
    );
    assert.throws(
      () => new Publisher(/** @type {any} */ ({ origin: PUBLISHER_ORIGIN })),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    await assert.rejects(
      () => publisher.render(/** @type {any} */ ({ resourceId: "123456" })),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("the Sealer refuses a periodSecret at all - even null - and takes a period-key supply", async () => {
    const signing = await signingKeypair();
    const issuer = await issuerKeypair();
    const base = {
      clock: new Clock(AT),
      random: new Random({ seed: 1 }),
      signingKeys: { [SIGNING_KID]: signing.privateKey },
      signingKid: SIGNING_KID,
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: ALGORITHM,
          publicKey: issuer.publicKey,
        },
      ],
    };

    // Period-key sourcing lives behind the supply. A caller still handing
    // the Sealer a periodSecret is on the old shape, and an explicit null
    // must not fall silently to content-key-only; both are fail-closed refusals.
    for (const periodSecretOption of [periodSecret(), null]) {
      assert.throws(
        () => new Sealer(/** @type {any} */ ({ ...base, periodSecret: periodSecretOption })),
        (/** @type {any} */ error) => error.code === "bad_config",
        `periodSecret: ${periodSecretOption === null ? "null" : "bytes"} is the old shape and is refused`,
      );
    }
  });

  test("refuses a periodSecret handed to the Publisher, since it accepts only a period-key supply", async () => {
    const signing = await signingKeypair();
    const issuer = await issuerKeypair();
    const validConfig = {
      origin: PUBLISHER_ORIGIN,
      clock: new Clock(AT),
      random: new Random({ seed: 1 }),
      signingKeys: { [SIGNING_KID]: signing.privateKey },
      signingKid: SIGNING_KID,
      periodKeySupply: randomPeriodKeySupply(),
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: ALGORITHM,
          publicKey: issuer.publicKey,
        },
      ],
    };

    // The Publisher takes a periodKeySupply, never a bare secret: periodSecret
    // is not on the OPTIONS allowlist, so the option-guard turns it away as a
    // knob the Publisher does not have.
    assert.throws(
      () => new Publisher(/** @type {any} */ ({ ...validConfig, periodSecret: periodSecret() })),
      (/** @type {any} */ error) => error.code === "unsupported_option",
    );
  });
});

test("demo preflight denies canonical origins while the signed-origin POST still opens", async () => {
  const routes = new Map();
  const original = Network.prototype.serveDocument;
  Network.prototype.serveDocument = function (url, handler) {
    routes.set(url, handler);
    return original.call(this, url, handler);
  };
  let world;
  try {
    world = await actorWorld();
  } finally {
    Network.prototype.serveDocument = original;
  }
  const handler = routes.get(UNLOCK_URL);
  assert.ok(handler);
  const preflight = await handler(null, { method: "OPTIONS", origin: `https://${DOMAIN}` });
  assert.equal(preflight.status, 403);
  assert.equal(preflight.headers["access-control-allow-origin"], undefined);
  const read = await readArticle(world.makeBrowser(), await world.render("A"), [CONTENT_NAME]);
  assert.equal(read.unlock.ok, true);
  assert.equal(read.texts[CONTENT_NAME], ARTICLES.A);
});
