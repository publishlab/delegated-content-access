// @ts-check
//
// The ordinary issuer answer, compared against key material derived the other way.
//
// One seeded render, one engine, one policy. What the issuer hands back is
// compared against the publisher's own key material, reached down the other
// path: the period key the seeded supply gave a coordinate, and the content key
// that period key unwraps out of `contentData`. The issuer arrives at both by
// opening the sealed blobs with its own key, so a disagreement is between two
// independent routes to the same bytes rather than between a run and a
// recording. That pins the ordinary work: an item contentKey opened at its
// own name, and the explicitly authorized labels of one access group,
// both under the render the publisher signed.
//
// The rest of this file pins the rules those two loops sit inside: one policy
// call per unlock, no opening key reached by a request that failed
// verification or was denied outright, a partial grant that leaves its granted
// siblings alone, and the three answers a key store can give.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { DcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";
import { sign } from "../../core-shared--publisher-issuer/jwt.js";
import { base64urlDecode, base64urlEncode } from "../../core-shared/codec.js";
import { decrypt } from "../../core-shared/aead.js";
import { dcaError } from "../../core-shared/errors.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
import { Random } from "../../demo/actors/Random.js";
import { Clock } from "../../demo/actors/Clock.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { wrapNonceOf } from "../support/contentKeyWrapNonceOctets.js";
import { recordsByName } from "../../core-shared--client-publisher/deliveryRecords.js";
import {
  contentKeyMap,
  errorMap,
  keyAt,
  notDeliveredMap,
  periodKeyMap,
  setKeyAt,
} from "../support/namedRecords.js";

const { subtle } = globalThis.crypto;

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const ORIGIN = "https://www.news-site.example";
const LOOPBACK_HTTP_ORIGIN = "http://www-default.localhost";
const PUBLIC_HTTP_ORIGIN = "http://publisher.example";
const NONCANONICAL_HTTPS_ORIGIN = "https://www.news-site.example/";
const AT = "2025-10-23T14:20:00Z";
const GROUP = "premium";
const BODY = "bodytext";
const SUMMARY = "summary";

/** The three hourly labels this render stamps, in canonical order. */
const T0 = "251023T1400";
const T1 = "251023T1500";
const T2 = "251023T1600";

/** @param {any} config */
function issuerEngine(config) {
  return new IssuerEngine({ operatingIssuerNames: [ISSUER_NAME], ...config });
}

/**
 * The bytes the publisher sealed, read off the render rather than recorded
 * from a run. The period keys come from the supply the publisher drew them
 * from; each content key comes out of the `contentData` wrap that period key
 * opens, which is the client's route to it. The issuer reaches the same bytes
 * by opening the sealed blobs with its own opening key.
 *
 * @param {any} page
 * @param {{ derive: (accessGroup: string, t: string) => Promise<Uint8Array> }} periodKeySupply
 */
async function keysFromRender(page, periodKeySupply) {
  /** @type {Record<string, string>} */
  const periodKeys = {};
  for (const t of [T0, T1]) {
    periodKeys[t] = base64urlEncode(await periodKeySupply.derive(GROUP, t));
  }

  /** @type {Record<string, string>} */
  const contentKeys = {};
  const openingPeriodKey = await periodKeySupply.derive(GROUP, T0);
  for (const name of [BODY, SUMMARY]) {
    const wrap = recordsByName(page.contentData, "contentName", () => true)
      ?.get(name)
      .keys.find((/** @type {any} */ entry) => entry.accessGroup === GROUP && entry.period === T0);
    contentKeys[name] = base64urlEncode(
      await decrypt(
        openingPeriodKey,
        wrapNonceOf(page, name, GROUP, T0),
        base64urlDecode(wrap.key),
      ),
    );
  }

  return { contentKeys, periodKeys };
}

const TEST_INTERPRETATION = Object.freeze({ profile: "test-only" });

/** @param {any[]} periods */
function represented(periods) {
  return { kind: "test-capability", interpretation: TEST_INTERPRETATION, periods };
}

/**
 * One publisher, one issuer keypair, one seeded render carrying two content
 * names and three periods of one access group.
 */
async function world() {
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const periodKeySupply = randomPeriodKeySupply({ random: new Random({ seed: 7 }) });

  const sealer = new Sealer({
    origin: ORIGIN,
    clock: new Clock(AT),
    random: new Random({ seed: 11 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply,
    period: { length: 60, slots: 3 },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(BODY, "<p>The council voted 7-2 to rezone the harbour.</p>", "text/html", {
    accessGroups: [GROUP],
  });
  sealer.content(SUMMARY, "<p>Seven votes to two.</p>", "text/html", { accessGroups: [GROUP] });
  const rendered = await sealer.seal();
  const page = JSON.parse(
    JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
  );

  /** Every lookup this store answered, so an untouched key is an assertion. */
  /** @type {string[]} */
  const asked = [];
  const keyStore = {
    /** @param {string} issuerName @param {string} keyId */
    get(issuerName, keyId) {
      asked.push(`${issuerName} ${keyId}`);
      if (issuerName !== ISSUER_NAME || keyId !== KEY_ID) return undefined;
      return { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey };
    },
  };

  const registration = {
    kid: SIGNING_KID,
    publicKey: signingKeys.publicKey,
    origins: [ORIGIN],
    openingKeys: keyStore,
  };

  const client = new Client({ publisherOrigin: ORIGIN });
  /** @param {string[]} needed */
  const requestFor = (needed) => client.buildRequest(client.parse(page), ISSUER_NAME, needed);

  return {
    page,
    registration,
    asked,
    requestFor,
    periodKeySupply,
    publisherKeys: await keysFromRender(page, periodKeySupply),
    signingPrivateKey: signingKeys.privateKey,
  };
}

/**
 * A policy answering a fixed decision, counting how often it was asked.
 *
 * @param {(requested: { contentNames: string[], accessGroups: string[], periodCoordinates: Record<string, string[]> }) => any} answer
 */
function policyAnswering(answer) {
  return {
    calls: 0,
    /**
     * @param {any} claims
     * @param {{ contentNames: string[], accessGroups: string[] }} requested
     */
    decide(claims, requested) {
      void claims;
      this.calls++;
      return answer(requested);
    },
  };
}

/** Grants every presented name and every explicitly presented period label. */
const generousPolicy = () =>
  policyAnswering((requested) => ({
    contentNames: [...requested.contentNames],
    periodGrants: requested.accessGroups.map((accessGroup) => ({
      accessGroup,
      periods: [...(requested.periodCoordinates[accessGroup] ?? [])].slice(0, 2),
    })),
    policyData: { seat: "A-14" },
  }));

describe("the ordinary issuer answer", () => {
  test(
    "a content-key grant and explicit period labels open to the bytes the publisher sealed",
    { tags: ["dca-profile-baseline/issuer/direct-result"] },
    async () => {
      const { registration, requestFor, publisherKeys } = await world();
      const policy = generousPolicy();
      const engine = issuerEngine({ accessPolicy: policy });
      const result = await engine.unlock(
        new DcaRequest(requestFor([BODY, SUMMARY])),
        registration,
        { principal: null },
      );

      assert.deepEqual(contentKeyMap(result.contentKeys), {
        [BODY]: publisherKeys.contentKeys[BODY],
        [SUMMARY]: publisherKeys.contentKeys[SUMMARY],
      });
      assert.deepEqual(periodKeyMap(result.periodKeys), { [GROUP]: publisherKeys.periodKeys });
      assert.deepEqual(errorMap(result.errors), {});
      assert.deepEqual(result.policyData, { seat: "A-14" });
    },
  );

  test("an explicit label absent from this request does not move to another period", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const policy = policyAnswering(() => ({
      contentNames: [BODY],
      periodGrants: [{ accessGroup: GROUP, periods: [T0] }],
    }));
    const engine = issuerEngine({ accessPolicy: policy });
    const document = requestFor([BODY]);
    document.sealed.periodKeys = document.sealed.periodKeys.filter(
      (/** @type {any} */ record) => record.accessGroup !== GROUP || record.period === T1,
    );

    const result = await engine.unlock(new DcaRequest(document), registration);

    assert.deepEqual(
      periodKeyMap(result.periodKeys),
      {},
      "T0 permission does not transfer to presented T1",
    );
    assert.deepEqual(contentKeyMap(result.contentKeys), {
      [BODY]: publisherKeys.contentKeys[BODY],
    });
  });

  test("the core-only content-key request opens only its named item", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const document = requestFor([BODY]);
    delete document.sealed.periodKeys;
    delete document.sealed.chainKeys;
    const engine = issuerEngine({
      accessPolicy: policyAnswering((requested) => ({
        contentNames: [...requested.contentNames],
        periodGrants: [],
      })),
    });

    const result = await engine.unlock(new DcaRequest(document), registration);

    assert.deepEqual(contentKeyMap(result.contentKeys), {
      [BODY]: publisherKeys.contentKeys[BODY],
    });
    assert.deepEqual(periodKeyMap(result.periodKeys), {});
    assert.deepEqual(errorMap(result.errors), {});
    assert.deepEqual(result.capabilities, []);
  });

  test("an endpoint rejects an issuer name outside its configured operating scope", async () => {
    const { registration, requestFor, asked } = await world();
    const policy = policyAnswering(() => {
      throw new Error("out-of-scope issuer names never reach policy");
    });
    const engine = issuerEngine({ accessPolicy: policy });
    const document = requestFor([BODY]);
    document.issuerName = "another_issuer_service";

    await assert.rejects(
      engine.unlock(new DcaRequest(document), registration),
      (/** @type {any} */ error) => error.code === "out_of_scope_issuer",
    );
    assert.equal(policy.calls, 0);
    assert.deepEqual(asked, [], "scope refusal precedes registration opening-key lookup");
  });

  test("a presented period outside the explicit grant is never opened", async () => {
    const { registration, requestFor } = await world();
    const engine = issuerEngine({ accessPolicy: generousPolicy() });

    const document = requestFor([BODY]);
    assert.deepEqual(Object.keys(periodKeyMap(document.sealed.periodKeys)[GROUP]).sort(), [
      T0,
      T1,
      T2,
    ]);

    const result = await engine.unlock(new DcaRequest(document), registration);
    assert.deepEqual(Object.keys(periodKeyMap(result.periodKeys)[GROUP]).sort(), [T0, T1]);
  });

  test("the access policy is asked once for the whole unlock", async () => {
    const { registration, requestFor } = await world();
    const policy = generousPolicy();
    const engine = issuerEngine({ accessPolicy: policy });

    await engine.unlock(new DcaRequest(requestFor([BODY, SUMMARY])), registration);
    assert.equal(policy.calls, 1);
  });

  test(
    "a partial grant answers its granted siblings and withholds the rest",
    { tags: ["dca-profile-baseline/issuer/direct-result"] },
    async () => {
      const { registration, requestFor, publisherKeys } = await world();
      const engine = issuerEngine({
        accessPolicy: policyAnswering(() => ({ contentNames: [BODY] })),
      });

      const result = await engine.unlock(new DcaRequest(requestFor([BODY, SUMMARY])), registration);
      assert.deepEqual(contentKeyMap(result.contentKeys), {
        [BODY]: publisherKeys.contentKeys[BODY],
      });
      assert.deepEqual(periodKeyMap(result.periodKeys), {});
      assert.deepEqual(errorMap(result.errors), {});
    },
  );

  test("a granted coordinate that will not open leaves its granted sibling intact", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const engine = issuerEngine({ accessPolicy: generousPolicy() });

    // The same genuine blob, presented at the other name. It was sealed
    // committed to `summary`, so rebuilding the binding at `bodytext` fails
    // to open it and reports one error beside the keys that did work.
    const document = requestFor([BODY, SUMMARY]);
    setKeyAt(
      document.sealed.contentKeys,
      { contentName: SUMMARY },
      keyAt(document.sealed.contentKeys, { contentName: BODY }),
    );

    const result = await engine.unlock(new DcaRequest(document), registration);
    assert.deepEqual(Object.keys(contentKeyMap(result.contentKeys)), [BODY]);
    assert.deepEqual(errorMap(result.errors), {
      [SUMMARY]: { error: "unseal_failed", message: "sealed value could not be opened" },
    });
    assert.deepEqual(periodKeyMap(result.periodKeys), { [GROUP]: publisherKeys.periodKeys });
  });
});

describe("what a refused unlock never reaches", () => {
  test("a complete denial is refused before any opening key is looked up", async () => {
    const { registration, requestFor, asked } = await world();
    const engine = issuerEngine({ accessPolicy: policyAnswering(() => ({})) });

    await assert.rejects(
      () => engine.unlock(new DcaRequest(requestFor([BODY])), registration),
      /** @param {any} error */ (error) => error.code === "denied",
    );
    assert.deepEqual(asked, [], "a denied request costs this issuer no key lookup");
  });

  test("a partial grant never opens the envelope of the name it denied", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const engine = issuerEngine({
      accessPolicy: policyAnswering(() => ({ contentNames: [BODY] })),
    });

    // An issuer that opened the denied envelope and then dropped its answer
    // returns the same document as one that never opened it, so this test
    // watches the opening itself. To open a blob the engine reads it out of
    // the request and then reads the private key, and both reads land in one
    // log in the order they happen.
    /** @type {string[]} */
    const events = [];
    const document = requestFor([BODY, SUMMARY]);
    // Each record logs the read of its envelope, not of its name: the engine
    // reads every name to know what was presented.
    document.sealed.contentKeys = document.sealed.contentKeys.map(
      (/** @type {any} */ record) =>
        new Proxy(record, {
          get(target, name, receiver) {
            if (name === "key") events.push(`sealed ${target.contentName}`);
            return Reflect.get(target, name, receiver);
          },
        }),
    );
    const store = registration.openingKeys;
    const watched = {
      ...registration,
      openingKeys: {
        /** @param {string} issuerName @param {string} keyId */
        get(issuerName, keyId) {
          const entry = store.get(issuerName, keyId);
          if (!entry) return entry;
          return {
            algorithm: entry.algorithm,
            get privateKey() {
              events.push("opening key");
              return entry.privateKey;
            },
          };
        },
      },
    };

    const result = await engine.unlock(new DcaRequest(document), watched);

    assert.deepEqual(contentKeyMap(result.contentKeys), {
      [BODY]: publisherKeys.contentKeys[BODY],
    });
    assert.deepEqual(errorMap(result.errors), {});
    assert.deepEqual(
      events,
      [`sealed ${BODY}`, "opening key"],
      "the granted blob is opened once, and the denied blob is never read or opened",
    );
  });

  test("a request whose signature does not verify reaches no opening key", async () => {
    const { registration, requestFor, asked } = await world();
    const policy = generousPolicy();
    const engine = issuerEngine({ accessPolicy: policy });

    const document = requestFor([BODY]);
    // The first character of the signature carries six significant bits, so
    // changing it changes the signature bytes whatever the keys were.
    const [header, payload, signature] = document.resourceJWT.split(".");
    const flipped = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
    document.resourceJWT = `${header}.${payload}.${flipped}`;

    await assert.rejects(
      () => engine.unlock(new DcaRequest(document), registration),
      /** @param {any} error */ (error) => error.code === "bad_signature",
    );
    assert.equal(policy.calls, 0, "an unverified request has no claims to decide on");
    assert.deepEqual(asked, []);
  });
});

describe("the issuer engine origin profile", () => {
  test("admits signed loopback http only under its explicit development profile", async () => {
    const production = await world();
    const productionPolicy = generousPolicy();
    const productionEngine = issuerEngine({ accessPolicy: productionPolicy });
    const signedForLoopback = await sign(
      { ...production.page.resource, origin: LOOPBACK_HTTP_ORIGIN },
      production.signingPrivateKey,
      { kid: SIGNING_KID },
    );
    const productionDocument = production.requestFor([BODY]);
    productionDocument.resourceJWT = signedForLoopback;

    await assert.rejects(
      () => productionEngine.unlock(new DcaRequest(productionDocument), production.registration),
      /** @param {any} error */ (error) => error.code === "bad_jwt",
    );
    assert.equal(productionPolicy.calls, 0, "the production profile refuses before policy");
    assert.deepEqual(production.asked, [], "the production profile refuses before key lookup");

    const development = await world();
    const developmentPolicy = generousPolicy();
    const developmentEngine = issuerEngine({
      accessPolicy: developmentPolicy,
      developmentHttpOrigin: true,
    });
    const developmentDocument = development.requestFor([BODY]);
    developmentDocument.resourceJWT = await sign(
      { ...development.page.resource, origin: LOOPBACK_HTTP_ORIGIN },
      development.signingPrivateKey,
      { kid: SIGNING_KID },
    );

    const opened = await developmentEngine.unlock(
      new DcaRequest(developmentDocument),
      development.registration,
    );
    assert.equal(
      contentKeyMap(opened.contentKeys)[BODY],
      development.publisherKeys.contentKeys[BODY],
      "the explicit opt-in is the positive control",
    );
    assert.equal(developmentPolicy.calls, 1);
    assert.deepEqual(development.asked, [`${ISSUER_NAME} ${KEY_ID}`]);

    for (const origin of [PUBLIC_HTTP_ORIGIN, NONCANONICAL_HTTPS_ORIGIN]) {
      const refused = await world();
      const policy = generousPolicy();
      const engine = issuerEngine({ accessPolicy: policy, developmentHttpOrigin: true });
      const document = refused.requestFor([BODY]);
      document.resourceJWT = await sign(
        { ...refused.page.resource, origin },
        refused.signingPrivateKey,
        {
          kid: SIGNING_KID,
        },
      );

      await assert.rejects(
        () => engine.unlock(new DcaRequest(document), refused.registration),
        /** @param {any} error */ (error) => error.code === "bad_jwt",
      );
      assert.equal(policy.calls, 0, `${origin} is refused before policy`);
      assert.deepEqual(refused.asked, [], `${origin} is refused before key lookup`);
    }
  });
});

describe("issuer engine constructor shapes", () => {
  test("rejects malformed profiles and sources while accepting their valid shapes", () => {
    const accessPolicy = generousPolicy();

    for (const config of [
      { developmentHttpOrigin: "yes" },
      { contentKeySource: {} },
      { contentKeyScope: {} },
      { periodCapabilitySource: { selection: () => () => ({ miss: true }) } },
    ]) {
      assert.throws(
        () => issuerEngine({ accessPolicy, ...config }),
        /** @param {any} error */ (error) => error.code === "bad_config",
      );
    }

    assert.doesNotThrow(() =>
      issuerEngine({
        supportedVersions: ["1"],
        accessPolicy,
        developmentHttpOrigin: true,
        contentKeySource: { contentKeys: () => async () => ({ miss: true }) },
        contentKeyScope: () => null,
        periodCapabilitySource: {
          selection: () => () => ({ miss: true }),
          capabilities: () => async () => represented([{ t: T0, bytes: new Uint8Array(16) }]),
        },
      }),
    );

    assert.throws(
      () => issuerEngine({ accessPolicy, clock: { now: () => new Date() } }),
      /** @param {any} error */ (error) =>
        error.code === "unsupported_option" &&
        error.message === "IssuerEngine has no clock yet, and will not pretend to",
    );
  });
});

test("a content-key source receives only the host-selected opaque scope", async () => {
  const { registration, requestFor, publisherKeys } = await world();
  const document = requestFor([BODY, SUMMARY]);
  const [bodySeal, summarySeal] = [BODY, SUMMARY].map((contentName) =>
    keyAt(document.sealed.contentKeys, { contentName }),
  );
  setKeyAt(document.sealed.contentKeys, { contentName: BODY }, summarySeal);
  setKeyAt(document.sealed.contentKeys, { contentName: SUMMARY }, bodySeal);
  const scope = Object.freeze({ periodKey: "selected-outside-the-request" });
  let selections = 0;
  let lookups = 0;
  /** @type {any} */
  let received;
  const engine = issuerEngine({
    accessPolicy: generousPolicy(),
    contentKeyScope(selectedRegistration) {
      selections += 1;
      assert.strictEqual(selectedRegistration, registration);
      return scope;
    },
    contentKeySource: {
      contentKeys(unlock) {
        received = unlock;
        return async (contentName) => {
          lookups++;
          return { bytes: base64urlDecode(publisherKeys.contentKeys[contentName]) };
        };
      },
    },
  });

  const result = await engine.unlock(new DcaRequest(document), registration);

  assert.equal(
    selections,
    1,
    "the authenticated registration selects one scope per needed fallback",
  );
  assert.strictEqual(received.scope, scope);
  assert.equal(Object.hasOwn(received, "registration"), false);
  assert.equal(Object.hasOwn(received, "openingKeys"), false);
  assert.equal(lookups, 2, "each failed ordinary seal asks the one constructed source lookup");
  assert.deepEqual(contentKeyMap(result.contentKeys), publisherKeys.contentKeys);
});

test("an unused content-key fallback cannot spoil an ordinary open", async () => {
  const { registration, requestFor, publisherKeys } = await world();
  let selections = 0;
  let factories = 0;
  const engine = issuerEngine({
    accessPolicy: generousPolicy(),
    contentKeyScope() {
      selections++;
      throw new Error("ordinary opens do not need a content-key scope");
    },
    contentKeySource: {
      contentKeys() {
        factories++;
        throw new Error("ordinary opens do not need a source lookup");
      },
    },
  });

  const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);

  assert.deepEqual(contentKeyMap(result.contentKeys), { [BODY]: publisherKeys.contentKeys[BODY] });
  assert.equal(selections, 0);
  assert.equal(factories, 0);
});

test("a retired opening key does not initialize a content-key fallback", async () => {
  const { registration, requestFor } = await world();
  const document = requestFor([BODY]);
  setKeyAt(
    document.sealed.contentKeys,
    { contentName: BODY },
    keyAt(document.sealed.contentKeys, { contentName: SUMMARY }),
  );
  let selections = 0;
  let factories = 0;
  const engine = issuerEngine({
    accessPolicy: generousPolicy(),
    contentKeyScope() {
      selections++;
      return null;
    },
    contentKeySource: {
      contentKeys() {
        factories++;
        return async () => ({ miss: true });
      },
    },
  });

  const result = await engine.unlock(new DcaRequest(document), {
    ...registration,
    openingKeys: { get: () => ({ retired: true }) },
  });

  assert.equal(errorMap(result.errors)[BODY].error, "key_retired");
  assert.equal(selections, 0);
  assert.equal(factories, 0);
});

test("a content source can open only its final granted content names", async () => {
  const { registration, requestFor, publisherKeys } = await world();
  const document = requestFor([BODY, SUMMARY]);
  const ordinaryBodySeal = keyAt(document.sealed.contentKeys, { contentName: BODY });
  setKeyAt(
    document.sealed.contentKeys,
    { contentName: BODY },
    keyAt(document.sealed.contentKeys, { contentName: SUMMARY }),
  );
  /** @type {import('../../core-issuer/IssuerEngine.js').ContentKeyUnlock|undefined} */
  let received;
  const engine = issuerEngine({
    accessPolicy: policyAnswering(() => ({ contentNames: [BODY] })),
    contentKeySource: {
      contentKeys(unlock) {
        received = unlock;
        return async (contentName) =>
          contentName === BODY
            ? { bytes: base64urlDecode(publisherKeys.contentKeys[BODY]) }
            : { miss: true };
      },
    },
  });
  const result = await engine.unlock(new DcaRequest(document), registration);
  assert.ok(received);
  const { request, open } = received;
  // Both items were presented and policy granted only BODY. The injected
  // source must not open the ungranted sibling, nor use an auxiliary period
  // envelope without naming the granted item it serves.
  await assert.rejects(
    () =>
      open(keyAt(request.sealedContentKeys, { contentName: SUMMARY }), { contentName: SUMMARY }),
    /** @param {any} error */ (error) => error.code === "bad_config",
  );
  await assert.rejects(
    () =>
      open(keyAt(request.sealedPeriodKeys, { accessGroup: GROUP, period: T0 }), {
        accessGroup: GROUP,
        t: T0,
      }),
    /** @param {any} error */ (error) => error.code === "bad_config",
  );
  await assert.rejects(
    () =>
      open(
        keyAt(request.sealedPeriodKeys, { accessGroup: GROUP, period: T0 }),
        { accessGroup: GROUP, t: T0 },
        SUMMARY,
      ),
    /** @param {any} error */ (error) => error.code === "bad_config",
  );
  await assert.rejects(
    () =>
      open(
        keyAt(request.sealedContentKeys, { contentName: SUMMARY }),
        { contentName: SUMMARY },
        BODY,
      ),
    /** @param {any} error */ (error) => error.code === "bad_config",
  );
  await assert.rejects(
    () =>
      open(
        keyAt(request.sealedPeriodKeys, { accessGroup: GROUP, period: T0 }),
        /** @type {any} */ ({ contentName: SUMMARY, accessGroup: GROUP, t: T0 }),
        BODY,
      ),
    /** @param {any} error */ (error) => error.code === "bad_config",
  );
  const auxiliary = await open(
    keyAt(request.sealedPeriodKeys, { accessGroup: GROUP, period: T0 }),
    { accessGroup: GROUP, t: T0 },
    BODY,
  );
  assert.ok("bytes" in auxiliary);
  assert.equal(base64urlEncode(auxiliary.bytes), publisherKeys.periodKeys[T0]);
  const allowed = await open(ordinaryBodySeal, { contentName: BODY });
  assert.ok("bytes" in allowed);
  assert.equal(base64urlEncode(allowed.bytes), publisherKeys.contentKeys[BODY]);
  const explicitlyAllowed = await open(ordinaryBodySeal, { contentName: BODY }, BODY);
  assert.ok("bytes" in explicitlyAllowed);
  assert.equal(base64urlEncode(explicitlyAllowed.bytes), publisherKeys.contentKeys[BODY]);

  // An item coordinate cannot also carry any auxiliary binding field. Use a
  // granted, matching name so another refusal cannot mask the mixed coordinate.
  for (const [field, value] of Object.entries({
    accessGroup: GROUP,
    t: T0,
    suppliedT: T0,
    chainKey: true,
    chainsPerDay: 1,
    periodMinutes: 60,
  })) {
    await assert.rejects(
      () => open(ordinaryBodySeal, { contentName: BODY, [field]: value }, BODY),
      /** @param {any} error */ (error) => error.code === "bad_config",
      field,
    );
  }
  await assert.rejects(
    () => open(ordinaryBodySeal, { contentName: BODY }, SUMMARY),
    /** @param {any} error */ (error) => error.code === "bad_config",
  );
  for (const name of [1, null, {}, undefined]) {
    await assert.rejects(
      () => open(ordinaryBodySeal, /** @type {any} */ ({ contentName: name })),
      /** @param {any} error */ (error) => error.code === "bad_config",
    );
    await assert.rejects(
      () =>
        open(
          keyAt(request.sealedPeriodKeys, { accessGroup: GROUP, period: T0 }),
          { accessGroup: GROUP, t: T0 },
          /** @type {any} */ (name),
        ),
      /** @param {any} error */ (error) => error.code === "bad_config",
    );
  }
  assert.deepEqual(contentKeyMap(result.contentKeys), { [BODY]: publisherKeys.contentKeys[BODY] });
});

for (const answerKind of ["miss", "error"]) {
  test(`a content-key fallback ${answerKind} preserves the valid sibling and returns no failed-item key`, async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const document = requestFor([BODY, SUMMARY]);
    // The summary envelope is genuine, but does not bind to BODY. SUMMARY
    // still opens normally; only BODY needs the composed fallback.
    setKeyAt(
      document.sealed.contentKeys,
      { contentName: BODY },
      keyAt(document.sealed.contentKeys, { contentName: SUMMARY }),
    );
    const sourceError = { error: "binding_failed", message: "fallback refused the item" };
    const lookedUp = [];
    const engine = issuerEngine({
      accessPolicy: generousPolicy(),
      contentKeySource: {
        contentKeys: () => async (contentName) => {
          lookedUp.push(contentName);
          return answerKind === "miss" ? { miss: true } : { error: sourceError };
        },
      },
    });
    const result = await engine.unlock(new DcaRequest(document), registration);
    assert.deepEqual(lookedUp, [BODY]);
    assert.deepEqual(contentKeyMap(result.contentKeys), {
      [SUMMARY]: publisherKeys.contentKeys[SUMMARY],
    });
    assert.deepEqual(Object.keys(errorMap(result.errors)), [BODY]);
    assert.equal(
      errorMap(result.errors)[BODY].error,
      answerKind === "miss" ? "unseal_failed" : sourceError.error,
    );
    if (answerKind === "error") assert.deepEqual(errorMap(result.errors)[BODY], sourceError);
  });
}

// A composed content-key source answers after the engine has made every
// request and entitlement decision, so nothing it returns or throws may stand
// in for one. Malformed key bytes are this issuer's own fault, and so is a
// throw: neither may reach the caller as key material or as a refusal code.
describe("what a composed content-key source cannot hand back", () => {
  /**
   * BODY's own seal is swapped for SUMMARY's, so it fails BIND and the engine
   * asks the source for BODY. The policy grants BODY alone.
   *
   * @param {import('../../core-issuer/IssuerEngine.js').ContentKeySource} contentKeySource
   * @param {object} [extra] - further engine configuration
   */
  async function sourceAsked(contentKeySource, extra = {}) {
    const { registration, requestFor } = await world();
    const document = requestFor([BODY, SUMMARY]);
    setKeyAt(
      document.sealed.contentKeys,
      { contentName: BODY },
      keyAt(document.sealed.contentKeys, { contentName: SUMMARY }),
    );
    const engine = issuerEngine({
      accessPolicy: policyAnswering(() => ({ contentNames: [BODY] })),
      contentKeySource,
      ...extra,
    });
    const answered = await new UnlockEndpoint(new IssuerProcessor(engine)).handleRequest({
      request: new DcaRequest(document),
      registration,
    });
    return { unlocked: () => engine.unlock(new DcaRequest(document), registration), answered };
  }

  test("a source answering 16 bytes delivers them as the item's content key", async () => {
    const bytes = new Uint8Array(16).fill(7);
    const { unlocked, answered } = await sourceAsked({
      contentKeys: () => async () => ({ bytes }),
    });
    assert.deepEqual(contentKeyMap((await unlocked()).contentKeys), {
      [BODY]: base64urlEncode(bytes),
    });
    assert.equal(answered.response.status, 200);
  });

  for (const width of [0, 15, 17, 32]) {
    test(`a source answering ${width} key bytes is a configuration fault, not a key`, async () => {
      const { unlocked, answered } = await sourceAsked({
        contentKeys: () => async () => ({ bytes: new Uint8Array(width).fill(7) }),
      });
      await assert.rejects(
        unlocked(),
        /** @param {any} error */ (error) => error.code === "bad_config",
      );
      assert.deepEqual(answered.response, { status: 500, body: { error: "internal_error" } });
    });
  }

  for (const code of ["denied", "binding_failed", "policy_unavailable", "unknown_key"]) {
    for (const [where, source, extra] of [
      [
        "its lookup",
        {
          contentKeys: () => async () => {
            throw Object.assign(new Error("period store refused"), { code });
          },
        },
        {},
      ],
      [
        "contentKeys(unlock)",
        {
          contentKeys: () => {
            throw Object.assign(new Error("period store refused"), { code });
          },
        },
        {},
      ],
      [
        "presented(request)",
        {
          presented: () => {
            throw Object.assign(new Error("period store refused"), { code });
          },
          contentKeys: () => async () => ({ miss: true }),
        },
        {},
      ],
      [
        "its host scope",
        { contentKeys: () => async () => ({ miss: true }) },
        {
          contentKeyScope: async () => {
            throw Object.assign(new Error("period store refused"), { code });
          },
        },
      ],
    ]) {
      test(`a ${JSON.stringify(code)} thrown from ${where} is an internal fault`, async () => {
        const { unlocked, answered } = await sourceAsked(
          /** @type {any} */ (source),
          /** @type {any} */ (extra),
        );
        await assert.rejects(
          unlocked(),
          /** @param {any} error */ (error) => error.code === "internal_error",
        );
        assert.deepEqual(answered.response, { status: 500, body: { error: "internal_error" } });
        assert.equal(answered.code, "internal_error");
      });
    }
  }

  test('a DcaError "denied" thrown from its lookup is an internal fault too', async () => {
    // A DCA-built source throws a DcaError, not a plain Error. The engine must
    // still recode `denied`: kept, it would refuse the whole request as a
    // denial the policy never made.
    const { unlocked, answered } = await sourceAsked({
      contentKeys: () => async () => {
        throw dcaError("denied", "period store refused");
      },
    });
    await assert.rejects(
      unlocked(),
      /** @param {any} error */ (error) => error.code === "internal_error",
    );
    assert.deepEqual(answered.response, { status: 500, body: { error: "internal_error" } });
    assert.equal(answered.code, "internal_error");
  });

  for (const code of ["bad_config", "bad_policy"]) {
    test(`a source's own ${JSON.stringify(code)} keeps its issuer-fault code`, async () => {
      const { unlocked } = await sourceAsked({
        contentKeys: () => async () => {
          throw dcaError(code, "the source's own configuration");
        },
      });
      await assert.rejects(unlocked(), /** @param {any} error */ (error) => error.code === code);
    });
  }

  test("an opening-key fault the engine raises under a source keeps its own code", async () => {
    const { registration, requestFor } = await world();
    const document = requestFor([BODY, SUMMARY]);
    // The engine's own seal walk meets a non-string and opens nothing; the
    // source then opens the real seal under the misdeclared key.
    const sealedBody = keyAt(document.sealed.contentKeys, { contentName: BODY });
    setKeyAt(document.sealed.contentKeys, { contentName: BODY }, 42);
    const misdeclared = {
      ...registration,
      openingKeys: {
        /** @param {string} issuerName @param {string} keyId */
        get(issuerName, keyId) {
          return { ...registration.openingKeys.get(issuerName, keyId), algorithm: "rsa-oaep" };
        },
      },
    };
    /** @type {any} */
    let opened;
    const engine = issuerEngine({
      accessPolicy: policyAnswering(() => ({ contentNames: [BODY] })),
      contentKeySource: {
        contentKeys:
          ({ open }) =>
          async () => {
            opened = open(sealedBody, { contentName: BODY });
            return opened;
          },
      },
    });
    await assert.rejects(
      engine.unlock(new DcaRequest(document), misdeclared),
      /** @param {any} error */ (error) => error.code === "bad_config",
    );
    assert.ok(opened, "the source reached the engine's opener");
  });
});

describe("selected period-source routing", () => {
  for (const lookup of [null, undefined, false, 1, "lookup", {}, []]) {
    test(`a selected source with a non-callable lookup (${JSON.stringify(lookup)}) is bad_config`, async () => {
      const { registration, requestFor } = await world();
      const engine = issuerEngine({
        accessPolicy: generousPolicy(),
        periodCapabilitySource: {
          selection: () => () => ({ selected: [{ t: T0 }] }),
          capabilities: () => /** @type {any} */ (lookup),
        },
      });

      // Valid period-key seals remain present: a broken selected representation
      // must not silently answer with their otherwise granted prefix.
      await assert.rejects(
        () => engine.unlock(new DcaRequest(requestFor([BODY])), registration),
        /** @param {any} error */ (error) => error.code === "bad_config",
      );
    });
  }

  test("a valid selected lookup answers only the selected representation", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const engine = issuerEngine({
      accessPolicy: generousPolicy(),
      periodCapabilitySource: {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities:
          ({ request, open }) =>
          async (accessGroup, selected) => {
            assert.equal(accessGroup, GROUP);
            assert.deepEqual(selected, [{ t: T0 }]);
            const opened = await open(
              keyAt(request.sealedPeriodKeys, { accessGroup: GROUP, period: T0 }),
              { accessGroup, t: T0 },
            );
            return represented([{ t: T0, ...opened }]);
          },
      },
    });

    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
    assert.deepEqual(contentKeyMap(result.contentKeys), {
      [BODY]: publisherKeys.contentKeys[BODY],
    });
    assert.deepEqual(periodKeyMap(result.periodKeys), {});
    assert.deepEqual(result.capabilities, [
      {
        kind: "test-capability",
        accessGroup: GROUP,
        entries: [{ t: T0, key: publisherKeys.periodKeys[T0] }],
        interpretation: TEST_INTERPRETATION,
      },
    ]);
    assert.deepEqual(errorMap(result.errors), {});
  });

  test("a selected period-key projection enters the ordinary periodKeys section", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const engine = issuerEngine({
      accessPolicy: generousPolicy(),
      periodCapabilitySource: {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities:
          ({ request, open }) =>
          async (accessGroup) => {
            const opened = await open(
              keyAt(request.sealedPeriodKeys, { accessGroup: GROUP, period: T0 }),
              { accessGroup, t: T0 },
            );
            return { kind: "period-keys", interpretation: {}, periods: [{ t: T0, ...opened }] };
          },
      },
    });

    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
    assert.deepEqual(periodKeyMap(result.periodKeys), {
      [GROUP]: { [T0]: publisherKeys.periodKeys[T0] },
    });
    assert.deepEqual(
      result.capabilities,
      [],
      "ordinary period-key output needs no capability encoder",
    );
    assert.deepEqual(errorMap(result.errors), {});
  });

  test("a miss keeps period-key output while unavailable keeps it closed; neither builds a lookup", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    for (const selection of [{ miss: true }, { unavailable: true }]) {
      const engine = issuerEngine({
        accessPolicy: generousPolicy(),
        periodCapabilitySource: {
          selection: () => () => /** @type {any} */ (selection),
          capabilities: () => {
            throw new Error("no selected representation needs a lookup");
          },
        },
      });
      const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
      assert.deepEqual(contentKeyMap(result.contentKeys), {
        [BODY]: publisherKeys.contentKeys[BODY],
      });
      assert.deepEqual(
        periodKeyMap(result.periodKeys),
        "miss" in selection ? { [GROUP]: publisherKeys.periodKeys } : {},
      );
      assert.deepEqual(result.capabilities, []);
      assert.deepEqual(errorMap(result.errors), {});
    }
  });

  test("a selected source under a retired key is not asked for a lookup", async () => {
    const { registration, requestFor } = await world();
    const engine = issuerEngine({
      accessPolicy: generousPolicy(),
      periodCapabilitySource: {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities: () => {
          throw new Error("retired keys never reach the source");
        },
      },
    });
    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), {
      ...registration,
      openingKeys: { get: () => ({ retired: true }) },
    });
    assert.deepEqual(contentKeyMap(result.contentKeys), {});
    assert.deepEqual(periodKeyMap(result.periodKeys), {});
    assert.deepEqual(result.capabilities, []);
    assert.deepEqual(Object.keys(errorMap(result.errors)).sort(), [BODY, `${GROUP}|${T0}`]);
    for (const error of Object.values(errorMap(result.errors)))
      assert.equal(error.error, "key_retired");
  });

  test("a callable selected lookup must still return a valid representation", async () => {
    const { registration, requestFor } = await world();
    for (const answer of [null, undefined, {}, { miss: true }, { periods: [] }]) {
      const engine = issuerEngine({
        accessPolicy: generousPolicy(),
        periodCapabilitySource: {
          selection: () => () => ({ selected: [{ t: T0 }] }),
          capabilities: () => async () => /** @type {any} */ (answer),
        },
      });
      await assert.rejects(
        () => engine.unlock(new DcaRequest(requestFor([BODY])), registration),
        /** @param {any} error */ (error) => error.code === "bad_config",
      );
    }
  });
});

describe("the three answers a key store gives", () => {
  test("a keyId this issuer never held refuses the whole request", async () => {
    const { registration, requestFor } = await world();
    const engine = issuerEngine({ accessPolicy: generousPolicy() });

    const document = requestFor([BODY]);
    document.keyId = "a-key-this-issuer-never-held";

    await assert.rejects(
      () => engine.unlock(new DcaRequest(document), registration),
      /** @param {any} error */ (error) => error.code === "unknown_key",
    );
  });

  test("a retired keyId answers every granted coordinate with the rollover failure", async () => {
    const { registration, requestFor } = await world();
    const engine = issuerEngine({ accessPolicy: generousPolicy() });

    const retiring = {
      ...registration,
      openingKeys: { get: () => ({ retired: true }) },
    };

    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), retiring);
    assert.deepEqual(contentKeyMap(result.contentKeys), {});
    assert.deepEqual(periodKeyMap(result.periodKeys), {});
    assert.deepEqual(Object.keys(errorMap(result.errors)).sort(), [
      BODY,
      `${GROUP}|${T0}`,
      `${GROUP}|${T1}`,
    ]);
    for (const entry of Object.values(errorMap(result.errors)))
      assert.equal(entry.error, "key_retired");
  });

  test("an entry that is both held and retired, or neither, is this issuer broken", async () => {
    const { registration, requestFor } = await world();
    const engine = issuerEngine({ accessPolicy: generousPolicy() });
    const document = requestFor([BODY]);

    for (const entry of [{ retired: true, privateKey: null }, { algorithm: "ecdh-p256" }]) {
      await assert.rejects(
        () =>
          engine.unlock(new DcaRequest(document), {
            ...registration,
            openingKeys: { get: () => entry },
          }),
        /** @param {any} error */ (error) => error.code === "bad_config",
      );
    }
  });
});

describe("a configuration fault refuses the whole request", () => {
  // The issuer configured its own opening key, so an entry declaring one
  // algorithm while holding another is this issuer broken. Answering that as
  // a per-coordinate `unseal_failed` would tell every reader its page was
  // tampered with and leave the operator reading a 200.

  /**
   * The endpoint this issuer application answers through.
   *
   * @param {IssuerEngine} engine
   */
  function endpointFor(engine) {
    return new UnlockEndpoint(new IssuerProcessor(engine));
  }

  test("an opening key declared as another algorithm refuses the whole request", async () => {
    const { registration, requestFor } = await world();
    const engine = issuerEngine({ accessPolicy: generousPolicy() });

    // The held key is the ECDH one the render was sealed to; only the
    // declaration beside it says RSA-OAEP.
    const misdeclared = {
      ...registration,
      openingKeys: {
        /** @param {string} issuerName @param {string} keyId */
        get(issuerName, keyId) {
          return { ...registration.openingKeys.get(issuerName, keyId), algorithm: "rsa-oaep" };
        },
      },
    };

    await assert.rejects(
      () => engine.unlock(new DcaRequest(requestFor([BODY])), misdeclared),
      /** @param {any} error */ (error) => error.code === "bad_config",
    );

    const answered = await endpointFor(engine).handleRequest({
      request: new DcaRequest(requestFor([BODY])),
      registration: misdeclared,
    });
    assert.deepEqual(answered.response, { status: 500, body: { error: "internal_error" } });
    assert.equal(answered.code, "internal_error");
  });

  test("a tampered coordinate beside a granted sibling still answers 200", async () => {
    const { registration, requestFor } = await world();
    const engine = issuerEngine({ accessPolicy: generousPolicy() });

    const document = requestFor([BODY, SUMMARY]);
    setKeyAt(
      document.sealed.contentKeys,
      { contentName: SUMMARY },
      keyAt(document.sealed.contentKeys, { contentName: BODY }),
    );

    const answered = await endpointFor(engine).handleRequest({
      request: new DcaRequest(document),
      registration,
    });
    assert.equal(answered.response.status, 200);
    const body = /** @type {any} */ (answered.response.body);
    assert.deepEqual(Object.keys(contentKeyMap(body.keys.contentKeys)), [BODY]);
    assert.deepEqual(errorMap(body.errors), {
      [SUMMARY]: { error: "unseal_failed", message: "sealed value could not be opened" },
    });
  });
});

// Period keys Section 5.6 lets an issuer name a presented access-group family it
// delivered nothing for, with `denied` or `unavailable`. The reference
// reports every such family the request presented in its own period sections
// when the host's disclosure setting, `notDeliveredReport`, asks it to.
// "partial" reports beside a result the request earns anyway, "complete" also
// answers a complete denial with a no-key result, and "none", the default,
// reports nothing.
describe("not-delivered family reports", () => {
  /** A period source that selects nothing current for any granted family. */
  const noCurrentPeriod = () => ({
    selection: () => () => /** @type {const} */ ({ unavailable: "unavailable" }),
    capabilities: () => {
      throw new Error("an unavailable family never reaches a lookup");
    },
  });

  test("a family the policy withheld is reported denied beside the content key it granted", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    for (const decision of [
      { contentNames: [BODY] },
      { contentNames: [BODY], periodGrants: [{ accessGroup: GROUP, periods: [] }] },
    ]) {
      const engine = issuerEngine({
        accessPolicy: policyAnswering(() => decision),
        notDeliveredReport: "partial",
      });
      const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
      assert.deepEqual(contentKeyMap(result.contentKeys), {
        [BODY]: publisherKeys.contentKeys[BODY],
      });
      assert.deepEqual(periodKeyMap(result.periodKeys), {});
      assert.deepEqual(errorMap(result.errors), {});
      assert.deepEqual(notDeliveredMap(result.notDelivered), { [GROUP]: { reason: "denied" } });
    }
  });

  test("a granted family with no current capability is reported unavailable", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const engine = issuerEngine({
      accessPolicy: generousPolicy(),
      periodCapabilitySource: noCurrentPeriod(),
      notDeliveredReport: "partial",
    });
    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
    assert.deepEqual(contentKeyMap(result.contentKeys), {
      [BODY]: publisherKeys.contentKeys[BODY],
    });
    assert.deepEqual(periodKeyMap(result.periodKeys), {});
    assert.deepEqual(errorMap(result.errors), {});
    assert.deepEqual(notDeliveredMap(result.notDelivered), { [GROUP]: { reason: "unavailable" } });
  });

  test("an authorized family with no current capability yields a no-key result under every report setting", async () => {
    const { registration, requestFor, asked } = await world();
    for (const setting of ["none", "partial", "complete"]) {
      asked.length = 0;
      const engine = issuerEngine({
        accessPolicy: policyAnswering(() => ({
          periodGrants: [{ accessGroup: GROUP, periods: [T0, T1] }],
        })),
        periodCapabilitySource: noCurrentPeriod(),
        notDeliveredReport: setting,
      });
      const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
      assert.deepEqual(contentKeyMap(result.contentKeys), {});
      assert.deepEqual(periodKeyMap(result.periodKeys), {});
      assert.deepEqual(result.capabilities, []);
      assert.deepEqual(errorMap(result.errors), {});
      assert.deepEqual(
        notDeliveredMap(result.notDelivered),
        setting === "none" ? {} : { [GROUP]: { reason: "unavailable" } },
      );
      assert.deepEqual(asked, [], "unreachable supply needs no opening key");
    }
  });

  test("an unavailable source without current-reach evidence omits the optional report", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const engine = issuerEngine({
      accessPolicy: generousPolicy(),
      periodCapabilitySource: {
        selection: () => () => ({ unavailable: true }),
        capabilities: () => {
          throw new Error("an unavailable family never reaches a lookup");
        },
      },
      notDeliveredReport: "partial",
    });
    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
    assert.deepEqual(contentKeyMap(result.contentKeys), {
      [BODY]: publisherKeys.contentKeys[BODY],
    });
    assert.deepEqual(periodKeyMap(result.periodKeys), {});
    assert.deepEqual(errorMap(result.errors), {});
    assert.deepEqual(notDeliveredMap(result.notDelivered), {});
  });

  test("denied wins when the family also has no current capability", async () => {
    const { registration, requestFor } = await world();
    const engine = issuerEngine({
      accessPolicy: policyAnswering(() => ({
        contentNames: [BODY],
        periodGrants: [{ accessGroup: GROUP, periods: [] }],
      })),
      periodCapabilitySource: noCurrentPeriod(),
      notDeliveredReport: "partial",
    });
    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
    assert.deepEqual(notDeliveredMap(result.notDelivered), { [GROUP]: { reason: "denied" } });
  });

  test("a delivered family, or one whose granted period keys fail to open, gets no entry", async () => {
    const { registration, requestFor } = await world();
    const engine = issuerEngine({
      accessPolicy: generousPolicy(),
      notDeliveredReport: "partial",
    });

    const delivered = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
    assert.deepEqual(notDeliveredMap(delivered.notDelivered), {});

    // Both granted blobs presented at each other's label: the family was
    // authorized and failed to open, which stays a coordinate error.
    const document = requestFor([BODY]);
    const [t0Seal, t1Seal] = [T0, T1].map((period) =>
      keyAt(document.sealed.periodKeys, { accessGroup: GROUP, period }),
    );
    setKeyAt(document.sealed.periodKeys, { accessGroup: GROUP, period: T0 }, t1Seal);
    setKeyAt(document.sealed.periodKeys, { accessGroup: GROUP, period: T1 }, t0Seal);
    const failed = await engine.unlock(new DcaRequest(document), registration);
    assert.deepEqual(periodKeyMap(failed.periodKeys), {});
    assert.deepEqual(Object.keys(errorMap(failed.errors)).sort(), [
      `${GROUP}|${T0}`,
      `${GROUP}|${T1}`,
    ]);
    assert.deepEqual(notDeliveredMap(failed.notDelivered), {});
  });

  test("a family presented only through a content-key source is never named", async () => {
    // The client's association knows only the period sections it sent, so a
    // family it did not send there would make the whole answer unsolicited.
    const { registration, requestFor } = await world();
    const engine = issuerEngine({
      accessPolicy: policyAnswering(() => ({ contentNames: [BODY] })),
      contentKeySource: {
        presented: () => ({ accessGroups: ["standard"] }),
        contentKeys: () => async () => ({ miss: true }),
      },
      notDeliveredReport: "partial",
    });
    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
    assert.deepEqual(notDeliveredMap(result.notDelivered), { [GROUP]: { reason: "denied" } });
  });

  for (const setting of [{}, { notDeliveredReport: "none" }]) {
    test(`reporting ${JSON.stringify(setting)} emits no entry and keeps the complete-denial refusal`, async () => {
      const { registration, requestFor, asked } = await world();
      const partial = issuerEngine({
        accessPolicy: policyAnswering(() => ({ contentNames: [BODY] })),
        periodCapabilitySource: noCurrentPeriod(),
        ...setting,
      });
      const result = await partial.unlock(new DcaRequest(requestFor([BODY])), registration);
      assert.deepEqual(notDeliveredMap(result.notDelivered), {});

      const denied = issuerEngine({ accessPolicy: policyAnswering(() => ({})), ...setting });
      asked.length = 0;
      await assert.rejects(
        () => denied.unlock(new DcaRequest(requestFor([BODY])), registration),
        /** @param {any} error */ (error) => error.code === "denied",
      );
      assert.deepEqual(asked, []);
    });
  }

  test("the partial setting keeps a complete denial a whole-request refusal", async () => {
    const { registration, requestFor, asked } = await world();
    const engine = issuerEngine({
      accessPolicy: policyAnswering(() => ({})),
      notDeliveredReport: "partial",
    });
    await assert.rejects(
      () => engine.unlock(new DcaRequest(requestFor([BODY])), registration),
      /** @param {any} error */ (error) => error.code === "denied",
    );
    assert.deepEqual(asked, []);
  });

  test("a complete denial becomes a no-key result naming the family, built before key lookup", async () => {
    const { registration, requestFor, asked } = await world();
    for (const [decision, source, reason] of [
      [{}, undefined, "denied"],
      [{ periodGrants: [{ accessGroup: GROUP, periods: [] }] }, noCurrentPeriod(), "denied"],
      [
        { periodGrants: [{ accessGroup: GROUP, periods: [T0, T1] }] },
        noCurrentPeriod(),
        "unavailable",
      ],
    ]) {
      asked.length = 0;
      const engine = issuerEngine({
        accessPolicy: policyAnswering(() => decision),
        notDeliveredReport: "complete",
        ...(source === undefined ? {} : { periodCapabilitySource: source }),
      });
      const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
      assert.deepEqual(
        contentKeyMap(result.contentKeys),
        {},
        "the denied content-name coordinate is omitted",
      );
      assert.deepEqual(periodKeyMap(result.periodKeys), {});
      assert.deepEqual(result.capabilities, []);
      assert.deepEqual(errorMap(result.errors), {});
      assert.deepEqual(notDeliveredMap(result.notDelivered), { [GROUP]: { reason } });
      assert.deepEqual(asked, [], "the no-key result reaches no opening key");
    }
  });

  test("a complete denial that presented no family is refused whatever the setting", async () => {
    const { registration, requestFor, asked } = await world();
    const document = requestFor([BODY]);
    delete document.sealed.periodKeys;
    const engine = issuerEngine({
      accessPolicy: policyAnswering(() => ({})),
      notDeliveredReport: "complete",
    });
    await assert.rejects(
      () => engine.unlock(new DcaRequest(document), registration),
      /** @param {any} error */ (error) => error.code === "denied",
    );
    assert.deepEqual(asked, []);
  });

  test("an issuer that obtained no policy decision emits no entry and fails closed", async () => {
    const { registration, requestFor, asked } = await world();
    for (const decide of [
      () => {
        throw Object.assign(new Error("entitlement source timed out"), { code: "unavailable" });
      },
      () => null,
      () => ({ periodGrants: [{ accessGroup: GROUP, periodCount: -1 }] }),
    ]) {
      asked.length = 0;
      const engine = issuerEngine({
        accessPolicy: { decide },
        notDeliveredReport: "complete",
      });
      await assert.rejects(() => engine.unlock(new DcaRequest(requestFor([BODY])), registration));
      assert.deepEqual(asked, []);
    }
  });

  test("the report setting takes one of its three values", () => {
    for (const notDeliveredReport of [true, "off", "", null]) {
      assert.throws(
        () => issuerEngine({ accessPolicy: generousPolicy(), notDeliveredReport }),
        /** @param {any} error */ (error) => error.code === "bad_config",
      );
    }
    for (const notDeliveredReport of ["none", "partial", "complete"]) {
      assert.doesNotThrow(() =>
        issuerEngine({ accessPolicy: generousPolicy(), notDeliveredReport }),
      );
    }
  });
});

test("an array-shaped policy period grant is refused", async () => {
  const { registration, requestFor } = await world();
  const malformed = Object.assign([], { accessGroup: GROUP, periods: [T0] });
  const engine = issuerEngine({
    accessPolicy: { decide: () => ({ contentNames: [], periodGrants: [malformed] }) },
  });
  await assert.rejects(
    () => engine.unlock(new DcaRequest(requestFor([BODY])), registration),
    /** @param {any} error */ (error) => error.code === "bad_policy",
  );
});
