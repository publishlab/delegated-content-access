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
// recording. That pins the ordinary work: a direct contentKey opened at its
// own name, and the granted prefix of one access group's presented periods,
// both under the render the publisher signed.
//
// The rest of this file pins the rules those two loops sit inside: one policy
// call per unlock, no opening key reached by a request that failed
// verification or was denied outright, a partial grant that leaves its granted
// siblings alone, and the three answers a key store can give.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../core-publisher/Sealer.js";
import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";
import { sign } from "../core-shared--publisher-issuer/jwt.js";
import { base64urlDecode, base64urlEncode } from "../core-shared/codec.js";
import { decrypt } from "../core-shared/aead.js";
import { Client } from "../test-lib/harnesses/client.js";
import { exactPeriodKeySupply } from "../demo/support/exactPeriodKeySupply.js";
import { Random } from "../demo/actors/Random.js";
import { Clock } from "../demo/actors/Clock.js";

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
const T0 = "251023T14";
const T1 = "251023T15";
const T2 = "251023T16";

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
    const wrap = page.contentData[name].keys[GROUP].find(
      (/** @type {any} */ entry) => entry.t === T0,
    );
    contentKeys[name] = base64urlEncode(
      await decrypt(openingPeriodKey, base64urlDecode(wrap.nonce), base64urlDecode(wrap.key)),
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
  const periodKeySupply = exactPeriodKeySupply({ random: new Random({ seed: 7 }) });

  const sealer = new Sealer({
    origin: ORIGIN,
    clock: new Clock(AT),
    random: new Random({ seed: 11 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply,
    period: { length: 60, slots: 3 },
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ECDH-P256",
        publicKey: issuerKeys.publicKey,
        unlockUrl: "https://api.example.com/unlock",
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
      return { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey };
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
 * @param {(requested: { contentNames: string[], accessGroups: string[] }) => any} answer
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

/** Grants every presented name and the first two periods of every group. */
const generousPolicy = () =>
  policyAnswering((requested) => ({
    contentNames: [...requested.contentNames],
    periodGrants: requested.accessGroups.map((accessGroup) => ({ accessGroup, periodCount: 2 })),
    policyData: { seat: "A-14" },
  }));

describe("the ordinary issuer answer", () => {
  test("a direct grant and a period prefix open to the bytes the publisher sealed", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const policy = generousPolicy();
    const engine = new IssuerEngine({ accessPolicy: policy });

    const result = await engine.unlock(new DcaRequest(requestFor([BODY, SUMMARY])), registration, {
      principal: null,
    });

    assert.deepEqual(result.contentKeys, {
      [BODY]: publisherKeys.contentKeys[BODY],
      [SUMMARY]: publisherKeys.contentKeys[SUMMARY],
    });
    assert.deepEqual(result.periodKeys, { [GROUP]: publisherKeys.periodKeys });
    assert.deepEqual(result.errors, {});
    assert.deepEqual(result.policyData, { seat: "A-14" });
  });

  test("the period past the granted prefix is present in the request and never opened", async () => {
    const { registration, requestFor } = await world();
    const engine = new IssuerEngine({ accessPolicy: generousPolicy() });

    const document = requestFor([BODY]);
    assert.deepEqual(Object.keys(document.sealed.periodKeys[GROUP]).sort(), [T0, T1, T2]);

    const result = await engine.unlock(new DcaRequest(document), registration);
    assert.deepEqual(Object.keys(result.periodKeys[GROUP]).sort(), [T0, T1]);
  });

  test("the access policy is asked once for the whole unlock", async () => {
    const { registration, requestFor } = await world();
    const policy = generousPolicy();
    const engine = new IssuerEngine({ accessPolicy: policy });

    await engine.unlock(new DcaRequest(requestFor([BODY, SUMMARY])), registration);
    assert.equal(policy.calls, 1);
  });

  test("a partial grant answers its granted siblings and withholds the rest", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const engine = new IssuerEngine({
      accessPolicy: policyAnswering(() => ({ contentNames: [BODY] })),
    });

    const result = await engine.unlock(new DcaRequest(requestFor([BODY, SUMMARY])), registration);
    assert.deepEqual(result.contentKeys, { [BODY]: publisherKeys.contentKeys[BODY] });
    assert.deepEqual(result.periodKeys, {});
    assert.deepEqual(result.errors, {});
  });

  test("a granted coordinate that will not open leaves its granted sibling intact", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const engine = new IssuerEngine({ accessPolicy: generousPolicy() });

    // The same genuine blob, presented at the other name. It was sealed
    // committed to `summary`, so rebuilding the binding at `bodytext` fails
    // to open it and reports one error beside the keys that did work.
    const document = requestFor([BODY, SUMMARY]);
    document.sealed.contentKeys[SUMMARY] = document.sealed.contentKeys[BODY];

    const result = await engine.unlock(new DcaRequest(document), registration);
    assert.deepEqual(Object.keys(result.contentKeys), [BODY]);
    assert.deepEqual(result.errors, {
      [SUMMARY]: { error: "unseal_failed", message: "sealed value could not be opened" },
    });
    assert.deepEqual(result.periodKeys, { [GROUP]: publisherKeys.periodKeys });
  });
});

describe("what a refused unlock never reaches", () => {
  test("a complete denial is refused before any opening key is looked up", async () => {
    const { registration, requestFor, asked } = await world();
    const engine = new IssuerEngine({ accessPolicy: policyAnswering(() => ({})) });

    await assert.rejects(
      () => engine.unlock(new DcaRequest(requestFor([BODY])), registration),
      /** @param {any} error */ (error) => error.code === "denied",
    );
    assert.deepEqual(asked, [], "a denied request costs this issuer no key lookup");
  });

  test("a request whose signature does not verify reaches no opening key", async () => {
    const { registration, requestFor, asked } = await world();
    const policy = generousPolicy();
    const engine = new IssuerEngine({ accessPolicy: policy });

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
    const productionEngine = new IssuerEngine({ accessPolicy: productionPolicy });
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
    const developmentEngine = new IssuerEngine({
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
      opened.contentKeys[BODY],
      development.publisherKeys.contentKeys[BODY],
      "the explicit opt-in is the positive control",
    );
    assert.equal(developmentPolicy.calls, 1);
    assert.deepEqual(development.asked, [`${ISSUER_NAME} ${KEY_ID}`]);

    for (const origin of [PUBLIC_HTTP_ORIGIN, NONCANONICAL_HTTPS_ORIGIN]) {
      const refused = await world();
      const policy = generousPolicy();
      const engine = new IssuerEngine({ accessPolicy: policy, developmentHttpOrigin: true });
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
        () => new IssuerEngine({ accessPolicy, ...config }),
        /** @param {any} error */ (error) => error.code === "bad_config",
      );
    }

    assert.doesNotThrow(
      () =>
        new IssuerEngine({
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
      () => new IssuerEngine({ accessPolicy, clock: { now: () => new Date() } }),
      /** @param {any} error */ (error) =>
        error.code === "unsupported_option" &&
        error.message === "IssuerEngine has no clock yet, and will not pretend to",
    );
  });
});

test("a content-key source receives only the host-selected opaque scope", async () => {
  const { registration, requestFor } = await world();
  const scope = Object.freeze({ exactLeaf: "selected-outside-the-request" });
  let selections = 0;
  /** @type {any} */
  let received;
  const engine = new IssuerEngine({
    accessPolicy: generousPolicy(),
    contentKeyScope(selectedRegistration) {
      selections += 1;
      assert.strictEqual(selectedRegistration, registration);
      return scope;
    },
    contentKeySource: {
      contentKeys(unlock) {
        received = unlock;
        return async () => ({ miss: true });
      },
    },
  });

  await engine.unlock(new DcaRequest(requestFor([BODY])), registration);

  assert.equal(selections, 1, "the authenticated registration selects one scope per active unlock");
  assert.strictEqual(received.scope, scope);
  assert.equal(Object.hasOwn(received, "registration"), false);
  assert.equal(Object.hasOwn(received, "openingKeys"), false);
});

describe("selected period-source routing", () => {
  for (const lookup of [null, undefined, false, 1, "lookup", {}, []]) {
    test(`a selected source with a non-callable lookup (${JSON.stringify(lookup)}) is bad_config`, async () => {
      const { registration, requestFor } = await world();
      const engine = new IssuerEngine({
        accessPolicy: generousPolicy(),
        periodCapabilitySource: {
          selection: () => () => ({ selected: [{ t: T0 }] }),
          capabilities: () => /** @type {any} */ (lookup),
        },
      });

      // Valid exact seals remain present: a broken selected representation
      // must not silently answer with their otherwise granted prefix.
      await assert.rejects(
        () => engine.unlock(new DcaRequest(requestFor([BODY])), registration),
        /** @param {any} error */ (error) => error.code === "bad_config",
      );
    });
  }

  test("a valid selected lookup answers only the selected representation", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const engine = new IssuerEngine({
      accessPolicy: generousPolicy(),
      periodCapabilitySource: {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities:
          ({ request, open }) =>
          async (accessGroup, selected) => {
            assert.equal(accessGroup, GROUP);
            assert.deepEqual(selected, [{ t: T0 }]);
            const opened = await open(request.sealedPeriodKeys[GROUP][T0], { accessGroup, t: T0 });
            return represented([{ t: T0, ...opened }]);
          },
      },
    });

    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
    assert.deepEqual(result.contentKeys, { [BODY]: publisherKeys.contentKeys[BODY] });
    assert.deepEqual(result.periodKeys, {});
    assert.deepEqual(result.capabilities, [
      {
        kind: "test-capability",
        accessGroup: GROUP,
        entries: { [T0]: publisherKeys.periodKeys[T0] },
        interpretation: TEST_INTERPRETATION,
      },
    ]);
    assert.deepEqual(result.errors, {});
  });

  test("a selected exact projection enters the ordinary periodKeys section", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    const engine = new IssuerEngine({
      accessPolicy: generousPolicy(),
      periodCapabilitySource: {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities:
          ({ request, open }) =>
          async (accessGroup) => {
            const opened = await open(request.sealedPeriodKeys[GROUP][T0], { accessGroup, t: T0 });
            return { kind: "period-keys", interpretation: {}, periods: [{ t: T0, ...opened }] };
          },
      },
    });

    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
    assert.deepEqual(result.periodKeys, { [GROUP]: { [T0]: publisherKeys.periodKeys[T0] } });
    assert.deepEqual(result.capabilities, [], "ordinary exact output needs no capability encoder");
    assert.deepEqual(result.errors, {});
  });

  test("a miss keeps exact output while unavailable keeps it closed; neither builds a lookup", async () => {
    const { registration, requestFor, publisherKeys } = await world();
    for (const selection of [{ miss: true }, { unavailable: true }]) {
      const engine = new IssuerEngine({
        accessPolicy: generousPolicy(),
        periodCapabilitySource: {
          selection: () => () => /** @type {any} */ (selection),
          capabilities: () => {
            throw new Error("no selected representation needs a lookup");
          },
        },
      });
      const result = await engine.unlock(new DcaRequest(requestFor([BODY])), registration);
      assert.deepEqual(result.contentKeys, { [BODY]: publisherKeys.contentKeys[BODY] });
      assert.deepEqual(
        result.periodKeys,
        "miss" in selection ? { [GROUP]: publisherKeys.periodKeys } : {},
      );
      assert.deepEqual(result.capabilities, []);
      assert.deepEqual(result.errors, {});
    }
  });

  test("a selected source under a retired key is not asked for a lookup", async () => {
    const { registration, requestFor } = await world();
    const engine = new IssuerEngine({
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
    assert.deepEqual(result.contentKeys, {});
    assert.deepEqual(result.periodKeys, {});
    assert.deepEqual(result.capabilities, []);
    assert.deepEqual(Object.keys(result.errors).sort(), [BODY, `${GROUP}|${T0}`]);
    for (const error of Object.values(result.errors)) assert.equal(error.error, "key_retired");
  });

  test("a callable selected lookup must still return a valid representation", async () => {
    const { registration, requestFor } = await world();
    for (const answer of [null, undefined, {}, { miss: true }, { periods: [] }]) {
      const engine = new IssuerEngine({
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
    const engine = new IssuerEngine({ accessPolicy: generousPolicy() });

    const document = requestFor([BODY]);
    document.keyId = "a-key-this-issuer-never-held";

    await assert.rejects(
      () => engine.unlock(new DcaRequest(document), registration),
      /** @param {any} error */ (error) => error.code === "unknown_key",
    );
  });

  test("a retired keyId answers every granted coordinate with the rollover failure", async () => {
    const { registration, requestFor } = await world();
    const engine = new IssuerEngine({ accessPolicy: generousPolicy() });

    const retiring = {
      ...registration,
      openingKeys: { get: () => ({ retired: true }) },
    };

    const result = await engine.unlock(new DcaRequest(requestFor([BODY])), retiring);
    assert.deepEqual(result.contentKeys, {});
    assert.deepEqual(result.periodKeys, {});
    assert.deepEqual(Object.keys(result.errors).sort(), [BODY, `${GROUP}|${T0}`, `${GROUP}|${T1}`]);
    for (const entry of Object.values(result.errors)) assert.equal(entry.error, "key_retired");
  });

  test("an entry that is both held and retired, or neither, is this issuer broken", async () => {
    const { registration, requestFor } = await world();
    const engine = new IssuerEngine({ accessPolicy: generousPolicy() });
    const document = requestFor([BODY]);

    for (const entry of [{ retired: true, privateKey: null }, { algorithm: "ECDH-P256" }]) {
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
    const engine = new IssuerEngine({ accessPolicy: generousPolicy() });

    // The held key is the ECDH one the render was sealed to; only the
    // declaration beside it says RSA-OAEP.
    const misdeclared = {
      ...registration,
      openingKeys: {
        /** @param {string} issuerName @param {string} keyId */
        get(issuerName, keyId) {
          return { ...registration.openingKeys.get(issuerName, keyId), algorithm: "RSA-OAEP" };
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
    const engine = new IssuerEngine({ accessPolicy: generousPolicy() });

    const document = requestFor([BODY, SUMMARY]);
    document.sealed.contentKeys[SUMMARY] = document.sealed.contentKeys[BODY];

    const answered = await endpointFor(engine).handleRequest({
      request: new DcaRequest(document),
      registration,
    });
    assert.equal(answered.response.status, 200);
    const body = /** @type {any} */ (answered.response.body);
    assert.deepEqual(Object.keys(body.keys.contentKeys), [BODY]);
    assert.deepEqual(body.errors, {
      [SUMMARY]: { error: "unseal_failed", message: "sealed value could not be opened" },
    });
  });
});
