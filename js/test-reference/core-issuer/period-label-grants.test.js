//
// Ordinary period grants name exact labels; the engine intersects them with
// the admitted labels the request presented.
//
// Three periods are presented for one family, and separate decisions grant
// chosen labels. Pinned here: only explicitly authorized labels open, a
// second article of a granted period opens from the cache with no further
// unlock, and an ungranted period never reaches the client. To read in it
// the client would have to ask again, and this policy would still say no to it.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { formatT } from "../../core-shared--publisher-issuer/periodKeys.js";
import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { Sealer } from "../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { parseDcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { Random } from "../../demo/actors/Random.js";
import { Clock } from "../../demo/actors/Clock.js";
import { base64urlDecode, utf8Decode } from "../../core-shared/codec.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const DOMAIN = "www.news-site.example";
const ORIGIN = `https://${DOMAIN}`;
const AT = "2025-10-23T14:20:00Z";
const GROUP = "premium";

/** Three hourly periods a render at this clock ships, in canonical order. */
const T0 = "251023T1400";
const T1 = "251023T1500";
const T2 = "251023T1600";

const ARTICLE_A = "<p>The council voted 7-2 to rezone the harbour.</p>";
const ARTICLE_B = "<p>The harbour plan goes to a second reading.</p>";

const TEST_INTERPRETATION = Object.freeze({ profile: "test-only" });

/** @param {any[]} periods */
function represented(periods) {
  return { kind: "test-capability", interpretation: TEST_INTERPRETATION, periods };
}
/**
 * A publisher and an issuer that share nothing but the issuer's public key.
 * Every render ships three periods of one family, so a policy can grant one
 * label and leave the others closed.
 *
 * @returns {Promise<{ keyStore: object, publisherRegistration: object, periodKeySupply: import('../../core-publisher/Sealer.js').PeriodKeySupply, render: (resourceId: string, value: string) => Promise<any> }>}
 */
async function world() {
  const issuerKeys = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const signingKeys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const periodKeySupply = randomPeriodKeySupply({ random: new Random({ seed: 7 }) });

  let seed = 1;

  /**
   * @param {string} resourceId
   * @param {string} value
   */
  async function render(resourceId, value) {
    const sealer = new Sealer({
      origin: ORIGIN,
      clock: new Clock(AT),
      random: new Random({ seed: seed++ }),
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

    sealer.resource(resourceId, { section: "politics" });
    sealer.content("bodytext", value, "text/html", { accessGroups: [GROUP] });

    const rendered = await sealer.seal();
    return JSON.parse(
      JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
    );
  }

  const keyStore = {
    /** @param {string} issuerName @param {string} keyId */
    get(issuerName, keyId) {
      if (issuerName !== ISSUER_NAME || keyId !== KEY_ID) return undefined;
      return { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey };
    },
  };

  const publisherRegistration = {
    kid: SIGNING_KID,
    publicKey: signingKeys.publicKey,
    origin: `https://${DOMAIN}`,
    openingKeys: keyStore,
  };

  return { keyStore, publisherRegistration, periodKeySupply, render };
}

/**
 * An endpoint whose policy grants these explicit presented periods, and
 * that counts what crossed it so "no further unlock" is an assertion.
 *
 * @param {object} publisherRegistration
 * @param {string[]} periods - the labels this policy grants for GROUP
 */
function endpointGranting(publisherRegistration, periods) {
  const processor = new IssuerProcessor(
    new IssuerEngine({
      operatingIssuerNames: [ISSUER_NAME],
      accessPolicy: {
        /**
         * @param {any} claims
         * @param {{ contentNames: string[], accessGroups: string[], periodCoordinates: Record<string, string[]> }} requested
         */
        decide(claims, requested) {
          void claims;
          return {
            contentNames: [...requested.contentNames],
            periodGrants: requested.accessGroups.map((accessGroup) => ({
              accessGroup,
              periods,
            })),
            policyData: [],
          };
        },
      },
    }),
    { periodKeyInput: true },
  );
  const endpoint = new UnlockEndpoint(processor);
  const calls = { count: 0 };
  return {
    calls,
    /** @param {any} body */
    async unlock(body) {
      calls.count++;
      return unlockThroughAdmission(processor, endpoint, body, publisherRegistration);
    },
  };
}

/**
 * The request the client would post, but with the group's presented periods
 * listed in reverse order. The engine has to canonically sort them, so a policy cannot accidentally depend on member order.
 *
 * @param {any} request
 * @returns {any}
 */
function periodsListedNewestFirst(request) {
  const periods = request.sealed.periodKeys[GROUP];
  /** @type {Record<string, string>} */
  const reversed = {};
  for (const t of Object.keys(periods).reverse()) reversed[t] = periods[t];
  request.sealed.periodKeys[GROUP] = reversed;
  return request;
}

describe("an explicit ordinary period-label grant", () => {
  test("a grant for one explicit label opens only that period", async () => {
    const { publisherRegistration, periodKeySupply, render } = await world();
    const cache = new PeriodKeyCache();
    const unsealer = new Client({ cache, publisherOrigin: `https://${DOMAIN}` });
    const endpoint = endpointGranting(publisherRegistration, [T0]);

    const first = unsealer.parse(await render("123456", ARTICLE_A));
    const request = periodsListedNewestFirst(
      unsealer.buildRequest(first, ISSUER_NAME, ["bodytext"]),
    );
    assert.deepEqual(
      Object.keys(request.sealed.periodKeys[GROUP]),
      [T2, T1, T0],
      "the request lists the periods newest first, so request order does not select the granted label",
    );

    const { status, body } = await endpoint.unlock(request);
    assert.equal(status, 200);

    // Exactly the lexicographically-first period, whatever order the request
    // carried, and not T2, which the request listed first.
    assert.deepEqual(Object.keys(body.keys.periodKeys[GROUP]), [T0]);
    assert.equal(body.keys.periodKeys[GROUP][T1], undefined, "an ungranted period is withheld");
    assert.equal(body.keys.periodKeys[GROUP][T2], undefined);

    // The one key delivered is the family's periodKey for T0, the same
    // bytes every article of premium@T0 is wrapped under, which is why the
    // next one opens with no further unlock.
    assert.deepEqual(
      base64urlDecode(body.keys.periodKeys[GROUP][T0]),
      await periodKeySupply.derive(GROUP, T0),
    );

    await unsealer.applyResponse(first, ISSUER_NAME, body);
    assert.equal((await cache.entries()).length, 1, "only the granted period is cached");

    // A second article of the same period opens from the cache, and the
    // issuer is not called again.
    const secondPage = await render("123457", ARTICLE_B);
    const second = unsealer.parse(secondPage);
    const { covered, missing } = await unsealer.resolve(second, ["bodytext"]);
    assert.deepEqual(covered, ["bodytext"]);
    assert.deepEqual(missing, [], "the cached granted period already opens the next article");
    const plaintext = await unsealer.decrypt(
      second,
      "bodytext",
      unsealer.extract(secondPage, "bodytext"),
    );
    assert.equal(utf8Decode(plaintext), ARTICLE_B);
    assert.equal(
      endpoint.calls.count,
      1,
      "the second article at the granted period cost no unlock",
    );

    // The ungranted periods never reached the client: to read in T1 it
    // would have to ask again, and hold no key for it until it did.
    assert.equal(
      (await cache.candidatesAt(GROUP, T0, { publisher: `https://${DOMAIN}` })).length,
      1,
      "no ungranted period key is held",
    );
  });

  test("a grant of two opens the first two presented periods, and still not the third", async () => {
    const { publisherRegistration, periodKeySupply, render } = await world();
    const unsealer = new Client({ cache: new PeriodKeyCache(), publisherOrigin: ORIGIN });
    const endpoint = endpointGranting(publisherRegistration, [T0, T1]);

    const dcaData = unsealer.parse(await render("123456", ARTICLE_A));
    const request = periodsListedNewestFirst(
      unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]),
    );

    const { status, body } = await endpoint.unlock(request);
    assert.equal(status, 200);

    assert.deepEqual(Object.keys(body.keys.periodKeys[GROUP]).sort(), [T0, T1]);
    assert.equal(
      body.keys.periodKeys[GROUP][T2],
      undefined,
      "the third presented period was not granted",
    );

    assert.deepEqual(
      base64urlDecode(body.keys.periodKeys[GROUP][T0]),
      await periodKeySupply.derive(GROUP, T0),
    );
    assert.deepEqual(
      base64urlDecode(body.keys.periodKeys[GROUP][T1]),
      await periodKeySupply.derive(GROUP, T1),
    );
  });

  test("the labels the engine sorts are the ones the render actually stamped", async () => {
    // A guard on the fixture: the three constants are the labels a render at
    // this clock stamps, in canonical order, so the explicit-label assertions above
    // mean what they say. They are read off the render rather than respelled
    // here, so a render stamping another sequence turns this red instead of
    // quietly changing which label is authorized.
    const { render } = await world();
    const page = await render("123456", ARTICLE_A);

    assert.deepEqual(Object.keys(page.issuerData[ISSUER_NAME].sealed.periodKeys[GROUP]).sort(), [
      T0,
      T1,
      T2,
    ]);
    assert.equal(formatT(new Date(AT)), T0, "and the first of them is the render instant");
  });
});

describe("a period grant at the edge counts", () => {
  test("an empty explicit label grant grants no period material, so the next article still needs an unlock", async () => {
    const { publisherRegistration, render } = await world();
    const cache = new PeriodKeyCache();
    const unsealer = new Client({ cache, publisherOrigin: ORIGIN });
    const endpoint = endpointGranting(publisherRegistration, []);

    const first = unsealer.parse(await render("123456", ARTICLE_A));
    const request = unsealer.buildRequest(first, ISSUER_NAME, ["bodytext"]);

    const { status, body } = await endpoint.unlock(request);
    assert.equal(status, 200);

    // An empty label list grants nothing: the presented group is answered
    // with no period field at all.
    assert.equal(body.keys.periodKeys, undefined, "a zero count delivers no period material");

    await unsealer.applyResponse(first, ISSUER_NAME, body);
    assert.equal((await cache.entries()).length, 0, "no period key was cached");
    assert.equal(
      (await cache.candidatesAt(GROUP, T0, { publisher: `https://${DOMAIN}` })).length,
      0,
      "the client holds nothing for the group",
    );

    // A second article of the same group cannot open from the cache: with no
    // period material the client would have to ask the issuer again.
    const second = unsealer.parse(await render("123457", ARTICLE_B));
    const { covered, missing } = await unsealer.resolve(second, ["bodytext"]);
    assert.deepEqual(covered, []);
    assert.deepEqual(missing, ["bodytext"], "the next article is still locked");
  });

  test("a malformed label list and retired count grant are refused as bad_policy", async () => {
    const { publisherRegistration, render } = await world();
    const page = await render("123456", ARTICLE_A);

    for (const invalidGrant of [
      { accessGroup: GROUP, periods: ["not-a-period"] },
      { accessGroup: GROUP, periodCount: 1 },
    ]) {
      const unsealer = new Client({ cache: new PeriodKeyCache(), publisherOrigin: ORIGIN });
      const dcaData = unsealer.parse(page);
      const processor = new IssuerProcessor(
        new IssuerEngine({
          operatingIssuerNames: [ISSUER_NAME],
          accessPolicy: { decide: () => ({ contentNames: [], periodGrants: [invalidGrant] }) },
        }),
        { periodKeyInput: true },
      );
      const endpoint = new UnlockEndpoint(processor);
      const request = unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
      const { status, body } = await unlockThroughAdmission(
        processor,
        endpoint,
        request,
        publisherRegistration,
      );
      assert.equal(body.error, "bad_policy", JSON.stringify(invalidGrant));
      assert.equal(status, 500, "malformed policy grant is a policy fault, not a grant");
    }
  });

  test("mutating the policy's requested-coordinate view cannot add a presented period", async () => {
    const { publisherRegistration, render } = await world();
    const unsealer = new Client({ cache: new PeriodKeyCache(), publisherOrigin: ORIGIN });
    const page = unsealer.parse(await render("123456", ARTICLE_A));
    const processor = new IssuerProcessor(
      new IssuerEngine({
        operatingIssuerNames: [ISSUER_NAME],
        accessPolicy: {
          decide(_claims, requested) {
            requested.periodCoordinates[GROUP].push("251023T1700");
            return {
              contentNames: [...requested.contentNames],
              periodGrants: [{ accessGroup: GROUP, periods: ["251023T1700"] }],
            };
          },
        },
      }),
      { periodKeyInput: true },
    );
    const endpoint = new UnlockEndpoint(processor);
    const request = unsealer.buildRequest(page, ISSUER_NAME, ["bodytext"]);
    const { status, body } = await unlockThroughAdmission(
      processor,
      endpoint,
      request,
      publisherRegistration,
    );

    assert.equal(status, 200);
    assert.equal(body.keys.periodKeys, undefined);
    assert.equal(body.errors, undefined);
  });
});

// A deployment may compose another representation of the period capability the
// policy granted. Base asks such a source once per granted group, before it
// opens a period key of that group: one granted capability reaches a client
// once. What the source does with the group is the source's own answer, so
// which representation a client gets is decided where the source is written and
// never by a flag this engine reads.
describe("a composed period-capability source", () => {
  /**
   * @param {object} publisherRegistration
   * @param {any} render
   * @param {import('../../core-issuer/IssuerEngine.js').PeriodCapabilitySource} [periodCapabilitySource]
   */
  async function unlockWith(publisherRegistration, render, periodCapabilitySource) {
    const unsealer = new Client({ cache: new PeriodKeyCache(), publisherOrigin: ORIGIN });
    const dcaData = unsealer.parse(await render("123456", ARTICLE_A));
    const document = unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
    const engine = new IssuerEngine({
      operatingIssuerNames: [ISSUER_NAME],
      accessPolicy: {
        /** @param {any} claims @param {{ contentNames: string[], accessGroups: string[] }} requested */
        decide(claims, requested) {
          void claims;
          return {
            contentNames: [],
            periodGrants: requested.accessGroups.map((accessGroup) => ({
              accessGroup,
              periods: [T0, T1],
            })),
          };
        },
      },
      periodCapabilitySource,
    });
    return engine.unlock(parseDcaRequest(JSON.stringify(document)), publisherRegistration);
  }

  /** A source that selects nothing anywhere, so every group keeps its period-key route. */
  const missingEverywhere = {
    selection: () => () => ({ miss: /** @type {true} */ (true) }),
    capabilities: () => async () => ({ periods: [] }),
  };

  test("a miss leaves the group to the period keys base would have opened anyway", async () => {
    const { publisherRegistration, render } = await world();

    const ordinary = await unlockWith(publisherRegistration, render);
    const missed = await unlockWith(publisherRegistration, render, missingEverywhere);

    assert.deepEqual(Object.keys(ordinary.periodKeys[GROUP]), [T0, T1]);
    assert.deepEqual(
      missed.periodKeys,
      ordinary.periodKeys,
      "the ordinary period-key grant is preserved",
    );
    assert.deepEqual(missed.capabilities, []);
  });

  test("a represented capability answers its group only under granted labels", async () => {
    const { publisherRegistration, render } = await world();

    const result = await unlockWith(publisherRegistration, render, {
      selection: () => () => ({
        selected: [{ t: T0 }, { t: T1 }],
      }),
      capabilities:
        () => async (/** @type {string} */ accessGroup, /** @type {any[]} */ selected) =>
          represented([
            { t: selected[0].t, bytes: new Uint8Array([1, 2, 3]) },
            {
              t: selected[1].t,
              error: { error: "unseal_failed", message: "sealed value could not be opened" },
            },
          ]),
    });

    assert.deepEqual(result.capabilities, [
      {
        kind: "test-capability",
        accessGroup: GROUP,
        entries: { [T0]: "AQID" },
        interpretation: TEST_INTERPRETATION,
      },
    ]);
    assert.deepEqual(result.periodKeys, {}, "no period key is opened beside the representation");
    assert.deepEqual(result.errors, {
      [`${GROUP}|${T1}`]: { error: "unseal_failed", message: "sealed value could not be opened" },
    });
  });

  test("an answer that is not the periods it selected is a composition fault", async () => {
    const { publisherRegistration, render } = await world();

    await assert.rejects(
      unlockWith(publisherRegistration, render, {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities: () => async () =>
          /** @type {any} */ ({ periods: [{ t: GROUP, bytes: "AQID" }] }),
      }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("a source may open only the coordinates it selected", async () => {
    const { publisherRegistration, render } = await world();

    // The granted count was counted from the selection, and the period-key route
    // stood down for it, so the selection is also the reach into the render.
    await assert.rejects(
      unlockWith(publisherRegistration, render, {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities:
          ({ open }) =>
          async (/** @type {string} */ accessGroup) => {
            await open("anything", { accessGroup, t: T1 });
            return represented([{ t: T0, bytes: new Uint8Array([1]) }]);
          },
      }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("a selected chain coordinate opens no period key at the same group and t", async () => {
    const { publisherRegistration, render } = await world();

    // An accessGroup and a t do not name a blob on their own. The
    // periodKey and the chain key at one coordinate are bound apart, and a
    // source that selected one of them selected one of them.
    await assert.rejects(
      unlockWith(publisherRegistration, render, {
        selection: () => () => ({ selected: [{ t: T0, chainKey: true }] }),
        capabilities:
          ({ open }) =>
          async (/** @type {string} */ accessGroup) => {
            await open("anything", { accessGroup, t: T0 });
            return represented([{ t: T0, bytes: new Uint8Array([1]) }]);
          },
      }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );

    await assert.rejects(
      unlockWith(publisherRegistration, render, {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities:
          ({ open }) =>
          async (/** @type {string} */ accessGroup) => {
            await open("anything", {
              accessGroup,
              suppliedT: T0,
              chainKey: true,
              chainsPerDay: 2,
              periodMinutes: 15,
            });
            return represented([{ t: T0, bytes: new Uint8Array([1]) }]);
          },
      }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("selected chain geometry is part of opening confinement", async () => {
    const { publisherRegistration, render } = await world();
    await assert.rejects(
      unlockWith(publisherRegistration, render, {
        selection: () => () => ({
          selected: [
            {
              t: T0,
              chainKey: true,
              chainsPerDay: 2,
              periodMinutes: 15,
            },
          ],
        }),
        capabilities:
          ({ open }) =>
          async (/** @type {string} */ accessGroup) => {
            await open("anything", {
              accessGroup,
              suppliedT: T0,
              chainKey: true,
              chainsPerDay: 4,
              periodMinutes: 15,
            });
            return represented([{ t: T0, bytes: new Uint8Array([1]) }]);
          },
      }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  /**
   * The same unlock as above, with the engine's sources and its policy chosen
   * by the caller, so a test can say which side of the seam presented a group.
   *
   * @param {object} publisherRegistration - what the engine is handed as the registration
   * @param {any} render
   * @param {object} composition
   * @param {{ decide: Function }} composition.accessPolicy
   * @param {any} [composition.contentKeySource]
   * @param {any} [composition.periodCapabilitySource]
   */
  async function unlockComposed(publisherRegistration, render, composition) {
    const unsealer = new Client({ cache: new PeriodKeyCache(), publisherOrigin: ORIGIN });
    const dcaData = unsealer.parse(await render("123456", ARTICLE_A));
    const document = unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
    const engine = new IssuerEngine(
      /** @type {any} */ ({ operatingIssuerNames: [ISSUER_NAME], ...composition }),
    );
    return engine.unlock(parseDcaRequest(JSON.stringify(document)), publisherRegistration);
  }

  /** A policy that grants one group a two-period reach and nothing else. */
  const grantingOnly = (/** @type {string} */ accessGroup) => ({
    decide: () => ({ contentNames: [], periodGrants: [{ accessGroup, periods: [T0, T1] }] }),
  });
  const independentGrantingOnly = (/** @type {string} */ accessGroup) => ({
    decide: () => ({
      contentNames: [],
      periodGrants: [{ accessGroup, futurePeriodCount: 2, authorizePeriod: () => true }],
    }),
  });

  /**
   * The same registration with its opening-key lookups counted, so a test can
   * say that a refusal never reached the key store.
   *
   * @param {any} publisherRegistration
   */
  function counted(publisherRegistration) {
    const lookups = { count: 0 };
    const registration = {
      ...publisherRegistration,
      openingKeys: {
        /** @param {string} issuerName @param {string} keyId */
        get(issuerName, keyId) {
          lookups.count++;
          return publisherRegistration.openingKeys.get(issuerName, keyId);
        },
      },
    };
    return { registration, lookups };
  }

  test("a source miss falls back to explicitly granted sealed period keys", async () => {
    const { publisherRegistration, render } = await world();
    const { registration, lookups } = counted(publisherRegistration);

    // The source misses, so the engine uses the explicitly granted ordinary
    // labels carried in the request.
    const result = await unlockComposed(registration, render, {
      accessPolicy: grantingOnly(GROUP),
      periodCapabilitySource: {
        presented: () => ({ accessGroups: [GROUP] }),
        ...missingEverywhere,
      },
    });
    assert.deepEqual(Object.keys(result.periodKeys[GROUP]), [T0, T1]);
    assert.equal(lookups.count, 1, "the period-key route opens only the granted labels");
  });

  test("an unavailable source route withholds period-key output without hiding the request", async () => {
    const { publisherRegistration, render } = await world();
    const { registration, lookups } = counted(publisherRegistration);
    let represented = 0;

    // The request carries valid period keys for this group. This composition
    // owns its period representation but selected none, so those period-key
    // values remain in the request without becoming an output route.
    const result = await unlockComposed(registration, render, {
      accessPolicy: grantingOnly(GROUP),
      periodCapabilitySource: {
        selection: () => () => ({ unavailable: true }),
        capabilities: () => {
          represented++;
          return async () => ({ periods: [] });
        },
      },
    });
    assert.deepEqual(result.periodKeys, {}, "authorized but unavailable supply returns no key");
    assert.deepEqual(result.notDelivered, {}, "the unavailable route supplies no reason");
    assert.equal(lookups.count, 0, "the no-key result reads no opening key");
    assert.equal(represented, 0, "an unavailable route is never asked to represent anything");
  });

  test("a family with no ordinary labels cannot gain period authorization from another source", async () => {
    const { publisherRegistration, render } = await world();

    // `ghost` reaches the policy through the content source's own grammar,
    // but it carries no ordinary period coordinates. A policy cannot turn
    // group visibility into period-key authority.
    await assert.rejects(
      unlockComposed(publisherRegistration, render, {
        accessPolicy: grantingOnly("ghost"),
        contentKeySource: {
          presented: () => ({ accessGroups: ["ghost"] }),
          contentKeys: () => async () => ({ miss: true }),
        },
        periodCapabilitySource: missingEverywhere,
      }),
      (/** @type {any} */ error) => error.code === "denied",
    );
  });

  test("a group counts what the source selected of it, and that is what is represented", async () => {
    const { publisherRegistration, render } = await world();

    const result = await unlockComposed(publisherRegistration, render, {
      accessPolicy: independentGrantingOnly("ghost"),
      periodCapabilitySource: {
        presented: () => ({ accessGroups: ["ghost"] }),
        selection: () => () => ({ selected: [{ t: T0 }, { t: T1 }] }),
        capabilities:
          () => async (/** @type {string} */ accessGroup, /** @type {any[]} */ selected) =>
            represented(selected.map(({ t }) => ({ t, bytes: new Uint8Array([1, 2, 3]) }))),
      },
    });

    assert.deepEqual(result.capabilities, [
      {
        kind: "test-capability",
        accessGroup: "ghost",
        entries: { [T0]: "AQID", [T1]: "AQID" },
        interpretation: TEST_INTERPRETATION,
      },
    ]);
    assert.deepEqual(result.periodKeys, {}, "the selected representation answers the group alone");
  });

  test("a selected coordinate that fails reports under its own label beside its siblings", async () => {
    const { publisherRegistration, render } = await world();

    const result = await unlockComposed(publisherRegistration, render, {
      accessPolicy: grantingOnly(GROUP),
      periodCapabilitySource: {
        selection: () => () => ({ selected: [{ t: T0 }, { t: T1 }] }),
        capabilities: () => async () =>
          represented([
            { t: T0, bytes: new Uint8Array([1, 2, 3]) },
            {
              t: T1,
              error: { error: "unseal_failed", message: "sealed value could not be opened" },
            },
          ]),
      },
    });

    assert.deepEqual(result.capabilities, [
      {
        kind: "test-capability",
        accessGroup: GROUP,
        entries: { [T0]: "AQID" },
        interpretation: TEST_INTERPRETATION,
      },
    ]);
    assert.deepEqual(
      result.periodKeys,
      {},
      "the group was represented, so no period key opens beside it",
    );
    assert.deepEqual(result.errors, {
      [`${GROUP}|${T1}`]: { error: "unseal_failed", message: "sealed value could not be opened" },
    });
  });

  test("a successful content-key seal suppresses the per-item source lookup", async () => {
    const { publisherRegistration, render } = await world();
    let lookups = 0;
    const result = await unlockComposed(publisherRegistration, render, {
      accessPolicy: { decide: () => ({ contentNames: ["bodytext"], periodGrants: [] }) },
      contentKeySource: {
        contentKeys: () => async () => {
          lookups++;
          return { miss: true };
        },
      },
    });

    assert.equal(base64urlDecode(result.contentKeys.bodytext).length, 16);
    assert.deepEqual(result.errors, {});
    assert.equal(lookups, 0, "constructing the lookup does not ask it for this content key");
  });

  test("a source answer naming two alternatives at once is a composition fault", async () => {
    const { publisherRegistration, render } = await world();
    const failure = { error: "unseal_failed", message: "sealed value could not be opened" };

    /** @param {any} composition */
    const refused = (composition) =>
      assert.rejects(
        unlockComposed(publisherRegistration, render, {
          accessPolicy: grantingOnly(GROUP),
          ...composition,
        }),
        (/** @type {any} */ error) => error.code === "bad_config",
      );

    // A selection that both misses and selects, a period carrying bytes and
    // an error, a content key carrying bytes and an error, and a failure
    // that is not a failure. Each names two answers where one item has one.
    await refused({
      periodCapabilitySource: {
        selection: () => () => ({ miss: true, selected: [{ t: T0 }] }),
        capabilities: () => async () => ({ periods: [{ t: T0, bytes: new Uint8Array([1]) }] }),
      },
    });
    await refused({
      periodCapabilitySource: {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities: () => async () => ({
          periods: [{ t: T0, bytes: new Uint8Array([1]), error: failure }],
        }),
      },
    });
    await refused({
      periodCapabilitySource: {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities: () => async () => ({
          periods: [{ t: T0, error: { error: "unseal_failed" } }],
        }),
      },
    });
    await refused({
      // A name only the source presents carries no content-key seal, so the
      // source is the one asked for it.
      accessPolicy: { decide: () => ({ contentNames: ["ghost-content"], periodGrants: [] }) },
      contentKeySource: {
        presented: () => ({ contentNames: ["ghost-content"] }),
        contentKeys: () => async () => ({ bytes: new Uint8Array([1]), error: failure }),
      },
    });
  });

  test("a retired opening key asks no period source and reports every selected period key", async () => {
    const { publisherRegistration, render } = await world();
    const retired = { ...publisherRegistration, openingKeys: { get: () => ({ retired: true }) } };
    let asked = 0;

    const result = await unlockComposed(retired, render, {
      accessPolicy: grantingOnly(GROUP),
      periodCapabilitySource: {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities: () => async () => {
          asked++;
          return represented([{ t: T0, bytes: new Uint8Array([1, 2, 3]) }]);
        },
      },
    });

    assert.equal(asked, 0, "a let-go key ends this issuer reach into the render on both seams");
    assert.deepEqual(result.capabilities, []);
    assert.deepEqual(result.errors, {
      [`${GROUP}|${T0}`]: {
        error: "key_retired",
        message: `keyId "${KEY_ID}" is retired and this issuer no longer holds it`,
      },
    });
  });

  test("a policy grant for an unpresented group cannot make a source select or answer it", async () => {
    const { publisherRegistration, render } = await world();
    const { registration, lookups } = counted(publisherRegistration);
    let selections = 0;
    let representations = 0;

    await assert.rejects(
      unlockComposed(registration, render, {
        accessPolicy: grantingOnly("ghost"),
        periodCapabilitySource: {
          selection: () => () => {
            selections++;
            return { selected: [{ t: T0 }] };
          },
          capabilities: () => async () => {
            representations++;
            return { periods: [{ t: T0, bytes: new Uint8Array([1]) }] };
          },
        },
      }),
      (/** @type {any} */ error) => error.code === "denied",
    );
    assert.equal(selections, 0, "policy cannot add a group to the presented request");
    assert.equal(representations, 0, "an unselected group cannot produce a response");
    assert.equal(lookups.count, 0, "complete denial precedes the opening-key store");
  });

  test("an empty selection cannot stand down period keys in a mixed grant", async () => {
    const { publisherRegistration, render } = await world();
    const { registration, lookups } = counted(publisherRegistration);

    await assert.rejects(
      unlockComposed(registration, render, {
        accessPolicy: {
          decide: () => ({
            contentNames: ["bodytext"],
            periodGrants: [{ accessGroup: GROUP, periods: [T0, T1] }],
          }),
        },
        periodCapabilitySource: {
          selection: () => () => ({ selected: [] }),
          capabilities: () => async () => ({ periods: [{ t: T0, bytes: new Uint8Array([1]) }] }),
        },
      }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.equal(
      lookups.count,
      0,
      "the invalid route is refused before content-key or period-key material opens",
    );
  });

  test("a source cannot replace the verified render anchor on an allowed coordinate", async () => {
    const { publisherRegistration, render } = await world();
    const ordinary = await unlockWith(publisherRegistration, render);

    const result = await unlockComposed(publisherRegistration, render, {
      accessPolicy: grantingOnly(GROUP),
      periodCapabilitySource: {
        selection: () => () => ({ selected: [{ t: T0 }] }),
        capabilities:
          ({ request, open }) =>
          async (/** @type {string} */ accessGroup) => {
            const family = /** @type {any} */ (request).sealedPeriodKeys[accessGroup];
            const opened = await open(family[T0], {
              accessGroup,
              t: T0,
              renderId: "AAAAAAAAAAAAAAAAAAAAAA",
            });
            return represented([
              "bytes" in opened ? { t: T0, bytes: opened.bytes } : { t: T0, error: opened.error },
            ]);
          },
      },
    });

    assert.deepEqual(
      result.capabilities,
      [
        {
          kind: "test-capability",
          accessGroup: GROUP,
          entries: { [T0]: ordinary.periodKeys[GROUP][T0] },
          interpretation: TEST_INTERPRETATION,
        },
      ],
      "the genuine blob opens under the signed renderId, not the source-supplied property",
    );
    assert.deepEqual(result.errors, {});
  });

  test("presented coordinates are lists of names before policy or key lookup", async () => {
    const { publisherRegistration, render } = await world();

    const cases = [
      {
        label: "content source contentNames string",
        contentKeySource: {
          presented: () => ({ contentNames: "ghost" }),
          contentKeys: () => async () => ({ miss: true }),
        },
      },
      {
        label: "content source contentNames member",
        contentKeySource: {
          presented: () => ({ contentNames: [null] }),
          contentKeys: () => async () => ({ miss: true }),
        },
      },
      {
        label: "content source accessGroups string",
        contentKeySource: {
          presented: () => ({ accessGroups: "ghost" }),
          contentKeys: () => async () => ({ miss: true }),
        },
      },
      {
        label: "content source accessGroups member",
        contentKeySource: {
          presented: () => ({ accessGroups: [null] }),
          contentKeys: () => async () => ({ miss: true }),
        },
      },
      {
        label: "period source accessGroups string",
        periodCapabilitySource: {
          presented: () => ({ accessGroups: "ghost" }),
          ...missingEverywhere,
        },
      },
      {
        label: "period source accessGroups member",
        periodCapabilitySource: {
          presented: () => ({ accessGroups: [null] }),
          ...missingEverywhere,
        },
      },
    ];

    for (const { label, ...source } of cases) {
      const { registration, lookups } = counted(publisherRegistration);
      const policy = {
        calls: 0,
        decide() {
          this.calls++;
          return {};
        },
      };
      await assert.rejects(
        unlockComposed(registration, render, { accessPolicy: policy, ...source }),
        (/** @type {any} */ error) => error.code === "bad_config",
        label,
      );
      assert.equal(policy.calls, 0, `${label}: policy was not asked`);
      assert.equal(lookups.count, 0, `${label}: opening-key store was not reached`);
    }
  });

  test("a selected coordinate outside the binding grammar is a composition fault", async () => {
    const { publisherRegistration, render } = await world();
    const { registration, lookups } = counted(publisherRegistration);
    let represented = 0;

    await assert.rejects(
      unlockComposed(registration, render, {
        accessPolicy: grantingOnly(GROUP),
        periodCapabilitySource: {
          selection: () => () => ({ selected: [{ t: `${T0}|x` }] }),
          capabilities: () => async () => {
            represented++;
            return { periods: [{ t: T0, bytes: new Uint8Array([1]) }] };
          },
        },
      }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.equal(lookups.count, 0, "selection-coordinate validation precedes opening-key lookup");
    assert.equal(represented, 0, "the invalid coordinate never reaches representation");
  });

  test("a represented label outside its coordinate grammar, or filed twice, is a composition fault", async () => {
    // What a source represents is filed into `keys` and into `errors` under
    // the label it names, and a client reads those names as coordinates. A
    // label that names no period coordinate of the kind it is filed as, or a
    // coordinate filed both as a key and as an error, is not a result an
    // issuer may send, whatever a client would make of it.
    const { publisherRegistration, render } = await world();
    const failure = { error: "unseal_failed", message: "sealed value could not be opened" };
    const keyBytes = new Uint8Array(16).fill(1);
    const chainAt = { t: "251023T1400", chainKey: true, chainsPerDay: 2, periodMinutes: 15 };

    const cases = [
      {
        label: "a key label carrying the delimiter",
        selected: [{ t: T0 }],
        answer: represented([{ t: "a|b", bytes: keyBytes }]),
      },
      {
        label: "an empty error label, which would file the group-only `premium|`",
        selected: [{ t: T0 }],
        answer: represented([
          { t: T0, bytes: keyBytes },
          { t: "", error: failure },
        ]),
      },
      {
        label: "one coordinate filed as a key and as an error",
        selected: [{ t: T0 }],
        answer: represented([
          { t: T0, bytes: keyBytes },
          { t: T0, error: failure },
        ]),
      },
      {
        label: "a period key under a label the period-key grammar refuses",
        selected: [{ t: T0 }],
        answer: {
          kind: "period-keys",
          interpretation: {},
          periods: [{ t: `${GROUP}-2`, bytes: keyBytes }],
        },
      },
      {
        label: "a chain-selected group answered under a label that is no chain position",
        selected: [chainAt],
        answer: represented([{ t: "251023T1401", bytes: keyBytes }]),
      },
    ];

    const outcomes = [];
    for (const { label, selected, answer } of cases) {
      try {
        const result = await unlockComposed(publisherRegistration, render, {
          accessPolicy: grantingOnly(GROUP),
          periodCapabilitySource: {
            selection: () => () => ({ selected }),
            capabilities: () => async () => answer,
          },
        });
        outcomes.push({
          label,
          filed: {
            periodKeys: result.periodKeys,
            entries: result.capabilities.map((/** @type {any} */ c) => c.entries),
            errors: Object.keys(result.errors),
          },
        });
      } catch (error) {
        outcomes.push({ label, code: /** @type {any} */ (error).code });
      }
    }

    assert.deepEqual(
      outcomes,
      cases.map(({ label }) => ({ label, code: "bad_config" })),
    );
  });

  test("unreadable periodGrants are policy faults before opening-key lookup", async () => {
    const { publisherRegistration, render } = await world();

    for (const periodGrants of ["premium", [null], [{ periodCount: 1 }]]) {
      const { registration, lookups } = counted(publisherRegistration);
      const policy = {
        calls: 0,
        decide() {
          this.calls++;
          return { contentNames: [], periodGrants };
        },
      };
      await assert.rejects(
        unlockComposed(registration, render, { accessPolicy: policy }),
        (/** @type {any} */ error) => error.code === "bad_policy",
      );
      assert.equal(policy.calls, 1, `${JSON.stringify(periodGrants)}: policy was asked once`);
      assert.equal(lookups.count, 0, `${JSON.stringify(periodGrants)}: no opening key was reached`);
    }
  });
});
