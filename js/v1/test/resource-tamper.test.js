//
// `resourceJWT` is the sole protocol source of resource claims. A page may keep
// a readable `resource` copy for diagnostics, but the client never sends it and
// the issuer never consumes it. These tests prove both sides of that boundary:
// mutating a page-local copy cannot move an unlock outcome, and a supplied
// legacy `resource` member is ignored.
//
// The application selects one publisher registration by exact JWT-header kid.
// Its canonical origin and scoped opening-key view are issuer-owned context;
// verified payload claims, requested coordinates and that context are the only
// policy inputs, and verified renderId anchors every BIND value.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { ALL_PERIODS } from "../demo/support/AccessPolicy.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";
import { sign, verify } from "../core-shared--publisher-issuer/jwt.js";
import { utf8Decode } from "../core-shared/codec.js";
import { actorWorld } from "../demo/scenarios/world.js";
import { rootFromPage } from "../demo/support/queryableRoot.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import {
  ARTICLES as TEXT,
  CONTENT_NAME as BODYTEXT,
  CONTENT_TYPE,
  DOMAIN,
  ISSUER_NAME as CLAIMS,
  RESOURCE_ID,
  SIGNING_KID,
  UNLOCK_URL as CLAIMS_UNLOCK,
} from "../demo/scenarios/fixtures.js";
import { requestFor } from "../test-lib/harnesses/issuer-endpoint.js";

/** The second publisher on this issuer's books. The fixtures name one host. */
const OTHER_DOMAIN = "www.other-paper.example";
const OTHER_SIGNING_KID = `${SIGNING_KID}-other`;
const PUBLISHER_ORIGIN = `https://${DOMAIN}`;

/**
 * The vaulted item's name, and the two accessGroups. `PREMIUM` is a contentName
 * here and not the fixtures' accessGroup of the same spelling: a tamper has to
 * cost the reader a whole item, so a render needs a second one to lose.
 */
const PREMIUM = "premium";
const ARTICLE_GROUP = "article";
const VAULT_GROUP = "premium-vault";

/**
 * Two items per render, one open and one vaulted, so a decision that narrows is
 * visible as a missing item. `article()` appends the items it is given after a
 * bodytext in the entitled family; here the bodytext is the open one, so the
 * list is written out.
 */
const ARTICLES = {
  A: {
    resourceId: RESOURCE_ID,
    [BODYTEXT]: TEXT.A,
    [PREMIUM]: "<p>Two councillors hold shares in the developer.</p>",
  },
  B: {
    resourceId: "123457",
    [BODYTEXT]: TEXT.B,
    [PREMIUM]: "<p>The second reading was moved twice already.</p>",
  },
};

/** What every request here asks for: the open item and the vaulted one. */
const NAMES = [BODYTEXT, PREMIUM];

/** The publisher-defined metadata an access decision is allowed to branch on. */
const DATA = { section: "politics", tier: "premium" };

/**
 * One decision over the verified resource and the requested coordinate names.
 *
 * `bodytext` and its accessGroup are open to anyone who asks; the vault needs
 * the render to be one this issuer was told about, in every field, and a caller
 * holding the entitlement.
 *
 * @param {any} resource
 * @param {{ contentNames: string[], accessGroups: string[] }} requested
 * @param {any} input
 * @param {Map<string, any>} manifest
 * @returns {{ contentNames: string[], periodGrants: { accessGroup: string, periodCount: number }[], policyData: object[] }}
 */
function decideFrom(resource, requested, input, manifest) {
  const entitlements = input?.principal?.entitlements ?? [];
  const enrolled = manifest.get(resource?.renderId);

  const open =
    enrolled !== undefined &&
    resource?.resourceId === enrolled.resourceId &&
    resource?.issuedAt === enrolled.issuedAt &&
    resource?.data?.section === enrolled.section &&
    resource?.data?.tier === enrolled.tier &&
    entitlements.includes("premium");

  return {
    contentNames: requested.contentNames.filter((name) => name === BODYTEXT || open),
    // Each granted family in full: `ALL_PERIODS` is clamped by the engine to
    // the periods the request carried.
    periodGrants: requested.accessGroups
      .filter((name) => name === ARTICLE_GROUP || open)
      .map((accessGroup) => ({ accessGroup, periodCount: ALL_PERIODS })),
    policyData: [],
  };
}

/**
 * The policy and the log of its complete input. There is no request object in
 * this call for a policy to read by mistake.
 *
 * @param {Map<string, any>} manifest
 */
function policyFor(manifest) {
  /** @type {any[]} */
  const seen = [];

  return {
    seen,
    policy: {
      /**
       * @param {any} claims
       * @param {{ contentNames: string[], accessGroups: string[] }} requested
       * @param {any} input
       */
      decide(claims, requested, input) {
        seen.push({ verified: claims.resource, requested, input });
        return decideFrom(claims.resource, requested, input, manifest);
      },
    },
  };
}

/**
 * One world: two publishers on one issuer's books, with access decided from
 * verified claims.
 *
 * Two signing keypairs, one per domain, because the swapped-domain case below
 * needs a key this issuer really holds and that belongs to somebody else: the
 * lookup hits, and the signature is what fails. Both publishers happen to name
 * their current key the same thing, each rotating on its own schedule, which is
 * what makes the swap select a key rather than miss the lookup.
 *
 * @returns {Promise<any>}
 */
async function world() {
  /** @type {Map<string, any>} */
  const manifest = new Map();
  const { seen, policy } = policyFor(manifest);

  const stage = await actorWorld({
    signingKids: { [DOMAIN]: [SIGNING_KID], [OTHER_DOMAIN]: [OTHER_SIGNING_KID] },
    accessPolicy: policy,
  });

  const servers = { claims: stage.servers.primary };

  /** @type {Record<string, import('../demo/support/IssuerKeyStore.js').IssuerKeyStore>} */
  const keyStores = { [CLAIMS]: stage.keyStores.primary };

  /**
   * How often the issuer's private key was reached for.
   *
   * @returns {number}
   */
  const reaches = () => keyStores[CLAIMS].reachCount;

  /**
   * A publisher per domain, each built on the first render it makes and kept,
   * so both of them seal for the issuer.
   *
   * @type {Record<string, any>}
   */
  const publishing = {};

  /**
   * @param {'A'|'B'} label
   * @param {{ publisher?: string }} [options]
   * @returns {Promise<import('../demo/support/Page.js').Page>}
   */
  const render = (label, options = {}) => {
    const domain = options.publisher ?? DOMAIN;
    publishing[domain] ??= stage.publisherWith({ domain });
    return publishing[domain].render({
      resourceId: ARTICLES[label].resourceId,
      data: { ...DATA },
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
    });
  };

  /**
   * What the publisher told the issuer about a render, out of band. Keyed by
   * renderId and holding every other field the decision reads.
   *
   * @param {import('../demo/support/Page.js').Page} page
   * @returns {any} the render's resource, as the page ships it
   */
  const enrol = (page) => {
    const resource = page.asJson().resource;
    manifest.set(resource.renderId, {
      resourceId: resource.resourceId,
      issuedAt: resource.issuedAt,
      section: resource.data.section,
      tier: resource.data.tier,
    });
    return resource;
  };

  servers.claims.grant("alice", { entitlements: ["premium"] });

  const { clock, network, signingKeyPairs, publisherRegistration, makeBrowser } = stage;
  return {
    clock,
    network,
    servers,
    signingKeyPairs,
    publisherRegistration,
    render,
    enrol,
    seen,
    reaches,
    makeBrowser,
  };
}

/**
 * @param {any} network
 * @param {string} url
 * @param {any} request
 * @returns {Promise<{ status: number, body: any }>}
 */
function post(network, url, request) {
  return network.post(url, request, { credential: "alice", origin: PUBLISHER_ORIGIN });
}

describe("A supplied legacy resource member, tampered in turn", () => {
  test("every supplied legacy resource field is ignored and the grant does not move", async () => {
    const { network, servers, signingKeyPairs, render, enrol, seen, reaches } = await world();

    const page = await render("A");
    const other = await render("B");
    const shipped = enrol(page);
    const otherResource = enrol(other);

    // The claims the decision is entitled to read: the signed payload.
    const signed = await verify(
      page.asJson().resourceJWT,
      signingKeyPairs[DOMAIN][SIGNING_KID].publicKey,
    );
    assert.deepEqual(
      signed,
      shipped,
      "the diagnostic page copy starts equal to the signed payload",
    );

    const clean = requestFor(page, CLAIMS, NAMES);
    const baseline = await post(network, CLAIMS_UNLOCK, clean);

    assert.equal(baseline.status, 200);
    assert.deepEqual(Object.keys(baseline.body.keys.contentKeys), NAMES);
    assert.deepEqual(Object.keys(baseline.body.keys.periodKeys), [ARTICLE_GROUP, VAULT_GROUP]);
    assert.equal(baseline.body.errors, undefined);

    /** @type {[string, any][]} */
    const cases = [
      ["resourceId", { ...shipped, resourceId: "999999" }],
      ["renderId", { ...shipped, renderId: otherResource.renderId }],
      ["issuedAt", { ...shipped, issuedAt: "2001-01-01T00:00:00Z" }],
      ["data.section", { ...shipped, data: { ...shipped.data, section: "sport" } }],
      ["data.tier", { ...shipped, data: { ...shipped.data, tier: "free" } }],
      ["the whole data object", { ...shipped, data: {} }],
      ["an entitlement the client wrote itself", { ...shipped, entitlements: ["premium"] }],
    ];

    for (const [name, resource] of cases) {
      const request =
        resource === undefined ? structuredClone(clean) : { ...structuredClone(clean), resource };
      const answer = await post(network, CLAIMS_UNLOCK, request);

      // The whole answer, not a summary of it: same status, same keys,
      // same bytes, same absence of errors.
      assert.deepEqual(answer, baseline, name);

      // Policy sees signed claims and requested names, never the
      // supplied legacy resource object.
      const call = seen.at(-1);
      assert.deepEqual(
        call.verified,
        signed,
        `${name}: the verified payload is the one the publisher signed`,
      );
      assert.deepEqual(call.requested, {
        contentNames: NAMES,
        accessGroups: [ARTICLE_GROUP, VAULT_GROUP],
      });
      assert.deepEqual(Object.keys(call).sort(), ["input", "requested", "verified"]);
    }

    // Every answer was made rather than remembered: no response cache is
    // configured, and each post reached the policy and the key store.
    assert.equal(servers.claims.stats().requests, cases.length + 1);
    assert.equal(seen.length, cases.length + 1);
    assert.equal(reaches(), cases.length + 1);
    assert.equal(
      servers.claims.stats().denials,
      0,
      "a tampered diagnostic copy is not a refusal; nobody reads it",
    );
  });

  test("the same tamper on a live unlock leaves the article the client reads unchanged", async () => {
    const { render, enrol, makeBrowser } = await world();

    const page = await render("A");
    enrol(page);

    /**
     * The whole client story, driven a step at a time rather than through
     * `readArticle`: the tamper has to land on the client's own copy of the
     * resource between the load and the unlock, and that seam is what a
     * one-call read has no room for.
     *
     * @param {(resource: any) => void} [tamper]
     */
    const read = async (tamper) => {
      const load = makeBrowser().load(rootFromPage(page));
      if (tamper) tamper(load.dcaData.resource);

      const unlock = await load.unlock({ issuerName: CLAIMS, credential: "alice" });

      /** @type {Record<string, string|null>} */
      const texts = {};
      for (const name of NAMES) {
        const { bytes } = await load.open(name);
        texts[name] = bytes === null ? null : utf8Decode(bytes);
      }
      return { status: unlock.status, texts };
    };

    const straight = await read();
    assert.equal(straight.status, 200);
    assert.equal(straight.texts[PREMIUM], ARTICLES.A[PREMIUM]);

    for (const tamper of [
      (/** @type {any} */ resource) => {
        resource.resourceId = "999999";
      },
      (/** @type {any} */ resource) => {
        resource.renderId = "AAAAAAAAAAAAAAAA";
      },
      (/** @type {any} */ resource) => {
        resource.data = { section: "sport", tier: "free" };
      },
    ]) {
      assert.deepEqual(await read(tamper), straight);
    }
  });
});

describe("Page-local diagnostic resource data is not a protocol input", () => {
  test("a missing, poisoned or disagreeing diagnostic copy leaves the token-selected outcome unchanged", async () => {
    const { network, servers, publisherRegistration, render, enrol, seen, reaches } = await world();

    const page = await render("A");
    enrol(page);

    const clean = requestFor(page, CLAIMS, NAMES);
    const decisions = seen.length;
    const keyStoreReads = reaches();

    const expected = await post(network, CLAIMS_UNLOCK, clean);
    assert.equal(expected.status, 200);

    for (const request of [
      (() => {
        const r = structuredClone(clean);
        delete r.resource;
        return r;
      })(),
      { ...clean, resource: null },
      { ...clean, resource: { domain: OTHER_DOMAIN, renderId: "poisoned" } },
    ]) {
      const answer = await post(network, CLAIMS_UNLOCK, request);
      assert.deepEqual(answer.body, expected.body);
    }
    assert.equal(
      seen.length,
      decisions + 4,
      "every accepted request reaches policy under verified claims",
    );
    assert.equal(
      reaches(),
      keyStoreReads + 4,
      "every accepted request reaches private work normally",
    );
    assert.equal(servers.claims.stats().denials, 0);
    assert.equal(servers.claims.stats().grants, 4);

    // The engine's own answer, under the class the port maps from.
    const engine = new IssuerEngine({
      accessPolicy: new AllowAllPolicy(),
    });
    await assert.doesNotReject(() =>
      engine.unlock(
        new DcaRequest({ ...clean, resource: { renderId: "poisoned" } }),
        publisherRegistration,
      ),
    );
  });

  test("a foreign signer cannot forge a payload under this page's registered kid", async () => {
    const { network, signingKeyPairs, render, enrol, seen, reaches } = await world();
    const page = await render("A");
    enrol(page);

    const clean = requestFor(page, CLAIMS, NAMES);
    const forgedJWT = await sign(
      { ...page.asJson().resource, resourceId: "forged-but-same-domain" },
      signingKeyPairs[OTHER_DOMAIN][OTHER_SIGNING_KID].privateKey,
      { kid: SIGNING_KID },
    );
    const forged = { ...clean, resourceJWT: forgedJWT };
    const decisions = seen.length;
    const keyStoreReads = reaches();

    const answer = await post(network, CLAIMS_UNLOCK, forged);
    assert.equal(answer.status, 400);
    assert.equal(answer.body.error, "bad_signature");
    assert.equal(seen.length, decisions);
    assert.equal(reaches(), keyStoreReads);
  });

  test("a foreign kid selects a key the token was not signed with, and is refused before policy", async () => {
    const { network, signingKeyPairs, render, enrol, seen, reaches } = await world();
    const page = await render("A");
    enrol(page);

    const clean = requestFor(page, CLAIMS, NAMES);
    const mismatchedJWT = await sign(
      { ...page.asJson().resource, resourceId: "mismatched-kid" },
      signingKeyPairs[DOMAIN][SIGNING_KID].privateKey,
      { kid: OTHER_SIGNING_KID },
    );
    const mismatched = { ...clean, resourceJWT: mismatchedJWT };
    const decisions = seen.length;
    const keyStoreReads = reaches();

    // The kid is a locator, so it selects the other publisher's
    // registration; that registration's verification key is not the one
    // this token was signed with, and the signature is what says so. The
    // signed origin is never reached, because there is no verified payload
    // to read one out of.
    const answer = await post(network, CLAIMS_UNLOCK, mismatched);
    assert.equal(answer.status, 400);
    assert.equal(answer.body.error, "bad_signature");
    assert.equal(answer.body.keys, undefined);
    assert.equal(answer.body.errors, undefined);
    assert.equal(seen.length, decisions, "the refusal is ahead of policy");
    assert.equal(reaches(), keyStoreReads, "and ahead of private work");
  });
});

describe("The decision inputs that are not on the resource object at all", () => {
  test("the version and the accessGroup list are unsigned too, and neither widens a grant", async () => {
    const { network, servers, render, enrol, seen, reaches } = await world();

    const page = await render("A");
    enrol(page);

    const clean = requestFor(page, CLAIMS, NAMES);
    const decisions = seen.length;
    const keyStoreReads = reaches();

    // The resourceJWT payload has no version in it, so there is no verified
    // version an access decision could read. One this issuer cannot read is
    // refused whole, before there is anything to decide about.
    const versioned = await post(network, CLAIMS_UNLOCK, { ...clean, version: "2" });
    assert.equal(versioned.status, 400);
    assert.equal(versioned.body.error, "bad_version");

    // The accessGroups a decision runs over are the keys of
    // `sealed.periodKeys` - the client's own list, and this caller is
    // entitled to everything on it, so the policy says yes to the invented
    // group as readily as to the real ones. What the list cannot do is carry
    // a blob to a coordinate it was not sealed at: the vault's periodKeys
    // are bound to `premium-vault`, and under `premium-vault-2` they open
    // nothing.
    const invented = structuredClone(clean);
    invented.sealed.periodKeys["premium-vault-2"] = { ...clean.sealed.periodKeys[VAULT_GROUP] };

    const widened = await post(network, CLAIMS_UNLOCK, invented);
    assert.equal(widened.status, 200);
    assert.deepEqual(Object.keys(widened.body.keys.periodKeys), [ARTICLE_GROUP, VAULT_GROUP]);
    assert.deepEqual(
      Object.keys(widened.body.errors),
      Object.keys(clean.sealed.periodKeys[VAULT_GROUP]).map((t) => `premium-vault-2|${t}`),
    );
    for (const failure of Object.values(widened.body.errors)) {
      assert.equal(/** @type {any} */ (failure).error, "unseal_failed");
    }

    // The version was refused before there was a decision to make; the
    // widened list was decided on and then failed at the private key, one
    // blob at a time. So the policy and the key store were each reached once
    // more, and neither request is a denial - nothing this caller asked for
    // was withheld on entitlement.
    assert.equal(seen.length, decisions + 1);
    assert.equal(reaches(), keyStoreReads + 1);
    assert.equal(servers.claims.stats().denials, 0);

    // Dropping one is the legal direction, and it narrows what comes back
    // rather than being refused: a client that resolved the vault from its
    // cache sends the group it still needs.
    const fewer = structuredClone(clean);
    delete fewer.sealed.periodKeys[VAULT_GROUP];

    const narrowed = await post(network, CLAIMS_UNLOCK, fewer);
    assert.equal(narrowed.status, 200);
    assert.deepEqual(Object.keys(narrowed.body.keys.periodKeys), [ARTICLE_GROUP]);
    assert.deepEqual(Object.keys(narrowed.body.keys.contentKeys), NAMES);
  });
});
