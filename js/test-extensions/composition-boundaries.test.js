// @ts-check
//
// An optional mixed setup in one delivery: gzip through `CompressingSealer`, an ordinary
// item key, a stock chain-key family and a content-group chain, read by
// `createBrowserClient` over the HTML carrier (`domOver` is a string harness,
// not a browser). The client nests `ContentGroupRequestBuilder` over the stock
// chain builder through its `innerBuilder` option: hand composition of a public
// option, documented in the content-groups README. The issuer is that README's
// base-engine recipe, not a stock convenience entry. The client-bound case calls
// the core and `KeyDelivery` directly, so it skips the browser Origin and kid
// admission that `createBrowserIssuer` gives the direct case.

import test from "node:test";
import assert from "node:assert/strict";

import { composePublisherConfig } from "../core-publisher/publisherComposition.js";
import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { KeyDelivery } from "../adapter-issuer/KeyDelivery.js";
import { createIssuerCore } from "../integration-issuer/createIssuerCore.js";
import { createBrowserIssuer } from "../integration-issuer/createBrowserIssuer.js";
import { createBrowserClient } from "../integration-client/createBrowserClient.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";
import { utf8Decode } from "../core-shared/codec.js";
import { domOver } from "../test-lib/helpers/domOver.js";
import { CompressingSealer } from "../extensions/content-compression/core-publisher/CompressingSealer.js";
import { decoders } from "../extensions/content-compression/core-shared--client-publisher/gzipCodec.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { chainKeyRequestBuilderFactory } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import { requireChainRepresentation } from "../extensions/chain-keys/core-issuer/chainKeyIssuerEngine.js";
import { chainKeyCapabilitySource } from "../extensions/chain-keys/core-issuer/chainKeyCapabilitySource.js";
import { chainKeyCapabilityEncoderFor } from "../extensions/chain-keys/core-issuer/chainKeyCapabilityEncoder.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilyContribution } from "../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import * as ecdhMethod from "../extensions/client-bound-transport/ecdhP256.js";
import { clientBoundKeyCapability } from "../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";
import { contentGroupsProfile } from "../extensions/content-groups/referenceProfile.js";
import {
  CHAIN,
  GEOMETRY,
  SECRET,
  T12,
  T18,
  UNLOCK,
} from "../extensions/content-groups/test/_lib/world.js";

const subtle = globalThis.crypto.subtle;
const ORIGIN = "https://news.example";
const AT = "2026-10-14T14:20:00Z";
const random = {
  bytes: (/** @type {number} */ n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
};

/** Repeated so gzip has something to shrink. @param {string} label */
const body = (label) => `<p>${`${label} `.repeat(30)}</p>`;
const ITEMS = [
  { name: "headline", value: body("headline"), contentType: "text/html" },
  { name: "lockedAd", value: body("locked ad"), contentType: "text/html" },
  {
    name: "bodytext",
    value: body("premium body"),
    contentType: "text/html",
    accessGroups: ["premium"],
  },
  {
    name: "sportsNews",
    value: body("sports"),
    contentType: "text/html",
    contentGroups: ["sports"],
  },
  {
    name: "politicsNews",
    value: body("politics"),
    contentType: "text/html",
    contentGroups: ["politics"],
  },
];
const NAMES = ITEMS.map((item) => item.name);
const OPENS = ["headline", "bodytext", "sportsNews"];
const CLOSED = ["lockedAd", "politicsNews"];

/** One publisher, issuer endpoint and set of reader caches; `bound` selects client-bound ECDH. */
async function setup(/** @type {boolean} */ bound) {
  const signing = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const opening = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const config = composePublisherConfig(
    /** @type {any} */ ({
      origin: ORIGIN,
      clock: { now: () => new Date(AT) },
      random,
      signingKeys: { p1: signing.privateKey },
      issuers: [
        {
          issuerName: "issuerA",
          keyId: "issuerA-k1",
          algorithm: "ecdh-p256",
          publicKey: opening.publicKey,
        },
      ],
      issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ page) => ({
        contentKeyNames: page.contentNames.filter((/** @type {string} */ n) =>
          ["headline", "lockedAd"].includes(n),
        ),
        suppliedAccessGroups: [...page.accessGroups],
        periodKeyDelivery: Object.fromEntries(
          page.accessGroups.map((/** @type {string} */ g) => [g, ["chain-keys"]]),
        ),
      }),
    }),
    periodFamilyContribution({
      families: {
        premium: periodFamilyGeneration({
          keyDerivationSecret: new Uint8Array(32).fill(7),
          geometry: GEOMETRY,
        }),
      },
      chainWindows: 2,
    }),
    contentGroupsProfile.publisherContribution({
      retainedSecret: SECRET,
      periodGeometry: GEOMETRY,
      issuerSeedWindows: { issuerA: { sportsNews: [T12], politicsNews: [T12] } },
      chain: CHAIN,
    }),
  ).config;

  /** @param {string} resourceId */
  async function render(resourceId) {
    const sealer = new CompressingSealer(config);
    sealer.resource(resourceId, {});
    for (const { name, value, contentType, ...options } of ITEMS)
      sealer.content(name, value, contentType, options);
    return sealer.seal();
  }

  // Grants change between steps: the reset step denies everything.
  const grants = { premium: true, sports: true, politics: false, buy: ["headline"] };
  const chainSource = chainKeyCapabilitySource({ representation: "chain-keys" });
  const core = createIssuerCore(
    /** @type {any} */ ({
      operatingIssuerNames: ["issuerA"],
      accessPolicy: {
        decide: (/** @type {any} */ _claims, /** @type {any} */ requested) => ({
          contentNames: requested.contentNames.filter((/** @type {string} */ n) =>
            grants.buy.includes(n),
          ),
          periodGrants: requested.accessGroups
            .filter((/** @type {string} */ g) => grants[/** @type {"premium"} */ (g)])
            .map((/** @type {string} */ accessGroup) => ({
              accessGroup,
              futurePeriodCount: 2,
              authorizePeriod: () => true,
            })),
        }),
      },
      periodCapabilitySource: requireChainRepresentation(chainSource),
      selectedExtensions: ["chain-keys"],
      capabilityEncoders: { "chain-keys": chainKeyCapabilityEncoderFor() },
    }),
    contentGroupsProfile.issuerContribution({
      chain: CHAIN,
      policy: {
        decide: (/** @type {any} */ input) => ({
          grants: Object.entries(
            /** @type {Record<string, { groups: string[], windows: string[] }>} */ (
              input.contentGroups
            ),
          ).flatMap(([contentName, { groups, windows }]) =>
            windows.includes(T12)
              ? groups
                  .filter((group) => grants[/** @type {"sports"} */ (group)])
                  .map((group) => ({
                    kind: "chain",
                    contentName,
                    group,
                    windowStart: T12,
                    cutoffT: T18,
                  }))
              : [],
          ),
          authorizePeriod: () => true,
        }),
      },
    }),
  );
  const registration = {
    kid: "p1",
    publicKey: signing.publicKey,
    origins: [ORIGIN],
    openingKeys: {
      get: (/** @type {string} */ issuerName, /** @type {string} */ keyId) =>
        issuerName === "issuerA" && keyId === "issuerA-k1"
          ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
          : undefined,
    },
  };

  /** Every raw answer and the bytes the client received, to show what travelled. */
  const answers = {
    posts: 0,
    raw: /** @type {any[]} */ ([]),
    sent: /** @type {any[]} */ ([]),
    bodies: /** @type {any[]} */ ([]),
  };
  const http = createBrowserIssuer({
    core,
    registrationForKid: (/** @type {string} */ kid) => (kid === "p1" ? registration : null),
    preflight: (/** @type {string} */ origin) => origin === ORIGIN,
    admitCaller: () => ({ kind: "admitted", principal: null }),
    clock: { now: () => new Date(AT) },
  });
  const kinds = ecdhMethod.settleKindDescriptors(contentGroupsProfile.kindDescriptors);
  const delivery = new KeyDelivery({
    random,
    profile: ecdhMethod,
    ...contentGroupsProfile.keyDeliveryMembers(kinds),
  });
  /** @param {any} response */
  const answer = (response) => {
    const body = JSON.parse(JSON.stringify(response.body));
    answers.bodies.push(body);
    return { status: response.status, contentType: "application/json", body };
  };
  const transport = {
    /** @param {string} _url @param {any} request */
    async post(_url, request) {
      answers.posts++;
      const document = JSON.parse(JSON.stringify(request));
      answers.sent.push(document);
      if (!bound) {
        const { status, body: wire } = await http.handle({
          method: "POST",
          origin: ORIGIN,
          contentType: "application/json",
          body: JSON.stringify(document),
          hostContext: {},
        });
        return answer({ status, body: wire });
      }
      // `createBrowserIssuer` has no key-delivery hook, so client-bound wraps around the same core.
      const admission = core.processor.admit(new DcaRequest(document));
      if (admission.kind !== "admitted") return answer(core.endpoint.refusal(admission).response);
      const view = await delivery.preflight("client-bound", admission.request);
      const { response } = await core.endpoint.handleRequest({
        request: admission.request,
        registration: /** @type {any} */ (registration),
        capturedAtMs: Date.parse(AT),
      });
      if (response.status !== 200) return answer(response);
      answers.raw.push(JSON.parse(JSON.stringify(response.body)));
      return answer({ status: 200, body: await delivery.prepare(response.body, view) });
    },
  };

  /** @type {any} */
  let capability;
  if (bound) {
    const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
      "deriveKey",
    ]);
    const jwk = await subtle.exportKey("jwk", pair.publicKey);
    capability = clientBoundKeyCapability(
      {
        privateKey: pair.privateKey,
        publicKey: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      },
      ecdhMethod,
      contentGroupsProfile.capabilityOptions(kinds),
    );
  }

  // One reader keeps these caches across page loads, as one browser profile does.
  const caches = { cache: new PeriodKeyCache(), chainCache: new ChainKeyCache() };
  const bundle = contentGroupsProfile.client({
    chain: CHAIN,
    createPeriodKeyCache: (/** @type {any} */ c) => new PeriodKeyCache(c),
    createChainKeyCache: (/** @type {any} */ c) => new ChainKeyCache(c),
  });
  /** @param {{ dcaData: any, sealedContent: any }} rendered */
  function clientFor(rendered) {
    return createBrowserClient({
      root: domOver(writeMarkupDelivery(rendered), { publisherOrigin: ORIGIN }),
      issuerName: "issuerA",
      unlockUrl: UNLOCK,
      transport,
      contentDecoders: decoders,
      ...caches,
      chainKeyProfile: referenceChainKeyProfile,
      ...(capability === undefined
        ? { relayPeriodKeys: true }
        : { clientBoundKeyCapability: capability }),
      // The content-group builder extends the stock chain builder through `innerBuilder`.
      requestBuilderFactory: (/** @type {object} */ options) =>
        bundle.requestBuilderFactory({ innerBuilder: chainKeyRequestBuilderFactory(options) }),
      recoverySources: bundle.composeOptions.recoverySources,
      responseSections: bundle.composeOptions.responseSections,
    });
  }

  return { render, clientFor, grants, answers };
}

/** @param {any} client @param {string} name */
const plaintext = async (client, name) => {
  const opened = await client.openLocal(name);
  assert.equal(opened.contentType, "text/html", `${name}: authored content type survives opening`);
  return utf8Decode(opened.bytes);
};

/** The entitled items open to their exact text and the denied ones stay closed, after one walk. */
async function assertFirstLoad(/** @type {any} */ client) {
  const walk = await client.unlockRoutes(NAMES, [{ issuerName: "issuerA", unlockUrl: UNLOCK }]);
  assert.deepEqual(walk.missing.sort(), [...CLOSED].sort());
  for (const name of OPENS)
    assert.equal(await plaintext(client, name), ITEMS.find((i) => i.name === name)?.value, name);
  for (const name of CLOSED) await assert.rejects(client.openLocal(name), { code: "no_key" }, name);
}

test("gzip items open by three routes, a later render reuses two, a reset closes a denied successor", async () => {
  const w = await setup(false);
  const first = await w.render("story1");
  for (const item of Object.values(first.dcaData.contentData))
    assert.deepEqual(/** @type {any} */ (item).contentEncodings, ["gzip"]);
  // Only the two ordinary items hold a sealed item key: bodytext and sportsNews need their own routes.
  assert.deepEqual(Object.keys(first.dcaData.issuerData.issuerA.sealed.contentKeys).sort(), [
    "headline",
    "lockedAd",
  ]);
  const client = w.clientFor(first);
  await assertFirstLoad(client);

  // Retained reach: the later render goes through the attempt path and still sends nothing.
  const posts = w.answers.posts;
  const later = w.clientFor(await w.render("story2"));
  const walk = await later.unlockRoutes(
    ["bodytext", "sportsNews"],
    [{ issuerName: "issuerA", unlockUrl: UNLOCK }],
  );
  assert.deepEqual(walk.missing, []);
  for (const name of ["bodytext", "sportsNews"])
    assert.equal(await plaintext(later, name), ITEMS.find((i) => i.name === name)?.value, name);
  assert.equal(w.answers.posts, posts, "the retained chains served the later render");

  // After a reset a denied successor holds nothing and the issuer still refuses it.
  await client.clearReaderContext();
  // The reset drops the ordinary, stock-chain and content-group material this client held.
  for (const name of OPENS)
    await assert.rejects(client.openLocal(name), { code: "no_key" }, `reset: ${name}`);
  Object.assign(w.grants, { premium: false, sports: false, buy: [] });
  const successor = w.clientFor(await w.render("story3"));
  for (const name of ["bodytext", "sportsNews"])
    await assert.rejects(successor.openLocal(name), { code: "no_key" }, name);
  assert.equal(w.answers.posts, posts, "the local check sent nothing");
  await successor.unlockRoutes(NAMES, [{ issuerName: "issuerA", unlockUrl: UNLOCK }]);
  assert.ok(w.answers.posts > posts, "the next attempt reached the issuer");
  for (const name of NAMES)
    await assert.rejects(successor.openLocal(name), { code: "no_key" }, name);
});

test("client-bound ECDH: no raw key leaves, three items open and two stay closed", async () => {
  const w = await setup(true);
  const client = w.clientFor(await w.render("story1"));
  await assertFirstLoad(client);
  assert.equal(w.answers.raw.length, 1);

  // Every raw key of the direct answer is absent from what the client received.
  const received = JSON.stringify(w.answers.bodies);
  const raw = w.answers.raw[0];
  const keys = [
    ...Object.values(raw.keys.contentKeys),
    ...Object.values(raw.keys.chainKeys.premium),
    ...Object.values(raw.contentGroups.chainKeys.sportsNews.sports).map((entry) => entry.key),
  ];
  assert.ok(keys.length >= 3);
  for (const key of keys)
    assert.ok(!received.includes(/** @type {string} */ (key)), "a raw key left");
});
