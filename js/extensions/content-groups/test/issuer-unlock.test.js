// Content-group unlocks through the base issuer processor and engine: a real
// page from `createPublisher`, a relayed request, and the annex order and
// atomic refusal. Expected keys come from the construction functions over the
// test chain port, not from the issuer code under test.
import { seedHandle } from "../core-shared--publisher-issuer/seedHandle.js";
import test from "node:test";
import assert from "node:assert/strict";
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { dcaError } from "../../../core-shared/errors.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { decrypt } from "../../../core-shared/aead.js";
import { base64urlDecode, base64urlEncode } from "../../../core-shared/codec.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";
import { contentGroupsPublisherContribution } from "../core-publisher/publish.js";
import { contentGroupsIssuerContribution } from "../core-issuer/unlock.js";
import { contentNameSeed, itemPad, xor16 } from "../core-shared/construction.js";
import { DERIVING_CHAIN, allZeroed, recordingChain } from "./_lib/derivingChainPort.js";
import { KeyDelivery } from "../../../adapter-issuer/KeyDelivery.js";
import {
  composedKeys,
  settleComposedSections,
} from "../../../core-shared--client-issuer/responseKeys.js";
import { KIND_DESCRIPTORS, RESPONSE_SECTIONS } from "../core-shared--client-issuer/request.js";
import { sealSeed } from "../core-shared/seed-envelope.js";
import { contentNameSeedAad } from "../core-shared/construction.js";
import {
  connectorOf,
  connectorsOf,
  contentKeyRecords,
  cutoffRecords,
  find,
  groupRecords,
  issuerBlock,
  itemRecords,
  keysAt,
  sealedContentKey,
  seedOf,
  seedRecords,
} from "./_lib/records.js";

const subtle = globalThis.crypto.subtle;
const ORIGIN = "https://news.example";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
const SECRET = Uint8Array.from({ length: 32 }, (_, i) => i);
const RIVAL_SECRET = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
const AT = "2026-10-14T14:20:00Z";
const W12 = "261014T1200";
const W00 = "261015T0000";
const T12 = "261014T1200";
const T13 = "261014T1300";
const T14 = "261014T1400";
const T15 = "261014T1500";
const T18 = "261014T1800";
const random = {
  bytes: (/** @type {number} */ n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
};

/** One publisher, two issuers and a page with two connector items and an ordinary item. */
async function world() {
  const signing = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const keys = {
    issuerA: await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]),
    issuerB: await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]),
  };
  const publisher = createPublisher(
    /** @type {any} */ ({
      origin: ORIGIN,
      clock: { now: () => new Date(AT) },
      random,
      signingKeys: { p1: signing.privateKey },
      issuers: [
        {
          issuerName: "issuerA",
          keyId: "a1",
          algorithm: "ecdh-p256",
          publicKey: keys.issuerA.publicKey,
        },
        {
          issuerName: "issuerB",
          keyId: "b1",
          algorithm: "ecdh-p256",
          publicKey: keys.issuerB.publicKey,
        },
      ],
      issuerSupplyPlanFor: (/** @type {any} */ issuer, /** @type {any} */ render) => ({
        contentKeyNames:
          issuer.issuerName === "issuerA"
            ? render.contentNames.filter((/** @type {string} */ n) => n === "purchase")
            : [],
        suppliedAccessGroups: [],
      }),
    }),
    contentGroupsPublisherContribution({
      retainedSecret: SECRET,
      periodGeometry: GEOMETRY,
      issuerSeedWindows: {
        issuerA: { bodytext: [W12, W00], headline: [W12] },
        issuerB: { headline: [W12] },
      },
      chain: DERIVING_CHAIN,
    }),
  );
  const { dcaData, sealedContent } = await publisher.publish({
    resourceId: "story1",
    data: {},
    items: [
      {
        name: "bodytext",
        value: "body text",
        contentType: "text/plain",
        contentGroups: ["politics", "sports"],
      },
      {
        name: "headline",
        value: "head line",
        contentType: "text/plain",
        contentGroups: ["politics"],
      },
      { name: "purchase", value: "buy", contentType: "text/plain" },
    ],
  });
  let verifierReads = 0;
  const registration = {
    kid: "p1",
    get publicKey() {
      verifierReads++;
      return signing.publicKey;
    },
    openingKeys: {
      get: (/** @type {string} */ issuerName) => {
        const held = /** @type {any} */ (keys)[issuerName];
        return held ? { algorithm: "ecdh-p256", privateKey: held.privateKey } : undefined;
      },
    },
  };
  const renderId = JSON.parse(
    Buffer.from(dcaData.resourceJWT.split(".")[1], "base64url").toString(),
  ).renderId;
  /**
   * A seed envelope for issuerA at a real coordinate, sealed from another
   * retained secret: it opens under the same AAD and derives different keys.
   * @param {string} contentName @param {string} window
   */
  const rivalSeed = async (contentName, window) => {
    const seed = await contentNameSeed(
      RIVAL_SECRET,
      ORIGIN,
      GEOMETRY,
      contentName,
      window,
      DERIVING_CHAIN,
    );
    const aad = await contentNameSeedAad(
      {
        publisher: ORIGIN,
        renderId,
        issuerName: "issuerA",
        contentName,
        windowStartLabel: window,
        periodGeometry: GEOMETRY,
      },
      DERIVING_CHAIN,
    );
    return sealSeed(seed, keys.issuerA.publicKey, aad);
  };
  return {
    page: /** @type {any} */ (dcaData),
    sealedContent,
    registration,
    renderId,
    rivalSeed,
    verifierReads: () => verifierReads,
  };
}

/**
 * A relayed request for one issuer, written out as the wire carries it. Short
 * literal maps become the request's records; an array passes through as the
 * records it already is.
 */
function request(
  /** @type {any} */ page,
  issuerName,
  extra = /** @type {Record<string, any>} */ ({}),
) {
  const issuer = issuerBlock(page, issuerName);
  const {
    seeds,
    contentKeys,
    requestedContentGroups,
    requestedContentKeys,
    requestedChainCutoffs,
    ...rest
  } = extra;
  /** @param {any} value @param {(map: any) => any[]} records */
  const asRecords = (value, records) =>
    value === undefined ? undefined : Array.isArray(value) ? value : records(value);
  const groups = asRecords(requestedContentGroups, groupRecords);
  const items = asRecords(requestedContentKeys, itemRecords);
  const cutoffs = asRecords(requestedChainCutoffs, cutoffRecords);
  const asked = new Set([...(groups ?? []), ...(items ?? [])].map((r) => r.contentName));
  return {
    version: "1",
    issuerName,
    keyId: issuer.keyId,
    resourceJWT: page.resourceJWT,
    sealed: {
      contentKeys: contentKeyRecords(contentKeys ?? {}),
      // By default the request carries exactly the seeds of the names it
      // requests, as the client builds it. A copy, so a test that edits a
      // request record leaves the page intact for the next request.
      contentWindowSeeds:
        seeds ??
        structuredClone(seedRecords(page, issuerName).filter((r) => asked.has(r.contentName))),
    },
    renderPeriod: page.renderPeriod,
    periodGeometry: page.periodGeometry,
    ...(groups === undefined && items === undefined
      ? {}
      : {
          requested: {
            ...(groups === undefined ? {} : { contentGroups: groups }),
            ...(items === undefined ? {} : { contentKeys: items }),
          },
        }),
    ...(cutoffs === undefined ? {} : { requestedChainCutoffs: cutoffs }),
    ...rest,
  };
}

/**
 * An issuer whose content-group policy grants what `grants` returns and
 * records every call.
 */
function issuer(/** @type {any} */ options = {}) {
  const calls = {
    decide: /** @type {any[]} */ ([]),
    authorize: /** @type {any[]} */ ([]),
  };
  const policy = {
    decide(/** @type {any} */ input) {
      calls.decide.push(input);
      if (Object.hasOwn(options, "decision")) return options.decision;
      return {
        grants: options.grants?.(input) ?? [],
        authorizePeriod(/** @type {string[]} */ ...args) {
          calls.authorize.push(args);
          return options.authorize ? options.authorize(...args) : true;
        },
      };
    },
  };
  const core = createIssuerCore(
    {
      operatingIssuerNames: ["issuerA", "issuerB"],
      accessPolicy: {
        decide: (/** @type {any} */ _c, /** @type {any} */ r) => ({ contentNames: r.contentNames }),
      },
    },
    contentGroupsIssuerContribution({
      chain: options.chain ?? DERIVING_CHAIN,
      policy,
      limits: options.limits,
    }),
  );
  return { ...core, calls };
}

/** @param {any} w @param {any} core @param {any} body */
async function send(w, core, body) {
  return core.endpoint.handleDocument(JSON.stringify(body), w.registration);
}

/** @param {string} contentName @param {string} window */
async function handleOf(contentName, window, secret = SECRET) {
  const seed = await contentNameSeed(secret, ORIGIN, GEOMETRY, contentName, window, DERIVING_CHAIN);
  return seedHandle(seed, GEOMETRY, window, DERIVING_CHAIN);
}

/** Known material derived by the real refusal paths, never read from the error. */
async function refusalSecrets(/** @type {any} */ page, contentName, group) {
  const seed = await contentNameSeed(SECRET, ORIGIN, GEOMETRY, contentName, W12, DERIVING_CHAIN);
  const handle = seedHandle(seed, GEOMETRY, W12, DERIVING_CHAIN);
  try {
    const periodKey = await handle.periodKey(group, T14);
    const chainKey = (await handle.chainKey(group, T14)).key;
    const renderId = JSON.parse(
      Buffer.from(page.resourceJWT.split(".")[1], "base64url").toString(),
    ).renderId;
    const pad = await itemPad(periodKey, { renderId, contentName });
    const recovered = connectorsOf(page, contentName).map(({ connector }) =>
      xor16(base64urlDecode(connector), pad),
    );
    return [SECRET, seed, periodKey, chainKey, pad, ...recovered];
  } finally {
    handle.dispose();
  }
}

/** @param {string} text @param {Uint8Array[]} secrets */
function assertNoSecretText(text, secrets) {
  for (const bytes of secrets)
    for (const spelling of [
      base64urlEncode(bytes),
      Buffer.from(bytes).toString("base64"),
      Buffer.from(bytes).toString("hex"),
      Array.from(bytes).join(","),
    ])
      assert.ok(!text.includes(spelling), "a refusal disclosed secret or derived key bytes");
}

/** The one content-group candidate for one item. @param {any} body @param {string} contentName */
function groupItemKey(body, contentName) {
  const keys = keysAt(body?.contentGroupKeys?.contentKeys, { contentName });
  assert.equal(keys.length, 1, `one candidate for ${contentName}`);
  return keys[0];
}
/** The base content key for one item. @param {any} body @param {string} contentName */
function baseItemKey(body, contentName) {
  return find(body?.keys?.contentKeys, { contentName })?.key;
}

/** Open the genuine body with the candidate returned for one item. */
async function openCandidate(/** @type {any} */ w, contentName, candidate) {
  return decrypt(
    base64urlDecode(candidate),
    new Uint8Array(12),
    base64urlDecode(w.sealedContent[contentName]),
    /** @type {Uint8Array} */ (contentAadOctets(w.page, contentName)),
  );
}

test("one exchange answers chain, period and item grants under the annex member names", async () => {
  const w = await world();
  const core = issuer({
    grants: () => [
      { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T18 },
      { kind: "period", contentName: "headline", group: "politics", t: T15 },
      { kind: "item", contentName: "bodytext" },
    ],
  });
  const body = request(w.page, "issuerA", {
    requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] },
    requestedContentKeys: {
      bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
    },
    contentKeys: { purchase: sealedContentKey(w.page, "issuerA", "purchase") },
  });
  const { response } = await send(w, core, body);
  assert.equal(response.status, 200);
  const answer = /** @type {any} */ (response.body);
  assert.deepEqual(Object.keys(answer), ["keys", "contentGroupKeys"]);
  assert.equal(Object.hasOwn(answer, "periodGeometry"), false);
  assert.ok(baseItemKey(answer, "purchase"));

  const bodytext = await handleOf("bodytext", W12);
  const headline = await handleOf("headline", W12);
  const chain = await bodytext.chainKey("politics", T18);
  assert.deepEqual(answer.contentGroupKeys.chainKeys, [
    { contentName: "bodytext", group: "politics", cutoff: T18, key: base64urlEncode(chain.key) },
  ]);
  assert.deepEqual(answer.contentGroupKeys.periodKeys, [
    {
      contentName: "headline",
      group: "politics",
      period: T15,
      key: base64urlEncode(await headline.periodKey("politics", T15)),
    },
  ]);
  // The recovered item key opens the body under its derived content AAD.
  const key = base64urlDecode(groupItemKey(answer, "bodytext"));
  const aad = /** @type {Uint8Array} */ (contentAadOctets(w.page, "bodytext"));
  const plain = await decrypt(
    key,
    new Uint8Array(12),
    base64urlDecode(w.sealedContent.bodytext),
    aad,
  );
  assert.equal(new TextDecoder().decode(plain), "body text");

  // Policy saw the annex input once, and authorized the whole chain prefix.
  assert.equal(core.calls.decide.length, 1);
  const input = core.calls.decide[0];
  assert.deepEqual(input.contentGroups, {
    bodytext: { groups: ["politics"], windows: [W12, W00] },
    headline: { groups: ["politics"], windows: [W12] },
  });
  assert.deepEqual(input.items, ["bodytext"]);
  assert.equal(input.issuerName, "issuerA");
  assert.equal(input.publisher.origin, ORIGIN);
  assert.equal(
    input.claims.renderId,
    JSON.parse(Buffer.from(w.page.resourceJWT.split(".")[1], "base64url").toString()).renderId,
  );
  const chainReach = core.calls.authorize
    .filter(([name]) => name === "bodytext")
    .map(([, , t]) => t);
  assert.deepEqual(chainReach, [T12, T13, T14, T15, "261014T1600", "261014T1700", T18]);
});

test("response source methods keep their original receiver and captured function", async () => {
  for (const route of ["direct", "contribution"]) {
    const w = await world();
    const contribution = contentGroupsIssuerContribution({
      chain: DERIVING_CHAIN,
      policy: {
        decide: () => ({
          grants: [{ kind: "item", contentName: "bodytext" }],
          authorizePeriod: () => true,
        }),
      },
    });
    const delegate = contribution.responseSectionSource;
    class PrivateResponseSource {
      #delegate;

      constructor(source) {
        this.#delegate = source;
        this.name = source.name;
        this.members = source.members;
        this.envelopeOpeners = source.envelopeOpeners;
      }

      presented(request) {
        return this.#delegate.presented(request);
      }

      respond(unlock) {
        return this.#delegate.respond(unlock);
      }
    }
    const source = new PrivateResponseSource(delegate);
    const base = {
      operatingIssuerNames: ["issuerA"],
      accessPolicy: {
        decide: (_claims, requested) => ({ contentNames: requested.contentNames }),
      },
    };
    const core =
      route === "direct"
        ? new IssuerEngine({
            ...base,
            responseSectionSources: [source],
          })
        : createIssuerCore(
            base,
            /** @type {any} */ ({ ...contribution, responseSectionSource: source }),
          );

    // Core construction captures the source methods; later caller assignment
    // must not change either admission or the engine's callback.
    /** @type {any} */ (source).presented = () => {
      throw new Error("reassigned presented method ran");
    };
    /** @type {any} */ (source).respond = () => {
      throw new Error("reassigned respond method ran");
    };

    const body = request(w.page, "issuerA", {
      requestedContentKeys: {
        bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
      },
      contentKeys: { purchase: sealedContentKey(w.page, "issuerA", "purchase") },
    });
    if (route === "direct") {
      const result = await core.unlock(new DcaRequest(body), w.registration);
      const purchase = find(result.contentKeys, { contentName: "purchase" })?.key;
      assert.ok(purchase);
      assert.equal(new TextDecoder().decode(await openCandidate(w, "purchase", purchase)), "buy");
      assert.equal(
        new TextDecoder().decode(
          await openCandidate(w, "bodytext", groupItemKey(result.sections, "bodytext")),
        ),
        "body text",
      );
    } else {
      const { response } = await core.endpoint.handleDocument(JSON.stringify(body), w.registration);
      assert.equal(response.status, 200);
      assert.ok(baseItemKey(response.body, "purchase"));
      assert.equal(
        new TextDecoder().decode(
          await openCandidate(w, "purchase", baseItemKey(response.body, "purchase")),
        ),
        "buy",
      );
      assert.equal(
        new TextDecoder().decode(
          await openCandidate(w, "bodytext", groupItemKey(response.body, "bodytext")),
        ),
        "body text",
      );
    }
  }
});

test("a captured contribution predicate admits and opens content without an ordinary purchase coordinate", async () => {
  const w = await world();
  const contribution = contentGroupsIssuerContribution({
    chain: DERIVING_CHAIN,
    policy: {
      decide: () => ({
        grants: [{ kind: "item", contentName: "bodytext" }],
        authorizePeriod: () => true,
      }),
    },
  });
  const delegate = contribution.responseSectionSource;
  class PrivateSource {
    #delegate = delegate;

    name = delegate.name;
    members = delegate.members;
    envelopeOpeners = delegate.envelopeOpeners;

    presented(request) {
      return this.#delegate.presented(request);
    }

    respond(unlock) {
      return this.#delegate.respond(unlock);
    }
  }
  const source = new PrivateSource();
  const core = createIssuerCore(
    {
      operatingIssuerNames: ["issuerA"],
      accessPolicy: { decide: () => ({ contentNames: [] }) },
    },
    /** @type {any} */ ({ ...contribution, responseSectionSource: source }),
  );
  source.presented = () => {
    throw new Error("the replaced contribution predicate must not run");
  };
  const body = request(w.page, "issuerA", {
    requestedContentKeys: {
      bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
    },
  });
  assert.deepEqual(body.sealed.contentKeys, [], "ordinary admission must not mask the predicate");
  const { response } = await core.endpoint.handleDocument(JSON.stringify(body), w.registration);
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.keys.contentKeys, []);
  assert.deepEqual(
    response.body.contentGroupKeys.contentKeys.map((/** @type {any} */ r) => r.contentName),
    ["bodytext"],
  );
  assert.equal(
    new TextDecoder().decode(
      await openCandidate(w, "bodytext", groupItemKey(response.body, "bodytext")),
    ),
    "body text",
  );
});

test("policy reads the request's geometry and render period as frozen request coordinates", async () => {
  const w = await world();
  const core = issuer();
  const body = request(w.page, "issuerA", { requestedContentGroups: { bodytext: ["politics"] } });
  // Member order is the relay's; the policy sees the admitted pair.
  body.periodGeometry = { periodMinutes: 60, chainsPerDay: 2 };
  await send(w, core, body);
  const input = core.calls.decide[0];
  assert.deepEqual(input.request, { periodGeometry: GEOMETRY, renderPeriod: T14 });
  assert.ok(Object.isFrozen(input.request));
  assert.ok(Object.isFrozen(input.request.periodGeometry));
  // The coordinates come from the request, not from the verified claims.
  assert.equal(Object.hasOwn(input.claims, "periodGeometry"), false);
  assert.equal(Object.hasOwn(input.claims, "renderPeriod"), false);
});

test("a malformed request coordinate refuses with binding_failed before policy runs", async () => {
  const w = await world();
  for (const [field, value] of /** @type {[string, any][]} */ ([
    ["periodGeometry", { chainsPerDay: 5, periodMinutes: 60 }],
    ["periodGeometry", { chainsPerDay: "2", periodMinutes: 60 }],
    ["periodGeometry", { periodMinutes: 60 }],
    ["renderPeriod", "261014T1430"],
    ["renderPeriod", "2026-10-14T14:00"],
  ])) {
    const core = issuer({
      grants: () => [
        {
          kind: "chain",
          contentName: "bodytext",
          group: "politics",
          windowStart: W12,
          cutoffT: T18,
        },
      ],
    });
    const body = request(w.page, "issuerA", { requestedContentGroups: { bodytext: ["politics"] } });
    body[field] = value;
    const result = await send(w, core, body);
    assert.equal(result.code, "binding_failed", `${field} ${JSON.stringify(value)}`);
    assert.equal(core.calls.decide.length, 0);
  }
});

test("a requested cutoff lowers the policy cutoff and caps period grants", async () => {
  const w = await world();
  const grants = () => [
    { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T18 },
  ];
  const core = issuer({ grants });
  const { response } = await send(
    w,
    core,
    request(w.page, "issuerA", {
      requestedContentGroups: { bodytext: ["politics"] },
      requestedChainCutoffs: { [W12]: T14 },
    }),
  );
  const chain = await (await handleOf("bodytext", W12)).chainKey("politics", T14);
  assert.deepEqual(/** @type {any} */ (response.body).contentGroupKeys.chainKeys, [
    { contentName: "bodytext", group: "politics", cutoff: T14, key: base64urlEncode(chain.key) },
  ]);
  const beyond = issuer({
    grants: () => [{ kind: "period", contentName: "bodytext", group: "politics", t: T15 }],
  });
  const refused = await send(
    w,
    beyond,
    request(w.page, "issuerA", {
      requestedContentGroups: { bodytext: ["politics"] },
      requestedChainCutoffs: { [W12]: T14 },
    }),
  );
  assert.equal(refused.code, "bad_policy");
});

test("an authorized changed connector returns a candidate that cannot open the genuine body", async () => {
  const w = await world();
  const core = issuer({ grants: () => [{ kind: "item", contentName: "bodytext" }] });
  const body = request(w.page, "issuerA", {
    requestedContentKeys: {
      bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
    },
  });
  const genuine = await send(w, core, body);
  assert.equal(genuine.response.status, 200);
  assert.equal(
    new TextDecoder().decode(
      await openCandidate(w, "bodytext", groupItemKey(genuine.response.body, "bodytext")),
    ),
    "body text",
  );
  for (const connector of [
    connectorOf(w.page, "bodytext", "politics"),
    base64urlEncode(new Uint8Array(16)),
  ]) {
    const changed = structuredClone(body);
    changed.requested.contentKeys[0].connector = connector;
    const result = await send(w, core, changed);
    assert.equal(result.response.status, 200);
    await assert.rejects(
      openCandidate(w, "bodytext", groupItemKey(result.response.body, "bodytext")),
      { name: "OperationError" },
    );
  }
  const denied = await send(w, issuer(), body);
  assert.equal(denied.code, "denied");
  assert.equal(Object.hasOwn(denied.response.body, "contentGroupKeys"), false);
  const malformed = structuredClone(body);
  malformed.requested.contentKeys[0].connector = base64urlEncode(new Uint8Array(15));
  assert.equal((await send(w, core, malformed)).code, "binding_failed");
});

test("a wrong candidate for one item does not suppress an authorized sibling candidate", async () => {
  const w = await world();
  const core = issuer({
    grants: () => [
      { kind: "item", contentName: "bodytext" },
      { kind: "item", contentName: "headline" },
    ],
  });
  const body = request(w.page, "issuerA", {
    requestedContentKeys: {
      bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
      headline: { group: "politics", connector: connectorOf(w.page, "bodytext", "politics") },
    },
  });
  const { response } = await send(w, core, body);
  assert.equal(response.status, 200);
  assert.equal(
    new TextDecoder().decode(
      await openCandidate(w, "bodytext", groupItemKey(response.body, "bodytext")),
    ),
    "body text",
  );
  await assert.rejects(openCandidate(w, "headline", groupItemKey(response.body, "headline")), {
    name: "OperationError",
  });
});

test("client-bound delivery wraps every content-group key the processor answered", async () => {
  const w = await world();
  const core = issuer({
    grants: () => [
      { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T18 },
      { kind: "period", contentName: "headline", group: "politics", t: T15 },
      { kind: "item", contentName: "bodytext" },
    ],
  });
  const { response } = await send(
    w,
    core,
    request(w.page, "issuerA", {
      requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] },
      requestedContentKeys: {
        bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
      },
    }),
  );
  assert.equal(response.status, 200);
  /** @type {string[]} */
  const wraps = [];
  const delivery = new KeyDelivery({
    profile: /** @type {any} */ ({
      METHOD: "TEST-METHOD",
      async seal() {
        return {
          transport: { publicKey: "transport" },
          async wrap(/** @type {Uint8Array} */ bytes, /** @type {string} */ keyKind) {
            wraps.push(keyKind);
            return { kind: keyKind, bytes: base64urlEncode(bytes) };
          },
        };
      },
    }),
    random,
    composedSections: RESPONSE_SECTIONS,
    composedKinds: KIND_DESCRIPTORS,
  });
  const clientRequest = new DcaRequest({
    version: "1",
    issuerName: "issuerA",
    clientPublicKey: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    sealed: { contentKeys: [] },
  });
  const view = await delivery.preflight("client-bound", clientRequest);
  const out = /** @type {any} */ (await delivery.prepare(/** @type {any} */ (response.body), view));
  const keys = [...composedKeys(out, settleComposedSections(RESPONSE_SECTIONS))];
  assert.equal(keys.length, 3);
  for (const { key } of keys)
    assert.equal(typeof key, "object", "a content-group key went unwrapped");
  assert.deepEqual(wraps.sort(), ["contentGroupChainKey", "contentGroupPeriodKey", "contentKey"]);
  assert.equal(typeof find(out.contentGroupKeys.chainKeys, { cutoff: T18 })?.key, "object");
});

test("every opened seed copy is zeroed when the unlock ends, answered or refused", async () => {
  const w = await world();
  const recorded = recordingChain();
  const core = issuer({
    chain: recorded.chain,
    grants: () => [
      { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T18 },
      { kind: "period", contentName: "headline", group: "politics", t: T15 },
      { kind: "item", contentName: "bodytext" },
    ],
  });
  const body = request(w.page, "issuerA", {
    requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] },
    requestedContentKeys: {
      bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
    },
  });
  const { response } = await send(w, core, body);
  assert.equal(response.status, 200);
  assert.ok(allZeroed(recorded.secrets), "an answered unlock left a seed copy");

  // A later seed fails authentication; earlier opened copies are zeroed as well.
  recorded.secrets.length = 0;
  const swapped = structuredClone(body);
  const seed = find(swapped.sealed.contentWindowSeeds, { contentName: "headline" });
  const corrupted = base64urlDecode(seed.key);
  corrupted[80] ^= 1;
  seed.key = base64urlEncode(corrupted);
  const refused = await send(w, core, swapped);
  assert.equal(refused.code, "binding_failed");
  assert.ok(allZeroed(recorded.secrets), "a refused unlock left a seed copy");
});

test("a seed envelope that does not open after another opened refuses the whole exchange", async () => {
  const w = await world();
  const core = issuer({
    grants: () => [
      { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T14 },
      { kind: "chain", contentName: "headline", group: "politics", windowStart: W12, cutoffT: T14 },
    ],
  });
  const seeds = structuredClone(seedRecords(w.page, "issuerA")).filter(
    (r) => r.contentName === "bodytext" || r.contentName === "headline",
  );
  // issuerB's envelope for headline is bound to issuerB and does not open here.
  /** @type {any} */ (find(seeds, { contentName: "headline", windowStart: W12 })).key = seedOf(
    w.page,
    "issuerB",
    "headline",
    W12,
  );
  const body = request(w.page, "issuerA", {
    seeds,
    requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] },
    contentKeys: { purchase: sealedContentKey(w.page, "issuerA", "purchase") },
  });
  const secrets = [
    ...(await refusalSecrets(w.page, "bodytext", "politics")),
    ...(await refusalSecrets(w.page, "headline", "politics")),
  ];
  await assert.rejects(
    core.engine.unlock(new DcaRequest(body), /** @type {any} */ (w.registration)),
    (error) => {
      assert.match(error.message, /a seed envelope does not open at its coordinate/);
      assertNoSecretText(String(error), secrets);
      return true;
    },
  );
  const refused = await send(w, core, body);
  assert.equal(refused.code, "binding_failed");
  assertNoSecretText(JSON.stringify(refused.response.body), secrets);
});

/** The world's registration with every opening key retired. */
function retiredRegistration(/** @type {any} */ w) {
  return {
    kid: "p1",
    get publicKey() {
      return w.registration.publicKey;
    },
    openingKeys: { get: () => ({ retired: true }) },
  };
}
const RETIRED = Object.freeze({ error: "key_retired" });

test("a retired opening key answers 200 with key_retired at every authorized scoped coordinate", async () => {
  const w = await world();
  const core = issuer({
    grants: () => [
      { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T18 },
      {
        kind: "chain",
        contentName: "bodytext",
        group: "politics",
        windowStart: W00,
        cutoffT: "261015T0300",
      },
      { kind: "period", contentName: "headline", group: "politics", t: T13 },
      { kind: "period", contentName: "headline", group: "politics", t: T15 },
      { kind: "item", contentName: "bodytext" },
    ],
  });
  const body = request(w.page, "issuerA", {
    // headline sports is requested but not granted: it carries no error.
    requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] },
    requestedChainCutoffs: { [W12]: T15, [W00]: "261015T0300" },
    requestedContentKeys: {
      bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
    },
    contentKeys: { purchase: sealedContentKey(w.page, "issuerA", "purchase") },
  });
  const { response } = await core.endpoint.handleDocument(
    JSON.stringify(body),
    /** @type {any} */ (retiredRegistration(w)),
  );
  assert.equal(response.status, 200);
  const answer = /** @type {any} */ (response.body);
  assert.equal(find(answer.errors, { coordinate: "purchase" })?.error, "key_retired");
  // The chain error is named by the served cutoff: the request's T15 ceiling.
  assert.deepEqual(answer.contentGroupKeys, {
    errors: {
      chainKeys: [
        { contentName: "bodytext", group: "politics", cutoff: T15, ...RETIRED },
        { contentName: "bodytext", group: "politics", cutoff: "261015T0300", ...RETIRED },
      ],
      periodKeys: [
        { contentName: "headline", group: "politics", period: T13, ...RETIRED },
        { contentName: "headline", group: "politics", period: T15, ...RETIRED },
      ],
      contentKeys: [{ contentName: "bodytext", ...RETIRED }],
    },
  });
});

test("a seed-only request under a retired key keeps its scoped retirement", async () => {
  const w = await world();
  const core = issuer({
    grants: () => [{ kind: "period", contentName: "headline", group: "politics", t: T14 }],
  });
  const body = request(w.page, "issuerA", { requestedContentGroups: { headline: ["politics"] } });
  const { response } = await core.endpoint.handleDocument(
    JSON.stringify(body),
    /** @type {any} */ (retiredRegistration(w)),
  );
  assert.equal(response.status, 200);
  assert.deepEqual(/** @type {any} */ (response.body).contentGroupKeys, {
    errors: {
      periodKeys: [{ contentName: "headline", group: "politics", period: T14, ...RETIRED }],
    },
  });
  // A denied request stays a denial; retirement is reported only for grants.
  const denying = issuer({ grants: () => [] });
  const denied = await denying.endpoint.handleDocument(
    JSON.stringify(body),
    /** @type {any} */ (retiredRegistration(w)),
  );
  assert.equal(denied.code, "denied");
});

test("a retired seed opening reports its coordinates while sibling grants keep their keys", async () => {
  // Retirement belongs to the opening key, so under one real key every seed
  // retires together. This drives the source directly with an opener that
  // retires two seeds and opens the third, to show the siblings survive.
  const w = await world();
  const bodytextW12 = seedOf(w.page, "issuerA", "bodytext", W12);
  const contribution = contentGroupsIssuerContribution({
    chain: DERIVING_CHAIN,
    policy: {
      decide: () => ({
        grants: [
          {
            kind: "chain",
            contentName: "bodytext",
            group: "politics",
            windowStart: W12,
            cutoffT: T18,
          },
          {
            kind: "chain",
            contentName: "bodytext",
            group: "politics",
            windowStart: W00,
            cutoffT: "261015T0300",
          },
          { kind: "period", contentName: "headline", group: "politics", t: T15 },
          { kind: "item", contentName: "bodytext" },
          { kind: "item", contentName: "headline" },
        ],
        authorizePeriod: () => true,
      }),
    },
  });
  const opened = await contentNameSeed(SECRET, ORIGIN, GEOMETRY, "bodytext", W12, DERIVING_CHAIN);
  const claims = JSON.parse(Buffer.from(w.page.resourceJWT.split(".")[1], "base64url").toString());
  const relayed = new DcaRequest(
    request(w.page, "issuerA", {
      requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] },
      requestedContentKeys: {
        bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
        headline: { group: "politics", connector: connectorOf(w.page, "headline", "politics") },
      },
    }),
  );
  const answer = /** @type {any} */ (
    await /** @type {any} */ (contribution.responseSectionSource).respond({
      request: relayed,
      claims,
      policyInput: { publisher: { origin: ORIGIN } },
      invocation: {},
      openAuxiliary: async (/** @type {unknown} */ sealed) =>
        sealed === bodytextW12
          ? { bytes: Uint8Array.from(opened) }
          : { error: { error: "key_retired", message: "retired" } },
    })
  );
  const bodytext = await handleOf("bodytext", W12);
  assert.deepEqual(answer.contentGroupKeys.chainKeys, [
    {
      contentName: "bodytext",
      group: "politics",
      cutoff: T18,
      key: base64urlEncode((await bodytext.chainKey("politics", T18)).key),
    },
  ]);
  assert.ok(groupItemKey(answer, "bodytext"));
  assert.equal(Object.hasOwn(answer.contentGroupKeys, "periodKeys"), false);
  assert.deepEqual(answer.contentGroupKeys.errors, {
    chainKeys: [{ contentName: "bodytext", group: "politics", cutoff: "261015T0300", ...RETIRED }],
    periodKeys: [{ contentName: "headline", group: "politics", period: T15, ...RETIRED }],
    contentKeys: [{ contentName: "headline", ...RETIRED }],
  });
  // Another failure under the same opener still refuses the whole exchange.
  await assert.rejects(
    /** @type {any} */ (contribution.responseSectionSource).respond({
      request: relayed,
      claims,
      policyInput: { publisher: { origin: ORIGIN } },
      invocation: {},
      openAuxiliary: async () => ({ error: { error: "unseal_failed", message: "no" } }),
    }),
    { code: "binding_failed" },
  );
});

test("a requested name without a seed, or a seed nothing requests, refuses before the verifier runs", async () => {
  const w = await world();
  const core = issuer({ grants: () => [] });
  /** @param {string[]} names */
  const seeds = (names) =>
    seedRecords(w.page, "issuerA").filter((r) => names.includes(r.contentName));
  for (const body of [
    request(w.page, "issuerA", {
      requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] },
      seeds: seeds(["headline"]),
    }),
    request(w.page, "issuerA", {
      requestedContentGroups: { bodytext: ["politics"] },
      seeds: seeds(["bodytext", "headline"]),
    }),
  ]) {
    const refused = await send(w, core, body);
    assert.equal(
      refused.code,
      "binding_failed",
      JSON.stringify(body.sealed.contentWindowSeeds.map((r) => r.contentName)),
    );
  }
  assert.equal(w.verifierReads(), 0);
  assert.equal(core.calls.decide.length, 0);
});

test("bounds refuse before the verifier runs", async () => {
  const w = await world();
  const core = issuer({ limits: { maxItems: 2 } });
  const names = Object.fromEntries(["a", "b", "c"].map((name) => [name, ["politics"]]));
  const refused = await send(
    w,
    core,
    request(w.page, "issuerA", { requestedContentGroups: names }),
  );
  assert.equal(refused.code, "too_many_entries");
  assert.equal(w.verifierReads(), 0);
  const malformed = await send(
    w,
    core,
    request(w.page, "issuerA", { requestedContentGroups: { bodytext: [] } }),
  );
  assert.equal(malformed.code, "binding_failed");
  assert.equal(w.verifierReads(), 0);
  // Positive control: the same issuer under its bound reaches the verifier.
  await send(
    w,
    core,
    request(w.page, "issuerA", { requestedContentGroups: { bodytext: ["politics"] } }),
  );
  assert.ok(w.verifierReads() > 0);
});

test("whole chain-prefix authorization is mandatory", async () => {
  const w = await world();
  const grants = () => [
    { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T15 },
  ];
  const body = request(w.page, "issuerA", { requestedContentGroups: { bodytext: ["politics"] } });
  const gap = issuer({
    grants,
    authorize: (/** @type {string} */ _n, /** @type {string} */ _g, /** @type {string} */ t) =>
      t !== T13,
  });
  assert.equal((await send(w, gap, body)).code, "bad_policy");
  const whole = issuer({ grants });
  assert.equal((await send(w, whole, body)).response.status, 200);
});

for (const [label, extra, grants, code] of /** @type {[string, any, any, string][]} */ ([
  [
    "a grant for an unrequested group",
    { requestedContentGroups: { bodytext: ["politics"] } },
    [{ kind: "chain", contentName: "bodytext", group: "sports", windowStart: W12, cutoffT: T14 }],
    "bad_policy",
  ],
  [
    "a grant for an unrequested name",
    { requestedContentGroups: { bodytext: ["politics"] } },
    [{ kind: "period", contentName: "headline", group: "politics", t: T14 }],
    "bad_policy",
  ],
  [
    "a grant in an unsupplied window",
    { requestedContentGroups: { headline: ["politics"] } },
    [
      {
        kind: "chain",
        contentName: "headline",
        group: "politics",
        windowStart: W00,
        cutoffT: "261015T0200",
      },
    ],
    "bad_policy",
  ],
  [
    "an unrequested item",
    { requestedContentGroups: { bodytext: ["politics"] } },
    [{ kind: "item", contentName: "bodytext" }],
    "bad_policy",
  ],
  [
    "a duplicate grant",
    { requestedContentGroups: { bodytext: ["politics"] } },
    [
      { kind: "period", contentName: "bodytext", group: "politics", t: T14 },
      { kind: "period", contentName: "bodytext", group: "politics", t: T14 },
    ],
    "bad_policy",
  ],
  [
    "an unknown kind",
    { requestedContentGroups: { bodytext: ["politics"] } },
    [{ kind: "seed", contentName: "bodytext" }],
    "bad_policy",
  ],
  ["no grant at all", { requestedContentGroups: { bodytext: ["politics"] } }, [], "denied"],
  [
    "an item with no render-window seed",
    {
      requestedContentKeys: {
        headline: { group: "politics", connector: "AAAAAAAAAAAAAAAAAAAAAA" },
      },
      seeds: [],
    },
    [],
    "binding_failed",
  ],
  [
    "a cutoff outside its window",
    {
      requestedContentGroups: { bodytext: ["politics"] },
      requestedChainCutoffs: { [W12]: "261015T0100" },
    },
    [],
    "binding_failed",
  ],
  ["a request with seeds only", {}, [], "binding_failed"],
])) {
  test(`the issuer refuses ${label}`, async () => {
    const w = await world();
    const core = issuer({ grants: () => grants });
    const result = await send(w, core, request(w.page, "issuerA", extra));
    assert.equal(result.code, code);
  });
}

test("host policy and generation faults are not malformed request refusals", async () => {
  const w = await world();
  const grant = {
    kind: "chain",
    contentName: "bodytext",
    group: "politics",
    windowStart: W12,
    cutoffT: T18,
  };
  for (const options of [
    {
      grants: () => {
        throw dcaError("bad_config", "host policy failed");
      },
    },
    {
      grants: () => [grant],
      chain: {
        ...DERIVING_CHAIN,
        familyGeneration() {
          throw dcaError("bad_config", "host generation failed");
        },
      },
    },
  ]) {
    const core = issuer(options);
    const body = request(w.page, "issuerA", { requestedContentGroups: { bodytext: ["politics"] } });
    const result = await send(w, core, body);
    assert.equal(result.code, "internal_error");
    assert.equal(core.calls.decide.length, 1, "valid coordinates reached policy");
  }
});

test("item-only requests admit every supplied seed window before policy", async () => {
  const w = await world();
  for (const label of [T15, "not-a-window"]) {
    const core = issuer({ grants: () => [{ kind: "item", contentName: "bodytext" }] });
    const body = request(w.page, "issuerA", {
      requestedContentKeys: {
        bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
      },
    });
    find(body.sealed.contentWindowSeeds, { windowStart: W00 }).windowStart = label;
    const result = await send(w, core, body);
    assert.equal(result.code, "binding_failed", label);
    assert.equal(core.calls.decide.length, 0, "malformed unused windows refuse before policy");
  }
  const core = issuer({ grants: () => [{ kind: "item", contentName: "bodytext" }] });
  const body = request(w.page, "issuerA", {
    requestedContentKeys: {
      bodytext: { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") },
    },
  });
  // An aligned unused alternative is admitted without opening its ciphertext.
  find(body.sealed.contentWindowSeeds, { windowStart: W00 }).key = base64urlEncode(
    new Uint8Array(113),
  );
  const result = await send(w, core, body);
  assert.equal(result.response.status, 200);
  assert.equal(
    new TextDecoder().decode(
      await openCandidate(w, "bodytext", groupItemKey(result.response.body, "bodytext")),
    ),
    "body text",
  );
});

test("content-group policy decisions require the declared authorizer even for item-only grants", async () => {
  const w = await world();
  const body = request(w.page, "issuerA", {
    requestedContentKeys: {
      bodytext: { group: "politics", connector: connectorOf(w.page, "bodytext", "politics") },
    },
  });
  for (const decision of [null, {}, { grants: [{ kind: "item", contentName: "bodytext" }] }]) {
    assert.equal((await send(w, issuer({ decision }), body)).code, "bad_policy");
  }
});

test("content-group response accepts exactly the configured member limit", async () => {
  const w = await world();
  const core = issuer({
    limits: { maxResponseMembers: 2 },
    grants: () =>
      ["bodytext", "headline"].map((contentName) => ({
        kind: "period",
        contentName,
        group: "politics",
        t: T14,
      })),
  });
  const answer = await send(
    w,
    core,
    request(w.page, "issuerA", {
      requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] },
    }),
  );
  assert.equal(answer.response.status, 200);
  assert.deepEqual(
    answer.response.body.contentGroupKeys.periodKeys
      .map((/** @type {any} */ r) => r.contentName)
      .sort(),
    ["bodytext", "headline"],
  );
});

test("unused malformed seed envelopes and absent render-window seeds refuse before policy", async () => {
  for (const malformedEnvelope of [true, false]) {
    const w = await world();
    const seeds = structuredClone(seedRecords(w.page, "issuerA")).filter(
      (r) => r.contentName === "bodytext",
    );
    if (malformedEnvelope)
      /** @type {any} */ (find(seeds, { windowStart: W00 })).key = base64urlEncode(
        new Uint8Array(124),
      );
    else seeds.splice(seeds.indexOf(/** @type {any} */ (find(seeds, { windowStart: W12 }))), 1);
    const core = issuer({ grants: () => [] });
    const extra = malformedEnvelope
      ? { requestedContentGroups: { bodytext: ["politics"] } }
      : {
          requestedContentKeys: {
            bodytext: {
              group: "politics",
              connector: connectorOf(w.page, "bodytext", "politics"),
            },
          },
        };
    const answer = await send(
      w,
      core,
      request(w.page, "issuerA", {
        ...extra,
        seeds,
      }),
    );
    assert.equal(answer.code, "binding_failed");
    if (malformedEnvelope) assert.equal(w.verifierReads(), 0);
    assert.equal(core.calls.decide.length, 0);
  }
});

test("rival seed records at one window each open and give distinct candidates under one logical grant", async () => {
  const w = await world();
  const core = issuer({
    grants: () => [
      { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T15 },
      { kind: "period", contentName: "bodytext", group: "sports", t: T14 },
      { kind: "item", contentName: "bodytext" },
    ],
  });
  const rival = {
    contentName: "bodytext",
    windowStart: W12,
    key: await w.rivalSeed("bodytext", W12),
  };
  const genuine = /** @type {any} */ (
    find(seedRecords(w.page, "issuerA"), {
      contentName: "bodytext",
      windowStart: W12,
    })
  );
  const route = { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") };
  for (const seeds of [
    [rival, genuine],
    [genuine, rival],
  ]) {
    core.calls.decide.length = 0;
    core.calls.authorize.length = 0;
    const body = request(w.page, "issuerA", {
      seeds,
      requestedContentGroups: { bodytext: ["politics", "sports"] },
      requestedContentKeys: { bodytext: route },
    });
    const { response } = await send(w, core, JSON.parse(JSON.stringify(body)));
    assert.equal(response.status, 200);
    const answer = /** @type {any} */ (response.body).contentGroupKeys;
    const real = await handleOf("bodytext", W12);
    const other = await handleOf("bodytext", W12, RIVAL_SECRET);
    // Both candidates sit at the one selected cutoff and the one period.
    assert.deepEqual(
      keysAt(answer.chainKeys, { contentName: "bodytext", group: "politics", cutoff: T15 }).sort(),
      [
        base64urlEncode((await real.chainKey("politics", T15)).key),
        base64urlEncode((await other.chainKey("politics", T15)).key),
      ].sort(),
    );
    assert.equal(answer.chainKeys.length, 2);
    assert.deepEqual(
      keysAt(answer.periodKeys, { contentName: "bodytext", group: "sports", period: T14 }).sort(),
      [
        base64urlEncode(await real.periodKey("sports", T14)),
        base64urlEncode(await other.periodKey("sports", T14)),
      ].sort(),
    );
    // The genuine body opens with one item candidate and not the other.
    const items = keysAt(answer.contentKeys, { contentName: "bodytext" });
    assert.equal(items.length, 2);
    const opened = await Promise.allSettled(items.map((key) => openCandidate(w, "bodytext", key)));
    assert.deepEqual(
      opened.map((result) => result.status),
      seeds[0] === rival ? ["rejected", "fulfilled"] : ["fulfilled", "rejected"],
    );
    // Policy answers the logical grants once; the chain reach is authorized
    // once, not once per candidate.
    assert.equal(core.calls.decide.length, 1);
    assert.deepEqual(
      core.calls.authorize.filter(([, group]) => group === "politics").map(([, , t]) => t),
      [T12, T13, T14, T15],
    );
  }
});

test("item routes for different groups each recover a candidate, in either order", async () => {
  const w = await world();
  const core = issuer({ grants: () => [{ kind: "item", contentName: "bodytext" }] });
  const working = { group: "sports", connector: connectorOf(w.page, "bodytext", "sports") };
  // A connector that is valid but belongs to another item: admissible, wrong.
  const wrong = { group: "politics", connector: connectorOf(w.page, "headline", "politics") };
  for (const routes of [
    [wrong, working],
    [working, wrong],
  ]) {
    const body = request(w.page, "issuerA", { requestedContentKeys: { bodytext: routes } });
    const { response } = await send(w, core, body);
    assert.equal(response.status, 200);
    const items = keysAt(/** @type {any} */ (response.body).contentGroupKeys.contentKeys, {
      contentName: "bodytext",
    });
    assert.equal(items.length, 2);
    const opened = await Promise.allSettled(items.map((key) => openCandidate(w, "bodytext", key)));
    assert.deepEqual(
      opened.map((result) => result.status),
      routes[0] === wrong ? ["rejected", "fulfilled"] : ["fulfilled", "rejected"],
    );
    // The routes grant the item only: no reusable key of either group.
    assert.equal(Object.hasOwn(response.body.contentGroupKeys, "chainKeys"), false);
    assert.equal(Object.hasOwn(response.body.contentGroupKeys, "periodKeys"), false);
  }
  // Two routes through the same group and connector are one candidate.
  const twice = request(w.page, "issuerA", {
    requestedContentKeys: { bodytext: [working, working] },
  });
  const { response } = await send(w, core, twice);
  assert.equal(
    keysAt(/** @type {any} */ (response.body).contentGroupKeys.contentKeys, {
      contentName: "bodytext",
    }).length,
    1,
  );
});

test("a seed record for one item cannot authorize another item", async () => {
  const w = await world();
  const core = issuer({
    grants: () => [{ kind: "period", contentName: "headline", group: "politics", t: T14 }],
  });
  // bodytext's genuine envelope relabelled as headline's: its AAD names bodytext.
  const body = request(w.page, "issuerA", {
    requestedContentGroups: { headline: ["politics"] },
    seeds: [
      {
        contentName: "headline",
        windowStart: W12,
        key: seedOf(w.page, "issuerA", "bodytext", W12),
      },
    ],
  });
  const refused = await send(w, core, body);
  assert.equal(refused.code, "binding_failed");
  assert.equal(Object.hasOwn(refused.response.body, "contentGroupKeys"), false);
});

test("repeated cutoff records cap a window at their lowest cutoff, in either order", async () => {
  const w = await world();
  const core = issuer({
    grants: () => [
      { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T18 },
    ],
  });
  const records = [
    { windowStart: W12, cutoff: T18 },
    { windowStart: W12, cutoff: T14 },
  ];
  for (const cutoffs of [records, [...records].reverse()]) {
    const { response } = await send(
      w,
      core,
      request(w.page, "issuerA", {
        requestedContentGroups: { bodytext: ["politics"] },
        requestedChainCutoffs: cutoffs,
      }),
    );
    assert.deepEqual(
      /** @type {any} */ (response.body).contentGroupKeys.chainKeys.map(
        (/** @type {any} */ r) => r.cutoff,
      ),
      [T14],
    );
  }
  // Every label is admitted before the lowest is taken: a higher label in
  // another window refuses even though a lower one would cap this window.
  const beforePolicy = core.calls.decide.length;
  const refused = await send(
    w,
    core,
    request(w.page, "issuerA", {
      requestedContentGroups: { bodytext: ["politics"] },
      requestedChainCutoffs: [...records, { windowStart: W12, cutoff: "261015T0100" }],
    }),
  );
  assert.equal(refused.code, "binding_failed");
  assert.equal(core.calls.decide.length, beforePolicy);
});

test("raw candidate records count against the response bounds before the issuer answers", async () => {
  const w = await world();
  const rival = {
    contentName: "bodytext",
    windowStart: W12,
    key: await w.rivalSeed("bodytext", W12),
  };
  const seeds = [
    /** @type {any} */ (
      find(seedRecords(w.page, "issuerA"), { contentName: "bodytext", windowStart: W12 })
    ),
    rival,
  ];
  const grants = () => [
    { kind: "period", contentName: "bodytext", group: "politics", t: T14 },
    { kind: "period", contentName: "bodytext", group: "politics", t: T15 },
  ];
  const body = request(w.page, "issuerA", {
    seeds,
    requestedContentGroups: { bodytext: ["politics"] },
  });
  // Two grants fit a bound of two; their four candidate records do not.
  for (const limits of [{ maxResponseMembers: 3 }, { maxPeriodKeysPerContentGroup: 3 }]) {
    const refused = await send(w, issuer({ grants, limits }), body);
    assert.equal(refused.code, "too_many_entries", JSON.stringify(limits));
  }
  const fits = await send(w, issuer({ grants, limits: { maxResponseMembers: 4 } }), body);
  assert.equal(fits.response.status, 200);
  assert.equal(fits.response.body.contentGroupKeys.periodKeys.length, 4);
  // Candidates at one window are one window, not two, for maxWindowsPerGroup.
  const chain = await send(
    w,
    issuer({
      limits: { maxWindowsPerGroup: 1 },
      grants: () => [
        {
          kind: "chain",
          contentName: "bodytext",
          group: "politics",
          windowStart: W12,
          cutoffT: T15,
        },
      ],
    }),
    body,
  );
  assert.equal(chain.response.status, 200);
  assert.equal(chain.response.body.contentGroupKeys.chainKeys.length, 2);
});

test("extensible request record members preserve a successful issuer exchange", async () => {
  const w = await world();
  const core = issuer({
    grants: () => [
      { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T18 },
    ],
  });
  const body = request(w.page, "issuerA", {
    requestedContentGroups: [{ contentName: "bodytext", groups: ["politics"], future: true }],
    requestedChainCutoffs: [{ windowStart: W12, cutoff: T14, future: "ignored" }],
  });
  for (const seed of body.sealed.contentWindowSeeds) seed.future = { ignored: true };
  const { response } = await send(w, core, body);
  assert.equal(response.status, 200);
  assert.equal(core.calls.decide.length, 1);
  assert.deepEqual(
    response.body.contentGroupKeys.chainKeys.map((record) => record.cutoff),
    [T14],
  );
});

test("unsupplied cutoff windows and closed item-route extras refuse before policy or key access", async () => {
  const w = await world();
  let openingKeyReads = 0;
  const registration = {
    ...w.registration,
    openingKeys: {
      get() {
        openingKeyReads++;
        throw new Error("key lookup must not precede admission");
      },
    },
  };
  for (const extra of [
    {
      requestedContentGroups: { bodytext: ["politics"] },
      requestedChainCutoffs: [
        { windowStart: W12, cutoff: T14 },
        { windowStart: "261016T0000", cutoff: "261016T0300" },
      ],
    },
    {
      requestedContentKeys: [
        {
          contentName: "bodytext",
          group: "politics",
          connector: connectorOf(w.page, "bodytext", "politics"),
          future: true,
        },
      ],
    },
  ]) {
    const core = issuer();
    const result = await core.endpoint.handleDocument(
      JSON.stringify(request(w.page, "issuerA", extra)),
      registration,
    );
    assert.equal(result.code, "binding_failed");
    assert.equal(core.calls.decide.length, 0);
    assert.equal(openingKeyReads, 0);
  }
});

test("seed opening preserves configured-key faults while wrong valid keys remain generic refusals", async () => {
  const w = await world();
  const wrongCurve = await subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, false, [
    "deriveBits",
  ]);
  const wrongValid = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const wrongUsage = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveKey",
  ]);
  const body = request(w.page, "issuerA", { requestedContentGroups: { bodytext: ["politics"] } });
  for (const [privateKey, status, code] of [
    [wrongCurve.privateKey, 500, "internal_error"],
    [wrongUsage.privateKey, 500, "internal_error"],
    [wrongValid.privateKey, 400, "binding_failed"],
  ]) {
    const core = issuer({
      grants: () => [
        {
          kind: "chain",
          contentName: "bodytext",
          group: "politics",
          windowStart: W12,
          cutoffT: T18,
        },
      ],
    });
    const result = await core.endpoint.handleDocument(JSON.stringify(body), {
      ...w.registration,
      openingKeys: { get: () => ({ algorithm: "ecdh-p256", privateKey }) },
    });
    assert.equal(result.response.status, status);
    assert.equal(result.code, code);
    assert.equal(result.response.body.contentGroupKeys, undefined);
    assert.equal(result.response.body.keys, undefined);
  }
});
