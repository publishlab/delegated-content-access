// @ts-check
//
// Ordinary period capabilities include projections from selected chain suppliers.
// Actual chain derivation still selects only chain suppliers for that family.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { ContentRepresentationOpener } from "../../../core-client/ContentRepresentationOpener.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { keyByIssuer, PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { encrypt } from "../../../core-shared/aead.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";
import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";

const PUB = "https://publisher.example";
const GROUP = "premium";
const CHAIN_ONLY = "chain_only_example";
const PERIOD_KEY_ONLY = "period_key_only_example";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const TERMINAL_T = "251023T2345";
const TARGET_T = "251023T1415";

const VECTORS = JSON.parse(
  readFileSync(new URL("./fixtures/dca-profile-chain-keys.vectors.json", import.meta.url), "utf8"),
);
const C1 = VECTORS.cases.find((/** @type {any} */ entry) => entry.id === "c1");

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {object} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", kid: "publisher-1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

/**
 * One render sealed under `premium` at the chain target coordinate, delivered by
 * two issuers: one carrying only the chain route and one carrying only the
 * period-key route.
 *
 * @param {{ nonce: string, key: string }} wrap
 */
function page(wrap) {
  return {
    version: "1",
    resource: { origin: PUB, resourceId: "123456", renderId: "AAAAAAAAAAAAAAAAAAAAAA" },
    resourceJWT: compactJwt({
      origin: PUB,
      resourceId: "123456",
      renderId: "AAAAAAAAAAAAAAAAAAAAAA",
    }),
    periodGeometry: GEOMETRY,
    issuerData: {
      [CHAIN_ONLY]: {
        keyId: "k1",
        unlockUrl: "https://chain.example/unlock",
        sealed: { chainKeys: { [GROUP]: { [TERMINAL_T]: "AAAA" } } },
      },
      [PERIOD_KEY_ONLY]: {
        keyId: "k2",
        unlockUrl: "https://period-keys.example/unlock",
        sealed: { periodKeys: { [GROUP]: { [TARGET_T]: "AAAA" } } },
      },
    },
    contentData: {
      bodytext: {
        contentType: "text/html",
        nonce: "n",
        keys: { [GROUP]: [{ t: TARGET_T, ...wrap }] },
      },
    },
  };
}

/** The content key this render's one cached wrap opens to, under the period key the chain derives. */
async function wrappedUnderTheDerivedPeriodKey() {
  const contentKey = new Uint8Array(16).fill(7);
  const nonce = new Uint8Array(12).fill(4);
  const periodKey = base64urlDecode(C1.periodKey);
  return {
    contentKey,
    wrap: {
      nonce: base64urlEncode(nonce),
      key: base64urlEncode(await encrypt(periodKey, nonce, contentKey)),
    },
  };
}

test("a chain-only issuer opens its own retained grant under an issuer-keyed chain cache", async () => {
  const { contentKey, wrap } = await wrappedUnderTheDerivedPeriodKey();
  const chainCache = new ChainKeyCache({ keyBy: keyByIssuer });
  await chainCache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), {
    publisher: PUB,
    issuerName: CHAIN_ONLY,
    ...GEOMETRY,
  });

  /** @type {string[][]} */
  const periodKeyReads = [];
  const resolver = new ContentKeyResolver({
    cache: {
      put() {},
      candidatesAt() {
        return [];
      },
      candidateEntriesAt(
        /** @type {string} */ _accessGroup,
        /** @type {string} */ _t,
        /** @type {any} */ context,
      ) {
        periodKeyReads.push(context.issuerNames);
        return [];
      },
      attempted() {},
    },
    chainCache,
    chainKeyProfile: explicitChainKeyClientProfile,
  });

  assert.deepEqual(
    await resolver.contentKeyFor(new DcaData(page(wrap), { publisherOrigin: PUB }), "bodytext"),
    contentKey,
    "the chain route reads under the issuer the publisher sealed chainKeys for",
  );
  assert.deepEqual(
    periodKeyReads,
    [[PERIOD_KEY_ONLY, CHAIN_ONLY]],
    "ordinary period lookup includes selected chain suppliers that may project period keys",
  );
});

test("the period-key route ignores an issuer whose only sealed map is the chain route", () => {
  const data = new DcaData(page({ nonce: "AAAA", key: "AAAA" }), { publisherOrigin: PUB });
  assert.deepEqual(data.issuerNamesFor(GROUP), [PERIOD_KEY_ONLY]);
  assert.deepEqual(data.chainIssuerNamesFor(GROUP), [CHAIN_ONLY]);
});

/** Real wraps and item keys for independently named items/coordinates. Each
 * render's publisher seals the content under its own token, so `assertOpens`
 * encrypts the item for the delivery it opens.
 * @param {{name: string, t: string, periodKey: Uint8Array}[]} items
 */
async function protectedItems(items) {
  const delivery = page({ nonce: "AAAA", key: "AAAA" });
  /** @type {Record<string, any>} */
  const contentData = {};
  /** @type {Record<string, {key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array}>} */
  const expected = {};
  for (const [index, item] of items.entries()) {
    const key = new Uint8Array(16).fill(index + 20);
    const nonce = new Uint8Array(12).fill(index + 1);
    const wrapNonce = new Uint8Array(12).fill(index + 11);
    const plaintext = utf8Encode(`content:${item.name}`);
    contentData[item.name] = {
      contentType: "text/plain",
      nonce: base64urlEncode(nonce),
      keys: {
        [GROUP]: [
          {
            t: item.t,
            nonce: base64urlEncode(wrapNonce),
            key: base64urlEncode(await encrypt(item.periodKey, wrapNonce, key)),
          },
        ],
      },
    };
    expected[item.name] = { key, nonce, plaintext };
  }
  delivery.contentData = /** @type {typeof delivery.contentData} */ (contentData);
  return { delivery, expected };
}

/** @param {ContentKeyResolver} resolver @param {DcaData} data @param {string[]} names
 * @param {any} response
 */
async function applyChainResponse(resolver, data, names, response) {
  const request = new ChainKeyRequestBuilder().build(data, CHAIN_ONLY, names).toObject();
  return resolver.applyResponse(
    data,
    CHAIN_ONLY,
    response,
    new ResponseAssociation(data, CHAIN_ONLY, request),
  );
}

/** @param {ContentKeyResolver} resolver @param {any} fixture @param {DcaData} data
 * @param {string} name @param {object} [application]
 */
async function assertOpens(resolver, fixture, data, name, application) {
  const { key, plaintext } = fixture.expected[name];
  const aad = contentAadOctets(data.toObject(), name);
  const ciphertext = base64urlEncode(await encrypt(key, new Uint8Array(12), plaintext, aad));
  const bytes = await new ContentRepresentationOpener().open({
    item: /** @type {any} */ (data.contentItemFor(name)),
    ciphertext,
    resolveKey: () => resolver.contentKeyFor(data, name, application),
  });
  assert.deepEqual(bytes, fixture.expected[name].plaintext);
}

/** @param {any} delivery @param {string} issuerName */
function periodOnly(delivery, issuerName = CHAIN_ONLY) {
  const result = structuredClone(delivery);
  delete result.periodGeometry;
  result.resource.renderId = "AQEBAQEBAQEBAQEBAQEBAQ";
  result.resourceJWT = compactJwt({ ...result.resource });
  result.issuerData = {
    [issuerName]: {
      keyId: "k1",
      unlockUrl: "https://chain.example/unlock",
      sealed: { periodKeys: { [GROUP]: { [TARGET_T]: "AAAA" } } },
    },
  };
  return result;
}

for (const strategy of ["expand", "retain"]) {
  test(`${strategy}: admitted derived period opens a later geometry-free render under selected issuer`, async () => {
    const fixture = await protectedItems([
      { name: "bodytext", t: TARGET_T, periodKey: base64urlDecode(C1.periodKey) },
    ]);
    const chainCache = new ChainKeyCache({
      strategy: /** @type {'expand'|'retain'} */ (strategy),
      keyBy: keyByIssuer,
    });
    const resolver = new ContentKeyResolver({
      chainCache,
      chainKeyProfile: explicitChainKeyClientProfile,
    });
    const data = new DcaData(fixture.delivery, { publisherOrigin: PUB });
    const application = await applyChainResponse(resolver, data, ["bodytext"], {
      periodGeometry: GEOMETRY,
      keys: { chainKeys: { [GROUP]: { [TERMINAL_T]: C1.rootChainKey } } },
    });
    await assertOpens(resolver, fixture, data, "bodytext", application);
    if (strategy === "retain") {
      // First-use uses private source; this later retained-source read memoizes
      // an ordinary period capability under the optional lazy strategy.
      await assertOpens(resolver, fixture, data, "bodytext");
    }
    const later = new DcaData(periodOnly(fixture.delivery), { publisherOrigin: PUB });
    const subtle = crypto.subtle;
    const derive = subtle.deriveBits;
    let derivations = 0;
    subtle.deriveBits = async (...args) => {
      derivations++;
      return derive.apply(subtle, args);
    };
    try {
      await assertOpens(resolver, fixture, later, "bodytext");
    } finally {
      subtle.deriveBits = derive;
    }
    assert.equal(derivations, 0, "ordinary period use does not derive or request chain geometry");
    assert.equal(
      await resolver.contentKeyFor(
        new DcaData(periodOnly(fixture.delivery, "unrelated"), { publisherOrigin: PUB }),
        "bodytext",
      ),
      null,
      "unrelated issuer remains ineligible",
    );
    assert.equal(
      await resolver.contentKeyFor(
        new DcaData(periodOnly(fixture.delivery), { publisherOrigin: "https://another.example" }),
        "bodytext",
      ),
      null,
      "publisher boundaries remain",
    );
    assert.equal(
      await new ContentKeyResolver({
        chainCache: new ChainKeyCache(),
        chainKeyProfile: explicitChainKeyClientProfile,
      }).contentKeyFor(later, "bodytext"),
      null,
      "another logical context with distinct retention has no grant",
    );
  });
}

test("chain-only supplier projection opens through ordinary issuer-partitioned cache", async () => {
  const fixture = await protectedItems([
    { name: "bodytext", t: TARGET_T, periodKey: base64urlDecode(C1.periodKey) },
  ]);
  const cache = new PeriodKeyCache({ keyBy: keyByIssuer });
  const resolver = new ContentKeyResolver({
    cache,
    chainCache: new ChainKeyCache({ keyBy: keyByIssuer }),
    chainKeyProfile: explicitChainKeyClientProfile,
  });
  const data = new DcaData(fixture.delivery, { publisherOrigin: PUB });
  const application = await applyChainResponse(resolver, data, ["bodytext"], {
    keys: { periodKeys: { [GROUP]: { [TARGET_T]: C1.periodKey } } },
  });
  assert.equal(application.accepted, 1);
  await assertOpens(resolver, fixture, data, "bodytext", application);
  assert.equal(
    await resolver.contentKeyFor(
      new DcaData(periodOnly(fixture.delivery, "unrelated"), { publisherOrigin: PUB }),
      "bodytext",
    ),
    null,
  );
  const isolated = new PeriodKeyCache({ keyBy: keyByIssuer });
  await isolated.put(GROUP, TARGET_T, base64urlDecode(C1.periodKey), {
    publisher: PUB,
    issuerName: "unrelated",
  });
  const withUnrelated = structuredClone(fixture.delivery);
  withUnrelated.issuerData.unrelated = {
    keyId: "other",
    unlockUrl: "https://unrelated.example/unlock",
    sealed: { periodKeys: { other_group: { [TARGET_T]: "AAAA" } } },
  };
  const isolatedResolver = new ContentKeyResolver({
    cache: isolated,
    chainCache: new ChainKeyCache({ keyBy: keyByIssuer }),
    chainKeyProfile: explicitChainKeyClientProfile,
  });
  assert.equal(
    await isolatedResolver.contentKeyFor(
      new DcaData(withUnrelated, { publisherOrigin: PUB }),
      "bodytext",
    ),
    null,
    "being named for another family does not enter this family's issuer eligibility",
  );
});

test("blocked chain promotion preserves all concurrent obtaining items even at period capacity one", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(31),
    geometry: GEOMETRY,
  });
  const earlyT = "251023T1200";
  const fixture = await protectedItems([
    { name: "bodytext", t: TARGET_T, periodKey: await generation.periodKey(GROUP, TARGET_T) },
    { name: "early", t: earlyT, periodKey: await generation.periodKey(GROUP, earlyT) },
  ]);
  const chainCache = new ChainKeyCache({
    strategy: "expand",
    maxMemoPeriodKeys: 1,
    keyBy: keyByIssuer,
  });
  let release = () => {};
  let started = () => {};
  const barrier = new Promise((resolve) => {
    release = () => resolve(undefined);
  });
  const promoting = new Promise((resolve) => {
    started = () => resolve(undefined);
  });
  const realPromote = chainCache.promote.bind(chainCache);
  let promotionCalls = 0;
  chainCache.promote = async (context) => {
    promotionCalls++;
    started();
    await barrier;
    return realPromote(context);
  };
  const resolver = new ContentKeyResolver({
    chainCache,
    chainKeyProfile: explicitChainKeyClientProfile,
  });
  const data = new DcaData(fixture.delivery, { publisherOrigin: PUB });
  const application = await applyChainResponse(resolver, data, ["bodytext", "early"], {
    periodGeometry: GEOMETRY,
    keys: {
      chainKeys: {
        [GROUP]: {
          [TERMINAL_T]: base64urlEncode((await generation.chainCapability(GROUP, TERMINAL_T)).key),
        },
      },
    },
  });
  const first = assertOpens(resolver, fixture, data, "bodytext", application);
  await promoting;
  const second = resolver.resolveDetailed(data, ["early", "bodytext"], application);
  // Its pending chain is still usable; completing this reader joins promotion.
  await new Promise((resolve) => setImmediate(resolve));
  release();
  await first;
  assert.deepEqual((await second).covered, ["early", "bodytext"]);
  assert.equal(
    promotionCalls,
    2,
    "resolver starts one promotion; release joins its completed promotion",
  );
  assert.equal(chainCache.entries().filter((entry) => entry.kind === "period-key").length, 1);
  assert.equal(
    await resolver.contentKeyFor(
      new DcaData(periodOnly(fixture.delivery), { publisherOrigin: PUB }),
      "early",
    ),
    null,
    "completed operation does not promise future eviction immunity",
  );
});

test("expanded generation rivals authenticate the matching period-only render", async () => {
  const generations = [32, 33].map((fill) =>
    periodFamilyGeneration({
      keyDerivationSecret: new Uint8Array(32).fill(fill),
      geometry: GEOMETRY,
    }),
  );
  const fixture = await protectedItems([
    { name: "bodytext", t: TARGET_T, periodKey: await generations[0].periodKey(GROUP, TARGET_T) },
  ]);
  const chainCache = new ChainKeyCache({ strategy: "expand", keyBy: keyByIssuer });
  for (const generation of generations)
    await chainCache.put(
      GROUP,
      TERMINAL_T,
      (await generation.chainCapability(GROUP, TERMINAL_T)).key,
      { publisher: PUB, issuerName: CHAIN_ONLY, ...GEOMETRY },
    );
  const resolver = new ContentKeyResolver({
    chainCache,
    chainKeyProfile: explicitChainKeyClientProfile,
  });
  const later = new DcaData(periodOnly(fixture.delivery), { publisherOrigin: PUB });
  await assertOpens(resolver, fixture, later, "bodytext");
  assert.equal(
    (
      await chainCache.periodCandidates(GROUP, TARGET_T, {
        publisher: PUB,
        issuerNames: [CHAIN_ONLY],
      })
    ).length,
    2,
    "authentication miss does not delete the other generation",
  );
});

test("ordinary and locally derived views share one finite trial budget", async () => {
  const fixture = await protectedItems([
    { name: "bodytext", t: TARGET_T, periodKey: base64urlDecode(C1.periodKey) },
  ]);
  const record = fixture.delivery.contentData.bodytext;
  const original = record.keys[GROUP][0];
  // Every entry is structurally usable but deliberately cannot authenticate.
  record.keys[GROUP] = Array.from({ length: 30 }, () => ({
    ...original,
    key: base64urlEncode(new Uint8Array(32)),
  }));
  const cache = new PeriodKeyCache({ keyBy: keyByIssuer });
  for (let fill = 1; fill <= 4; fill++)
    await cache.put(GROUP, TARGET_T, new Uint8Array(16).fill(fill), {
      publisher: PUB,
      issuerName: PERIOD_KEY_ONLY,
    });
  const chainCache = new ChainKeyCache({ strategy: "expand", keyBy: keyByIssuer });
  await chainCache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), {
    publisher: PUB,
    issuerName: CHAIN_ONLY,
    ...GEOMETRY,
  });
  const resolver = new ContentKeyResolver({
    cache,
    chainCache,
    chainKeyProfile: explicitChainKeyClientProfile,
  });
  const subtle = crypto.subtle;
  const decrypt = subtle.decrypt;
  let trials = 0;
  subtle.decrypt = async (...args) => {
    trials++;
    return decrypt.apply(subtle, args);
  };
  try {
    assert.equal(
      await resolver.contentKeyFor(
        new DcaData(fixture.delivery, { publisherOrigin: PUB }),
        "bodytext",
      ),
      null,
    );
  } finally {
    subtle.decrypt = decrypt;
  }
  assert.equal(trials, 64, "adding another period view does not add another operation budget");
});

test("retained chain cannot derive under an unrelated geometry or beyond its cutoff", async () => {
  const fixture = await protectedItems([
    { name: "bodytext", t: TARGET_T, periodKey: base64urlDecode(C1.periodKey) },
  ]);
  const chainCache = new ChainKeyCache({ keyBy: keyByIssuer });
  await chainCache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), {
    publisher: PUB,
    issuerName: CHAIN_ONLY,
    ...GEOMETRY,
  });
  const resolver = new ContentKeyResolver({
    chainCache,
    chainKeyProfile: explicitChainKeyClientProfile,
  });
  const otherGeometry = structuredClone(fixture.delivery);
  otherGeometry.periodGeometry = { chainsPerDay: 4, periodMinutes: 15 };
  assert.equal(
    await resolver.contentKeyFor(new DcaData(otherGeometry, { publisherOrigin: PUB }), "bodytext"),
    null,
    "a positioned chain cannot be walked as another geometry",
  );
  const beyond = structuredClone(fixture.delivery);
  beyond.contentData.bodytext.keys[GROUP][0].t = "251024T0000";
  assert.equal(
    await resolver.contentKeyFor(new DcaData(beyond, { publisherOrigin: PUB }), "bodytext"),
    null,
    "a retained cutoff cannot authorize forward derivation",
  );
  await assertOpens(
    resolver,
    fixture,
    new DcaData(fixture.delivery, { publisherOrigin: PUB }),
    "bodytext",
  );
});

test("composed ordinary pool tries newly filed derived key ahead of four older base rivals", async () => {
  const fixture = await protectedItems([
    { name: "bodytext", t: TARGET_T, periodKey: base64urlDecode(C1.periodKey) },
  ]);
  const cache = new PeriodKeyCache({ keyBy: keyByIssuer });
  for (let fill = 1; fill <= 4; fill++)
    await cache.put(GROUP, TARGET_T, new Uint8Array(16).fill(fill), {
      publisher: PUB,
      issuerName: CHAIN_ONLY,
    });
  const chainCache = new ChainKeyCache({ strategy: "expand", keyBy: keyByIssuer });
  await chainCache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), {
    publisher: PUB,
    issuerName: CHAIN_ONLY,
    ...GEOMETRY,
  });
  const resolver = new ContentKeyResolver({
    cache,
    chainCache,
    chainKeyProfile: explicitChainKeyClientProfile,
  });
  const data = new DcaData(periodOnly(fixture.delivery), { publisherOrigin: PUB });
  const subtle = crypto.subtle;
  const decrypt = subtle.decrypt;
  let trials = 0;
  subtle.decrypt = async (...args) => {
    trials++;
    return decrypt.apply(subtle, args);
  };
  try {
    assert.deepEqual(await resolver.contentKeyFor(data, "bodytext"), fixture.expected.bodytext.key);
  } finally {
    subtle.decrypt = decrypt;
  }
  assert.equal(trials, 1, "old base view cannot crowd the newly filed matching ordinary key out");

  // A new base filing now leads the derived candidate across the two views.
  await cache.put(GROUP, TARGET_T, new Uint8Array(16).fill(99), {
    publisher: PUB,
    issuerName: CHAIN_ONLY,
  });
  trials = 0;
  subtle.decrypt = async (...args) => {
    trials++;
    return decrypt.apply(subtle, args);
  };
  try {
    assert.deepEqual(await resolver.contentKeyFor(data, "bodytext"), fixture.expected.bodytext.key);
  } finally {
    subtle.decrypt = decrypt;
  }
  assert.equal(trials, 2, "newest filing is compared across views, not fixed view order");

  const wrong = structuredClone(fixture.delivery);
  wrong.contentData.bodytext.keys[GROUP][0].key = base64urlEncode(new Uint8Array(32));
  trials = 0;
  subtle.decrypt = async (...args) => {
    trials++;
    return decrypt.apply(subtle, args);
  };
  try {
    assert.equal(
      await resolver.contentKeyFor(new DcaData(wrong, { publisherOrigin: PUB }), "bodytext"),
      null,
    );
  } finally {
    subtle.decrypt = decrypt;
  }
  assert.equal(trials, 4, "one combined ordinary ceiling governs both views");
});

test("obtaining response's private period key leads newer retained derived rivals", async () => {
  const fixture = await protectedItems([
    { name: "bodytext", t: TARGET_T, periodKey: base64urlDecode(C1.periodKey) },
  ]);
  const cache = new PeriodKeyCache({ keyBy: keyByIssuer });
  // Re-delivery of these bytes does not refresh their retained filing order.
  await cache.put(GROUP, TARGET_T, base64urlDecode(C1.periodKey), {
    publisher: PUB,
    issuerName: CHAIN_ONLY,
  });
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(44),
    geometry: GEOMETRY,
  });
  const chainCache = new ChainKeyCache({ strategy: "expand", keyBy: keyByIssuer });
  await chainCache.put(
    GROUP,
    TERMINAL_T,
    (await generation.chainCapability(GROUP, TERMINAL_T)).key,
    { publisher: PUB, issuerName: CHAIN_ONLY, ...GEOMETRY },
  );
  const resolver = new ContentKeyResolver({
    cache,
    chainCache,
    chainKeyProfile: explicitChainKeyClientProfile,
  });
  const data = new DcaData(fixture.delivery, { publisherOrigin: PUB });
  const application = await applyChainResponse(resolver, data, ["bodytext"], {
    keys: { periodKeys: { [GROUP]: { [TARGET_T]: C1.periodKey } } },
  });
  const subtle = crypto.subtle;
  const decrypt = subtle.decrypt;
  let trials = 0;
  subtle.decrypt = async (...args) => {
    trials++;
    return decrypt.apply(subtle, args);
  };
  try {
    assert.deepEqual(
      await resolver.contentKeyFor(data, "bodytext", application),
      fixture.expected.bodytext.key,
    );
  } finally {
    subtle.decrypt = decrypt;
  }
  assert.equal(trials, 1, "operation-private material leads even an older duplicate filing");
});

test("legacy ordinary cache works alone; two views require metadata before any reads", async () => {
  const fixture = await protectedItems([
    { name: "bodytext", t: TARGET_T, periodKey: base64urlDecode(C1.periodKey) },
  ]);
  let reads = 0;
  const legacy = {
    put: async () => {},
    attempted: async () => {},
    candidatesAt: async () => {
      reads++;
      return [base64urlDecode(C1.periodKey)];
    },
  };
  const data = new DcaData(periodOnly(fixture.delivery), { publisherOrigin: PUB });
  await assertOpens(new ContentKeyResolver({ cache: legacy }), fixture, data, "bodytext");
  reads = 0;
  const chainCache = new ChainKeyCache({ strategy: "expand" });
  const read = chainCache.periodCandidateEntries.bind(chainCache);
  chainCache.periodCandidateEntries = async (...args) => {
    reads++;
    return read(...args);
  };
  assert.throws(
    () =>
      new ContentKeyResolver({
        cache: legacy,
        chainCache,
        chainKeyProfile: explicitChainKeyClientProfile,
      }),
    { code: "bad_config", message: "composed ordinary period views need shared filing metadata" },
  );
  assert.equal(reads, 0, "constructor admission reads neither the legacy nor empty derived view");
  assert.deepEqual(chainCache.entries(), []);
});
