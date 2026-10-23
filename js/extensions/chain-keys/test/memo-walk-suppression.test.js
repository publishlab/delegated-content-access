// @ts-check
//
// A memoized period key stands in for the chain walk it came from only when
// the memo is actually offered for the wrap being opened. The ordinary rival
// ceiling of four can leave a correct memo out of a wrap's trials; its
// retained chain key then still walks, so holding one more correct key never
// costs the reader an item. A memo that was tried keeps suppressing the
// redundant walk, inside the unchanged rival bounds and 64-trial budget.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { encrypt } from "../../../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { contentKeyWrapNonceOctets } from "../../../test-reference/support/contentKeyWrapNonceOctets.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";

const VECTORS = JSON.parse(
  readFileSync(new URL("./fixtures/dca-profile-chain-keys.vectors.json", import.meta.url), "utf8"),
);
const C1 = VECTORS.cases.find((/** @type {any} */ entry) => entry.id === "c1");

const PUB = "https://publisher.example";
const GROUP = "premium";
const CHAIN = "chain_issuer";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const CONTEXT = Object.freeze({ publisher: PUB, ...GEOMETRY });
const TERMINAL_T = "251023T2345";
const TARGET_T = "251023T1415";

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {unknown} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", kid: "publisher-1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

/**
 * One chain-carrying render whose item "a" is wrapped at TARGET_T under
 * `periodKey`.
 *
 * @param {string} renderId @param {Uint8Array} periodKey
 */
async function render(renderId, periodKey) {
  const contentKey = new Uint8Array(16).fill(20);
  const wrapNonce = contentKeyWrapNonceOctets({
    renderId,
    contentName: "a",
    accessGroup: GROUP,
    t: TARGET_T,
  });
  const resource = { origin: PUB, resourceId: "123456", renderId };
  const data = new DcaData(
    {
      version: "1",
      resource,
      resourceJWT: compactJwt(resource),
      periodGeometry: GEOMETRY,
      issuerData: [
        {
          issuerName: CHAIN,
          keyId: "k1",
          unlockUrl: "https://chain.example/unlock",
          sealed: { chainKeys: [{ accessGroup: GROUP, cutoff: TERMINAL_T, key: "AAAA" }] },
        },
      ],
      contentData: [
        {
          contentName: "a",
          contentType: "text/plain",
          nonce: base64urlEncode(new Uint8Array(12).fill(1)),
          keys: [
            {
              accessGroup: GROUP,
              period: TARGET_T,
              key: base64urlEncode(await encrypt(periodKey, wrapNonce, contentKey)),
            },
          ],
        },
      ],
    },
    { publisherOrigin: PUB },
  );
  return { data, contentKey };
}

/** @returns {Promise<ChainKeyCache>} */
async function retainedChain() {
  const chainCache = new ChainKeyCache({ strategy: "retain" });
  await chainCache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), CONTEXT);
  return chainCache;
}

/** @param {ChainKeyCache} chainCache @param {PeriodKeyCache} cache */
function resolverOver(chainCache, cache) {
  return new ContentKeyResolver({
    cache,
    chainCache,
    chainKeyProfile: explicitChainKeyClientProfile,
  });
}

/**
 * AES-GCM trials and HKDF invocations spent by one call, counted at the
 * WebCrypto boundary.
 *
 * @template T
 * @param {() => Promise<T>} run
 * @returns {Promise<{ result: T, trials: number, derivations: number }>}
 */
async function spent(run) {
  const subtle = globalThis.crypto.subtle;
  const { decrypt, deriveBits } = subtle;
  let trials = 0;
  let derivations = 0;
  subtle.decrypt = async function (/** @type {any[]} */ ...args) {
    trials++;
    return decrypt.apply(this, /** @type {any} */ (args));
  };
  subtle.deriveBits = async function (/** @type {any[]} */ ...args) {
    derivations++;
    return deriveBits.apply(this, /** @type {any} */ (args));
  };
  try {
    return { result: await run(), trials, derivations };
  } finally {
    subtle.decrypt = decrypt;
    subtle.deriveBits = deriveBits;
  }
}

/** Four wrong ordinary rivals, each filed after whatever the cache held. @param {PeriodKeyCache} cache */
async function fileWrongRivals(cache) {
  for (let fill = 101; fill <= 104; fill++)
    await cache.put(GROUP, TARGET_T, new Uint8Array(16).fill(fill), { publisher: PUB });
}

test("a correct memo left out by four newer wrong rivals does not suppress its retained chain walk", async () => {
  const periodKey = base64urlDecode(C1.periodKey);
  const first = await render("AAAAAAAAAAAAAAAAAAAAAA", periodKey);

  // Control: the retained chain and the four rivals, with no memo yet.
  const controlCache = new PeriodKeyCache();
  await fileWrongRivals(controlCache);
  const controlRun = await spent(async () =>
    resolverOver(await retainedChain(), controlCache).contentKeyFor(first.data, "a"),
  );
  assert.deepEqual(controlRun.result, first.contentKey, "control: the chain walk opens the item");

  // An earlier read memoized the correct period key before the rivals came.
  const chainCache = await retainedChain();
  const cache = new PeriodKeyCache();
  assert.deepEqual(
    await resolverOver(chainCache, cache).contentKeyFor(first.data, "a"),
    first.contentKey,
  );
  await fileWrongRivals(cache);

  const later = await render("AQEBAQEBAQEBAQEBAQEBAQ", periodKey);
  const run = await spent(() => resolverOver(chainCache, cache).contentKeyFor(later.data, "a"));
  assert.deepEqual(run.result, later.contentKey, "the retained chain still opens the item");
  assert.equal(
    run.trials,
    5,
    "four ordinary rivals, then the one walked period key, well inside the 64-trial budget",
  );
  assert.ok(run.derivations > 0, "the walk the memo did not stand in for ran");
});

test("a memo actually tried for this wrap still suppresses its redundant chain walk", async () => {
  const periodKey = base64urlDecode(C1.periodKey);
  const chainCache = await retainedChain();
  const cache = new PeriodKeyCache();
  const first = await render("AAAAAAAAAAAAAAAAAAAAAA", periodKey);
  assert.deepEqual(
    await resolverOver(chainCache, cache).contentKeyFor(first.data, "a"),
    first.contentKey,
  );

  // A later render wraps the item under a key nothing held derives. The memo
  // is tried and fails; walking its chain again would only rebuild it.
  const rotated = await render("AQEBAQEBAQEBAQEBAQEBAQ", new Uint8Array(16).fill(77));
  const run = await spent(() => resolverOver(chainCache, cache).contentKeyFor(rotated.data, "a"));
  assert.equal(run.result, null);
  assert.equal(run.trials, 1, "the memo is tried once and its rebuilt bytes are not tried again");
  assert.equal(run.derivations, 0, "the chain key behind the tried memo is not walked");
});

test("the chain-only read walks a chain whose memo the caller did not try, and skips one it did", async () => {
  const chainCache = await retainedChain();
  const firstWalk = await spent(() => chainCache.candidates(GROUP, TARGET_T, CONTEXT));
  assert.deepEqual(firstWalk.result.map(base64urlEncode), [C1.periodKey]);

  const untried = await spent(() =>
    chainCache.candidates(GROUP, TARGET_T, { ...CONTEXT, chainOnly: true, triedPeriodKeys: [] }),
  );
  assert.deepEqual(
    untried.result.map(base64urlEncode),
    [C1.periodKey],
    "an untried memo does not answer for its chain key",
  );
  assert.equal(untried.derivations, firstWalk.derivations, "so the chain key walks again");

  const tried = await spent(() =>
    chainCache.candidates(GROUP, TARGET_T, {
      ...CONTEXT,
      chainOnly: true,
      triedPeriodKeys: [base64urlDecode(C1.periodKey)],
    }),
  );
  assert.deepEqual(tried.result, [], "a tried memo answers for its chain key");
  assert.equal(tried.derivations, 0);
});

test("a memo the read leaves outside its four offered period keys does not suppress its chain", async () => {
  const keyBy = (
    /** @type {{ accessGroup: string, issuerName: string }} */ { accessGroup, issuerName },
  ) => `${issuerName}/${accessGroup}`;
  const cache = new ChainKeyCache({ strategy: "retain", keyBy });
  const contextA = { ...CONTEXT, issuerName: "issuer_a" };
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), contextA);
  const walkA = await spent(() => cache.candidates(GROUP, TARGET_T, contextA));
  assert.deepEqual(walkA.result.map(base64urlEncode), [C1.periodKey]);

  // A second issuer's four rival generations file newer memos at the same
  // coordinate, so a read accepting both issuers offers only those four.
  const contextB = { ...CONTEXT, issuerName: "issuer_b" };
  for (let index = 0; index < 4; index++) {
    const generation = periodFamilyGeneration({
      keyDerivationSecret: new Uint8Array(32).fill(index + 41),
      geometry: GEOMETRY,
    });
    await cache.put(
      GROUP,
      TERMINAL_T,
      (await generation.chainCapability(GROUP, TERMINAL_T)).key,
      contextB,
    );
  }
  assert.equal((await cache.candidates(GROUP, TARGET_T, contextB)).length, 4);

  const both = await spent(() =>
    cache.candidates(GROUP, TARGET_T, { ...CONTEXT, issuerNames: ["issuer_a", "issuer_b"] }),
  );
  assert.ok(
    both.result.map(base64urlEncode).includes(C1.periodKey),
    "issuer A's chain key still derives the period key its unoffered memo holds",
  );
  assert.equal(both.result.length, 5, "four offered memos and one walked chain key");
  assert.equal(
    both.derivations,
    walkA.derivations,
    "only issuer A's chain walks; issuer B's offered memos stand in for theirs",
  );
});
