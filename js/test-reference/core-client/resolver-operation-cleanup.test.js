// @ts-check
//
// Every resolver entry that reads under a response application completes that
// response's attempt when it ends, by a fault as well as by a return: the
// cache hears `attempted` exactly once, the application stops naming its
// lease, and the caller still sees the fault that ended the operation. A
// concurrent reader of the same application keeps its private material until
// it finishes, whichever operation faulted first.

import test from "node:test";
import assert from "node:assert/strict";

import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../core-client/DcaRequestBuilder.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { encrypt } from "../../core-shared/aead.js";
import { base64urlEncode, utf8Encode } from "../../core-shared/codec.js";

const PUB = "https://publisher.example";
const GROUP = "premium";
const ISSUER = "period_issuer";
const T = "251023T1415";
const PERIOD_KEY = new Uint8Array(16).fill(5);
const CONTENT_KEY = new Uint8Array(16).fill(20);

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {unknown} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", kid: "publisher-1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

/** One render whose item "a" is wrapped at T under PERIOD_KEY. */
async function page() {
  const wrapNonce = new Uint8Array(12).fill(11);
  const resource = { origin: PUB, resourceId: "123456", renderId: "r-1" };
  return new DcaData(
    {
      version: "1",
      resource,
      resourceJWT: compactJwt(resource),
      issuerData: {
        [ISSUER]: {
          keyId: "k1",
          unlockUrl: "https://period.example/unlock",
          sealed: { periodKeys: { [GROUP]: { [T]: "AAAA" } } },
        },
      },
      contentData: {
        a: {
          contentType: "text/plain",
          nonce: base64urlEncode(new Uint8Array(12).fill(1)),
          aad: "item:a",
          keys: {
            [GROUP]: [
              {
                t: T,
                nonce: base64urlEncode(wrapNonce),
                key: base64urlEncode(await encrypt(PERIOD_KEY, wrapNonce, CONTENT_KEY)),
              },
            ],
          },
        },
      },
    },
    { publisherOrigin: PUB },
  );
}

/**
 * A period cache that holds response-private keys under their lease and
 * records every read lease and every completion. `reads` lists one hook per
 * upcoming read; a hook may throw or wait.
 */
function recordingCache() {
  /** @type {Map<object, Uint8Array[]>} */
  const pending = new Map();
  /** @type {(object|undefined)[]} */
  const readLeases = [];
  /** @type {object[]} */
  const completions = [];
  /** @type {(() => Promise<void>|void)[]} */
  const reads = [];
  /** @type {Error|null} */
  let completionFault = null;
  return {
    readLeases,
    completions,
    reads,
    /** @param {Error} fault */
    failCompletion(fault) {
      completionFault = fault;
    },
    cache: {
      async clearReaderContext() {
        pending.clear();
      },
      /** @param {string} _group @param {string} _t @param {Uint8Array} key @param {{ lease?: object }} context */
      async put(_group, _t, key, { lease }) {
        if (lease !== undefined) pending.set(lease, [...(pending.get(lease) ?? []), key]);
      },
      /** @param {string} _group @param {string} _t @param {{ lease?: object }} context */
      async candidatesAt(_group, _t, { lease }) {
        readLeases.push(lease);
        await reads.shift()?.();
        return lease === undefined ? [] : (pending.get(lease) ?? []);
      },
      /** @param {{ lease: object }} context */
      async attempted({ lease }) {
        completions.push(lease);
        pending.delete(lease);
        if (completionFault) throw completionFault;
      },
    },
  };
}

/** A resolver over a recording cache, and the application of one direct period-key answer.
 * @param {import('../../core-client/ContentKeyResolver.js').ChainCache} [chainCache]
 */
async function obtained(chainCache) {
  const recorder = recordingCache();
  const resolver = new ContentKeyResolver({
    cache: recorder.cache,
    ...(chainCache && {
      chainCache,
      chainKeyProfile: {
        constructionProfile: {
          name: "test-chain-profile",
          constructionId: "test",
          chainKeyBytes: 16,
        },
        parametersForResponse: () => ({}),
        acceptsPeriodKeyResponseCoordinate: () => true,
        acceptsResponseCoordinate: () => true,
        candidateSourceFor: () => ({ async *attempts() {} }),
      },
    }),
  });
  const data = await page();
  const request = new DcaRequestBuilder({ relayPeriodKeys: true })
    .build(data, ISSUER, ["a"])
    .toObject();
  const application = await resolver.applyResponse(
    data,
    ISSUER,
    { keys: { periodKeys: { [GROUP]: { [T]: base64urlEncode(PERIOD_KEY) } } } },
    new ResponseAssociation(data, ISSUER, request),
  );
  assert.equal(application.accepted, 1);
  return { recorder, resolver, data, application };
}

/** @param {string} message */
function storageFault(message) {
  return Object.assign(new Error(message), { code: "storage_fault" });
}

/**
 * Each entry that takes an application, called for item "a".
 * @type {Record<string, (resolver: ContentKeyResolver, data: DcaData, application: object) => Promise<unknown>>}
 */
const ENTRIES = {
  resolveDetailed: (resolver, data, application) =>
    resolver.resolveDetailed(data, ["a"], application),
  resolve: (resolver, data, application) => resolver.resolve(data, ["a"], application),
  contentKeyWithOriginFor: (resolver, data, application) =>
    resolver.contentKeyWithOriginFor(data, "a", application),
  contentKeyFor: (resolver, data, application) => resolver.contentKeyFor(data, "a", application),
  resolveAuthenticated: (resolver, data, application) =>
    resolver.resolveAuthenticated(data, ["a"], async () => true, application),
};

for (const [name, entry] of Object.entries(ENTRIES)) {
  test(`${name} surfaces a storage fault and completes the obtaining attempt exactly once`, async () => {
    const { recorder, resolver, data, application } = await obtained();
    const fault = storageFault("transient storage fault");
    recorder.reads.push(() => {
      throw fault;
    });

    await assert.rejects(entry(resolver, data, application), (error) => error === fault);
    const lease = recorder.readLeases[0];
    assert.equal(typeof lease, "object", "the faulted read ran under the response lease");
    assert.deepEqual(recorder.completions, [lease], "the attempt completed once, under that lease");

    await entry(resolver, data, application);
    assert.equal(
      recorder.readLeases[1],
      undefined,
      "the application no longer names its lease, so a later call is a later operation",
    );
    assert.equal(recorder.completions.length, 1, "and nothing completes twice");
  });

  test(`${name} surfaces the operation fault when completion also fails`, async () => {
    const { recorder, resolver, data, application } = await obtained();
    const fault = storageFault("read fault");
    recorder.reads.push(() => {
      throw fault;
    });
    recorder.failCompletion(storageFault("completion fault"));

    await assert.rejects(entry(resolver, data, application), (error) => error === fault);
    assert.equal(recorder.completions.length, 1, "completion still ran once");
  });

  test(`${name} completes once after a concurrent reader of the same application finishes`, async () => {
    const { recorder, resolver, data, application } = await obtained();
    /** @type {() => void} */
    let release = () => undefined;
    const held = new Promise((resolve) => {
      release = () => resolve(undefined);
    });
    const fault = storageFault("transient storage fault");
    recorder.reads.push(
      () => held,
      () => {
        throw fault;
      },
    );

    const reader = resolver.resolveDetailed(data, ["a"], application);
    const faulting = entry(resolver, data, application);
    /** @type {unknown} */
    let faulted = null;
    const settled = faulting.catch((error) => {
      faulted = error;
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.deepEqual(
      recorder.completions,
      [],
      "the faulted operation waits for the captured reader before completing",
    );

    release();
    const read = await reader;
    await settled;
    assert.equal(faulted, fault);
    assert.deepEqual(read.covered, ["a"], "the reader still opened with the private key");
    assert.equal(recorder.completions.length, 1);
  });
}

test("a predicate fault in resolveAuthenticated surfaces and completes the attempt once", async () => {
  const { recorder, resolver, data, application } = await obtained();
  const fault = new Error("predicate fault");
  await assert.rejects(
    resolver.resolveAuthenticated(
      data,
      ["a"],
      async () => {
        throw fault;
      },
      application,
    ),
    (error) => error === fault,
  );
  assert.equal(recorder.completions.length, 1);
});

for (const [name, entry] of Object.entries(ENTRIES)) {
  test(`${name} releases both caches after a failed promotion without poisoning later calls`, async () => {
    const fault = storageFault("promotion failed");
    let promotions = 0;
    let releases = 0;
    const { recorder, resolver, data, application } = await obtained({
      async put() {},
      async candidates() {
        return [];
      },
      async promote() {
        promotions++;
        throw fault;
      },
      async attempted() {
        releases++;
        throw storageFault("chain cleanup failed");
      },
    });
    recorder.failCompletion(storageFault("period cleanup failed"));

    await assert.rejects(entry(resolver, data, application), (error) => error === fault);
    assert.equal(promotions, 1);
    assert.equal(recorder.completions.length, 1);
    assert.equal(releases, 1, "period cleanup failure did not skip chain cleanup");
    const retained =
      name === "contentKeyFor" || name === "contentKeyWithOriginFor" ? null : CONTENT_KEY;
    assert.deepEqual(
      await resolver.contentKeyFor(data, "a", application),
      retained,
      "later lookup follows ordinary item retention without replaying the completion fault",
    );
    assert.equal(promotions, 1);
    assert.equal(releases, 1);
    assert.equal(recorder.completions.length, 1);
  });
}

test("failed promotion detaches new calls but drains captured readers with their private keys", async () => {
  const promotionFault = storageFault("promotion failed");
  const operationFault = storageFault("reader failed");
  let promotions = 0;
  let releases = 0;
  const { recorder, resolver, data, application } = await obtained({
    async put() {},
    async candidates() {
      return [];
    },
    async promote() {
      promotions++;
      throw promotionFault;
    },
    async attempted() {
      releases++;
    },
  });
  let release = () => {};
  const barrier = new Promise((resolve) => {
    release = () => resolve(undefined);
  });
  recorder.reads.push(
    () => barrier,
    () => {
      throw operationFault;
    },
  );
  const reader = resolver.resolveDetailed(data, ["a"], application);
  const faulting = resolver.contentKeyFor(data, "a", application);
  const joiner = resolver.resolveDetailed(data, [], application);
  const settled = Promise.all([
    assert.rejects(reader, (error) => error === promotionFault),
    assert.rejects(faulting, (error) => error === operationFault),
    assert.rejects(joiner, (error) => error === promotionFault),
  ]);
  try {
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(promotions, 1);
    assert.deepEqual(recorder.completions, [], "captured reader still owns private material");
    assert.equal(releases, 0);
    assert.equal(
      await resolver.contentKeyFor(data, "a", application),
      null,
      "a new call uses ordinary retained material, without joining the failed lease",
    );
    assert.equal(recorder.readLeases.at(-1), undefined);
  } finally {
    release();
    await settled;
  }
  assert.equal(recorder.completions.length, 1);
  assert.equal(releases, 1);
  assert.deepEqual(
    await resolver.contentKeyFor(data, "a", application),
    CONTENT_KEY,
    "the captured reader acquired its private key before terminal release",
  );
});

test("a cleanup fault is terminal and both cleanup owners run once", async () => {
  const fault = storageFault("period cleanup failed");
  let releases = 0;
  const { recorder, resolver, data, application } = await obtained({
    async put() {},
    async candidates() {
      return [];
    },
    async attempted() {
      releases++;
      throw storageFault("chain cleanup failed");
    },
  });
  recorder.failCompletion(fault);
  await assert.rejects(
    resolver.resolveDetailed(data, ["a"], application),
    (error) => error === fault,
  );
  assert.equal(releases, 1);
  assert.deepEqual(await resolver.contentKeyFor(data, "a", application), CONTENT_KEY);
  assert.equal(recorder.completions.length, 1);
  assert.equal(releases, 1);
});

test("reader reset retires completion waiters while captured readers drain", async () => {
  let entered, release, promoted;
  const reading = new Promise((resolve) => {
    entered = resolve;
  });
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const promotion = new Promise((resolve) => {
    promoted = resolve;
  });
  const chainCache = {
    put() {},
    candidates: async () => [],
    attempted: async () => {},
    promote: async () => {
      promoted();
    },
    clearReaderContext: async () => {},
  };
  const { recorder, resolver, data, application } = await obtained(chainCache);
  recorder.reads.push(async () => {
    entered();
    await held;
  });
  const first = assert.rejects(resolver.resolveDetailed(data, ["a"], application), {
    code: "context_retired",
  });
  await reading;
  const second = assert.rejects(resolver.resolveDetailed(data, ["a"], application), {
    code: "context_retired",
  });
  await promotion;
  // Let the completed promotion's continuation enter its captured-reader wait.
  await Promise.resolve();
  await resolver.clearReaderContext();
  release();
  await Promise.all([first, second]);
  assert.deepEqual((await resolver.resolveDetailed(data, ["a"], application)).missing, ["a"]);
});

test("resolver cleanup invokes every retaining owner even after a synchronous failure", async () => {
  for (const failingSide of ["period", "chain"]) {
    const fault = new Error(`${failingSide} cleanup failed`);
    let period = 0,
      chain = 0;
    const resolver = new ContentKeyResolver({
      cache: {
        put() {},
        candidatesAt: async () => [],
        attempted: async () => {},
        clearReaderContext() {
          period++;
          if (failingSide === "period") throw fault;
        },
      },
      chainCache: {
        put() {},
        candidates: async () => [],
        attempted: async () => {},
        clearReaderContext() {
          chain++;
          if (failingSide === "chain") throw fault;
          return Promise.resolve();
        },
      },
      chainKeyProfile: {
        constructionProfile: { name: "test", constructionId: "test", chainKeyBytes: 16 },
        parametersForResponse: () => ({}),
        acceptsPeriodKeyResponseCoordinate: () => true,
        acceptsResponseCoordinate: () => true,
        candidateSourceFor: () => ({ async *attempts() {} }),
      },
    });
    const clearing = resolver.clearReaderContext();
    assert.deepEqual({ period, chain }, { period: 1, chain: 1 });
    await assert.rejects(clearing, (error) => error === fault);
    await assert.rejects(resolver.clearReaderContext(), (error) => error === fault);
    await assert.rejects(resolver.contentKeyFor(await page(), "a"), { code: "context_retired" });
  }
});
