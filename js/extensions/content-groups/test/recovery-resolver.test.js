// @ts-check
//
// The shared resolver's recovery-source seam, driven by test sources. A source
// yields candidate content keys; the resolver authenticates each through the
// caller's predicate, bounds the trials per item, holds the first key that
// opens, and fences every step against a reader reset. A source never sees an
// unauthenticated path: a plain resolve does not ask it.

import test from "node:test";
import assert from "node:assert/strict";

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";

const RIGHT = new Uint8Array(16).fill(19);
/** @param {number} fill */
const wrong = (fill) => new Uint8Array(16).fill(fill);

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {object} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", typ: "JWT", kid: "k1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

function page() {
  return new DcaData(
    {
      version: "1",
      resourceJWT: compactJwt({ origin: "https://news.example", renderId: "r-1" }),
      issuerData: [{ issuerName: "issuer", keyId: "k1", sealed: {} }],
      contentData: [
        {
          contentName: "bodytext",
          contentType: "text/html",
          nonce: base64urlEncode(new Uint8Array(12)),
        },
      ],
    },
    { publisherOrigin: "https://news.example" },
  );
}

/** @param {Uint8Array} candidate */
const opensRight = async (candidate) =>
  candidate instanceof Uint8Array && candidate.every((byte, i) => byte === RIGHT[i]);

/**
 * A recovery source over a fixed candidate list that records what it saw.
 * @param {Uint8Array[]} keys
 * @param {{ maxTrialsPerItem?: number, before?: (index: number) => Promise<void> }} [options]
 */
function listSource(keys, { maxTrialsPerItem = 16, before } = {}) {
  const seen = { calls: /** @type {any[]} */ ([]), yielded: 0, closed: false, cleared: 0 };
  return {
    seen,
    source: {
      maxTrialsPerItem,
      /** @param {any} context */
      async *candidates(context) {
        seen.calls.push(context);
        try {
          for (const [index, contentKey] of keys.entries()) {
            await before?.(index);
            seen.yielded++;
            yield { contentKey, origin: { route: "test", index } };
          }
        } finally {
          seen.closed = true;
        }
      },
      async clearReaderContext() {
        seen.cleared++;
      },
    },
  };
}

test("an authenticated recovery holds the first key that opens and answers it as held", async () => {
  const { seen, source } = listSource([wrong(1), wrong(2), RIGHT, wrong(3)]);
  const resolver = new ContentKeyResolver({ recoverySources: [source] });
  const dcaData = page();

  const result = await resolver.resolveAuthenticated(dcaData, ["bodytext"], (_, candidate) =>
    opensRight(/** @type {Uint8Array} */ (candidate)),
  );
  assert.deepEqual(result.covered, ["bodytext"]);
  assert.deepEqual(result.origins, [
    { contentName: "bodytext", origin: { kind: "recovered-content-key", route: "test", index: 2 } },
  ]);
  assert.equal(seen.yielded, 3, "the walk stops at the first authenticated key");
  assert.ok(seen.closed, "the resolver closes the source after its answer");
  assert.equal(seen.calls[0].contentName, "bodytext");
  assert.equal(seen.calls[0].publisher, "https://news.example");
  assert.equal(seen.calls[0].renderId, "r-1");
  assert.equal(seen.calls[0].dcaData, dcaData);
  assert.equal(typeof seen.calls[0].check, "function");

  const held = await resolver.contentKeyWithOriginFor(dcaData, "bodytext");
  assert.deepEqual(held, { key: RIGHT, origin: { kind: "held-content-key" } });
});

test("an unauthenticated resolve never asks a recovery source", async () => {
  const { seen, source } = listSource([RIGHT]);
  const resolver = new ContentKeyResolver({ recoverySources: [source] });
  const result = await resolver.resolveDetailed(page(), ["bodytext"]);
  assert.deepEqual(result.missing, ["bodytext"]);
  assert.equal(await resolver.contentKeyFor(page(), "bodytext"), null);
  assert.equal(seen.calls.length, 0, "recovered bytes are never held without authentication");
});

test("maxTrialsPerItem bounds the authenticated trials of one item in one call", async () => {
  const { seen, source } = listSource(
    Array.from({ length: 10 }, (_, i) => wrong(i + 1)),
    { maxTrialsPerItem: 3 },
  );
  const resolver = new ContentKeyResolver({ recoverySources: [source] });
  let trials = 0;
  const key = await resolver.contentKeyForAuthenticatedItem(page(), "bodytext", async () => {
    trials++;
    return false;
  });
  assert.equal(key, null);
  assert.equal(trials, 3);
  assert.ok(seen.closed);
});

test("a recovery source is checked at construction and its candidates are checked", async () => {
  const valid = listSource([]).source;
  for (const bad of [
    { ...valid, candidates: undefined },
    { ...valid, maxTrialsPerItem: 0 },
    { ...valid, maxTrialsPerItem: 1.5 },
    { ...valid, promote: "no" },
  ])
    assert.throws(
      () => new ContentKeyResolver({ recoverySources: [/** @type {any} */ (bad)] }),
      (error) => /** @type {any} */ (error)?.code === "bad_config",
    );
  assert.throws(
    () => new ContentKeyResolver({ recoverySources: /** @type {any} */ (valid) }),
    (error) => /** @type {any} */ (error)?.code === "bad_config",
  );

  const resolver = new ContentKeyResolver({
    recoverySources: [listSource([new Uint8Array(15)]).source],
  });
  await assert.rejects(
    resolver.contentKeyForAuthenticatedItem(page(), "bodytext", opensRight),
    (error) => /** @type {any} */ (error)?.code === "bad_config" && /16/.test(error.message),
  );
});

test("reset during a source's await: no authentication, nothing held, the call is retired", async () => {
  /** @type {(() => void)|null} */
  let release = null;
  const { seen, source } = listSource([RIGHT], {
    // This source ignores check(); the resolver must fence on its own.
    before: () =>
      new Promise((resolve) => {
        release = () => resolve(undefined);
      }),
  });
  const resolver = new ContentKeyResolver({ recoverySources: [source] });
  const dcaData = page();
  let authenticated = 0;
  const pending = resolver.contentKeyForAuthenticatedItem(dcaData, "bodytext", async (key) => {
    authenticated++;
    return opensRight(/** @type {Uint8Array} */ (key));
  });
  while (release === null) await new Promise((resolve) => setImmediate(resolve));
  const check = seen.calls[0].check;

  const clearing = resolver.clearReaderContext();
  assert.throws(check, (error) => /** @type {any} */ (error)?.code === "context_retired");
  /** @type {() => void} */ (release)();
  await assert.rejects(pending, (error) => /** @type {any} */ (error)?.code === "context_retired");
  await clearing;

  assert.equal(authenticated, 0, "no recovered key is authenticated under a retired reader");
  assert.equal(seen.cleared, 1, "the reset reached the recovery source");
  assert.equal(await resolver.contentKeyFor(dcaData, "bodytext"), null);
});

test("recovery sources join reset and the reset-duty check", async () => {
  const { source } = listSource([]);
  const { clearReaderContext, ...retaining } = source;
  void clearReaderContext;
  const resolver = new ContentKeyResolver({ recoverySources: [retaining] });
  assert.throws(
    () => resolver.assertReaderContextReset(),
    (error) => /** @type {any} */ (error)?.code === "bad_config",
  );
  await assert.rejects(
    resolver.clearReaderContext(),
    (error) => /** @type {any} */ (error)?.code === "bad_config",
  );

  const complete = new ContentKeyResolver({ recoverySources: [listSource([]).source] });
  complete.assertReaderContextReset();
});
