// @ts-check
//
// The content-key resolver reads a page through one `DcaData` currency: the
// same instance a load builds once and threads through the whole flow. Every
// public entry (resolve, applyResponse, contentKeyFor) requires that
// instance and refuses a raw parsed object, so a caller cannot hand the
// resolver a page the builder would have refused. The refusal lands before any
// field is read: a raw object carrying a perfectly good renderId is still a
// `bad_config`, not a `bad_page`, so the guard is about the type of the
// argument and not the shape of the page inside it.
//
// The currency reads live: one instance re-reads its underlying object on
// every accessor, so a load that threads one instance still sees a mid-load
// mutation rather than a value cached at construction.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { Storage } from "../../demo/actors/Storage.js";
import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { attemptContentKeyWrap } from "../../core-client/contentKeyWrapAttempt.js";
import { periodKeyCandidateSource } from "../../core-client/periodKeyCandidateSource.js";
import { openContent } from "../../core-client/openContent.js";
import { DcaData } from "../../core-client/DcaData.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { decrypt, encrypt } from "../../core-shared/aead.js";
import { binaryStringBytes } from "../../core-shared/binaryStrings.js";
import { base64urlEncode, utf8Decode, utf8Encode } from "../../core-shared/codec.js";
import { decodeCompactJwt } from "../../core-shared/compactJwt.js";
import { dcaError } from "../../core-shared/errors.js";
import { Client } from "../../test-lib/harnesses/client.js";

function compactJwt(payload) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "ES256", kid: "publisher-1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

/**
 * The identity a chain-capable bundle states: the construction its cache and
 * candidate source were composed on, and the period-key profile whose keys that
 * construction derives. The bundles below are doubles, so this record is
 * written here rather than taken from the extension, which the base does not
 * import.
 */
const CHAIN_IDENTITY = {
  name: "dca-profile-chain-keys",
  constructionId: "dca-construction-chain-keys",
  chainKeyBytes: 16,
};

/** A well-formed page, so a rejection is about the argument type and not the page. */
function pageData() {
  return {
    version: "1",
    resource: {
      origin: "https://signed.example",
      resourceId: "123456",
      renderId: "AAAAAAAAAAAAAAAAAAAAAA",
    },
    resourceJWT: compactJwt({
      origin: "https://signed.example",
      resourceId: "123456",
      renderId: "AAAAAAAAAAAAAAAAAAAAAA",
    }),
    issuerData: {
      issuer_example: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: {} },
    },
    contentData: { bodytext: { contentType: "text/html", nonce: "n" } },
  };
}

/** Preserve old focused fixtures while spelling out which response each belongs to. */
function applyResponse(resolver, page, issuerName, response) {
  if (!(page instanceof DcaData)) return resolver.applyResponse(page, issuerName, response);
  const keys = response?.keys;
  const sealed = { contentKeys: {} };
  if (keys !== null && typeof keys === "object" && !Array.isArray(keys)) {
    for (const section of ["contentKeys", "periodKeys", "chainKeys"]) {
      const value = keys[section];
      if (value !== undefined) sealed[section] = value;
    }
  }
  const request = {
    version: page.version,
    issuerName,
    resourceJWT: page.resourceJWT,
    keyId: page.keyIdFor(issuerName),
    sealed,
  };
  if (response?.transport?.method === "ECDH-P256") {
    request.clientPublicKey = { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" };
  } else if (response?.transport?.method === "RSA-OAEP") {
    request.clientPublicKey = { kty: "RSA", n: "request-n", e: "AQAB" };
  }
  return resolver.applyResponse(
    page,
    issuerName,
    response,
    new ResponseAssociation(page, issuerName, request),
  );
}

/** @param {DcaData} page @param {string} issuerName @param {object} sealed @param {object} [requestMembers] */
function associationFor(page, issuerName, sealed, requestMembers = {}) {
  return new ResponseAssociation(page, issuerName, {
    version: page.version,
    issuerName,
    resourceJWT: page.resourceJWT,
    keyId: page.keyIdFor(issuerName),
    sealed,
    ...requestMembers,
  });
}

/**
 * The same bytes spelled in the standard alphabet: `-` and `+` are both 62, `_`
 * and `/` are both 63. The generic decoder translates them back, so a value
 * respelled this way carries exactly the bytes the canonical spelling carries
 * and only the spelling is refused. Bytes of 0xfb encode as `-_v7`, so
 * every value respelled below has a character to respell.
 *
 * @param {string} canonical
 * @returns {string}
 */
function standardAlphabet(canonical) {
  assert.match(
    canonical,
    /[-_]/,
    "the value has a character the standard alphabet spells another way",
  );
  return canonical.replace(/-/g, "+").replace(/_/g, "/");
}

describe("one content-key wrap attempt", () => {
  test("ordinary bytes and an opaque period-key handle open the same wrap in their native forms", async () => {
    const periodKey = new Uint8Array(16).fill(3);
    const contentKey = new Uint8Array(16).fill(7);
    const nonce = new Uint8Array(12).fill(4);
    const entry = {
      t: "251023T1500",
      nonce: base64urlEncode(nonce),
      key: base64urlEncode(await encrypt(periodKey, nonce, contentKey)),
    };

    assert.deepEqual(await attemptContentKeyWrap(entry, periodKey), contentKey);

    const periodHandle = await globalThis.crypto.subtle.importKey(
      "raw",
      periodKey,
      { name: "AES-GCM" },
      false,
      ["unwrapKey"],
    );
    const opened = await attemptContentKeyWrap(entry, periodHandle);
    assert.ok(
      opened instanceof globalThis.CryptoKey,
      "the opaque path returns a handle, not bytes",
    );
    assert.equal(opened.extractable, false);
    assert.deepEqual([...opened.usages], ["decrypt"]);
    await assert.rejects(() => globalThis.crypto.subtle.exportKey("raw", periodHandle));
    await assert.rejects(() => globalThis.crypto.subtle.exportKey("raw", opened));

    const article = new Uint8Array([1, 2, 3]);
    const articleNonce = new Uint8Array(12).fill(5);
    assert.deepEqual(
      await decrypt(opened, articleNonce, await encrypt(contentKey, articleNonce, article)),
      article,
      "the returned handle is usable for content decryption",
    );
  });

  test("decode and authentication failures miss, while configuration faults stay faults", async () => {
    const periodKey = new Uint8Array(16).fill(3);
    const nonce = new Uint8Array(12).fill(4);
    const wrapped = await encrypt(periodKey, nonce, new Uint8Array(16).fill(7));
    const entry = { nonce: base64urlEncode(nonce), key: base64urlEncode(wrapped) };

    assert.equal(await attemptContentKeyWrap({ ...entry, key: "!!!!" }, periodKey), null);
    assert.equal(
      await attemptContentKeyWrap(entry, periodKey, new Uint8Array([1])),
      null,
      "the wrong AAD is an authentication miss",
    );
    assert.equal(
      await attemptContentKeyWrap(
        { ...entry, nonce: base64urlEncode(new Uint8Array(11)) },
        periodKey,
      ),
      null,
      "a malformed entry nonce is a pre-crypto miss",
    );
    // A byte candidate of another width is not a key this profile's wrap
    // takes, so it is refused rather than tried and missed: a miss there
    // would read as the wrong key rather than as the wrong profile.
    await assert.rejects(
      () => attemptContentKeyWrap(entry, new Uint8Array(31)),
      (/** @type {any} */ error) => error.code === "bad_key",
    );
    await assert.rejects(
      () => attemptContentKeyWrap(entry, /** @type {any} */ ({})),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("authenticated non-16-byte content-key carriers miss for bytes and handles", async () => {
    const periodKey = new Uint8Array(16).fill(3);
    const nonce = new Uint8Array(12).fill(4);
    const periodHandle = await globalThis.crypto.subtle.importKey(
      "raw",
      periodKey,
      { name: "AES-GCM" },
      false,
      ["unwrapKey"],
    );

    for (const width of [15, 17, 24, 32]) {
      const entry = {
        nonce: base64urlEncode(nonce),
        key: base64urlEncode(await encrypt(periodKey, nonce, new Uint8Array(width).fill(7))),
      };
      assert.equal(
        await attemptContentKeyWrap(entry, periodKey),
        null,
        `${width}-byte authenticated plaintext is not a v1 content key under period-key bytes`,
      );
      assert.equal(
        await attemptContentKeyWrap(entry, periodHandle),
        null,
        `${width}-byte authenticated plaintext is not a client-bound v1 content key`,
      );
    }
  });

  test("an authenticated wrong-width first wrap does not suppress a later valid wrap", async () => {
    const periodKey = new Uint8Array(16).fill(3);
    const contentKey = new Uint8Array(16).fill(7);
    const nonce = new Uint8Array(12).fill(4);

    for (const width of [15, 17, 24, 32]) {
      const raw = pageData();
      raw.contentData.bodytext.keys = {
        premium: [
          {
            t: "251023T1500",
            nonce: base64urlEncode(nonce),
            key: base64urlEncode(await encrypt(periodKey, nonce, new Uint8Array(width).fill(9))),
          },
          {
            t: "251023T1500",
            nonce: base64urlEncode(nonce),
            key: base64urlEncode(await encrypt(periodKey, nonce, contentKey)),
          },
        ],
      };
      const resolver = new ContentKeyResolver({
        cache: { put() {}, candidatesAt: () => [periodKey], attempted() {} },
      });
      assert.deepEqual(
        await resolver.contentKeyFor(new DcaData(raw), "bodytext"),
        contentKey,
        `${width}-byte first wrap is a miss and the canonical sibling opens`,
      );
    }
  });

  test("malformed entries and cached byte candidates stay provisional until a later candidate opens", async () => {
    const periodKey = new Uint8Array(16).fill(3);
    const contentKey = new Uint8Array(16).fill(7);
    const nonce = new Uint8Array(12).fill(4);
    const raw = pageData();
    raw.contentData.bodytext.keys = {
      premium: [
        { t: "251023T1500", nonce: base64urlEncode(new Uint8Array(11)), key: "AAAA" },
        {
          t: "251023T1500",
          nonce: base64urlEncode(nonce),
          key: base64urlEncode(await encrypt(periodKey, nonce, contentKey)),
        },
      ],
    };
    // A rival key of this profile's width that opens nothing, ahead of the
    // one that opens: both are keys the wrap takes, so the first is a miss
    // and the walk goes on. A candidate of another width is a refusal
    // instead, proven in the wrap-attempt case above.
    const resolver = new ContentKeyResolver({
      cache: {
        put() {},
        candidatesAt: () => [new Uint8Array(16).fill(9), periodKey],
        attempted() {},
      },
    });

    assert.deepEqual(
      await resolver.contentKeyFor(new DcaData(raw), "bodytext"),
      contentKey,
      "the later valid candidate still answers after both malformed misses",
    );
  });

  test("a resolver given an unknown option is refused at construction", () => {
    assert.throws(
      () => new ContentKeyResolver({ inventedSelector: "dca-profile-period-keys-invented" }),
      (/** @type {any} */ error) => error.code === "unsupported_option",
    );
  });

  test("a wrap entry respelled in the standard alphabet is a miss, not the key it would decode to", async () => {
    const periodKey = new Uint8Array(16).fill(3);
    const contentKey = new Uint8Array(16).fill(7);
    const nonce = new Uint8Array(12).fill(0xfb);
    const entry = {
      t: "251023T1500",
      nonce: base64urlEncode(nonce),
      key: base64urlEncode(await encrypt(periodKey, nonce, contentKey)),
    };

    assert.deepEqual(await attemptContentKeyWrap(entry, periodKey), contentKey, "the control");
    assert.equal(
      await attemptContentKeyWrap({ ...entry, nonce: standardAlphabet(entry.nonce) }, periodKey),
      null,
      "a nonce in the standard alphabet supplies no nonce bytes",
    );
    assert.equal(
      await attemptContentKeyWrap({ ...entry, key: standardAlphabet(entry.key) }, periodKey),
      null,
      "a wrapped key in the standard alphabet supplies no carrier bytes",
    );
    assert.equal(
      await attemptContentKeyWrap({ ...entry, nonce: `${entry.nonce}=` }, periodKey),
      null,
      "and a padded nonce is the same miss",
    );
  });

  test("a noncanonical sealed entry leaves a valid sibling candidate usable", async () => {
    // The failure scope in spec--data-format.md Section 2.2, "Binary
    // strings": one unreadable sealed entry removes one candidate. The two entries
    // wrap different keys, so an implementation that took the first one
    // would answer with the wrong bytes rather than with the sibling's.
    const periodKey = new Uint8Array(16).fill(3);
    const refused = new Uint8Array(16).fill(1);
    const sibling = new Uint8Array(16).fill(2);
    const nonce = new Uint8Array(12).fill(0xfb);
    const raw = pageData();
    const sealedEntry = async (/** @type {Uint8Array} */ contentKey) => ({
      t: "251023T1500",
      nonce: base64urlEncode(nonce),
      key: base64urlEncode(await encrypt(periodKey, nonce, contentKey)),
    });
    const first = await sealedEntry(refused);
    raw.contentData.bodytext.keys = {
      premium: [{ ...first, key: standardAlphabet(first.key) }, await sealedEntry(sibling)],
    };
    const resolver = new ContentKeyResolver({
      cache: { put() {}, candidatesAt: () => [periodKey], attempted() {} },
    });

    assert.deepEqual(
      await resolver.contentKeyFor(new DcaData(raw), "bodytext"),
      sibling,
      "the canonical sibling answers, and the respelled sealed entry supplied nothing",
    );
  });

  test("base declines an unknown binding marker instead of guessing ordinary no-AAD", async () => {
    const periodKey = new Uint8Array(16).fill(3);
    const contentKey = new Uint8Array(16).fill(7);
    const nonce = new Uint8Array(12).fill(4);
    const entry = {
      t: "251023T1500",
      nonce: base64urlEncode(nonce),
      key: base64urlEncode(await encrypt(periodKey, nonce, contentKey)),
      bind: "unknown-binding",
    };
    const raw = pageData();
    raw.contentData.bodytext.keys = { premium: [entry] };
    const resolver = new ContentKeyResolver({
      cache: { put() {}, candidatesAt: () => [periodKey], attempted() {} },
    });

    assert.equal(await resolver.contentKeyFor(new DcaData(raw), "bodytext"), null);
    delete entry.bind;
    assert.deepEqual(
      await resolver.contentKeyFor(new DcaData(raw), "bodytext"),
      contentKey,
      "the otherwise identical ordinary entry remains the valid sibling",
    );
  });
});

test("whole-delivery admission precedes held and cached key use", async () => {
  const malformed = pageData();
  malformed.version = "2";
  let cacheReads = 0;
  const resolver = new ContentKeyResolver({
    cache: {
      put() {},
      candidatesAt() {
        cacheReads += 1;
        return [new Uint8Array(16).fill(3)];
      },
      attempted() {},
    },
  });

  await assert.rejects(
    () => resolver.contentKeyFor(new DcaData(malformed), "bodytext"),
    (/** @type {any} */ error) => error.code === "bad_page" && /version "1"/.test(error.message),
  );
  assert.equal(cacheReads, 0, "no cached candidate is read before outer admission");
});

test("the period-key source reads only each entry's exact coordinate and carries cache provenance", async () => {
  const entries = [{ t: "251023T1400" }, { t: "251023T1500" }];
  const first = new Uint8Array(16).fill(1);
  const second = new Uint8Array(16).fill(2);
  const calls = [];
  const source = periodKeyCandidateSource({
    candidatesAt(accessGroup, t, context) {
      calls.push({ accessGroup, t, context });
      return [first, second];
    },
    attempted() {},
  });
  const attempts = [];
  for await (const attempt of source.attempts({
    dcaData: new DcaData(pageData()),
    contentName: "bodytext",
    accessGroup: "premium",
    entries,
    publisher: "https://publisher.example",
    issuerNames: ["issuer-a", "issuer-b"],
  }))
    attempts.push(attempt);

  assert.deepEqual(
    calls,
    entries.map(({ t }) => ({
      accessGroup: "premium",
      t,
      context: {
        publisher: "https://publisher.example",
        issuerNames: ["issuer-a", "issuer-b"],
        lease: undefined,
      },
    })),
  );
  assert.deepEqual(
    attempts.map(({ entry, periodKey }) => [entry.t, periodKey[0]]),
    [
      ["251023T1400", 1],
      ["251023T1400", 2],
      ["251023T1500", 1],
      ["251023T1500", 2],
    ],
  );
  assert.deepEqual(
    attempts.map(({ origin }) => origin),
    [
      { kind: "cached-period-key", accessGroup: "premium", t: "251023T1400" },
      { kind: "cached-period-key", accessGroup: "premium", t: "251023T1400" },
      { kind: "cached-period-key", accessGroup: "premium", t: "251023T1500" },
      { kind: "cached-period-key", accessGroup: "premium", t: "251023T1500" },
    ],
  );
  assert.ok(attempts.every(({ origin }) => !Object.hasOwn(origin, "key")));
});

test("the period-key source bounds rivals per wrap and total key/wrap trials", async () => {
  const entries = Array.from({ length: 17 }, (_, i) => ({
    t: `251023T${String(i).padStart(2, "0")}00`,
  }));
  const source = periodKeyCandidateSource({
    candidatesAt() {
      return Array.from({ length: 5 }, (_, i) => new Uint8Array(16).fill(i));
    },
    attempted() {},
  });
  const attempts = [];
  for await (const attempt of source.attempts({
    accessGroup: "premium",
    entries,
    issuerNames: [],
  }))
    attempts.push(attempt);

  assert.equal(attempts.length, 64, "the seventeenth four-rival coordinate is not attempted");
  assert.ok(
    attempts.every(
      ({ entry }) => attempts.filter((attempt) => attempt.entry === entry).length <= 4,
    ),
  );
});

test("each access group receives its own finite period-key/wrap budget", async () => {
  const raw = pageData();
  raw.contentData.bodytext.keys = Object.fromEntries(
    Array.from({ length: 17 }, (_, i) => [
      `group-${i}`,
      [{ t: "251023T1400", nonce: "AAAA", key: "AAAA" }],
    ]),
  );
  const asked = [];
  const resolver = new ContentKeyResolver({
    cache: {
      put() {},
      candidatesAt(accessGroup) {
        asked.push(accessGroup);
        return Array.from({ length: 4 }, () => new Uint8Array(16));
      },
      attempted() {},
    },
  });

  assert.equal(await resolver.contentKeyFor(new DcaData(raw), "bodytext"), null);
  assert.equal(asked.length, 17, "every alternative access group is attempted");
  assert.equal(asked.length * 4, 68, "each group applies its own four-rival bound");
});

test("period-key cache construction requires explicit candidatesAt and attempted methods", () => {
  for (const cache of [
    { put() {}, candidates() {}, attempted() {} },
    { put() {}, candidatesAt() {} },
  ]) {
    assert.throws(
      () => new ContentKeyResolver({ cache }),
      (/** @type {any} */ error) =>
        error.code === "bad_config" && /candidatesAt and attempted/.test(error.message),
    );
  }
  assert.throws(
    () => periodKeyCandidateSource({ candidates() {}, attempted() {} }),
    (/** @type {any} */ error) =>
      error.code === "bad_config" && /candidatesAt and attempted/.test(error.message),
  );
});

test("a source fault stays loud instead of becoming a candidate miss", async () => {
  const failure = new Error("store unavailable");
  const source = periodKeyCandidateSource({
    candidatesAt() {
      throw failure;
    },
    attempted() {},
  });
  await assert.rejects(
    async () => {
      for await (const unused of source.attempts({
        accessGroup: "premium",
        entries: [{ t: "251023T1400" }],
        issuerNames: [],
      }))
        void unused;
    },
    (error) => error === failure,
  );
});

test("all selected sources miss in one access group before the next group is tried", async () => {
  const contentKey = new Uint8Array(16).fill(9);
  const firstPeriodKey = new Uint8Array(16).fill(1);
  const secondPeriodKey = new Uint8Array(16).fill(2);
  const nonce = new Uint8Array(12).fill(4);
  const raw = pageData();
  raw.contentData.bodytext.keys = {
    first: [
      {
        t: "251023T1400",
        nonce: base64urlEncode(nonce),
        key: base64urlEncode(await encrypt(firstPeriodKey, nonce, contentKey)),
      },
    ],
    second: [
      {
        t: "251023T1400",
        nonce: base64urlEncode(nonce),
        key: base64urlEncode(await encrypt(secondPeriodKey, nonce, contentKey)),
      },
    ],
  };
  const reads = [];
  const resolver = new ContentKeyResolver({
    cache: {
      put() {},
      candidatesAt(accessGroup, t) {
        reads.push(accessGroup);
        void t;
        return [accessGroup === "first" ? new Uint8Array(16).fill(3) : secondPeriodKey];
      },
      attempted() {},
    },
  });

  assert.deepEqual(await resolver.contentKeyFor(new DcaData(raw), "bodytext"), contentKey);
  assert.deepEqual(reads, ["first", "second"], "page access-group order stays outermost");
});

test("the resolver refuses an option it does not implement", () => {
  assert.throws(
    () => new ContentKeyResolver(/** @type {any} */ ({ clock: {} })),
    (/** @type {any} */ error) => {
      assert.equal(error.code, "unsupported_option");
      assert.match(error.message, /ContentKeyResolver has no clock yet/);
      return true;
    },
  );
});

test("the resolver requires one synchronous entry interpretation shape", async () => {
  assert.throws(
    () => new ContentKeyResolver({ entryInterpretation: /** @type {any} */ ({}) }),
    (/** @type {any} */ error) => error.code === "bad_config",
  );

  const raw = pageData();
  raw.contentData.bodytext.keys = {
    premium: [{ t: "251023T1500", nonce: "AAAA", key: "AAAA" }],
  };
  const resolver = new ContentKeyResolver({
    cache: { put() {}, candidatesAt: () => [new Uint8Array(16)], attempted() {} },
    entryInterpretation: () => /** @type {any} */ (undefined),
  });
  await assert.rejects(
    () => resolver.contentKeyFor(new DcaData(raw), "bodytext"),
    (/** @type {any} */ error) =>
      error.code === "bad_config" && /entryInterpretation/.test(error.message),
  );

  const asynchronous = new ContentKeyResolver({
    cache: { put() {}, candidatesAt: () => [new Uint8Array(16)], attempted() {} },
    entryInterpretation: async () => ({ aad: undefined }),
  });
  await assert.rejects(
    () => asynchronous.contentKeyFor(new DcaData(raw), "bodytext"),
    (/** @type {any} */ error) =>
      error.code === "bad_config" && /synchronously/.test(error.message),
  );
});

describe("the resolver requires a DcaData currency", () => {
  test("resolve refuses a raw parsed object with bad_config", async () => {
    const resolver = new ContentKeyResolver();
    await assert.rejects(
      () => resolver.resolve(/** @type {any} */ (pageData()), ["bodytext"]),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
  });

  test("applyResponse refuses a raw parsed object with bad_config", async () => {
    const resolver = new ContentKeyResolver();
    await assert.rejects(
      () =>
        applyResponse(resolver, /** @type {any} */ (pageData()), "issuer_example", { keys: {} }),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
  });

  test("contentKeyFor refuses a raw parsed object with bad_config", async () => {
    const resolver = new ContentKeyResolver();
    await assert.rejects(
      () => resolver.contentKeyFor(/** @type {any} */ (pageData()), "bodytext"),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
  });

  test("the refusal lands before any renderId read", async () => {
    // A raw object carrying a valid renderId is still bad_config, never the
    // bad_page a missing renderId would raise once inside. So the guard
    // checks the argument type, before the page is read at all.
    const resolver = new ContentKeyResolver();
    for (const call of [
      () =>
        applyResponse(
          resolver,
          /** @type {any} */ ({ resource: { renderId: "AAAAAAAAAAAAAAAAAAAAAA" } }),
          "i",
          {
            keys: {},
          },
        ),
      () =>
        resolver.contentKeyFor(
          /** @type {any} */ ({ resource: { renderId: "AAAAAAAAAAAAAAAAAAAAAA" } }),
          "bodytext",
        ),
    ]) {
      await assert.rejects(call, (/** @type {any} */ e) => e.code === "bad_config");
    }
  });

  test("a DcaData currency is accepted by every entry", async () => {
    const resolver = new ContentKeyResolver();
    const page = new DcaData(pageData());

    // No cache and nothing held, so these answer rather than throw, and
    // the DcaData argument passes the type guard.
    assert.deepEqual(await resolver.resolve(page, ["bodytext"]), {
      covered: [],
      missing: ["bodytext"],
    });
    assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
    await applyResponse(resolver, page, "issuer_example", { keys: {} });
  });
});

describe("a malformed key value is skipped, not fatal", () => {
  for (const [shape, periodKeys] of [
    ["numeric section", 7],
    ["malformed family beside an empty valid family", { premium: null, other: {} }],
  ]) {
    test(`a ${shape} reports one issue without losing a valid item key`, async () => {
      const resolver = new ContentKeyResolver({
        cache: {
          put() {
            assert.fail("a malformed period section must not install a period key");
          },
          candidatesAt: () => [],
          attempted() {},
        },
      });
      const page = new DcaData(pageData());
      const good = new Uint8Array(16).fill(7);
      const association = associationFor(page, "issuer_example", {
        contentKeys: { bodytext: "sealed-content" },
        periodKeys: { premium: { "251023T1500": "sealed-period" } },
      });
      assert.deepEqual(
        await resolver.applyResponse(
          page,
          "issuer_example",
          { keys: { contentKeys: { bodytext: base64urlEncode(good) }, periodKeys } },
          association,
        ),
        {
          accepted: 1,
          errors: [],
          issues: [{ section: "periodKeys", code: "malformed_key" }],
        },
      );
      assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), good);
    });
  }

  test(
    "a malformed contentKey in direct representation is reported while its valid sibling is held",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      const resolver = new ContentKeyResolver();
      const page = new DcaData(pageData());
      const good = new Uint8Array(16).fill(7);

      const response = { keys: { contentKeys: { good: base64urlEncode(good), bad: "!!!!" } } };
      assert.deepEqual(await applyResponse(resolver, page, "issuer_example", response), {
        accepted: 1,
        errors: [],
        issues: [{ section: "contentKeys", code: "malformed_key" }],
      });

      assert.deepEqual(
        await resolver.contentKeyFor(page, "good"),
        good,
        "the readable key survives its bad neighbour",
      );
      assert.equal(
        await resolver.contentKeyFor(page, "bad"),
        null,
        "the unreadable key is skipped",
      );
    },
  );
});

describe("a noncanonical key value in direct representation is skipped, not fatal", () => {
  test(
    "a contentKey in the standard alphabet is reported while its valid sibling is held",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      const resolver = new ContentKeyResolver();
      const page = new DcaData(pageData());
      const good = new Uint8Array(16).fill(7);
      // 32 bytes of 0xfb is a width the resolver admits, so the only thing
      // wrong with the respelled key entry is how it is spelled.
      const respelled = standardAlphabet(base64urlEncode(new Uint8Array(16).fill(0xfb)));

      const response = { keys: { contentKeys: { good: base64urlEncode(good), bad: respelled } } };
      assert.deepEqual(await applyResponse(resolver, page, "issuer.example", response), {
        accepted: 1,
        errors: [],
        issues: [{ section: "contentKeys", code: "malformed_key" }],
      });

      assert.deepEqual(
        await resolver.contentKeyFor(page, "good"),
        good,
        "the canonical key survives its bad neighbour",
      );
      assert.equal(await resolver.contentKeyFor(page, "bad"), null, "the respelled key is skipped");
    },
  );
});

test(
  "period keys of another width in a direct response are not retained or used beside a valid sibling",
  { tags: ["dca-profile-period-keys/client/period-key-admission"] },
  async () => {
    const labels = ["251023T1400", "251023T1500", "251023T1600"];
    const good = new Uint8Array(16).fill(7);
    const short = new Uint8Array(15).fill(8);
    const wide = new Uint8Array(17).fill(9);
    const contentKey = new Uint8Array(16).fill(3);
    const nonce = new Uint8Array(12).fill(4);
    const raw = pageData();
    const names = ["good", "short", "wide"];
    const wrappingKeys = [good, new Uint8Array([...short, 0]), wide.slice(0, 16)];
    const wraps = [];
    for (let i = 0; i < names.length; i++) {
      const wrap = {
        t: labels[i],
        nonce: base64urlEncode(nonce),
        key: base64urlEncode(await encrypt(wrappingKeys[i], nonce, contentKey)),
      };
      wraps.push(wrap);
      raw.contentData[names[i]] = {
        ...raw.contentData.bodytext,
        keys: { premium: [wrap] },
      };
    }
    assert.deepEqual(await attemptContentKeyWrap(wraps[2], wide.slice(0, 16)), contentKey);
    const filed = [];
    const resolver = new ContentKeyResolver({
      cache: {
        put(...args) {
          filed.push(args);
        },
        candidatesAt(accessGroup, t) {
          return filed
            .filter(([group, label]) => group === accessGroup && label === t)
            .map(([, , key]) => key);
        },
        attempted() {},
      },
    });
    const page = new DcaData(raw, { publisherOrigin: "https://publisher.example" });
    const association = associationFor(page, "issuer_example", {
      contentKeys: {},
      periodKeys: { premium: Object.fromEntries(labels.map((t) => [t, "presented-envelope"])) },
    });
    const report = await resolver.applyResponse(
      page,
      "issuer_example",
      {
        keys: {
          periodKeys: {
            premium: Object.fromEntries(
              labels.map((t, i) => [t, base64urlEncode([good, short, wide][i])]),
            ),
          },
        },
      },
      association,
    );
    assert.deepEqual(report, {
      accepted: 1,
      errors: [],
      issues: [
        { section: "periodKeys", code: "malformed_key" },
        { section: "periodKeys", code: "malformed_key" },
      ],
    });
    assert.equal(filed.length, 1);
    assert.deepEqual(filed[0].slice(0, 3), ["premium", labels[0], good]);
    assert.deepEqual(await resolver.contentKeyFor(page, "good"), contentKey);
    assert.equal(await resolver.contentKeyFor(page, "short"), null);
    assert.equal(await resolver.contentKeyFor(page, "wide"), null);
  },
);

describe("a key value of another width in direct representation is skipped, not truncated", () => {
  test(
    "a 17-octet contentKey is never held, though its first 16 octets open the item",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      const resolver = new ContentKeyResolver();
      const page = new DcaData(pageData());
      const nonce = new Uint8Array(12).fill(4);
      /** @param {Uint8Array} key @param {string} contentName @param {string} text */
      const item = async (key, contentName, text) => {
        const aad = `r-1|${contentName}`;
        const ciphertext = await encrypt(
          key,
          new Uint8Array(12),
          utf8Encode(text),
          utf8Encode(aad),
        );
        return {
          contentName,
          aad,
          nonce: base64urlEncode(nonce),
          ciphertext: base64urlEncode(ciphertext),
        };
      };
      /** @param {Uint8Array} key @param {{ contentName: string, aad: string, nonce: string, ciphertext: string }} sealed */
      const opened = async (key, sealed) =>
        utf8Decode(
          await openContent(key, sealed.contentName, sealed.ciphertext, utf8Encode(sealed.aad)),
        );

      const goodKey = new Uint8Array(16).fill(7);
      const good = await item(goodKey, "good", "<p>Open sibling.</p>");
      const wideKey = new Uint8Array(17).fill(9);
      const wide = await item(wideKey.subarray(0, 16), "wide", "<p>Must stay locked.</p>");
      const wideContentKey = base64urlEncode(wideKey);

      // The key entry is canonical, so width is the only thing wrong with it, and a
      // client that kept its first 16 octets would release this item's text.
      assert.deepEqual(binaryStringBytes(wideContentKey), wideKey);
      assert.equal(await opened(wideKey.slice(0, 16), wide), "<p>Must stay locked.</p>");

      const report = await applyResponse(resolver, page, "issuer_example", {
        keys: { contentKeys: { good: base64urlEncode(goodKey), wide: wideContentKey } },
      });

      assert.equal(
        await resolver.contentKeyFor(page, "wide"),
        null,
        "no key is held for the overlong key entry, so no route opens its item",
      );
      const held = /** @type {Uint8Array} */ (await resolver.contentKeyFor(page, "good"));
      assert.equal(await opened(held, good), "<p>Open sibling.</p>", "the valid sibling opens");
      assert.deepEqual(report, {
        accepted: 1,
        errors: [],
        issues: [{ section: "contentKeys", code: "malformed_key" }],
      });
      assert.deepEqual(await resolver.resolve(page, ["good", "wide"]), {
        covered: ["good"],
        missing: ["wide"],
      });
    },
  );
});

describe("response application reports consumer decisions", () => {
  const key = (fill) => base64urlEncode(new Uint8Array(16).fill(fill));
  const deliveredPage = () =>
    new DcaData(pageData(), { publisherOrigin: "https://publisher.example" });

  test(
    "an unsupported chain section beside valid content leaves the content usable",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      const resolver = new ContentKeyResolver();
      const page = deliveredPage();

      assert.deepEqual(
        await applyResponse(resolver, page, "issuer_example", {
          keys: {
            contentKeys: { bodytext: key(1) },
            chainKeys: { premium: { "251023T1500": key(2) } },
          },
        }),
        {
          accepted: 1,
          errors: [],
          issues: [{ section: "chainKeys", code: "unsupported_section" }],
        },
      );
      assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), new Uint8Array(16).fill(1));
    },
  );

  test("a malformed period-key coordinate in the request snapshot is not presented", async () => {
    const filed = [];
    const resolver = new ContentKeyResolver({
      cache: {
        put: (...args) => {
          filed.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
    });

    assert.deepEqual(
      await applyResponse(resolver, deliveredPage(), "issuer_example", {
        keys: { periodKeys: { premium: { bad: key(9) } } },
      }),
      {
        accepted: 0,
        errors: [],
        issues: [{ section: "periodKeys", code: "unsolicited_coordinate" }],
      },
    );
    assert.deepEqual(filed, []);
  });

  test("invalid transport preflight returns before any section writes", async () => {
    let preflights = 0;
    let periodKeyPuts = 0;
    let chainPuts = 0;
    const resolver = new ContentKeyResolver({
      cache: {
        put() {
          periodKeyPuts++;
        },
        candidatesAt: () => [],
        attempted() {},
      },
      chainCache: {
        put() {
          chainPuts++;
        },
        candidates: () => [],
      },
      chainKeyProfile: {
        constructionProfile: CHAIN_IDENTITY,
        parametersForResponse: () => ({ maxSteps: 2 }),
        acceptsPeriodKeyResponseCoordinate: () => true,
        acceptsResponseCoordinate: () => true,
        candidateSourceFor: () => ({ async *attempts() {} }),
      },
      clientBoundKeyCapability: {
        assertCanOpenChainKeys() {},
        openDeliveredKeys() {
          preflights++;
          return null;
        },
      },
    });
    const page = deliveredPage();

    assert.deepEqual(
      await applyResponse(resolver, page, "issuer.example", {
        transport: { method: "ECDH-P256" },
        keys: {
          periodKeys: { premium: { "251023T1500": { key: "wrapped-period" } } },
          chainKeys: { premium: { "251023T1500": key(9) } },
          contentKeys: { bodytext: { key: "wrapped-content" } },
        },
      }),
      {
        accepted: 0,
        errors: [],
        issues: [{ section: "response", code: "invalid_transport" }],
      },
    );
    assert.equal(preflights, 0, "a direct chain sibling rejects representation before opening");
    assert.equal(periodKeyPuts, 0);
    assert.equal(chainPuts, 0);
    assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
  });

  test("client-bound period keys and content keys use one opener with least privilege", async () => {
    const periodHandle = await globalThis.crypto.subtle.importKey(
      "raw",
      new Uint8Array(16).fill(2),
      { name: "AES-GCM" },
      false,
      ["unwrapKey"],
    );
    const contentHandle = await globalThis.crypto.subtle.importKey(
      "raw",
      new Uint8Array(16).fill(3),
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );
    const opens = [];
    const filed = [];
    let preflights = 0;
    const resolver = new ContentKeyResolver({
      cache: {
        put(...args) {
          filed.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
      clientBoundKeyCapability: {
        openDeliveredKeys(transport) {
          preflights++;
          assert.deepEqual(transport, { method: "ECDH-P256" });
          return {
            open(value, usages) {
              opens.push([value.key, [...usages]]);
              return value.key === "period" ? periodHandle : contentHandle;
            },
          };
        },
      },
    });
    const page = deliveredPage();

    assert.deepEqual(
      await applyResponse(resolver, page, "issuer.example", {
        transport: { method: "ECDH-P256" },
        keys: {
          periodKeys: { premium: { "251023T1500": { key: "period" } } },
          contentKeys: { bodytext: { key: "content" } },
        },
      }),
      { accepted: 2, errors: [], issues: [] },
    );
    assert.equal(preflights, 1);
    assert.deepEqual(opens, [
      ["period", ["unwrapKey"]],
      ["content", ["decrypt"]],
    ]);
    assert.equal(filed.length, 1);
    assert.equal(filed[0][2], periodHandle);
    assert.equal(await resolver.contentKeyFor(page, "bodytext"), contentHandle);
  });

  test("a client-bound opener cannot file or hold a wider AES handle", async () => {
    const wider = await globalThis.crypto.subtle.importKey(
      "raw",
      new Uint8Array(32).fill(9),
      { name: "AES-GCM" },
      false,
      ["decrypt", "unwrapKey"],
    );
    const filed = [];
    const resolver = new ContentKeyResolver({
      cache: {
        put(...args) {
          filed.push(args);
        },
        candidatesAt: () => [],
        attempted() {},
      },
      clientBoundKeyCapability: {
        openDeliveredKeys: () => ({ open: () => wider }),
      },
    });
    const page = deliveredPage();

    assert.deepEqual(
      await applyResponse(resolver, page, "issuer.example", {
        transport: { method: "ECDH-P256" },
        keys: {
          periodKeys: { premium: { "251023T1500": { key: "wrapped-period" } } },
          contentKeys: { bodytext: { key: "wrapped-content" } },
        },
      }),
      {
        accepted: 0,
        errors: [],
        issues: [
          { section: "periodKeys", code: "malformed_key" },
          { section: "contentKeys", code: "malformed_key" },
        ],
      },
    );
    assert.deepEqual(filed, [], "the wider period handle never reaches the cache");
    assert.equal(
      await resolver.contentKeyFor(page, "bodytext"),
      null,
      "the wider content handle is never held",
    );
  });

  test("a client-bound opener cannot file a key handle as a chain key", async () => {
    const handle = await globalThis.crypto.subtle.importKey(
      "raw",
      new Uint8Array(16).fill(7),
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );
    const puts = [];
    const resolver = new ContentKeyResolver({
      chainCache: {
        put(...args) {
          puts.push(args);
        },
        candidates: () => [],
      },
      chainKeyProfile: {
        constructionProfile: CHAIN_IDENTITY,
        parametersForResponse: () => ({ maxSteps: 2 }),
        acceptsPeriodKeyResponseCoordinate: () => true,
        acceptsResponseCoordinate: () => true,
        candidateSourceFor: () => ({ async *attempts() {} }),
      },
      clientBoundKeyCapability: {
        assertCanOpenChainKeys() {},
        openDeliveredKeys: () => ({ open: () => handle }),
      },
    });

    assert.deepEqual(
      await applyResponse(resolver, deliveredPage(), "issuer.example", {
        transport: { method: "ECDH-P256" },
        keys: { chainKeys: { premium: { "251023T1500": { key: "chain" } } } },
      }),
      {
        accepted: 0,
        errors: [],
        issues: [{ section: "chainKeys", code: "malformed_key" }],
      },
    );
    assert.deepEqual(puts, [], "Step and Leaf need chain-key bytes, not a handle");
  });

  test("an admitted client-bound chain key opens to bytes and enters only the chain-key cache", async () => {
    let preflights = 0;
    let opens = 0;
    const puts = [];
    const resolver = new ContentKeyResolver({
      chainCache: {
        put(...args) {
          puts.push(args);
        },
        putPeriodKey() {
          throw new Error("a chain key must not enter the period-key cache");
        },
        candidates: () => [],
      },
      chainKeyProfile: {
        constructionProfile: CHAIN_IDENTITY,
        parametersForResponse: () => ({ maxSteps: 2 }),
        acceptsPeriodKeyResponseCoordinate: () => true,
        acceptsResponseCoordinate: () => true,
        candidateSourceFor: () => ({ async *attempts() {} }),
      },
      clientBoundKeyCapability: {
        assertCanOpenChainKeys() {},
        openDeliveredKeys() {
          preflights++;
          return {
            open() {
              opens++;
              return new Uint8Array(16).fill(7);
            },
          };
        },
      },
    });

    assert.deepEqual(
      await applyResponse(resolver, deliveredPage(), "issuer.example", {
        transport: { method: "ECDH-P256" },
        keys: { chainKeys: { premium: { "251023T1500": { key: "chain" } } } },
      }),
      {
        accepted: 1,
        errors: [],
        issues: [],
      },
    );
    assert.equal(preflights, 1);
    assert.equal(opens, 1);
    assert.equal(puts.length, 1);
    assert.equal(puts[0][0], "premium");
    assert.equal(puts[0][1], "251023T1500");
    assert.deepEqual(puts[0][2], new Uint8Array(16).fill(7));
    assert.equal(puts[0][3].issuerName, "issuer.example");
  });

  test("a tampered wrapped chain key does not suppress an admitted sibling", async () => {
    const filed = [];
    const resolver = new ContentKeyResolver({
      chainCache: {
        put(...args) {
          filed.push(args);
        },
        putPeriodKey() {
          throw new Error("a chain key must not enter the period-key cache");
        },
        candidates: () => [],
      },
      chainKeyProfile: {
        constructionProfile: CHAIN_IDENTITY,
        parametersForResponse: () => ({ maxSteps: 2 }),
        acceptsPeriodKeyResponseCoordinate: () => true,
        acceptsResponseCoordinate: () => true,
        candidateSourceFor: () => ({ async *attempts() {} }),
      },
      clientBoundKeyCapability: {
        assertCanOpenChainKeys() {},
        openDeliveredKeys: () => ({
          open(value, usages, keyKind) {
            assert.deepEqual(usages, []);
            assert.equal(keyKind, "chainKey");
            if (value.key === "tampered") throw dcaError("unwrap_failed", "tampered chain key");
            return new Uint8Array(16).fill(9);
          },
        }),
      },
    });

    const result = await applyResponse(resolver, deliveredPage(), "issuer.example", {
      transport: { method: "ECDH-P256" },
      keys: {
        chainKeys: {
          premium: { "251023T1500": { key: "tampered" } },
          archive: { "251023T1500": { key: "valid" } },
        },
      },
    });
    assert.deepEqual(result, {
      accepted: 1,
      errors: [],
      issues: [{ section: "chainKeys", code: "malformed_key" }],
    });
    assert.equal(filed.length, 1);
    assert.equal(filed[0][0], "archive");
    assert.equal(filed[0][3].issuerName, "issuer.example");
  });

  test("direct fallback acceptance does not grant raw period-key persistence", async () => {
    let puts = 0;
    const capability = {
      assertCanOpenChainKeys() {},
      openDeliveredKeys() {
        throw new Error("direct response opened a capability");
      },
    };
    const clientBoundOnly = new ContentKeyResolver({
      cache: {
        put() {
          puts++;
        },
        candidatesAt: () => [],
        attempted() {},
      },
      clientBoundKeyCapability: capability,
    });
    const acceptedContentOnly = new ContentKeyResolver({
      cache: {
        put() {
          puts++;
        },
        candidatesAt: () => [],
        attempted() {},
      },
      chainCache: {
        put() {
          puts++;
        },
        putPeriodKey() {
          puts++;
        },
        candidates: () => [],
      },
      chainKeyProfile: {
        constructionProfile: CHAIN_IDENTITY,
        parametersForResponse: () => ({ maxSteps: 2 }),
        acceptsPeriodKeyResponseCoordinate: () => true,
        acceptsResponseCoordinate: () => true,
        candidateSourceFor: () => ({ async *attempts() {} }),
      },
      clientBoundKeyCapability: capability,
      acceptDirectFallback: true,
    });
    const response = {
      keys: {
        contentKeys: { bodytext: key(4) },
        periodKeys: { premium: { "251023T1500": key(5) } },
        chainKeys: { premium: { "251023T1500": key(6) } },
      },
    };

    assert.deepEqual(
      await applyResponse(clientBoundOnly, deliveredPage(), "issuer_example", response),
      {
        accepted: 0,
        errors: [],
        issues: [
          { section: "chainKeys", code: "unsupported_section" },
          { section: "periodKeys", code: "unsupported_section" },
          { section: "contentKeys", code: "unsupported_section" },
        ],
      },
    );
    const contentPage = deliveredPage();
    assert.deepEqual(
      await applyResponse(acceptedContentOnly, contentPage, "issuer_example", response),
      {
        accepted: 1,
        errors: [],
        issues: [
          { section: "periodKeys", code: "unsupported_section" },
          { section: "chainKeys", code: "unsupported_section" },
        ],
      },
    );
    assert.deepEqual(
      await acceptedContentOnly.contentKeyFor(contentPage, "bodytext"),
      new Uint8Array(16).fill(4),
    );
    assert.equal(puts, 0, "neither composition gains raw-cache permission implicitly");
  });

  test("storage and opener faults keep their exact thrown identity", async () => {
    const storeFault = new Error("store fault");
    const storageResolver = new ContentKeyResolver({
      cache: {
        put() {
          throw storeFault;
        },
        candidatesAt: () => [],
        attempted() {},
      },
    });
    await assert.rejects(
      () =>
        applyResponse(storageResolver, deliveredPage(), "issuer_example", {
          keys: { periodKeys: { premium: { "251023T1500": key(6) } } },
        }),
      (error) => error === storeFault,
    );

    const openerFault = new Error("opener fault");
    const openingResolver = new ContentKeyResolver({
      clientBoundKeyCapability: {
        openDeliveredKeys: () => ({
          open() {
            throw openerFault;
          },
        }),
      },
    });
    await assert.rejects(
      () =>
        applyResponse(openingResolver, deliveredPage(), "issuer_example", {
          transport: { method: "ECDH-P256" },
          keys: { contentKeys: { bodytext: { key: "wrapped" } } },
        }),
      (error) => error === openerFault,
    );

    const transportConfigFault = dcaError("bad_config", "transport composition fault");
    const transportResolver = new ContentKeyResolver({
      clientBoundKeyCapability: {
        openDeliveredKeys() {
          throw transportConfigFault;
        },
      },
    });
    await assert.rejects(
      () =>
        applyResponse(transportResolver, deliveredPage(), "issuer_example", {
          transport: { method: "ECDH-P256" },
          keys: { contentKeys: { bodytext: { key: "wrapped" } } },
        }),
      (error) => error === transportConfigFault,
    );

    const openerConfigFault = dcaError("bad_config", "opener composition fault");
    const typedOpeningResolver = new ContentKeyResolver({
      clientBoundKeyCapability: {
        openDeliveredKeys: () => ({
          open() {
            throw openerConfigFault;
          },
        }),
      },
    });
    await assert.rejects(
      () =>
        applyResponse(typedOpeningResolver, deliveredPage(), "issuer_example", {
          transport: { method: "ECDH-P256" },
          keys: { contentKeys: { bodytext: { key: "wrapped" } } },
        }),
      (error) => error === openerConfigFault,
    );
  });
});

describe("response association admission", () => {
  const key = (fill) => base64urlEncode(new Uint8Array(16).fill(fill));
  const deliveredPage = () =>
    new DcaData(pageData(), { publisherOrigin: "https://publisher.example" });

  test(
    "an exact page and issuer association is mandatory before transport opening",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      let preflights = 0;
      const resolver = new ContentKeyResolver({
        clientBoundKeyCapability: {
          openDeliveredKeys() {
            preflights++;
            return { open: () => null };
          },
        },
      });
      const page = deliveredPage();
      const response = { keys: { contentKeys: { bodytext: { key: "wrapped" } } } };

      await assert.rejects(
        () => resolver.applyResponse(page, "issuer_example", response),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
      const malformedDelivery = pageData();
      malformedDelivery.resourceJWT = "not-a-jwt";
      const responseBeforePreflight = new Proxy(
        {},
        {
          getOwnPropertyDescriptor() {
            throw new Error("response was inspected");
          },
        },
      );
      await assert.rejects(
        () =>
          resolver.applyResponse(
            new DcaData(malformedDelivery, { publisherOrigin: "https://publisher.example" }),
            "issuer_example",
            responseBeforePreflight,
          ),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
      const association = associationFor(page, "issuer_example", {
        contentKeys: { bodytext: "sealed" },
      });
      const equalClone = new DcaData(structuredClone(page.toObject()), {
        publisherOrigin: "https://publisher.example",
      });
      await assert.rejects(
        () => resolver.applyResponse(equalClone, "issuer_example", response, association),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
      await assert.rejects(
        () => resolver.applyResponse(page, "other_issuer", response, association),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
      const wrongOrigin = new DcaData(page.toObject(), {
        publisherOrigin: "https://other-publisher.example",
      });
      await assert.rejects(
        () => resolver.applyResponse(wrongOrigin, "issuer_example", response, association),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
      const anotherView = new DcaData(page.toObject(), {
        publisherOrigin: "https://publisher.example",
      });
      assert.deepEqual(
        await resolver.applyResponse(
          anotherView,
          "issuer_example",
          { keys: { contentKeys: {} } },
          association,
        ),
        { accepted: 0, errors: [], issues: [] },
      );
      assert.equal(preflights, 0);
    },
  );

  test(
    "same-object mutation of any retained security coordinate invalidates the association",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      const mutations = [
        [
          "version",
          (delivery) => {
            delivery.version = "2";
          },
        ],
        [
          "resourceJWT",
          (delivery) => {
            delivery.resourceJWT = compactJwt({
              origin: "https://signed.example",
              resourceId: "123456",
              renderId: "AAAAAAAAAAAAAAAAAAAAAA",
              changed: true,
            });
          },
        ],
        [
          "renderId",
          (_delivery, page) => {
            Object.defineProperty(page, "renderId", { value: "r-2" });
          },
        ],
        [
          "keyId",
          (delivery) => {
            delivery.issuerData.issuer_example.keyId = "k2";
          },
        ],
        [
          "publisherOrigin",
          (_delivery, page) => {
            Object.defineProperty(page, "publisherOrigin", {
              value: "https://other-publisher.example",
            });
          },
        ],
      ];

      for (const [coordinate, mutate] of mutations) {
        const delivery = pageData();
        const page = new DcaData(delivery, { publisherOrigin: "https://publisher.example" });
        const association = associationFor(page, "issuer_example", { contentKeys: {} });
        mutate(delivery, page);
        await assert.rejects(
          () =>
            new ContentKeyResolver().applyResponse(
              page,
              "issuer_example",
              { keys: { contentKeys: {} } },
              association,
            ),
          (/** @type {any} */ error) => error.code === "bad_config",
          coordinate,
        );
      }
    },
  );

  test(
    "requested base siblings survive unsolicited names, families and key entries",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      const filed = [];
      const resolver = new ContentKeyResolver({
        cache: {
          put(...args) {
            filed.push(args);
          },
          candidatesAt: () => [],
          attempted() {},
        },
      });
      const page = deliveredPage();
      const association = associationFor(page, "issuer_example", {
        contentKeys: { bodytext: "sealed-content" },
        periodKeys: { premium: { "251023T1500": "sealed-period" } },
      });
      const application = await resolver.applyResponse(
        page,
        "issuer_example",
        {
          keys: {
            contentKeys: { bodytext: key(1), surprise: key(2) },
            periodKeys: {
              premium: { "251023T1500": key(3), "251023T1600": key(4) },
              other: { "251023T1500": key(5) },
            },
          },
        },
        association,
      );

      assert.deepEqual(application, {
        accepted: 2,
        errors: [],
        issues: [
          { section: "contentKeys", code: "unsolicited_coordinate" },
          { section: "periodKeys", code: "unsolicited_coordinate" },
          { section: "periodKeys", code: "unsolicited_coordinate" },
        ],
      });
      assert.deepEqual(application.errors, []);
      assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), new Uint8Array(16).fill(1));
      assert.equal(await resolver.contentKeyFor(page, "surprise"), null);
      assert.equal(filed.length, 1);
      assert.equal(filed[0][0], "premium");
      assert.equal(filed[0][1], "251023T1500");
    },
  );

  test("the opener never receives an unsolicited wrapped key entry", async () => {
    const opened = [];
    const handle = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(16).fill(7),
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const resolver = new ContentKeyResolver({
      clientBoundKeyCapability: {
        openDeliveredKeys: () => ({
          open(value) {
            opened.push(value.key);
            return handle;
          },
        }),
      },
    });
    const page = deliveredPage();
    const association = associationFor(
      page,
      "issuer_example",
      {
        contentKeys: { bodytext: "sealed-content" },
      },
      { clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" } },
    );

    const application = await resolver.applyResponse(
      page,
      "issuer_example",
      {
        transport: { method: "ECDH-P256" },
        keys: {
          contentKeys: {
            bodytext: { key: "requested" },
            surprise: { key: "unsolicited" },
          },
        },
      },
      association,
    );

    assert.deepEqual(opened, ["requested"]);
    assert.deepEqual(application, {
      accepted: 1,
      errors: [],
      issues: [{ section: "contentKeys", code: "unsolicited_coordinate" }],
    });
    assert.deepEqual(application.errors, []);
  });

  test("client-bound transport must match both its mode and the immutable request offer", async () => {
    let preflights = 0;
    const resolver = new ContentKeyResolver({
      clientBoundKeyCapability: {
        openDeliveredKeys() {
          preflights++;
          return { open: () => new Uint8Array(16).fill(7) };
        },
      },
    });
    const page = deliveredPage();
    const sealed = { contentKeys: { bodytext: "sealed-content" } };
    const response = (transport) => ({
      transport,
      keys: { contentKeys: { bodytext: { key: "wrapped" } } },
    });
    const mutableOffer = { kty: "RSA", n: "request-n", e: "AQAB" };
    const snapshottedMismatch = associationFor(page, "issuer_example", sealed, {
      clientPublicKey: mutableOffer,
    });
    mutableOffer.kty = "EC";
    mutableOffer.crv = "P-256";
    const cases = [
      ["absent offer", associationFor(page, "issuer_example", sealed), { method: "ECDH-P256" }],
      [
        "mismatched offer",
        associationFor(page, "issuer_example", sealed, {
          clientPublicKey: { kty: "RSA", n: "request-n", e: "AQAB" },
        }),
        { method: "ECDH-P256" },
      ],
      [
        "unknown method",
        associationFor(page, "issuer_example", sealed, {
          clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" },
        }),
        { method: "unsupported" },
      ],
      [
        "unsupported EC curve",
        associationFor(page, "issuer_example", sealed, {
          clientPublicKey: { kty: "EC", crv: "P-384", x: "request-x", y: "request-y" },
        }),
        { method: "ECDH-P256" },
      ],
      ["offer mutated after association", snapshottedMismatch, { method: "ECDH-P256" }],
    ];

    for (const [name, association, transport] of cases) {
      assert.deepEqual(
        await resolver.applyResponse(page, "issuer_example", response(transport), association),
        { accepted: 0, errors: [], issues: [{ code: "invalid_transport" }] },
        name,
      );
    }
    assert.equal(
      preflights,
      0,
      "an invalid response never reaches the client private-key capability",
    );
    assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
  });

  test("mixed direct and wrapped key entries reject the response before any key entry is retained", async () => {
    let opens = 0;
    let puts = 0;
    const resolver = new ContentKeyResolver({
      cache: {
        put() {
          puts++;
        },
        candidatesAt: () => [],
        attempted() {},
      },
      clientBoundKeyCapability: {
        openDeliveredKeys: () => ({
          open() {
            opens++;
            return new Uint8Array(16).fill(7);
          },
        }),
      },
    });
    const page = deliveredPage();
    const association = associationFor(
      page,
      "issuer_example",
      {
        contentKeys: { bodytext: "sealed-one", sibling: "sealed-two" },
        periodKeys: { premium: { "251023T1500": "sealed-period" } },
      },
      { clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" } },
    );

    assert.deepEqual(
      await resolver.applyResponse(
        page,
        "issuer_example",
        {
          transport: { method: "ECDH-P256" },
          keys: {
            contentKeys: { bodytext: { key: "wrapped" }, sibling: key(4) },
            periodKeys: { premium: { "251023T1500": { key: "wrapped-period" } } },
          },
        },
        association,
      ),
      { accepted: 0, errors: [], issues: [{ section: "response", code: "invalid_transport" }] },
    );
    assert.equal(opens, 0);
    assert.equal(puts, 0);
    assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
    assert.equal(await resolver.contentKeyFor(page, "sibling"), null);
  });

  test("one malformed wrapped key entry stays local and does not suppress a valid sibling", async () => {
    const handle = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(16).fill(8),
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const resolver = new ContentKeyResolver({
      clientBoundKeyCapability: {
        openDeliveredKeys: () => ({
          open(value) {
            return value.key === "good" ? handle : null;
          },
        }),
      },
    });
    const page = deliveredPage();
    const association = associationFor(
      page,
      "issuer_example",
      {
        contentKeys: { bodytext: "sealed-one", sibling: "sealed-two" },
      },
      { clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" } },
    );

    assert.deepEqual(
      await resolver.applyResponse(
        page,
        "issuer_example",
        {
          transport: { method: "ECDH-P256" },
          keys: {
            contentKeys: {
              bodytext: { key: "bad" },
              sibling: { key: "good" },
            },
          },
        },
        association,
      ),
      {
        accepted: 1,
        errors: [],
        issues: [{ section: "contentKeys", code: "malformed_key" }],
      },
    );
    assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
    assert.deepEqual(await resolver.contentKeyFor(page, "sibling"), handle);
  });

  test(
    "own request members outside protocol coordinate grammar are never presented",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      let puts = 0;
      let extensionAdmissions = 0;
      const resolver = new ContentKeyResolver({
        cache: {
          put() {
            puts++;
          },
          candidatesAt: () => [],
          attempted() {},
        },
        chainKeyProfile: {
          acceptsPeriodKeyResponseCoordinate() {
            extensionAdmissions++;
            return true;
          },
        },
      });
      const page = deliveredPage();
      const association = associationFor(page, "issuer_example", {
        contentKeys: { "bad name": "sealed" },
        periodKeys: {
          "bad group": { "251023T1500": "sealed" },
          premium: { bad: "sealed" },
        },
      });

      assert.deepEqual(
        await resolver.applyResponse(
          page,
          "issuer_example",
          {
            keys: {
              contentKeys: { "bad name": key(1) },
              periodKeys: {
                "bad group": { "251023T1500": key(2) },
                premium: { bad: key(3) },
              },
            },
            errors: {
              "bad name": { error: "unseal_failed" },
              "bad group|251023T1500": { error: "unseal_failed" },
              "premium|bad": { error: "unseal_failed" },
            },
          },
          association,
        ),
        {
          accepted: 0,
          errors: [],
          issues: [
            { section: "contentKeys", code: "unsolicited_coordinate" },
            { section: "periodKeys", code: "unsolicited_coordinate" },
            { section: "periodKeys", code: "unsolicited_coordinate" },
            { section: "errors", code: "malformed_error" },
            { section: "errors", code: "malformed_error" },
            { section: "errors", code: "malformed_error" },
          ],
        },
      );
      assert.equal(puts, 0);
      assert.equal(
        extensionAdmissions,
        0,
        "base grammar admission precedes any extension projection",
      );
      assert.equal(await resolver.contentKeyFor(page, "bad name"), null);
    },
  );

  test("only well-formed requested errors without a sibling key are surfaced", async () => {
    const resolver = new ContentKeyResolver();
    const page = deliveredPage();
    const association = associationFor(page, "issuer_example", {
      contentKeys: {
        bodytext: "sealed-key",
        denied: "sealed-denied",
        malformed: "sealed-malformed",
      },
      periodKeys: { premium: { "251023T1500": "sealed-period" } },
    });
    const application = await resolver.applyResponse(
      page,
      "issuer_example",
      {
        keys: { contentKeys: { bodytext: key(1) } },
        errors: {
          denied: { error: "withheld", message: "subscription required", ignored: true },
          malformed: { error: "", message: 7 },
          bodytext: { error: "unseal_failed" },
          "premium|251023T1500": { error: "unseal_failed" },
          surprise: { error: "withheld" },
        },
      },
      association,
    );

    assert.deepEqual(application, {
      accepted: 1,
      errors: [
        { coordinate: "denied", error: "withheld", message: "subscription required" },
        { coordinate: "premium|251023T1500", error: "unseal_failed" },
      ],
      issues: [
        { section: "errors", code: "malformed_error" },
        { section: "errors", code: "malformed_error" },
        { section: "errors", code: "unsolicited_coordinate" },
      ],
    });
    assert.deepEqual(application.errors, [
      { coordinate: "denied", error: "withheld", message: "subscription required" },
      { coordinate: "premium|251023T1500", error: "unseal_failed" },
    ]);
    assert.ok(Object.isFrozen(application.errors));
    assert.ok(Object.isFrozen(application.errors[0]));
    assert.deepEqual({ ...application }, application);
    assert.deepEqual(JSON.parse(JSON.stringify(application)).errors, application.errors);
    assert.deepEqual(Object.keys(application), ["accepted", "errors", "issues"]);
  });

  test("malformed content, family and period-key-label coordinates never become usable errors", async () => {
    const resolver = new ContentKeyResolver();
    const page = deliveredPage();
    const association = associationFor(page, "issuer_example", {
      contentKeys: { denied: "sealed", "bad name": "sealed" },
      periodKeys: {
        "bad group": { "251023T1500": "sealed" },
        premium: { bad: "sealed" },
      },
    });
    const application = await resolver.applyResponse(
      page,
      "issuer_example",
      {
        keys: { contentKeys: {} },
        errors: {
          denied: { error: "withheld" },
          "bad name": { error: "withheld" },
          "bad group|251023T1500": { error: "withheld" },
          "premium|bad": { error: "withheld" },
          "premium|251023T1500|extra": { error: "withheld" },
          validMissing: { error: "withheld" },
        },
      },
      association,
    );

    assert.deepEqual(application, {
      accepted: 0,
      errors: [{ coordinate: "denied", error: "withheld" }],
      issues: [
        { section: "errors", code: "malformed_error" },
        { section: "errors", code: "malformed_error" },
        { section: "errors", code: "malformed_error" },
        { section: "errors", code: "malformed_error" },
        { section: "errors", code: "unsolicited_coordinate" },
      ],
    });
  });

  test(
    "inherited and later-added request members never widen the snapshot",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      const inherited = Object.create({ inherited: "sealed-inherited" });
      inherited.bodytext = "sealed-body";
      const sealed = { contentKeys: inherited };
      const page = deliveredPage();
      const association = associationFor(page, "issuer_example", sealed);
      inherited.addedLater = "sealed-later";
      assert.ok(Object.isFrozen(association.request));

      const responseContent = Object.create({ inheritedResponse: key(5) });
      responseContent.bodytext = key(1);
      responseContent.inherited = key(2);
      responseContent.addedLater = key(3);
      const resolver = new ContentKeyResolver();
      const application = await resolver.applyResponse(
        page,
        "issuer_example",
        {
          keys: { contentKeys: responseContent },
          errors: Object.create({ bodytext: { error: "withheld" } }),
        },
        association,
      );

      assert.deepEqual(application, {
        accepted: 1,
        errors: [],
        issues: [
          { section: "contentKeys", code: "unsolicited_coordinate" },
          { section: "contentKeys", code: "unsolicited_coordinate" },
          { code: "malformed_error" },
        ],
      });
      assert.deepEqual(application.errors, []);
      assert.equal(await resolver.contentKeyFor(page, "inheritedResponse"), null);
      assert.equal(await resolver.contentKeyFor(page, "inherited"), null);
      assert.equal(await resolver.contentKeyFor(page, "addedLater"), null);
    },
  );

  test("request snapshotting never dispatches through an array instance map", () => {
    const page = deliveredPage();
    const hostile = [1, { nested: true }];
    Object.defineProperty(hostile, "map", {
      value: () => {
        throw new Error("array map was dispatched");
      },
      enumerable: false,
    });
    const association = new ResponseAssociation(page, "issuer_example", {
      version: page.version,
      issuerName: "issuer_example",
      resourceJWT: page.resourceJWT,
      keyId: page.keyIdFor("issuer_example"),
      sealed: { contentKeys: {} },
      probe: hostile,
    });

    assert.deepEqual(association.request.probe, [1, { nested: true }]);
    assert.ok(Object.isFrozen(association.request.probe));
    assert.ok(Object.isFrozen(association.request.probe[1]));
  });

  test("an empty error map is malformed and cannot drive control flow", async () => {
    const resolver = new ContentKeyResolver();
    const page = deliveredPage();
    const association = associationFor(page, "issuer_example", { contentKeys: {} });
    assert.deepEqual(
      await resolver.applyResponse(
        page,
        "issuer_example",
        { keys: { contentKeys: {} }, errors: {} },
        association,
      ),
      {
        accepted: 0,
        errors: [],
        issues: [{ code: "malformed_error" }],
      },
    );
  });
});

describe("the harness implicit response association slot", () => {
  test("one delivery and issuer cannot overwrite or reuse an outstanding implicit association", async () => {
    const client = new Client({ publisherOrigin: "https://publisher.example" });
    const data = pageData();
    client.buildRequest(data, "issuer_example", ["bodytext"]);
    assert.throws(
      () => client.buildRequest(data, "issuer_example", ["bodytext"]),
      (/** @type {any} */ error) =>
        error.code === "bad_config" && /outstanding/.test(error.message),
    );

    assert.deepEqual(
      await client.applyResponse(data, "issuer_example", { keys: { contentKeys: {} } }),
      {
        accepted: 0,
        errors: [],
        issues: [],
      },
    );
    await assert.rejects(
      () => client.applyResponse(data, "issuer_example", { keys: { contentKeys: {} } }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    assert.doesNotThrow(() => client.buildRequest(data, "issuer_example", ["bodytext"]));
  });

  test("an explicitly supplied association remains available without an implicit slot", async () => {
    const client = new Client({ publisherOrigin: "https://publisher.example" });
    const data = pageData();
    const page = new DcaData(data, { publisherOrigin: "https://publisher.example" });
    const association = associationFor(page, "issuer_example", {
      contentKeys: { bodytext: "sealed" },
    });

    assert.deepEqual(
      await client.applyResponse(
        data,
        "issuer_example",
        { keys: { contentKeys: {} } },
        association,
      ),
      { accepted: 0, errors: [], issues: [] },
    );
  });
});

describe("the publisher cache coordinate", () => {
  test("a period key is not filed when the delivery carries no publisher origin", async () => {
    let puts = 0;
    const resolver = new ContentKeyResolver({
      cache: {
        put: async () => {
          puts += 1;
        },
        candidatesAt: async () => [],
        attempted() {},
      },
    });
    const page = new DcaData(pageData());
    const key = base64urlEncode(new Uint8Array(16).fill(7));

    await assert.rejects(
      () =>
        applyResponse(resolver, page, "issuer_example", {
          keys: { periodKeys: { premium: { "251023T1400": key } } },
        }),
      (/** @type {any} */ e) => e.code === "bad_page",
    );
    assert.equal(puts, 0, "the refusal precedes the cache store");
  });
});

describe("key-resolution origins", () => {
  test(
    "a directly delivered content-key grant is held for its render and its origin carries no key material",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      const resolver = new ContentKeyResolver();
      const page = new DcaData(pageData());
      const key = new Uint8Array(16).fill(9);

      await applyResponse(resolver, page, "issuer_example", {
        keys: { contentKeys: { bodytext: base64urlEncode(key) } },
      });

      const resolved = await resolver.contentKeyWithOriginFor(page, "bodytext");
      assert.deepEqual(
        resolved.key,
        key,
        "the detailed call returns the same internal key as contentKeyFor",
      );
      assert.deepEqual(resolved.origin, { kind: "held-content-key" });
      assert.deepEqual(
        await resolver.contentKeyFor(page, "bodytext"),
        key,
        "the established API delegates unchanged",
      );

      const detailed = await resolver.resolveDetailed(page, ["bodytext"]);
      assert.deepEqual(detailed, {
        covered: ["bodytext"],
        missing: [],
        origins: [{ contentName: "bodytext", origin: { kind: "held-content-key" } }],
      });
      assert.equal(
        Object.hasOwn(detailed.origins[0].origin, "key"),
        false,
        "the observation contains no key material",
      );
      assert.deepEqual(
        await resolver.resolve(page, ["bodytext"]),
        { covered: ["bodytext"], missing: [] },
        "the established resolve shape remains exact",
      );
    },
  );

  test(
    "held content keys stay isolated when publishers reuse renderId and contentName",
    { tags: ["dca-profile-baseline/client/direct-admission"] },
    async () => {
      const resolver = new ContentKeyResolver();
      const pageA = new DcaData(pageData(), { publisherOrigin: "https://publisher-a.example" });
      const pageB = new DcaData(pageData(), { publisherOrigin: "https://publisher-b.example" });
      const key = (fill) => base64urlEncode(new Uint8Array(16).fill(fill));

      await applyResponse(resolver, pageA, "issuer_example", {
        keys: { contentKeys: { bodytext: key(1) } },
      });
      assert.deepEqual(await resolver.contentKeyFor(pageA, "bodytext"), new Uint8Array(16).fill(1));
      assert.equal(
        await resolver.contentKeyFor(pageB, "bodytext"),
        null,
        "a colliding renderId does not cross the publisher boundary",
      );
    },
  );

  test("held period-key-resolved content keys stay isolated by publisher", async () => {
    const periodKey = new Uint8Array(16).fill(2);
    const contentKey = new Uint8Array(16).fill(3);
    const nonce = new Uint8Array(12).fill(4);
    const rawA = pageData();
    rawA.contentData.bodytext.keys = {
      premium: [
        {
          t: "251023T1500",
          nonce: base64urlEncode(nonce),
          key: base64urlEncode(await encrypt(periodKey, nonce, contentKey)),
        },
      ],
    };
    const pageA = new DcaData(rawA, { publisherOrigin: "https://publisher-a.example" });
    const pageB = new DcaData(pageData(), { publisherOrigin: "https://publisher-b.example" });
    const resolver = new ContentKeyResolver({
      cache: {
        candidatesAt: async (_group, _t, { publisher }) =>
          publisher === pageA.publisherOrigin ? [periodKey] : [],
        put: async () => undefined,
        attempted: async () => undefined,
      },
    });

    assert.deepEqual((await resolver.resolve(pageA, ["bodytext"])).covered, ["bodytext"]);
    assert.deepEqual(await resolver.contentKeyFor(pageA, "bodytext"), contentKey);
    assert.equal(
      await resolver.contentKeyFor(pageB, "bodytext"),
      null,
      "a period-key-resolved key does not cross the publisher boundary",
    );
  });

  test("the successful cached sealed entry reports its accessGroup and period", async () => {
    const periodKey = new Uint8Array(16).fill(3);
    const contentKey = new Uint8Array(16).fill(7);
    const nonce = new Uint8Array(12).fill(4);
    const wrapped = await encrypt(periodKey, nonce, contentKey);
    const raw = pageData();
    raw.contentData.bodytext.keys = {
      premium: [
        {
          t: "251023T1500",
          nonce: base64urlEncode(nonce),
          key: base64urlEncode(wrapped),
        },
      ],
    };
    const resolver = new ContentKeyResolver({
      cache: {
        put: async () => undefined,
        candidatesAt: async () => [periodKey],
        attempted() {},
      },
    });

    const resolved = await resolver.contentKeyWithOriginFor(new DcaData(raw), "bodytext");
    assert.deepEqual(resolved.key, contentKey);
    assert.deepEqual(resolved.origin, {
      kind: "cached-period-key",
      accessGroup: "premium",
      t: "251023T1500",
    });
    assert.equal(
      Object.hasOwn(resolved.origin, "key"),
      false,
      "origin metadata never carries the opened key",
    );
  });

  test("a miss is explicit without changing the existing resolve result", async () => {
    const resolver = new ContentKeyResolver();
    const page = new DcaData(pageData());

    assert.deepEqual(await resolver.resolveDetailed(page, ["bodytext"]), {
      covered: [],
      missing: ["bodytext"],
      origins: [{ contentName: "bodytext", origin: { kind: "missing" } }],
    });
  });
});

describe("the DcaData currency", () => {
  test("contentNames answers the items the page declares records for", () => {
    assert.deepEqual(new DcaData(pageData()).contentNames(), ["bodytext"]);
  });

  test("contentNames refuses a page whose inventory is missing or not an object", () => {
    // The inventory is required, so there is no page with no items on it:
    // a reader raises bad_page where it would otherwise have answered with
    // an empty list.
    for (const bad of [undefined, null, "scalar", 42]) {
      assert.throws(
        () => new DcaData({ contentData: bad }).contentNames(),
        (/** @type {any} */ e) => e.code === "bad_page",
      );
    }
    assert.throws(
      () => new DcaData(undefined).contentNames(),
      (/** @type {any} */ e) => e.code === "bad_page",
    );
  });

  test("publisherOrigin reads delivery context, never the resourceJWT payload", () => {
    // The page's own resourceJWT names another origin, and it is decodable,
    // so a client that read the cache namespace off the token would report
    // it here. Nothing about that token is verified in the browser; the
    // cache is partitioned by the origin the delivery boundary observed.
    assert.equal(decodeCompactJwt(pageData().resourceJWT).payload.origin, "https://signed.example");
    assert.equal(
      new DcaData(pageData(), { publisherOrigin: "https://news.example" }).publisherOrigin,
      "https://news.example",
    );
    assert.equal(new DcaData(pageData()).publisherOrigin, undefined);
  });

  test("the view is live: one instance sees a mid-load mutation, not a cached read", () => {
    const raw = pageData();
    const page = new DcaData(raw);
    assert.deepEqual(page.contentNames(), ["bodytext"]);

    raw.contentData.premium = { contentType: "text/html", nonce: "n2" };
    // Same instance, re-read at call time: the accessor does not memoize.
    assert.deepEqual(page.contentNames(), ["bodytext", "premium"]);
  });
});

// Period keys Section 5.6 and response-binding Section 3: every client admits a
// `notDelivered` family report, validates the whole member and its request
// association before it admits a report or reusable family key, and hands valid entries to the
// application as their own typed collection.
describe("not-delivered family reports", () => {
  const key = (fill) => base64urlEncode(new Uint8Array(16).fill(fill));
  const deliveredPage = () =>
    new DcaData(pageData(), { publisherOrigin: "https://publisher.example" });
  const MALFORMED = Object.freeze({
    accepted: 0,
    errors: [],
    issues: [{ section: "notDelivered", code: "malformed_response" }],
  });
  /** A request presenting a content name, a period-key family and a chain family. */
  const presentingFamilies = (page) =>
    associationFor(page, "issuer_example", {
      contentKeys: { bodytext: "sealed-body", summary: "sealed-summary" },
      periodKeys: { premium: { "251023T1500": "sealed-period" } },
      chainKeys: { archive: { "251023T1500": "sealed-chain" } },
    });

  test("an admitted report reaches the application as typed family outcomes", async () => {
    const resolver = new ContentKeyResolver();
    const page = deliveredPage();
    const application = await resolver.applyResponse(
      page,
      "issuer_example",
      {
        keys: { contentKeys: { bodytext: key(1) } },
        notDelivered: {
          premium: { reason: "denied", message: "subscription required", ignored: true },
          archive: { reason: "unavailable" },
        },
      },
      presentingFamilies(page),
    );

    assert.deepEqual(application, {
      accepted: 1,
      errors: [],
      issues: [],
      notDelivered: [
        { accessGroup: "premium", reason: "denied", message: "subscription required" },
        { accessGroup: "archive", reason: "unavailable" },
      ],
    });
    assert.ok(Object.isFrozen(application.notDelivered));
    assert.ok(Object.isFrozen(application.notDelivered[0]));
    assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), new Uint8Array(16).fill(1));
  });

  test("a content key and a content-name error coexist with the report", async () => {
    const resolver = new ContentKeyResolver();
    const page = deliveredPage();
    const application = await resolver.applyResponse(
      page,
      "issuer_example",
      {
        keys: { contentKeys: { bodytext: key(1) } },
        errors: { summary: { error: "unseal_failed" } },
        notDelivered: { premium: { reason: "denied" } },
      },
      presentingFamilies(page),
    );
    assert.deepEqual(application, {
      accepted: 1,
      errors: [{ coordinate: "summary", error: "unseal_failed" }],
      issues: [],
      notDelivered: [{ accessGroup: "premium", reason: "denied" }],
    });
  });

  for (const [name, members] of [
    ["an empty member", { notDelivered: {} }],
    ["an array member", { notDelivered: [] }],
    ["a string member", { notDelivered: "premium" }],
    ["a null member", { notDelivered: null }],
    ["an array entry", { notDelivered: { premium: [] } }],
    ["a string entry", { notDelivered: { premium: "denied" } }],
    ["a null entry", { notDelivered: { premium: null } }],
    ["a missing reason", { notDelivered: { premium: { message: "no" } } }],
    ["an unknown reason", { notDelivered: { premium: { reason: "withheld" } } }],
    ["a non-string reason", { notDelivered: { premium: { reason: 7 } } }],
    ["a non-string message", { notDelivered: { premium: { reason: "denied", message: 7 } } }],
    ["an unsolicited family", { notDelivered: { standard: { reason: "denied" } } }],
    [
      "a period key for the named family",
      {
        keys: {
          contentKeys: { bodytext: key(1) },
          periodKeys: { premium: { "251023T1500": key(2) } },
        },
        notDelivered: { premium: { reason: "unavailable" } },
      },
    ],
    [
      "a chain key for the named family",
      {
        keys: {
          contentKeys: { bodytext: key(1) },
          chainKeys: { archive: { "251023T1500": key(2) } },
        },
        notDelivered: { archive: { reason: "unavailable" } },
      },
    ],
    [
      "a period-coordinate error in the named family",
      {
        errors: { "premium|251023T1500": { error: "unseal_failed" } },
        notDelivered: { premium: { reason: "denied" } },
      },
    ],
  ]) {
    test(`${name} refuses the report and family keys but retains an independent item key`, async () => {
      const resolver = new ContentKeyResolver({
        cache: {
          async put() {
            throw new Error("a malformed response files no period key");
          },
          async candidatesAt() {
            return [];
          },
          async attempted() {},
        },
      });
      const page = deliveredPage();
      const application = await resolver.applyResponse(
        page,
        "issuer_example",
        { keys: { contentKeys: { bodytext: key(1) } }, ...members },
        presentingFamilies(page),
      );
      assert.deepEqual(application, {
        ...MALFORMED,
        accepted: 1,
        errors: Object.hasOwn(members, "errors")
          ? [{ coordinate: "premium|251023T1500", error: "unseal_failed" }]
          : [],
      });
      assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), new Uint8Array(16).fill(1));
    });
  }

  for (const [name, notDelivered] of [
    ["an empty member", {}],
    ["an unsolicited family entry", { premium: { reason: "denied" } }],
  ]) {
    test(
      `a request presenting only a content name, answered with its content key and ${name}, retains the item key`,
      { tags: ["dca-profile-baseline/client/direct-admission"] },
      async () => {
        // Validation of the member does not depend on the request having
        // presented a period family: this request presented none.
        const resolver = new ContentKeyResolver();
        const page = deliveredPage();
        const application = await resolver.applyResponse(
          page,
          "issuer_example",
          { keys: { contentKeys: { bodytext: key(1) } }, notDelivered },
          associationFor(page, "issuer_example", { contentKeys: { bodytext: "sealed-body" } }),
        );
        assert.deepEqual(application, { ...MALFORMED, accepted: 1 });
        assert.deepEqual(
          await resolver.contentKeyFor(page, "bodytext"),
          new Uint8Array(16).fill(1),
        );
      },
    );
  }

  test("a key rejection local to one key entry keeps an otherwise admitted report", async () => {
    const resolver = new ContentKeyResolver();
    const page = deliveredPage();
    const application = await resolver.applyResponse(
      page,
      "issuer_example",
      {
        keys: { contentKeys: { bodytext: "!!!!", surprise: key(3) } },
        notDelivered: { premium: { reason: "denied" } },
      },
      presentingFamilies(page),
    );
    assert.deepEqual(application, {
      accepted: 0,
      errors: [],
      issues: [
        { section: "contentKeys", code: "unsolicited_coordinate" },
        { section: "contentKeys", code: "malformed_key" },
      ],
      notDelivered: [{ accessGroup: "premium", reason: "denied" }],
    });
  });

  test("a response without the member keeps its established report shape", async () => {
    const resolver = new ContentKeyResolver();
    const page = deliveredPage();
    const application = await resolver.applyResponse(
      page,
      "issuer_example",
      { keys: { contentKeys: { bodytext: key(1) } } },
      presentingFamilies(page),
    );
    assert.deepEqual(application, { accepted: 1, errors: [], issues: [] });
    assert.deepEqual(Object.keys(application), ["accepted", "errors", "issues"]);
  });
});

test("malformed period labels skip before cache reads; valid-label storage faults remain visible", async () => {
  const raw = pageData();
  const nonce = new Uint8Array(12).fill(3);
  const period = new Uint8Array(16).fill(11);
  const item = new Uint8Array(16).fill(12);
  const valid = {
    t: "251023T1500",
    nonce: base64urlEncode(nonce),
    key: base64urlEncode(await encrypt(period, nonce, item)),
  };
  raw.contentData.bodytext.keys = {
    premium: [{ ...valid, t: "" }, { ...valid, t: "bogus" }, valid],
  };
  raw.contentData.sibling = { ...raw.contentData.bodytext };
  const page = new DcaData(raw, { publisherOrigin: "https://publisher.example" });
  const reads = [];
  const cache = {
    put() {},
    attempted() {},
    candidatesAt(_group, t) {
      reads.push(t);
      return [period];
    },
  };
  const result = await new ContentKeyResolver({ cache }).resolveDetailed(page, [
    "bodytext",
    "sibling",
  ]);
  assert.deepEqual(result.covered, ["bodytext", "sibling"]);
  assert.deepEqual(reads, [valid.t, valid.t]);
  cache.candidatesAt = (_group, t) => {
    reads.push(t);
    throw dcaError("bad_storage", "corrupt");
  };
  await assert.rejects(new ContentKeyResolver({ cache }).resolveDetailed(page, ["bodytext"]), {
    code: "bad_storage",
  });
  cache.candidatesAt = (_group, t) => {
    reads.push(t);
    return [];
  };
  raw.contentData.bodytext.keys.premium.reverse();
  assert.deepEqual(
    (await new ContentKeyResolver({ cache }).resolveDetailed(page, ["bodytext"])).missing,
    ["bodytext"],
  );
  assert.equal(
    reads.every((t) => t === valid.t),
    true,
  );
});

test("authenticated resolution continues after a valid wrap yields the wrong item key", async () => {
  const raw = pageData();
  const period = new Uint8Array(16).fill(17),
    wrong = new Uint8Array(16).fill(18),
    right = new Uint8Array(16).fill(19);
  const nonce = new Uint8Array(12).fill(9);
  raw.contentData.bodytext.keys = {
    premium: await Promise.all(
      [wrong, right].map(async (key) => ({
        t: "251023T1500",
        nonce: base64urlEncode(nonce),
        key: base64urlEncode(await encrypt(period, nonce, key)),
      })),
    ),
  };
  const page = new DcaData(raw, { publisherOrigin: "https://publisher.example" });
  const resolver = new ContentKeyResolver({
    cache: { put() {}, attempted() {}, candidatesAt: () => [period] },
  });
  const ciphertext = base64urlEncode(
    await encrypt(right, new Uint8Array(12), utf8Encode("article"), utf8Encode("aad")),
  );
  let tried = 0;
  const result = await resolver.resolveAuthenticated(page, ["bodytext"], async (_name, key) => {
    tried++;
    try {
      await openContent(key, "bodytext", ciphertext, utf8Encode("aad"));
      return true;
    } catch (cause) {
      if (cause.code === "decrypt_failed") return false;
      throw cause;
    }
  });
  assert.deepEqual(result.covered, ["bodytext"]);
  assert.equal(tried, 2);
  assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), right);
});

test("storage-backed opaque response capability authenticates first use and closes on exceptions", async () => {
  for (const fail of [false, true]) {
    const raw = pageData(),
      period = new Uint8Array(16).fill(29),
      item = new Uint8Array(16).fill(30),
      nonce = new Uint8Array(12).fill(8);
    raw.contentData.bodytext.keys = {
      premium: [
        {
          t: "251023T1500",
          nonce: base64urlEncode(nonce),
          key: base64urlEncode(await encrypt(period, nonce, item)),
        },
      ],
    };
    const page = new DcaData(raw, { publisherOrigin: "https://publisher.example" });
    const handle = await crypto.subtle.importKey("raw", period, "AES-GCM", false, ["unwrapKey"]);
    const cache = new PeriodKeyCache({ storage: new Storage() });
    const resolver = new ContentKeyResolver({
      cache,
      clientBoundKeyCapability: { openDeliveredKeys: () => ({ open: async () => handle }) },
    });
    const association = associationFor(
      page,
      "issuer_example",
      { periodKeys: { premium: { "251023T1500": "AA" } } },
      { clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" } },
    );
    const application = await resolver.applyResponse(
      page,
      "issuer_example",
      {
        transport: { method: "ECDH-P256" },
        keys: { periodKeys: { premium: { "251023T1500": { key: "wrapped" } } } },
      },
      association,
    );
    assert.equal(application.accepted, 1);
    const ciphertext = base64urlEncode(
      await encrypt(item, new Uint8Array(12), utf8Encode("article"), utf8Encode("aad")),
    );
    const fault = new Error("predicate fault");
    const operation = resolver.resolveAuthenticated(
      page,
      ["bodytext"],
      async (_name, key) => {
        assert.ok(key instanceof CryptoKey);
        assert.equal(key.extractable, false);
        if (fail) throw fault;
        assert.equal(
          utf8Decode(await openContent(key, "bodytext", ciphertext, utf8Encode("aad"))),
          "article",
        );
        return true;
      },
      application,
    );
    if (fail) await assert.rejects(operation, (error) => error === fault);
    else assert.deepEqual((await operation).covered, ["bodytext"]);
    assert.equal(await new ContentKeyResolver({ cache }).contentKeyFor(page, "bodytext"), null);
    if (fail)
      assert.deepEqual(
        (await resolver.resolveAuthenticated(page, ["bodytext"], async () => true, application))
          .missing,
        ["bodytext"],
        "exception closes obtaining lease",
      );
  }
});

test("wrapped opener refuses extractable handles and raw item bytes without suppressing valid sibling", async () => {
  const opaque = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(16).fill(3),
    "AES-GCM",
    false,
    ["decrypt"],
  );
  const extractable = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(16).fill(4),
    "AES-GCM",
    true,
    ["decrypt"],
  );
  const page = new DcaData(pageData(), { publisherOrigin: "https://publisher.example" });
  const resolver = new ContentKeyResolver({
    clientBoundKeyCapability: {
      openDeliveredKeys: () => ({
        open: async (value) =>
          ({ bad: extractable, raw: new Uint8Array(16), good: opaque })[value.key],
      }),
    },
  });
  const association = associationFor(
    page,
    "issuer_example",
    { contentKeys: { bodytext: "AA", raw: "AA", sibling: "AA" } },
    { clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" } },
  );
  const result = await resolver.applyResponse(
    page,
    "issuer_example",
    {
      transport: { method: "ECDH-P256" },
      keys: {
        contentKeys: { bodytext: { key: "bad" }, raw: { key: "raw" }, sibling: { key: "good" } },
      },
    },
    association,
  );
  assert.equal(result.accepted, 1);
  assert.equal(result.issues.filter((issue) => issue.code === "malformed_key").length, 2);
  assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
  assert.equal(await resolver.contentKeyFor(page, "sibling"), opaque);
});

test("base-presented period coordinate survives extension false; unsolicited coordinate does not", async () => {
  const filed = [];
  const resolver = new ContentKeyResolver({
    cache: {
      put(...args) {
        filed.push(args);
      },
      candidatesAt: () => [],
      attempted() {},
    },
    chainKeyProfile: { acceptsPeriodKeyResponseCoordinate: () => false },
  });
  const page = new DcaData(pageData(), { publisherOrigin: "https://publisher.example" });
  const result = await resolver.applyResponse(
    page,
    "issuer_example",
    {
      keys: {
        periodKeys: {
          premium: {
            "251023T1500": base64urlEncode(new Uint8Array(16)),
            "251023T1600": base64urlEncode(new Uint8Array(16)),
          },
        },
      },
    },
    associationFor(page, "issuer_example", { periodKeys: { premium: { "251023T1500": "AA" } } }),
  );
  assert.equal(result.accepted, 1);
  assert.equal(filed.length, 1);
  assert.equal(filed[0][1], "251023T1500");
  assert.deepEqual(result.issues, [{ section: "periodKeys", code: "unsolicited_coordinate" }]);
});

test("empty optional response containers do not conflict with truthful family reports", async () => {
  const page = new DcaData(pageData(), { publisherOrigin: "https://publisher.example" });
  const association = associationFor(page, "issuer_example", {
    periodKeys: { premium: { "251023T1500": "AA" } },
  });
  for (const sections of [
    {},
    { periodKeys: {} },
    { chainKeys: {} },
    { periodKeys: { premium: {} } },
    { chainKeys: { premium: {} } },
  ]) {
    const resolver = new ContentKeyResolver({
      cache: {
        put() {
          throw new Error("no leaf may file");
        },
        candidatesAt: () => [],
        attempted() {},
      },
    });
    const result = await resolver.applyResponse(
      page,
      "issuer_example",
      {
        keys: { contentKeys: {}, ...sections },
        notDelivered: { premium: { reason: "unavailable" } },
      },
      association,
    );
    assert.equal(result.accepted, 0);
    assert.deepEqual(result.notDelivered, [{ accessGroup: "premium", reason: "unavailable" }]);
    assert.equal(
      result.issues.some((issue) => issue.code === "malformed_response"),
      false,
    );
  }
  assert.equal(
    (
      await new ContentKeyResolver().applyResponse(
        page,
        "issuer_example",
        { keys: { contentKeys: {} } },
        association,
      )
    ).accepted,
    0,
  );
});

test("actual family leaf conflicts before reusable writes without discarding an independent item key", async () => {
  const page = new DcaData(pageData(), { publisherOrigin: "https://publisher.example" });
  const association = associationFor(page, "issuer_example", {
    contentKeys: { bodytext: "AA" },
    periodKeys: { premium: { "251023T1500": "AA" } },
  });
  for (const section of ["periodKeys", "chainKeys"])
    for (const value of [null, base64urlEncode(new Uint8Array(16))]) {
      let writes = 0;
      const resolver = new ContentKeyResolver({
        cache: {
          put() {
            writes++;
          },
          candidatesAt: () => [],
          attempted() {},
        },
      });
      const result = await resolver.applyResponse(
        page,
        "issuer_example",
        {
          keys: {
            contentKeys: { bodytext: base64urlEncode(new Uint8Array(16).fill(6)) },
            [section]: { premium: { "251023T1500": value } },
          },
          notDelivered: { premium: { reason: "unavailable" } },
        },
        association,
      );
      assert.equal(result.accepted, 1);
      assert.equal(writes, 0);
      assert.deepEqual(result.issues, [{ section: "notDelivered", code: "malformed_response" }]);
      assert.deepEqual(
        await resolver.contentKeyFor(page, "bodytext"),
        new Uint8Array(16).fill(6),
        "the independent item grant remains admitted",
      );
    }
});

describe("representation classification by JSON type", () => {
  // Response binding Section 3: after unsupported sections are discarded and
  // containers admitted, before coordinates, a string is a direct entry and a
  // non-array object a client-bound one, whatever its members. Both kinds in
  // one response reject the representation before any key entry is admitted;
  // other JSON values fail only at their own entry.
  const key = (/** @type {number} */ fill) => base64urlEncode(new Uint8Array(16).fill(fill));
  const page = () => new DcaData(pageData(), { publisherOrigin: "https://publisher.example" });
  const T = "251023T1500";

  const handle = globalThis.crypto.subtle.importKey(
    "raw",
    new Uint8Array(16).fill(7),
    "AES-GCM",
    false,
    ["decrypt"],
  );

  /** A resolver that accepts both representations, so only classification decides. */
  async function instrumented(/** @type {object} */ extra = {}) {
    const opened = await handle;
    const counts = { puts: 0, chainPuts: 0, preflights: 0, opens: 0 };
    const resolver = new ContentKeyResolver({
      acceptDirectFallback: true,
      persistRawPeriodKeys: true,
      cache: {
        put() {
          counts.puts++;
        },
        candidatesAt: () => [],
        attempted() {},
      },
      clientBoundKeyCapability: {
        assertCanOpenChainKeys() {},
        openDeliveredKeys() {
          counts.preflights++;
          return {
            open() {
              counts.opens++;
              return opened;
            },
          };
        },
      },
      ...extra,
    });
    return { counts, resolver };
  }

  const objectEntries = /** @type {const} */ ([
    ["an empty object", {}],
    ["an object without key", { nonce: "n" }],
    ["an object with a wrong-typed key", { key: 7 }],
    ["an object with a null key", { key: null }],
    ["a complete wrapped object", { key: "wrapped", nonce: "n" }],
  ]);

  for (const [label, entry] of objectEntries) {
    test(`${label} beside a direct string rejects the representation`, async () => {
      const { counts, resolver } = await instrumented();
      const delivered = page();
      assert.deepEqual(
        await applyResponse(resolver, delivered, "issuer_example", {
          keys: { contentKeys: { bodytext: key(4), sibling: structuredClone(entry) } },
        }),
        { accepted: 0, errors: [], issues: [{ section: "response", code: "invalid_transport" }] },
      );
      assert.deepEqual(counts, { puts: 0, chainPuts: 0, preflights: 0, opens: 0 });
      assert.equal(await resolver.contentKeyFor(delivered, "bodytext"), null);
    });
  }

  test("the classification spans supported content and period sections", async () => {
    for (const keys of [
      { contentKeys: { bodytext: key(4) }, periodKeys: { premium: { [T]: {} } } },
      { contentKeys: { bodytext: {} }, periodKeys: { premium: { [T]: key(5) } } },
    ]) {
      const { counts, resolver } = await instrumented();
      const delivered = page();
      assert.deepEqual(
        await applyResponse(resolver, delivered, "issuer_example", { keys }),
        { accepted: 0, errors: [], issues: [{ section: "response", code: "invalid_transport" }] },
        JSON.stringify(keys),
      );
      assert.equal(counts.puts, 0, "no period key is filed");
      assert.equal(await resolver.contentKeyFor(delivered, "bodytext"), null);
    }
  });

  test("the classification spans a selected chain section", async () => {
    const chainPuts = [];
    const { counts, resolver } = await instrumented({
      chainCache: {
        put(/** @type {any[]} */ ...args) {
          chainPuts.push(args);
        },
        candidates: () => [],
      },
      chainKeyProfile: {
        constructionProfile: CHAIN_IDENTITY,
        parametersForResponse: () => ({ maxSteps: 2 }),
        acceptsPeriodKeyResponseCoordinate: () => true,
        acceptsResponseCoordinate: () => true,
        candidateSourceFor: () => ({ async *attempts() {} }),
      },
    });
    const delivered = page();
    assert.deepEqual(
      await applyResponse(resolver, delivered, "issuer_example", {
        keys: { contentKeys: { bodytext: key(4) }, chainKeys: { premium: { [T]: {} } } },
      }),
      { accepted: 0, errors: [], issues: [{ section: "response", code: "invalid_transport" }] },
    );
    assert.deepEqual(chainPuts, []);
    assert.equal(counts.preflights, 0);
    assert.equal(await resolver.contentKeyFor(delivered, "bodytext"), null);
  });

  for (const [label, entry] of /** @type {const} */ ([
    ["an array", []],
    ["an array holding a key member", [{ key: "wrapped" }]],
    ["null", null],
    ["a number", 7],
    ["a boolean", true],
  ])) {
    test(`${label} beside a direct string fails only at its own entry`, async () => {
      const { counts, resolver } = await instrumented();
      const delivered = page();
      assert.deepEqual(
        await applyResponse(resolver, delivered, "issuer_example", {
          keys: { contentKeys: { bodytext: key(4), sibling: structuredClone(entry) } },
        }),
        { accepted: 1, errors: [], issues: [{ section: "contentKeys", code: "malformed_key" }] },
      );
      assert.equal(counts.preflights, 0);
      assert.deepEqual(
        await resolver.contentKeyFor(delivered, "bodytext"),
        new Uint8Array(16).fill(4),
      );
    });
  }

  test("an object in a discarded unsupported section establishes no representation", async () => {
    const { resolver } = await instrumented();
    const delivered = page();
    assert.deepEqual(
      await applyResponse(resolver, delivered, "issuer_example", {
        keys: { contentKeys: { bodytext: key(4) }, chainKeys: { premium: { [T]: {} } } },
      }),
      { accepted: 1, errors: [], issues: [{ section: "chainKeys", code: "unsupported_section" }] },
    );
    assert.deepEqual(
      await resolver.contentKeyFor(delivered, "bodytext"),
      new Uint8Array(16).fill(4),
    );
  });

  test("an object at an unpresented coordinate still rejects a mixed representation", async () => {
    // An unsolicited coordinate cannot hide a response-wide contradiction.
    // Classification itself never selects an opener or retains a sibling.
    const { counts, resolver } = await instrumented();
    const delivered = page();
    assert.deepEqual(
      await resolver.applyResponse(
        delivered,
        "issuer_example",
        { keys: { contentKeys: { bodytext: key(4), unsolicited: {} } } },
        associationFor(delivered, "issuer_example", { contentKeys: { bodytext: key(4) } }),
      ),
      {
        accepted: 0,
        errors: [],
        issues: [{ section: "response", code: "invalid_transport" }],
      },
    );
    assert.deepEqual(counts, { puts: 0, chainPuts: 0, preflights: 0, opens: 0 });
    assert.equal(await resolver.contentKeyFor(delivered, "bodytext"), null);
  });

  test("unpresented period coordinates still contribute to a mixed representation", async () => {
    for (const family of ["other", "bad|group"]) {
      const { counts, resolver } = await instrumented();
      const delivered = page();
      const result = await resolver.applyResponse(
        delivered,
        "issuer_example",
        {
          keys: { contentKeys: { bodytext: key(4) }, periodKeys: { [family]: { [T]: {} } } },
        },
        associationFor(delivered, "issuer_example", { contentKeys: { bodytext: key(4) } }),
      );
      assert.deepEqual(result, {
        accepted: 0,
        errors: [],
        issues: [{ section: "response", code: "invalid_transport" }],
      });
      assert.deepEqual(counts, { puts: 0, chainPuts: 0, preflights: 0, opens: 0 });
      assert.equal(await resolver.contentKeyFor(delivered, "bodytext"), null);
    }
  });

  test("an unsolicited direct entry contradicts a bound response before opener acquisition", async () => {
    for (const bodytext of [{ key: "wrapped" }, undefined]) {
      const { counts, resolver } = await instrumented();
      const delivered = page();
      const contentKeys = { unsolicited: key(4), ...(bodytext ? { bodytext } : {}) };
      const result = await resolver.applyResponse(
        delivered,
        "issuer_example",
        {
          transport: { method: "ECDH-P256" },
          keys: { contentKeys },
        },
        associationFor(
          delivered,
          "issuer_example",
          { contentKeys: { bodytext: "sealed" } },
          {
            clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" },
          },
        ),
      );
      assert.deepEqual(result, {
        accepted: 0,
        errors: [],
        issues: [{ section: "response", code: "invalid_transport" }],
      });
      assert.deepEqual(counts, { puts: 0, chainPuts: 0, preflights: 0, opens: 0 });
      assert.equal(await resolver.contentKeyFor(delivered, "bodytext"), null);
    }
  });

  test("out-of-reach chain objects affect representation but never acquire an opener", async () => {
    for (const withDirect of [true, false]) {
      let chainPuts = 0;
      const { counts, resolver } = await instrumented({
        chainCache: {
          put() {
            chainPuts++;
          },
          candidates: () => [],
        },
        chainKeyProfile: {
          constructionProfile: CHAIN_IDENTITY,
          parametersForResponse: () => null,
          acceptsPeriodKeyResponseCoordinate: () => false,
          acceptsResponseCoordinate: () => false,
          candidateSourceFor: () => ({ async *attempts() {} }),
        },
      });
      const delivered = page();
      const result = await resolver.applyResponse(
        delivered,
        "issuer_example",
        {
          keys: {
            ...(withDirect ? { contentKeys: { bodytext: key(4) } } : {}),
            chainKeys: { premium: { [T]: { key: "wrapped" } } },
          },
        },
        associationFor(delivered, "issuer_example", { contentKeys: { bodytext: "sealed" } }),
      );
      assert.equal(result.accepted, 0);
      assert.deepEqual(result.issues, [
        withDirect
          ? { section: "response", code: "invalid_transport" }
          : { section: "chainKeys", code: "malformed_key" },
      ]);
      assert.deepEqual(counts, { puts: 0, chainPuts: 0, preflights: 0, opens: 0 });
      assert.equal(chainPuts, 0);
      assert.equal(await resolver.contentKeyFor(delivered, "bodytext"), null);
    }
  });

  test("unsupported period entries and malformed family containers establish no representation", async () => {
    for (const [cache, periodKeys] of [
      [null, { premium: { [T]: {} } }],
      [undefined, { premium: [] }],
      [undefined, { premium: null }],
    ]) {
      const { counts, resolver } = await instrumented(cache === null ? { cache } : {});
      const delivered = page();
      const result = await applyResponse(resolver, delivered, "issuer_example", {
        keys: { contentKeys: { bodytext: key(4) }, periodKeys },
      });
      assert.equal(result.accepted, 1);
      assert.equal(
        result.issues.some(({ code }) => code === "invalid_transport"),
        false,
      );
      assert.equal(counts.preflights, 0);
      assert.equal(counts.opens, 0);
      assert.deepEqual(
        await resolver.contentKeyFor(delivered, "bodytext"),
        new Uint8Array(16).fill(4),
      );
    }
  });

  test("an object-only answer keeps per-entry failure for a malformed object", async () => {
    const { counts, resolver } = await instrumented();
    const delivered = page();
    assert.deepEqual(
      await applyResponse(resolver, delivered, "issuer_example", {
        transport: { method: "ECDH-P256" },
        keys: { contentKeys: { bodytext: { key: "wrapped" }, sibling: {} } },
      }),
      { accepted: 1, errors: [], issues: [{ section: "contentKeys", code: "malformed_key" }] },
    );
    assert.equal(counts.opens, 1, "only the well-formed object reaches the opener");
    assert.equal(await resolver.contentKeyFor(delivered, "bodytext"), await handle);
  });
});
