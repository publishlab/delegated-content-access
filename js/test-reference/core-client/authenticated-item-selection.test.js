// @ts-check
//
// `contentKeyForAuthenticatedItem` called directly, not through a route walk:
// a held key must pass the caller's predicate like any candidate, a refused
// held key leaves the cached wrap path open, and the predicate's own faults and
// non-boolean answers stay visible.

import test from "node:test";
import assert from "node:assert/strict";

import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../core-client/DcaData.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { openContent } from "../../core-client/openContent.js";
import { encrypt } from "../../core-shared/aead.js";
import { base64urlEncode, utf8Encode } from "../../core-shared/codec.js";
import { contentKeyWrapNonceOctets } from "../support/contentKeyWrapNonceOctets.js";

const ISSUER = "issuer_example";
const T = "251023T1500";
const PERIOD = new Uint8Array(16).fill(17);
const WRONG = new Uint8Array(16).fill(18);
const RIGHT = new Uint8Array(16).fill(19);
const NONCE = new Uint8Array(12).fill(9);
const WRAP_NONCE = contentKeyWrapNonceOctets({
  renderId: "AAAAAAAAAAAAAAAAAAAAAA",
  contentName: "bodytext",
  accessGroup: "premium",
  t: T,
});

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {object} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", typ: "JWT", kid: "k1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

/** One item wrapped under one cached period key, and its sealed bytes. */
async function world() {
  const page = new DcaData(
    {
      version: "1",
      resourceJWT: compactJwt({
        origin: "https://signed.example",
        renderId: "AAAAAAAAAAAAAAAAAAAAAA",
      }),
      issuerData: [
        { issuerName: ISSUER, keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: {} },
      ],
      contentData: [
        {
          contentName: "bodytext",
          contentType: "text/html",
          nonce: base64urlEncode(NONCE),
          keys: [
            {
              accessGroup: "premium",
              period: T,
              key: base64urlEncode(await encrypt(PERIOD, WRAP_NONCE, RIGHT)),
            },
          ],
        },
      ],
    },
    { publisherOrigin: "https://publisher.example" },
  );
  const ciphertext = base64urlEncode(
    await encrypt(RIGHT, new Uint8Array(12), utf8Encode("article"), utf8Encode("aad")),
  );
  const reads = [];
  const resolver = new ContentKeyResolver({
    cache: {
      put() {},
      attempted() {},
      candidatesAt(/** @type {string} */ group, /** @type {string} */ t) {
        reads.push(`${group}|${t}`);
        return [PERIOD];
      },
    },
  });
  // Hold the wrong item key the ordinary way: an admitted direct response.
  const application = await resolver.applyResponse(
    page,
    ISSUER,
    { keys: { contentKeys: [{ contentName: "bodytext", key: base64urlEncode(WRONG) }] } },
    new ResponseAssociation(page, ISSUER, {
      version: page.version,
      issuerName: ISSUER,
      resourceJWT: page.resourceJWT,
      keyId: page.keyIdFor(ISSUER),
      sealed: { contentKeys: [{ contentName: "bodytext", key: "AA" }] },
    }),
  );
  assert.equal(application.accepted, 1);
  assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), WRONG);
  /** @param {Uint8Array|CryptoKey} candidate */
  const opens = async (candidate) => {
    try {
      await openContent(candidate, "bodytext", ciphertext, utf8Encode("aad"));
      return true;
    } catch (cause) {
      if (/** @type {any} */ (cause)?.code === "decrypt_failed") return false;
      throw cause;
    }
  };
  return { page, resolver, reads, opens };
}

test("a held wrong key fails the predicate and the cached wrap supplies the right key", async () => {
  const { page, resolver, reads, opens } = await world();
  /** @type {Uint8Array[]} */
  const seen = [];
  const key = await resolver.contentKeyForAuthenticatedItem(page, "bodytext", async (candidate) => {
    seen.push(/** @type {Uint8Array} */ (candidate));
    return opens(candidate);
  });
  assert.deepEqual(key, RIGHT);
  assert.deepEqual(seen, [WRONG, RIGHT], "the held key is tried first, then the wrap");
  assert.deepEqual(reads, [`premium|${T}`]);
  assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), RIGHT, "the right key is held");
});

test("a held key that passes the predicate answers before any cache read", async () => {
  const { page, resolver, reads } = await world();
  const key = await resolver.contentKeyForAuthenticatedItem(page, "bodytext", async () => true);
  assert.deepEqual(key, WRONG, "the predicate, not the resolver, decides what opens");
  assert.deepEqual(reads, []);
});

test("a predicate that refuses every candidate yields null and replaces no held key", async () => {
  const { page, resolver, reads } = await world();
  let calls = 0;
  const key = await resolver.contentKeyForAuthenticatedItem(page, "bodytext", async () => {
    calls++;
    return false;
  });
  assert.equal(key, null);
  assert.equal(calls, 2);
  assert.deepEqual(reads, [`premium|${T}`]);
  assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), WRONG);
});

test("a predicate fault surfaces unchanged", async () => {
  const { page, resolver } = await world();
  const fault = new Error("predicate fault");
  await assert.rejects(
    resolver.contentKeyForAuthenticatedItem(page, "bodytext", async () => {
      throw fault;
    }),
    (cause) => cause === fault,
  );
});

for (const [name, answer] of [
  ["a number", 1],
  ["a string", "true"],
  ["undefined", undefined],
  ["null", null],
]) {
  test(`a predicate answering ${name} is refused as bad_config`, async () => {
    const { page, resolver } = await world();
    await assert.rejects(
      resolver.contentKeyForAuthenticatedItem(
        page,
        "bodytext",
        // @ts-expect-error the predicate breaks its boolean contract on purpose
        async () => answer,
      ),
      { code: "bad_config" },
    );
  });
}

test("the entry refuses a raw page and a missing predicate before any read", async () => {
  const { page, resolver, reads } = await world();
  await assert.rejects(
    // @ts-expect-error a raw page is not a DcaData
    resolver.contentKeyForAuthenticatedItem({}, "bodytext", async () => true),
    { code: "bad_config" },
  );
  await assert.rejects(
    // @ts-expect-error the predicate is required
    resolver.contentKeyForAuthenticatedItem(page, "bodytext", undefined),
    { code: "bad_config" },
  );
  assert.deepEqual(reads, []);
});
