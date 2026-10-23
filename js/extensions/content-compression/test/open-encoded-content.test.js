// @ts-check
//
// The client half on its own, over a delivery and a ciphertext this test
// builds with base primitives. This file checks the order of the two steps: an
// item this opener cannot read is refused before its resolveKey callback.
// It also checks that the opener uses the captured item view for decoder
// selection. Content AAD binds the render ID and item name, not type or encodings.

import test from "node:test";
import assert from "node:assert/strict";

import { encrypt } from "../../../core-shared/aead.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";
import { decode, encode } from "../core-shared--client-publisher/gzipCodec.js";
import { openEncodedContent } from "../core-client/openEncodedContent.js";

const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";

// Three unpadded base64url segments: the shape a signing input is cut from.
// Nothing here verifies the signature, so its segment is an invented value.
const RESOURCE_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZW5kZXJJZCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ.c2lnbmF0dXJl";

/**
 * One delivery carrying `record` as its bodytext item. The item record gains
 * its `contentName` and keeps the prototype `record` has, so a test about an
 * inherited member still hands the reader one.
 *
 * @param {Record<string, unknown>} record
 */
function delivery(record) {
  const named = Object.assign(
    Object.create(Object.getPrototypeOf(record)),
    { contentName: "bodytext" },
    record,
  );
  return {
    version: "1",
    resourceJWT: RESOURCE_JWT,
    contentData: [named],
    issuerData: [{ issuerName: "issuer_a", keyId: "k", sealed: {} }],
  };
}

/**
 * One sealed item, as a page carries it, sealed under the content AAD its
 * record and the delivery token derive.
 *
 * @param {Uint8Array} plaintext
 * @param {string[]} [contentEncodings]
 */
async function sealed(plaintext, contentEncodings) {
  const contentKey = new Uint8Array(16).fill(9);
  const nonce = new Uint8Array(12);
  const record = {
    contentType: "text/html",
    nonce: base64urlEncode(nonce),
    ...(contentEncodings === undefined ? {} : { contentEncodings }),
  };
  const aad = contentAadOctets(delivery(record), "bodytext");
  const ciphertext = await encrypt(contentKey, nonce, plaintext, aad);

  return { contentKey, ciphertext: base64urlEncode(ciphertext), record };
}

/**
 * The view the opener reads, captured from a delivery carrying `record`.
 *
 * @param {Record<string, unknown>} record
 */
function captured(record) {
  return /** @type {import('../../../core-client/DcaData.js').ContentItemView} */ (
    new DcaData(delivery(record)).contentItemFor("bodytext")
  );
}

/** A resolveKey that records whether it was reached. */
function spy(/** @type {Uint8Array} */ key) {
  const calls = { count: 0 };
  return {
    calls,
    resolveKey: async () => {
      calls.count += 1;
      return key;
    },
  };
}

test("a record with no contentEncodings opens as base opens it", async () => {
  const item = await sealed(utf8Encode(ARTICLE));
  const { calls, resolveKey } = spy(item.contentKey);

  const bytes = await openEncodedContent({
    item: captured(item.record),
    ciphertext: item.ciphertext,
    resolveKey,
  });

  assert.deepEqual(bytes, utf8Encode(ARTICLE));
  assert.equal(calls.count, 1);
});

test("a gzip record opens through the default decoder", async () => {
  const item = await sealed(await encode(utf8Encode(ARTICLE)), ["gzip"]);
  const { resolveKey } = spy(item.contentKey);

  const bytes = await openEncodedContent({
    item: captured(item.record),
    ciphertext: item.ciphertext,
    resolveKey,
  });

  assert.deepEqual(bytes, utf8Encode(ARTICLE));
});

test(
  "an encoding this extension does not write is refused before the key is resolved",
  { tags: ["dca-profile-baseline/client/representation-processing"] },
  async () => {
    const item = await sealed(utf8Encode(ARTICLE), ["br"]);
    const { calls, resolveKey } = spy(item.contentKey);

    await assert.rejects(
      () =>
        openEncodedContent({
          item: captured(item.record),
          ciphertext: item.ciphertext,
          resolveKey,
        }),
      { code: "unsupported_encoding", message: /"br"/ },
    );

    assert.equal(calls.count, 0, "no key was resolved for an item this client cannot read");
  },
);

test(
  "a client explicitly without gzip refuses the gzip item before the key",
  { tags: ["dca-profile-baseline/client/representation-processing"] },
  async () => {
    const item = await sealed(await encode(utf8Encode(ARTICLE)), ["gzip"]);
    const { calls, resolveKey } = spy(item.contentKey);

    await assert.rejects(
      () =>
        openEncodedContent({
          item: captured(item.record),
          ciphertext: item.ciphertext,
          resolveKey,
          gzip: null,
        }),
      { code: "unsupported_encoding", message: /bodytext/ },
    );

    assert.equal(calls.count, 0);
  },
);

test(
  "a malformed encoding list is a bad page before the key",
  { tags: ["dca-profile-baseline/client/representation-processing"] },
  async () => {
    const item = await sealed(utf8Encode(ARTICLE));
    const { calls, resolveKey } = spy(item.contentKey);

    // The capture refuses the record, so the opener is never reached.
    await assert.rejects(
      async () =>
        openEncodedContent({
          item: captured({ ...item.record, contentEncodings: [7] }),
          ciphertext: item.ciphertext,
          resolveKey,
        }),
      { code: "bad_page" },
    );

    assert.equal(calls.count, 0);
  },
);

test("a carried aad is ignored whatever its type", async () => {
  const item = await sealed(utf8Encode(ARTICLE));

  // The opener rebuilds the content AAD from the captured view and never reads
  // one off the record, so a carried member of any type changes nothing.
  const inherited = Object.create({ aad: "123456|1|bodytext" });
  Object.assign(inherited, item.record);
  for (const record of [
    { ...item.record, aad: "123456|1|bodytext" },
    { ...item.record, aad: 42 },
    inherited,
  ]) {
    const { resolveKey } = spy(item.contentKey);
    const bytes = await openEncodedContent({
      item: captured(record),
      ciphertext: item.ciphertext,
      resolveKey,
    });
    assert.deepEqual(bytes, utf8Encode(ARTICLE));
  }
});

test("handling metadata selects processing after successful authentication", async () => {
  const item = await sealed(await encode(utf8Encode(ARTICLE)), ["gzip"]);
  const changedType = captured({ ...item.record, contentType: "text/plain" });
  const opened = await openEncodedContent({
    item: changedType,
    ciphertext: item.ciphertext,
    resolveKey: async () => item.contentKey,
  });
  assert.equal(new TextDecoder().decode(opened), ARTICLE);
  for (const contentEncodings of [["gzip", "gzip"]]) {
    await assert.rejects(
      openEncodedContent({
        item: captured({ ...item.record, contentEncodings }),
        ciphertext: item.ciphertext,
        resolveKey: async () => item.contentKey,
      }),
      { code: "bad_encoding" },
    );
  }
  const unlayered = await openEncodedContent({
    item: captured({ contentType: "text/html" }),
    ciphertext: item.ciphertext,
    resolveKey: async () => item.contentKey,
  });
  assert.deepEqual(unlayered, await encode(utf8Encode(ARTICLE)));
});

test("an inherited member does not stand in for a declared encoding", async () => {
  const item = await sealed(utf8Encode(ARTICLE));
  const record = Object.create({ contentEncodings: ["gzip"] });
  Object.assign(record, item.record);
  const { resolveKey } = spy(item.contentKey);

  const bytes = await openEncodedContent({
    item: captured(record),
    ciphertext: item.ciphertext,
    resolveKey,
    gzip: null,
  });

  assert.deepEqual(bytes, utf8Encode(ARTICLE));
});

test("the injected gzip is what opens the item", async () => {
  const item = await sealed(await encode(utf8Encode(ARTICLE)), ["gzip"]);
  const { resolveKey } = spy(item.contentKey);
  let asked = 0;

  const bytes = await openEncodedContent({
    item: captured(item.record),
    ciphertext: item.ciphertext,
    resolveKey,
    gzip: {
      encode,
      decode: (input, budget) => {
        asked += 1;
        assert.deepEqual(budget, { maxOutputBytes: 64 * 1024 * 1024 });
        return decode(input, budget);
      },
    },
  });

  assert.equal(asked, 1, "the default was not reached behind the injected one");
  assert.deepEqual(bytes, utf8Encode(ARTICLE));
});

test("candidate origin reaches authentication through the compression convenience API", async () => {
  const item = await sealed(utf8Encode(ARTICLE));
  for (const [origin, code] of /** @type {const} */ ([
    [{ kind: "held-content-key" }, "decrypt_failed"],
    [{ kind: "recovered-content-key" }, "no_key"],
  ])) {
    await assert.rejects(
      openEncodedContent({
        item: captured(item.record),
        ciphertext: item.ciphertext,
        resolveKey: async (authenticate) => {
          assert.equal(await authenticate(new Uint8Array(16).fill(7), origin), false);
          return null;
        },
      }),
      { code },
    );
  }
});
