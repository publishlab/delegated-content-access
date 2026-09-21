// @ts-check
//
// The client half on its own, over a record and a ciphertext this test builds
// with base primitives. This file checks the order of the two steps: an
// item this client cannot read is refused before any key is resolved, so a
// page carrying one costs no unlock call.

import test from "node:test";
import assert from "node:assert/strict";

import { encrypt } from "../../../core-shared/aead.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { decode, encode } from "../core-shared--client-publisher/gzipCodec.js";
import { openEncodedContent } from "../core-client/openEncodedContent.js";

const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const AAD = "123456|1|bodytext";

/**
 * One sealed item, as a page carries it.
 *
 * @param {Uint8Array} plaintext
 * @param {string[]} [contentEncodings]
 */
async function sealed(plaintext, contentEncodings) {
  const contentKey = new Uint8Array(16).fill(9);
  const nonce = new Uint8Array(12).fill(3);
  const ciphertext = await encrypt(contentKey, nonce, plaintext, utf8Encode(AAD));

  return {
    contentKey,
    ciphertext: base64urlEncode(ciphertext),
    record: {
      contentType: "text/html",
      nonce: base64urlEncode(nonce),
      aad: AAD,
      ...(contentEncodings === undefined ? {} : { contentEncodings }),
    },
  };
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
    record: item.record,
    contentName: "bodytext",
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
    record: item.record,
    contentName: "bodytext",
    ciphertext: item.ciphertext,
    resolveKey,
  });

  assert.deepEqual(bytes, utf8Encode(ARTICLE));
});

test("an encoding this extension does not write is refused before the key is resolved", async () => {
  const item = await sealed(utf8Encode(ARTICLE), ["br"]);
  const { calls, resolveKey } = spy(item.contentKey);

  await assert.rejects(
    () =>
      openEncodedContent({
        record: item.record,
        contentName: "bodytext",
        ciphertext: item.ciphertext,
        resolveKey,
      }),
    { code: "unsupported_encoding", message: /"br"/ },
  );

  assert.equal(calls.count, 0, "no key was resolved for an item this client cannot read");
});

test("a client explicitly without gzip refuses the gzip item before the key", async () => {
  const item = await sealed(await encode(utf8Encode(ARTICLE)), ["gzip"]);
  const { calls, resolveKey } = spy(item.contentKey);

  await assert.rejects(
    () =>
      openEncodedContent({
        record: item.record,
        contentName: "bodytext",
        ciphertext: item.ciphertext,
        resolveKey,
        gzip: null,
      }),
    { code: "unsupported_encoding", message: /bodytext/ },
  );

  assert.equal(calls.count, 0);
});

test("a malformed encoding list is a bad page before the key", async () => {
  const item = await sealed(utf8Encode(ARTICLE));
  const { calls, resolveKey } = spy(item.contentKey);

  await assert.rejects(
    () =>
      openEncodedContent({
        record: { ...item.record, contentEncodings: [7] },
        contentName: "bodytext",
        ciphertext: item.ciphertext,
        resolveKey,
      }),
    { code: "bad_page" },
  );

  assert.equal(calls.count, 0);
});

test("a record carrying no aad is a bad page, not a tag failure", async () => {
  const item = await sealed(utf8Encode(ARTICLE));

  // This convenience reads the aad off the record itself, so a page that
  // mangled the member hands `undefined` to base. Base refuses it, and it
  // refuses by name: a caller told "auth tag mismatch" would go looking for a
  // wrong key.
  const absent = { ...item.record };
  delete absent.aad;
  const inherited = Object.create({ aad: AAD });
  Object.assign(inherited, absent);

  for (const record of [absent, { ...item.record, aad: 42 }, inherited]) {
    const { resolveKey } = spy(item.contentKey);
    await assert.rejects(
      () =>
        openEncodedContent({
          record,
          contentName: "bodytext",
          ciphertext: item.ciphertext,
          resolveKey,
        }),
      { code: "bad_page" },
    );
  }
});

test("an inherited member does not stand in for a declared encoding", async () => {
  const item = await sealed(utf8Encode(ARTICLE));
  const record = Object.create({ contentEncodings: ["gzip"] });
  Object.assign(record, item.record);
  const { resolveKey } = spy(item.contentKey);

  const bytes = await openEncodedContent({
    record,
    contentName: "bodytext",
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
    record: item.record,
    contentName: "bodytext",
    ciphertext: item.ciphertext,
    resolveKey,
    gzip: {
      encode,
      decode: (input) => {
        asked += 1;
        return decode(input);
      },
    },
  });

  assert.equal(asked, 1, "the default was not reached behind the injected one");
  assert.deepEqual(bytes, utf8Encode(ARTICLE));
});
