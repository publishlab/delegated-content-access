// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { attemptContentKeyWrap } from "../../core-client/contentKeyWrapAttempt.js";
import { encrypt, decrypt } from "../../core-shared/aead.js";
import { base64urlEncode } from "../../core-shared/codec.js";

async function fixture() {
  const periodKey = new Uint8Array(16).fill(3);
  const contentKey = new Uint8Array(16).fill(7);
  const nonce = new Uint8Array(12).fill(4);
  const articleNonce = new Uint8Array(12).fill(5);
  const article = new Uint8Array([1, 2, 3]);
  const ciphertext = await encrypt(contentKey, articleNonce, article);
  const wrapped = await encrypt(periodKey, nonce, contentKey);
  const entry = { t: "251023T1400", key: base64urlEncode(wrapped) };
  const periodHandle = await globalThis.crypto.subtle.importKey(
    "raw",
    periodKey,
    "AES-GCM",
    false,
    ["unwrapKey"],
  );
  return {
    periodKey,
    contentKey,
    nonce,
    articleNonce,
    article,
    ciphertext,
    wrapped,
    entry,
    periodHandle,
  };
}

/** @param {Awaited<ReturnType<typeof fixture>>} data @param {Uint8Array|CryptoKey|null} opened */
async function opensArticle(data, opened) {
  assert.notEqual(opened, null, "the valid wrap returns a usable content key");
  assert.deepEqual(
    await decrypt(/** @type {Uint8Array|CryptoKey} */ (opened), data.articleNonce, data.ciphertext),
    data.article,
  );
}

test("a wrap attempt propagates a handle usage fault instead of reporting a candidate miss", async () => {
  const data = await fixture();
  for (const usage of ["decrypt", "encrypt"]) {
    const handle = await globalThis.crypto.subtle.importKey(
      "raw",
      data.periodKey,
      "AES-GCM",
      false,
      [/** @type {KeyUsage} */ (usage)],
    );
    assert.equal(handle.extractable, false);
    await assert.rejects(
      () => attemptContentKeyWrap(data.entry, handle, data.nonce),
      (/** @type {any} */ error) =>
        error instanceof DOMException &&
        ["InvalidAccessError", "InvalidAccessException"].includes(error.name),
    );
  }
  await opensArticle(data, await attemptContentKeyWrap(data.entry, data.periodHandle, data.nonce));
});

test("a wrap attempt refuses incompatible key capabilities as faults", async () => {
  const data = await fixture();
  for (const key of [null, undefined, {}, "period-key"]) {
    await assert.rejects(
      () => attemptContentKeyWrap(data.entry, /** @type {any} */ (key), data.nonce),
      {
        code: "bad_config",
      },
    );
  }
  const wrongAlgorithm = await globalThis.crypto.subtle.importKey(
    "raw",
    data.periodKey,
    "AES-CBC",
    false,
    ["unwrapKey"],
  );
  const wrongWidth = await globalThis.crypto.subtle.importKey(
    "raw",
    new Uint8Array(32),
    "AES-GCM",
    false,
    ["unwrapKey"],
  );
  for (const key of [new Uint8Array(15), new Uint8Array(32), wrongAlgorithm, wrongWidth]) {
    await assert.rejects(() => attemptContentKeyWrap(data.entry, key, data.nonce), {
      code: "bad_key",
    });
  }
  await opensArticle(data, await attemptContentKeyWrap(data.entry, data.periodKey, data.nonce));
});

test("invalid AAD cannot become an empty-AAD wrap opening", async () => {
  const data = await fixture();
  const aad = new Uint8Array([6, 7]);
  const boundEntry = {
    ...data.entry,
    key: base64urlEncode(await encrypt(data.periodKey, data.nonce, data.contentKey, aad)),
  };
  for (const key of [data.periodKey, data.periodHandle]) {
    await opensArticle(data, await attemptContentKeyWrap(data.entry, key, data.nonce));
    for (const malformed of ["abc", "", new ArrayBuffer(0)]) {
      await assert.rejects(
        () => attemptContentKeyWrap(data.entry, key, data.nonce, /** @type {any} */ (malformed)),
        { code: "bad_config" },
      );
    }
    await opensArticle(data, await attemptContentKeyWrap(boundEntry, key, data.nonce, aad));
    assert.equal(
      await attemptContentKeyWrap(boundEntry, key, data.nonce),
      null,
      "no unbound retry opens a bound wrap",
    );
    assert.equal(
      await attemptContentKeyWrap(boundEntry, key, data.nonce, new Uint8Array([8])),
      null,
    );
    await opensArticle(data, await attemptContentKeyWrap(data.entry, key, data.nonce));
  }
});

test("entry misses leave the same raw and opaque capability usable", async () => {
  const data = await fixture();
  const tampered = Uint8Array.from(data.wrapped);
  tampered[tampered.length - 1] ^= 1;
  const unreadable = [
    { ...data.entry, key: "!!!!" },
    { ...data.entry, key: base64urlEncode(data.wrapped.subarray(1)) },
    { ...data.entry, key: base64urlEncode(tampered) },
  ];
  for (const key of [data.periodKey, data.periodHandle]) {
    for (const entry of unreadable) {
      assert.equal(await attemptContentKeyWrap(entry, key, data.nonce), null);
      await opensArticle(data, await attemptContentKeyWrap(data.entry, key, data.nonce));
    }
  }
});

test("the wrap opens only under the nonce the caller derived", async () => {
  const data = await fixture();
  const other = Uint8Array.from(data.nonce);
  other[0] ^= 1;
  for (const key of [data.periodKey, data.periodHandle]) {
    assert.equal(await attemptContentKeyWrap(data.entry, key, other), null, "a wrong nonce misses");
    await opensArticle(data, await attemptContentKeyWrap(data.entry, key, data.nonce));
  }
});

test("a carried nonce member supplies no IV and causes no miss", async () => {
  const data = await fixture();
  const other = Uint8Array.from(data.nonce);
  other[0] ^= 1;
  for (const key of [data.periodKey, data.periodHandle]) {
    for (const carried of [
      base64urlEncode(data.nonce),
      base64urlEncode(other),
      "AAAA=",
      "!!",
      12,
      null,
      { bytes: [4] },
    ]) {
      const entry = { ...data.entry, nonce: carried };
      await opensArticle(data, await attemptContentKeyWrap(entry, key, data.nonce));
      assert.equal(
        await attemptContentKeyWrap({ ...entry, nonce: base64urlEncode(data.nonce) }, key, other),
        null,
        "the carried value never replaces the derived nonce",
      );
    }
  }
});

test("a nonce that is not 12 bytes is a caller fault, not a candidate miss", async () => {
  const data = await fixture();
  for (const nonce of [
    undefined,
    null,
    "AAAAAAAAAAAAAAAA",
    new Uint8Array(11),
    new Uint8Array(13),
    [4],
  ]) {
    await assert.rejects(
      () => attemptContentKeyWrap(data.entry, data.periodKey, /** @type {any} */ (nonce)),
      { code: "bad_config" },
    );
  }
});
