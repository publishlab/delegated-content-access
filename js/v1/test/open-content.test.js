// @ts-check
//
// The shared decode-and-open tail on its own, called directly. Every
// composition reaches content bytes through this one function, so the variants
// and the convenience wrappers inherit what it admits. A caller
// that arrived at no aad at all has to be refused here, where the refusal names
// the missing member, rather than three steps down where GCM can only report a
// tag that did not verify.

import test from "node:test";
import assert from "node:assert/strict";

import { encrypt } from "../core-shared/aead.js";
import { base64urlEncode, utf8Decode, utf8Encode } from "../core-shared/codec.js";
import { openContent } from "../core-client/openContent.js";
import { DcaError } from "../core-shared/errors.js";

const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const CONTENT_NAME = "bodytext";
const AAD = "123456|1|bodytext";

/**
 * One sealed item, in the base64url shapes a page carries.
 *
 * @param {string} [contentName] - the name the aad commits to, so two items of
 *   one render can be sealed side by side
 */
async function sealed(contentName = CONTENT_NAME) {
  const contentKey = new Uint8Array(16).fill(9);
  // 0xfb encodes as `-_v7`, so both this nonce and the ciphertext under it
  // carry a character the standard alphabet spells another way, which makes a
  // same-bytes respelling of them possible below.
  const nonce = new Uint8Array(12).fill(0xfb);
  const aad = `123456|1|${contentName}`;
  const ciphertext = await encrypt(contentKey, nonce, utf8Encode(ARTICLE), utf8Encode(aad));

  return {
    contentKey,
    contentName,
    aad,
    nonce: base64urlEncode(nonce),
    ciphertext: base64urlEncode(ciphertext),
  };
}

/**
 * The spellings section 2.2 refuses, built from a canonical one: padding, a
 * standard-base64 character, and a last character carrying nonzero unused bits.
 * The third one exists only where the length leaves unused bits to set; a
 * spelling whose length is a multiple of four has none, and setting a bit there
 * would name different bytes rather than the same ones spelled another way.
 *
 * @param {string} canonical
 * @returns {string[]}
 */
function noncanonical(canonical) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const variants = [`${canonical}=`, standardAlphabet(canonical)];

  if (canonical.length % 4 !== 0) {
    const last = alphabet.indexOf(/** @type {string} */ (canonical.at(-1)));
    variants.push(`${canonical.slice(0, -1)}${alphabet[last | 1]}`);
  }
  return variants;
}

/**
 * The same bytes spelled in the standard alphabet: `-` is 62 and so is `+`, `_`
 * is 63 and so is `/`. The generic decoder translates them back, so this
 * spelling supplies exactly the bytes the canonical one does and the refusal is
 * about the spelling alone.
 *
 * @param {string} canonical
 * @returns {string}
 */
function standardAlphabet(canonical) {
  return canonical.replace(/-/g, "+").replace(/_/g, "/");
}

/**
 * @param {string} message
 * @returns {(error: unknown) => boolean}
 */
const badPage = (message) => (error) =>
  error instanceof DcaError && error.code === "bad_page" && error.message === message;

test("the shared opener opens an item whose caller carried every part of it", async () => {
  const item = await sealed();

  const bytes = await openContent(item.contentKey, CONTENT_NAME, item.nonce, item.ciphertext, AAD);

  assert.equal(utf8Decode(bytes), ARTICLE);
});

test("a nonce the page did not carry is a bad page, not a bare codec throw", async () => {
  const item = await sealed();

  await assert.rejects(
    () => openContent(item.contentKey, CONTENT_NAME, undefined, item.ciphertext, AAD),
    badPage(`the contentData record for "${CONTENT_NAME}" carries no nonce`),
  );
});

test("an aad the caller did not arrive at is a bad page, not a tag failure", async () => {
  const item = await sealed();

  // Absent, and then the shapes a mangled page hands a caller that reads the
  // member off the record without looking at it. Each one has to answer with
  // the missing member; a tag mismatch would say the key was wrong.
  for (const aad of [undefined, null, 42, {}, ["123456|1|bodytext"]]) {
    await assert.rejects(
      () =>
        openContent(
          item.contentKey,
          CONTENT_NAME,
          item.nonce,
          item.ciphertext,
          /** @type {any} */ (aad),
        ),
      badPage(`the contentData record for "${CONTENT_NAME}" carries no aad`),
      `aad ${JSON.stringify(aad) ?? "undefined"}`,
    );
  }
});

test("a noncanonical nonce or ciphertext is a bad page, not bytes off a lenient decoder", async () => {
  const item = await sealed();
  const message = `the nonce or ciphertext for "${CONTENT_NAME}" is not base64url`;

  assert.notEqual(
    standardAlphabet(item.nonce),
    item.nonce,
    "the nonce has a respelling in the standard alphabet",
  );
  assert.notEqual(standardAlphabet(item.ciphertext), item.ciphertext, "so does the ciphertext");

  // Every spelling below decodes through `base64urlDecode`, so before the
  // named admission rule each one handed AES-GCM a nonce or a carrier the page
  // did not spell. Section 2.2 says a refused spelling supplies no bytes.
  for (const nonce of noncanonical(item.nonce)) {
    await assert.rejects(
      () => openContent(item.contentKey, CONTENT_NAME, nonce, item.ciphertext, AAD),
      badPage(message),
      `nonce ${JSON.stringify(nonce)}`,
    );
  }
  for (const ciphertext of noncanonical(item.ciphertext)) {
    await assert.rejects(
      () => openContent(item.contentKey, CONTENT_NAME, item.nonce, ciphertext, AAD),
      badPage(message),
      `ciphertext ${JSON.stringify(ciphertext)}`,
    );
  }
});

test("a noncanonical ciphertext leaves the other items of the same render openable", async () => {
  // The failure scope in spec--data-format.md Section 2.2, "Binary strings":
  // a malformed leaf takes its own item and nothing beside it.
  const mangled = await sealed("premiumtext");
  const sibling = await sealed();

  // The standard alphabet, which the generic decoder translates back, so this
  // item would otherwise have opened on a spelling the page may not use.
  await assert.rejects(
    () =>
      openContent(
        mangled.contentKey,
        mangled.contentName,
        mangled.nonce,
        standardAlphabet(mangled.ciphertext),
        mangled.aad,
      ),
    badPage(`the nonce or ciphertext for "${mangled.contentName}" is not base64url`),
  );

  assert.equal(
    utf8Decode(
      await openContent(
        sibling.contentKey,
        sibling.contentName,
        sibling.nonce,
        sibling.ciphertext,
        sibling.aad,
      ),
    ),
    ARTICLE,
    "the sibling item opens after its neighbour was refused",
  );
});
