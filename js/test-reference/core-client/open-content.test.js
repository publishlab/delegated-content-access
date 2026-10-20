// @ts-check
//
// The shared decode-and-open tail on its own, called directly, and the
// representation opener over an item view captured from a live page. Every
// composition reaches content bytes through these, so the variants and the
// convenience wrappers inherit what they admit. The content AAD is bytes the
// client rebuilt from captured values; a caller holding no bytes is refused
// here rather than three steps down where GCM can only report a tag that did
// not verify.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { encrypt } from "../../core-shared/aead.js";
import { base64urlEncode, utf8Decode, utf8Encode } from "../../core-shared/codec.js";
import { ContentRepresentationOpener } from "../../core-client/ContentRepresentationOpener.js";
import { openContent } from "../../core-client/openContent.js";
import { DcaData } from "../../core-client/DcaData.js";
import { DcaError } from "../../core-shared/errors.js";
import { contentAadOctets } from "../support/contentAadOctets.js";

const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const CONTENT_NAME = "bodytext";
const TOKEN =
  "eyJhbGciOiJFUzI1NiJ9.eyJyZW5kZXJJZCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ.c2lnbmF0dXJl";

/** A delivery shaped like the wire, written out, with one record per name. */
function delivery(/** @type {Record<string, object>} */ contentData) {
  return {
    version: "1",
    resourceJWT: TOKEN,
    contentData,
    issuerData: { issuer_example: { keyId: "k1", sealed: { contentKeys: {} } } },
  };
}

/** @param {string} contentName */
function aadOf(contentName) {
  return contentAadOctets(delivery({ [contentName]: { contentType: "text/html" } }), contentName);
}
const AAD = aadOf(CONTENT_NAME);

/**
 * One sealed item, in the base64url shapes a page carries.
 *
 * @param {string} [contentName] - the name the aad commits to, so two items of
 *   one render can be sealed side by side
 */
async function sealed(contentName = CONTENT_NAME) {
  const contentKey = new Uint8Array(16).fill(9);
  // Content encryption always uses twelve zero octets.
  const nonce = new Uint8Array(12);
  const aad = aadOf(contentName);
  const ciphertext = await encrypt(contentKey, new Uint8Array(12), utf8Encode(ARTICLE), aad);

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

  const bytes = await openContent(item.contentKey, CONTENT_NAME, item.ciphertext, AAD);

  assert.equal(utf8Decode(bytes), ARTICLE);
});

test("content AAD that is not bytes is refused before the key is used", async () => {
  const item = await sealed();

  // The former carried string, and the shapes a composition that read a
  // member off the record would pass. None reaches GCM as a changed AAD.
  for (const aad of [undefined, null, 42, {}, "123456|1|bodytext", [1, 2]]) {
    await assert.rejects(
      () => openContent(item.contentKey, CONTENT_NAME, item.ciphertext, /** @type {any} */ (aad)),
      { code: "bad_config" },
      `aad ${JSON.stringify(aad) ?? "undefined"}`,
    );
  }
});

test("a noncanonical ciphertext is a bad page, not bytes off a lenient decoder", async () => {
  const item = await sealed();
  const message = `the ciphertext for "${CONTENT_NAME}" is not base64url`;

  for (const ciphertext of noncanonical(item.ciphertext)) {
    await assert.rejects(
      () => openContent(item.contentKey, CONTENT_NAME, ciphertext, AAD),
      badPage(message),
      `ciphertext ${JSON.stringify(ciphertext)}`,
    );
  }
});

test("a noncanonical ciphertext leaves the other items of the same render openable", async () => {
  // The failure scope in spec--data-format.md Section 2.2, "Binary strings":
  // a malformed ciphertext entry takes its own item and nothing beside it.
  const mangled = await sealed("premiumtext");
  const sibling = await sealed();

  // The standard alphabet, which the generic decoder translates back, so this
  // item would otherwise have opened on a spelling the page may not use.
  await assert.rejects(
    () =>
      openContent(
        mangled.contentKey,
        mangled.contentName,
        standardAlphabet(mangled.ciphertext),
        mangled.aad,
      ),
    badPage(`the ciphertext for "${mangled.contentName}" is not base64url`),
  );

  assert.equal(
    utf8Decode(
      await openContent(sibling.contentKey, sibling.contentName, sibling.ciphertext, sibling.aad),
    ),
    ARTICLE,
    "the sibling item opens after its neighbour was refused",
  );
});

test("malformed AES-GCM page lengths fail before key admission", async () => {
  const message = `the ciphertext for "${CONTENT_NAME}" has an invalid AES-GCM length`;
  for (const width of [0, 15]) {
    await assert.rejects(
      () =>
        openContent(
          /** @type {any} */ (null),
          CONTENT_NAME,
          base64urlEncode(new Uint8Array(width)),
          AAD,
        ),
      badPage(message),
    );
  }
});

test("a type with an unpaired surrogate fails capture, and a literal U+FFFD type opens", async () => {
  const contentKey = new Uint8Array(16).fill(9);
  const nonce = new Uint8Array(12);
  const page = delivery({
    [CONTENT_NAME]: { contentType: "text/�", nonce: base64urlEncode(nonce) },
  });
  const ciphertext = base64urlEncode(
    await encrypt(
      contentKey,
      new Uint8Array(12),
      utf8Encode(ARTICLE),
      contentAadOctets(page, CONTENT_NAME),
    ),
  );
  const item = new DcaData(page).contentItemFor(CONTENT_NAME);
  assert.ok(item);
  const opener = new ContentRepresentationOpener();
  const bytes = await opener.open({ item, ciphertext, resolveKey: async () => contentKey });
  assert.equal(utf8Decode(bytes), ARTICLE);
  for (const surrogate of ["\ud800", "\udfff"]) {
    /** @type {any} */ (page.contentData[CONTENT_NAME]).contentType = `text/${surrogate}`;
    assert.throws(() => new DcaData(page).contentItemFor(CONTENT_NAME), { code: "bad_page" });
  }
});

test("a representation opener refuses an item without AAD bytes before resolving its key", async () => {
  let resolutions = 0;
  for (const contentAad of [undefined, "123456|1|bodytext"]) {
    await assert.rejects(
      new ContentRepresentationOpener().open({
        item: /** @type {any} */ ({
          contentName: CONTENT_NAME,
          contentType: "text/html",
          contentEncodings: [],
          nonce: "AAAAAAAAAAAAAAAA",
          contentAad,
        }),
        ciphertext: "",
        resolveKey: async () => {
          resolutions += 1;
          return new Uint8Array(16);
        },
      }),
      { code: "bad_config" },
    );
  }
  assert.equal(resolutions, 0);
});

describe("Opening a captured item while the live page changes", () => {
  const KEY = new Uint8Array(16).fill(3);
  const SIBLING_KEY = new Uint8Array(16).fill(4);
  const NONCE = new Uint8Array(12);
  const OTHER_NONCE = new Uint8Array(12).fill(6);

  /**
   * A live page with two items. `bodytext` is sealed in its "x" layer; the
   * "x" decoder strips a marker and the "y" decoder would reverse the bytes.
   */
  async function livePage() {
    const page = delivery({
      [CONTENT_NAME]: {
        contentType: "text/html",
        nonce: base64urlEncode(NONCE),
        contentEncodings: ["x"],
      },
      sidebar: { contentType: "text/plain", nonce: base64urlEncode(NONCE) },
    });
    const ciphertexts = {
      [CONTENT_NAME]: base64urlEncode(
        await encrypt(KEY, NONCE, utf8Encode(`X:${ARTICLE}`), contentAadOctets(page, CONTENT_NAME)),
      ),
      sidebar: base64urlEncode(
        await encrypt(SIBLING_KEY, NONCE, utf8Encode("sidebar"), contentAadOctets(page, "sidebar")),
      ),
    };
    /** @type {string[]} */
    const decoded = [];
    const opener = new ContentRepresentationOpener({
      x: (bytes) => {
        decoded.push("x");
        return bytes.subarray(2);
      },
      y: (bytes) => {
        decoded.push("y");
        return Uint8Array.from(bytes).reverse();
      },
    });
    return { page, ciphertexts, decoded, opener, dcaData: new DcaData(page) };
  }

  /** Every bound input of `bodytext` and the delivery's token, changed in place. @param {any} page */
  function mutate(page) {
    const record = page.contentData[CONTENT_NAME];
    record.contentType = "text/plain";
    record.contentEncodings = ["y"];
    record.nonce = base64urlEncode(OTHER_NONCE);
    page.resourceJWT =
      "eyJhbGciOiJub25lIn0.eyJyZW5kZXJJZCI6IkFRRUJBUUVCQVFFQkFRRUJBUUVCQVEifQ.c2lnbmF0dXJl";
  }

  test("authentication, decoder choice and the handed-off type use the captured values", async () => {
    const { page, ciphertexts, decoded, opener, dcaData } = await livePage();
    const item = dcaData.contentItemFor(CONTENT_NAME);
    assert.ok(item);
    const bytes = await opener.open({
      item,
      ciphertext: ciphertexts[CONTENT_NAME],
      resolveKey: async () => {
        mutate(page);
        await new Promise((resolve) => setImmediate(resolve));
        return KEY;
      },
    });
    assert.equal(utf8Decode(bytes), ARTICLE, "opened under the captured render/name transcript");
    assert.deepEqual(decoded, ["x"], "the captured decoder ran and the edited one did not");
    assert.equal(item.contentType, "text/html", "the type a caller hands off is the captured one");
  });

  test("a capture after the edit fails without plaintext, and a sibling still opens", async () => {
    const { page, ciphertexts, decoded, opener, dcaData } = await livePage();
    const sibling = dcaData.contentItemFor("sidebar");
    assert.ok(sibling);
    mutate(page);
    /** @type {any} */ (page.contentData[CONTENT_NAME]).nonce = base64urlEncode(NONCE);
    const edited = dcaData.contentItemFor(CONTENT_NAME);
    assert.ok(edited);
    await assert.rejects(
      opener.open({
        item: edited,
        ciphertext: ciphertexts[CONTENT_NAME],
        resolveKey: async () => KEY,
      }),
      { code: "decrypt_failed" },
    );
    assert.deepEqual(decoded, [], "no decoder saw bytes from a failed item");

    // A malformed record fails only its own capture.
    page.contentData[CONTENT_NAME] = /** @type {any} */ ("not a record");
    assert.throws(() => dcaData.contentItemFor(CONTENT_NAME), { code: "bad_page" });

    // The sibling captured before the edits still opens under its captured
    // token; a fresh capture binds the edited token and does not.
    const bytes = await opener.open({
      item: sibling,
      ciphertext: ciphertexts.sidebar,
      resolveKey: async () => SIBLING_KEY,
    });
    assert.equal(utf8Decode(bytes), "sidebar");
    const fresh = dcaData.contentItemFor("sidebar");
    assert.ok(fresh);
    await assert.rejects(
      opener.open({
        item: fresh,
        ciphertext: ciphertexts.sidebar,
        resolveKey: async () => SIBLING_KEY,
      }),
      { code: "decrypt_failed" },
    );
  });

  test("carried aad and nonce beside the record change nothing about the open", async () => {
    for (const aad of [
      undefined,
      "AAA=",
      "AA",
      "123456|1|bodytext",
      7,
      { a: 1 },
      "x\ud800",
      null,
      [],
      false,
    ]) {
      const { page, ciphertexts, opener } = await livePage();
      /** @type {any} */ (page.contentData[CONTENT_NAME]).aad = aad;
      /** @type {any} */ (page.contentData[CONTENT_NAME]).nonce = aad;
      const item = new DcaData(page).contentItemFor(CONTENT_NAME);
      assert.ok(item);
      const bytes = await opener.open({
        item,
        ciphertext: ciphertexts[CONTENT_NAME],
        resolveKey: async () => KEY,
      });
      assert.equal(utf8Decode(bytes), ARTICLE, `aad ${JSON.stringify(aad)}`);
    }
  });
});
