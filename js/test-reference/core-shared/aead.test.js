//
// core-shared/aead - AES-GCM, used for content, key wrapping and transport.

import { test, portableTest } from "../support/portable-test.js";
import assert from "node:assert/strict";

import { encrypt, decrypt, decryptToKey } from "../../core-shared/aead.js";
import { utf8Encode, utf8Decode } from "../../core-shared/codec.js";
import { exportRawKey, importAesGcmKey } from "../../core-shared/cryptoProvider.js";

/**
 * A local deterministic byte stream keeps this shared-only test replayable
 * without pulling the demo Random actor into the extracted test slice.
 *
 * @param {number} seed
 * @returns {{ bytes: (n: number) => Uint8Array }}
 */
function seededRandom(seed) {
  let state = seed | 0;
  return {
    bytes(n) {
      const out = new Uint8Array(n);
      for (let i = 0; i < n; i += 4) {
        state = (state + 0x9e3779b9) | 0;
        let word = state ^ (state >>> 16);
        word = Math.imul(word, 0x21f0aaad);
        word ^= word >>> 15;
        word = Math.imul(word, 0x735a2d97);
        word = (word ^ (word >>> 15)) >>> 0;
        out[i] = word & 0xff;
        if (i + 1 < n) out[i + 1] = (word >>> 8) & 0xff;
        if (i + 2 < n) out[i + 2] = (word >>> 16) & 0xff;
        if (i + 3 < n) out[i + 3] = (word >>> 24) & 0xff;
      }
      return out;
    },
  };
}

/**
 * One seed for the file, drawn again inside every test rather than once at
 * module scope: every test works from the same key and nonce, and no test's
 * bytes depend on how many draws the tests before it made.
 */
const SEED = 7;

/**
 * The key, the nonce and the stream they came from, all a test's own. The order
 * of the two draws fixes their bytes, so it is written once here.
 *
 * @param {number} seed
 */
function material(seed) {
  const random = seededRandom(seed);
  return { random, key: random.bytes(16), nonce: random.bytes(12) };
}

/** @param {any} error */
function authFailure(error) {
  return error instanceof DOMException && error.name === "OperationError";
}

/** @param {any} error */
function nonExtractableKeyFailure(error) {
  return (
    error instanceof DOMException &&
    ["InvalidAccessError", "InvalidAccessException"].includes(error.name)
  );
}
const portableCoreTest = portableTest("portable-core");
const portableCoreDynamicTest = portableTest("portable-core-dynamic");

/** An aad of no bytes, which a twin states where the direct case leaves the aad out. */
const EMPTY_AAD = new Uint8Array(0);

/** Stated key widths beside key lengths that disagree with them, as [stated, given]. */
const DISAGREEING_WIDTHS = [
  [16, 32],
  [16, 15],
  [16, 17],
  [32, 16],
  [32, 31],
];

/** Stated key widths no profile uses. */
const UNUSED_WIDTHS = [0, 8, 24, 31, 33, 64];

/**
 * Stated key widths that are not a number, which the width declares, so their
 * twin runs under portable-core-dynamic.
 */
const NOT_NUMBER_WIDTHS = ["16", null];

/** Authenticated plaintext widths that are not a 16-byte delivered key. */
const NOT_DELIVERED_KEY_WIDTHS = [15, 17, 24, 32];

portableCoreTest("aead round-trips a plaintext", async () => {
  const { key, nonce } = material(SEED);
  const plaintext = utf8Encode("the quick brown fox");

  const ciphertext = await encrypt(key, nonce, plaintext);
  const recovered = await decrypt(key, nonce, ciphertext);

  assert.equal(utf8Decode(recovered), "the quick brown fox");
});

portableCoreTest("aead appends a 16-byte auth tag", async () => {
  const { random, key, nonce } = material(SEED);

  const plaintext = random.bytes(48);
  const ciphertext = await encrypt(key, nonce, plaintext);
  assert.equal(ciphertext.length, plaintext.length + 16);
});

portableCoreTest("aead round-trips with aad", async () => {
  const { key, nonce } = material(SEED);
  const plaintext = utf8Encode("premium");
  const aad = utf8Encode("123456|1|bodytext");

  const ciphertext = await encrypt(key, nonce, plaintext, aad);
  const recovered = await decrypt(key, nonce, ciphertext, aad);

  assert.equal(utf8Decode(recovered), "premium");
});

test("aead rejects a flipped ciphertext byte", async () => {
  const { key, nonce } = material(SEED);

  const ciphertext = await encrypt(key, nonce, utf8Encode("the quick brown fox"));
  const tampered = Uint8Array.from(ciphertext);
  tampered[3] ^= 0x01;

  await assert.rejects(() => decrypt(key, nonce, tampered), authFailure);
});

test("aead rejects a flipped auth tag byte", async () => {
  const { key, nonce } = material(SEED);

  const ciphertext = await encrypt(key, nonce, utf8Encode("the quick brown fox"));
  const tampered = Uint8Array.from(ciphertext);
  tampered[tampered.length - 1] ^= 0x01;

  await assert.rejects(() => decrypt(key, nonce, tampered), authFailure);
});

test("aead rejects a changed aad", async () => {
  const { key, nonce } = material(SEED);
  const plaintext = utf8Encode("premium");
  const ciphertext = await encrypt(key, nonce, plaintext, utf8Encode("123456|1|bodytext"));

  await assert.rejects(
    () => decrypt(key, nonce, ciphertext, utf8Encode("123456|1|premiumtext")),
    authFailure,
  );
});

test("aead rejects the wrong nonce", async () => {
  const { random, key, nonce } = material(SEED);

  const ciphertext = await encrypt(key, nonce, utf8Encode("premium"));
  await assert.rejects(() => decrypt(key, random.bytes(12), ciphertext), authFailure);
});

portableCoreTest("aead refuses raw key bytes of the wrong length, as a coded error", async () => {
  const { random, nonce } = material(SEED);

  await assert.rejects(
    () => encrypt(random.bytes(32), nonce, utf8Encode("premium")),
    (/** @type {any} */ error) => error.code === "bad_key",
  );
  await assert.rejects(
    () => decrypt(random.bytes(31), nonce, utf8Encode("premium")),
    (/** @type {any} */ error) => error.code === "bad_key",
  );
});

portableCoreTest("aead refuses a nonce of the wrong length, as a coded error", async () => {
  const { random, key } = material(SEED);

  await assert.rejects(
    () => encrypt(key, random.bytes(16), utf8Encode("premium")),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
  await assert.rejects(
    () => decrypt(key, random.bytes(0), utf8Encode("premium")),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
});

test("aead takes a CryptoKey as well as raw bytes", async () => {
  const { key, nonce } = material(SEED);

  const handle = await importAesGcmKey(key, ["encrypt", "decrypt"]);

  const ciphertext = await encrypt(handle, nonce, utf8Encode("handle"));
  assert.equal(utf8Decode(await decrypt(key, nonce, ciphertext)), "handle");
});

test("aead decryptToKey opens a wrapped key into a usable handle", async () => {
  const { random, key: wrappingKey, nonce } = material(SEED);
  const contentKey = random.bytes(16);
  const articleNonce = random.bytes(12);

  // The publisher wraps a contentKey under the wrappingKey, and seals an
  // article under that same contentKey's bytes.
  const wrapped = await encrypt(wrappingKey, nonce, contentKey);
  const article = await encrypt(contentKey, articleNonce, utf8Encode("the body"));

  // The client opens the wrap to a handle it can never read, and the handle
  // decrypts the article all the same.
  const handle = await decryptToKey(wrappingKey, nonce, wrapped);
  const recovered = await decrypt(handle, articleNonce, article);

  assert.equal(utf8Decode(recovered), "the body");
});

test("aead decryptToKey refuses an authenticated wrap with a noncanonical nonce width", async () => {
  const { random, key: wrappingKey, nonce } = material(SEED);
  const contentKey = random.bytes(16);
  const aad = utf8Encode("content-key");
  const rawWrappingKey = await globalThis.crypto.subtle.importKey(
    "raw",
    wrappingKey,
    "AES-GCM",
    false,
    ["encrypt", "unwrapKey"],
  );
  const article = await encrypt(contentKey, nonce, utf8Encode("nonce-width control"));

  for (const width of [12, 16]) {
    const wrapNonce = random.bytes(width);
    // Stock GCM accepts this IV width, so refusal must come from the DCA
    // format guard rather than a bad tag or malformed wrapped key.
    const algorithm = { name: "AES-GCM", iv: wrapNonce, additionalData: aad, tagLength: 128 };
    const wrapped = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(algorithm, rawWrappingKey, contentKey),
    );
    const stockHandle = await globalThis.crypto.subtle.unwrapKey(
      "raw",
      wrapped,
      rawWrappingKey,
      algorithm,
      "AES-GCM",
      false,
      ["decrypt"],
    );
    assert.equal(utf8Decode(await decrypt(stockHandle, nonce, article)), "nonce-width control");
    if (width === 12) {
      const handle = await decryptToKey(wrappingKey, wrapNonce, wrapped, aad);
      assert.equal(utf8Decode(await decrypt(handle, nonce, article)), "nonce-width control");
    } else {
      await assert.rejects(
        () => decryptToKey(wrappingKey, wrapNonce, wrapped, aad),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
  }
});

test("aead decryptToKey handle can itself unwrap the next key in the chain", async () => {
  const { random, key: wrappingKey, nonce } = material(SEED);
  const middleKey = random.bytes(16);
  const middleNonce = random.bytes(12);
  const contentKey = random.bytes(16);
  const articleNonce = random.bytes(12);

  // A periodKey wraps a contentKey, which seals the article: the chain the
  // handle path exists to carry without any key landing in JavaScript.
  const wrappedMiddle = await encrypt(wrappingKey, nonce, middleKey);
  const wrappedContentKey = await encrypt(middleKey, middleNonce, contentKey);
  const article = await encrypt(contentKey, articleNonce, utf8Encode("chained"));

  // The middle handle is a periodKey: it has to unwrap the next hop, so it is
  // opened with `['unwrapKey']`. The last hop is a contentKey and only decrypts.
  const middleHandle = await decryptToKey(wrappingKey, nonce, wrappedMiddle, undefined, [
    "unwrapKey",
  ]);
  const contentKeyHandle = await decryptToKey(
    middleHandle,
    middleNonce,
    wrappedContentKey,
    undefined,
    ["decrypt"],
  );
  const recovered = await decrypt(contentKeyHandle, articleNonce, article);

  assert.equal(utf8Decode(recovered), "chained");
});

test("aead decryptToKey rejects a tampered wrap", async () => {
  const { random, key: wrappingKey, nonce } = material(SEED);
  const wrapped = await encrypt(wrappingKey, nonce, random.bytes(16));

  const flippedBody = Uint8Array.from(wrapped);
  flippedBody[3] ^= 0x01;
  await assert.rejects(() => decryptToKey(wrappingKey, nonce, flippedBody), authFailure);

  const flippedTag = Uint8Array.from(wrapped);
  flippedTag[flippedTag.length - 1] ^= 0x01;
  await assert.rejects(() => decryptToKey(wrappingKey, nonce, flippedTag), authFailure);
});

test("aead decryptToKey returns a non-extractable handle with exactly the usages asked for", async () => {
  const { random, key: wrappingKey, nonce } = material(SEED);
  const wrapped = await encrypt(wrappingKey, nonce, random.bytes(16));

  // Least privilege: the handle carries the intended usages and nothing more.
  // A contentKey decrypts; a periodKey only unwraps the next hop. Neither is
  // handed both; the caller-supplied set exists to prevent that over-grant.
  const contentKey = await decryptToKey(wrappingKey, nonce, wrapped, undefined, ["decrypt"]);
  assert.equal(contentKey.extractable, false);
  await assert.rejects(() => exportRawKey(contentKey), nonExtractableKeyFailure);
  assert.deepEqual([...contentKey.usages].sort(), ["decrypt"]);

  const periodKey = await decryptToKey(wrappingKey, nonce, wrapped, undefined, ["unwrapKey"]);
  assert.equal(periodKey.extractable, false);
  await assert.rejects(() => exportRawKey(periodKey), nonExtractableKeyFailure);
  assert.deepEqual([...periodKey.usages].sort(), ["unwrapKey"]);
});

test("a canonical 16-byte key wraps and opens a canonical 16-byte contentKey", async () => {
  const { random, nonce } = material(SEED);
  const periodKey = random.bytes(16);
  const contentKey = random.bytes(16);
  const articleNonce = random.bytes(12);
  const article = "the council voted 7-2 to rezone the harbour";

  const wrapped = await encrypt(periodKey, nonce, contentKey);
  assert.equal(wrapped.length, 32, "the 16-byte contentKey and its 16-byte tag");

  const recovered = await decrypt(periodKey, nonce, wrapped);
  assert.deepEqual(recovered, contentKey);

  const sealed = await encrypt(contentKey, articleNonce, utf8Encode(article));
  assert.equal(utf8Decode(await decrypt(recovered, articleNonce, sealed)), article);
});

test("a 16-byte wrap binds its associated data", async () => {
  const { random, nonce } = material(SEED);
  const periodKey = random.bytes(16);
  const contentKey = random.bytes(16);
  const aad = utf8Encode("dca-bind-key-envelope|p|r|premium|251023T1415");

  const wrapped = await encrypt(periodKey, nonce, contentKey, aad);
  assert.deepEqual(await decrypt(periodKey, nonce, wrapped, aad), contentKey);
  await assert.rejects(() => decrypt(periodKey, nonce, wrapped), authFailure);
  await assert.rejects(
    () =>
      decrypt(periodKey, nonce, wrapped, utf8Encode("dca-bind-key-envelope|p|r|sport|251023T1415")),
    authFailure,
  );
});

test("the stated width and the key it is given have to agree", async () => {
  const { random, nonce } = material(SEED);
  const plaintext = utf8Encode("premium");

  for (const [stated, given] of DISAGREEING_WIDTHS) {
    await assert.rejects(
      () => encrypt(random.bytes(given), nonce, plaintext, undefined, stated),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_key");
        assert.match(error.message, new RegExp(`${stated}-byte key, got ${given}`));
        return true;
      },
      `a ${given}-byte key stated as ${stated}`,
    );
    await assert.rejects(
      () => decrypt(random.bytes(given), nonce, plaintext, undefined, stated),
      (/** @type {any} */ error) => error.code === "bad_key",
    );
  }
});

// The portable twin of the case above. A width is stated after the aad, and
// `undefined` does not cross a reference API, so the twin states an empty aad.
// The width is refused before the aad is read.
portableCoreTest(
  "the stated width and the key it is given have to agree, under an empty aad",
  async () => {
    const { random, nonce } = material(SEED);
    const plaintext = utf8Encode("premium");

    for (const [stated, given] of DISAGREEING_WIDTHS) {
      await assert.rejects(
        () => encrypt(random.bytes(given), nonce, plaintext, EMPTY_AAD, stated),
        (/** @type {any} */ error) => {
          assert.equal(error.code, "bad_key");
          assert.match(error.message, new RegExp(`${stated}-byte key, got ${given}`));
          return true;
        },
        `a ${given}-byte key stated as ${stated}`,
      );
      await assert.rejects(
        () => decrypt(random.bytes(given), nonce, plaintext, EMPTY_AAD, stated),
        (/** @type {any} */ error) => error.code === "bad_key",
      );
    }
  },
);

test("a stated width no profile uses is refused rather than imported", async () => {
  const { random, nonce } = material(SEED);
  const plaintext = utf8Encode("premium");

  for (const stated of [...UNUSED_WIDTHS, ...NOT_NUMBER_WIDTHS]) {
    await assert.rejects(
      () => encrypt(random.bytes(32), nonce, plaintext, undefined, /** @type {any} */ (stated)),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_config");
        assert.match(error.message, /16 or 32 bytes/);
        return true;
      },
      `a stated width of ${JSON.stringify(stated)}`,
    );
  }
});

/**
 * Asserts that encrypt refuses each stated width under an empty aad.
 *
 * @param {unknown[]} widths
 */
async function refusesStatedWidths(widths) {
  const { random, nonce } = material(SEED);
  const plaintext = utf8Encode("premium");

  for (const stated of widths) {
    await assert.rejects(
      () => encrypt(random.bytes(32), nonce, plaintext, EMPTY_AAD, /** @type {any} */ (stated)),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_config");
        assert.match(error.message, /16 or 32 bytes/);
        return true;
      },
      `a stated width of ${JSON.stringify(stated)}`,
    );
  }
}

// The portable twins of the case above, under an empty aad for the same
// reason. The widths that are not a number run in the dynamic twin.
portableCoreTest(
  "a stated width no profile uses is refused rather than imported, under an empty aad",
  () => refusesStatedWidths(UNUSED_WIDTHS),
);

portableCoreDynamicTest(
  "a stated width that is not a number is refused rather than imported, under an empty aad",
  () => refusesStatedWidths(NOT_NUMBER_WIDTHS),
);

test("an AES-256 transport handle retains its own outer width while unwrapping a 16-byte key", async () => {
  const random = seededRandom(SEED);
  const transportBytes = random.bytes(32);
  const transported = random.bytes(16);
  const nonce = random.bytes(12);
  const handle = await importAesGcmKey(transportBytes, ["encrypt", "unwrapKey"]);
  const wrapped = await encrypt(handle, nonce, transported, undefined, 32);
  const opened = await decryptToKey(handle, nonce, wrapped, undefined, ["decrypt"], 32, 16);
  assert.equal(opened.algorithm.length, 128);
});

test("decryptToKey refuses an authenticated carrier whose raw key width differs from the stated output", async () => {
  const { random, key: wrappingKey, nonce } = material(SEED);

  for (const width of NOT_DELIVERED_KEY_WIDTHS) {
    // AES-GCM authenticates every one of these values. Width is a separate
    // v1 admission rule, so a valid tag cannot turn another AES key size
    // into a delivered capability.
    const wrapped = await encrypt(wrappingKey, nonce, random.bytes(width));
    await assert.rejects(
      () => decryptToKey(wrappingKey, nonce, wrapped, undefined, ["decrypt"]),
      (/** @type {any} */ error) =>
        error.code === "bad_key" && /wrapped key is 32 bytes/.test(error.message),
      `${width}-byte authenticated plaintext is not a 16-byte delivered key`,
    );
  }
});

// The portable twin of the case above, under an empty aad: the usages follow
// the aad, and `undefined` does not cross a reference API. The carrier width
// is refused before the aad is read or a key is returned.
portableCoreTest(
  "decryptToKey refuses an authenticated carrier whose raw key width differs from the stated output, under an empty aad",
  async () => {
    const { random, key: wrappingKey, nonce } = material(SEED);

    for (const width of NOT_DELIVERED_KEY_WIDTHS) {
      const wrapped = await encrypt(wrappingKey, nonce, random.bytes(width));
      await assert.rejects(
        () => decryptToKey(wrappingKey, nonce, wrapped, EMPTY_AAD, ["decrypt"]),
        (/** @type {any} */ error) =>
          error.code === "bad_key" && /wrapped key is 32 bytes/.test(error.message),
        `${width}-byte authenticated plaintext is not a 16-byte delivered key`,
      );
    }
  },
);

test("an omitted width never infers AES-256 from an opaque CryptoKey", async () => {
  const { random, nonce } = material(SEED);
  const transport = await importAesGcmKey(random.bytes(32), ["encrypt", "decrypt"]);

  await assert.rejects(
    () => encrypt(transport, nonce, random.bytes(16)),
    (/** @type {any} */ error) =>
      error.code === "bad_key" && /AES-128-GCM CryptoKey/.test(error.message),
  );
});

test("a CryptoKey is checked against the stated width where the runtime states its own", async () => {
  const { random, nonce } = material(SEED);
  const periodKey = random.bytes(16);
  const contentKey = random.bytes(16);
  const importKey = (bytes) => importAesGcmKey(bytes, ["encrypt", "decrypt"]);

  const aes128 = await importKey(periodKey);
  const aes256 = await importKey(random.bytes(32));

  const wrapped = await encrypt(aes128, nonce, contentKey, undefined, 16);
  assert.deepEqual(await decrypt(aes128, nonce, wrapped, undefined, 16), contentKey);

  for (const [handle, stated] of [
    [aes256, 16],
    [aes128, 32],
  ]) {
    await assert.rejects(
      () => encrypt(handle, nonce, contentKey, undefined, stated),
      (/** @type {any} */ error) => {
        assert.equal(error.code, "bad_key");
        assert.match(error.message, /GCM CryptoKey/);
        return true;
      },
    );
  }
});

test("decryptToKey under a 16-byte wrapping key answers a canonical AES-128-GCM handle", async () => {
  const { random, nonce } = material(SEED);
  const periodKey = random.bytes(16);
  const contentKey = random.bytes(16);
  const articleNonce = random.bytes(12);

  const wrapped = await encrypt(periodKey, nonce, contentKey);
  const article = await encrypt(contentKey, articleNonce, utf8Encode("the body"));

  const handle = await decryptToKey(periodKey, nonce, wrapped, undefined, ["decrypt"]);
  assert.equal(handle.extractable, false);
  assert.equal(/** @type {any} */ (handle.algorithm).length, 128);
  assert.equal(utf8Decode(await decrypt(handle, articleNonce, article)), "the body");
});
