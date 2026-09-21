//
// What the transport key has to keep doing across page loads. A client stores
// wrapped periodKeys and no key handle, since handles do not survive a load, so
// everything it kept is unreadable unless the same agreement lands on the same
// AES key every time it is run.
//
// The claim is tested through the profile's response-scoped surface, the level
// it sits at: `seal` at the issuer end and `open` at the client's, with nothing
// cached between the calls. The controls sit beside it, a different client
// keypair and a peer public key from another response, so a run that passed
// because every derivation produces a working key would be visible, and each
// control is followed by the honest pair opening the same blob.
//
// One runtime limit gives these functions their shape: WebCrypto will not take
// `{name:"ECDH"}` as an unwrap algorithm, so a shared secret has to become an
// AES key before it can unwrap anything. webcrypto-environment.test.js pins it.
//
// Every test that draws bytes takes a seeded byte stream of its own, from a seed of its
// own. One at module scope would make each test's nonces depend on how many
// draws the tests above it had made, so moving or skipping one would change its
// neighbours' bytes and a failing run could not be replayed on its own.
//
// Nothing here stands up a world: these tests sit underneath the actors, at the
// transport functions themselves, so `demo/scenarios/` has nothing they need.
//
// These cases pin the storage and caching determinism claim.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { seal, open } from "../ecdhP256.js";
import { encrypt, decrypt, decryptToKey, NONCE_BYTES } from "../../../core-shared/aead.js";
import { base64urlEncode, base64urlDecode, utf8Encode } from "../../../core-shared/codec.js";
import { seededRandom } from "../../../test-reference/support/keys.js";

const { subtle } = globalThis.crypto;

/**
 * An ECDH pair for one end of the transport agreement, with the `deriveKey`
 * usage the client-bound profile takes. Local rather than `test-reference/support/keys.js`'s
 * `issuerKeypair`, which is the same generateKey call under a name that says
 * issuer: the pairs here are a client's and a per-response ephemeral, and
 * neither is the issuer's static seal key.
 *
 * @returns {Promise<CryptoKeyPair>}
 */
function ecdhPair() {
  return /** @type {Promise<CryptoKeyPair>} */ (
    subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
  );
}

describe("The transport key is deterministic", () => {
  // A client stores no ephemeral public key and re-derives the transport key on
  // each page load. docs/spec--response-binding.md Section 7.2 fixes that
  // derivation, one HKDF-SHA-256 over the ECDH shared x-coordinate under a fixed
  // info string, and Section 9 lets a client keep a wrapped leaf plus enough
  // transport context to reopen it with the same client private key. A client
  // that stores wrapped periodKeys and re-derives the key that opens them is
  // betting on exactly that. The demo's issuer end is ephemeral per response, so
  // what a load re-derives against is the transportPublicKey the response
  // carried; the claim under test is that the same client private key against
  // the same peer public key lands on the same AES key, call after call, with
  // nothing cached between.

  /**
   * One client keypair and its wire form, which is what a request carries.
   *
   * @returns {Promise<{ privateKey: CryptoKey, publicKeyJwk: JsonWebKey }>}
   */
  async function clientKeys() {
    const pair = await ecdhPair();
    return {
      privateKey: pair.privateKey,
      publicKeyJwk: await subtle.exportKey("jwk", pair.publicKey),
    };
  }

  test("a transport key re-derived on a fresh page load still unwraps the earlier load's ciphertexts", async () => {
    const random = seededRandom(44);
    const { privateKey, publicKeyJwk } = await clientKeys();

    // Load one. The issuer seals for this client and wraps a periodKey; the
    // client opens its end and reads the answer.
    const sealer = await seal(publicKeyJwk, { random });
    const periodKeyBytes = random.bytes(16);
    const wrapped = await sealer.wrap(periodKeyBytes);

    const firstLoad = await open(sealer.transport, privateKey);
    const handleOne = await firstLoad.open(wrapped, ["decrypt"]);

    // What survives the load: the wrapped value and the transport it names.
    // No key handle and no shared secret.
    const stored = { wrapped, transport: sealer.transport };

    // Load two. A new open call, nothing carried over from the first, and
    // the same stored value opens.
    const secondLoad = await open(stored.transport, privateKey);
    assert.notEqual(secondLoad, firstLoad, "a genuinely new opener, not the one from before");
    // This test compares two non-extractable periodKey handles by decrypting
    // one article with each, and then carries the chain on by unwrapping a
    // contentKey with this same handle - so it is opened with both usages.
    const handleTwo = await secondLoad.open(stored.wrapped, ["decrypt", "unwrapKey"]);

    // The two handles are the same key, shown the only way non-extractable
    // handles can be compared: one ciphertext, sealed under the bytes the
    // issuer wrapped, and both handles open it.
    const article = new Uint8Array([7, 7, 7, 7]);
    const nonce = random.bytes(NONCE_BYTES);
    const sealed = await encrypt(periodKeyBytes, nonce, article);
    assert.deepEqual(
      await decrypt(handleOne, nonce, sealed),
      article,
      "the first load reached the key",
    );
    assert.deepEqual(
      await decrypt(handleTwo, nonce, sealed),
      article,
      "and so did the re-derivation",
    );

    // And the chain carries on past the re-derivation: the periodKey handle
    // from load two unwraps a contentKey the way the client's does: it runs the
    // same `aead.decryptToKey` the cached trial uses, with the handle as the
    // unwrapping key.
    const contentKeyBytes = random.bytes(16);
    const contentNonce = random.bytes(NONCE_BYTES);
    const sealedContentKey = base64urlEncode(
      await encrypt(periodKeyBytes, contentNonce, contentKeyBytes),
    );
    const contentKey = await decryptToKey(
      handleTwo,
      contentNonce,
      base64urlDecode(sealedContentKey),
      undefined,
      ["decrypt"],
    );

    const body = new Uint8Array([1, 1, 2, 3, 5]);
    const bodyNonce = random.bytes(NONCE_BYTES);
    assert.deepEqual(
      await decrypt(contentKey, bodyNonce, await encrypt(contentKeyBytes, bodyNonce, body)),
      body,
      "a fresh load reached the article through two unwraps",
    );
  });

  test("a transport key re-derives from the issuer's stored ephemeral pair too, and the JWK repeats", async () => {
    const random = seededRandom(45);
    const { privateKey, publicKeyJwk } = await clientKeys();
    const ephemeralKeyPair = await ecdhPair();

    // The other end of the same claim: an issuer holding the pair it answered
    // with lands on the same transport key when it seals again. That is what
    // makes a replayed client-bound response reproducible at all.
    const first = await seal(publicKeyJwk, { random, ephemeralKeyPair });
    const second = await seal(publicKeyJwk, { random, ephemeralKeyPair });

    assert.deepEqual(second.transport, first.transport, "the same peer public key on the wire");

    // A value wrapped by each re-sealed sealer opens under the one client
    // opener: both seals landed on the same transport key, or the second's
    // blob would not open against the first's transport public key.
    const keyBytes = random.bytes(16);
    const wrappedByFirst = await first.wrap(keyBytes);
    const wrappedBySecond = await second.wrap(keyBytes);

    const opener = await open(first.transport, privateKey);
    const handleFirst = await opener.open(wrappedByFirst, ["decrypt"]);
    const handleSecond = await opener.open(wrappedBySecond, ["decrypt"]);

    const message = new Uint8Array([4, 2]);
    const messageNonce = random.bytes(NONCE_BYTES);
    const sealed = await encrypt(keyBytes, messageNonce, message);
    assert.deepEqual(await decrypt(handleFirst, messageNonce, sealed), message);
    assert.deepEqual(
      await decrypt(handleSecond, messageNonce, sealed),
      message,
      "the re-sealed pair landed on the same key",
    );
  });

  test("a different client keypair re-derives a different transport key, and the stored ciphertext stays shut", async () => {
    const random = seededRandom(46);

    // The control that gives the determinism test its meaning: if every
    // derivation produced a working key, "deterministic" would be unfalsifiable
    // here. The input that has to match is the client private key.
    const first = await clientKeys();
    const sealer = await seal(first.publicKeyJwk, { random });
    const wrapped = await sealer.wrap(random.bytes(16));

    const other = await clientKeys();
    const wrongOpener = await open(sealer.transport, other.privateKey);
    await assert.rejects(
      () => wrongOpener.open(wrapped, ["decrypt"]),
      (/** @type {any} */ err) => err.code === "unwrap_failed",
    );

    // A peer public key from another response is the same failure: both halves
    // of the agreement are inputs, and neither is optional.
    const otherSealer = await seal(first.publicKeyJwk, { random });
    const wrongPeerOpener = await open(otherSealer.transport, first.privateKey);
    await assert.rejects(
      () => wrongPeerOpener.open(wrapped, ["decrypt"]),
      (/** @type {any} */ err) => err.code === "unwrap_failed",
    );

    // And the honest pair still opens it, so the two refusals above are about
    // the inputs and not about the ciphertext having been damaged.
    const rightOpener = await open(sealer.transport, first.privateKey);
    const handle = await rightOpener.open(wrapped, ["decrypt"]);
    assert.equal(handle.algorithm.name, "AES-GCM");
  });
});

describe("The open form is the client's call at open time", () => {
  // The profile opens a wrapped periodKey to a non-extractable handle, so the
  // bytes never land in the client's JavaScript. Nothing in the wire form makes
  // that the only reading: the same wrapped value the issuer sent opens to raw
  // bytes just as well, under the very transport key the handle form uses. Which
  // form a client keeps is its own decision, taken when it opens the value, and
  // the issuer neither sees it nor constrains it. The bytes form has a cost the
  // handle form does not: the recovered key is copyable, where the byte-free
  // transport form leaves nothing to copy. This test holds both against one
  // transport key.
  //
  // Holding the transport key here means agreeing it the way the client's `open`
  // does, so this mirrors the ECDH-P256 opener's transportKeyFor: ECDH-P256 to
  // the shared secret, then HKDF-SHA256 over it under this info string to the
  // AES-GCM key. The profile keeps that key to itself, so a client that wants
  // the bytes form agrees it for itself; the equivalence check below fails
  // loudly if this mirror ever drifts from the module.
  const CLIENT_TRANSPORT_INFO = "DCA-client-bound-transport";

  /**
   * The AES-GCM transport key the client agrees, held directly so both open
   * forms run off the one non-extractable handle. Non-extractable like the
   * profile's own, and carrying both usages the two forms need: `decrypt` for
   * the bytes form, `unwrapKey` for the handle form.
   *
   * @param {JsonWebKey} transportPublicKey - the ephemeral public key the response carried
   * @param {CryptoKey} clientPrivateKey
   * @returns {Promise<CryptoKey>}
   */
  async function clientTransportKey(transportPublicKey, clientPrivateKey) {
    const peer = await subtle.importKey(
      "jwk",
      transportPublicKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const material = await subtle.deriveKey(
      { name: "ECDH", public: peer },
      clientPrivateKey,
      "HKDF",
      false,
      ["deriveKey"],
    );
    return subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: utf8Encode(CLIENT_TRANSPORT_INFO),
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt", "unwrapKey"],
    );
  }

  test("the same wrapped periodKey opens to copyable bytes or a sealed handle, and the choice is the client's", async () => {
    const random = seededRandom(47);
    const clientPair = await ecdhPair();
    const publicKeyJwk = await subtle.exportKey("jwk", clientPair.publicKey);
    const ephemeralKeyPair = await ecdhPair();

    // The issuer seals for this client and wraps a periodKey, exactly as the
    // determinism tests above do.
    const sealer = await seal(publicKeyJwk, { random, ephemeralKeyPair });
    const periodKeyBytes = random.bytes(16);
    const wrapped = await sealer.wrap(periodKeyBytes);

    // One transport key, agreed once, non-extractable.
    const transportKey = await clientTransportKey(
      sealer.transport.publicKey,
      clientPair.privateKey,
    );
    const nonce = base64urlDecode(wrapped.nonce);
    const blob = base64urlDecode(wrapped.key);

    // Bytes form. `aead.decrypt` opens the wrapped value to raw periodKey
    // bytes, and those bytes re-import as an extractable AES-GCM key that
    // exports right back to itself, the copyable cost of the bytes form.
    const recovered = await decrypt(transportKey, nonce, blob, undefined, 32);
    assert.deepEqual(recovered, periodKeyBytes, "the bytes form recovered the wrapped periodKey");
    const copyable = await subtle.importKey("raw", recovered, "AES-GCM", true, ["decrypt"]);
    assert.equal(copyable.extractable, true, "the recovered bytes re-import extractable");
    assert.deepEqual(
      new Uint8Array(await subtle.exportKey("raw", copyable)),
      periodKeyBytes,
      "and export straight back out - a copyable key",
    );

    // Handle form. `aead.decryptToKey`, which is what the profile's `open`
    // runs, opens the same value off the same transport key to a
    // non-extractable handle: no bytes, and `exportKey` refuses.
    const handle = await decryptToKey(transportKey, nonce, blob, undefined, ["unwrapKey"], 32, 16);
    assert.equal(handle.extractable, false, "the handle form keeps the key unreadable");
    await assert.rejects(
      () => subtle.exportKey("raw", handle),
      "a non-extractable handle does not export",
    );

    // Equivalence. Both forms carry the same periodKey, so both carry the
    // chain on. A contentKey sealed under the periodKey bytes: the bytes form
    // decrypts it to bytes, the handle form unwraps it to a handle, and both
    // open the same article. The two forms differ only in what the client
    // asked for at open time.
    const contentKeyBytes = random.bytes(16);
    const contentNonce = random.bytes(NONCE_BYTES);
    const wrappedContentKey = await encrypt(periodKeyBytes, contentNonce, contentKeyBytes);

    const contentKeyFromBytes = await decrypt(recovered, contentNonce, wrappedContentKey);
    assert.deepEqual(
      contentKeyFromBytes,
      contentKeyBytes,
      "the bytes form unwrapped the contentKey to bytes",
    );
    const contentKeyFromHandle = await decryptToKey(
      handle,
      contentNonce,
      wrappedContentKey,
      undefined,
      ["decrypt"],
    );

    const article = new Uint8Array([1, 1, 2, 3, 5]);
    const articleNonce = random.bytes(NONCE_BYTES);
    const sealedArticle = await encrypt(contentKeyBytes, articleNonce, article);
    assert.deepEqual(
      await decrypt(contentKeyFromBytes, articleNonce, sealedArticle),
      article,
      "the bytes form reached the article",
    );
    assert.deepEqual(
      await decrypt(contentKeyFromHandle, articleNonce, sealedArticle),
      article,
      "and the handle form reached the same article",
    );
  });
});
