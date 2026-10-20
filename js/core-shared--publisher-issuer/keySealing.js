// @ts-check
//
// Publisher to issuer. The publisher seals a key with the issuer's public key
// at render; the issuer unseals it at unlock. Nobody in between can read it,
// and the blob is self-contained; the wire carries no algorithm field,
// because the issuer knows its own key type.
//
// The publisher commits every seal to its coordinate. `bind.js` builds the
// value, `binding` is required in both directions, and the blobs travel through
// the reader's browser: a blob presented at a coordinate it was not sealed at
// does not open.
// The construction supports both carriers and the binding layout below.
// `unseal_failed` is fixed wire vocabulary for an envelope that cannot open;
// callers must not substitute an implementation-specific error code.
//
// Both algorithms carry the same binding value, each in the place where it
// costs nothing:
//
//   ECDH P-256   the AES-256-GCM `additionalData`. Not transmitted: the issuer
//                rebuilds it, and a wrong one fails the tag. It leaves the blob
//                layout unchanged, at the same 109 bytes.
//   RSA-OAEP     the first bytes of the OAEP plaintext, ahead of the key. The
//                ciphertext is one modulus wide whatever it carries, so a longer
//                plaintext costs nothing; OAEP is non-malleable, so the prefix
//                cannot be edited without the private key. No OAEP label: stock PHP
//                and .NET lack label support, so those issuers could not open
//                a labelled blob.
//
// The value is the same on both carriers, but the check differs: GCM verifies
// the binding while it decrypts, and RSA recovers a plaintext and compares it
// whole. The asymmetry is deliberate, and it keeps the ECDH path free.
//
// The value is always `bindValue`: BIND stays on the protocol path, and this
// core exposes no seam to swap it. A red team's alternate encodings - the naive
// delimiterless join, a v2 grammar a migration coexists across - are run in
// their own named sealings under `js/experiments/bind-on-renderId-and-slot/implementation/`, not
// behind a hook here.
//
// ECDH P-256 blob, fixed-size fields, no length prefixes:
//
//     0    65 bytes   ephemeral public key, uncompressed P-256 point
//     65   12 bytes   AES-256-GCM nonce
//     77   remaining  ciphertext and 16-byte tag
//
// For the canonical 16-byte payload that is 109 bytes, base64url to 146
// characters. `open` refuses any other length before the key agreement.
//
// RSA-OAEP blob: the RSA ciphertext and nothing else. spec--sealed-key-envelopes.md
// Section 5 is one sentence - "The binary envelope is one RSA ciphertext exactly
// as wide as the issuer modulus." The key is wrapped by OAEP directly,
// with the binding value ahead of it inside the one plaintext, so there is no
// ephemeral AES layer and no nonce to carry; the blob is exactly one modulus
// wide, 256 bytes at 2048 bits, base64url to the 342 characters the spec's size
// table budgets, whatever the plaintext holds.
//
// The two also differ in reproducibility. An ECDH seal is replayable once its
// ephemeral keypair and nonce source are injected, which is what makes a render
// byte-identical and a golden vector possible. OAEP draws its padding seed inside WebCrypto
// with nothing to inject, so an RSA render is not reproducible and an RSA
// vector can only pin an unseal, never a re-seal.
//
// A neighbouring module, the optional client-bound transport extension, covers
// the other direction: issuer to client, under client-bound transport. Both run
// the same operation in opposite directions: agree a key with a peer's public
// half and wrap under it, on the same AES-GCM primitive. They are separate
// modules so that a role carries only the direction it runs. They differ in
// their output.
// A sealed blob is opened to bytes, because the issuer has to hand something
// over; a client-bound wrap is opened to a `CryptoKey` handle, so the bytes
// never appear in the client's JavaScript.
//
// This code applies no KDF and offers no option for one.
// spec--sealed-key-envelopes.md Section 4 is explicit: the 32 x-coordinate
// octets "are used directly as the AES-256-GCM key" and a producer "MUST NOT
// apply a KDF." That is the one construction here. An earlier version also
// offered a second reading as a `kdf` option, and nothing on the wire said which
// reading a blob was built under: a publisher and an issuer that disagreed got
// a GCM tag failure with no way to tell it from a relabel. A
// KDF-based construction needs its own identified algorithm or profile, so a
// stated `kdf` is refused here at every spelling rather than accepted.

import { base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { encrypt, decrypt, NONCE_BYTES, TAG_BYTES } from "../core-shared/aead.js";
import { BIND_DELIMITER, bindFields } from "./bind.js";
import { dcaError } from "../core-shared/errors.js";
import {
  deriveAesGcmKey,
  exportRawKey,
  generateEcdhKeyPair,
  importRawEcdhPublicKey,
  rsaOaepDecrypt,
  rsaOaepEncrypt,
} from "../core-shared/cryptoProvider.js";

/** Uncompressed P-256 point: 0x04 and two 32-byte coordinates. */
const EPHEMERAL_BYTES = 65;

/** The data format fixes RSA-OAEP to SHA-256. */
const OAEP_HASH = "SHA-256";

/** What OAEP spends on padding: a hash length each for seed and label, plus 2. */
const OAEP_OVERHEAD = 2 * 32 + 2;

/**
 * The narrowest RSA modulus the sealed-key specification admits. It is stated in
 * bits because that is how the specification and a `CryptoKey` both state it.
 */
const RSA_MODULUS_BITS_FLOOR = 2048;

/**
 * The key width the RSA plaintext's boundary is read from. `BIND ‖ key` is a run
 * of bytes with nothing in it saying where the value stops, so the split has to
 * come from somewhere, and the format fixes these keys at 16 bytes.
 *
 * The compare depends on this width. Comparing only the first `BIND.length`
 * bytes accepts any blob whose value is a prefix of this one: a `premiumtext`
 * blob opens under a `premium` grant, the four extra characters sit in front of
 * a genuine key, and the issuer hands it over. So the value is recovered as everything
 * ahead of the last 16 bytes and compared whole. GCM needs none of this: the tag
 * commits the AAD's length along with its bytes.
 */
const SEALED_KEY_BYTES = 16;

/** 65 ephemeral point, 12 nonce, the payload, 16 tag. */
function ecdhEnvelopeBytes() {
  return EPHEMERAL_BYTES + NONCE_BYTES + SEALED_KEY_BYTES + TAG_BYTES;
}

/**
 * @typedef {import('./bind.js').Binding} Binding
 */

/**
 * @typedef {object} SealOptions
 * @property {Binding} [binding] - the coordinate this blob is bound to.
 *   Required in both directions: a call that quietly omitted it would produce a
 *   wire that looks right and opens for anyone who asks under any name.
 * @property {{ bytes: (n: number) => Uint8Array }} [random] - required to seal
 *   ECDH, which carries a nonce. RSA-OAEP needs none: OAEP randomises itself.
 *   In production it is a cryptographic random-bit generator, so each
 *   envelope gets a fresh nonce. A fixed or deterministic source reproduces a
 *   test vector and is not a conforming production source
 *   (docs/spec--sealed-key-envelopes.md).
 * @property {CryptoKeyPair} [ephemeralKeyPair] - injectable with `random` for a replayed run.
 *   WebCrypto has no seeded key generation, so this is the only way an ECDH
 *   seal repeats; left out, a fresh pair is generated per seal. A caller may
 *   supply a pair in production only if it is freshly generated for this one
 *   envelope; a reused or fixed pair is test-vector material, and with a
 *   repeated nonce it exposes the XOR of two sealed keys. Refused for
 *   RSA-OAEP, which has no ephemeral key and cannot be made to repeat.
 */

/**
 * The algorithm and binding one call runs under. Every canonical sealed-key
 * kind carries exactly one 16-byte key.
 *
 * @param {string} algorithm
 * @param {SealOptions} options
 * @returns {{ aad: Uint8Array }}
 */
function checkSupport(algorithm, options) {
  // docs/spec--sealed-key-envelopes.md §2; §4. These are the provisioning
  // tokens an issuer hands its publishers. The uppercase spellings are the
  // client-bound method names and the WebCrypto names, so no alias is taken.
  if (algorithm !== "ecdh-p256" && algorithm !== "rsa-oaep") {
    throw dcaError("unsupported_algorithm", `keySealing has no ${algorithm} yet`);
  }
  if (options.binding === undefined) {
    throw dcaError(
      "binding_failed",
      "a seal names the coordinate it is for, and this call names none",
    );
  }

  // Neither carrier derives anything, so a `kdf` member means nothing on
  // either and is refused ahead of the algorithm split. A caller that states it has
  // the wrong model of the construction, and silently ignoring it would hand
  // that caller a blob built the other way.
  if (/** @type {any} */ (options).kdf !== undefined) {
    throw dcaError(
      "unsupported_option",
      "keySealing applies no KDF: the ECDH carrier uses the agreed x-coordinate as the AES key, " +
        "and RSA-OAEP wraps the key",
    );
  }

  if (/** @type {any} */ (options).payloadBytes !== undefined) {
    throw dcaError("unsupported_option", "sealed-key payload width is fixed at 16 bytes");
  }
  const fields = bindFields(options.binding);
  const aad = utf8Encode(fields.join(BIND_DELIMITER));

  if (algorithm === "rsa-oaep" && options.ephemeralKeyPair !== undefined) {
    throw dcaError(
      "unsupported_option",
      "ephemeralKeyPair is ECDH only: OAEP draws its padding inside WebCrypto, " +
        "so an RSA seal cannot be made to repeat",
    );
  }
  return { aad };
}

/**
 * The blob width, and the three checks the key itself answers. An issuer
 * configured `rsa-oaep` against an EC key, against an RSA key hashing with
 * SHA-1, or against a modulus narrower than the specification admits, is a
 * configuration mistake worth a stated error; otherwise WebCrypto would either throw a
 * bare InvalidAccessError or quietly produce blobs no conforming issuer can
 * open.
 *
 * The floor is checked here rather than beside the OAEP capacity arithmetic
 * because a narrow modulus is wrong whatever it is asked to carry. The capacity
 * check refuses only a plaintext that does not fit, so a short enough binding
 * would otherwise seal under a 1024-bit key, and an unseal never consults
 * capacity at all.
 *
 * @param {CryptoKey} key
 * @returns {number} the modulus width in bytes, which is the exact blob size
 */
function rsaWidth(key) {
  // docs/spec--sealed-key-envelopes.md §5
  const algorithm = /** @type {RsaHashedKeyAlgorithm} */ (key.algorithm);

  if (algorithm.name !== "RSA-OAEP") {
    throw dcaError("bad_config", `RSA-OAEP needs an RSA-OAEP key, got ${algorithm.name}`);
  }
  if (algorithm.hash.name !== OAEP_HASH) {
    throw dcaError(
      "bad_config",
      `the data format fixes RSA-OAEP to ${OAEP_HASH}; this key hashes with ${algorithm.hash.name}`,
    );
  }
  if (algorithm.modulusLength < RSA_MODULUS_BITS_FLOOR) {
    throw dcaError(
      "bad_config",
      `a sealed-key modulus is at least ${RSA_MODULUS_BITS_FLOOR} bits, and this key is ` +
        `${algorithm.modulusLength}`,
    );
  }

  // RSA ciphertexts are the canonical modulus width in octets. A WebCrypto
  // modulus length is in bits and need not divide by eight (for example,
  // 2050 bits produces 257 octets), so truncation would reject the runtime's
  // own conforming ciphertext before OAEP gets to inspect it.
  return Math.ceil(algorithm.modulusLength / 8);
}

/**
 * The v1 payload must be a Uint8Array. WebCrypto also turns some array-like
 * values into bytes, but accepting a string or number here gives callers a
 * different key from the one they supplied, with no wire marker for it.
 *
 * @param {unknown} keyBytes
 * @returns {asserts keyBytes is Uint8Array}
 */
function checkSealedKeyBytes(keyBytes) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== SEALED_KEY_BYTES) {
    throw dcaError(
      "bad_key",
      `this envelope carries exactly ${SEALED_KEY_BYTES} Uint8Array octets, and this payload is ` +
        `${keyBytes instanceof Uint8Array ? keyBytes.length : typeof keyBytes}`,
    );
  }
}

/**
 * The ECDH counterpart to `rsaWidth`, run in both directions. It checks key
 * type and curve so that a misconfigured publisher or issuer gets a stated
 * error. `seal(key, issuerKey, 'ecdh-p256')` handed an RSA key, or an issuer
 * unsealing with an EC key on another curve, would otherwise fail with a bare
 * InvalidAccessError inside `agree`'s `deriveBits`, with nothing to say the
 * wrong key type was configured.
 *
 * @param {CryptoKey} key
 */
function checkEcdhKey(key) {
  const algorithm = key.algorithm;

  if (algorithm.name !== "ECDH") {
    throw dcaError("bad_config", `ECDH-P256 needs an ECDH key, got ${algorithm.name}`);
  }
  const namedCurve = /** @type {EcKeyAlgorithm} */ (algorithm).namedCurve;
  if (namedCurve !== "P-256") {
    throw dcaError(
      "bad_config",
      `the data format fixes ECDH to P-256; this key uses ${namedCurve}`,
    );
  }
}

/**
 * The check an unseal runs on the ECDH key its issuer configured, ahead of the
 * broad catch. A key that states which algorithm it is gets checked, and a
 * mismatch is that issuer's configuration fault. A value that states none is no
 * key at all: the caller's store held something other than a key, WebCrypto
 * refuses it inside the agreement, and the unseal fails the way it always has.
 *
 * @param {CryptoKey} key
 */
function checkConfiguredEcdhKey(key) {
  if (typeof (/** @type {any} */ (key)?.algorithm?.name) !== "string") return;
  checkEcdhKey(key);
}

/**
 * The width an unseal reads off the RSA key its issuer configured. A key that
 * states which algorithm it is goes through `rsaWidth`, so a type or hash the
 * format does not fix is that issuer's configuration fault. A value that states
 * none is no key at all, so this function skips the width check, as
 * `checkConfiguredEcdhKey` does: WebCrypto refuses the value inside the decrypt, and the unseal
 * fails the way it always has.
 *
 * @param {CryptoKey} key
 * @returns {number|null} the modulus width in bytes, or null where the value states no algorithm
 */
function configuredRsaWidth(key) {
  if (typeof (/** @type {any} */ (key)?.algorithm?.name) !== "string") return null;
  return rsaWidth(key);
}

/**
 * The wire's base64url as bytes, in the one spelling section 2.2 admits. A
 * value spelled any other way is a fact about the blob that arrived, so the
 * issuer answers it at the coordinate it arrived at. Every envelope algorithm
 * reaches the wire through here, so this is the one place the rule is applied.
 *
 * @param {string} blob
 * @returns {Uint8Array}
 */
function sealedBytes(blob) {
  // docs/spec--sealed-key-envelopes.md §2
  const bytes = binaryStringBytes(blob);
  if (bytes === null) {
    throw dcaError("unseal_failed", "sealed value is not base64url the wire could have carried");
  }
  return bytes;
}

/**
 * Byte equality that does not stop at the first difference. WebCrypto has no
 * comparison primitive, and the recovered value is compared against one the
 * caller rebuilt, so the loop compares every byte rather than running a `===`
 * over decoded strings.
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function sameBytes(a, b) {
  if (a.length !== b.length) return false;

  let differing = 0;
  for (let i = 0; i < a.length; i++) differing |= a[i] ^ b[i];
  return differing === 0;
}

/**
 * @param {Uint8Array} keyBytes
 * @param {CryptoKey} issuerPublicKey
 * @param {Uint8Array} aad - the binding value, UTF-8
 * @returns {Promise<string>}
 */
async function sealRsa(keyBytes, issuerPublicKey, aad) {
  const width = rsaWidth(issuerPublicKey);
  const capacity = width - OAEP_OVERHEAD;

  // The unseal reads the boundary off this width, so a blob that does not
  // have it cannot be checked, and a seal that quietly produced one would let
  // a blob open under a value that is only a prefix of its own binding.
  if (keyBytes.length !== SEALED_KEY_BYTES) {
    throw dcaError(
      "bad_config",
      `the RSA plaintext puts the binding ahead of a ${SEALED_KEY_BYTES}-byte key, and this key is ` +
        `${keyBytes.length}`,
    );
  }

  const plaintext = new Uint8Array(aad.length + keyBytes.length);
  plaintext.set(aad, 0);
  plaintext.set(keyBytes, aad.length);

  // A binding and a key that do not fit call for the hybrid RSA-KEM, which is
  // a wire change rather than something to squeeze in here.
  if (plaintext.length > capacity) {
    // docs/spec--sealed-key-envelopes.md §5
    throw dcaError(
      "bad_config",
      `RSA-OAEP over ${width * 8} bits carries ${capacity} bytes at most, and the binding with the key is ` +
        `${plaintext.length}`,
    );
  }

  return base64urlEncode(await rsaOaepEncrypt(issuerPublicKey, plaintext));
}

/**
 * @param {string} blob
 * @param {CryptoKey} issuerPrivateKey
 * @param {Uint8Array} aad
 * @returns {Promise<Uint8Array>}
 */
async function unsealRsa(blob, issuerPrivateKey, aad) {
  // docs/spec--sealed-key-envelopes.md §5
  const width = configuredRsaWidth(issuerPrivateKey);
  const bytes = sealedBytes(blob);

  // RSA takes exactly one modulus of ciphertext. Checking here is what turns
  // a 109-octet ECDH envelope routed to an RSA issuer into a stated failure
  // instead of a bare OperationError from inside WebCrypto.
  if (width !== null && bytes.length !== width) {
    throw dcaError(
      "unseal_failed",
      `sealed blob is ${bytes.length} bytes, not the ${width} this modulus takes`,
    );
  }

  let plaintext;
  try {
    plaintext = new Uint8Array(await rsaOaepDecrypt(issuerPrivateKey, bytes));
  } catch {
    // A wrong private key and a flipped byte are one padding failure, the
    // same way the ECDH side has one tag failure.
    throw dcaError("unseal_failed", "RSA-OAEP unseal failed: OAEP padding check");
  }

  // On this carrier the binding is checked after the unseal, and that check is
  // the whole of the relabel defence here: a blob sealed for another coordinate
  // recovers fine and carries another value in front of its key.
  //
  // The recovered value is everything ahead of the key, and it is compared
  // whole. A compare over the first `aad.length` bytes instead would be a
  // prefix test, and a prefix test opens `premiumtext`'s blob for `premium`.
  if (
    plaintext.length !== aad.length + SEALED_KEY_BYTES ||
    !sameBytes(plaintext.subarray(0, plaintext.length - SEALED_KEY_BYTES), aad)
  ) {
    throw dcaError(
      "unseal_failed",
      "RSA-OAEP unseal failed: the plaintext is not bound to this coordinate",
    );
  }

  return plaintext.subarray(aad.length);
}

/**
 * The AES-256 key both sides arrive at from one ECDH agreement.
 *
 * `deriveBits` rather than `deriveKey`, because the agreed bytes are the key
 * themselves and nothing is derived from them. For P-256 those 32 bytes are the
 * shared point's x-coordinate, which is exactly what the spec calls the raw
 * shared secret.
 *
 * @param {CryptoKey} publicKey - the other side's ECDH public key
 * @param {CryptoKey} privateKey
 * @returns {Promise<CryptoKey>}
 */
async function agree(publicKey, privateKey) {
  // docs/spec--sealed-key-envelopes.md §4
  return deriveAesGcmKey(publicKey, privateKey);
}

/**
 * @param {Uint8Array} keyBytes - the canonical 16-byte DCA capability the issuer gets back
 * @param {CryptoKey} issuerPublicKey
 * @param {string} algorithm - the provisioning token, 'ecdh-p256' or 'rsa-oaep'
 * @param {SealOptions} options
 * @returns {Promise<string>} the base64url blob, as it appears on the wire
 */
export async function seal(keyBytes, issuerPublicKey, algorithm, options = {}) {
  const { aad } = checkSupport(algorithm, options);
  checkSealedKeyBytes(keyBytes);

  if (algorithm === "rsa-oaep") {
    return sealRsa(keyBytes, issuerPublicKey, aad);
  }

  checkEcdhKey(issuerPublicKey);

  // ECDH needs an injected nonce source. RSA returned above without using one.
  if (!options.random) {
    throw dcaError("missing_random", "keySealing.seal needs a Random for the blob nonce");
  }

  // docs/spec--sealed-key-envelopes.md §4
  const ephemeral = options.ephemeralKeyPair ?? (await generateEcdhKeyPair());

  const ephemeralPublic = new Uint8Array(await exportRawKey(ephemeral.publicKey));
  const nonce = options.random.bytes(NONCE_BYTES);

  const wrappingKey = await agree(issuerPublicKey, ephemeral.privateKey);
  // docs/spec--sealed-key-envelopes.md §4
  const ciphertext = await encrypt(wrappingKey, nonce, keyBytes, aad, 32);

  const blob = new Uint8Array(ephemeralPublic.length + nonce.length + ciphertext.length);
  blob.set(ephemeralPublic, 0);
  blob.set(nonce, ephemeralPublic.length);
  blob.set(ciphertext, ephemeralPublic.length + nonce.length);

  return base64urlEncode(blob);
}

/**
 * @param {string} blob - the base64url string from the wire
 * @param {CryptoKey} issuerPrivateKey
 * @param {string} algorithm - the provisioning token, 'ecdh-p256' or 'rsa-oaep'
 * @param {SealOptions} options
 * @returns {Promise<Uint8Array>}
 */
export async function open(blob, issuerPrivateKey, algorithm, options = {}) {
  const { aad } = checkSupport(algorithm, options);

  if (algorithm === "rsa-oaep") {
    return unsealRsa(blob, issuerPrivateKey, aad);
  }

  // The issuer's own key, ahead of anything the blob says. `rsaWidth` runs
  // this check on the other carrier already; here it runs before the
  // catch below, so an issuer holding an RSA key or a P-384 key where it
  // configured ecdh-p256 reads its own misconfiguration instead of a
  // coordinate its readers are told is unopenable.
  checkConfiguredEcdhKey(issuerPrivateKey);

  const bytes = sealedBytes(blob);
  if (bytes.length < EPHEMERAL_BYTES + NONCE_BYTES + TAG_BYTES) {
    throw dcaError("unseal_failed", `sealed blob too short: ${bytes.length} bytes`);
  }

  // On this carrier the envelope length fixes the ciphertext length, so the
  // canonical payload width is checked here, before the issuer's private key
  // touches an attacker-shaped blob. An envelope carrying a retired or other
  // width therefore never reaches a key agreement, and a truncated one fails
  // the same check rather than the tag.
  const envelopeBytes = ecdhEnvelopeBytes();
  // docs/spec--sealed-key-envelopes.md §4
  if (bytes.length !== envelopeBytes) {
    throw dcaError(
      "unseal_failed",
      `a sealed envelope carrying ${SEALED_KEY_BYTES} bytes is exactly ${envelopeBytes} bytes, and this one is ` +
        `${bytes.length}`,
    );
  }

  const ephemeralPublic = bytes.subarray(0, EPHEMERAL_BYTES);
  // The envelope format admits only SEC 1 uncompressed P-256 points. Check
  // its marker before importing or using the issuer's private key; some crypto
  // providers also accept hybrid encodings for the same point.
  if (ephemeralPublic[0] !== 0x04) {
    throw dcaError("unseal_failed", "ECDH ephemeral key is not an uncompressed P-256 point");
  }
  const nonce = bytes.subarray(EPHEMERAL_BYTES, EPHEMERAL_BYTES + NONCE_BYTES);
  const ciphertext = bytes.subarray(EPHEMERAL_BYTES + NONCE_BYTES);

  let opened;
  try {
    // docs/spec--sealed-key-envelopes.md §4
    const publicKey = await importRawEcdhPublicKey(ephemeralPublic);
    const wrappingKey = await agree(publicKey, issuerPrivateKey);
    // docs/spec--sealed-key-envelopes.md §4
    opened = await decrypt(wrappingKey, nonce, ciphertext, aad, 32);
  } catch {
    // docs/spec--sealed-key-envelopes.md §6
    // A wrong private key, a blob presented at another coordinate, one from
    // another render and a flipped byte all end here as one tag failure.
    // Neither the issuer nor this code can tell them apart: a binding
    // failure deliberately has no more specific observable cause.
    throw dcaError("unseal_failed", "ECDH unseal failed: AES-GCM auth tag mismatch");
  }

  // The sealed-key specification states the envelope width and the recovered
  // payload width as two requirements, so both are checked. On this carrier
  // the second has no reachable input, because the envelope length above
  // already fixed the ciphertext length; a carrier whose layout does not pin
  // the payload must not slip past on the length check alone.
  if (opened.length !== SEALED_KEY_BYTES) {
    throw dcaError(
      "unseal_failed",
      `a sealed envelope carries exactly ${SEALED_KEY_BYTES} bytes, and this one carried ${opened.length}`,
    );
  }
  return opened;
}
