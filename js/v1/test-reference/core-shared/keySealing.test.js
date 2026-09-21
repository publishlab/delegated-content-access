//
// core-shared/keySealing - publisher to issuer, ECDH P-256 and RSA-OAEP.
// The ECDH carrier has one construction, the agreed x-coordinate used as the
// AES key, so there is no derivation setting to run these bodies twice under.
//
// Every call names a coordinate, because the seal takes one in both directions.
// bind.test.js runs what the binding stops and what it costs; here it is one
// coordinate throughout, so anything that fails is the algorithm and not the
// binding.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { seal, open } from "../../core-shared--publisher-issuer/keySealing.js";
import { RENDER_ID_BYTES, bindValue } from "../../core-shared--publisher-issuer/bind.js";
import { base64urlDecode, base64urlEncode } from "../../core-shared/codec.js";
import { DcaError } from "../../core-shared/errors.js";
import { MAX_NAME_LENGTH } from "../../core-shared/names.js";
import { generateEcdhKeyPair } from "../../core-shared/cryptoProvider.js";
import { issuerKeypair, seededRandom } from "../support/keys.js";

/**
 * One refusal, asserted on the code rather than the message. The port maps a
 * status from the code, so a test matching only the wording would pass while
 * the status went wrong; and a rejection that is not a `DcaError` at all is a
 * bug in the code under test wearing the shape of an expected refusal.
 *
 * @param {() => unknown} run - called here, and either throwing or rejecting is
 *   the refusal
 * @param {string|{ code: string, message?: RegExp }} expected - the code, or the
 *   code beside what the message has to say
 * @param {string} why - what this refusal is being asked to show, repeated into
 *   every failure message so a red line names the claim and not just the code
 * @returns {Promise<void>}
 */
async function refuses(run, expected, why) {
  const { code, message } =
    typeof expected === "string" ? { code: expected, message: undefined } : expected;

  await assert.rejects(
    async () => run(),
    (error) => {
      assert.ok(error instanceof DcaError, `${why}: expected a DcaError, got ${error}`);
      assert.equal(/** @type {DcaError} */ (error).code, code, why);
      if (message !== undefined) {
        assert.match(/** @type {DcaError} */ (error).message, message, why);
      }
      return true;
    },
  );
}

/**
 * One seed for the file, drawn again inside every test rather than once at
 * module scope: the key bytes come out the same, and no test's stream depends
 * on how many draws the tests before it made.
 */
const SEED = 11;

/**
 * One render's one contentKey, which is the coordinate every call below uses.
 * Local to this file rather than a demo/scenarios/ fixture: nothing outside a seal
 * names a coordinate this way, and the point of it here is that it never varies.
 */
const BINDING = {
  renderId: base64urlEncode(new Uint8Array(RENDER_ID_BYTES).fill(0x5a)),
  contentName: "bodytext",
};

test("keySealing round-trips a contentKey over the spec's raw shared secret", async () => {
  const random = seededRandom(SEED);
  const { publicKey, privateKey } = await issuerKeypair();
  const keyBytes = random.bytes(16);

  const blob = await seal(keyBytes, publicKey, "ECDH-P256", { random, binding: BINDING });
  const recovered = await open(blob, privateKey, "ECDH-P256", { binding: BINDING });

  assert.deepEqual(recovered, keyBytes);
});

test("a kdf option is refused rather than sealed under a second construction", async () => {
  // One construction. The ECDH carrier uses the agreed x-coordinate as the
  // AES-256-GCM key and applies no KDF, and RSA-OAEP wraps the key and derives
  // nothing, so `kdf` names nothing either carrier does. Ignoring the member
  // would hand a caller who believes it asked for a derivation a blob built
  // the other way, with nothing on the wire to say which it got.
  const random = seededRandom(SEED);
  const { publicKey, privateKey } = await issuerKeypair();

  for (const kdf of ["none", "hkdf", "x25519"]) {
    await refuses(
      () => seal(random.bytes(16), publicKey, "ECDH-P256", { kdf, random, binding: BINDING }),
      "unsupported_option",
      `a seal stating kdf ${JSON.stringify(kdf)} is refused`,
    );
    await refuses(
      () => open("x", privateKey, "ECDH-P256", { kdf, binding: BINDING }),
      "unsupported_option",
      `and an unseal stating kdf ${JSON.stringify(kdf)} is refused`,
    );
  }
});

test("the ECDH blob is ephemeral public key, nonce, ciphertext and tag", async () => {
  const random = seededRandom(SEED);
  const { publicKey } = await issuerKeypair();

  const blob = await seal(random.bytes(16), publicKey, "ECDH-P256", { random, binding: BINDING });
  const bytes = base64urlDecode(blob);

  assert.equal(bytes.length, 65 + 12 + 16 + 16, "the spec's 109-byte blob");
  assert.equal(bytes[0], 0x04, "uncompressed P-256 point");
});

test("a fresh ephemeral keypair per seal makes two seals of one key differ", async () => {
  const random = seededRandom(SEED);
  const { publicKey } = await issuerKeypair();
  const keyBytes = random.bytes(16);

  const first = await seal(keyBytes, publicKey, "ECDH-P256", { random, binding: BINDING });
  const second = await seal(keyBytes, publicKey, "ECDH-P256", { random, binding: BINDING });

  assert.notEqual(first, second);
});

test("an injected ephemeral keypair makes a seal replayable", async () => {
  // WebCrypto has no seeded key generation, so this is the only way an ECDH
  // seal repeats byte for byte - which a recorded run needs.
  const { publicKey, privateKey } = await issuerKeypair();
  // An ephemeral pair, not an issuer's: the same P-256 shape, a different
  // role, so it is generated here rather than asked of `issuerKeypair()`.
  const ephemeralKeyPair = await generateEcdhKeyPair();
  const keyBytes = seededRandom(3).bytes(16);

  const first = await seal(keyBytes, publicKey, "ECDH-P256", {
    random: seededRandom(3),
    ephemeralKeyPair,
    binding: BINDING,
  });
  const second = await seal(keyBytes, publicKey, "ECDH-P256", {
    random: seededRandom(3),
    ephemeralKeyPair,
    binding: BINDING,
  });

  assert.equal(first, second);
  assert.deepEqual(await open(first, privateKey, "ECDH-P256", { binding: BINDING }), keyBytes);
});

test("another issuer's private key does not unseal the blob", async () => {
  const random = seededRandom(SEED);
  const mine = await issuerKeypair();
  const theirs = await issuerKeypair();

  const blob = await seal(random.bytes(16), mine.publicKey, "ECDH-P256", {
    random,
    binding: BINDING,
  });

  await assert.rejects(
    () => open(blob, theirs.privateKey, "ECDH-P256", { binding: BINDING }),
    /unseal failed/i,
  );
});

test("a tampered blob fails the GCM tag", async () => {
  const random = seededRandom(SEED);
  const { publicKey, privateKey } = await issuerKeypair();
  const blob = await seal(random.bytes(16), publicKey, "ECDH-P256", { random, binding: BINDING });

  const bytes = base64urlDecode(blob);
  bytes[100] ^= 0x01;

  await assert.rejects(
    () => open(base64urlEncode(bytes), privateKey, "ECDH-P256", { binding: BINDING }),
    /unseal failed/i,
  );
});

test("a truncated blob is refused before any key agreement", async () => {
  const { privateKey } = await issuerKeypair();

  // The message and not the code: every ECDH unseal failure is
  // `unseal_failed`, and what is claimed here is that this one stopped at the
  // length rather than at the tag.
  await assert.rejects(
    () => open(base64urlEncode(new Uint8Array(80)), privateKey, "ECDH-P256", { binding: BINDING }),
    /too short/i,
  );
});

test("a seal that names no coordinate is refused rather than written unbound", async () => {
  const random = seededRandom(SEED);
  const { publicKey } = await issuerKeypair();

  // The blob would look like every other one on the wire and open for whoever
  // asked, under any name. There is no unbound seal to fall back to.
  await refuses(
    () => seal(random.bytes(16), publicKey, "ECDH-P256", { random }),
    "binding_failed",
    "a seal with no binding is refused",
  );
  // X25519-sealedbox is libsodium rather than WebCrypto and is out of the
  // data format; it stands in here for any third algorithm.
  await refuses(
    () => seal(random.bytes(16), publicKey, "X25519", { random, binding: BINDING }),
    "unsupported_algorithm",
    "a third algorithm is refused rather than guessed at",
  );
});

test("CONFUSION: an RSA key handed to an ECDH seal is refused, not handed to WebCrypto", async () => {
  // The mirror of the RSA path's key-type guard: a publisher configured
  // `ecdh-p256` for an issuer whose key is RSA would otherwise die as a bare
  // InvalidAccessError inside the ECDH agreement, with nothing to say the
  // wrong key type was configured.
  const random = seededRandom(SEED);
  const rsa = await issuerKeypair("RSA-OAEP");

  await refuses(
    () => seal(random.bytes(16), rsa.publicKey, "ECDH-P256", { random, binding: BINDING }),
    "bad_config",
    "sealing to an RSA key under ECDH-P256 is refused",
  );
});

describe("RSA-OAEP - the second seal algorithm", () => {
  // spec--sealed-key-envelopes.md Section 5: "The binary envelope is one RSA
  // ciphertext exactly as wide as the issuer modulus." So the content
  // key is wrapped by OAEP directly - no ephemeral AES layer, no nonce, nothing
  // concatenated. The blob is the raw RSA ciphertext, one modulus wide.

  test("RSA-OAEP round-trips a contentKey", async () => {
    const random = seededRandom(SEED);
    const { publicKey, privateKey } = await issuerKeypair("RSA-OAEP");
    const keyBytes = random.bytes(16);

    const blob = await seal(keyBytes, publicKey, "RSA-OAEP", { random, binding: BINDING });
    const recovered = await open(blob, privateKey, "RSA-OAEP", { binding: BINDING });

    assert.deepEqual(recovered, keyBytes);
  });

  test("an RSA-OAEP seal needs no Random - OAEP does its own padding", async () => {
    // The ECDH blob carries a nonce the sealer has to supply. This one does
    // not, so demanding a Random here would be theatre.
    const { publicKey, privateKey } = await issuerKeypair("RSA-OAEP");
    const keyBytes = seededRandom(SEED).bytes(16);

    const blob = await seal(keyBytes, publicKey, "RSA-OAEP", { binding: BINDING });

    assert.deepEqual(await open(blob, privateKey, "RSA-OAEP", { binding: BINDING }), keyBytes);
  });

  test("the RSA-OAEP blob is one modulus wide - 256 bytes, 342 base64url chars at 2048 bits", async () => {
    // spec--sealed-key-envelopes.md Section 5 makes the RSA-OAEP envelope one
    // modulus wide, 256 bytes at 2048 bits, ~342 base64url characters.
    // That figure is the encoded string, which is what the wire carries.
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair("RSA-OAEP");

    const blob = await seal(random.bytes(16), publicKey, "RSA-OAEP", { binding: BINDING });

    assert.equal(base64urlDecode(blob).length, 256, "raw RSA ciphertext, 2048-bit modulus");
    assert.equal(blob.length, 342, "the spec's ~342 B sealed blob");
  });

  test("a 3072-bit issuer key widens the blob to its own modulus", async () => {
    // The spec says 2048+, so the width is the key's, not a constant.
    const { publicKey, privateKey } = await issuerKeypair("RSA-OAEP", { modulusLength: 3072 });
    const keyBytes = seededRandom(SEED).bytes(16);

    const blob = await seal(keyBytes, publicKey, "RSA-OAEP", { binding: BINDING });

    assert.equal(base64urlDecode(blob).length, 384);
    assert.deepEqual(await open(blob, privateKey, "RSA-OAEP", { binding: BINDING }), keyBytes);
  });

  test("a 2050-bit issuer modulus uses the rounded-up ciphertext width when the runtime supports it", async (t) => {
    let keys;
    try {
      keys = await issuerKeypair("RSA-OAEP", { modulusLength: 2050 });
    } catch (error) {
      t.skip(`this WebCrypto runtime does not generate a 2050-bit RSA-OAEP key: ${error}`);
      return;
    }
    const keyBytes = seededRandom(SEED).bytes(16);
    const blob = await seal(keyBytes, keys.publicKey, "RSA-OAEP", { binding: BINDING });

    assert.equal(
      keys.publicKey.algorithm.modulusLength,
      2050,
      "the runtime retained the requested modulus width",
    );
    assert.equal(base64urlDecode(blob).length, 257, "RSA ciphertext width is ceil(2050 / 8)");
    assert.deepEqual(await open(blob, keys.privateKey, "RSA-OAEP", { binding: BINDING }), keyBytes);
  });

  test("an issuer modulus under 2048 bits is refused before any RSA operation", async () => {
    // The floor is a property of the issuer's own key and not of anything the
    // wire carries, so a narrow modulus is that issuer's configuration fault
    // and is stated on both directions of the call. The message is asserted
    // here because the OAEP capacity check also refuses a 1024-bit seal, for
    // a different reason and only when the plaintext happens not to fit; the
    // floor stands ahead of it and holds on the unseal too, where capacity is
    // never consulted.
    const random = seededRandom(SEED);
    const { publicKey, privateKey } = await issuerKeypair("RSA-OAEP", { modulusLength: 1024 });

    await refuses(
      () => seal(random.bytes(16), publicKey, "RSA-OAEP", { binding: BINDING }),
      { code: "bad_config", message: /2048/ },
      "a 1024-bit issuer key is refused at the seal",
    );
    await refuses(
      () => open("x", privateKey, "RSA-OAEP", { binding: BINDING }),
      { code: "bad_config", message: /2048/ },
      "and at the unseal, so both sides read the one floor",
    );
  });

  test("RSA-2048 seal/open at the format maxima: 16-byte renderId, maximum-length names, 11-char t", async () => {
    const renderId = base64urlEncode(new Uint8Array(RENDER_ID_BYTES).fill(0x5a));
    assert.equal(renderId.length, 22, "16 bytes as unpadded base64url");
    const accessGroup = "g".repeat(MAX_NAME_LENGTH);
    const contentName = "c".repeat(MAX_NAME_LENGTH);
    const t = "251023T1330"; // 11 chars, the longest the t grammar admits

    const random = seededRandom(SEED);
    const { publicKey, privateKey } = await issuerKeypair("RSA-OAEP");
    const keyBytes = random.bytes(16);
    const periodBinding = { renderId, accessGroup, t };

    // 1. The budget, executable: the fixed grammar, a 22-character renderId
    //    and the maximum accessGroup total 113 bytes; plus the 16-byte key is
    //    129, inside the OAEP capacity of 190 (256 - OAEP_OVERHEAD,
    //    js/v1/core-shared--publisher-issuer/keySealing.js:98).
    const periodBindBytes = bindValue(periodBinding).length;
    assert.equal(periodBindBytes, 113);
    const periodPlaintextBytes = periodBindBytes + keyBytes.length;
    assert.equal(periodPlaintextBytes, 129);
    assert.ok(periodPlaintextBytes <= 190, "the maxima bind + sealed key fits OAEP-2048 capacity");

    // 2. Period kind at maxima round-trips.
    const periodBlob = await seal(keyBytes, publicKey, "RSA-OAEP", { binding: periodBinding });
    assert.equal(base64urlDecode(periodBlob).length, 256);
    assert.deepEqual(
      await open(periodBlob, privateKey, "RSA-OAEP", { binding: periodBinding }),
      keyBytes,
    );

    // 3. The frozen chain suffix fits the same RSA floor and authenticates
    //    both geometry values.
    const chainBinding = {
      renderId,
      accessGroup,
      suppliedT: t,
      periodChain: true,
      chainsPerDay: 2,
      periodMinutes: 15,
    };
    const chainBindBytes = bindValue(chainBinding).length;
    assert.equal(chainBindBytes, 119);
    const chainPlaintextBytes = chainBindBytes + keyBytes.length;
    assert.equal(chainPlaintextBytes, 135);
    assert.ok(
      chainPlaintextBytes <= 190,
      "the chain bind plus sealed state fits OAEP-2048 capacity",
    );
    const chainBlob = await seal(keyBytes, publicKey, "RSA-OAEP", { binding: chainBinding });
    assert.deepEqual(
      await open(chainBlob, privateKey, "RSA-OAEP", { binding: chainBinding }),
      keyBytes,
    );
    await assert.rejects(
      () =>
        open(chainBlob, privateKey, "RSA-OAEP", {
          binding: { ...chainBinding, periodMinutes: 5 },
        }),
      /unseal failed/i,
      "substituting the resolved geometry fails authentication",
    );

    // 4. Content kind at maxima round-trips.
    const contentBinding = { renderId, contentName };
    const contentBlob = await seal(keyBytes, publicKey, "RSA-OAEP", { binding: contentBinding });
    assert.equal(base64urlDecode(contentBlob).length, 256);
    assert.deepEqual(
      await open(contentBlob, privateKey, "RSA-OAEP", { binding: contentBinding }),
      keyBytes,
    );

    // 5. Any other renderId width is refused before RSA-OAEP runs.
    await refuses(
      () =>
        seal(keyBytes, publicKey, "RSA-OAEP", {
          binding: {
            renderId: base64urlEncode(new Uint8Array(RENDER_ID_BYTES + 1).fill(0x5b)),
            accessGroup,
            t,
          },
        }),
      "binding_failed",
      "a renderId outside the exact width is refused at seal",
    );
  });

  test("two RSA-OAEP seals of one key differ, and nothing can pin them", async () => {
    // OAEP draws its own padding seed inside WebCrypto, unreachable from JS.
    // There is no RSA counterpart to `ephemeralKeyPair`: an RSA render is not
    // byte-reproducible, which is what a golden vector would need.
    const { publicKey } = await issuerKeypair("RSA-OAEP");
    const keyBytes = seededRandom(SEED).bytes(16);

    const first = await seal(keyBytes, publicKey, "RSA-OAEP", { binding: BINDING });
    const second = await seal(keyBytes, publicKey, "RSA-OAEP", { binding: BINDING });

    assert.notEqual(first, second);
  });

  test("another issuer's RSA private key does not unseal the blob", async () => {
    const random = seededRandom(SEED);
    const mine = await issuerKeypair("RSA-OAEP");
    const theirs = await issuerKeypair("RSA-OAEP");

    const blob = await seal(random.bytes(16), mine.publicKey, "RSA-OAEP", { binding: BINDING });

    await refuses(
      () => open(blob, theirs.privateKey, "RSA-OAEP", { binding: BINDING }),
      "unseal_failed",
      "a blob sealed for one issuer stays shut for another",
    );
  });

  test("a tampered RSA-OAEP blob fails the OAEP padding check", async () => {
    const random = seededRandom(SEED);
    const { publicKey, privateKey } = await issuerKeypair("RSA-OAEP");
    const blob = await seal(random.bytes(16), publicKey, "RSA-OAEP", { binding: BINDING });

    const bytes = base64urlDecode(blob);
    bytes[100] ^= 0x01;

    await refuses(
      () => open(base64urlEncode(bytes), privateKey, "RSA-OAEP", { binding: BINDING }),
      "unseal_failed",
      "a flipped byte is caught by the padding check",
    );
  });

  test("a blob that is not one modulus wide is refused before any RSA operation", async () => {
    const { privateKey } = await issuerKeypair("RSA-OAEP");

    await refuses(
      () =>
        open(base64urlEncode(new Uint8Array(200)), privateKey, "RSA-OAEP", { binding: BINDING }),
      "unseal_failed",
      "a blob of the wrong width is refused on its length",
    );
  });

  test("CONFUSION: an ECDH blob handed to an RSA issuer fails typed", async () => {
    // The realistic mix-up: a publisher configured `ecdh-p256` for an issuer
    // whose key is RSA. 125 bytes into a 256-byte slot.
    const random = seededRandom(SEED);
    const ecdh = await issuerKeypair();
    const rsa = await issuerKeypair("RSA-OAEP");
    const keyBytes = random.bytes(16);

    const ecdhBlob = await seal(keyBytes, ecdh.publicKey, "ECDH-P256", {
      random,
      binding: BINDING,
    });

    await refuses(
      () => open(ecdhBlob, rsa.privateKey, "RSA-OAEP", { binding: BINDING }),
      "unseal_failed",
      "an ECDH blob read as RSA comes back typed",
    );
  });

  test("CONFUSION: an RSA blob handed to an ECDH issuer fails typed", async () => {
    const ecdh = await issuerKeypair();
    const rsa = await issuerKeypair("RSA-OAEP");
    const keyBytes = seededRandom(SEED).bytes(16);

    const rsaBlob = await seal(keyBytes, rsa.publicKey, "RSA-OAEP", { binding: BINDING });

    // 256 bytes clears the ECDH length floor, so this goes all the way into
    // the P-256 point import and has to come back typed, not as a raw
    // WebCrypto DataError.
    await refuses(
      () => open(rsaBlob, ecdh.privateKey, "ECDH-P256", { binding: BINDING }),
      "unseal_failed",
      "an RSA blob read as ECDH comes back typed",
    );
  });

  test("CONFUSION: a key of the wrong type is refused, not handed to WebCrypto", async () => {
    const random = seededRandom(SEED);
    const ecdh = await issuerKeypair();
    const rsa = await issuerKeypair("RSA-OAEP");

    await refuses(
      () => seal(random.bytes(16), ecdh.publicKey, "RSA-OAEP", { binding: BINDING }),
      "bad_config",
      "sealing to an ECDH key under RSA-OAEP is refused",
    );

    const blob = await seal(random.bytes(16), rsa.publicKey, "RSA-OAEP", { binding: BINDING });
    await refuses(
      () => open(blob, ecdh.privateKey, "RSA-OAEP", { binding: BINDING }),
      "bad_config",
      "unsealing with an ECDH key under RSA-OAEP is refused",
    );
  });

  test("an RSA key hashing with SHA-1 is refused - the spec says RSA-OAEP with SHA-256", async () => {
    // Two sides that disagree on the OAEP hash fail at the padding check with
    // nothing on the wire to say why, which is why the hash is fixed rather
    // than negotiated.
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair("RSA-OAEP", { hash: "SHA-1" });

    await refuses(
      () => seal(random.bytes(16), publicKey, "RSA-OAEP", { binding: BINDING }),
      "bad_config",
      "an SHA-1 OAEP key is refused",
    );
  });

  test("RSA-OAEP refuses the ECDH-only option rather than ignoring it", async () => {
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair("RSA-OAEP");
    // Again an ephemeral pair rather than an issuer's, held here only to be
    // offered to a seal that has to refuse it.
    const ephemeralKeyPair = await generateEcdhKeyPair();

    // Injecting a keypair makes an ECDH seal replayable. Accepting it here
    // would promise a reproducible RSA blob, which WebCrypto cannot give.
    await refuses(
      () => seal(random.bytes(16), publicKey, "RSA-OAEP", { ephemeralKeyPair, binding: BINDING }),
      "unsupported_option",
      "an injected ephemeral keypair on an RSA seal is refused",
    );
  });

  test("a key that is not 16 bytes is refused, because the plaintext boundary is read off that width", async () => {
    // `BIND ‖ key` carries nothing that says where the value stops, so the
    // unseal splits at the last 16 bytes. A key of another width would be split
    // in the wrong place and compared against a value nobody built.
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair("RSA-OAEP");

    await refuses(
      () => seal(random.bytes(15), publicKey, "RSA-OAEP", { binding: BINDING }),
      "bad_key",
      "a 15-byte key is refused",
    );
    await refuses(
      () => seal(random.bytes(200), publicKey, "RSA-OAEP", { binding: BINDING }),
      "bad_key",
      "a 200-byte key is refused",
    );
  });

  test("RSA-OAEP seals only a 16-octet Uint8Array, never a coercible value", async () => {
    const { publicKey } = await issuerKeypair("RSA-OAEP");
    const coercible = [
      "x".repeat(16),
      Array(16).fill(7),
      16,
      new Uint8Array(15),
      new Uint8Array(17),
    ];

    for (const value of coercible) {
      await refuses(
        () => seal(/** @type {any} */ (value), publicKey, "RSA-OAEP", { binding: BINDING }),
        "bad_key",
        `RSA-OAEP refuses ${Object.prototype.toString.call(value)} rather than coercing it into a key`,
      );
    }
  });

  test("more plaintext than OAEP can carry is refused typed", async () => {
    // 2048-bit OAEP with SHA-256 tops out at 190 bytes, and the binding rides
    // inside it, so a long enough contentName is what overflows a 16-byte key.
    // A caller gets a stated limit, not an OperationError.
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair("RSA-OAEP");
    const binding = { ...BINDING, contentName: "x".repeat(200) };

    await refuses(
      () => seal(random.bytes(16), publicKey, "RSA-OAEP", { binding }),
      "binding_failed",
      "an identifier exceeding the BIND field bound is refused before OAEP",
    );
  });
});

describe("which failure keeps which identity", () => {
  // Sealed material that will not open is a fact about the blob that arrived,
  // so every carrier, width, coordinate and key mix-up over it answers with
  // the one `unseal_failed` an issuer reports at that coordinate. The opening
  // key is the issuer's own, so a key that is not the type or the curve it
  // was configured as is that issuer's configuration fault and keeps its
  // typed code for the whole-request path to answer on.

  test("malformed, mis-sized, moved and altered sealed material is uniformly unseal_failed", async () => {
    const random = seededRandom(SEED);
    const mine = await issuerKeypair();
    const theirs = await issuerKeypair();
    const rsa = await issuerKeypair("RSA-OAEP");
    const keyBytes = random.bytes(16);

    const ecdhBlob = await seal(keyBytes, mine.publicKey, "ECDH-P256", {
      random,
      binding: BINDING,
    });
    const rsaBlob = await seal(keyBytes, rsa.publicKey, "RSA-OAEP", { binding: BINDING });

    const altered = base64urlDecode(ecdhBlob);
    altered[100] ^= 0x01;

    // A value the wire could not have carried: `atob` refuses it, and the
    // caller gets the coordinate's answer rather than a raw codec throw.
    const malformed = "AAA*AAA";

    /** @type {[string, () => Promise<Uint8Array>][]} */
    const cases = [
      [
        "malformed base64 under ECDH",
        () => open(malformed, mine.privateKey, "ECDH-P256", { binding: BINDING }),
      ],
      [
        "malformed base64 under RSA-OAEP",
        () => open(malformed, rsa.privateKey, "RSA-OAEP", { binding: BINDING }),
      ],
      [
        "a carrier too narrow for ECDH",
        () =>
          open(base64urlEncode(new Uint8Array(80)), mine.privateKey, "ECDH-P256", {
            binding: BINDING,
          }),
      ],
      [
        "a carrier that is not one modulus wide",
        () =>
          open(base64urlEncode(new Uint8Array(200)), rsa.privateKey, "RSA-OAEP", {
            binding: BINDING,
          }),
      ],
      [
        "an altered ECDH ciphertext",
        () => open(base64urlEncode(altered), mine.privateKey, "ECDH-P256", { binding: BINDING }),
      ],
      [
        "a blob presented at another coordinate",
        () =>
          open(ecdhBlob, mine.privateKey, "ECDH-P256", {
            binding: { ...BINDING, contentName: "summary" },
          }),
      ],
      [
        "the other algorithm's carrier under an ECDH key",
        () => open(rsaBlob, mine.privateKey, "ECDH-P256", { binding: BINDING }),
      ],
      [
        "the other algorithm's carrier under an RSA key",
        () => open(ecdhBlob, rsa.privateKey, "RSA-OAEP", { binding: BINDING }),
      ],
      [
        "a wrong private key of the configured type",
        () => open(ecdhBlob, theirs.privateKey, "ECDH-P256", { binding: BINDING }),
      ],
    ];

    for (const [why, run] of cases) await refuses(run, "unseal_failed", why);
  });

  test("a sealed envelope respelled off the canonical alphabet is unseal_failed, others still open", async () => {
    // Every spelling below decodes to the very bytes the canonical one
    // decodes to: padding adds nothing, the standard alphabet numbers `-`
    // and `_` the same way as `+` and `/`, and the two unused bits of the
    // last character are discarded by every decoder. So each of them would
    // have unsealed. Section 2.2 admits one spelling, and the failure scope
    // in spec--data-format.md Section 2.2, "Binary strings", keeps the
    // refusal to that one leaf.
    const random = seededRandom(SEED);
    const mine = await issuerKeypair();
    const theirs = await issuerKeypair();
    const keyBytes = random.bytes(16);

    const mineBlob = await seal(keyBytes, mine.publicKey, "ECDH-P256", {
      random,
      binding: BINDING,
    });
    const theirsBlob = await seal(keyBytes, theirs.publicKey, "ECDH-P256", {
      random,
      binding: BINDING,
    });

    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    assert.equal(
      mineBlob.length % 4,
      2,
      "the last character of a 109-byte envelope carries four unused bits",
    );
    const tailBits = `${mineBlob.slice(0, -1)}${alphabet[alphabet.indexOf(mineBlob.slice(-1)) | 1]}`;

    // Padding and a last character with its unused bits set follow from the
    // 146-character length, so both of those spellings are here on every
    // run. The standard alphabet respells `-` and `_`, and whether the
    // drawn envelope carries one of them is the draw's business, so that
    // spelling joins the list where it has something to respell.
    const spellings = [
      ["a padded envelope", `${mineBlob}=`],
      ["an envelope with nonzero unused trailing bits", tailBits],
    ];
    if (/[-_]/.test(mineBlob)) {
      spellings.push([
        "an envelope in the standard alphabet",
        mineBlob.replace(/-/g, "+").replace(/_/g, "/"),
      ]);
    }

    for (const [why, spelling] of spellings) {
      assert.deepEqual(
        base64urlDecode(spelling),
        base64urlDecode(mineBlob),
        `${why} is the same bytes`,
      );
      await refuses(
        () => open(spelling, mine.privateKey, "ECDH-P256", { binding: BINDING }),
        "unseal_failed",
        why,
      );
    }

    assert.deepEqual(
      await open(theirsBlob, theirs.privateKey, "ECDH-P256", { binding: BINDING }),
      keyBytes,
      "the envelope sealed for another issuer opens as it did",
    );
  });

  test("an opening key that is not what it was configured as is bad_config", async () => {
    const random = seededRandom(SEED);
    const ecdh = await issuerKeypair();
    const rsa = await issuerKeypair("RSA-OAEP");
    // P-384 agrees with nothing this format seals to, and the issuer that
    // configured it learns that from the code rather than from a coordinate
    // its readers cannot open.
    const p384 = /** @type {CryptoKeyPair} */ (await generateEcdhKeyPair("P-384"));

    const ecdhBlob = await seal(random.bytes(16), ecdh.publicKey, "ECDH-P256", {
      random,
      binding: BINDING,
    });
    const rsaBlob = await seal(random.bytes(16), rsa.publicKey, "RSA-OAEP", { binding: BINDING });

    await refuses(
      () => open(ecdhBlob, rsa.privateKey, "ECDH-P256", { binding: BINDING }),
      "bad_config",
      "an RSA key configured as ECDH-P256",
    );
    await refuses(
      () => open(rsaBlob, ecdh.privateKey, "RSA-OAEP", { binding: BINDING }),
      "bad_config",
      "an ECDH key configured as RSA-OAEP",
    );
    await refuses(
      () => open(ecdhBlob, p384.privateKey, "ECDH-P256", { binding: BINDING }),
      "bad_config",
      "an ECDH key on the wrong curve",
    );
    await refuses(
      () => open(ecdhBlob, ecdh.privateKey, "X25519", { binding: BINDING }),
      "unsupported_algorithm",
      "an algorithm this module does not have",
    );
  });

  test("a key claimed and not held is the coordinate's answer on both carriers", async () => {
    // A store that names a key and hands over nothing has answered and been
    // wrong, which `test/rotation.test.js` states as the field being the
    // claim rather than the value behind it. Neither key check reads an
    // algorithm off it, so both carriers fall to WebCrypto, which refuses
    // the value, and both report the coordinate.
    const random = seededRandom(SEED);
    const ecdh = await issuerKeypair();
    const rsa = await issuerKeypair("RSA-OAEP");
    const ecdhBlob = await seal(random.bytes(16), ecdh.publicKey, "ECDH-P256", {
      random,
      binding: BINDING,
    });
    const rsaBlob = await seal(random.bytes(16), rsa.publicKey, "RSA-OAEP", { binding: BINDING });

    await refuses(
      () => open(ecdhBlob, /** @type {any} */ (null), "ECDH-P256", { binding: BINDING }),
      "unseal_failed",
      "a null key under ECDH-P256",
    );
    await refuses(
      () => open(rsaBlob, /** @type {any} */ (null), "RSA-OAEP", { binding: BINDING }),
      "unseal_failed",
      "a null key under RSA-OAEP",
    );
  });
});

describe("The canonical payload width", () => {
  const PERIOD_BINDING = { renderId: BINDING.renderId, accessGroup: "premium", t: "251023T1415" };

  test("c, p and pc envelopes all carry 16 bytes in 109-byte ECDH envelopes", async () => {
    const random = seededRandom(SEED);
    const { publicKey, privateKey } = await issuerKeypair();
    const bindings = [
      BINDING,
      PERIOD_BINDING,
      {
        renderId: BINDING.renderId,
        accessGroup: "premium",
        suppliedT: "251023T2345",
        periodChain: true,
        chainsPerDay: 2,
        periodMinutes: 15,
      },
    ];
    for (const binding of bindings) {
      const payload = random.bytes(16);
      const blob = await seal(payload, publicKey, "ECDH-P256", { random, binding });
      assert.equal(base64urlDecode(blob).length, 109);
      assert.equal(blob.length, 146);
      assert.deepEqual(await open(blob, privateKey, "ECDH-P256", { binding }), payload);
    }
  });

  test("payloadBytes is no longer a profile selector", async () => {
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair();
    await refuses(
      () =>
        seal(random.bytes(16), publicKey, "ECDH-P256", {
          random,
          binding: PERIOD_BINDING,
          payloadBytes: 16,
        }),
      { code: "unsupported_option", message: /fixed at 16 bytes/ },
      "a removed payload-width selector",
    );
  });

  test("a 32-byte payload is refused for every sealed-key kind", async () => {
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair();
    await refuses(
      () => seal(random.bytes(32), publicKey, "ECDH-P256", { random, binding: PERIOD_BINDING }),
      { code: "bad_key", message: /exactly 16 .*octets/ },
      "a noncanonical payload",
    );
  });
});
