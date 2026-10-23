//
// js/core-shared--publisher-issuer/keySealing.js - publisher to issuer,
// ECDH P-256 and RSA-OAEP.
// The ECDH carrier has one construction, the agreed x-coordinate used as the
// AES key, so there is no derivation setting to run these bodies twice under.
//
// Every call names a coordinate, because the seal takes one in both directions.
// bind.test.js runs what the binding stops and what it costs; here it is one
// coordinate throughout, so anything that fails is the algorithm and not the
// binding.

import { describe } from "node:test";
import { envelopeBehavior } from "../../test-lib/suites/envelope-behavior.js";
import assert from "node:assert/strict";

import { seal, open } from "../../core-shared--publisher-issuer/keySealing.js";
import { RENDER_ID_BYTES, bindValue } from "../../core-shared--publisher-issuer/bind.js";
import { base64urlDecode, base64urlEncode } from "../../core-shared/codec.js";
import { DcaError } from "../../core-shared/errors.js";
import { MAX_NAME_LENGTH } from "../../core-shared/names.js";
import { generateEcdhKeyPair, generateRsaOaepKeyPair } from "../../core-shared/cryptoProvider.js";
import { issuerKeypair, seededRandom } from "../support/keys.js";
import { portableTest, test } from "../support/portable-test.js";

const portableCoreTest = portableTest("portable-core");
const portableKeySealingDynamicTest = portableTest("portable-key-sealing-refusals-dynamic");

/** Payloads of the declared Uint8Array type that are not 16 octets. */
const NOT_SIXTEEN_OCTETS = [new Uint8Array(15), new Uint8Array(17)];

/** Payloads of another JSON kind that WebCrypto could coerce into 16 octets. */
const COERCIBLE_NOT_BYTES = [Array(16).fill(7), 16];

/**
 * The issuer key the portable twins pass. A `CryptoKey` does not cross to a
 * synchronous PHP member, and every refusal these twins check fires before
 * `seal` or `open` reads the key. `null` contradicts the declared `CryptoKey`,
 * so the twins run under portable-key-sealing-refusals-dynamic.
 */
const STAND_IN_KEY = /** @type {any} */ (null);

/** A payload of the declared width, for twins whose refusal is about something else. */
const SIXTEEN_OCTETS = new Uint8Array(16).fill(0x2a);

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

  const blob = await seal(keyBytes, publicKey, "ecdh-p256", { random, binding: BINDING });
  const recovered = await open(blob, privateKey, "ecdh-p256", { binding: BINDING });

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
      () => seal(random.bytes(16), publicKey, "ecdh-p256", { kdf, random, binding: BINDING }),
      "unsupported_option",
      `a seal stating kdf ${JSON.stringify(kdf)} is refused`,
    );
    await refuses(
      () => open("x", privateKey, "ecdh-p256", { kdf, binding: BINDING }),
      "unsupported_option",
      `and an unseal stating kdf ${JSON.stringify(kdf)} is refused`,
    );
  }
});

// The portable twin of the case above. `kdf` is refused before the key or the
// key is read, so the twin passes the stand-in key and no `random`.
portableKeySealingDynamicTest(
  "a kdf option is refused rather than sealed under a second construction, under a stand-in key",
  async () => {
    for (const kdf of ["none", "hkdf", "x25519"]) {
      await refuses(
        () =>
          seal(
            SIXTEEN_OCTETS,
            STAND_IN_KEY,
            "ecdh-p256",
            /** @type {any} */ ({ kdf, binding: BINDING }),
          ),
        "unsupported_option",
        `a seal stating kdf ${JSON.stringify(kdf)} is refused`,
      );
      await refuses(
        () => open("x", STAND_IN_KEY, "ecdh-p256", /** @type {any} */ ({ kdf, binding: BINDING })),
        "unsupported_option",
        `and an unseal stating kdf ${JSON.stringify(kdf)} is refused`,
      );
    }
  },
);

test("the ECDH blob is ephemeral public key, ciphertext and tag, with no carried nonce", async () => {
  const random = seededRandom(SEED);
  const { publicKey } = await issuerKeypair();

  const blob = await seal(random.bytes(16), publicKey, "ecdh-p256", { random, binding: BINDING });
  const bytes = base64urlDecode(blob);

  assert.equal(bytes.length, 65 + 16 + 16, "the spec's 97-byte blob");
  assert.equal(bytes[0], 0x04, "uncompressed P-256 point");
});

test("ECDH opens only the uncompressed point encoding", async () => {
  const random = seededRandom(SEED);
  const { publicKey, privateKey } = await issuerKeypair();
  const keyBytes = random.bytes(16);
  const blob = await seal(keyBytes, publicKey, "ecdh-p256", { random, binding: BINDING });
  const bytes = base64urlDecode(blob);

  assert.equal(bytes[0], 0x04);
  assert.deepEqual(await open(blob, privateKey, "ecdh-p256", { binding: BINDING }), keyBytes);

  const hybridBytes = bytes.slice();
  hybridBytes[0] = bytes[64] & 1 ? 0x07 : 0x06;
  await refuses(
    () => open(base64urlEncode(hybridBytes), privateKey, "ecdh-p256", { binding: BINDING }),
    "unseal_failed",
    "a hybrid encoding of the same valid ephemeral point",
  );
});

test("a fresh ephemeral keypair per seal makes two seals of one key differ", async () => {
  const random = seededRandom(SEED);
  const { publicKey } = await issuerKeypair();
  const keyBytes = random.bytes(16);

  const first = await seal(keyBytes, publicKey, "ecdh-p256", { random, binding: BINDING });
  const second = await seal(keyBytes, publicKey, "ecdh-p256", { random, binding: BINDING });

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

  const first = await seal(keyBytes, publicKey, "ecdh-p256", {
    random: seededRandom(3),
    ephemeralKeyPair,
    binding: BINDING,
  });
  const second = await seal(keyBytes, publicKey, "ecdh-p256", {
    random: seededRandom(3),
    ephemeralKeyPair,
    binding: BINDING,
  });

  assert.equal(first, second);
  assert.deepEqual(await open(first, privateKey, "ecdh-p256", { binding: BINDING }), keyBytes);
});

test("ECDH zero-nonce carrier matches an independent raw-x AES-256-GCM answer", async () => {
  // Isolated test-vector keys: P-256 private scalars 1 and 2. The literal
  // answer was computed with Node createECDH/computeSecret + createCipheriv,
  // literal ASCII BIND and twelve zero nonce bytes, without reference helpers.
  const issuerJwk = {
    kty: "EC",
    crv: "P-256",
    x: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
    y: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
  };
  const ephemeralJwk = {
    kty: "EC",
    crv: "P-256",
    x: "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg",
    y: "B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E",
  };
  const algorithm = { name: "ECDH", namedCurve: "P-256" };
  const publicKey = await crypto.subtle.importKey("jwk", issuerJwk, algorithm, true, []);
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    {
      ...issuerJwk,
      d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
    },
    algorithm,
    false,
    ["deriveBits"],
  );
  const ephemeralKeyPair = {
    publicKey: await crypto.subtle.importKey("jwk", ephemeralJwk, algorithm, true, []),
    privateKey: await crypto.subtle.importKey(
      "jwk",
      {
        ...ephemeralJwk,
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI",
      },
      algorithm,
      false,
      ["deriveBits"],
    ),
  };
  const expected =
    "BHzyexiNA09-ilI4AwS1GsPAiWnid_IbNaYLSPxHZpl4B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9EtlKnLANVYCNM88cGezOesegTB9nfkUMncQXrLj6aaLw";
  const payload = Uint8Array.from({ length: 16 }, (_, i) => i);
  assert.equal(
    await seal(payload, publicKey, "ecdh-p256", {
      binding: BINDING,
      ephemeralKeyPair,
    }),
    expected,
  );
  assert.deepEqual(await open(expected, privateKey, "ecdh-p256", { binding: BINDING }), payload);

  // An old-format carrier with an explicit zero nonce would authenticate
  // under a fallback parser. Refuse its 109-byte layout instead.
  const current = base64urlDecode(expected);
  const old = new Uint8Array(109);
  old.set(current.subarray(0, 65));
  old.set(current.subarray(65), 77);
  await refuses(
    () => open(base64urlEncode(old), privateKey, "ecdh-p256", { binding: BINDING }),
    { code: "unseal_failed", message: /exactly 97 bytes/ },
    "the old carried-nonce carrier is not another opening procedure",
  );
});

test("ECDH captures Buffer payload and BIND before asynchronous work", async () => {
  const recipient = await issuerKeypair();
  const payload = Buffer.from(Array.from({ length: 16 }, (_, i) => i));
  const original = Uint8Array.from(payload);
  const binding = { ...BINDING };
  const pending = seal(payload, recipient.publicKey, "ecdh-p256", { binding });
  payload.fill(0xff);
  binding.contentName = "sidebar";
  const blob = await pending;
  const openingBinding = { ...BINDING };
  const opening = open(blob, recipient.privateKey, "ecdh-p256", { binding: openingBinding });
  openingBinding.contentName = "sidebar";
  assert.deepEqual(await opening, original);
  await refuses(
    () => open(blob, recipient.privateKey, "ecdh-p256", { binding }),
    "unseal_failed",
    "the edited coordinate is not the captured one",
  );
});

test("same-coordinate rival payloads each open with independent ephemeral points", async () => {
  const recipient = await issuerKeypair();
  const firstKey = new Uint8Array(16).fill(1);
  const secondKey = new Uint8Array(16).fill(2);
  const first = await seal(firstKey, recipient.publicKey, "ecdh-p256", { binding: BINDING });
  const second = await seal(secondKey, recipient.publicKey, "ecdh-p256", { binding: BINDING });
  assert.notDeepEqual(
    base64urlDecode(first).subarray(0, 65),
    base64urlDecode(second).subarray(0, 65),
  );
  for (const entries of [
    [
      [first, firstKey],
      [second, secondKey],
    ],
    [
      [second, secondKey],
      [first, firstKey],
    ],
  ]) {
    const wire = JSON.parse(JSON.stringify(entries.map(([blob]) => blob)));
    for (let i = 0; i < entries.length; i++) {
      assert.deepEqual(
        await open(wire[i], recipient.privateKey, "ecdh-p256", { binding: BINDING }),
        entries[i][1],
      );
    }
  }
});

// The shared suite exercises shipped envelope operations for each supported BIND
// coordinate, without selecting optional period/chain derivation implementations.
envelopeBehavior(
  {
    createRecipient: () => issuerKeypair(),
    seal: (bytes, recipient, binding) => seal(bytes, recipient.publicKey, "ecdh-p256", { binding }),
    open: async (blob, recipient, binding) => {
      try {
        return await open(blob, recipient.privateKey, "ecdh-p256", { binding });
      } catch (error) {
        assert.ok(error instanceof DcaError, `expected a DcaError, got ${error}`);
        throw error;
      }
    },
  },
  test,
);

test("another issuer's private key does not unseal the blob", async () => {
  const random = seededRandom(SEED);
  const mine = await issuerKeypair();
  const theirs = await issuerKeypair();

  const blob = await seal(random.bytes(16), mine.publicKey, "ecdh-p256", {
    random,
    binding: BINDING,
  });

  await assert.rejects(
    () => open(blob, theirs.privateKey, "ecdh-p256", { binding: BINDING }),
    /unseal failed/i,
  );
});

test("a tampered blob fails the GCM tag", async () => {
  const random = seededRandom(SEED);
  const { publicKey, privateKey } = await issuerKeypair();
  const blob = await seal(random.bytes(16), publicKey, "ecdh-p256", { random, binding: BINDING });

  const bytes = base64urlDecode(blob);
  bytes[bytes.length - 1] ^= 0x01;

  await assert.rejects(
    () => open(base64urlEncode(bytes), privateKey, "ecdh-p256", { binding: BINDING }),
    /unseal failed/i,
  );
});

test("a truncated blob is refused before any key agreement", async () => {
  const { privateKey } = await issuerKeypair();

  // The message and not the code: every ECDH unseal failure is
  // `unseal_failed`, and what is claimed here is that this one stopped at the
  // length rather than at the tag.
  await assert.rejects(
    () => open(base64urlEncode(new Uint8Array(80)), privateKey, "ecdh-p256", { binding: BINDING }),
    /too short/i,
  );
});

test("the lowercase provisioning tokens seal and open on both carriers", async () => {
  // docs/spec--sealed-key-envelopes.md, 2: the envelope algorithms are named
  // `ecdh-p256` and `rsa-oaep`. That name is a provisioning token, not a
  // WebCrypto algorithm name and not a wire member.
  for (const [token, pair] of /** @type {const} */ ([
    ["ecdh-p256", await generateEcdhKeyPair()],
    ["rsa-oaep", await generateRsaOaepKeyPair()],
  ])) {
    const random = seededRandom(SEED);
    const key = random.bytes(16);
    const blob = await seal(key, pair.publicKey, token, { random, binding: BINDING });
    assert.deepEqual(await open(blob, pair.privateKey, token, { binding: BINDING }), key, token);
  }
});

test("an uppercase or mixed-case provisioning spelling is refused, with no alias", async () => {
  // `ECDH-P256` and `RSA-OAEP` are the client-bound method names and the
  // WebCrypto names; neither selects an envelope. The refusal comes before
  // the binding or the key is read.
  for (const token of ["ECDH-P256", "RSA-OAEP", "Ecdh-P256", "ecdh-P256", "ECDH", "rsa-oaep-256"]) {
    await refuses(
      () => seal(SIXTEEN_OCTETS, STAND_IN_KEY, token, {}),
      "unsupported_algorithm",
      `seal under ${token}`,
    );
    await refuses(
      () => open("AAAA", STAND_IN_KEY, token, {}),
      "unsupported_algorithm",
      `open under ${token}`,
    );
  }
});

test("a seal that names no coordinate is refused rather than written unbound", async () => {
  const random = seededRandom(SEED);
  const { publicKey } = await issuerKeypair();

  // The blob would look like every other one on the wire and open for whoever
  // asked, under any name. There is no unbound seal to fall back to.
  await refuses(
    () => seal(random.bytes(16), publicKey, "ecdh-p256", { random }),
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

// The portable twin of the case above, under the stand-in key and with no
// `random`: both refusals fire before either is read.
portableKeySealingDynamicTest(
  "a seal that names no coordinate is refused rather than written unbound, under a stand-in key",
  async () => {
    await refuses(
      () => seal(SIXTEEN_OCTETS, STAND_IN_KEY, "ecdh-p256", {}),
      "binding_failed",
      "a seal with no binding is refused",
    );
    await refuses(
      () => seal(SIXTEEN_OCTETS, STAND_IN_KEY, "X25519", { binding: BINDING }),
      "unsupported_algorithm",
      "a third algorithm is refused rather than guessed at",
    );
  },
);

test("CONFUSION: an RSA key handed to an ECDH seal is refused, not handed to WebCrypto", async () => {
  // The mirror of the RSA path's key-type guard: a publisher configured
  // `ecdh-p256` for an issuer whose key is RSA would otherwise die as a bare
  // InvalidAccessError inside the ECDH agreement, with nothing to say the
  // wrong key type was configured.
  const random = seededRandom(SEED);
  const rsa = await issuerKeypair("rsa-oaep");

  await refuses(
    () => seal(random.bytes(16), rsa.publicKey, "ecdh-p256", { random, binding: BINDING }),
    "bad_config",
    "sealing to an RSA key under ECDH-P256 is refused",
  );
});

describe("RSA-OAEP - the second seal algorithm", () => {
  // spec--sealed-key-envelopes.md Section 5: "The binary envelope is one RSA
  // ciphertext exactly as wide as the issuer modulus." So the content
  // key is wrapped by OAEP directly - no ephemeral AES layer, no nonce, nothing
  // concatenated. The blob is the raw RSA ciphertext, one modulus wide.

  /** A period coordinate at the format maxima: the maximum accessGroup and an 11-char t. */
  const MAXIMA_PERIOD_BINDING = {
    renderId: BINDING.renderId,
    accessGroup: "g".repeat(MAX_NAME_LENGTH),
    t: "251023T1330", // 11 chars, the longest the t grammar admits
  };

  /** The chain-key coordinate at the same maxima, with its resolved geometry. */
  const MAXIMA_CHAIN_BINDING = {
    renderId: MAXIMA_PERIOD_BINDING.renderId,
    accessGroup: MAXIMA_PERIOD_BINDING.accessGroup,
    suppliedT: MAXIMA_PERIOD_BINDING.t,
    chainKey: true,
    chainsPerDay: 2,
    periodMinutes: 15,
  };

  test("RSA-OAEP round-trips a contentKey", async () => {
    const random = seededRandom(SEED);
    const { publicKey, privateKey } = await issuerKeypair("rsa-oaep");
    const keyBytes = random.bytes(16);

    const blob = await seal(keyBytes, publicKey, "rsa-oaep", { random, binding: BINDING });
    const recovered = await open(blob, privateKey, "rsa-oaep", { binding: BINDING });

    assert.deepEqual(recovered, keyBytes);
  });

  test("an RSA-OAEP seal needs no Random - OAEP does its own padding", async () => {
    // RSA-OAEP draws its padding randomness inside WebCrypto.
    const { publicKey, privateKey } = await issuerKeypair("rsa-oaep");
    const keyBytes = seededRandom(SEED).bytes(16);

    const blob = await seal(keyBytes, publicKey, "rsa-oaep", { binding: BINDING });

    assert.deepEqual(await open(blob, privateKey, "rsa-oaep", { binding: BINDING }), keyBytes);
  });

  test("the RSA-OAEP blob is one modulus wide - 256 bytes, 342 base64url chars at 2048 bits", async () => {
    // spec--sealed-key-envelopes.md Section 5 makes the RSA-OAEP envelope one
    // modulus wide, 256 bytes at 2048 bits, ~342 base64url characters.
    // That figure is the encoded string, which is what the wire carries.
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair("rsa-oaep");

    const blob = await seal(random.bytes(16), publicKey, "rsa-oaep", { binding: BINDING });

    assert.equal(base64urlDecode(blob).length, 256, "raw RSA ciphertext, 2048-bit modulus");
    assert.equal(blob.length, 342, "the spec's ~342 B sealed blob");
  });

  test("a 3072-bit issuer key widens the blob to its own modulus", async () => {
    // The spec says 2048+, so the width is the key's, not a constant.
    const { publicKey, privateKey } = await issuerKeypair("rsa-oaep", { modulusLength: 3072 });
    const keyBytes = seededRandom(SEED).bytes(16);

    const blob = await seal(keyBytes, publicKey, "rsa-oaep", { binding: BINDING });

    assert.equal(base64urlDecode(blob).length, 384);
    assert.deepEqual(await open(blob, privateKey, "rsa-oaep", { binding: BINDING }), keyBytes);
  });

  test("a 2050-bit issuer modulus uses the rounded-up ciphertext width when the runtime supports it", async (t) => {
    let keys;
    try {
      keys = await issuerKeypair("rsa-oaep", { modulusLength: 2050 });
    } catch (error) {
      t.skip(`this WebCrypto runtime does not generate a 2050-bit RSA-OAEP key: ${error}`);
      return;
    }
    const keyBytes = seededRandom(SEED).bytes(16);
    const blob = await seal(keyBytes, keys.publicKey, "rsa-oaep", { binding: BINDING });

    assert.equal(
      keys.publicKey.algorithm.modulusLength,
      2050,
      "the runtime retained the requested modulus width",
    );
    assert.equal(base64urlDecode(blob).length, 257, "RSA ciphertext width is ceil(2050 / 8)");
    assert.deepEqual(await open(blob, keys.privateKey, "rsa-oaep", { binding: BINDING }), keyBytes);
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
    const { publicKey, privateKey } = await issuerKeypair("rsa-oaep", { modulusLength: 1024 });

    await refuses(
      () => seal(random.bytes(16), publicKey, "rsa-oaep", { binding: BINDING }),
      { code: "bad_config", message: /2048/ },
      "a 1024-bit issuer key is refused at the seal",
    );
    await refuses(
      () => open("x", privateKey, "rsa-oaep", { binding: BINDING }),
      { code: "bad_config", message: /2048/ },
      "and at the unseal, so both sides read the one floor",
    );
  });

  test("RSA-2048 seal/open at the format maxima: 16-byte renderId, maximum-length names, 11-char t", async () => {
    const { renderId, accessGroup, t } = MAXIMA_PERIOD_BINDING;
    assert.equal(renderId.length, 22, "16 bytes as unpadded base64url");
    const contentName = "c".repeat(MAX_NAME_LENGTH);

    const random = seededRandom(SEED);
    const { publicKey, privateKey } = await issuerKeypair("rsa-oaep");
    const keyBytes = random.bytes(16);
    const periodBinding = MAXIMA_PERIOD_BINDING;

    // 1. The budget, executable: the fixed grammar, a 22-character renderId
    //    and the maximum accessGroup total 123 bytes; plus the 16-byte key is
    //    139, inside the OAEP capacity of 190 (256 - OAEP_OVERHEAD,
    //    js/core-shared--publisher-issuer/keySealing.js).
    const periodBindBytes = bindValue(periodBinding).length;
    assert.equal(periodBindBytes, 123);
    const periodPlaintextBytes = periodBindBytes + keyBytes.length;
    assert.equal(periodPlaintextBytes, 139);
    assert.ok(periodPlaintextBytes <= 190, "the maxima bind + sealed key fits OAEP-2048 capacity");

    // 2. Period kind at maxima round-trips.
    const periodBlob = await seal(keyBytes, publicKey, "rsa-oaep", { binding: periodBinding });
    assert.equal(base64urlDecode(periodBlob).length, 256);
    assert.deepEqual(
      await open(periodBlob, privateKey, "rsa-oaep", { binding: periodBinding }),
      keyBytes,
    );

    // 3. The frozen chain suffix fits the same RSA floor and authenticates
    //    both geometry values.
    const chainBinding = MAXIMA_CHAIN_BINDING;
    const chainBindBytes = bindValue(chainBinding).length;
    assert.equal(chainBindBytes, 129);
    const chainPlaintextBytes = chainBindBytes + keyBytes.length;
    assert.equal(chainPlaintextBytes, 145);
    assert.ok(
      chainPlaintextBytes <= 190,
      "the chain bind plus sealed chain key fits OAEP-2048 capacity",
    );
    const chainBlob = await seal(keyBytes, publicKey, "rsa-oaep", { binding: chainBinding });
    assert.deepEqual(
      await open(chainBlob, privateKey, "rsa-oaep", { binding: chainBinding }),
      keyBytes,
    );
    await assert.rejects(
      () =>
        open(chainBlob, privateKey, "rsa-oaep", {
          binding: { ...chainBinding, periodMinutes: 5 },
        }),
      /unseal failed/i,
      "substituting the resolved geometry fails authentication",
    );

    // 4. Content kind at maxima round-trips.
    const contentBinding = { renderId, contentName };
    const contentBlob = await seal(keyBytes, publicKey, "rsa-oaep", { binding: contentBinding });
    assert.equal(base64urlDecode(contentBlob).length, 256);
    assert.deepEqual(
      await open(contentBlob, privateKey, "rsa-oaep", { binding: contentBinding }),
      keyBytes,
    );

    // 5. Any other renderId width is refused before RSA-OAEP runs.
    await refuses(
      () =>
        seal(keyBytes, publicKey, "rsa-oaep", {
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

  // The portable twins of the case above. Its round trips need the issuer's
  // private key, which does not cross; the two binding widths and the
  // renderId refusal do. The widths pass the declared Binding records.
  portableCoreTest("a binding at the format maxima is 123 bytes, and its chain form 129", () => {
    assert.equal(bindValue(MAXIMA_PERIOD_BINDING).length, 123);
    assert.equal(bindValue(MAXIMA_CHAIN_BINDING).length, 129);
  });

  portableKeySealingDynamicTest(
    "a renderId outside the exact width is refused at seal, under a stand-in key",
    async () => {
      await refuses(
        () =>
          seal(SIXTEEN_OCTETS, STAND_IN_KEY, "rsa-oaep", {
            binding: {
              ...MAXIMA_PERIOD_BINDING,
              renderId: base64urlEncode(new Uint8Array(RENDER_ID_BYTES + 1).fill(0x5b)),
            },
          }),
        "binding_failed",
        "a renderId outside the exact width is refused at seal",
      );
    },
  );

  test("two RSA-OAEP seals of one key differ, and nothing can pin them", async () => {
    // OAEP draws its own padding seed inside WebCrypto, unreachable from JS.
    // There is no RSA counterpart to `ephemeralKeyPair`: an RSA render is not
    // byte-reproducible, which is what a golden vector would need.
    const { publicKey } = await issuerKeypair("rsa-oaep");
    const keyBytes = seededRandom(SEED).bytes(16);

    const first = await seal(keyBytes, publicKey, "rsa-oaep", { binding: BINDING });
    const second = await seal(keyBytes, publicKey, "rsa-oaep", { binding: BINDING });

    assert.notEqual(first, second);
  });

  test("another issuer's RSA private key does not unseal the blob", async () => {
    const random = seededRandom(SEED);
    const mine = await issuerKeypair("rsa-oaep");
    const theirs = await issuerKeypair("rsa-oaep");

    const blob = await seal(random.bytes(16), mine.publicKey, "rsa-oaep", { binding: BINDING });

    await refuses(
      () => open(blob, theirs.privateKey, "rsa-oaep", { binding: BINDING }),
      "unseal_failed",
      "a blob sealed for one issuer stays shut for another",
    );
  });

  test("a tampered RSA-OAEP blob fails the OAEP padding check", async () => {
    const random = seededRandom(SEED);
    const { publicKey, privateKey } = await issuerKeypair("rsa-oaep");
    const blob = await seal(random.bytes(16), publicKey, "rsa-oaep", { binding: BINDING });

    const bytes = base64urlDecode(blob);
    bytes[bytes.length - 1] ^= 0x01;

    await refuses(
      () => open(base64urlEncode(bytes), privateKey, "rsa-oaep", { binding: BINDING }),
      "unseal_failed",
      "a flipped byte is caught by the padding check",
    );
  });

  test("a blob that is not one modulus wide is refused before any RSA operation", async () => {
    const { privateKey } = await issuerKeypair("rsa-oaep");

    await refuses(
      () =>
        open(base64urlEncode(new Uint8Array(200)), privateKey, "rsa-oaep", { binding: BINDING }),
      "unseal_failed",
      "a blob of the wrong width is refused on its length",
    );
  });

  test("CONFUSION: an ECDH blob handed to an RSA issuer fails typed", async () => {
    // The realistic mix-up: a publisher configured `ecdh-p256` for an issuer
    // whose key is RSA. 97 bytes into a 256-byte slot.
    const random = seededRandom(SEED);
    const ecdh = await issuerKeypair();
    const rsa = await issuerKeypair("rsa-oaep");
    const keyBytes = random.bytes(16);

    const ecdhBlob = await seal(keyBytes, ecdh.publicKey, "ecdh-p256", {
      random,
      binding: BINDING,
    });

    await refuses(
      () => open(ecdhBlob, rsa.privateKey, "rsa-oaep", { binding: BINDING }),
      "unseal_failed",
      "an ECDH blob read as RSA comes back typed",
    );
  });

  test("CONFUSION: an RSA blob handed to an ECDH issuer fails typed", async () => {
    const ecdh = await issuerKeypair();
    const rsa = await issuerKeypair("rsa-oaep");
    const keyBytes = seededRandom(SEED).bytes(16);

    const rsaBlob = await seal(keyBytes, rsa.publicKey, "rsa-oaep", { binding: BINDING });

    // The ECDH exact-length check refuses the 256-byte RSA carrier before
    // any P-256 point import.
    await refuses(
      () => open(rsaBlob, ecdh.privateKey, "ecdh-p256", { binding: BINDING }),
      "unseal_failed",
      "an RSA blob read as ECDH comes back typed",
    );
  });

  test("CONFUSION: a key of the wrong type is refused, not handed to WebCrypto", async () => {
    const random = seededRandom(SEED);
    const ecdh = await issuerKeypair();
    const rsa = await issuerKeypair("rsa-oaep");

    await refuses(
      () => seal(random.bytes(16), ecdh.publicKey, "rsa-oaep", { binding: BINDING }),
      "bad_config",
      "sealing to an ECDH key under RSA-OAEP is refused",
    );

    const blob = await seal(random.bytes(16), rsa.publicKey, "rsa-oaep", { binding: BINDING });
    await refuses(
      () => open(blob, ecdh.privateKey, "rsa-oaep", { binding: BINDING }),
      "bad_config",
      "unsealing with an ECDH key under RSA-OAEP is refused",
    );
  });

  test("an RSA key hashing with SHA-1 is refused - the spec says RSA-OAEP with SHA-256", async () => {
    // Two sides that disagree on the OAEP hash fail at the padding check with
    // nothing on the wire to say why, which is why the hash is fixed rather
    // than negotiated.
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair("rsa-oaep", { hash: "SHA-1" });

    await refuses(
      () => seal(random.bytes(16), publicKey, "rsa-oaep", { binding: BINDING }),
      "bad_config",
      "an SHA-1 OAEP key is refused",
    );
  });

  test("RSA-OAEP refuses the ECDH-only option rather than ignoring it", async () => {
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair("rsa-oaep");
    // Again an ephemeral pair rather than an issuer's, held here only to be
    // offered to a seal that has to refuse it.
    const ephemeralKeyPair = await generateEcdhKeyPair();

    // Injecting a keypair makes an ECDH seal replayable. Accepting it here
    // would promise a reproducible RSA blob, which WebCrypto cannot give.
    await refuses(
      () => seal(random.bytes(16), publicKey, "rsa-oaep", { ephemeralKeyPair, binding: BINDING }),
      "unsupported_option",
      "an injected ephemeral keypair on an RSA seal is refused",
    );
  });

  // The portable twin of the case above. An empty record stands in for the
  // key pair, which does not cross: the member being there is the refusal.
  portableKeySealingDynamicTest(
    "RSA-OAEP refuses the ECDH-only option rather than ignoring it, under a stand-in key",
    async () => {
      await refuses(
        () =>
          seal(SIXTEEN_OCTETS, STAND_IN_KEY, "rsa-oaep", {
            ephemeralKeyPair: /** @type {any} */ ({}),
            binding: BINDING,
          }),
        "unsupported_option",
        "an injected ephemeral keypair on an RSA seal is refused",
      );
    },
  );

  test("a key that is not 16 bytes is refused, because the plaintext boundary is read off that width", async () => {
    // `BIND ‖ key` carries nothing that says where the value stops, so the
    // unseal splits at the last 16 bytes. A key of another width would be split
    // in the wrong place and compared against a value nobody built.
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair("rsa-oaep");

    await refuses(
      () => seal(random.bytes(15), publicKey, "rsa-oaep", { binding: BINDING }),
      "bad_key",
      "a 15-byte key is refused",
    );
    await refuses(
      () => seal(random.bytes(200), publicKey, "rsa-oaep", { binding: BINDING }),
      "bad_key",
      "a 200-byte key is refused",
    );
  });

  test("RSA-OAEP seals only a 16-octet Uint8Array, never a coercible value", async () => {
    const { publicKey } = await issuerKeypair("rsa-oaep");
    const coercible = ["x".repeat(16), ...COERCIBLE_NOT_BYTES, ...NOT_SIXTEEN_OCTETS];

    for (const value of coercible) {
      await refuses(
        () => seal(/** @type {any} */ (value), publicKey, "rsa-oaep", { binding: BINDING }),
        "bad_key",
        `RSA-OAEP refuses ${Object.prototype.toString.call(value)} rather than coercing it into a key`,
      );
    }
  });

  // The portable twin of the case above. seal checks the payload before it
  // reads the key. The text string stays in the direct case: a port holding
  // bytes in its string type takes it as its 16 octets.
  portableKeySealingDynamicTest(
    "RSA-OAEP seals only a 16-octet Uint8Array, under a stand-in key",
    async () => {
      for (const value of [...COERCIBLE_NOT_BYTES, ...NOT_SIXTEEN_OCTETS]) {
        await refuses(
          () => seal(/** @type {any} */ (value), STAND_IN_KEY, "rsa-oaep", { binding: BINDING }),
          "bad_key",
          `RSA-OAEP refuses ${value instanceof Uint8Array ? `${value.length} octets` : JSON.stringify(value)}`,
        );
      }
    },
  );

  test("more plaintext than OAEP can carry is refused typed", async () => {
    // 2048-bit OAEP with SHA-256 tops out at 190 bytes, and the binding rides
    // inside it, so a long enough contentName is what overflows a 16-byte key.
    // A caller gets a stated limit, not an OperationError.
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair("rsa-oaep");
    const binding = { ...BINDING, contentName: "x".repeat(200) };

    await refuses(
      () => seal(random.bytes(16), publicKey, "rsa-oaep", { binding }),
      "binding_failed",
      "an identifier exceeding the BIND field bound is refused before OAEP",
    );
  });

  // The portable twin of the case above, under the stand-in key.
  portableKeySealingDynamicTest(
    "more plaintext than OAEP can carry is refused typed, under a stand-in key",
    async () => {
      const binding = { ...BINDING, contentName: "x".repeat(200) };

      await refuses(
        () => seal(SIXTEEN_OCTETS, STAND_IN_KEY, "rsa-oaep", { binding }),
        "binding_failed",
        "an identifier exceeding the BIND field bound is refused before OAEP",
      );
    },
  );
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
    const rsa = await issuerKeypair("rsa-oaep");
    const keyBytes = random.bytes(16);

    const ecdhBlob = await seal(keyBytes, mine.publicKey, "ecdh-p256", {
      random,
      binding: BINDING,
    });
    const rsaBlob = await seal(keyBytes, rsa.publicKey, "rsa-oaep", { binding: BINDING });

    const altered = base64urlDecode(ecdhBlob);
    altered[altered.length - 1] ^= 0x01;

    // A value the wire could not have carried: `atob` refuses it, and the
    // caller gets the coordinate's answer rather than a raw codec throw.
    const malformed = "AAA*AAA";

    /** @type {[string, () => Promise<Uint8Array>][]} */
    const cases = [
      [
        "malformed base64 under ECDH",
        () => open(malformed, mine.privateKey, "ecdh-p256", { binding: BINDING }),
      ],
      [
        "malformed base64 under RSA-OAEP",
        () => open(malformed, rsa.privateKey, "rsa-oaep", { binding: BINDING }),
      ],
      [
        "a carrier too narrow for ECDH",
        () =>
          open(base64urlEncode(new Uint8Array(80)), mine.privateKey, "ecdh-p256", {
            binding: BINDING,
          }),
      ],
      [
        "a carrier that is not one modulus wide",
        () =>
          open(base64urlEncode(new Uint8Array(200)), rsa.privateKey, "rsa-oaep", {
            binding: BINDING,
          }),
      ],
      [
        "an altered ECDH ciphertext",
        () => open(base64urlEncode(altered), mine.privateKey, "ecdh-p256", { binding: BINDING }),
      ],
      [
        "a blob presented at another coordinate",
        () =>
          open(ecdhBlob, mine.privateKey, "ecdh-p256", {
            binding: { ...BINDING, contentName: "summary" },
          }),
      ],
      [
        "the other algorithm's carrier under an ECDH key",
        () => open(rsaBlob, mine.privateKey, "ecdh-p256", { binding: BINDING }),
      ],
      [
        "the other algorithm's carrier under an RSA key",
        () => open(ecdhBlob, rsa.privateKey, "rsa-oaep", { binding: BINDING }),
      ],
      [
        "a wrong private key of the configured type",
        () => open(ecdhBlob, theirs.privateKey, "ecdh-p256", { binding: BINDING }),
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
    // refusal to that one sealed entry.
    const random = seededRandom(SEED);
    const mine = await issuerKeypair();
    const theirs = await issuerKeypair();
    const keyBytes = random.bytes(16);

    const mineBlob = await seal(keyBytes, mine.publicKey, "ecdh-p256", {
      random,
      binding: BINDING,
    });
    const theirsBlob = await seal(keyBytes, theirs.publicKey, "ecdh-p256", {
      random,
      binding: BINDING,
    });

    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    assert.equal(
      mineBlob.length % 4,
      2,
      "the last character of a 97-byte envelope carries four unused bits",
    );
    const tailBits = `${mineBlob.slice(0, -1)}${alphabet[alphabet.indexOf(mineBlob.slice(-1)) | 1]}`;

    // Padding and a last character with its unused bits set follow from the
    // 130-character length, so both of those spellings are here on every
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
        () => open(spelling, mine.privateKey, "ecdh-p256", { binding: BINDING }),
        "unseal_failed",
        why,
      );
    }

    assert.deepEqual(
      await open(theirsBlob, theirs.privateKey, "ecdh-p256", { binding: BINDING }),
      keyBytes,
      "the envelope sealed for another issuer opens as it did",
    );
  });

  test("an opening key that is not what it was configured as is bad_config", async () => {
    const random = seededRandom(SEED);
    const ecdh = await issuerKeypair();
    const rsa = await issuerKeypair("rsa-oaep");
    // P-384 agrees with nothing this format seals to, and the issuer that
    // configured it learns that from the code rather than from a coordinate
    // its readers cannot open.
    const p384 = /** @type {CryptoKeyPair} */ (await generateEcdhKeyPair("P-384"));

    const ecdhBlob = await seal(random.bytes(16), ecdh.publicKey, "ecdh-p256", {
      random,
      binding: BINDING,
    });
    const rsaBlob = await seal(random.bytes(16), rsa.publicKey, "rsa-oaep", { binding: BINDING });

    await refuses(
      () => open(ecdhBlob, rsa.privateKey, "ecdh-p256", { binding: BINDING }),
      "bad_config",
      "an RSA key configured as ECDH-P256",
    );
    await refuses(
      () => open(rsaBlob, ecdh.privateKey, "rsa-oaep", { binding: BINDING }),
      "bad_config",
      "an ECDH key configured as RSA-OAEP",
    );
    await refuses(
      () => open(ecdhBlob, p384.privateKey, "ecdh-p256", { binding: BINDING }),
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
    const rsa = await issuerKeypair("rsa-oaep");
    const ecdhBlob = await seal(random.bytes(16), ecdh.publicKey, "ecdh-p256", {
      random,
      binding: BINDING,
    });
    const rsaBlob = await seal(random.bytes(16), rsa.publicKey, "rsa-oaep", { binding: BINDING });

    await refuses(
      () => open(ecdhBlob, /** @type {any} */ (null), "ecdh-p256", { binding: BINDING }),
      "unseal_failed",
      "a null key under ECDH-P256",
    );
    await refuses(
      () => open(rsaBlob, /** @type {any} */ (null), "rsa-oaep", { binding: BINDING }),
      "unseal_failed",
      "a null key under RSA-OAEP",
    );
  });
});

describe("The canonical payload width", () => {
  const PERIOD_BINDING = { renderId: BINDING.renderId, accessGroup: "premium", t: "251023T1415" };

  test("c, p and pc envelopes all carry 16 bytes in 97-byte ECDH envelopes", async () => {
    const random = seededRandom(SEED);
    const { publicKey, privateKey } = await issuerKeypair();
    const bindings = [
      BINDING,
      PERIOD_BINDING,
      {
        renderId: BINDING.renderId,
        accessGroup: "premium",
        suppliedT: "251023T2345",
        chainKey: true,
        chainsPerDay: 2,
        periodMinutes: 15,
      },
    ];
    for (const binding of bindings) {
      const payload = random.bytes(16);
      const blob = await seal(payload, publicKey, "ecdh-p256", { random, binding });
      assert.equal(base64urlDecode(blob).length, 97);
      assert.equal(blob.length, 130);
      assert.deepEqual(await open(blob, privateKey, "ecdh-p256", { binding }), payload);
    }
  });

  test("payloadBytes is no longer a profile selector", async () => {
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair();
    await refuses(
      () =>
        seal(random.bytes(16), publicKey, "ecdh-p256", {
          random,
          binding: PERIOD_BINDING,
          payloadBytes: 16,
        }),
      { code: "unsupported_option", message: /fixed at 16 bytes/ },
      "a removed payload-width selector",
    );
  });

  // The portable twin of the case above. `payloadBytes` is refused before the
  // key is read.
  portableKeySealingDynamicTest(
    "payloadBytes is no longer a profile selector, under a stand-in key",
    async () => {
      await refuses(
        () =>
          seal(
            SIXTEEN_OCTETS,
            STAND_IN_KEY,
            "ecdh-p256",
            /** @type {any} */ ({ binding: PERIOD_BINDING, payloadBytes: 16 }),
          ),
        { code: "unsupported_option", message: /fixed at 16 bytes/ },
        "a removed payload-width selector",
      );
    },
  );

  test("a 32-byte payload is refused for every sealed-key kind", async () => {
    const random = seededRandom(SEED);
    const { publicKey } = await issuerKeypair();
    await refuses(
      () => seal(random.bytes(32), publicKey, "ecdh-p256", { random, binding: PERIOD_BINDING }),
      { code: "bad_key", message: /exactly 16 .*octets/ },
      "a noncanonical payload",
    );
  });
});
