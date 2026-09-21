// @ts-check
//
// The contract every client-bound profile keeps, run against each profile in
// one list. A profile is one method the issuer may choose for the last hop:
// `seal` at the issuer end turns a client public key into a response-scoped
// sealer, `open` at the client end turns the transport the response carried into
// an opener, and what comes out of the opener is a `CryptoKey` handle whose
// bytes the client cannot read. The claims below are the surface KeyDelivery
// stands on, so they are asserted here once and not re-derived at every actor.
//
// The list contains ECDH-P256 and RSA-OAEP, and the whole contract runs for both
// from the same loop, which tests the interface rather than one method's
// internals.
//
// Every test that draws bytes takes a seeded byte stream of its own, from a seed of its
// own, for the reason crypto-chain.test.js gives: a stream shared at module
// scope makes each test's bytes depend on how many draws ran before it.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import * as ecdhProfile from "../ecdhP256.js";
import * as rsaProfile from "../rsaOaep.js";
import { agreeTransport } from "../core-shared--client-issuer/ecdhP256.js";
import { encrypt, decrypt } from "../../../core-shared/aead.js";
import { base64urlDecode, base64urlEncode } from "../../../core-shared/codec.js";
import { seededRandom } from "../../../test-reference/support/keys.js";

const { subtle } = globalThis.crypto;

/**
 * One client keypair in the shape a request carries it: the private half a
 * handle the client cannot read, the public half an exported JWK.
 *
 * @param {AlgorithmIdentifier|EcKeyGenParams} params
 * @param {KeyUsage[]} usages
 * @returns {Promise<{ privateKey: CryptoKey, publicKeyJwk: JsonWebKey }>}
 */
async function clientKeysOf(params, usages) {
  const pair = /** @type {CryptoKeyPair} */ (await subtle.generateKey(params, false, usages));
  return {
    privateKey: pair.privateKey,
    publicKeyJwk: await subtle.exportKey("jwk", pair.publicKey),
  };
}

/**
 * The two ECDH halves the respelling test seals under, fixed rather than drawn.
 * A 48-byte wrapped blob spells in 64 characters, which takes no padding and
 * leaves no unused bits, so the standard alphabet is the only other spelling of
 * those bytes and a drawn blob whose characters all sit below 62 has none at
 * all. These halves agree the same transport key every run and the wrapping
 * nonce comes off the seeded stream, so the blob and its spelling are fixed:
 * the test asserts the same three facts on every run.
 */
const FIXED_ECDH = {
  client: {
    kty: "EC",
    crv: "P-256",
    x: "4q6v-NEjqqF9BrZkgRQaKNSOkjqWuHRGM5nvlL71EHc",
    y: "6qqKL_xtmKwJBTaIEpul_58ccXEHNDUXTlHq6QpaVk8",
    d: "5NGiWsQXYv7MEj_kaw03AAMwNeCOZktaVLO3ohyQZ1k",
  },
  ephemeral: {
    kty: "EC",
    crv: "P-256",
    x: "4j9IwsTuU2TMkFZ8UtEO6xNQ_084lUpPyPCJjDPdbPs",
    y: "YgFZ1BOliSsAQ_hRMueC7_hJPNlt5rI2SGdoXlppJvI",
    d: "B0OsiweZdx185x6WtCBRsLi6bFpGqKoGJoAurW_XLps",
  },
};

/**
 * One of those halves as a keypair, in the shape `seal` takes for an injected
 * ephemeral pair. The public half is imported extractable because the issuer
 * exports it into the transport it hands the client.
 *
 * @param {{ kty: string, crv: string, x: string, y: string, d: string }} jwk
 */
async function ecdhPairOf(jwk) {
  const publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const params = { name: "ECDH", namedCurve: "P-256" };
  return {
    privateKey: await subtle.importKey("jwk", jwk, params, false, ["deriveKey"]),
    publicKey: await subtle.importKey("jwk", publicKeyJwk, params, true, []),
    publicKeyJwk,
  };
}

/** The RSA client keypair both that profile and its respelling seal take. */
const rsaClientKeys = () =>
  clientKeysOf(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    ["unwrapKey"],
  );

/**
 * A real ECDH transport carrier made below the issuer profile's `wrap` seam.
 * It deliberately authenticates arbitrary plaintext widths so the client
 * opener, rather than the issuer writer, proves its own width admission.
 */
async function ecdhAuthenticatedCarrier() {
  const client = await ecdhPairOf(FIXED_ECDH.client);
  const ephemeral = await ecdhPairOf(FIXED_ECDH.ephemeral);
  const transportKey = await agreeTransport(client.publicKey, ephemeral.privateKey);
  const random = seededRandom(113);
  return {
    privateKey: client.privateKey,
    transport: { publicKey: ephemeral.publicKeyJwk },
    async wrap(payload) {
      const nonce = random.bytes(12);
      return {
        key: base64urlEncode(await encrypt(transportKey, nonce, payload, undefined, 32)),
        nonce: base64urlEncode(nonce),
      };
    },
  };
}

/** Same reader-side probe for the RSA profile, using a genuine OAEP carrier. */
async function rsaAuthenticatedCarrier() {
  const { privateKey, publicKeyJwk } = await rsaClientKeys();
  const { kty, n, e } = publicKeyJwk;
  const peer = await subtle.importKey(
    "jwk",
    { kty, n, e },
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  return {
    privateKey,
    transport: {},
    async wrap(payload) {
      return {
        key: base64urlEncode(
          new Uint8Array(await subtle.encrypt({ name: "RSA-OAEP" }, peer, payload)),
        ),
      };
    },
  };
}

/**
 * The profiles under test. Each says how to make a client keypair for its
 * method, the seal options that method takes, the members its wrap yields, the
 * client keys it refuses at seal, the transports it refuses at open, and the
 * sealer its respelling test wraps under.
 */
const profiles = [
  {
    method: "ECDH-P256",
    randomRequired: true,
    module: ecdhProfile,
    wrapMembers: ["key", "nonce"],
    clientKeys: () => clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]),
    // ECDH draws its wrapping nonces from the seeded byte stream; the sealer refuses none.
    sealOptions: (/** @type {any} */ random) => ({ random }),
    /** @param {JsonWebKey} publicKeyJwk */
    badClientKeys: (publicKeyJwk) => [
      {},
      "not-a-jwk",
      { ...publicKeyJwk, kty: "RSA" },
      { ...publicKeyJwk, crv: "P-384" },
      { ...publicKeyJwk, d: "AAAA" },
    ],
    // The transport shapes a client-bound answer must not open against: the
    // ECDH profile needs the ephemeral public key it was wrapped under.
    missingTransports: [undefined, null, {}, { publicKey: undefined }],
    // Fixed halves at both ends, for the reason FIXED_ECDH gives.
    respellingSeal: async (/** @type {any} */ random) => {
      const client = await ecdhPairOf(FIXED_ECDH.client);
      const ephemeral = await ecdhPairOf(FIXED_ECDH.ephemeral);
      return {
        privateKey: client.privateKey,
        sealer: await ecdhProfile.seal(client.publicKeyJwk, {
          random,
          ephemeralKeyPair: ephemeral,
        }),
      };
    },
    authenticatedCarrier: ecdhAuthenticatedCarrier,
  },
  {
    method: "RSA-OAEP",
    randomRequired: false,
    module: rsaProfile,
    wrapMembers: ["key"],
    clientKeys: rsaClientKeys,
    // RSA wraps straight under the client's public key and draws no wrapping
    // nonce, so its seal takes no options and ignores the seeded stream every
    // profile is offered.
    sealOptions: () => undefined,
    /** @param {JsonWebKey} publicKeyJwk */
    badClientKeys: (publicKeyJwk) => [
      {},
      "not-a-jwk",
      { ...publicKeyJwk, kty: "EC" },
      { ...publicKeyJwk, n: undefined },
      { ...publicKeyJwk, d: "AAAA" },
    ],
    // RSA reads nothing off the transport, since the key opens against the
    // client's private half alone, so no transport shape is refused at open.
    missingTransports: [],
    // A 2048-bit OAEP blob is 256 bytes, 342 characters, so the padding and
    // trailing-bit spellings hold for whatever the draw was and a drawn
    // client keypair does here.
    respellingSeal: async () => {
      const { privateKey, publicKeyJwk } = await rsaClientKeys();
      return { privateKey, sealer: await rsaProfile.seal(publicKeyJwk) };
    },
    authenticatedCarrier: rsaAuthenticatedCarrier,
  },
];

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * One canonical value, spelled every other way that decodes to the same bytes:
 * the standard alphabet, which numbers `-` and `_` the way `+` and `/` are
 * numbered, and where the length leaves unused bits, padding and a last
 * character carrying those bits set. Each of them opens through a lenient
 * decoder, so a delivered leaf respelled this way separates admitting one
 * spelling from admitting any spelling of the same bytes.
 *
 * Which of the three a value has follows from the value: the standard alphabet
 * respells `-` and `_` and needs one of them present, while padding and a
 * trailing-bit character follow from the length alone. Every caller here hands
 * in a value whose spellings are fixed rather than drawn, and the assertion
 * below says so.
 *
 * @param {string} canonical
 * @returns {string[]}
 */
function respellings(canonical) {
  /** @type {string[]} */
  const variants = [];

  if (/[-_]/.test(canonical)) variants.push(canonical.replace(/-/g, "+").replace(/_/g, "/"));
  variants.push(`${canonical}=`);
  if (canonical.length % 4 !== 0) {
    variants.push(
      `${canonical.slice(0, -1)}${ALPHABET[ALPHABET.indexOf(canonical.slice(-1)) | 1]}`,
    );
  }

  assert.ok(
    variants.length > 0,
    `${canonical.length} characters and no other spelling of the same bytes`,
  );
  return variants;
}

for (const profile of profiles) {
  describe(`Client-bound profile: ${profile.method}`, () => {
    test("round-trips one key: seal, wrap 16 bytes, open to a handle with exactly the usages threaded", async () => {
      const random = seededRandom(101);
      const { privateKey, publicKeyJwk } = await profile.clientKeys();

      const sealer = await profile.module.seal(publicKeyJwk, profile.sealOptions(random));
      const keyBytes = random.bytes(16);
      const wrapped = await sealer.wrap(keyBytes);

      for (const usages of [["unwrapKey"], ["decrypt"]]) {
        const opener = await profile.module.open(sealer.transport, privateKey);
        const handle = await opener.open(wrapped, usages);

        assert.ok(handle, "a good wrapped value opens to a handle, not null");
        assert.equal(handle.algorithm.name, "AES-GCM", "the handle is an AES-GCM key");
        assert.equal(handle.algorithm.length, 128, "the handle is an AES-128 key");
        assert.equal(
          handle.extractable,
          false,
          "the handle is non-extractable: the bytes never appear",
        );
        assert.deepEqual(
          [...handle.usages].sort(),
          [...usages].sort(),
          "the handle carries exactly the usages the opener was threaded",
        );
      }
    });

    test("refuses every retired or otherwise wrong delivered-key width before wrapping", async () => {
      const random = {
        calls: 0,
        bytes(n) {
          this.calls++;
          return new Uint8Array(n);
        },
      };
      const { publicKeyJwk } = await profile.clientKeys();
      const sealer = await profile.module.seal(publicKeyJwk, profile.sealOptions(random));

      for (const width of [15, 17, 24, 32]) {
        await assert.rejects(
          () => sealer.wrap(new Uint8Array(width)),
          (/** @type {any} */ error) =>
            error.code === "bad_key" && /exactly 16-byte DCA keys/.test(error.message),
          `${width}-byte delivered material is not a v1 capability`,
        );
      }
      assert.equal(random.calls, 0, "ECDH does not draw a wrap nonce for a rejected payload");

      const wrapped = await sealer.wrap(new Uint8Array(16));
      assert.ok(wrapped.key, "the canonical 16-byte payload remains accepted");
    });

    test("refuses authenticated non-16-byte payloads at the reader seam", async () => {
      const carrier = await profile.authenticatedCarrier();
      const opener = await profile.module.open(carrier.transport, carrier.privateKey);

      for (const usages of [["decrypt"], ["unwrapKey"]]) {
        for (const width of [15, 17, 24, 32]) {
          await assert.rejects(
            () => carrier.wrap(new Uint8Array(width)).then((value) => opener.open(value, usages)),
            (/** @type {any} */ error) => error.code === "unwrap_failed",
            `${width}-byte authenticated delivery is not a v1 ${usages[0]} handle`,
          );
        }

        const handle = await opener.open(await carrier.wrap(new Uint8Array(16)), usages);
        assert.equal(handle.algorithm.name, "AES-GCM");
        assert.equal(handle.algorithm.length, 128, "the canonical carrier still opens to AES-128");
        assert.deepEqual(
          handle.usages,
          usages,
          "the canonical handle retains the requested capability",
        );
      }
    });

    test("the handle is the same key: it decrypts a ciphertext sealed under the raw bytes", async () => {
      const random = seededRandom(102);
      const { privateKey, publicKeyJwk } = await profile.clientKeys();

      const sealer = await profile.module.seal(publicKeyJwk, profile.sealOptions(random));
      const keyBytes = random.bytes(16);
      const wrapped = await sealer.wrap(keyBytes);

      const opener = await profile.module.open(sealer.transport, privateKey);
      const handle = await opener.open(wrapped, ["decrypt"]);

      const message = new Uint8Array([9, 8, 7, 6]);
      const nonce = random.bytes(12);
      const sealed = await encrypt(keyBytes, nonce, message);
      assert.ok(handle);
      assert.deepEqual(
        await decrypt(handle, nonce, sealed),
        message,
        "the opened handle is the very key the issuer wrapped",
      );
    });

    test("rejects a wrong private key and a tampered blob as unwrap_failed", async () => {
      const random = seededRandom(103);
      const { privateKey, publicKeyJwk } = await profile.clientKeys();

      const sealer = await profile.module.seal(publicKeyJwk, profile.sealOptions(random));
      const wrapped = await sealer.wrap(random.bytes(16));

      const other = await profile.clientKeys();
      const wrongOpener = await profile.module.open(sealer.transport, other.privateKey);
      await assert.rejects(
        () => wrongOpener.open(wrapped, ["decrypt"]),
        (/** @type {any} */ err) => err.code === "unwrap_failed",
        "a body wrapped for another client",
      );

      // A tampered blob is the same event: flip one byte of the wrapped
      // key and the auth tag no longer holds, opened with the honest key.
      const bytes = base64urlDecode(wrapped.key);
      bytes[0] ^= 0x01;
      const tampered = { ...wrapped, key: base64urlEncode(bytes) };
      const opener = await profile.module.open(sealer.transport, privateKey);
      await assert.rejects(
        () => opener.open(tampered, ["decrypt"]),
        (/** @type {any} */ err) => err.code === "unwrap_failed",
        "a flipped byte in the wrapped key",
      );
    });

    test("rejects a wrapped key respelled off the canonical alphabet as unwrap_failed", async () => {
      const random = seededRandom(110);
      const { privateKey, sealer } = await profile.respellingSeal(random);

      const wrapped = await sealer.wrap(random.bytes(16));
      const opener = await profile.module.open(sealer.transport, privateKey);

      assert.ok(await opener.open(wrapped, ["decrypt"]), "the control opens");
      for (const spelling of respellings(wrapped.key)) {
        assert.deepEqual(
          base64urlDecode(spelling),
          base64urlDecode(wrapped.key),
          `${JSON.stringify(spelling.slice(-8))} is the same bytes`,
        );
        await assert.rejects(
          () => opener.open({ ...wrapped, key: spelling }, ["decrypt"]),
          (/** @type {any} */ err) => err.code === "unwrap_failed",
          `wrapped key spelled ${JSON.stringify(spelling.slice(-8))}`,
        );
      }
    });

    test("rejects a bad client key at seal as bad_client_key", async () => {
      const random = seededRandom(104);
      const { publicKeyJwk } = await profile.clientKeys();

      for (const bad of profile.badClientKeys(publicKeyJwk)) {
        await assert.rejects(
          () => profile.module.seal(/** @type {any} */ (bad), profile.sealOptions(random)),
          (/** @type {any} */ err) => err.code === "bad_client_key",
          `bad client key ${JSON.stringify(bad)}`,
        );
      }
    });

    test("rejects a missing transport field at open as bad_response", async () => {
      const { privateKey } = await profile.clientKeys();

      for (const transport of profile.missingTransports) {
        await assert.rejects(
          () => profile.module.open(/** @type {any} */ (transport), privateKey),
          (/** @type {any} */ err) => err.code === "bad_response",
          `transport ${JSON.stringify(transport)}`,
        );
      }
    });

    test("surface: method, randomness need, client-key validator, and wrap members are the profile's", async () => {
      const random = seededRandom(105);
      const { publicKeyJwk } = await profile.clientKeys();

      assert.equal(profile.module.METHOD, profile.method, "the profile names its method");
      assert.equal(
        profile.module.RANDOM_REQUIRED,
        profile.randomRequired,
        "the profile tells its issuer host whether sealing needs injected randomness",
      );
      assert.equal(
        typeof profile.module.validateClientKeyPair,
        "function",
        "the profile owns its client-key-pair requirements",
      );

      const sealer = await profile.module.seal(publicKeyJwk, profile.sealOptions(random));
      const wrapped = await sealer.wrap(random.bytes(16));
      assert.deepEqual(
        Object.keys(wrapped).sort(),
        [...profile.wrapMembers].sort(),
        "the wrapped value carries exactly this profile's members",
      );
    });
  });
}

describe("ECDH-P256 public JWK coordinate conformance", () => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  /** @param {string} coordinate */
  function noncanonicalTailBits(coordinate) {
    // A 32-byte coordinate has 43 base64url characters. The last character
    // has four data bits and two padding bits, which must both be zero.
    const last = coordinate.at(-1);
    const index = alphabet.indexOf(/** @type {string} */ (last));
    return `${coordinate.slice(0, -1)}${alphabet[index | 1]}`;
  }

  test("seal rejects padded, whitespace, noncanonical-tail, and wrong-width coordinates as bad_client_key", async () => {
    const { publicKeyJwk } = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, [
      "deriveKey",
    ]);

    for (const coordinate of ["x", "y"]) {
      const value = /** @type {string} */ (/** @type {any} */ (publicKeyJwk)[coordinate]);
      const variants = [`${value}=`, ` ${value}`, noncanonicalTailBits(value), `${value}A`];
      for (const variant of variants) {
        await assert.rejects(
          () =>
            ecdhProfile.seal(
              { ...publicKeyJwk, [coordinate]: variant },
              { random: seededRandom(106) },
            ),
          (/** @type {any} */ err) => err.code === "bad_client_key",
          `${coordinate} variant ${JSON.stringify(variant)}`,
        );
      }
    }
  });

  test("open rejects the same noncanonical coordinate spellings as bad_response", async () => {
    const { privateKey, publicKeyJwk } = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, [
      "deriveKey",
    ]);
    const sealer = await ecdhProfile.seal(publicKeyJwk, { random: seededRandom(107) });

    for (const coordinate of ["x", "y"]) {
      const value = /** @type {string} */ (
        /** @type {any} */ (sealer.transport.publicKey)[coordinate]
      );
      const variants = [`${value}=`, `\n${value}`, noncanonicalTailBits(value), `${value}A`];
      for (const variant of variants) {
        const transport = {
          ...sealer.transport,
          publicKey: { ...sealer.transport.publicKey, [coordinate]: variant },
        };
        await assert.rejects(
          () => ecdhProfile.open(transport, privateKey),
          (/** @type {any} */ err) => err.code === "bad_response",
          `${coordinate} variant ${JSON.stringify(variant)}`,
        );
      }
    }
  });

  test("seal and open reject a canonical-width point that is not on P-256", async () => {
    const { privateKey, publicKeyJwk } = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, [
      "deriveKey",
    ]);
    const zero = base64urlEncode(new Uint8Array(32));
    assert.equal(base64urlDecode(zero).length, 32, "both coordinates pass the wire-width guard");
    const offCurve = { ...publicKeyJwk, x: zero, y: zero };

    await assert.rejects(
      () => ecdhProfile.seal(offCurve, { random: seededRandom(109) }),
      (/** @type {any} */ error) =>
        error.code === "bad_client_key" && /point is not on P-256/.test(error.message),
      "the issuer refuses the client point at WebCrypto import",
    );
    await assert.rejects(
      () => ecdhProfile.open({ publicKey: offCurve }, privateKey),
      (/** @type {any} */ error) =>
        error.code === "bad_response" && /point is not on P-256/.test(error.message),
      "the client refuses the issuer point at WebCrypto import",
    );
  });

  test("a delivered nonce respelled off the canonical alphabet is an unreadable entry", async () => {
    // The ECDH opener answers null for a nonce it cannot read, which is one
    // entry skipped rather than a refusal for the response. Every spelling
    // here decodes to the nonce the issuer wrapped under, so before the
    // named admission rule each of them opened.
    // Seed 112 draws a nonce whose spelling carries a `_`, so the standard
    // alphabet has something to respell.
    const random = seededRandom(112);
    const { privateKey, publicKeyJwk } = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, [
      "deriveKey",
    ]);

    const sealer = await ecdhProfile.seal(publicKeyJwk, { random });
    const wrapped = await sealer.wrap(random.bytes(16));
    const opener = await ecdhProfile.open(sealer.transport, privateKey);

    assert.ok(await opener.open(wrapped, ["decrypt"]), "the control opens");
    for (const spelling of respellings(wrapped.nonce)) {
      assert.equal(
        await opener.open({ ...wrapped, nonce: spelling }, ["decrypt"]),
        null,
        `nonce spelled ${JSON.stringify(spelling)}`,
      );
    }
  });

  test("accepts benign JWK metadata but emits a four-member transport public JWK", async () => {
    const { privateKey, publicKeyJwk } = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, [
      "deriveKey",
    ]);
    const clientWithMetadata = {
      ...publicKeyJwk,
      ext: false,
      key_ops: ["verify"],
      alg: "not-an-ECDH-algorithm",
      unrelated: "ignored",
    };
    const sealer = await ecdhProfile.seal(clientWithMetadata, { random: seededRandom(108) });
    assert.deepEqual(Object.keys(sealer.transport.publicKey).sort(), ["crv", "kty", "x", "y"]);

    const transportWithMetadata = {
      ...sealer.transport,
      publicKey: {
        ...sealer.transport.publicKey,
        ext: false,
        key_ops: ["verify"],
        unrelated: "ignored",
      },
    };
    await assert.doesNotReject(() => ecdhProfile.open(transportWithMetadata, privateKey));
  });
});

// What the RSA profile refuses that has no ECDH twin: keys of the wrong family
// or hash at seal, and a ciphertext of the wrong width at open.
describe("RSA-OAEP profile specifics", () => {
  test("admits only canonical Base64urlUInt modulus and exponent members", async () => {
    const { publicKeyJwk } = await rsaClientKeys();

    for (const member of ["n", "e"]) {
      const value = /** @type {string} */ (/** @type {any} */ (publicKeyJwk)[member]);
      const leadingZero = base64urlEncode(new Uint8Array([0, ...base64urlDecode(value)]));
      for (const variant of [`${value}=`, leadingZero]) {
        await assert.rejects(
          () => rsaProfile.seal({ ...publicKeyJwk, [member]: variant }),
          (/** @type {any} */ error) => error.code === "bad_client_key",
          `${member} variant ${JSON.stringify(variant)}`,
        );
      }
    }
  });

  test("admits an odd exponent of at least 3, including the common 65537 exponent", async () => {
    const { publicKeyJwk } = await rsaClientKeys();
    assert.equal(publicKeyJwk.e, "AQAB", "the generated control uses exponent 65537");
    await assert.doesNotReject(() => rsaProfile.seal(publicKeyJwk));

    const beyondSafeInteger = base64urlEncode(new Uint8Array([0x20, 0, 0, 0, 0, 0, 0, 1]));
    assert.ok(0x2000000000000001n > BigInt(Number.MAX_SAFE_INTEGER));
    await assert.doesNotReject(
      () => rsaProfile.seal({ ...publicKeyJwk, e: beyondSafeInteger }),
      "an odd Base64urlUInt is admitted without lossy Number conversion",
    );

    for (const exponent of [1, 2, 4]) {
      const e = base64urlEncode(new Uint8Array([exponent]));
      await assert.rejects(
        () => rsaProfile.seal({ ...publicKeyJwk, e }),
        (/** @type {any} */ error) => error.code === "bad_client_key",
        `exponent ${exponent}`,
      );
    }
  });

  test("admits empty key_ops from an unwrapKey-only public export, but rejects incompatible metadata and private RSA members", async () => {
    const { publicKeyJwk } = await rsaClientKeys();
    assert.deepEqual(
      publicKeyJwk.key_ops,
      [],
      "Node exports an unwrapKey-only pair public JWK with empty key_ops",
    );
    const emptyKeyOps = await rsaProfile.seal(publicKeyJwk);
    assert.ok(
      (await emptyKeyOps.wrap(new Uint8Array(16))).key,
      "the exported public JWK remains a usable issuer wrapping offer",
    );
    const { key_ops: ignoredKeyOps, ...withoutKeyOps } = publicKeyJwk;
    assert.deepEqual(
      ignoredKeyOps,
      [],
      "the control proves omission is distinct from Node’s empty export",
    );
    await assert.doesNotReject(
      () => rsaProfile.seal(withoutKeyOps),
      "key_ops is optional in the RSA client offer",
    );
    for (const key_ops of [["encrypt"], ["wrapKey"], ["encrypt", "wrapKey"]]) {
      await assert.doesNotReject(
        () => rsaProfile.seal({ ...publicKeyJwk, key_ops }),
        `issuer-compatible key_ops ${JSON.stringify(key_ops)}`,
      );
    }

    const incompatible = [
      { alg: "RSA-OAEP" },
      { alg: 7 },
      { use: "sig" },
      { ext: "false" },
      { key_ops: ["verify"] },
      { key_ops: ["unwrapKey"] },
    ];
    for (const metadata of incompatible) {
      await assert.rejects(
        () => rsaProfile.seal({ ...publicKeyJwk, ...metadata }),
        (/** @type {any} */ error) => error.code === "bad_client_key",
        `metadata ${JSON.stringify(metadata)}`,
      );
    }
    const wrapKeyOnly = await rsaProfile.seal({
      ...publicKeyJwk,
      alg: "RSA-OAEP-256",
      use: "enc",
      ext: false,
      key_ops: ["wrapKey"],
    });
    assert.ok(
      (await wrapKeyOnly.wrap(new Uint8Array(16))).key,
      "wrapKey-only metadata is admitted then sanitized for the issuer encryption primitive",
    );

    for (const member of ["d", "p", "q", "dp", "dq", "qi", "oth"]) {
      await assert.rejects(
        () => rsaProfile.seal({ ...publicKeyJwk, [member]: "AA" }),
        (/** @type {any} */ error) => error.code === "bad_client_key",
        `private member ${member}`,
      );
    }
  });

  test("rejects a genuine EC key offered to the RSA seal as bad_client_key", async () => {
    const { publicKeyJwk } = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, [
      "deriveBits",
    ]);

    await assert.rejects(
      () => rsaProfile.seal(/** @type {any} */ (publicKeyJwk)),
      (/** @type {any} */ err) => err.code === "bad_client_key",
      "an EC public key is not an RSA-OAEP one",
    );
  });

  test("rejects an RSA key built for another OAEP hash as bad_client_key", async () => {
    // The data format fixes RSA-OAEP to SHA-256, and the JWK carries its
    // hash in `alg` ('RSA-OAEP' is SHA-1). The seal forces SHA-256, so a
    // SHA-1 key fails the import as a stated refusal.
    const { publicKeyJwk } = await clientKeysOf(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-1",
      },
      ["unwrapKey"],
    );
    assert.equal(publicKeyJwk.alg, "RSA-OAEP", "the SHA-1 key names its hash in alg");

    await assert.rejects(
      () => rsaProfile.seal(/** @type {any} */ (publicKeyJwk)),
      (/** @type {any} */ err) => err.code === "bad_client_key",
      "a SHA-1 OAEP key is not the SHA-256 the format fixes",
    );
  });

  test("rejects an RSA key under the 2048-bit floor as bad_client_key", async () => {
    // A 1024-bit key imports and wraps, so the floor is the profile's to
    // enforce: it turns a too-narrow modulus into a stated refusal.
    const { publicKeyJwk } = await clientKeysOf(
      {
        name: "RSA-OAEP",
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      ["unwrapKey"],
    );

    await assert.rejects(
      () => rsaProfile.seal(/** @type {any} */ (publicKeyJwk)),
      (/** @type {any} */ err) => err.code === "bad_client_key",
      "a 1024-bit modulus is under the floor",
    );

    const { publicKeyJwk: fullWidth } = await rsaClientKeys();
    const shortBits = base64urlDecode(/** @type {string} */ (fullWidth.n));
    shortBits[0] = 0x7f;
    assert.equal(shortBits.length, 256, "the regression stays one RSA-2048 byte width");
    await assert.rejects(
      () => rsaProfile.seal({ ...fullWidth, n: base64urlEncode(shortBits) }),
      (/** @type {any} */ err) => err.code === "bad_client_key",
      "a 256-byte modulus with only 2047 significant bits is under the floor",
    );
  });

  test("rejects a ciphertext of the wrong modulus width at open as unwrap_failed", async () => {
    const random = seededRandom(201);
    const { privateKey, publicKeyJwk } = await clientKeysOf(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      ["unwrapKey"],
    );

    const sealer = await rsaProfile.seal(publicKeyJwk);
    const wrapped = await sealer.wrap(random.bytes(16));

    // One byte wider than a 2048-bit modulus: WebCrypto cannot open it, and
    // the profile turns that into its one padding failure.
    const widened = new Uint8Array([...base64urlDecode(wrapped.key), 0]);
    const opener = await rsaProfile.open(sealer.transport, privateKey);
    await assert.rejects(
      () => opener.open({ key: base64urlEncode(widened) }, ["decrypt"]),
      (/** @type {any} */ err) => err.code === "unwrap_failed",
      "a blob one byte too wide for the modulus",
    );
  });
});
