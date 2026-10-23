// @ts-check
//
// Construction and response-method admission for the client-bound capability
// that keeps a client private key handle in the adapter.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import * as ecdhProfile from "../ecdhP256.js";
import * as rsaProfile from "../rsaOaep.js";
import { clientBoundKeyCapability } from "../core-client/clientBoundKeyCapability.js";
import { createBrowserClient } from "../../../integration-client/createBrowserClient.js";
import { writeMarkupDelivery } from "../../../adapter-publisher/writeMarkupDelivery.js";
import { domOver } from "../../../test-lib/helpers/domOver.js";
import { encrypt } from "../../../core-shared/aead.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";
import { contentKeyWrapNonceOctets } from "../../../test-reference/support/contentKeyWrapNonceOctets.js";
import { base64urlEncode, utf8Encode, utf8Decode } from "../../../core-shared/codec.js";
import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";

const { subtle } = globalThis.crypto;

/** The private JWK members (RFC 7518 Section 6) that never reach a request. */
const PRIVATE_JWK_MEMBERS = ["d", "k", "p", "q", "dp", "dq", "qi", "oth"];

const chainConfig = {
  chainCache: {},
  chainKeyProfile: {
    constructionProfile: { name: "test-chain", constructionId: "test", chainKeyBytes: 16 },
    parametersForResponse() {},
    candidateSourceFor() {
      return {
        attempts() {
          return [];
        },
      };
    },
    acceptsPeriodKeyResponseCoordinate() {},
    acceptsResponseCoordinate() {},
  },
};

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

describe("Client-bound capability response admission", () => {
  test("the capability refuses a body wrapped by another method as bad_response", async () => {
    // An RSA client hands the capability the RSA profile. A body tagged
    // ECDH-P256 is one it cannot open, and the method check catches it before
    // the private half is reached for.
    const { privateKey, publicKeyJwk } = await clientKeysOf(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      ["unwrapKey"],
    );
    const capability = clientBoundKeyCapability(
      { privateKey, publicKey: publicKeyJwk },
      rsaProfile,
    );

    await assert.rejects(
      async () => capability.openDeliveredKeys({ method: "ECDH-P256", publicKey: {} }),
      (/** @type {any} */ err) => err.code === "bad_response",
      "an ECDH-tagged body on an RSA client",
    );
    for (const transport of [null, {}, { method: "unknown-method" }]) {
      await assert.rejects(
        async () => capability.openDeliveredKeys(transport),
        (/** @type {any} */ err) => err.code === "bad_response",
        "a missing or unknown method never infers the selected profile",
      );
    }
  });

  for (const profile of [ecdhProfile, rsaProfile]) {
    test(`${profile.METHOD} opens authentic keys without a transport mode`, async () => {
      const ec = profile === ecdhProfile;
      const keys = await clientKeysOf(
        ec
          ? { name: "ECDH", namedCurve: "P-256" }
          : {
              name: "RSA-OAEP",
              modulusLength: 2048,
              publicExponent: new Uint8Array([1, 0, 1]),
              hash: "SHA-256",
            },
        ec ? ["deriveKey"] : ["unwrapKey", "decrypt"],
      );
      const capability = clientBoundKeyCapability(
        { privateKey: keys.privateKey, publicKey: keys.publicKeyJwk },
        profile,
      );
      const sealer = await profile.seal(keys.publicKeyJwk, {
        random: { bytes: (n) => new Uint8Array(n).fill(17) },
      });
      const bytes = new Uint8Array(16).fill(31);
      const wrapped = await sealer.wrap(bytes, "chainKey");
      const transport = { ...sealer.transport, method: profile.METHOD };
      assert.equal(Object.hasOwn(transport, "mode"), false);
      for (const admitted of [transport, { ...transport, mode: "unknown-extra" }]) {
        const opener = await capability.openDeliveredKeys(admitted);
        assert.deepEqual(await opener.open(wrapped, [], "chainKey"), bytes);
        await assert.rejects(
          () => opener.open(wrapped, ["decrypt"], "contentKey"),
          (/** @type {any} */ error) => error.code === "unwrap_failed",
          "omitting the transport mode preserves key-kind binding",
        );
      }
      for (const method of [undefined, "unknown-method", ec ? "RSA-OAEP" : "ECDH-P256"]) {
        const refused = { ...sealer.transport, ...(method === undefined ? {} : { method }) };
        await assert.rejects(
          async () => capability.openDeliveredKeys(refused),
          (/** @type {any} */ error) => error.code === "bad_response",
        );
      }
    });
  }
});

describe("Honest client-bound capability construction", () => {
  test("chain setup requires RSA decrypt while period-key-only RSA and ECDH remain usable", async () => {
    const rsaParams = {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    };
    const unwrapOnly = await clientKeysOf(rsaParams, ["unwrapKey"]);
    const periodKeyCapability = clientBoundKeyCapability(
      { privateKey: unwrapOnly.privateKey, publicKey: unwrapOnly.publicKeyJwk },
      rsaProfile,
    );
    assert.doesNotThrow(
      () => new ContentKeyResolver({ clientBoundKeyCapability: periodKeyCapability }),
    );
    assert.throws(
      () =>
        new ContentKeyResolver({ ...chainConfig, clientBoundKeyCapability: periodKeyCapability }),
      (/** @type {any} */ error) =>
        error.code === "bad_config" && /decrypt usage/.test(error.message),
    );

    const rsaChainPair = await clientKeysOf(rsaParams, ["unwrapKey", "decrypt"]);
    const rsaChainCapability = clientBoundKeyCapability(
      { privateKey: rsaChainPair.privateKey, publicKey: rsaChainPair.publicKeyJwk },
      rsaProfile,
    );
    assert.doesNotThrow(
      () =>
        new ContentKeyResolver({ ...chainConfig, clientBoundKeyCapability: rsaChainCapability }),
    );

    const ec = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]);
    const ecCapability = clientBoundKeyCapability(
      { privateKey: ec.privateKey, publicKey: ec.publicKeyJwk },
      ecdhProfile,
    );
    assert.doesNotThrow(
      () => new ContentKeyResolver({ ...chainConfig, clientBoundKeyCapability: ecCapability }),
    );
  });

  test("chain admission rejects absent and asynchronous profile hooks during setup", async () => {
    const pair = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]);
    const keyPair = { privateKey: pair.privateKey, publicKey: pair.publicKeyJwk };
    for (const hook of [undefined, async () => {}, () => ({ then() {} })]) {
      const profile = {
        METHOD: "example/v1",
        validateClientKeyPair() {},
        publicKeyForOffer(publicKey) {
          return publicKey;
        },
        ...(hook === undefined ? {} : { assertCanOpenChainKeys: hook }),
        async open() {
          return {
            async open() {
              return null;
            },
          };
        },
      };
      const capability = clientBoundKeyCapability(keyPair, profile);
      assert.doesNotThrow(() => new ContentKeyResolver({ clientBoundKeyCapability: capability }));
      assert.throws(
        () => new ContentKeyResolver({ ...chainConfig, clientBoundKeyCapability: capability }),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
  });

  test("composed raw kinds need a synchronous raw-key hook at setup; handle kinds do not", async () => {
    const rawKinds = ecdhProfile.settleKindDescriptors({ rawKind: { width: 16, open: "raw" } });
    const handleKinds = ecdhProfile.settleKindDescriptors({
      handleKind: { width: 16, open: "aesHandle" },
    });
    const unwrapOnly = await clientKeysOf(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      ["unwrapKey"],
    );
    const rsaKeyPair = { privateKey: unwrapOnly.privateKey, publicKey: unwrapOnly.publicKeyJwk };
    assert.doesNotThrow(
      () => clientBoundKeyCapability(rsaKeyPair, rsaProfile, { composedKinds: handleKinds }),
      "an unwrap-only RSA key opens composed handle kinds",
    );
    assert.throws(
      () => clientBoundKeyCapability(rsaKeyPair, rsaProfile, { composedKinds: rawKinds }),
      (/** @type {any} */ error) => error.code === "bad_config",
      "an unwrap-only RSA key cannot open composed raw kinds",
    );

    const pair = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]);
    const keyPair = { privateKey: pair.privateKey, publicKey: pair.publicKeyJwk };
    /** @param {any} hook */
    const profileWith = (hook) => ({
      METHOD: "example/v1",
      validateClientKeyPair() {},
      publicKeyForOffer(publicKey) {
        return publicKey;
      },
      ...(hook === undefined ? {} : { assertCanOpenRawKeys: hook }),
      async open() {
        return {
          async open() {
            return null;
          },
        };
      },
    });
    for (const hook of [undefined, async () => {}, () => ({ then() {} })]) {
      assert.doesNotThrow(() =>
        clientBoundKeyCapability(keyPair, profileWith(hook), { composedKinds: handleKinds }),
      );
      assert.throws(
        () => clientBoundKeyCapability(keyPair, profileWith(hook), { composedKinds: rawKinds }),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
    for (const hook of [() => undefined, () => null]) {
      assert.doesNotThrow(() =>
        clientBoundKeyCapability(keyPair, profileWith(hook), { composedKinds: rawKinds }),
      );
    }
    assert.throws(
      () =>
        clientBoundKeyCapability(
          keyPair,
          ecdhProfile,
          /** @type {any} */ ({ composedKind: rawKinds }),
        ),
      (/** @type {any} */ error) => error.code === "unsupported_option",
      "a misspelt option is refused, not run as an empty composed set",
    );
  });

  test("refuses an extractable private handle and a public JWK carrying private material", async () => {
    const pair = /** @type {CryptoKeyPair} */ (
      await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"])
    );
    const publicKey = await subtle.exportKey("jwk", pair.publicKey);
    let validations = 0;
    const observedEcdhProfile = {
      METHOD: ecdhProfile.METHOD,
      validateClientKeyPair(keyPair) {
        validations++;
        return ecdhProfile.validateClientKeyPair(keyPair);
      },
      publicKeyForOffer: ecdhProfile.publicKeyForOffer,
      open: ecdhProfile.open,
    };

    assert.throws(
      () =>
        clientBoundKeyCapability({ privateKey: pair.privateKey, publicKey }, observedEcdhProfile),
      (/** @type {any} */ error) => error.code === "bad_config",
      "an extractable client private key contradicts the capability claim",
    );
    assert.equal(validations, 0, "an extractable handle stops before profile validation");

    const honest = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]);
    for (const member of PRIVATE_JWK_MEMBERS) {
      assert.throws(
        () =>
          clientBoundKeyCapability(
            {
              privateKey: honest.privateKey,
              publicKey: { ...honest.publicKeyJwk, [member]: "not-a-secret" },
            },
            observedEcdhProfile,
          ),
        (/** @type {any} */ error) => error.code === "bad_config",
        `a request public key must not accidentally contain private member ${member}`,
      );
    }
    assert.equal(validations, 0, "private JWK material stops before profile validation");
  });

  test("requires the private key, public JWK, and usages to match the selected profile", async () => {
    const ec = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]);
    const rsa = await clientKeysOf(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      ["unwrapKey"],
    );
    const ecWrongUsage = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, ["deriveBits"]);
    const rsaWrongUsage = await clientKeysOf(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      ["decrypt"],
    );

    const weakRsa = await clientKeysOf(
      {
        name: "RSA-OAEP",
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      ["unwrapKey"],
    );

    const sha1Rsa = await clientKeysOf(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-1",
      },
      ["unwrapKey"],
    );

    for (const [pair, profile, label] of [
      // A valid public offer must not hide an undersized native private key.
      [
        { privateKey: weakRsa.privateKey, publicKeyJwk: rsa.publicKeyJwk },
        rsaProfile,
        "RSA private key under 2048 bits beside a valid public offer",
      ],
      // Response binding Section 8 fixes the client RSA-OAEP key to SHA-256.
      [
        { privateKey: sha1Rsa.privateKey, publicKeyJwk: rsa.publicKeyJwk },
        rsaProfile,
        "RSA-OAEP SHA-1 private key beside a valid public offer",
      ],
      [ec, rsaProfile, "ECDH keypair with RSA profile"],
      [rsa, ecdhProfile, "RSA keypair with ECDH profile"],
      [ecWrongUsage, ecdhProfile, "ECDH keypair lacking deriveKey"],
      [rsaWrongUsage, rsaProfile, "RSA keypair lacking unwrapKey"],
    ]) {
      let validations = 0;
      const observedProfile = {
        METHOD: /** @type {any} */ (profile).METHOD,
        validateClientKeyPair(keyPair) {
          validations++;
          return /** @type {any} */ (profile).validateClientKeyPair(keyPair);
        },
        publicKeyForOffer: /** @type {any} */ (profile).publicKeyForOffer,
        open: /** @type {any} */ (profile).open,
      };
      assert.throws(
        () =>
          clientBoundKeyCapability(
            {
              privateKey: /** @type {any} */ (pair).privateKey,
              publicKey: /** @type {any} */ (pair).publicKeyJwk,
            },
            observedProfile,
          ),
        (/** @type {any} */ error) => error.code === "bad_config",
        label,
      );
      assert.equal(validations, 1, `${label} reaches the selected profile validator once`);
    }
  });

  test("accepts an injected profile that owns its own key requirements", async () => {
    const pair = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]);
    /** @type {Array<{ privateKey: CryptoKey, publicKey: JsonWebKey }>} */
    const validated = [];
    let opens = 0;
    const profile = {
      METHOD: "example-profile/v1",
      validateClientKeyPair(keyPair) {
        validated.push(keyPair);
      },
      publicKeyForOffer(publicKey) {
        return publicKey;
      },
      async open() {
        opens++;
        return {
          async open() {
            return null;
          },
        };
      },
    };

    const capability = clientBoundKeyCapability(
      { privateKey: pair.privateKey, publicKey: pair.publicKeyJwk },
      profile,
    );
    assert.notEqual(
      capability.publicKey,
      pair.publicKeyJwk,
      "the offer is detached from the source JWK",
    );
    assert.deepEqual(capability.publicKey, pair.publicKeyJwk, "the profile controls offer members");
    assert.deepEqual(
      validated,
      [{ privateKey: pair.privateKey, publicKey: pair.publicKeyJwk }],
      "the injected profile, not a method allowlist, validates the exact pair",
    );
    await capability.openDeliveredKeys({ method: profile.METHOD });
    assert.equal(
      opens,
      1,
      "the injected profile opener remains the one the capability delegates to",
    );
  });

  test("requires a synchronous profile validator and never opens after validator refusal", async () => {
    const pair = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]);
    const keyPair = { privateKey: pair.privateKey, publicKey: pair.publicKeyJwk };
    const open = async () => ({
      async open() {
        return null;
      },
    });

    for (const profile of [
      { METHOD: "missing-validator/v1", publicKeyForOffer: () => keyPair.publicKey, open },
      {
        METHOD: "nonfunction-validator/v1",
        validateClientKeyPair: true,
        publicKeyForOffer: () => keyPair.publicKey,
        open,
      },
    ]) {
      assert.throws(
        () => clientBoundKeyCapability(keyPair, /** @type {any} */ (profile)),
        (/** @type {any} */ error) => error.code === "bad_config",
        "a profile must provide a validator function",
      );
    }

    for (const validateClientKeyPair of [async () => {}, () => ({ then() {} })]) {
      assert.throws(
        () =>
          clientBoundKeyCapability(
            keyPair,
            /** @type {any} */ ({
              METHOD: "async-validator/v1",
              validateClientKeyPair,
              publicKeyForOffer: () => keyPair.publicKey,
              open,
            }),
          ),
        (/** @type {any} */ error) => error.code === "bad_config",
        "the validator cannot defer its decision past capability construction",
      );
    }

    let opens = 0;
    const refusal = new Error("profile key mismatch");
    assert.throws(
      () =>
        clientBoundKeyCapability(keyPair, {
          METHOD: "refusing-validator/v1",
          validateClientKeyPair() {
            throw refusal;
          },
          publicKeyForOffer: () => keyPair.publicKey,
          async open() {
            opens++;
            return {
              async open() {
                return null;
              },
            };
          },
        }),
      (error) => error === refusal,
      "the profile validator owns its mismatch refusal",
    );
    assert.equal(opens, 0, "a refusing validator stops before the opener is available");
  });

  test("captures a detached offer from a synchronous profile-owned hook", async () => {
    const pair = await clientKeysOf({ name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]);
    const source = { ...pair.publicKeyJwk, key_ops: ["verify"] };
    const offered = {
      kty: "CUSTOM",
      marker: "captured",
      key_ops: ["custom-op"],
      metadata: { nested: ["kept", { level: 2 }] },
    };
    let calls = 0;
    const profile = {
      METHOD: "custom/v1",
      validateClientKeyPair() {},
      publicKeyForOffer(publicKey) {
        calls++;
        assert.equal(publicKey, source);
        return offered;
      },
      async open() {
        return {
          async open() {
            return null;
          },
        };
      },
    };
    const capability = clientBoundKeyCapability(
      { privateKey: pair.privateKey, publicKey: source },
      profile,
    );
    assert.equal(calls, 1);
    offered.marker = "mutated";
    offered.key_ops.push("mutated");
    offered.metadata.nested[1].level = 3;
    source.marker = "source mutation";
    assert.deepEqual(capability.publicKey, {
      kty: "CUSTOM",
      marker: "captured",
      key_ops: ["custom-op"],
      metadata: { nested: ["kept", { level: 2 }] },
    });

    // Legal JSON shapes the snapshot keeps: null, a long array, null-prototype
    // records and one object reached twice without a cycle.
    const shared = { level: 1 };
    const legal = Object.assign(Object.create(null), {
      kty: "CUSTOM",
      empty: null,
      long: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
      record: Object.assign(Object.create(null), { kept: true }),
      first: shared,
      second: shared,
    });
    assert.deepEqual(
      clientBoundKeyCapability(
        { privateKey: pair.privateKey, publicKey: pair.publicKeyJwk },
        { ...profile, publicKeyForOffer: () => legal },
      ).publicKey,
      {
        kty: "CUSTOM",
        empty: null,
        long: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        record: { kept: true },
        first: { level: 1 },
        second: { level: 1 },
      },
    );

    const badHooks = [
      undefined,
      true,
      async () => ({ kty: "CUSTOM" }),
      () => ({ kty: "CUSTOM", then() {} }),
      ...PRIVATE_JWK_MEMBERS.map((member) => () => ({ kty: "CUSTOM", [member]: "private" })),
      () => Object.create({ kty: "CUSTOM" }),
      () => ({ kty: "CUSTOM", invalid: undefined }),
      () => ({ kty: "CUSTOM", invalid: Number.NaN }),
      () => ({ kty: "CUSTOM", invalid: Symbol("no-json") }),
    ];
    for (const publicKeyForOffer of badHooks) {
      assert.throws(
        () =>
          clientBoundKeyCapability(
            { privateKey: pair.privateKey, publicKey: pair.publicKeyJwk },
            {
              METHOD: "bad-offer/v1",
              validateClientKeyPair() {},
              publicKeyForOffer,
              async open() {
                return {
                  async open() {
                    return null;
                  },
                };
              },
            },
          ),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
    const cyclic = { kty: "CUSTOM" };
    cyclic.metadata = cyclic;
    assert.throws(
      () =>
        clientBoundKeyCapability(
          { privateKey: pair.privateKey, publicKey: pair.publicKeyJwk },
          { ...profile, publicKeyForOffer: () => cyclic },
        ),
      (/** @type {any} */ error) => error.code === "bad_config",
      "cyclic offer values are not JSON-compatible",
    );

    assert.throws(
      () =>
        clientBoundKeyCapability(
          {
            privateKey: pair.privateKey,
            publicKey: { ...pair.publicKeyJwk, x: "not-canonical" },
          },
          ecdhProfile,
        ),
      (/** @type {any} */ error) => error.code === "bad_config",
      "ECDH offer construction rejects noncanonical coordinates without claiming point validation",
    );
  });
});

for (const profile of [ecdhProfile, rsaProfile]) {
  for (const boundary of ["session", "key"]) {
    for (const kind of ["contentKey", "periodKey"]) {
      test(`${profile.METHOD} reader reset fences a delayed ${boundary} carrying ${kind} handles`, async () => {
        const params =
          profile === ecdhProfile
            ? { name: "ECDH", namedCurve: "P-256" }
            : {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
              };
        const pair = await clientKeysOf(
          params,
          profile === ecdhProfile ? ["deriveKey"] : ["unwrapKey"],
        );
        const capability = clientBoundKeyCapability(
          { privateKey: pair.privateKey, publicKey: pair.publicKeyJwk },
          profile,
        );
        const publisher = "https://publisher.example",
          issuer = "issuer",
          group = "premium",
          t = "251023T1400";
        const key = new Uint8Array(16).fill(30),
          period = new Uint8Array(16).fill(31),
          nonce = new Uint8Array(12).fill(19);
        const resource = {
          origin: publisher,
          resourceId: "article",
          renderId: "AAAAAAAAAAAAAAAAAAAAAA",
        };
        const encode = (value) => base64urlEncode(utf8Encode(JSON.stringify(value)));
        const raw = {
          version: "1",
          resource,
          resourceJWT: `${encode({ alg: "ES256", kid: "signer" })}.${encode(resource)}.c2ln`,
          issuerData: [
            {
              issuerName: issuer,
              keyId: "key",
              sealed: {
                contentKeys: [{ contentName: "a", key: "AA" }],
                ...(kind === "periodKey"
                  ? { periodKeys: [{ accessGroup: group, period: t, key: "AA" }] }
                  : {}),
              },
            },
          ],
          contentData: [
            {
              contentName: "a",
              contentType: "text/plain",
              nonce: base64urlEncode(nonce),
              ...(kind === "periodKey"
                ? {
                    keys: [
                      {
                        accessGroup: group,
                        period: t,
                        key: base64urlEncode(
                          await encrypt(
                            period,
                            contentKeyWrapNonceOctets({
                              renderId: resource.renderId,
                              contentName: "a",
                              accessGroup: group,
                              t,
                            }),
                            key,
                          ),
                        ),
                      },
                    ],
                  }
                : {}),
            },
          ],
        };
        const markup = writeMarkupDelivery({
          dcaData: raw,
          sealedContent: {
            a: base64urlEncode(
              await encrypt(
                key,
                new Uint8Array(12),
                utf8Encode("opened"),
                contentAadOctets(raw, "a"),
              ),
            ),
          },
        });
        let entered, release;
        const started = new Promise((resolve) => {
          entered = resolve;
        });
        const gate = new Promise((resolve) => {
          release = resolve;
        });
        let paused = false;
        const pause = async () => {
          if (!paused) {
            paused = true;
            entered();
            await gate;
          }
        };
        const selected = {
          publicKey: capability.publicKey,
          async openDeliveredKeys(transport) {
            const opener = await capability.openDeliveredKeys(transport);
            if (boundary === "session") await pause();
            return {
              async open(...args) {
                const handle = await opener.open(...args);
                assert.ok(handle instanceof CryptoKey);
                assert.equal(handle.extractable, false);
                if (boundary === "key") await pause();
                return handle;
              },
            };
          },
        };
        const client = createBrowserClient({
          root: domOver(markup, { publisherOrigin: publisher }),
          issuerName: issuer,
          unlockUrl: "https://issuer.example/unlock",
          clientBoundKeyCapability: selected,
          relayPeriodKeys: true,
          transport: {
            async post() {
              const sealer = await profile.seal(pair.publicKeyJwk, {
                random: { bytes: (n) => crypto.getRandomValues(new Uint8Array(n)) },
              });
              const value = await sealer.wrap(kind === "contentKey" ? key : period, kind);
              return {
                status: 200,
                contentType: "application/json",
                body: {
                  transport: { method: profile.METHOD, ...sealer.transport },
                  keys:
                    kind === "contentKey"
                      ? { contentKeys: [{ contentName: "a", key: value }] }
                      : { periodKeys: [{ accessGroup: group, period: t, key: value }] },
                },
              };
            },
          },
        });
        const old = assert.rejects(client.open("a"), { code: "context_retired" });
        await started;
        await client.clearReaderContext();
        assert.equal(await client.resolver.contentKeyFor(client.dcaData, "a"), null);
        release();
        await old;
        await assert.rejects(client.openLocal("a"), { code: "no_key" });
        assert.deepEqual(await client.cache.entries(), []);
        assert.equal(
          utf8Decode((await client.open("a")).bytes),
          "opened",
          "configured recipient keypair remains usable",
        );
        await client.clearReaderContext();
        await assert.rejects(client.openLocal("a"), { code: "no_key" });
      });
    }
  }
}

test("exported stock offer helpers reject private material and project only public members", async () => {
  for (const [profile, algorithm, usages] of [
    [ecdhProfile, { name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]],
    [
      rsaProfile,
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      ["encrypt", "decrypt"],
    ],
  ]) {
    const pair = await subtle.generateKey(algorithm, true, usages);
    const publicKey = await subtle.exportKey("jwk", pair.publicKey);
    const privateKey = await subtle.exportKey("jwk", pair.privateKey);
    delete privateKey.key_ops;
    for (const value of [null, undefined, true, "key", [], privateKey]) {
      assert.throws(() => profile.publicKeyForOffer(value), { code: "bad_config" });
    }
    for (const member of PRIVATE_JWK_MEMBERS) {
      assert.throws(() => profile.publicKeyForOffer({ ...publicKey, [member]: "private" }), {
        code: "bad_config",
      });
    }
    const offered = profile.publicKeyForOffer({ ...publicKey, hostNote: "not offered" });
    const allowed =
      profile === rsaProfile
        ? ["kty", "n", "e", "alg", "use", "ext", "key_ops"]
        : ["kty", "crv", "x", "y"];
    assert.ok(Object.keys(offered).every((member) => allowed.includes(member)));
    if (profile === rsaProfile) {
      assert.deepEqual(offered.key_ops, publicKey.key_ops);
      assert.notEqual(offered.key_ops, publicKey.key_ops);
      assert.equal(offered.n, publicKey.n);
    } else assert.equal(offered.x, publicKey.x);
  }
});
