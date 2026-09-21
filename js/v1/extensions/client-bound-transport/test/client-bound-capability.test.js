// @ts-check
//
// Construction and response-method admission for the client-bound capability
// that keeps a client private key handle in the adapter.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import * as ecdhProfile from "../ecdhP256.js";
import * as rsaProfile from "../rsaOaep.js";
import { clientBoundKeyCapability } from "../core-client/clientBoundKeyCapability.js";

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
      async () =>
        capability.openDeliveredKeys({ mode: "client-bound", method: "ECDH-P256", publicKey: {} }),
      (/** @type {any} */ err) => err.code === "bad_response",
      "an ECDH-tagged body on an RSA client",
    );
    await assert.rejects(
      async () => capability.openDeliveredKeys({ mode: "direct", method: "RSA-OAEP" }),
      (/** @type {any} */ err) => err.code === "bad_response",
      "the selected method cannot make a non-client-bound mode usable",
    );
  });
});

describe("Honest client-bound capability construction", () => {
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
    assert.throws(
      () =>
        clientBoundKeyCapability(
          {
            privateKey: honest.privateKey,
            publicKey: { ...honest.publicKeyJwk, d: "not-a-secret" },
          },
          observedEcdhProfile,
        ),
      (/** @type {any} */ error) => error.code === "bad_config",
      "a request public key must not accidentally contain a private scalar",
    );
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

    for (const [pair, profile, label] of [
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
    assert.equal(
      capability.publicKey,
      pair.publicKeyJwk,
      "the generic capability preserves the profile public JWK",
    );
    assert.deepEqual(
      validated,
      [{ privateKey: pair.privateKey, publicKey: pair.publicKeyJwk }],
      "the injected profile, not a method allowlist, validates the exact pair",
    );
    await capability.openDeliveredKeys({ mode: "client-bound", method: profile.METHOD });
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
      { METHOD: "missing-validator/v1", open },
      { METHOD: "nonfunction-validator/v1", validateClientKeyPair: true, open },
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
            /** @type {any} */ ({ METHOD: "async-validator/v1", validateClientKeyPair, open }),
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
});
