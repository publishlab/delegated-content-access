// @ts-check

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { assertBindingSupportsTarget } from "../../support/contract-runner-validation.js";

/**
 * Keys returned by imports are opaque to the harness. Host callback invocation
 * is an explicitly selected observation, separate from the wire response.
 * @typedef {object} BrowserIssuerDriver
 * @property {(jwk: JsonWebKey) => Promise<any>} importIssuerPrivateKey
 * @property {(jwk: JsonWebKey) => Promise<any>} importPublisherPublicKey
 * @property {(config: any) => { unlock: (rawRequest: string, input: { origin: string, hostContext: any, contentType?: string|null }) => Promise<{status: number, headers?: Record<string, string>, body?: any}> }} createBrowserIssuer
 */

/** @param {JsonWebKey} privateJwk @param {string} kid @param {object} claims */
async function signedAssertion(privateJwk, kid, claims) {
  const key = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const encode = (/** @type {unknown} */ value) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const input = `${encode({ alg: "ES256", typ: "JWT", kid })}.${encode(claims)}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(input),
  );
  return `${input}.${Buffer.from(signature).toString("base64url")}`;
}

/** @param {BrowserIssuerDriver} driver @param {any} vector */
async function provision(driver, vector) {
  const issuer = vector.input.issuers[0];
  const signing = vector.input.signingKeys[0];
  const data = vector.expected.dcaData;
  const privateKey = await driver.importIssuerPrivateKey(issuer.privateKeyJwk);
  const publicKey = await driver.importPublisherPublicKey(signing.publicKeyJwk);
  /** @type {string[]} */
  const events = [];
  /** @type {Map<string, any>} */
  const registrations = new Map();
  registrations.set(signing.kid, {
    kid: signing.kid,
    publicKey,
    origins: [data.resource.origin],
    openingKeys: {
      get(/** @type {string} */ issuerName, /** @type {string} */ keyId) {
        events.push(`open:A:${issuerName}:${keyId}`);
        return issuerName === issuer.issuerName && keyId === issuer.keyId
          ? { algorithm: issuer.algorithm, privateKey }
          : null;
      },
    },
  });
  const hostContext = { principal: "contract-reader" };
  const browser = driver.createBrowserIssuer({
    operatingIssuerNames: [issuer.issuerName],
    registrationForKid(/** @type {string} */ kid) {
      events.push(`registration:${kid}`);
      return registrations.get(kid);
    },
    admitCaller(/** @type {any} */ context, /** @type {any} */ registration) {
      events.push(`caller:${registration.kid}`);
      assert.deepEqual(context, hostContext);
      return { kind: "admitted", principal: context.principal };
    },
    accessPolicy: {
      decide(/** @type {any} */ claims, /** @type {any} */ requested) {
        events.push(`policy:${claims.resource.origin}`);
        return { contentNames: requested.contentNames };
      },
    },
    clock: { now: () => new Date("2025-10-23T14:20:00Z") },
  });
  const request = {
    version: data.version,
    issuerName: issuer.issuerName,
    keyId: issuer.keyId,
    resourceJWT: data.resourceJWT,
    sealed: {
      contentKeys: data.issuerData.find(
        (/** @type {any} */ record) => record.issuerName === issuer.issuerName,
      ).sealed.contentKeys,
    },
  };
  return { issuer, signing, data, browser, events, registrations, request, hostContext };
}

/** @param {any} response */
function assertNoKey(response) {
  for (const section of Object.values(response.body?.keys ?? {})) {
    assert.deepEqual(
      section,
      [],
      "refused or unavailable material supplies no key section entries",
    );
  }
}

/** @param {any} binding @param {any} target @param {any[]} vectors */
export function registerBrowserIssuerContract(binding, target, vectors) {
  const declared = binding.targets?.["issuer-browser-origin"];
  assertBindingSupportsTarget("issuer-browser-origin", target, declared);
  const driver = /** @type {BrowserIssuerDriver} */ (declared.driver);
  const vector = vectors.find((value) => value.name === "seal-ecdh");
  if (!vector || vectors.length !== 1) {
    throw new Error("issuer-browser-origin selects the single existing seal-ecdh fixture");
  }

  describe("portable selected browser-Origin issuer admission", () => {
    test("missing or incompatible media type is refused before publisher lookup without CORS", async () => {
      const f = await provision(driver, vector);
      for (const contentType of [undefined, "text/plain"]) {
        const response = await f.browser.unlock(JSON.stringify(f.request), {
          origin: f.data.resource.origin,
          hostContext: f.hostContext,
          contentType,
        });
        assert.equal(response.status, 415);
        assert.equal(response.headers?.["access-control-allow-origin"], undefined);
      }
      assert.deepEqual(f.events, []);
    });

    test("matched Origin reaches policy before the registration-scoped opening key", async () => {
      const f = await provision(driver, vector);
      const response = await f.browser.unlock(JSON.stringify(f.request), {
        origin: f.data.resource.origin,
        hostContext: f.hostContext,
        contentType: "application/json",
      });
      assert.equal(response.status, 200);
      assert.deepEqual(
        [...response.body.keys.contentKeys].sort((a, b) =>
          a.contentName.localeCompare(b.contentName),
        ),
        Object.entries(vector.expected.contentKeys)
          .map(([contentName, key]) => ({
            contentName,
            key,
          }))
          .sort((a, b) => a.contentName.localeCompare(b.contentName)),
      );
      assert.deepEqual(f.events, [
        `registration:${f.signing.kid}`,
        `caller:${f.signing.kid}`,
        `policy:${f.data.resource.origin}`,
        `open:A:${f.issuer.issuerName}:${f.issuer.keyId}`,
      ]);
    });

    test("mismatched observed Origin refuses before policy and private-key lookup", async () => {
      const f = await provision(driver, vector);
      const response = await f.browser.unlock(JSON.stringify(f.request), {
        origin: "https://other-publisher.example",
        hostContext: f.hostContext,
        contentType: "application/json",
      });
      assert.equal(response.status, 403);
      assertNoKey(response);
      assert.deepEqual(f.events, [`registration:${f.signing.kid}`, `caller:${f.signing.kid}`]);
    });

    test("unknown registration refuses before caller, policy and private-key lookup", async () => {
      const f = await provision(driver, vector);
      const resourceJWT = await signedAssertion(
        f.signing.privateKeyJwk,
        "unknown-signing-key",
        f.data.resource,
      );
      const response = await f.browser.unlock(JSON.stringify({ ...f.request, resourceJWT }), {
        origin: f.data.resource.origin,
        hostContext: f.hostContext,
        contentType: "application/json",
      });
      assert.equal(response.status, 400);
      assertNoKey(response);
      assert.deepEqual(f.events, ["registration:unknown-signing-key"]);
    });

    test("a distinct registered publisher cannot consult another publisher's opening view", async () => {
      const f = await provision(driver, vector);
      const pair = /** @type {CryptoKeyPair} */ (
        await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
          "sign",
          "verify",
        ])
      );
      const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
      const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
      const origin = "https://registered-publisher-b.example";
      const kid = "publisher-b-signing-key";
      f.registrations.set(kid, {
        kid,
        publicKey: await driver.importPublisherPublicKey(publicJwk),
        origins: [origin],
        openingKeys: {
          get(/** @type {string} */ issuerName, /** @type {string} */ keyId) {
            f.events.push(`open:B:${issuerName}:${keyId}`);
            return null;
          },
        },
      });
      // The valid B signature presents A's unchanged recorded envelope and
      // unsigned key selectors. Only A's registration has the key that opens it.
      const resourceJWT = await signedAssertion(privateJwk, kid, { ...f.data.resource, origin });
      const response = await f.browser.unlock(JSON.stringify({ ...f.request, resourceJWT }), {
        origin,
        hostContext: f.hostContext,
        contentType: "application/json",
      });
      assertNoKey(response);
      assert.deepEqual(f.events, [
        `registration:${kid}`,
        `caller:${kid}`,
        `policy:${origin}`,
        `open:B:${f.issuer.issuerName}:${f.issuer.keyId}`,
      ]);
      f.events.length = 0;
      const positive = await f.browser.unlock(JSON.stringify(f.request), {
        origin: f.data.resource.origin,
        hostContext: f.hostContext,
        contentType: "application/json",
      });
      assert.equal(positive.status, 200);
      assert.deepEqual(
        [...positive.body.keys.contentKeys].sort((a, b) =>
          a.contentName.localeCompare(b.contentName),
        ),
        Object.entries(vector.expected.contentKeys)
          .map(([contentName, key]) => ({
            contentName,
            key,
          }))
          .sort((a, b) => a.contentName.localeCompare(b.contentName)),
      );
      assert.deepEqual(f.events, [
        `registration:${f.signing.kid}`,
        `caller:${f.signing.kid}`,
        `policy:${f.data.resource.origin}`,
        `open:A:${f.issuer.issuerName}:${f.issuer.keyId}`,
      ]);
    });
  });
}
