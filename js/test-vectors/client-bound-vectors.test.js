//
// Replays the two versioned issuer-to-client delivery profiles outside the base
// vector set. The ECDH profile seals and opens from injected entropy; RSA-OAEP
// opens its recorded ciphertexts only because OAEP's padding seed is internal.
//
// Each recorded key entry is also checked against a transcript computed here from
// docs/spec--response-binding.md sections 6 to 8 with WebCrypto alone: the kind
// context spelled from its octets, ECDH, HKDF and AES-GCM for ECDH-P256, and
// RSA-OAEP with the context as label. That check shares no code with the
// profile modules, so a fixture regenerated from a wrong construction fails it.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { basename, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import * as ecdhProfile from "../extensions/client-bound-transport/ecdhP256.js";
import * as rsaProfile from "../extensions/client-bound-transport/rsaOaep.js";
import { encrypt, decrypt, decryptToKey } from "../core-shared/aead.js";
import { base64urlDecode } from "../core-shared/codec.js";
import { vectorFilesIn } from "../tools/checksums.js";

const { subtle } = globalThis.crypto;

const ECDH_FILE = fileURLToPath(
  new URL(
    "../../verification/vectors/v1/profiles/dca-profile-client-bound-ecdh-p256/client-bound-ecdh-p256.json",
    import.meta.url,
  ),
);
const RSA_FILE = fileURLToPath(
  new URL(
    "../../verification/vectors/v1/profiles/dca-profile-client-bound-rsa-oaep/client-bound-rsa-oaep.json",
    import.meta.url,
  ),
);

test("client-bound vector replay names every member of both sets", () => {
  for (const file of [ECDH_FILE, RSA_FILE]) {
    assert.deepEqual(vectorFilesIn(dirname(file)), [basename(file)]);
  }
});

/** @param {string} file */
function vectorAt(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

/** Profile vectors pin the P-256 point, not browser-specific JWK export metadata. */
function p256PublicJwk(jwk) {
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

/** @param {{ publicKeyJwk: JsonWebKey, privateKeyJwk: JsonWebKey }} pair */
async function importEcdhPair(pair) {
  const algorithm = { name: "ECDH", namedCurve: "P-256" };
  return {
    publicKey: await subtle.importKey("jwk", pair.publicKeyJwk, algorithm, true, []),
    privateKey: await subtle.importKey("jwk", pair.privateKeyJwk, algorithm, false, ["deriveKey"]),
  };
}

/**
 * The kind context of docs/spec--response-binding.md section 6, spelled from
 * its octets: UTF-8 `dca-bind-client-bound-key-kind`, one zero octet, UTF-8 kind.
 *
 * @param {string} keyKind
 */
function kindContext(keyKind) {
  return new Uint8Array(
    Buffer.concat([
      Buffer.from("dca-bind-client-bound-key-kind", "utf8"),
      Buffer.from([0]),
      Buffer.from(keyKind, "utf8"),
    ]),
  );
}

/** The section each kind belongs to, as section 6 fixes it. */
const SECTION_OF = { contentKey: "contentKeys", periodKey: "periodKeys", chainKey: "chainKeys" };

/**
 * Both packages record one delivered key per result section, in section order, with
 * the context its kind fixes.
 *
 * @param {any} vector
 */
function assertKeyEntryLayout(vector) {
  assert.deepEqual(
    vector.input.deliveredKeys.map((/** @type {any} */ deliveredKey) => [
      deliveredKey.section,
      deliveredKey.keyKind,
    ]),
    Object.entries(SECTION_OF).map(([kind, section]) => [section, kind]),
  );
  vector.expected.deliveredKeys.forEach(
    (/** @type {any} */ deliveredKey, /** @type {number} */ i) => {
      const input = vector.input.deliveredKeys[i];
      assert.equal(deliveredKey.keyKind, input.keyKind);
      assert.equal(deliveredKey.openedKeyBase64url, input.deliveryKeyBase64url);
      assert.deepEqual(
        base64urlDecode(deliveredKey.kindContextBase64url),
        kindContext(deliveredKey.keyKind),
        `${deliveredKey.keyKind} records the section 6 context`,
      );
    },
  );
}

/**
 * The profile opener recovers each delivered key as its own kind: a non-extractable
 * handle that is the delivered content or period key, or the chain-key bytes.
 *
 * @param {any} opener
 * @param {any} deliveredKey - one expected delivered key
 */
async function assertProfileOpens(opener, deliveredKey) {
  const keyBytes = base64urlDecode(deliveredKey.openedKeyBase64url);
  if (deliveredKey.keyKind === "chainKey") {
    assert.deepEqual(await opener.open(deliveredKey.wrappedKey, [], "chainKey"), keyBytes);
    return;
  }
  const usages = deliveredKey.keyKind === "contentKey" ? ["decrypt"] : ["unwrapKey"];
  const handle = await opener.open(deliveredKey.wrappedKey, usages, deliveredKey.keyKind);
  assert.equal(handle.extractable, false, "the client opens a non-extractable key handle");
  assert.equal(handle.algorithm.name, "AES-GCM");
  assert.deepEqual([...handle.usages], usages);
  const nonce = new Uint8Array([1, 3, 3, 7, 9, 9, 2, 5, 8, 4, 6, 0]);
  const payload = new Uint8Array(16).fill(42);
  const sealed = await encrypt(keyBytes, nonce, payload);
  if (deliveredKey.keyKind === "contentKey") {
    assert.deepEqual(await decrypt(handle, nonce, sealed), payload, "the handle is the key");
  } else {
    const unwrapped = await decryptToKey(handle, nonce, sealed, undefined, ["decrypt"]);
    assert.equal(unwrapped.algorithm.name, "AES-GCM", "the period handle is the key");
  }
  for (const other of Object.keys(SECTION_OF)) {
    if (other === deliveredKey.keyKind) continue;
    await assert.rejects(
      () => opener.open(deliveredKey.wrappedKey, usages, other),
      (/** @type {any} */ error) => error.code === "unwrap_failed",
      `${deliveredKey.keyKind} entry read from ${SECTION_OF[/** @type {keyof typeof SECTION_OF} */ (other)]}`,
    );
  }
}

// No issuer duty tag: this seal runs from an injected ephemeral pair and nonce,
// so it replays the method's wrapped-key bytes and never sees an issuer select the
// method, refuse a missing offer or wrap its whole result. That observation
// belongs to an issuer-endpoint test, so the claim stays incomplete until one
// carries the tag.
test(
  "client-bound ECDH-P256 profile re-seals the wire and opens it",
  { tags: ["dca-profile-client-bound-ecdh-p256/client/offer-and-admit"] },
  async () => {
    const vector = vectorAt(ECDH_FILE);
    assert.equal(vector.vectorFormat, "profile");
    assert.equal(vector.profile, "dca-profile-client-bound-ecdh-p256");
    assert.deepEqual(Object.keys(vector.expected.transport).sort(), ["method", "publicKey"]);
    assertKeyEntryLayout(vector);

    const nonces = vector.input.deliveredKeys.map((/** @type {any} */ deliveredKey) =>
      base64urlDecode(deliveredKey.nonceBase64url),
    );
    let drawn = 0;
    const sealer = await ecdhProfile.seal(vector.input.client.publicKeyJwk, {
      ephemeralKeyPair: await importEcdhPair(vector.input.issuerEphemeralKeyPair),
      random: {
        bytes: (n) => {
          assert.equal(n, 12);
          return nonces[drawn++];
        },
      },
    });
    assert.deepEqual(
      {
        publicKey: p256PublicJwk(sealer.transport.publicKey),
        method: ecdhProfile.METHOD,
      },
      vector.expected.transport,
      "the injected ephemeral key is the response public key",
    );
    const opener = await ecdhProfile.open(
      sealer.transport,
      (await importEcdhPair(vector.input.client)).privateKey,
    );
    for (const [i, deliveredKey] of vector.expected.deliveredKeys.entries()) {
      assert.deepEqual(Object.keys(deliveredKey.wrappedKey).sort(), ["key", "nonce"]);
      assert.deepEqual(
        await sealer.wrap(
          base64urlDecode(vector.input.deliveredKeys[i].deliveryKeyBase64url),
          deliveredKey.keyKind,
        ),
        deliveredKey.wrappedKey,
        `the injected nonce makes the issuer seal of the ${deliveredKey.keyKind} entry byte-replayable`,
      );
      await assertProfileOpens(opener, deliveredKey);
    }
  },
);

test("client-bound ECDH-P256 key entries follow the section 7 transcript computed here", async () => {
  const vector = vectorAt(ECDH_FILE);
  const algorithm = { name: "ECDH", namedCurve: "P-256" };
  const clientPrivate = await subtle.importKey(
    "jwk",
    vector.input.client.privateKeyJwk,
    algorithm,
    false,
    ["deriveBits"],
  );
  const issuerPublic = await subtle.importKey(
    "jwk",
    vector.expected.transport.publicKey,
    algorithm,
    false,
    [],
  );
  const shared = await subtle.deriveBits(
    { name: "ECDH", public: issuerPublic },
    clientPrivate,
    256,
  );
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const transportBytes = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode("dca-derivation-client-bound-transport"),
    },
    ikm,
    256,
  );
  const transportKey = await subtle.importKey("raw", transportBytes, "AES-GCM", false, ["decrypt"]);
  /** @param {any} deliveredKey @param {Uint8Array} additionalData */
  const openWith = async (deliveredKey, additionalData) =>
    new Uint8Array(
      await subtle.decrypt(
        { name: "AES-GCM", iv: base64urlDecode(deliveredKey.wrappedKey.nonce), additionalData },
        transportKey,
        base64urlDecode(deliveredKey.wrappedKey.key),
      ),
    );

  for (const deliveredKey of vector.expected.deliveredKeys) {
    assert.deepEqual(
      await openWith(deliveredKey, kindContext(deliveredKey.keyKind)),
      base64urlDecode(deliveredKey.openedKeyBase64url),
      `${deliveredKey.keyKind} opens under its own kind context`,
    );
    for (const wrong of [
      new Uint8Array(0),
      ...Object.keys(SECTION_OF)
        .filter((kind) => kind !== deliveredKey.keyKind)
        .map(kindContext),
    ]) {
      await assert.rejects(
        () => openWith(deliveredKey, wrong),
        `${deliveredKey.keyKind} under another context`,
      );
    }
  }
});

test(
  "client-bound RSA-OAEP profile opens its recorded wire without claiming a repeatable seal",
  { tags: ["dca-profile-client-bound-rsa-oaep/client/offer-and-admit"] },
  async () => {
    const vector = vectorAt(RSA_FILE);
    assert.equal(vector.vectorFormat, "profile");
    assert.equal(vector.profile, "dca-profile-client-bound-rsa-oaep");
    assert.deepEqual(Object.keys(vector.expected.transport).sort(), ["method"]);
    assertKeyEntryLayout(vector);

    const privateKey = await subtle.importKey(
      "jwk",
      vector.input.client.privateKeyJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["unwrapKey", "decrypt"],
    );
    const opener = await rsaProfile.open(vector.expected.transport, privateKey);
    for (const deliveredKey of vector.expected.deliveredKeys) {
      assert.deepEqual(Object.keys(deliveredKey.wrappedKey), ["key"]);
      await assertProfileOpens(opener, deliveredKey);
    }
  },
);

test("client-bound RSA-OAEP key entries follow the section 8 transcript computed here", async () => {
  const vector = vectorAt(RSA_FILE);
  const privateKey = await subtle.importKey(
    "jwk",
    vector.input.client.privateKeyJwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
  /** @param {any} deliveredKey @param {Uint8Array} label */
  const openWith = async (deliveredKey, label) =>
    new Uint8Array(
      await subtle.decrypt(
        { name: "RSA-OAEP", label },
        privateKey,
        base64urlDecode(deliveredKey.wrappedKey.key),
      ),
    );

  for (const deliveredKey of vector.expected.deliveredKeys) {
    assert.deepEqual(
      await openWith(deliveredKey, kindContext(deliveredKey.keyKind)),
      base64urlDecode(deliveredKey.openedKeyBase64url),
      `${deliveredKey.keyKind} opens under its own kind label`,
    );
    for (const wrong of [
      new Uint8Array(0),
      ...Object.keys(SECTION_OF)
        .filter((kind) => kind !== deliveredKey.keyKind)
        .map(kindContext),
    ]) {
      await assert.rejects(
        () => openWith(deliveredKey, wrong),
        `${deliveredKey.keyKind} under another label`,
      );
    }
  }
});
