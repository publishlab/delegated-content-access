// @ts-check
// This file records a WebCrypto mechanism for the client-bound transport design.
// It is not a security claim on its own. Read the boundaries below before quoting it.
//
// What it shows: exportKey and wrapKey refuse to hand out a private key generated
// non-extractable. Page script cannot read or wrap out the bytes of an honestly
// generated client key. The RSA key below still opens a delivery. The one ECDH
// oracle a script gets, deriveBits, returns the x-coordinate of d*P for a chosen
// point, not the scalar d.
// This file runs both methods, RSA-OAEP and ECDH P-256.
//
// What it does not show, and why this stays a soft barrier, not a guarantee:
//  - The reader chooses whether to generate honestly, and the reader controls
//    the client. A reader can generate their own client keypair EXTRACTABLE and
//    export it, hand another person's public key to the issuer, or use the
//    handle on another person's behalf. DCA carries no attestation that the
//    client key was generated non-extractable, so nothing here stops a reader
//    sharing access.
//  - The d*P result from deriveBits holds only because WebCrypto validates curve
//    points at importKey, which blocks the invalid-curve attack. Browsers and
//    Node validate; a broken implementation might not.
//
// The file uses plain WebCrypto, disconnected from the DCA reference. Run:
//     node evidence-platform-tests/nonExtractableKeyExportRefusal.mjs
// Every check is an assertion, so it exits non-zero if a platform ever exported a
// non-extractable key.

import assert from "node:assert/strict";

const { subtle } = globalThis.crypto;
const deliveredKey = crypto.getRandomValues(new Uint8Array(16));
const kek = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["wrapKey"]);

/** Return true if the operation threw, i.e. WebCrypto refused it. */
async function refused(fn) {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

// ---- RSA-OAEP method ----
{
  const client = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false,
    ["wrapKey", "unwrapKey"],
  );

  assert.equal(client.privateKey.extractable, false);
  assert.ok(
    await refused(() => subtle.exportKey("pkcs8", client.privateKey)),
    "RSA exportKey refused",
  );
  assert.ok(
    await refused(() => subtle.exportKey("jwk", client.privateKey)),
    "RSA exportKey jwk refused",
  );
  assert.ok(
    await refused(() =>
      subtle.wrapKey("pkcs8", client.privateKey, kek, { name: "AES-GCM", iv: new Uint8Array(12) }),
    ),
    "RSA wrapKey refused",
  );

  // The same key still opens a delivery.
  const delivered = await subtle.importKey("raw", deliveredKey, "AES-GCM", true, ["encrypt"]);
  const wrapped = await subtle.wrapKey("raw", delivered, client.publicKey, { name: "RSA-OAEP" });
  const opened = await subtle.unwrapKey(
    "raw",
    wrapped,
    client.privateKey,
    { name: "RSA-OAEP" },
    "AES-GCM",
    false,
    ["decrypt"],
  );
  assert.equal(opened.type, "secret", "RSA key still opens a delivery");
  console.log(
    "RSA-OAEP method : honestly non-extractable key - exportKey and wrapKey refused, still opens",
  );
}

// ---- ECDH P-256 method ----
{
  const client = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveKey",
    "deriveBits",
  ]);

  assert.equal(client.privateKey.extractable, false);
  assert.ok(
    await refused(() => subtle.exportKey("pkcs8", client.privateKey)),
    "EC exportKey refused",
  );
  assert.ok(
    await refused(() => subtle.exportKey("jwk", client.privateKey)),
    "EC exportKey jwk refused",
  );
  assert.ok(
    await refused(() =>
      subtle.wrapKey("pkcs8", client.privateKey, kek, { name: "AES-GCM", iv: new Uint8Array(12) }),
    ),
    "EC wrapKey refused",
  );

  // deriveBits returns the x-coordinate of the agreement point d*P; deriveKey
  // makes a key from the same agreement output. Neither operation exports d.
  const other = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const viaBits = new Uint8Array(
    await subtle.deriveBits({ name: "ECDH", public: other.publicKey }, client.privateKey, 256),
  );
  const derived = await subtle.deriveKey(
    { name: "ECDH", public: other.publicKey },
    client.privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"],
  );
  const viaKey = new Uint8Array(await subtle.exportKey("raw", derived));
  assert.equal(viaBits.length, 32, "P-256 deriveBits returns the requested 256 bits");
  assert.equal(viaKey.length, 32, "AES-256 deriveKey returns a 256-bit key");
  console.log(
    "ECDH P-256 method: honestly non-extractable key - exportKey and wrapKey refused; deriveBits/deriveKey do not export d",
  );
}
