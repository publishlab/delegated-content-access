// @ts-check
// This file records a WebCrypto mechanism for the client-bound transport design.
// It is not a security claim on its own. Read the boundaries below before quoting it.
//
// What it shows: the CALLER sets the OUTPUT key's extractability on unwrapKey and
// deriveKey. Page script that already holds the client private-key handle can
// unwrap a delivered key with extractable:true and read the raw bytes. On the
// honest path the client asks for a non-extractable handle. This file runs both
// client-bound methods, RSA-OAEP and ECDH P-256.
//
// What it does not show:
//  - Reachability is a separate question. The client private key stays in the
//    page's own closure or in IndexedDB, and a reader with a DevTools console
//    reaches it only if the page put it somewhere script can name. Nothing here
//    tests that.
//  - The consequence differs by key kind. Exporting a CONTENT key opens the one
//    item the client already renders. Exporting a PERIOD key opens the whole
//    access-group and period it covers, a wider reach. This file exports a
//    stand-in for either; read the design documents for which kind is at stake.
//  - The ECDH path here derives the transport key straight to AES and omits
//    DCA's deriveBits -> HKDF(info) step. The omitted step changes only how the
//    transport key is derived; the delivered-key unwrap, which is what this file
//    records, behaves the same either way.
//
// Both methods are soft barriers against a reader who controls the client. The
// file uses plain WebCrypto, disconnected from the DCA reference. Run:
//     node evidence-platform-tests/unwrapOutputExtractability.mjs
// Every check is an assertion, so it exits non-zero on a platform where the caller
// no longer chooses the output key's extractability.

import assert from "node:assert/strict";

const { subtle } = globalThis.crypto;
const rawBytes = async (key) => new Uint8Array(await subtle.exportKey("raw", key));
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

const deliveredKey = crypto.getRandomValues(new Uint8Array(16));

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
  const delivered = await subtle.importKey("raw", deliveredKey, "AES-GCM", true, ["encrypt"]);
  const wrapped = await subtle.wrapKey("raw", delivered, client.publicKey, { name: "RSA-OAEP" });

  const honest = await subtle.unwrapKey(
    "raw",
    wrapped,
    client.privateKey,
    { name: "RSA-OAEP" },
    "AES-GCM",
    false,
    ["decrypt"],
  );
  assert.equal(honest.extractable, false, "RSA honest path yields a non-extractable handle");

  const opened = await subtle.unwrapKey(
    "raw",
    wrapped,
    client.privateKey,
    { name: "RSA-OAEP" },
    "AES-GCM",
    true,
    ["decrypt"],
  );
  assert.ok(
    same(await rawBytes(opened), deliveredKey),
    "RSA caller with the handle can unwrap extractable",
  );
  console.log(
    "RSA-OAEP method : output extractability is the caller's; extractable unwrap read the bytes",
  );
}

// ---- ECDH P-256 method ----
{
  const client = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveKey",
  ]);
  const ephem = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveKey",
  ]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const issuerTransport = await subtle.deriveKey(
    { name: "ECDH", public: client.publicKey },
    ephem.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey"],
  );
  const delivered = await subtle.importKey("raw", deliveredKey, "AES-GCM", true, ["encrypt"]);
  const wrapped = await subtle.wrapKey("raw", delivered, issuerTransport, {
    name: "AES-GCM",
    iv: nonce,
  });

  const clientTransport = await subtle.deriveKey(
    { name: "ECDH", public: ephem.publicKey },
    client.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["unwrapKey"],
  );

  const honest = await subtle.unwrapKey(
    "raw",
    wrapped,
    clientTransport,
    { name: "AES-GCM", iv: nonce },
    "AES-GCM",
    false,
    ["decrypt"],
  );
  assert.equal(honest.extractable, false, "EC honest path yields a non-extractable handle");

  const opened = await subtle.unwrapKey(
    "raw",
    wrapped,
    clientTransport,
    { name: "AES-GCM", iv: nonce },
    "AES-GCM",
    true,
    ["decrypt"],
  );
  assert.ok(
    same(await rawBytes(opened), deliveredKey),
    "EC caller with the handle can unwrap extractable",
  );
  console.log(
    "ECDH P-256 method: output extractability is the caller's; extractable unwrap read the bytes",
  );
}
