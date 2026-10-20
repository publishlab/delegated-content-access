// @ts-check
// This file records a WebCrypto mechanism for the client-bound transport design.
// It records three holes. A reader who controls the client can still do all three,
// and all three succeed here. Non-extractability stops copying key bytes off the
// device, not sharing what the key can do:
//
//  1. JS decrypts with the handle. A non-extractable contentKey handle decrypts
//     content to plaintext in JavaScript; it must, to render. Non-extractability
//     never stopped decryption, only reading the key bytes.
//  2. Handle as oracle. The reader keeps the non-extractable handle and exposes a
//     decrypt(blob) -> plaintext service. The key bytes never leave the handle;
//     the reader rents out what it can do. The oracle works only while the
//     reader's browser is running and reachable.
//  3. Own extractable key. The reader generates an extractable keypair of their
//     own and exports the private key, which they can then share offline. The
//     issuer wraps to whatever public key the request supplies, and DCA carries
//     no attestation of where that key came from.
//
// Non-extractability and the handle chain keep key bytes off disk and off the
// device, and keep one principal's keys from opening under another. The reader
// stays free to decrypt their own content and to rent the capability out. For now
// this file records the boundary. Closing it takes an attestation of where the key
// came from, which WebCrypto does not provide.
//
// The file uses plain WebCrypto, disconnected from the DCA reference. Run:
//     node evidence-platform-tests/nonExtractabilityBoundary.mjs
// It asserts that all three holes are open, so it exits non-zero only when a
// platform change closes one of them, which would move the boundary.

import assert from "node:assert/strict";

const { subtle } = globalThis.crypto;
const enc = new TextEncoder();
const dec = new TextDecoder();

// In the chain the content key arrives as a non-extractable handle; the import
// below stands in for it. On the issuer side here we hold the bytes, to build
// the ciphertext.
const keyBytes = crypto.getRandomValues(new Uint8Array(16));
const nonce = crypto.getRandomValues(new Uint8Array(12));
const forEnc = await subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
const article = new Uint8Array(
  await subtle.encrypt({ name: "AES-GCM", iv: nonce }, forEnc, enc.encode("the paywalled article")),
);
const handle = await subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]); // non-extractable
assert.equal(handle.extractable, false);

// Hole 1: JS decrypts with the handle and gets plaintext, with no key bytes.
const plain = dec.decode(await subtle.decrypt({ name: "AES-GCM", iv: nonce }, handle, article));
assert.equal(plain, "the paywalled article");
console.log("hole 1: non-extractable handle decrypted content to plaintext in JS");

// Hole 2: handle as oracle. A closure holds the handle and rents its capability;
// callers get plaintext, never the key. exportKey still refuses the bytes.
const oracle = (
  (k) => async (iv, ct) =>
    new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, k, ct))
)(handle);
const viaOracle = dec.decode(await oracle(nonce, article));
assert.equal(viaOracle, "the paywalled article");
let bytesRefused = false;
try {
  await subtle.exportKey("raw", handle);
} catch {
  bytesRefused = true;
}
assert.ok(bytesRefused, "the oracle rents capability while the key bytes stay refused");
console.log(
  "hole 2: handle rented as a decrypt oracle; capability shared, key bytes still refused",
);

// Hole 3: own extractable key. The reader generates an extractable keypair of
// their own and exports the private key, before the issuer ever wraps to the
// matching public key.
const own = await subtle.generateKey(
  {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  true,
  ["unwrapKey"],
);
const exported = await subtle.exportKey("pkcs8", own.privateKey);
assert.ok(exported.byteLength > 0, "a self-generated extractable key exports to portable bytes");
console.log("hole 3: reader-generated extractable key exported to portable bytes");

console.log(
  "BOUNDARY: non-extractability stops copying key bytes, not sharing what the key can do.",
);
