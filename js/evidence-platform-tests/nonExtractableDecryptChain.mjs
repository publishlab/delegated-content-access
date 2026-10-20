// @ts-check
// This file records a WebCrypto mechanism for the client-bound transport design.
// It is not a security claim on its own. Read the boundaries below before quoting it.
//
// What it shows: the delivered-key decrypt chain runs on non-extractable handles
// end to end, with no key bytes in JavaScript:
//     periodKey (handle) --unwrapKey--> contentKey (handle) --decrypt--> content
// Each hop uses unwrapKey, which lets the caller mark the OUTPUT non-extractable.
// A periodKey handle unwraps a contentKey handle, and that contentKey decrypts the
// article without either key's bytes appearing. The DCA reference already runs
// this in memory (decryptToKey / unwrapKey yield non-extractable handles). The
// caller chooses at each hop: unwrapKey returns a handle, decrypt returns bytes,
// so a transport built on decrypt puts the key bytes in JavaScript.
//
// What it does not show:
//  - Honest-path only. A reader controlling the client asks for an extractable
//    output at the unwrap (see unwrapOutputExtractability.mjs), or mints their
//    own key upstream. This keeps key bytes out of places any script on the
//    origin can read; it does not stop the determined reader. W3C calls
//    non-extractability obfuscation, not a seal.
//  - Two hops run OUTSIDE this chain in the reference: the EC transport
//    agreement (agreeTransport's deriveKey, the hop above periodKey) and
//    periodKey persistence (the string store serializes handles to base64url).
//    Neither is exercised here.
//
// The file uses plain WebCrypto, disconnected from the DCA reference. Run:
//     node evidence-platform-tests/nonExtractableDecryptChain.mjs
// Every check is an assertion, so it exits non-zero if a platform stops running
// the chain on non-extractable handles.

import assert from "node:assert/strict";

const { subtle } = globalThis.crypto;
const enc = new TextEncoder();
const dec = new TextDecoder();
const refused = async (fn) => {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
};

// The issuer side holds the bytes and builds the wrapped blobs.
const periodBytes = crypto.getRandomValues(new Uint8Array(16));
const contentBytes = crypto.getRandomValues(new Uint8Array(16));
const nonceC = crypto.getRandomValues(new Uint8Array(12)); // contentKey wrapped under periodKey
const nonceM = crypto.getRandomValues(new Uint8Array(12)); // article encrypted under contentKey

const periodForWrap = await subtle.importKey("raw", periodBytes, "AES-GCM", false, ["wrapKey"]);
const contentExtractable = await subtle.importKey("raw", contentBytes, "AES-GCM", true, [
  "encrypt",
]);
const wrappedContentKey = await subtle.wrapKey("raw", contentExtractable, periodForWrap, {
  name: "AES-GCM",
  iv: nonceC,
});
const contentForEnc = await subtle.importKey("raw", contentBytes, "AES-GCM", false, ["encrypt"]);
const article = new Uint8Array(
  await subtle.encrypt(
    { name: "AES-GCM", iv: nonceM },
    contentForEnc,
    enc.encode("the paywalled article"),
  ),
);

// The client side runs on handles only. The periodKey arrives non-extractable,
// from the transport unwrap or from the cache; the import below stands in for
// that arrival.
const periodKey = await subtle.importKey("raw", periodBytes, "AES-GCM", false, ["unwrapKey"]);
assert.ok(
  await refused(() => subtle.exportKey("raw", periodKey)),
  "periodKey handle should not export",
);

// Hop one: periodKey handle unwraps the contentKey into another non-extractable handle.
const contentKey = await subtle.unwrapKey(
  "raw",
  wrappedContentKey,
  periodKey,
  { name: "AES-GCM", iv: nonceC },
  "AES-GCM",
  false,
  ["decrypt"],
);
assert.equal(contentKey.extractable, false, "contentKey should arrive non-extractable");
assert.ok(
  await refused(() => subtle.exportKey("raw", contentKey)),
  "contentKey handle should not export",
);

// Hop two: contentKey handle decrypts the article.
const plain = dec.decode(
  await subtle.decrypt({ name: "AES-GCM", iv: nonceM }, contentKey, article),
);
assert.equal(plain, "the paywalled article", "content should decrypt");

console.log("periodKey(handle) -> unwrap -> contentKey(handle) -> decrypt -> content");
console.log("both keys non-extractable, export refused at each hop, article decrypted");
