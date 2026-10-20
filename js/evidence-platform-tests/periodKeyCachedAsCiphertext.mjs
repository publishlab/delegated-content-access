// @ts-check
// This file records a WebCrypto mechanism for the client-bound transport design.
// It is not a security claim on its own. Read the boundaries below before quoting it.
//
// What it shows: a periodKey can be CACHED as ciphertext and reopened over time
// without ever persisting key bytes. The issuer wraps the periodKey to the
// client's DURABLE key; the client stores only that wrapped blob and the
// non-extractable opener. The blob is ciphertext, so holding it as bytes is safe.
// Later, after the response transport is gone, the client unwraps the stored blob
// back into a non-extractable periodKey handle and opens further articles in the
// same period:
//     stored ciphertext + durable opener -> periodKey handle -> contentKey handle -> content
// The client opens two articles delivered at different times in the period from
// that one cached blob: no re-unlock, no key bytes on disk.
//
// The design keeps one durable secret, the opener: a non-extractable private key
// whose only usage is unwrapKey, since decrypt would return the bytes instead of a
// handle. Everything else on disk stays ciphertext, which the client reopens into
// handles on demand. Only that one key must survive a restart non-extractable.
//
// What it does not show:
//  - Honest-path only, same soft-barrier caveat as the other files here: a reader
//    controlling the client asks for an extractable output at the unwrap or mints
//    their own key. This keeps key bytes off disk; it does not stop the
//    determined reader.
//  - It needs the periodKey wrapped to the client's DURABLE key. DCA's reference
//    wraps under a per-response ephemeral key that the issuer discards, so a blob
//    wrapped that way cannot be reopened later, and wrapKey refuses to re-wrap a
//    non-extractable handle on the client. The durable wrap therefore has to come
//    from the issuer, as a durable wrapped-key structure rather than the
//    ephemeral one.
//  - Node has no IndexedDB, so this file simulates persistence: it keeps the
//    durable opener as a handle and the blob as a base64url string. In a browser,
//    structured cloning puts that handle into IndexedDB across a restart. Nothing
//    here exercises the IndexedDB round-trip of a non-extractable key.
//
// The file uses plain WebCrypto, disconnected from the DCA reference. Run:
//     node evidence-platform-tests/periodKeyCachedAsCiphertext.mjs
// Every check is an assertion, so it exits non-zero if the client can no longer
// reopen the cached ciphertext.

import assert from "node:assert/strict";

const { subtle } = globalThis.crypto;
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (u8) => Buffer.from(u8).toString("base64url");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64url"));
const refused = async (fn) => {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
};

// --- The client's DURABLE key. A browser generates this once non-extractable and
// keeps it in IndexedDB. Here it is generated extractable, exported and
// re-imported non-extractable, and that re-imported handle survives the "restart"
// below. ---
const gen = await subtle.generateKey(
  {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  true,
  ["wrapKey", "unwrapKey"],
);
const durablePub = gen.publicKey;
const durableJwk = await subtle.exportKey("jwk", gen.privateKey);
const durablePriv = await subtle.importKey(
  "jwk",
  durableJwk,
  { name: "RSA-OAEP", hash: "SHA-256" },
  false,
  ["unwrapKey"],
);
assert.ok(
  await refused(() => subtle.exportKey("pkcs8", durablePriv)),
  "durable opener must not export",
);

// --- Issuer side (one response). Wrap the periodKey to the durable client key,
// and wrap each article's contentKey under the periodKey. ---
const periodBytes = crypto.getRandomValues(new Uint8Array(16));
const periodForWrap = await subtle.importKey("raw", periodBytes, "AES-GCM", false, ["wrapKey"]);
const periodForCarrier = await subtle.importKey("raw", periodBytes, "AES-GCM", true, ["encrypt"]);
const wrappedPeriodKey = new Uint8Array(
  await subtle.wrapKey("raw", periodForCarrier, durablePub, { name: "RSA-OAEP" }),
);

async function articleUnder(period, text) {
  const cBytes = crypto.getRandomValues(new Uint8Array(16));
  const nC = crypto.getRandomValues(new Uint8Array(12));
  const nM = crypto.getRandomValues(new Uint8Array(12));
  const cForWrap = await subtle.importKey("raw", cBytes, "AES-GCM", true, ["encrypt"]);
  const wrappedContentKey = new Uint8Array(
    await subtle.wrapKey("raw", cForWrap, period, { name: "AES-GCM", iv: nC }),
  );
  const cForEnc = await subtle.importKey("raw", cBytes, "AES-GCM", false, ["encrypt"]);
  const body = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv: nM }, cForEnc, enc.encode(text)),
  );
  return { wrappedContentKey: b64(wrappedContentKey), nC: b64(nC), nM: b64(nM), body: b64(body) };
}
const article1 = await articleUnder(periodForWrap, "article one, delivered at T");
const article2 = await articleUnder(periodForWrap, "article two, same period, later");

// --- T1: the client caches ONLY ciphertext. The response transport is gone. ---
const cache = { periodBlob: b64(wrappedPeriodKey), a1: article1, a2: article2 };
assert.notEqual(
  cache.periodBlob,
  b64(periodBytes),
  "the cached periodKey entry is ciphertext, not the key",
);

// The client uses the opener to unwrap the cached periodKey back to a
// non-extractable handle.
async function openPeriodFromCache() {
  const handle = await subtle.unwrapKey(
    "raw",
    unb64(cache.periodBlob),
    durablePriv,
    { name: "RSA-OAEP" },
    "AES-GCM",
    false,
    ["unwrapKey"],
  );
  assert.ok(
    await refused(() => subtle.exportKey("raw", handle)),
    "reopened periodKey handle must not export",
  );
  return handle;
}
async function openArticle(entry) {
  const period = await openPeriodFromCache();
  const contentKey = await subtle.unwrapKey(
    "raw",
    unb64(entry.wrappedContentKey),
    period,
    { name: "AES-GCM", iv: unb64(entry.nC) },
    "AES-GCM",
    false,
    ["decrypt"],
  );
  assert.equal(contentKey.extractable, false, "reopened contentKey must be non-extractable");
  return dec.decode(
    await subtle.decrypt({ name: "AES-GCM", iv: unb64(entry.nM) }, contentKey, unb64(entry.body)),
  );
}

// --- T2 (later): open article one from the cached ciphertext alone. ---
assert.equal(await openArticle(cache.a1), "article one, delivered at T");
// --- T3 (later still): a different article, same period, same cached blob, no re-unlock. ---
assert.equal(await openArticle(cache.a2), "article two, same period, later");

console.log("cached periodKey stays ciphertext:", cache.periodBlob !== b64(periodBytes));
console.log(
  "T2 opened article one, T3 opened article two - from the cached blob + durable opener, no key bytes on disk",
);
