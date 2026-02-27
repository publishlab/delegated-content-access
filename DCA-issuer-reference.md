# DCA Issuer Reference

How to implement DCA unlock and decrypt - for issuers and CMS integrators.

Status: Working Draft
Copyright 2026 Labrador CMS AS. Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Overview

**Why verification matters:** The client assembles the unlock request from publisher markup. Without verification, a client could swap sealed blobs between content items or across articles to gain access to content it is not entitled to. JWT signatures and proof hashes bind sealed keys to their intended context. How thoroughly an issuer verifies is a choice - more verification makes tampering harder, less verification is simpler to implement. The steps below are recommended to reach the hardening level the spec is designed for (see [threat model](README.md#threat-model)).

The issuer controls the full unlock flow: server-side (verify, unseal, access decisions) and browser-side (decrypt, key management). The publisher or a third party may provide a reference implementation for the browser decrypt flow - if not, the issuer must provide it. The publisher may also provide a placement callback for DOM rendering.

### Issuer checklist

1. Generate keypair (ECDH P-256 or RSA-OAEP) - [prerequisites](#prerequisites-issuer-keypair)
2. Send public key + `keyId` to publisher (PEM format)
3. Receive publisher's signing public key (ECDSA P-256, for ES256 verification)
4. Implement unlock endpoint - [server: unlock endpoint](#server-unlock-endpoint)
   - Authenticate user (issuer owns the user relationship - DCA carries no user identity)
   - Verify JWT signatures (resourceJWT + issuerJWT)
   - Make access decision (which content items, which delivery mode)
   - Unseal granted keys
   - Return granted keys
5. Browser-side JS for decrypt flow (steps 1-6) - publisher or third party may provide a reference implementation, otherwise issuer must provide it

**Key relationship:** The publisher holds only the issuer's public key (provided during onboarding). The issuer keeps the private key. No shared secrets, no runtime coordination. The publisher seals keys with the issuer's public key at render time - only the issuer can unlock them.

**Onboarding exchange** (PEM format):
- Issuer → publisher: issuer's public key (for sealing) + `keyId` (opaque string, issuer chooses format)
- Publisher → issuer: publisher's signing public key (ECDSA P-256, for ES256 verification) + `issuerName` (the key used in `issuerData`, e.g. `"paywall_subscription_service"` - publisher defines the name)

### Prerequisites: issuer keypair

The issuer must generate a keypair before onboarding. The publisher seals keys with the issuer's public key - the issuer chooses the algorithm, the publisher must support it.

| Algorithm | Key type | Tradeoff |
|-----------|----------|----------|
| **ECDH P-256** (recommended) | EC | Fast, small keys, WebCrypto-compatible (edge/Lambda) |
| **RSA-OAEP 2048+** | RSA | Widest runtime support, slower, larger keys. OAEP is the padding mode used at seal time - keygen is just RSA. |

The publisher needs the public key as PEM (base64-encoded SPKI). Private key format and storage is the issuer's choice. Example using OpenSSL:

```bash
# ECDH P-256 (recommended)
openssl ecparam -genkey -name prime256v1 -noout -out issuer-private.pem
openssl ec -in issuer-private.pem -pubout -out issuer-public.pem

# RSA-OAEP 2048
openssl genrsa -out issuer-private.pem 2048
openssl rsa -in issuer-private.pem -pubout -out issuer-public.pem
```

Send `issuer-public.pem` and a `keyId` to the publisher. Keep `issuer-private.pem` on your server - it never leaves your infrastructure.

`keyId` is an opaque string - the publisher stores and echoes it in markup (`issuerData.*.keyId`). During key rollover, the issuer keeps both private keys and uses `keyId` to pick the right one.

Best practice - derive from the key itself (deterministic, no coordination):
```bash
# SHA-256 fingerprint of public key, truncated
openssl pkey -pubin -in issuer-public.pem -outform DER | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=' | cut -c1-10 > issuer-public-key-id.txt
```
A simple date like `"2025-10"` also works for infrequent rotation.

```
Publisher                    Browser                      Issuer Server
    │                           │                             │
    │── markup ────────────────▶│ extract data                │
    │   (sealed content + keys) │                             │
    │                           │── unlock request ──────────▶│
    │                           │   (sealed keys + JWTs)      │ verify JWTs
    │                           │                             │ access decision
    │                           │                             │ unseal keys
    │                           │◀── unlock response ─────────│
    │                           │    (unlocked keys)          │
    │                           │                             │
    │                           │ unwrap contentKey           │
    │                           │ decrypt content             │
    │                           │ place in DOM                │
```

The publisher delivers two markup elements (see [DCA-data-format.md](DCA-data-format.md) for structure and field definitions):
- `dca-data` - JSON with resource metadata, sealed keys, issuer config, and content type info (`contentSealData`)
- `dca-sealed-content` - outer `<template>` containing `<div>` elements keyed by `data-dca-content-name`

### Transport modes

How the issuer delivers keys to the browser is the issuer's domain - DCA does not mandate a transport mode. The crypto chain (sealed keys → unwrap → decrypt) is the same regardless of how keys travel from issuer to browser. Issuers may provide their own browser-side JavaScript for key delivery.

**Direct transport (default):** Issuer returns unlocked keys as readable JSON values. Simple and universal. Key bytes are visible in JavaScript scope.

**Client-bound transport (opt-in):** Issuer's JavaScript generates a non-extractable WebCrypto keypair and negotiates key delivery with the issuer's server. The raw key bytes never appear in JavaScript scope.

The flow below covers both modes. Where they diverge, both paths are shown.

### Quick reference (browser)

Nonce/AAD definitions are normative in [DCA-data-format.md#nonces-and-aad](DCA-data-format.md#nonces-and-aad). Everything the browser needs comes from publisher markup. Two crypto operations (both AES-256-GCM), plus request assembly:

| Operation | Key | Input | Nonce | AAD |
|-----------|-----|-------|-------|-----|
| **Decrypt content** | contentKey | `dca-sealed-content` → `[data-dca-content-name]` | `contentSealData[contentName].nonce` | `contentSealData[contentName].aad` |
| **Unwrap contentKey** | periodKey | `sealedContentKeys[contentName][i].key` | `sealedContentKeys[contentName][i].nonce` | - |
| **Build unlock request** | - | `version` + `issuerName` + `resource` + `resourceJWT` + `issuerJWT[issuerName]` + `issuerData.<issuerName>.sealed` + `keyId` | - | - |

Full implementation: [Browser: Unlock and decrypt](#browser-unlock-and-decrypt) (steps 1-6).


## Server: Unlock endpoint

The browser sends unlock requests cross-origin (publisher domain → issuer domain). The endpoint must handle CORS or the browser silently blocks the response.

`POST` with `Content-Type: application/json` triggers a preflight `OPTIONS` request. Both the preflight and the actual response need CORS headers:

```
Access-Control-Allow-Origin: https://www.news-site.com
Access-Control-Allow-Methods: POST
Access-Control-Allow-Headers: Content-Type
```

Use the publisher's origin (from onboarding), not `*`. Multiple publishers = check the `Origin` header against a whitelist.

DCA unlock does not require cookies. If the issuer's auth relies on the user's session cookies on the issuer's domain, add `Access-Control-Allow-Credentials: true` and use `credentials: 'include'` on the fetch (`*` is not allowed for `Allow-Origin` when credentials are used). Note: these are third-party cookies (publisher page → issuer domain) and subject to browser restrictions.

Typical unlock requests are 5-10KB. Consider a request body size limit (e.g., 64KB) to reject oversized payloads before processing.

### Verify request

Unlock requests must include `resourceJWT`, `issuerJWT` (both signed), and `issuerName`. `resource` (plain JSON) is unsigned - use only for publisher key lookup (step below), never for access decisions. Use verified JWT payload claims for all access logic. Verify `issuerJWT` for blob integrity before unsealing. See [dca-data](DCA-data-format.md#dca-data-json) for field structure and [signed envelopes](DCA-data-format.md#signed-envelopes) for JWT details.

**Verify signatures and bindings:**
- Validates `version` - forwarded from markup. Current version is `"1"`. Verify and handle according to issuer capabilities - reject unsupported versions
- Identifies the publisher by `resource.domain` - used to select the correct signing key. Always look up by domain, even with a single publisher (adding a second publisher should just work)
- Looks up publisher's signing public key for that domain (obtained during onboarding)
- Verifies `resourceJWT` signature (ES256) using that signing key → confirms data originates from publisher. If `resource.domain` was tampered with, the wrong signing key is selected and verification fails. Do not add expiry/freshness checks - `issuedAt` is render-time debug metadata, not a validity window (markup is edge-cached, old values are normal)
- Verifies `issuerJWT` signature (ES256) using the same signing key. Both JWTs must carry the same `renderId` (proves they come from the same render). From the verified payloads: check `issuerJwtPayload.renderId === resourceJwtPayload.renderId` and `issuerJwtPayload.issuerName === request.issuerName`
- Verifies `issuerJwtPayload.issuerName` matches the configured issuer for this endpoint/route (reject mismatch)

**Select key and authenticate:**
- Selects issuer private key using `issuerName` + `keyId` from the request (for key rollover - see [keypair prerequisites](#prerequisites-issuer-keypair))
- Authenticates the user - the unlock endpoint is the issuer's auth touchpoint. The issuer's browser JS handles login/auth as part of the unlock flow (redirect, popup, existing session - issuer's choice). DCA carries no user identity

Use a JWT library for signature verification. Pin expected algorithm to ES256, reject any other `alg` value.

**Suggested failure handling - two classes:**

- **Integrity failure** (reject entire request): bad JWT signature, renderId mismatch, issuerName mismatch, proof hash mismatch. These validate as a group - JWTs and sealed keys are cryptographically bound and should all pass or all fail. Likely indicates tampering or a bug. Implementer should log these for investigation.
- **Operational failure** (partial response): unseal fails for individual blobs (key rollover race, unknown keyId, corrupted cache). Consider returning successfully unsealed keys and reporting errors per content item. See [unlock response](#unlock-response).

Implementers should take care to distinguish these - any integrity failure should reject the entire request (HTTP 400), not attempt partial processing.

**Replay protection:** DCA does not include replay prevention - unlock requests with valid JWTs can be replayed within the periodKey rotation window. Rate limiting, renderId dedup, or metering controls are the issuer's responsibility, handled through the issuer's own auth layer.

### Unseal keys

`base64urlDecode` and `base64urlEncode` used below - see [binary encoding](DCA-data-format.md#scope).

Each sealed value in `request.sealed.<contentName>.contentKey` and `.periodKeys[t]` is an opaque blob - the output of the publisher's seal operation using the issuer's public key. The issuer decrypts it with the corresponding private key. The sealed value contains everything needed for decryption (algorithm-specific internals like nonces or ephemeral keys are packed inside the blob by the publisher's seal implementation).

```
seal(keyBytes, issuerPubKey)  → sealedKeyBytes     // publisher, at render
unseal(sealedKeyBytes, issuerPrivKey)  → keyBytes   // issuer, at unlock
```

**Proof verification (before unseal):** `issuerJWT` payload includes `proof` - signed SHA-256 hashes of the issuer's sealed blobs (mirrors the shape of `sealed`). The issuer hashes each incoming sealed blob and compares to the signed proof. Mismatch - reject (integrity failure). This prevents content item relabeling in unlock requests.

The client may send a subset of sealed keys (cache-resolved items omitted). The proof covers all items, but the issuer only verifies and unseals what it receives. The proof protects against swapping or adding blobs. Omitting items is expected (cache-resolved items are not sent).

```javascript
// issuerJwtPayload is verified issuerJWT payload with { renderId, issuerName, proof }
// Before using proof, verify bindings:
//   issuerJwtPayload.renderId === resourceJwtPayload.renderId
//   issuerJwtPayload.issuerName === request.issuerName
async function hashSealedBlob(sealedValueB64url) {
    // Note: hash the base64url string directly, NOT the decoded binary.
    // Unlike typical crypto patterns, DCA hashes the wire representation for simplicity.
    const bytes = new TextEncoder().encode(sealedValueB64url);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return base64urlEncode(new Uint8Array(digest)); // 43-char base64url
}

// Before unseal - verify each sealed blob against proof.
// Content items not in proof are rejected (undefined !== actual).
const proof = issuerJwtPayload.proof;
for (const [contentName, sealedItem] of Object.entries(request.sealed)) {
    const actual = await hashSealedBlob(sealedItem.contentKey);
    if (proof[contentName]?.contentKey !== actual) throw new Error("proof_mismatch");

    for (const [t, blob] of Object.entries(sealedItem.periodKeys || {})) {
        const actual = await hashSealedBlob(blob);
        if (proof[contentName]?.periodKeys?.[t] !== actual) throw new Error("proof_mismatch");
    }
}
```

Use `issuerName` + `keyId` from the request to select the correct private key (important during key rollover). The issuer knows its own algorithm from the key - no algorithm field in the wire format. During algorithm migration (e.g., RSA → ECDH), encode the new algorithm in the new key's `keyId` (e.g., `"ecdh-2025-10"`) - no need to rename existing keys. Old `keyId` values continue to resolve to the old algorithm. Keep both keys available until cached markup sealed with the old key expires.

**Unseal - by algorithm:**

Both algorithms: the sealed blob is self-contained. The publisher's seal packs everything the issuer needs to unseal. The issuer loads its private key at startup in whatever format it uses (JWK, PKCS#8, PEM). Examples below use WebCrypto (`crypto.subtle`).

**ECDH P-256:**

Sealed blob packs: ephemeral public key + iv + ciphertext. See [sealed blob format](DCA-data-format.md#sealed-blob-format) for layout.

```javascript
// issuerPrivateKey: CryptoKey - imported once at startup (JWK, PKCS#8, etc.)

// Sealed values arrive as base64url strings in JSON - decode to bytes first
const sealedKeyBytes = base64urlDecode(sealedValue);

// Parse sealed blob (65-byte pubkey | 12-byte iv | ciphertext+tag)
const ephemeralPublicKeyRaw = sealedKeyBytes.slice(0, 65);
const iv = sealedKeyBytes.slice(65, 77);
const ciphertext = sealedKeyBytes.slice(77);

const ephemeralPublicKey = await crypto.subtle.importKey(
    "raw", ephemeralPublicKeyRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false, []
);

const sharedKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: ephemeralPublicKey },
    issuerPrivateKey,
    { name: "AES-GCM", length: 256 },
    false, ["decrypt"]
);

const keyBytes = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    sharedKey,
    ciphertext
);
// → base64urlEncode(keyBytes) for the unlock response
```

**Non-WebCrypto runtimes:** The AES-256-GCM key is the raw ECDH shared secret (x-coordinate of the shared point, 32 bytes) used directly - no KDF. WebCrypto's `deriveKey` does this implicitly. Other runtimes need to do it explicitly. Node.js 16+ has `crypto.subtle` (WebCrypto) - prefer the WebCrypto example above. Python example:

```python
# Python (cryptography library)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Sealed values arrive as base64url strings in JSON - decode to bytes first
sealed_bytes = base64url_decode(sealed_value)

# Parse sealed blob (65-byte pubkey | 12-byte iv | ciphertext+tag)
ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), sealed_bytes[:65])
iv = sealed_bytes[65:77]
ciphertext_with_tag = sealed_bytes[77:]

shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
# shared_secret is 32 bytes - use directly as AES key, no HKDF

aes = AESGCM(shared_secret)
key_bytes = aes.decrypt(iv, ciphertext_with_tag, None)
```

If AES-GCM decryption fails despite correct keys, check that no KDF is applied after key agreement.

**RSA-OAEP:**

```javascript
// issuerPrivateKey: CryptoKey - imported once at startup (JWK, PKCS#8, etc.)

const sealedKeyBytes = base64urlDecode(sealedValue);

// Single WebCrypto call - RSA-OAEP maps directly
// hash: SHA-256 (set at key import time in WebCrypto; specify per-operation in other runtimes)
const keyBytes = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    issuerPrivateKey,
    sealedKeyBytes
);
// → base64urlEncode(keyBytes) for the unlock response
```

**Key import examples** (runtime-specific, once at startup):
```javascript
// WebCrypto (V8, Lambda, edge) - PEM → PKCS#8 DER → CryptoKey
const pem = fs.readFileSync("issuer-private.pem", "utf8");
const der = base64urlDecode(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')); // handles standard base64 too
const issuerPrivateKey = await crypto.subtle.importKey(
    "pkcs8", der,
    { name: "ECDH", namedCurve: "P-256" },  // or { name: "RSA-OAEP", hash: "SHA-256" }
    false, ["deriveKey"]                      // or ["decrypt"] for RSA-OAEP
);
```
```javascript
// Node.js native crypto
const { createPrivateKey } = require("crypto");
const issuerPrivateKey = createPrivateKey(fs.readFileSync("issuer-private.pem"));
```
```python
# Python
from cryptography.hazmat.primitives.serialization import load_pem_private_key
private_key = load_pem_private_key(open("issuer-private.pem", "rb").read(), password=None)
```

### Access decision

The issuer decides **per request, per content item** what to return. Nothing is hardcoded - the same user may get different delivery depending on the article, the content item, or any business logic the issuer applies.

Two levels of access:
- **contentKey** - one article, one render. Unique per render, tied to this page. Browser decrypts and discards - nothing is reusable. Issuer sees every article visit.
- **periodKey** - per contentName for a time period. Shared across all articles within the period. Browser caches and reuses - no unlock needed for subsequent articles. Fewer requests, more resilient to issuer downtime. The issuer does not check or interpret `t` values. For granted content items, the access decision is contentKey (single view) or periodKeys (all content of that type for a period). For periodKey delivery, unseal all `t` values and return them - time rotation is handled by the publisher (key derivation) and client (trial unwrap).

The issuer can mix levels in the same response. Examples:

- Free trial: return `contentKey` only for `bodytext` - per-view, no caching, no premium content items
- Subscriber: return `periodKeys` for all content items - cached, works across articles
- Metered access: return `contentKey` for first N articles, then stop returning keys

Since each content item is independent, access is granular. The issuer is not choosing from a fixed set of tiers - it constructs the response dynamically from the sealed keys it received.

### Unlock response

Keys returned are unlocked. Response Content-Type: `application/json`. Issuer only returns keys for the granted access level.

**Direct transport:** key values are base64url-encoded raw bytes (32 bytes for AES-256). The issuer unseals, base64url-encodes, returns in JSON.

**Client-bound transport:** key values are wrapped for the client's public key. The browser unwraps with its non-extractable private key - raw bytes never appear in JS.

**Detection** by field presence per content item:
- `contentKey` → contentKey delivery: browser decrypts immediately
- `periodKeys` → periodKey delivery: browser unwraps contentKey from `sealedContentKeys`, then decrypts
- Mixed modes supported in same response (different content items, different delivery). If both fields are present for a single content item, `contentKey` takes precedence (periodKeys are still cached)

**contentKey delivery:**
```json
{
    "keys": {
        "bodytext": {
            "contentKey": "<contentKey>"
        }
    }
}
```

**periodKey delivery:**
```json
{
    "keys": {
        "bodytext": {
            "periodKeys": {
                "251023T13": "<periodKey-h13>",
                "251023T14": "<periodKey-h14>"
            }
        }
    }
}
```

**Mixed modes** (different content items, different delivery):
```json
{
    "keys": {
        "bodytext": {
            "contentKey": "<contentKey>"
        },
        "premiumtext": {
            "periodKeys": {
                "251023T13": "<periodKey-h13>",
                "251023T14": "<periodKey-h14>"
            }
        }
    }
}
```

**Partial grant (HTTP 200):** The issuer may return keys for some content items and omit others. The browser decrypts what it receives - missing content items remain sealed.

**Denial:** Access denied is the issuer's domain. HTTP 401 with an optional JSON body (reason, login URL, etc.) is a reasonable default. The browser handles denial in the issuer's own JS - not specified by DCA.

**Unseal failure (HTTP 200, partial with errors):** If unsealing fails for some content items (wrong key, corrupted blob, key rollover race), return successfully unsealed keys and report errors per content item. The browser decrypts what it can - failed items remain sealed. Common during key rollover: cached markup sealed with old key, issuer already rotated.

```json
{
    "keys": {
        "bodytext": {
            "periodKeys": { "251023T13": "<periodKey-h13>", "251023T14": "<periodKey-h14>" }
        }
    },
    "errors": {
        "premiumtext": { "error": "unseal_failed", "message": "Key mismatch - keyId may be stale" }
    }
}
```

**Client-bound transport:** When the unlock request includes a client public key, wrap returned keys with that public key instead of returning raw values. The browser unwraps with its non-extractable private key.


## Browser: Unlock and decrypt


### 1. Extract data from markup

Extract the two DCA elements from the page:

```javascript
const dcaData = JSON.parse(document.querySelector('.dca-data').textContent);
const sealedOuter = document.querySelector('template.dca-sealed-content');
```

For JSON API responses (headless CMS, SPAs), sealed ciphertext is in `sealedContent[contentName]` instead of the DOM query - see [JSON API variant](DCA-data-format.md#json-api-variant). The crypto chain is identical.

### 2. Check periodKey cache

Before calling the issuer, check if cached periodKeys can already unwrap the contentKeys in `sealedContentKeys`.

```javascript
// Track resolved items to avoid double-decrypt in step 4
// (placement callbacks may have side effects; metered issuers may double-count)
const resolved = new Set();
for (const [contentName, entries] of Object.entries(dcaData.sealedContentKeys)) {
    const cached = cache.getNewestFirst(contentName); // [key, key, ...] newest t first
    if (cached) {
        const contentKey = await tryUnwrap(cached, entries);
        if (contentKey) {
            try { await decryptAndPlace(contentName, contentKey); } catch { continue; }
            resolved.add(contentName);
        }
    }
}
```

Content items resolved from cache skip the unlock request. Only unresolved content items need unlocking. If all content items resolve from cache, skip the unlock request entirely (no network call needed). Sending all sealed keys is simpler and always correct - the issuer handles whatever it receives. Optionally filter `sealed` to exclude resolved items (avoids unnecessary unsealing, prevents double-counting for metered access).

### 3. Build and send unlock request

Pick an issuer from `issuerData`. `resourceJWT`, `issuerJWT`, and `issuerName` are required - the issuer verifies all three (JWT signatures + issuer routing match + renderId binding). `resource` is required (issuer uses `domain` for key lookup, JWT claims for access decisions). `unlockUrl` is the endpoint - available in markup for publisher-provided reference scripts; issuer SDKs typically have it built in.

```javascript
const issuerName = "paywall_subscription_service";
const issuer = dcaData.issuerData[issuerName];

const unlockRequest = {
    version:     dcaData.version,                // DCA format version - forward from markup
    issuerName,                                  // required - issuer routing/binding
    resource:    dcaData.resource,               // issuer uses domain for key lookup, JWT claims for access decisions
    resourceJWT: dcaData.resourceJWT,            // required - issuer verifies for access decisions
    issuerJWT:   dcaData.issuerJWT[issuerName],  // required - issuer verifies for blob integrity
    sealed:      issuer.sealed,
    keyId:       issuer.keyId
};
```

**Client-bound transport** adds a client public key to the request:
```javascript
// Generate or load persistent non-extractable keypair (IndexedDB - omitted for brevity)
const clientKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false, // non-extractable
    ["deriveKey"]
);

unlockRequest.clientPublicKey = await crypto.subtle.exportKey("jwk", clientKeyPair.publicKey);
```

```http
POST /unlock
```
Note: `resource.renderId` is an unsigned convenience copy - authoritative value is in `resourceJWT` payload. `issuerJWT` is resolved from `issuerJWT[issuerName]` in markup.

```json
{
    "version": "1",
    "issuerName": "paywall_subscription_service",
    "resource": {
        "renderId": "<renderId>",
        "domain": "www.news-site.com",
        "issuedAt": "2025-10-23T14:00:00Z",
        "resourceId": "123456",
        "data": {
            "date.published": "2025-10-20T10:30:00Z",
            "section": "politics",
            "tags": ["breaking", "elections", "analysis"],
            "fields.extractedCustomField1": "customValue"
        }
    },
    "resourceJWT": "eyJhbGciOiJFUzI1NiJ9...EXAMPLE",
    "issuerJWT": "eyJhbGciOiJFUzI1NiJ9...EXAMPLE",
    "keyId": "2025-10",
    "sealed": {
        "bodytext": {
            "contentKey": "<contentKey--sealed-with--issuer-pubkey>",
            "periodKeys": {
                "251023T13": "<periodKey-h13--sealed-with--issuer-pubkey>",
                "251023T14": "<periodKey-h14--sealed-with--issuer-pubkey>"
            }
        },
        "premiumtext": {
            "contentKey": "<contentKey--sealed-with--issuer-pubkey>",
            "periodKeys": {
                "251023T13": "<periodKey-h13--sealed-with--issuer-pubkey>",
                "251023T14": "<periodKey-h14--sealed-with--issuer-pubkey>"
            }
        }
    }
}
```

### 4. Handle response

The client must try all keys returned in the unlock response. contentKeys are used for immediate decryption, periodKeys are cached and used to unwrap contentKeys. Keys that fail decryption are skipped (AES-GCM auth tag catches bad keys).

```javascript
// Send unlockRequest to issuer.unlockUrl (POST, JSON) → unlockResponse

for (const [contentName, keyData] of Object.entries(unlockResponse.keys)) {
    // Always cache periodKeys (even for resolved items - refreshes cache for future articles)
    if (keyData.periodKeys) {
        for (const [t, b64key] of Object.entries(keyData.periodKeys)) {
            try { cache.set(contentName, t, await importKey(b64key)); } catch { continue; }
        }
    }
    if (resolved.has(contentName)) continue; // already decrypted from cache in step 2
    if (keyData.contentKey) {
        // contentKey delivery - decrypt immediately
        try {
            const contentKey = await importKey(keyData.contentKey);
            await decryptAndPlace(contentName, contentKey);
        } catch { continue; } // bad key - skip this content item
    } else if (keyData.periodKeys) {
        // periodKey delivery - unwrap contentKey, then decrypt
        const periodKeys = cache.getNewestFirst(contentName);
        const contentKey = await tryUnwrap(periodKeys, dcaData.sealedContentKeys[contentName]);
        if (!contentKey) continue; // stale markup - no matching period, skip this content item
        try { await decryptAndPlace(contentName, contentKey); } catch { continue; }
    }
}
// unlockResponse.errors - per-content-item failures (unseal_failed, key rollover race).
// Content items in errors remain sealed. Handle as appropriate (retry, show fallback, log).
```

**`importKey`** - key values in the response are base64url-encoded raw bytes (see [binary encoding](DCA-data-format.md#scope)):
```javascript
async function importKey(b64url) {
    return crypto.subtle.importKey(
        "raw", base64urlDecode(b64url),
        { name: "AES-GCM", length: 256 },
        false, ["decrypt"]
    );
}
```

**Client-bound transport:** `importKey` above becomes `unwrapKey` using the non-extractable client private key. Keys arrive wrapped, not as raw bytes:
```javascript
// Direct:       importKey(raw bytes) → CryptoKey
// Client-bound: unwrapKey(wrapped bytes, clientPrivateKey) → CryptoKey (non-extractable)
```

### 5. Unwrap contentKey with periodKeys (trial unwrap)

Try each periodKey (newest `t` first) against each sealedContentKey entry until one succeeds. AES-GCM guarantees: wrong key = auth failure (exception), never silent garbage. A failed attempt does not discard the key - it may match an article from a different period.

```javascript
async function tryUnwrap(periodKeys, sealedEntries) {
    for (const periodKey of periodKeys) {
        for (const entry of sealedEntries) {
            try {
                const rawKey = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: base64urlDecode(entry.nonce) }, // no AAD - periodKey is already content-specific (HKDF-derived)
                    periodKey,
                    base64urlDecode(entry.key)
                );
                return await crypto.subtle.importKey(
                    "raw", rawKey,
                    { name: "AES-GCM", length: 256 },
                    false, ["decrypt"]
                );
            } catch {
                continue;
            }
        }
    }
    return null;
}
```

**Client-bound transport:** same trial loop, replace `decrypt` + `importKey` with `unwrapKey` - raw key bytes never appear in JS scope:
```javascript
// Direct:       decrypt(periodKey, wrapped) → raw bytes → importKey() → CryptoKey
// Client-bound: unwrapKey(periodKey, wrapped) → CryptoKey (non-extractable, no raw bytes exposed)
```

**Why multiple periodKeys?** Articles can be cached across hour boundaries. If a user unlocks at 14:55 and navigates to an article rendered at 15:05, the contentKey was sealed with periodKey-15, not periodKey-14.

**Try sequence:** periodKeys from cache, newest `t` first × sealedContentKeys entries. First success wins. Clock skew is irrelevant - just try keys.

**Hour boundary example:**
```
14:45 - User unlocks article (period="14") → gets periodKey-14 + periodKey-15
15:05 - User navigates to article rendered at 15:02 (period="15")
      - Cache has: periodKey-15, periodKey-14 (newest first)
      - Try periodKey-15 × entry t="15" → SUCCESS (first try)
```

### 6. Decrypt content

Read nonce and AAD, decrypt ciphertext from `dca-sealed-content`.

```javascript
async function decryptAndPlace(contentName, contentKey) {
    const sealData = dcaData.contentSealData[contentName];
    const nonce = base64urlDecode(sealData.nonce);
    const aad = new TextEncoder().encode(sealData.aad);

    const el = sealedOuter.content.querySelector(
        `[data-dca-content-name="${contentName}"]`
    );
    if (!el) return; // deferred content - fetch ciphertext from URL (delivery format TBD)
    const ciphertext = base64urlDecode(el.textContent.trim());

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad },
        contentKey,
        ciphertext
    );

    Lab.v1.dca.placeContent(contentName, decrypted, sealData.contentType); // publisher-specific - see Content placement
}
```

## Browser: periodKey cache

Cache periodKeys from periodKey delivery responses for reuse across articles. Only periodKey delivery populates the cache - contentKey delivery does not.

**Scope:** One cache per contentName, scoped to the browser origin (no domain in cache key needed - localStorage and IndexedDB are origin-scoped). periodKeys are publisher-derived (via HKDF), not issuer-specific - any issuer returning the same contentName yields the same key bytes. periodKeys are shared across issuers for the same contentName. If multiple issuers are granted the same content items, a periodKey from one issuer's cache works for articles accessed via another. Publishers should consider this when granting overlapping content items to issuers with different access models.

**Structure:** Map of `t → key` per contentName, evict oldest `t` when full. `t` is the period bucket from `sealedContentKeys` entries (e.g., `"251023T14"`). Max size: implementation choice (e.g., 8-12 entries).

Each unlock typically returns 2 periodKeys per contentName: current period + next (the overlap key). periodKeys are deterministic per period (`HKDF(secret, contentName, period)`), so duplicate keys from different articles in the same period have the same `t` - dedup by string equality. The cache grows by ~1-2 unique keys per period crossing, not per article visit.

```
cache[contentName] = {
  "251023T17": periodKey-h17,
  "251023T16": periodKey-h16,
  "251023T15": periodKey-h15,
  "251023T14": periodKey-h14,
}

Add key:
1. Dedup by t (same t = same period = same key bytes while periodSecret is stable). After periodSecret rotation, cached keys with the same `t` may differ - tryUnwrap handles this (wrong key fails, triggers unlock)
2. Evict oldest t when full

Retrieve: getNewestFirst(contentName) → keys sorted by t descending
```

No clock awareness needed - the client does not interpret `t` as a timestamp, only uses string operations: dedup (equality), sort (lexicographic, newest first for trial unwrap), evict (oldest `t` when full).

**Never discard a key because it failed a trial unwrap.** A periodKey that fails on this article may succeed on an article from a different period - articles span periods, that's the whole concept. Eviction is only by cache size (oldest `t`), never by trial outcome.

**Eviction is safe.** Cache is optimization, not correctness. Evicted key → cache miss → unlock request. Each article carries its own sealed keys, unlock always works.

**Partial cache hits:** An article may have some content items cached and others not. Hits decrypt locally, misses trigger an unlock request for only the missing content items.

**Storage options:**

| | localStorage | IndexedDB |
|--|--|--|
| Raw key bytes (direct transport) | Yes | Yes |
| CryptoKey objects (client-bound transport) | No | Yes |
| Shared across tabs | Yes | Yes |


## Integration architecture

The issuer's integration has two parts - a server endpoint and browser JavaScript. The publisher or a third party may provide a reference implementation for the browser decrypt flow (any transport mode) - if not, the issuer must provide it. The publisher may also provide a placement callback. Neither side handles the other's concern.

### Decrypt object

The issuer provides a decrypt object that encapsulates the full client flow (steps 1-6 above). The publisher may provide a placement callback. The decrypt chain is transport-specific internally; the placement callback is identical regardless of transport mode.

- **Direct transport:** raw key bytes arrive in JS → `importKey()` → decrypt chain. Key bytes are briefly visible in JS scope.
- **Client-bound transport:** `unwrapKey()` produces non-extractable CryptoKey handles → decrypt chain. Raw bytes never appear in JS.

**SubtleCrypto chain (client-bound mode):** Terms below (`transportPublicKey`, `transportSharedKey`, `transportNonce`) are issuer implementation details, not part of the DCA wire format.
```
IndexedDB(clientPrivateKey) + transportPublicKey
    → deriveKey(ECDH) → transportSharedKey (non-extractable AES-GCM)
        + IndexedDB(wrapped periodKey + transportNonce)
            → unwrapKey(AES-GCM) → periodKey (non-extractable)
                → unwrapKey(AES-GCM) → contentKey (non-extractable)
                    → decrypt(AES-GCM) → plaintext → placement callback → DOM
```

`transportNonce` is generated by the issuer's server per wrapped key and sent alongside it in the unlock response. This is an issuer implementation detail - not part of the wire format.

### Content placement

A publisher may provide a reference placement script. The issuer's decrypt chain calls it with the decrypted plaintext - the callback handles DOM rendering, never sees key material. The API shape is publisher-specific (each publisher uses their own namespace), not part of DCA.

```javascript
// Example: Labrador CMS placement callback
Lab.v1.dca.placeContent(contentName, decryptedBytes, contentType)
// Publisher handles text vs binary decode based on contentType
```

The publisher knows its own markup - `contentName` identifies where and how to place the content. The publisher's script registers the callbacks. The issuer's decrypt object calls the appropriate one after successful decryption.


## Client-bound transport: security properties

**What it adds:**
- XSS cannot extract raw key bytes (`exportKey()` throws on non-extractable keys)
- Keys cannot be copied to another device or browser for offline sharing

**What it does not add:**
- No protection against modified browsers (can override `extractable: false`)
- No protection against DOM scraping (decrypted content is still in the page)
- XSS can still use keys as decrypt oracles or clone CryptoKey handles via `postMessage` (structured-clonable)
- Does not change the threat model. Raises the bar within the same trust boundaries

`extractable: false` prevents `exportKey()` and `wrapKey()` from returning raw key bytes. However, CryptoKey objects are structured-clonable (W3C Web Crypto spec). This limits what the protection actually provides:

| Threat | Protected? | Why |
|--------|------------|-----|
| Key bytes leaked via XSS | Yes | `exportKey()` throws on non-extractable keys |
| Key copied to another device for sharing | Yes | No way to extract raw bytes for transfer |
| XSS using key as decrypt oracle | No | Attacker has script execution, can call `decrypt()` |
| XSS exfiltrating CryptoKey via `postMessage` | No | Structured clone sends the handle cross-origin |
| Modified browser / Spectre | No | Process-level access bypasses all JS restrictions |

The W3C spec authors describe non-extractable as obfuscation rather than a security primitive. Render-process compromise (Spectre, browser extensions with host permissions) can recover key material regardless of the extractable flag.

**What client-bound actually provides:** prevents casual key extraction and offline sharing. An active XSS attacker with code execution can still use keys as oracles or clone them via `postMessage`, but cannot extract portable key material. This raises the bar without changing the fundamental trust boundary: content decrypted in the browser is accessible to code running in that browser.

References:
- [MDN: SubtleCrypto.unwrapKey()](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/unwrapKey) - `extractable` parameter on unwrapped result
- [MDN: CryptoKey.extractable](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/extractable) - structured-clonable, exportKey restriction
- [W3C WebCrypto Issue #269: Security model for non-extractable keys](https://github.com/w3c/webcrypto/issues/269) - spec authors on obfuscation vs security primitive
- [W3C Web Crypto API Level 2](https://w3c.github.io/webcrypto/) - normative spec


## Appendix: Importing publisher's signing key (WebCrypto)

The publisher sends their signing public key as PEM during onboarding. The issuer needs it to verify `resourceJWT` and `issuerJWT` signatures. WebCrypto doesn't import PEM directly - strip headers and base64-decode to SPKI DER:

```javascript
const pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKo...base64...\n-----END PUBLIC KEY-----";
const der = base64urlDecode(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')); // handles standard base64 too

const verifyKey = await crypto.subtle.importKey(
    "spki", der,
    { name: "ECDSA", namedCurve: "P-256" },  // ES256 = ECDSA P-256 + SHA-256
    true, ["verify"]
);
```

Convert once at startup, not per request. Traditional server environments (Node.js, PHP, Python) import PEM natively. The issuer's own private key storage is an implementation choice - not covered here.
