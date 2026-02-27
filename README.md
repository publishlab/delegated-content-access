# Delegated Content Access (DCA)

*A design for delegating content access control from publisher system to multiple independent issuers.*

DCA encrypts content at render time and delegates access decisions to independent issuers (subscription services, CRM systems, SSO providers) who hold the user relationships and make unlock decisions directly. The publisher delivers encrypted content without handling user authentication or entitlement logic.

## How it works

1. Publisher seals content and keys at render time
2. Client receives sealed markup (content unreadable, keys unusable)
3. Client forwards sealed keys to issuer
4. Issuer unlocks keys, returns them to client
5. Client decrypts content

Markup is identical for all users - cacheable at edge. Access control happens at unlock time, not render time. Harder than CSS, not DRM.

**Terminology:** DCA uses **sealed** for encrypted/wrapped data (opaque, unusable without a key) and **unlocked** for the reverse. Not "locked" - that implies visibility behind bars. Sealed means opaque, can't even inspect. Field names are semantic (`contentKey`, `periodKey`), not crypto jargon (`wrappedCEK`).

## Actors

| Actor | Role |
|-------|------|
| **Publisher** | Encrypts and delivers content. Derives keys, configures issuers, renders DCA markup or API responses. |
| **Issuer** | Controls access. Holds private key, makes unlock decisions. Owns both sides: server (verify, unseal, decide) and browser JS (decrypt, cache, render). One team, one integration. |
| **Client** | Requests unlock, decrypts, renders content. |

## Background

The typical approach to content access control is server-side gating: the publisher integrates with each access provider, handles OAuth flows, parses provider-specific ID tokens and entitlement formats, and maps them to content. Some providers require deeper integration: session management, identity federation, or user state on the publisher side.

DCA inverts this: the publisher encrypts content once and delegates access decisions entirely to issuers. No per-provider integration, no user state on the publisher side.

## Design goals

- **Asymmetric trust:** Publisher holds only issuer public keys, never private keys. Publisher breach cannot compromise issuer credentials.
- **Multi-issuer:** Each issuer holds its own private key. Separate trust boundaries, no shared secrets. Compromising one issuer does not expose others.
- **Zero runtime coordination:** Publisher only needs issuer pubkey at render time. No API calls, OAuth, or sync.
- **Multi-publisher ready:** Issuers identify the publisher by domain and look up the corresponding signing key. Adding a second publisher should just work - no code changes, just a new key in the issuer's config.
- **Opaque unlock:** DCA specifies the encryption envelope, not how the issuer delivers keys to the client. Issuers choose their own transport.
- **CDN-friendly:** Encrypted content is identical for all users. Cacheable at edge without per-user rendering.
- **Crypto:** Symmetric encryption for content, asymmetric key transport per issuer, deterministic key derivation for time-windowed caching. See [DCA-data-format.md](DCA-data-format.md) for algorithms and wire format.
- **Security parity with cookies:** [Direct transport](DCA-issuer-reference.md#transport-modes): keys are replayable (like any bearer credential). [Client-bound transport](DCA-issuer-reference.md#client-bound-transport-security-properties): keys are bound to the browser (like session cookies, if unmodified). DCA does not ask for more trust in the browser than cookie-based gating already does.

## Content items

Articles contain multiple independently encrypted content items (e.g., `bodytext`, `premiumtext`, `locked-data`). Each has its own key and can contain any data type (HTML, JSON, image URLs). The issuer decides which to unlock per user, composing access dynamically from the available items. Same markup, same keys - the access policy lives entirely on the issuer side. The publisher does not need to know about issuer tier structures.

## Period keys

Without periodKeys, every article requires a separate unlock request. A periodKey (a time-windowed key) gives access to a specific content item across all articles within a time period. The client caches periodKeys, reuses across articles - fewer unlock requests.

**Trade-off:** Longer period = more reuse but wider key sharing window. Acceptable for non-DRM use cases.

**Clock-independent:** Only the publisher needs clock sync (to derive periodKeys at render time). The issuer unseals whatever the publisher sealed - no time awareness needed. The client tries periodKeys in order until one works.

## Data flow

Sequence diagram: [DCA-issuer-reference.md](DCA-issuer-reference.md#overview).

**Publisher → Client** (in markup, at render time):
- Sealed content (unreadable without keys)
- Sealed contentKey and sealed periodKeys per issuer (unusable without issuer's private key)
- Issuer endpoint identifiers

**Client → Issuer** (unlock request):
- Forwards sealed keys meant for this issuer
- `resourceJWT` (issuer verifies publisher origin, reads claims for access decisions)
- `issuerJWT` (issuer verifies sealed blob integrity and binding to the correct resource and issuer before unsealing)

**Issuer → Client** (unlock response):
- Unlocked contentKey (one article, per-view users) or unlocked periodKeys (cacheable across articles, subscribers)

**Never exchanged:**
- `periodSecret` - stays on publisher, derives periodKeys
- `issuerPrivateKey` - stays on issuer, unseals keys

**Access control is in the sealing.** The publisher grants issuers access to content items by sealing keys for them. Two issuers may be granted the same content items. The differentiation is which content items the publisher seals for each issuer, controlled at render time.

## Key layers

Three layers, three independent dimensions:

Normative wire-format details: [DCA-data-format.md#key-hierarchy](DCA-data-format.md#key-hierarchy).

| Layer | Dimension | Controls |
|-------|-----------|----------|
| **contentKey** | What + when | Per content item, per render |
| **periodKey** | Caching | Cross-article reuse within time window |
| **issuerPublicKey** | Who decides | Per-issuer delegation |

The issuer composes access from these primitives: which content items to unlock (granularity), contentKey vs periodKey per item (one-time vs cached), different decisions per user/article/request, mixed modes in the same response.

### Layers of encapsulation

#### a) contentKey delivery

Direct: one unlock request per article. Issuer returns the contentKey, client decrypts immediately.

<pre>
<b>content</b>
  ← sealed with <b>contentKey</b>
    ← sealed with <b>issuerPublicKey</b>
</pre>

Sealing (publisher, at render time):
- Publisher seals content with contentKey
- Publisher seals contentKey with issuerPublicKey

Unlocking (client, at page load):
- Client sends sealed keys to issuer
- Issuer unlocks contentKey with issuerPrivateKey
- Client decrypts content with contentKey

#### b) periodKey delivery

Cached: one unlock request per time period. Issuer returns a periodKey, client unlocks contentKey locally, then decrypts. periodKey is cacheable across articles.

<pre>
<b>content</b>
  ← sealed with <b>contentKey</b>
    ← sealed with <b>periodKey</b>
      ← sealed with <b>issuerPublicKey</b>
</pre>

Sealing (publisher, at render time):
- Publisher seals content with contentKey
- Publisher seals contentKey with periodKey
- Publisher seals periodKey with issuerPublicKey

Unlocking (client, at page load):
- Client sends sealed keys to issuer
- Issuer unlocks periodKey with issuerPrivateKey
- Client unlocks contentKey with periodKey
- Client decrypts content with contentKey

## Threat model

**Design stance:** Raise the bar vs CSS/JS hiding, not bulletproof content protection. Acceptable for paywall use case where goal is "honest users pay" not "impossible to copy".

### Trust boundaries

| From | To | Trust given |
|------|----|-------------|
| Publisher | Issuer | Sealed keys - issuer can unlock and grant to anyone |
| Issuer | Client | Unlocked keys - client can decrypt and copy content |
| Publisher | Client | Encrypted content only - no keys without issuer |

Issuer controls access policy, publisher provides keys. Any issuer you configure can grant access to their entitled content. Once decrypted, content is plaintext - copyable by client.

### Protection scope

**What DCA protects against:**
- Casual bypass (view-source, disable JS, browser extensions)
- Unauthorized access without valid issuer grant
- Bulk scraping of plaintext - scraped markup is ciphertext, useless without issuer authorization per article
- Cross-publisher key substitution (different signing keys per publisher, issuer verifies origin via `resourceJWT`)
- Content item relabeling in unlock requests - sealed blobs are bound to their content item slot via signed proof (`issuerJWT`)
- Request replay - not prevented, but mitigated: replay window is bounded by periodKey rotation (e.g., hourly)

**What DCA does NOT protect against (not DRM):**
- Authorized user copying decrypted content
- Key sharing between users and key extraction from compromised clients. Can be mitigated - issuers can deliver keys as non-extractable WebCrypto keys (see [client-bound transport](DCA-issuer-reference.md#client-bound-transport-security-properties)).
- Screen capture, copy/paste of rendered content
- JS hooks reading DOM post-decrypt - plaintext must reach the DOM to render

### Asymmetric trust model

Publisher holds only issuer public keys. Issuer holds the private key. This means:

- **Publisher breach:** Publisher already has plaintext content, and decrypted content already exists in browser caches and client DOMs. `periodSecret` additionally enables decryption of collected encrypted markup - incremental exposure. No forward secrecy: `periodSecret` is long-lived, compromise enables retrospective decryption of all previously collected encrypted content.
  - **Blast radius:** Issuer credentials unaffected. Other issuers continue to operate normally.
  - **Mitigation:** Rotate `periodSecret`, re-seal future content, purge cached sealed markup rendered with the compromised secret. Past encrypted markup is exposed, but the publisher had the plaintext anyway.
- **Issuer breach:** Attacker gets that issuer's private key and can unlock content sealed for that issuer.
  - **Blast radius:** Only content items granted to that issuer are affected. Other issuers are independent. Previously sealed content remains decryptable until it expires from caches. Note: periodKeys are publisher-derived per `contentName` - if multiple issuers are granted the same content items, the underlying key material is identical, but only the compromised issuer's transport encryption is broken.
  - **Mitigation:** Publisher removes the issuer's public key, re-seals with remaining issuers.
- **No shared secrets:** DCA isolates private keys per issuer. Designs that share a secret between publisher and issuer double the attack surface - breach of either side exposes all content. DCA's asymmetric transport means breach of one side does not compromise the other.

## Operational considerations

**Search indexing (Googlebot etc.):** The publisher system already renders two modes: open (full content) and protected (reduced/paywalled content). DCA changes the protected mode - encrypted content replaces reduced content. The open mode stays as-is. Infrastructure controls which mode to serve via a request header, caching both variants on the same URL (extra cache key on that header). Bot detection and IP verification at the infrastructure layer routes verified bots to the open variant. Details are publisher-implementation-specific (see publisher reference).

**Issuer failover:** If an issuer is unavailable, the publisher system can disable encryption for affected content (self-service via editorial/admin). Content falls back to unencrypted delivery until the issuer recovers.

**JS-disabled users:** DCA content is ciphertext in markup - disabling JavaScript shows nothing, not the plaintext. This is a fundamental improvement over CSS/JS-based paywalls where content is in the DOM.

## Documents

| Document | Scope |
|----------|-------|
| [DCA-data-format.md](DCA-data-format.md) | **The wire format.** Publisher → client markup structure, dca-data JSON, sealed content. |
| [DCA-issuer-reference.md](DCA-issuer-reference.md) | **Implementation guide.** Server-side (verify, unseal, access decisions) and browser-side (unlock, decrypt, cache, placement). Not normative. |

## Status

Draft - all documents are under active development. These documents are extracted from a larger internal design and research effort. Additional material will be published as it stabilizes.

Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Copyright 2026 Labrador CMS AS.

## Planned

- **Test vectors** - test keys, sealed blobs, dca-data JSON, and expected outputs at each step. Given these inputs, verify your implementation produces the correct results (ECDH unseal, proof hash, content decryption).
- **DCA-publisher-reference.md** - publisher-side implementation guide: key derivation, sealing, AAD format, markup generation, issuer onboarding.
