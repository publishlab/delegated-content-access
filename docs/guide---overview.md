# Delegated Content Access (DCA) overview

Status: Informative Draft

DCA lets a publisher ship one encrypted, cacheable render while independent
issuers decide which readers receive the keys needed to open it. This document
explains the design. The focused `spec--*.md` documents state protocol
requirements and exact bytes; disagreement with them is a defect here, not a
second conforming interpretation.

## Design goal

**DCA blocks CSS-only bypasses but does not provide DRM.**

A reader without an issuer grant cannot reveal protected content by removing a
CSS rule or copying public markup. An authorized reader can still copy
plaintext, relay access, or retain delivered key capability. DCA preserves the
cacheability of encrypted publisher output; it does not provide continuous
control over material already delivered.

## Actors and trust

| Actor | Responsibility |
| --- | --- |
| Publisher | Creates a render, encrypts each protected item, supplies period capability, signs resource context, and seals key material to configured issuers. |
| Issuer | Verifies the publisher, authenticates the reader when required or handles the request as explicitly anonymous, applies policy, opens only authorized coordinates, and returns selected key capability. |
| Client | Reads one publisher delivery, asks issuers about unresolved coordinates, retains admitted capability, and opens protected items. |

The publisher needs issuer public opening keys but never issuer private keys.
Issuers do not share secrets or coordinate with one another. Mutually untrusted
publishers use separate registrations and opening-key namespaces at an issuer.
The complete attacker and browser-origin boundaries are in
[the security model](spec--security-model.md).

## One render, several routes

A render contains independently protected items named by `contentName`. Every
item has a fresh random `contentKey`. The same item may offer several
alternative routes:

- an issuer envelope carrying that item's `contentKey`; and
- one or more content-key wraps under period keys for named
  `accessGroup` families.

Those routes are OR alternatives. The client opens the item through any one route; several
groups do not imply conjunction, a threshold, or a hierarchy. An item may rely
only on its item-specific content key. Every protected item needs a complete
issuer-mediated opening route
([core Section 9](spec--core-protocol.md#9-delegation-completeness)): an issuer
that can supply its content key, or the period key for one of its declared
group wraps.

The three useful key roles are:

Read each arrow as "the value on the left is protected under or delivered
through the key on the right."

```text
protected item
  <- contentKey                  one item in one render
     <- periodKey                one publisher/group/period coordinate

contentKey or period capability
  <- issuer public opening key   one issuer delegation route
```

The period layer exists for cross-render reuse. The issuer layer exists so the
publisher can delegate the access decision. Adding user or subscription key
layers to the public render would reduce cache sharing; those distinctions
remain issuer policy.

## Names and policy meaning

`contentName`, `accessGroup`, and `issuerName` are flat publisher-scoped
identifiers. Their spelling is not interpreted as a path or hierarchy.

`accessGroup` names a reusable period-key family. A publisher may use business
vocabulary such as `premium`, but the spelling grants nothing and must not be
treated as a per-article list of issuers. The publisher decides which item
wraps use the family; the issuer decides whether the reader receives capability
for it.

Readable names and request fields do not grant access. The unsigned
`issuerName`, `keyId`, request maps, and readable resource mirror
only select or describe work; the issuer still makes the access decision.

The compact period label remains `t` because it is an established coordinate
repeated in maps and wrap candidates, while its meaning is defined by the
selected period profile. The publisher supplies the label as a coordinate;
profiles may also use it as construction input. A label is never entitlement
by itself.

DCA calls encrypted or wrapped values *sealed* and usable returned capability
*unlocked*. Field names describe protocol roles rather than one runtime's
cryptographic API.

## Publisher delivery

The baseline publisher delivery is one serialized UTF-8 JSON document containing
the metadata and optional `sealedContent` ciphertext map. Under the optional
`dca-profile-html-carrier` profile, publisher markup carries one inert JSON
metadata carrier and may carry a second for inline ciphertext:

- `dca-data` contains signed resource context, issuer routes, item metadata,
  and key envelopes or wraps; and
- `dca-sealed-content`, when present, contains ciphertext keyed by
  `contentName` for content delivered with the page.

Separating ciphertext keeps large opaque values away from the metadata the
client reads first and permits deferred ciphertext delivery. The format does
not define a fetch token or compression transform. The publisher compresses
before encrypting when the selected profile uses compression.

The host uses `contentType` when placing plaintext. It is not authorization or
authenticated page placement. The issuer decides embargo under its policy.
Deferred delivery returns the ciphertext of the existing item
([content protection Section 7](spec--content-protection.md#7-deferred-ciphertext-and-content-handling)).

The shared encrypted render may enter a public cache. Personalized plaintext
must not. A decrypting edge or service must finish authorization and
authenticated opening before releasing any plaintext prefix. Streaming,
personalized cache keys, and placement are deployment concerns unless a
selected delivery profile specifies them.

## Signed resource context

Each render has a fresh random `renderId` and one ES256 `resourceJWT`. The
issuer uses the unverified `kid` only to select one active signing-key entry and
its parent registration, verifies the exact token, and only then consumes its
payload.

`renderId`, `origin`, `issuedAt`, `resourceId`, and `data` are DCA-specific
private-use JWT claim names. Here private-use means custom or unregistered, not
confidential. Reusing registered claims would import semantics DCA does not
promise, most notably treating `issuedAt` like JWT `iat` or an expiry rule.
The authors rejected a raw JWS object: compact JWT and its tooling already carry
the required signed JSON resource context without another envelope grammar.

The signed assertion supplies authenticated context, not entitlement. Policy
still comes from the issuer's authenticated principal, configuration, and
state. `issuedAt` is available to policy and diagnostics but is not a protocol
expiry time.

## Publisher-to-issuer envelopes and BIND

An issuer envelope carries one key or positioned chain key. The selected v1
algorithms are:

- P-256 ECDH with a fresh ephemeral key, using the raw 32-byte shared
  x-coordinate directly as the AES-256-GCM key; and
- RSA-OAEP with SHA-256.

Public-key envelopes avoid a pre-established publisher-issuer shared secret:
the publisher receives only public opening material, while the issuer retains
opening authority. A shared secret would add secret distribution and storage
at the publisher and couple the parties' rotation and trust domains.
Registration-scoped issuer keysets preserve separation between mutually
untrusted publishers. Publishers sharing one opening keyset are intentionally
inside the same trust boundary. Possession of public opening material does not
authenticate a publisher; the verified registration and signed assertion do.

V1 needs no speculative hybrid carrier: its bounded BIND plus 16-octet key fits
native RSA-OAEP at the minimum RSA-2048/SHA-256 profile, with the largest base
plaintext using 139 of the available 190 octets. That is a measured v1
property, not a general RSA limit. A future wider BIND needs a new grammar
identifier and its own capacity proof; a new envelope algorithm must likewise
be identified explicitly rather than introduced as a local option.

By design, the ECDH construction has no KDF. Every target runtime exposes
the raw shared secret, while an unsignalled KDF adds a second transcript that
fails only as an opaque opening error. A KDF-based envelope therefore needs a
distinct interoperable identifier rather than a local option.

BIND is the authenticated string that names an issuer envelope's key kind and
coordinate. It commits each envelope to its render and content, period, or
chain coordinate. The publisher constructs it where the envelope is placed;
the issuer reconstructs it from verified render context and the envelope's own
kind and coordinate, not a policy-selected result coordinate. The client never supplies authoritative BIND bytes.

When one envelope fails, the issuer fails that coordinate only. At the
issuer-facing boundary, the issuer returns one generic opening result for
malformed encoding, authentication, BIND, and payload-width failures. Internal
diagnostics may remain specific.

The publisher puts BIND in the OAEP plaintext, not the OAEP label, so platforms
whose OAEP APIs expose no label can implement the same format. The one generic
answer also covers an RSA-OAEP padding failure: an answer that told padding,
width and BIND failures apart would give a caller the query a padding-oracle
attack needs. That is why the envelope specification asks an issuer to decode
through its runtime's own OAEP implementation and to compare BIND in constant
time where the runtime offers it.

## Content protection

The publisher encrypts each item once with AES-128-GCM under a fresh
independent 16-octet content key and exactly twelve zero nonce octets. The
publisher and client build AAD as `LP(renderId) || LP(contentName)`, where LP
is a four-octet big-endian UTF-8 octet length followed by the string's UTF-8.
[Content protection Section 3.2](spec--content-protection.md#32-content-aad)
defines admission and exact bytes. Items carry neither nonce nor AAD; a client
ignores either member if present and never selects a legacy retry from it.

Moving a whole item record and ciphertext to another name or render fails
local authentication even when a cached period key recovers its content key.
The tag does not bind type, encodings or other JWT claims: an admitted change
can alter host handling or decoding without failing authentication. Clients
still capture and validate handling metadata before asynchronous opening, and
authenticate before decoding. A client decodes the token's render ID for this
binding; that establishes no identity or authorization. The issuer verifies
the signature and authorizes every unlock request. A cached opening need not
contact it. A holder of a content key can create another valid tuple; source
retrieval and placement remain host responsibilities.

The fixed content nonce depends on one encryption per fresh independent key.
It changes no wrap or envelope nonce. This procedure is mandatory baseline
publisher/client behavior and adds no issuer nonce duty or runtime toggle.
Readers and deliveries using random content nonces need a separately selected
old reader; no fallback is selected here.

A period key wraps content keys for one publisher, access group, and
period. The wrap has no additional data: its authenticated ciphertext and the
period key's coordinate determine whether it opens. The client does not invent
wrap AAD from the entry coordinate.

Random 96-bit nonces make collisions improbable, not impossible. A reused
period key accumulates its AES-GCM invocation count across every render,
node, restart, and backfill that uses those bytes. The publisher's key supplier
and operations must enforce the selected profile's bound.

Rejected content-key supply alternatives include a shared bundle of item
content keys, an issuer-specific transport seed, a preconfigured
publisher/issuer shared secret, and a render-scoped derivation root. They
either widen one compromise, reintroduce runtime coordination, or create a
second derivation authority.
V1 instead keeps fresh item keys, independently routed issuer envelopes, and
the optional canonical chain-key construction.

## Period capability

Base period-key processing treats a `periodKey` as opaque key material; it
defines no `periodSecret` and no derivation between periods. The optional
chain-key profile lets an issuer or client derive period keys from a bounded
positioned chain key. See [period keys](guide--period-keys.md#period-keys-are-opaque)
and the [chain companion](guide--chain-keys.md#reach).

Neither a period boundary nor cache eviction revokes delivered material. A
period key continues to open retained ciphertext at its coordinate; a chain key
continues to derive its bounded prefix. Newer renders move to newer
coordinates, and later acquisitions still require current issuer approval.

## Issuer processing and policy effects

The client controls the unsigned request. The client names coordinates; only
the issuer decides grants. The issuer verifies
the signed publisher context, enforces the selected request binding, obtains an
authenticated or explicitly anonymous principal, applies policy, and only then
opens or derives selected capability.

DCA cannot join an external policy commit atomically to key opening, response
construction and delivery; exact-once charging is not a wire guarantee. The
[metering guide](guide--integration--metering.md#commit-only-for-a-deliverable-key-result)
shows where an issuer commits.

## Issuer-to-client delivery

Under direct delivery the issuer returns admitted key bytes. Under a
client-bound profile the issuer seals each delivered key for the selected client
public key. Item content keys and period keys open to non-extractable,
usage-limited handles; chain keys remain usable bytes for derivation and carry
no non-extractability guarantee. A copied sealed key cannot be opened without
the corresponding private key.
This is key custody, not issuer authentication, authorization, or proof that
the key belongs to a user, account, device, or registered client; the issuer
also receives no proof that the response was opened or the content consumed.

Putting identity or coordinate values in AAD, HKDF info, or an OAEP label can
bind the supplied bytes to that wrap, but cannot establish their truth or a
principal binding. In the common browser realization, client-bound delivery
also does not attest a reader-controlled browser, stop page script from using
an exposed handle, or prevent plaintext sharing.

Item content-key delivery provides one-item reach and requires the issuer for
each unresolved item. Cached period capability reduces issuer traffic and
availability dependence at the cost of reusable group reach. The publisher
chooses what reusable material exists; the issuer chooses what it grants.

## Multi-issuer operation

Several issuer blocks may coexist in one render; each issuer has independent
opening keys and policy, and a client addresses one issuer block per request.
Sibling issuer blocks do not override one another's decisions.
[Core Section 5.3](spec--core-protocol.md#53-multiple-issuers) owns which
outcomes let a configured route advance to another issuer;
[unlock routing and fallback](guide--unlock-fallback.md#when-the-client-may-advance)
walks through them.

Migration can temporarily seal for old and new issuers. Availability fallback
is a deployment policy and transport concern, not authority inferred from the
presence of another block. The selected HTTP binding defines portable response
behavior; deployment route policy defines which endpoint failures may retry.

## Authority map

The [specification overview's document map](spec---overview.md#document-map)
names the owner of each subject.
