# DCA content protection

Status: Public Working Draft

## Abstract

This document specifies DCA v1 protected-item encryption and exact-period
content-key wrapping. It defines the base cryptographic transcripts, the
relationship among direct and reusable key routes, client opening behavior,
deferred ciphertext invariants and the boundary for content transforms and
alternative wrapping profiles.

<a id="1-scope-and-requirements-language"></a>
## 1. Introduction

This document defines:

- generation and use of a per-render, per-item `contentKey`;
- the AES-128-GCM protected-item transcript;
- the base exact-period content-key wrapping transcript;
- local candidate-attempt and item-opening outcomes; and
- the cryptographic invariants for deferred ciphertext and transforms.

It does not define JSON or markup placement, canonical binary spelling,
publisher-to-issuer envelopes, BIND, authorization, issuer result delivery,
period-key derivation or chain reach. Those rules remain with their focused
specifications.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14) when, and only when, they appear
in all capitals.

## 2. Terminology and inputs

An **item** is the protected value identified by one `contentName` in a render.
Its **content key** is the 16-octet symmetric key named `contentKey`. A
**content-key route** is any authorized mechanism that yields that same key,
including a direct issuer result or a successful unwrap under an exact period
capability.

This specification consumes:

- `renderId` and `resourceId` from the publisher's resource model;
- `contentName`, item records and ciphertext placement from
  [spec--data-format.md](spec--data-format.md);
- authorized direct-key results from
  [spec--core-protocol.md](spec--core-protocol.md); and
- exact period keys, exactly 16 octets under the v1 exact-period profile, and
  admitted `t` values from
  [spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements).

All octet lengths in this document are lengths after binary decoding. Wire
values use the canonical unpadded base64url spelling defined by the data-format
specification.

## 3. Base protected-item transcript

### 3.1. Content-key generation

For every `(renderId, contentName)` pair, the publisher MUST generate a fresh,
independent, uniformly random 16-octet `contentKey`. It MUST use that key for
only that item in that render and MUST NOT derive it from `renderId`,
`contentName`, a period key or another content key.

Every direct, exact-period or extension route authored for the item MUST yield
that same `contentKey`. A publisher MUST NOT create alternative valid routes
that resolve to different keys for one item.

The base content representation is an octet string selected by the publisher.
When a publisher converts a string to that representation, the octets MUST be its
[UTF-8](https://www.rfc-editor.org/rfc/rfc3629) encoding without a byte-order
mark. A publisher MAY instead begin with content octets directly. Section 8
defines how an optional representation profile transforms the base octets
before encryption.

### 3.2. Content AAD

For v1, the publisher constructs the content AAD string as:

```text
content-aad-v1 = resourceId "|" "1" "|" contentName
```

The AEAD associated data is the exact UTF-8 encoding of this string.
`contentName` already excludes `|` under the identifier grammar. A publisher
using this content-protection profile MUST also choose a `resourceId` that is
non-empty and contains no U+007C (`|`). Neither value is Unicode-normalized or
case-folded before construction.

The publisher MUST carry the exact constructed string in the item's `aad`
member. The client MUST encode that carried string as UTF-8 without alteration
and supply those bytes to AEAD opening. It MUST NOT substitute the readable
top-level `resource` object or locally reconstruct different AAD.

The AAD detects inconsistency among the selected key, nonce, AAD and
ciphertext. Because the publisher-to-client `aad` value is not independently
authenticated, this construction is not publisher authentication,
authorization, BIND or proof of page placement.

### 3.3. Content encryption

The publisher encrypts the content plaintext with AES-128-GCM using:

| Input | Value |
| --- | --- |
| key | the item's 16-octet `contentKey` |
| nonce | a fresh 12-octet content nonce |
| associated data | the bytes from Section 3.2 |
| authentication tag | 16 octets |

The output is the AES-GCM ciphertext followed by the 16-octet authentication
tag. The publisher carries the nonce in the item's `nonce` member and the
output in the applicable `sealedContent[contentName]` location.

A producer MUST sample a fresh nonce from a cryptographic random-bit generator
for every AES-GCM invocation under a key, and MUST NOT deliberately or
deterministically repeat a nonce under that key at any invocation count. Every
content encryption and every exact-period content-key wrap uses the RBG-based IV
construction of NIST SP 800-38D: a new 96-bit nonce sampled for that invocation
from a cryptographic random-bit generator. Separate generator instances MUST be
seeded independently. A deterministic random source injected for tests is not a
conforming production generator. Random sampling makes a repeat improbable, not
impossible; the invocation limit below keeps the repeat probability within what
the standard requires.

Under the RBG-based construction the aggregate number of AES-GCM invocations
with one key MUST NOT exceed `2^32`
([SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), section 8.3). The
count spans every producer, process lifetime, restart, replacement node and
backfill job that uses those key bytes. A fresh per-item `contentKey` keeps
content encryption far inside that limit. Because publishers reuse exact
period keys to wrap content keys across renders, they count every invocation
against the exact-period-key limit;
[spec--period-keys.md](spec--period-keys.md#content-wrapping-and-rollover)
defines their counting domain and the deployment obligation that comes with it.

## 4. Base exact-period content-key wrapping

An item may declare one or more exact-period routes. Each base wrap entry
corresponds to `(contentName, accessGroup, t)` and contains `t`, `nonce` and
`key` as placed by the data-format specification.

For each entry, the publisher encrypts the item's 16-octet `contentKey` with
AES-128-GCM under `dca-v1-exact-period`,
using:

| Input | Value |
| --- | --- |
| key | the 16-octet exact period key for `(accessGroup, t)` |
| nonce | a fresh 12-octet wrap nonce |
| associated data | no AES-GCM `additionalData` is supplied; cryptographically the empty octet string |
| authentication tag | 16 octets |

The `contentKey` is exactly 16 octets. The `nonce` member carries the wrap
nonce, and the `key` member carries the 16-octet encrypted content key followed
by its 16-octet tag and therefore MUST decode to exactly 32 octets. Its
canonical unpadded base64url spelling is exactly 43 characters.

All exact-period entries for an item, including entries under different access
groups or times, MUST wrap the same item `contentKey`. The absence of wrap AAD
is part of the base v1 transcript; an implementation MUST NOT invent implicit
AAD from the entry coordinate.

The absence of an own `bind` member selects this base transcript. Base v1 has
no string-valued base marker. An own `bind` member selects an alternative-wrap
profile: a client that selected and recognizes that marker MUST use that
profile's transcript exclusively. An unknown marker, or a recognized marker
whose profile the client has not selected, is a candidate miss. The client
MUST NOT remove, ignore or retry that marked entry as a base no-AAD wrap.

## 5. Opening a protected item

### 5.1. Item admission

When the client opens an item, it first admits the item record under the
data-format specification. A missing or malformed required member is an item
record failure. It is not a cached-candidate miss and MUST NOT suppress a valid
sibling item.

If the ciphertext is present, its binary spelling, the item nonce and every
attempted wrap value MUST satisfy the data-format specification before their
bytes are used. Structural failure supplies no plaintext or key material.

### 5.2. Resolving a content key

A client may encounter content-key routes at different stages:

1. Before contacting an issuer, it SHOULD try applicable cached period
   capabilities.
2. If no cached route resolves the item, it follows the core unlock flow.
3. After an issuer result is admitted, an authorized direct content key for the
   item takes precedence over reconsulting cached routes.

A direct content key MUST contain exactly 16 octets. The client retains it only
for the applicable `(renderId, contentName)` and MUST NOT store it as a reusable
period capability.

For cached resolution, the client takes candidate sources in the order the
selected period-capability profiles define, and each source supplies its
candidates in its own defined order. The client attempts base exact-period
sources before selected chain-derived sources unless the selected profile
states otherwise. Within a
source, it preserves source candidate order and attempts authored wrap entries
in array order.

Access-group traversal is a local choice and MUST NOT affect correctness.
Because publishers are required to wrap one content key on every route, every
successful route yields the same result.

The implementation applies the finite candidate-trial bound in
[spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements)
independently to each access group.

### 5.3. Cached wrap attempts

For an applicable exact period-key candidate and wrap entry, the client:

1. requires a candidate period key of the selected exact-period profile, a
   12-octet wrap nonce and a 32-octet wrapped value;
2. opens the wrapped value with that profile's exact-wrap algorithm, a 16-octet
   tag and no AAD; and
3. accepts the result only if authentication succeeds and the plaintext is
   exactly 16 octets.

A failure of binary decoding, a required length check or GCM authentication is
a candidate miss. The client MUST continue with later applicable candidates
and MUST NOT delete or invalidate the failed cached period capability merely
because it missed this entry. A period capability can remain valid for another
item or entry.

A storage, source-configuration or profile failure is not a candidate miss.
The owning capability profile defines its scope and recovery behavior. A
candidate period key whose width disagrees with the selected exact-period
profile is such a profile failure: the client refuses those bytes before it
tries the wrap, under
[spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements).

The client may use the first authenticated 16-octet unwrap in the defined
traversal as the item `contentKey`. If later content opening fails, the client
reports an item decryption failure; the base profile does not reinterpret that
failure as authorization and does not require searching for a publisher-authored
alternative key.

### 5.4. Content opening and containment

The client opens the item ciphertext with the resolved 16-octet `contentKey`,
the 12-octet item nonce, the exact carried AAD bytes and a 16-octet tag.

On successful authentication, it passes only the resulting plaintext octets
and admitted handling metadata to the host placement boundary. On failure, it
MUST produce no plaintext and MUST fail or leave locked only that item. A
failure MUST NOT unlock a sibling, broaden a capability, or turn unauthenticated
bytes into displayable content.

## 6. Direct and protected key representations

An admitted direct response may represent a content key as raw 16-octet key
material or as a non-extractable implementation handle under a selected
response-binding profile. Either representation is semantically the same item
`contentKey` and MUST be usable only for AES-128-GCM opening of that item.

A handle need not expose its bytes. A client MUST NOT require byte comparison
between direct and cached routes, and MUST NOT export a non-extractable handle
to manufacture a cacheable capability. Response representation, offer and
selection are defined by
[spec--response-binding.md](spec--response-binding.md).

## 7. Deferred ciphertext and content handling

A data-format no-ciphertext outcome for `sealedContent[contentName]`, including
a missing or non-string carrier member, means that ciphertext delivery is
deferred. It does not change key resolution and is not a cryptographic profile.
Later delivery MUST supply the exact ciphertext originally produced for the
item's `contentKey`, nonce and AAD; it MUST NOT silently reseal the item under a
new tuple while reusing the old item record.

This specification does not define how deferred ciphertext is located,
authorized, fetched or freshness-checked. A deferred-delivery profile defines
those rules if DCA adopts one; no such DCA profile is selected by this
document. Regardless of transport, the client applies the same admission and
AEAD opening rules before releasing plaintext.

The host uses `contentType` to place the plaintext. It does not select a key,
grant authority or alter either base cryptographic transcript. Host
interpretation is outside this specification. A host MUST NOT infer that AEAD
authenticates `contentType`, because v1 does not include that member in content
AAD. A selected transform or handling profile may define its own admission and
interpretation rules.

## 8. Content representations and extension profiles

The base transcript is independently implementable without an extension. An
extension that changes content plaintext preparation, wrap AAD, entry shape,
key representation or post-decryption processing MUST define:

- an unambiguous selection signal and every affected actor;
- the exact octet transcript and processing order;
- its relationship to base and other extension routes;
- behavior when support or agreement is absent;
- failure scope and resource limits; and
- conformance evidence for each permitted capability combination.

Section 4 defines the admission boundary for an entry that carries an
alternative-wrap marker. An extension specifies the marker it recognizes and
the transcript it exclusively defines.

The optional `contentEncodings` member lists ordered representation layers for
one item. The publisher applies the named forward transforms in
listed order to the base representation, then encrypts the resulting octets
under Section 3.3. A publisher component may receive those already-transformed
octets, but the producer remains responsible for the declared sequence.

Before attempting content-key opening for that item, a client MUST admit the
complete list and determine that it supports every named inverse transform.
This local ordering does not imply that an independently scheduled unlock has
not already occurred. The client authenticates and decrypts the content under
the AES-128-GCM opening rules in Section 5.4, then applies the inverse
transforms in reverse list order. It MUST NOT pass unauthenticated bytes to a
decoder or release represented, intermediate or partially decoded bytes to the
host.

A malformed list, unsupported transform, transform failure, non-octet
transform result or resource-limit breach is an item failure. While the member
is present, a client MUST NOT retry or expose the item as the base
representation. Every implementation MUST enforce finite limits on layer
count, the bytes supplied to and returned from each transform, total output and
aggregate decoding work or time. The limits are implementation or deployment
choices unless a selected transform profile specifies interoperable bounds.

This specification selects the generic list and processing order, but no named
transform. Each transform is separately optional and its profile defines its
exact name, forward and inverse operations, inputs, outputs, failures and any
additional limits or `contentType` interaction. Local decoder registration is
an implementation matter, not wire behavior.

`contentEncodings` does not change `contentKey` identity, key resolution or
authorization. DCA v1 does not include it in content AAD or otherwise
authenticate it independently. If anyone deletes or substitutes it, a client
can produce undecoded output or fail the item; an implementation MUST NOT claim
representation-metadata integrity from the base transcript.

A deployment MAY select an optimized profile only when every actor whose
behavior or wire interpretation changes has declared support at the profile's
applicable configuration or protocol boundary. A relay that copies opaque data need not
understand the profile unless it is assigned validation or transformation work.

This section also reserves the extension boundary for alternative wrap
transcripts. It does not select deferred delivery or any named transform as
part of DCA v1.

## 9. Security considerations

Fresh per-item keys limit accidental key coupling among items and renders.
Exact-period capabilities deliberately have wider reuse and reach; this
document consumes that authority and does not narrow it through entry
filtering, AAD or client attempt order.

AES-GCM nonce reuse under one key can destroy confidentiality and integrity.
This is especially material for exact period keys because one key may wrap
many content keys. Producers must enforce the invocation limit of Section 3.3
rather than treating a random nonce generator as unlimited.

The item AAD is sent with the ciphertext metadata. It detects corruption or a
mismatched cryptographic tuple but does not independently authenticate the
publisher-supplied coordinate. Publisher authentication and authorization come
from the core protocol; publisher-to-issuer coordinate authentication comes
from envelope BIND.

`contentType`, deferred-ciphertext location and page placement are not
authenticated by the base content AAD. A host that places decrypted bytes
therefore does so on its own authority. A delivery or handling profile that
needs that assurance defines it separately.

## 10. Dependencies and applicability

This specification depends normatively on:

- [spec--data-format.md](spec--data-format.md) for records, placement,
  identifiers and canonical binary strings;
- [spec--core-protocol.md](spec--core-protocol.md) for authorized key results,
  delegation completeness and issuer processing; and
- [spec--period-keys.md](spec--period-keys.md) when an exact period capability
  is used; and
- [spec--period-key-chains.md](spec--period-key-chains.md) when that capability
  is chain-derived.

[spec--security-model.md](spec--security-model.md) defines the mandatory trust
and authorization boundary for the specification set.

Deferred delivery and alternative wrap transcripts remain non-baseline until
their focused profiles define selection and failure.

The reference path does not yet enforce generic layer-count, name-size,
decoded-output or decoding-work limits. Implementers must add those limits
before the reference claims the content-representations profile.

Authenticating `contentEncodings` would change the transcript and requires an
explicit version or profile decision; this document does not make that change
implicitly.

## 11. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [RFC 3629: UTF-8, a transformation format of ISO 10646](https://www.rfc-editor.org/info/rfc3629)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [DCA data format](spec--data-format.md)
- [DCA core protocol](spec--core-protocol.md)
- [DCA exact period-key capabilities](spec--period-keys.md)
- [DCA period-chain construction and delegation](spec--period-key-chains.md)
- [DCA issuer-response binding](spec--response-binding.md)
- [DCA security model](spec--security-model.md)

## 12. Informative References

This specification has no additional informative references.
