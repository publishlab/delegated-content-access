# DCA content protection

Status: Public Working Draft

## Abstract

This document specifies DCA v1 protected-item encryption and period-key
content-key wrapping. It defines the base cryptographic transcripts, the
relationship among item content-key and period-key-wrap alternatives, client
opening behavior,
deferred ciphertext invariants, ordered content representations with the
`gzip` transform, and the boundary for alternative wrapping profiles.

<a id="1-scope-and-requirements-language"></a>
## 1. Introduction

This document defines:

- generation and use of a per-render, per-item `contentKey`;
- the AES-128-GCM protected-item transcript;
- the base period-key content-key wrapping transcript;
- local candidate-attempt and item-opening outcomes;
- the cryptographic invariants for deferred ciphertext; and
- ordered content representation layers and the `gzip` transform.

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
Its **content key** is the 16-octet symmetric key named `contentKey`. The
publisher may author an item content-key alternative for an issuer, one or more
period-key-wrap alternatives, or both. A client obtains that same content key
either from an issuer result or by unwrapping it with an applicable period key,
as [core §2.4](spec--core-protocol.md#24-obtaining-and-delivering-keys)
describes.

The publisher's per-item access-group assignment for period-key alternatives
is defined in
[period-key Section 6.1](spec-profile--period-keys.md#61-assigning-access-groups-before-sealing).
An item content-key alternative can stand alone without a period-key wrap.
[Core Section 9](spec--core-protocol.md#9-delegation-completeness) defines the
required complete issuer-mediated route for every item.

This specification consumes:

- `renderId` from the publisher's resource model;
- the delivery's `resourceJWT` from
  [core Section 4.1](spec--core-protocol.md#41-producer-form);
- `contentName`, item records and ciphertext placement from
  [spec--data-format.md](spec--data-format.md);
- authorized issuer-returned item content keys from
  [spec--core-protocol.md](spec--core-protocol.md); and
- period keys of 16 octets
  ([sealed-key envelopes](spec--sealed-key-envelopes.md) Section 2) and
  admitted `t` values from
  [spec-profile--period-keys.md](spec-profile--period-keys.md#base-period-key-requirements).

All octet lengths in this document are lengths after binary decoding. Wire
values use the canonical unpadded base64url spelling defined by the data-format
specification.

## 3. Base protected-item transcript

### 3.1. Content-key generation

For every `(renderId, contentName)` pair, the publisher MUST generate a fresh,
independent, uniformly random 16-octet `contentKey`. It MUST use that key for
exactly one content-encryption invocation and MUST NOT derive it from `renderId`,
`contentName`, a period key or another content key.

Every authored alternative for opening the item MUST yield that same
`contentKey`. A publisher MUST NOT create valid alternatives
that resolve to different keys for one item.

The base content representation is an octet string selected by the publisher.
When a publisher converts a string to that representation, the octets MUST be its
[UTF-8](https://www.rfc-editor.org/rfc/rfc3629) encoding without a byte-order
mark. A publisher MAY instead begin with content octets directly. Section 8
defines how declared representation layers transform the base octets before
encryption.

### 3.2. Content AAD

The publisher and the client each build the content AAD from the admitted
render ID and item name. No item member carries it. This two-field binding is
AES-GCM associated data itself, not a separate wire AAD or a nonce derivation.

Let `UTF8(s)` encode a string of Unicode scalar values as
[UTF-8](https://www.rfc-editor.org/rfc/rfc3629) without normalization, case
folding or a byte-order mark; a string holding an unpaired surrogate fails.
Let `U32BE(n)` be exactly four octets holding the unsigned integer `n` in
big-endian order, for `0 <= n <= 4294967295`. Define:

```text
LP(s) = U32BE(length_in_octets(UTF8(s))) || UTF8(s)
content_aad = LP(renderId) || LP(contentName)
```

`||` is octet concatenation. Lengths count encoded octets, not characters or
UTF-16 code units. No label, hash, salt, JSON serialization or other input is
added.

| Input | Source |
| --- | --- |
| `renderId` | The canonical 22-character render ID in the delivery's `resourceJWT` payload, admitted under core Section 4.1 |
| `contentName` | The admitted member name that selects the item in that delivery's `contentData` |

The client decodes the token to obtain its render ID; the optional diagnostic
`resource` object supplies no input. Local decoding does not authenticate the
publisher or authorize access. Issuer signature verification and authorization
remain mandatory under
[core Section 4.2](spec--core-protocol.md#42-verification-and-registration).
An implementation applies its finite resource limits before allocating or
traversing an input; an inadmissible value or excessive length fails the item.
Handling admission of `contentType` and `contentEncodings` remains required
independently of this transcript.

A publisher MUST omit the item `aad` and `nonce` members. A client MUST ignore
carried item `aad` and `nonce` members under the data-format unknown-member
rule, whatever their types, and MUST NOT use either to select another
procedure or retry an opening.

With the content key and ciphertext held fixed, changing the render ID or
content name fails authentication, including when a cached period key recovers
the content key without contacting an issuer. The content tag does not bind
`contentType`, `contentEncodings`, other JWT claims or the token's serialized
spelling. Changing those inputs while retaining the render ID and name need
not fail authentication and can change subsequent processing. The binding
does not prove authorship, authorization or page placement: a holder of the
content key can build another valid tuple, and an unchanged delivery remains
copyable ([security model Section 8.5](spec--security-model.md#what-opening-proves)).

### 3.3. Content encryption

The publisher declares and applies the representation layers (Section 8.1),
builds the Section 3.2 bytes and encrypts the content representation with
AES-128-GCM using:

| Input | Value |
| --- | --- |
| key | the item's fresh independent 16-octet `contentKey`, used for this one encryption |
| nonce | exactly twelve zero octets |
| associated data | the bytes from Section 3.2 |
| authentication tag | 16 octets |

The output is the AES-GCM ciphertext followed by the 16-octet authentication
tag, carried in the applicable `sealedContent[contentName]` location. The
nonce is implicit and is not transmitted. Replaying or decrypting this output
is not a new encryption. Producing a second ciphertext, including a changed
representation, requires a fresh independent content key; changing AAD alone
does not make reuse of a key safe.

This is the mandatory publisher/client baseline procedure, with no profile
selection, runtime toggle or legacy retry. Issuers have no new nonce procedure.
Readers and deliveries using the former random content nonce do not
interoperate with it without a separately selected old reader; the presence
of an item `nonce` MUST NOT select such a reader.

This content-only rule does not change wrap or envelope nonces. Period keys
wrap many content keys using fresh random wrap nonces under Section 4;
[spec-profile--period-keys.md](spec-profile--period-keys.md#content-wrapping-and-rollover)
defines their invocation bound and deployment counting duty.

## 4. Base period-key content-key wrapping

An item may declare one or more period-key wrap alternatives. Each base
wrap entry corresponds to `(contentName, accessGroup, t)` and contains `t`, `nonce` and
`key` as placed by the data-format specification.

For each entry, the publisher encrypts the item's 16-octet `contentKey` with
AES-128-GCM under `dca-profile-period-keys`,
using:

| Input | Value |
| --- | --- |
| key | the 16-octet period key for `(accessGroup, t)` |
| nonce | a fresh 12-octet wrap nonce |
| associated data | no AES-GCM `additionalData` is supplied; cryptographically the empty octet string |
| authentication tag | 16 octets |

The `contentKey` is exactly 16 octets. The `nonce` member carries the wrap
nonce, and the `key` member carries the 16-octet encrypted content key followed
by its 16-octet tag and therefore MUST decode to exactly 32 octets. Its
canonical unpadded base64url spelling is exactly 43 characters.

The absence of wrap AAD is part of the base v1 transcript; an implementation
MUST NOT invent implicit AAD from the entry coordinate.

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
record failure. It is not a cached-candidate miss and suppresses no valid
sibling item ([data format Section 7](spec--data-format.md#7-structural-processing)).

If the ciphertext is present, its binary spelling and every
attempted wrap value MUST satisfy the data-format specification before their
bytes are used. Structural failure supplies no plaintext or key material.

Before its first asynchronous step for the item, the client captures the
delivery's render ID from `resourceJWT`, the admitted `contentName`,
`contentType`, complete `contentEncodings` list and available ciphertext, and
builds the Section 3.2 bytes from those captured values. A failed input
admission, including an inadmissible render ID, is an item failure. Opening, inverse
transforms and the host handoff MUST use those captured values; the client
MUST NOT reread mutable item or delivery metadata after it starts the item.

### 5.2. Resolving a content key

Before contacting an issuer, a client SHOULD try applicable cached period
capabilities (Section 5.3); an item they do not resolve follows the core
unlock flow.

After an issuer result is admitted, an authorized issuer-returned item content
key takes precedence over reconsulting cached period capabilities.

An issuer-returned item content key MUST contain exactly 16 octets. The client
retains it only
for the applicable `(renderId, contentName)` and MUST NOT store it as a reusable
period capability.

For this scope, `renderId` is the value in the associated delivery's
`resourceJWT` payload, not its diagnostic `resource` object. A client need not
verify the JWT merely to use that value as a local render label; decoding it
establishes no publisher identity or authorization. The retained key remains
associated with that delivery's item and render. An unverified label does not
establish a trusted publisher security namespace or cross-context authority.
This association adds no expiry tied to a page visit or delivery object's lifetime.

For cached resolution, the client takes candidate sources in the order the
selected period-capability profiles define, and each source supplies its
candidates in its own defined order. The client attempts stored period-key
sources before selected chain-key derivation sources unless the selected profile
states otherwise. Within a
source, it preserves source candidate order and attempts authored wrap entries
in array order.

Access-group traversal is a local choice and MUST NOT affect correctness.
Because the publisher authors every alternative for one item to yield its
one content key, every successful alternative yields the same result.

The finite candidate-trial bound in
[period keys Section 5.5](spec-profile--period-keys.md#base-period-key-requirements)
applies across ordinary candidates from all sources and storage views for one
operation; a selected chain-key profile also bounds combined trials and
additional derivation work.

### 5.3. Cached wrap attempts

For an applicable period-key candidate and wrap entry, the client:

1. requires a candidate period key of the selected period-key profile, a
   12-octet wrap nonce and a 32-octet wrapped value;
2. opens the wrapped value with that profile's content-key wrap algorithm, a
   16-octet tag and no AAD; and
3. accepts the result only if authentication succeeds and the plaintext is
   exactly 16 octets.

A failure of binary decoding, a required length check or GCM authentication is
a candidate miss. The client MUST continue with later applicable candidates
and MUST NOT delete or invalidate the failed cached period capability merely
because it missed this entry. A period capability can remain valid for another
item or entry.

A storage, source-configuration or profile failure, including a candidate
period key of the wrong width
([spec-profile--period-keys.md](spec-profile--period-keys.md#base-period-key-requirements)), is
not a candidate miss; the owning capability profile defines its scope and
recovery.

If content opening fails under an unwrapped key, the client reports an item
decryption failure; the base profile does not reinterpret that failure as
authorization and does not require searching for another publisher-authored
alternative.

### 5.4. Content opening and containment

The client opens the item ciphertext with the resolved 16-octet `contentKey`,
exactly twelve zero nonce octets, the Section 3.2 bytes it built from the captured
inputs (Section 5.1) and a 16-octet tag.

On successful authentication, it passes only the resulting plaintext octets
and the captured handling metadata to the host placement boundary. On failure,
it MUST produce no plaintext and MUST fail or leave locked only that item. It
MUST NOT retry with another nonce or AAD. A
failure MUST NOT unlock a sibling, broaden a capability, or turn unauthenticated
bytes into displayable content.

## 6. Content-key response representations

A content key returned by the issuer is carried as raw 16-octet key material in a
direct response or as a wrapped key value in a client-bound response. After
opening the wrapped value, the client uses a non-extractable implementation handle.
Both forms provide the same item `contentKey` and MUST be usable only for
AES-128-GCM opening of that item.

A handle need not expose its bytes. A client MUST NOT require byte comparison
between an issuer-returned content key and one obtained from a cached period
capability, and MUST NOT export a non-extractable handle
to manufacture a cacheable capability. Response representation, offer and
selection are defined by
[spec--response-binding.md](spec--response-binding.md).

## 7. Deferred ciphertext and content handling

A data-format no-ciphertext outcome for `sealedContent[contentName]`, including
a missing or non-string carrier member, means that ciphertext delivery is
deferred. It does not change key resolution and is not a cryptographic profile.
Later delivery MUST supply the exact ciphertext originally produced for the
item's `contentKey`, fixed nonce and AAD; it MUST NOT silently reseal the item under a
new tuple while reusing the old item record. Deferred ciphertext opens only
with the inputs of its original render.

Changing JWT signature bytes, serialized spelling or claims other than
`renderId` does not change the content AAD. The content tag therefore does not
validate those changes. Any newly submitted unlock request still requires
issuer verification and authorization of the submitted token. An issuer
endpoint change also does not change content AAD. A new render requires a
fresh render ID, fresh item content keys, newly encrypted items and rebuilt
issuer envelopes.

This specification does not define how deferred ciphertext is located,
authorized, fetched or freshness-checked. Regardless of transport, the client applies the same admission and
AEAD opening rules before releasing plaintext.

The host uses `contentType` to place the plaintext. It does not select a key,
grant authority or alter either base cryptographic transcript. Host
interpretation is outside this specification. The content tag does not
authenticate `contentType`; an altered admitted value can change host handling
of the same successfully opened bytes. Successful opening establishes neither
the type's correctness nor its safety. A
selected transform or handling profile may define its own admission and
interpretation rules.

The proposed optional [browser-integration contract](spec-proposal--browser-integration.md)
defines the decoded-content handoff that follows opening and selected decoding.

## 8. Content representations and extension profiles

The base transcript is independently implementable without an extension. An
extension that changes content plaintext preparation, wrap AAD, entry shape,
key representation or post-decryption processing MUST define:

- an unambiguous selection signal and every affected actor;
- the exact octet transcript and processing order;
- its relationship to base and other extension alternatives;
- behavior when support or agreement is absent;
- failure scope and resource limits; and
- conformance evidence for each permitted capability combination.

Section 4 defines the admission boundary for an entry that carries an
alternative-wrap marker. An extension specifies the marker it recognizes and
the transcript it exclusively defines.

A deployment MAY select an optimized profile only when every actor whose
behavior or wire interpretation changes has declared support at the profile's
applicable configuration or protocol boundary. A relay that copies opaque data need not
understand the profile unless it is assigned validation or transformation work.

Section 8.1 defines the ordered representation layers that every client
processes, and Section 8.2 defines the `gzip` transform. This section also
reserves the extension boundary for alternative wrap transcripts. It selects
neither deferred delivery nor an alternative wrap as part of DCA v1.

### 8.1. Ordered representation layers

The optional `contentEncodings` member lists ordered representation layers for
one item. The publisher applies the named forward transforms in
listed order to the base representation, then encrypts the resulting octets
under Section 3.3. A publisher component may receive those already-transformed
octets, but the producer remains responsible for the declared sequence.

The publisher MUST list every transform it applied, in application order, and
MUST omit the member when it applied none. The declared sequence MUST match
the octets the publisher encrypts, including octets that an earlier build step
prepared.

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
choices unless a transform definition specifies interoperable bounds.

Every DCA v1 client processes the list under this section; the
[baseline profile](spec--profiles.md#34-client-requirements) requires it. No
named transform is mandatory. A client that supports no transform conforms: it
opens an item without the member and fails an item that carries it. Each
transform is separately optional, and its definition states its exact name,
forward and inverse operations, inputs, outputs, failures and any additional
limits or `contentType` interaction. Section 8.2 defines `gzip`; this
specification defines no other transform.

A publisher selects a
sequence per item, and only for intended clients that support every named
transform. DCA defines no negotiation, unlock-time offer or advertisement for
representations, and an issuer has no representation duty.

`contentEncodings` does not change `contentKey` identity, key resolution or
authorization. The content AAD does not include this list. A deleted,
reordered or substituted admitted list need not fail authentication: it can
change decoding, fail during transformation, or, when removed, pass compressed
representation bytes to the host as base bytes. Admission, capture and
authenticate-before-transform ordering remain mandatory.

### 8.2. `gzip` transform

The transform name is the string `gzip`, compared octet for octet. The forward
operation compresses its input octets into exactly one
[RFC 1952](https://www.rfc-editor.org/rfc/rfc1952) gzip member that uses CM=8
and holds one [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951) DEFLATE
stream. The inverse operation decodes that one member. RFC 1952 also permits a
file of concatenated members; this transform does not.

The transform is compression before item encryption. It is not an HTTP content
coding, and it does not change how a carrier or transport delivers the render.

The decoder MUST accept legal `FTEXT`, `FEXTRA`, `FNAME`, `FCOMMENT` and
`FHCRC` header fields, skip optional data according to the format, and verify
FHCRC when present. Reserved flags and malformed, unterminated or truncated
header fields fail the item. The decoder skips `FEXTRA` using `XLEN` and
need not interpret or validate the subfields inside it. The declared extra-field
octets MUST be present and are included when verifying FHCRC.
Header metadata, including `MTIME`, `XFL` and
`OS`, does not identify a publisher or affect interpretation.

The decoder MUST reach DEFLATE end, read the complete eight-octet trailer, and
verify CRC32 and ISIZE against the decoded output, with the length checked
modulo 2^32 as RFC 1952 specifies. It MUST consume the entire supplied input
as that one member. A second member, zero padding, other tail octets, invalid
integrity values or truncation fail the item. ISIZE is checked against the
actual output. A complete member whose
decoded content is empty is valid; an empty compressed input is not.
ISIZE is not an allocation request.

Section 8.1 governs order and failure for this transform; a decoder load or
configuration failure is a transform failure.

This specification fixes no numeric limit for `gzip`. The finite limits of
Section 8.1 apply, and an implementation applies each limit before the
allocation or work that the limit bounds. Header scanning and storage count
against the compressed-input and implementation-resource budgets; there is no
separate header-size ceiling.

The
[`dca-profile-content-compression` profile](spec--profiles.md#6-dca-profile-content-compression-profile)
defines which sequence it guarantees.

## 9. Security considerations

Fresh per-item keys limit accidental key coupling among items and renders.
Period-key capabilities deliberately have wider reuse and reach; this
document consumes that authority and does not narrow it through entry
filtering, AAD or client attempt order.

AES-GCM nonce reuse under one key can destroy confidentiality and integrity.
The fixed content nonce relies on a fresh independent key for every encryption.
An accidental random-key collision repeats the key/nonce pair; a key-reuse bug
is not rescued by changing AAD. Fresh random wrap nonces and the period-key
invocation bound remain separate requirements (Section 4 and the period-key
specification).

The content AAD binds the render ID and item name under the content key
(Section 3.2). A party rearranging public records cannot move a complete item
record and ciphertext into another slot or render and have it open there,
even when a held period key recovers its content key. A content-key holder
can create a new authenticated tuple. Type, encoding list and other JWT claims
are outside the content tag; altered admitted metadata can change actual
processing without a new key grant. The AAD authenticates
neither the publisher, deferred-ciphertext location nor page placement:
publisher authentication comes from the core protocol, coordinate
authentication from envelope BIND, and a host places decrypted bytes on its
own authority. A client that needs to know where a delivery came from follows
[security model Section 8.5](spec--security-model.md#what-opening-proves).

## 10. Dependencies and applicability

[spec--security-model.md](spec--security-model.md) defines the mandatory trust
and authorization boundary for the specification set.

## 11. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [RFC 3629: UTF-8, a transformation format of ISO 10646](https://www.rfc-editor.org/info/rfc3629)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [DCA data format](spec--data-format.md)
- [DCA core protocol](spec--core-protocol.md)
- [DCA sealed key envelopes](spec--sealed-key-envelopes.md)
- [DCA period-key capabilities](spec-profile--period-keys.md)
- [DCA chain keys: construction and delegation](spec-profile--chain-keys.md)
- [DCA issuer-response binding](spec--response-binding.md)
- [DCA security model](spec--security-model.md)
- [RFC 1951: DEFLATE compressed data format](https://www.rfc-editor.org/rfc/rfc1951)
- [RFC 1952: GZIP file format](https://www.rfc-editor.org/rfc/rfc1952)

## 12. Informative References

- [DCA v1 conformance profiles](spec--profiles.md)
- [DCA browser integration](spec-proposal--browser-integration.md)
- [DCA reference implementation status](guide--reference-implementation-status.md)
