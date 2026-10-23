# DCA issuer-response binding

Status: Public Working Draft

## Abstract

This document specifies how an authorized DCA issuer-core result is delivered
to and admitted by a client. In the base direct transport mode, the response
carries key bytes inside an issuer-authenticated confidential request/response
channel. Optional client-bound methods additionally wrap each key for one
client's non-extractable keypair; they do not replace channel authentication.

<a id="1-scope-and-requirements-language"></a>

## 1. Introduction

This document defines response-binding selection, client admission of a result,
and the direct and client-bound key representations with their ECDH-P256 and
RSA-OAEP transcripts. The
[overview glossary](spec---overview.md#terms-across-the-specifications)
distinguishes endpoint bindings, transport modes, key kinds and profiles.

It does not authorize a coordinate, define capability reach or content
encryption, or specify browser Origin/CORS processing; an endpoint
specification says how a deployment provides the channel Section 2 requires.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Layered security model

A conforming key response has two distinct layers:

1. A **response channel binding** authenticates the issuer endpoint, protects
   request and response confidentiality and integrity, and associates exactly
   one admitted response with the request that caused it.
2. A **key representation** carries each authorized key either as direct bytes
   or, under an optional client-bound method, as a value that only the selected
   client private key can open.

The direct and client-bound alternatives are the issuer-to-client **transport
modes**. A transport mode names how one response carries keys; it does not
name the response channel or the publisher-to-issuer envelope algorithm.

A transport mode is independent of the key it carries: direct and client-bound
transport mode can each carry an item content key, a period key or, under the
chain-key profile, a chain key, and neither changes the key's kind,
construction or reach.

Every deployment returning usable keys MUST select an endpoint binding that
provides layer 1. TLS, HTTP, CORS and proxy configuration are not inferred by
this document; an applicable endpoint specification must state how it provides
these properties.

Client-bound wrapping encrypts each delivered key for the selected client. This
wrapping does not authenticate the issuer: any party that knows a client's
public key can produce a value encrypted to it. It MUST NOT be used without
layer 1 and MUST NOT be described as an issuer signature or response-wide
authentication.

Publisher-to-issuer BIND is unrelated to this boundary. It authenticates
publisher-supplied coordinates during issuer opening and does not authenticate
the issuer response.

## 3. Inputs and common response form

The input is the issuer-core result defined by
[spec--core-protocol.md](spec--core-protocol.md#7-baseline-issuer-core-result).
The issuer MUST preserve the core result's `keys` records and their coordinate
fields, complete `errors` records and non-key members, including
`notDelivered` when present.
Chain-result geometry comes from the exact associated request, not a response
echo. It may replace only delivered key entries with the selected
representation and may add a top-level `transport` member; `transport` is the
only member this binding adds. It MUST NOT turn an error into a key
representation or move a coordinate between `keys` and `errors`.

The issuer MUST NOT add a key coordinate, widen a result, rename a coordinate
or transform one key kind into another. A response contains at most one key
representation. The client admits sections before it judges the representation.
It first rejects or ignores any section it does not support, without affecting
the supported sections. It then judges the supported sections, including
`keys.chainKeys` for a selected chain-key client. Mixing direct string key
entries and client-bound object key entries among supported sections is
malformed; the client MUST reject the response representation.

After discarding unsupported sections and applying container admission, the
client classifies the key entry, the `key` member, of each record in the
remaining key collections by JSON type, before individual coordinate or
key-entry admission. A string counts as a direct
entry and a non-array object counts as a client-bound object entry, even when
its method-specific members are absent or malformed. If both kinds occur,
the client MUST reject the response representation. Other JSON values do not
establish a representation and fail at their individual entry. This
classification grants no key and admits neither its coordinate nor contents.

A client without selected stock chain-result support MUST discard
`keys.chainKeys`. Selected stock and content-group chain consumers use the
complete geometry captured in the exact associated request, validate it before
opening key entries, and retain that same pair with the capability. They MUST
NOT obtain or override that geometry from response metadata.
The conflict checks of period keys Section 5.6 still apply
to the received result. An operation that selects chain-result consumption
requires its applicable client duties; a client lacking that support MUST fail
the selected operation rather than reinterpret the result as another capability
form.

The response channel MUST preserve one response as the answer to one exact
request. Before it opens or retains a key, the client MUST have:

- the issuer identity and endpoint selected for that request;
- the request version and the presented set of that request;
- the publisher delivery and render to which the request belonged; and
- the response obtained through the selected authenticated channel.

The client MUST ignore or reject, before opening, every returned coordinate
outside the admissible result set of the associated request
([core Section 6.1](spec--core-protocol.md#61-presented-coordinates)) and MUST
retain no key for it; for the chain-key extension,
[chain-keys Section 9](spec-profile--chain-keys.md#9-chain-key-role-requirements)
states the window, position and captured-request geometry checks. A syntactically
valid unsolicited key grants nothing.

For response `keys.contentKeys`, `keys.periodKeys` and selected
`keys.chainKeys`, identifier admission is per record. If a record's
`contentName` or `accessGroup` is missing, is not a string or violates
[data format Section 2.1](spec--data-format.md#21-identifiers), the client MUST
reject that record and MUST NOT reject independently admissible sibling keys
solely because of that identifier failure. This is an exception to the
collection-wide identifier refusal rule for delivery and request collections.
It applies after common container and representation admission; it MUST NOT
bypass response association, mixed-representation rejection or selected
transport checks. Failures in those shared checks retain their specified
failure scope.

Before surfacing or using an error, the client MUST admit its error-object
shape and coordinate grammar and associate the coordinate with the presented
set of that request as
[spec--core-protocol.md](spec--core-protocol.md#61-presented-coordinates)
defines. It MUST ignore or reject a malformed, nonconforming or unsolicited
error and MUST NOT use such an entry for control flow. A core error grants no
capability; core Sections 5.3 and 10 say when a selected profile may give it
control-flow meaning.

Every client, a baseline-only client included, MUST admit and process the
top-level `notDelivered` member as
[period-keys Section 5.6](spec-profile--period-keys.md#56-family-reports-notdelivered)
requires. A malformed report does not itself invalidate independently
admissible item keys or unrelated sections; its specified refusal scope applies
only after the original supported entries have passed response representation
classification. A selected capability extension may define further top-level result
members and their admission and refusal scope. Before using any key from such a
member, the client MUST admit that member and its association with the request.
If the extension defines member-local refusal, a malformed member MUST supply
no key or control-flow permission, but does not invalidate independently
admissible siblings. Without a specified narrower refusal scope, a malformed
member makes the whole response malformed. An extension's local refusal scope
MUST NOT bypass the common response association, representation classification
or selected transport checks; those shared failures still refuse every affected
key.

## 4. Selection and agreement

An issuer endpoint has a declared **endpoint response agreement**: direct
transport mode, client-bound transport mode by one named method, or both
according to stated policy, together with its offer, selection, fallback and
admission rules. A client MUST know that agreement before it treats the
endpoint as usable. This can be established by a containing deployment
profile or authenticated endpoint metadata; it MUST NOT be an undisclosed
local convention whose wire-visible choice the peer cannot predict. The
agreement is not a profile identifier. It states which transport modes the
issuer may select; each response selects one.

The optional request member `clientPublicKey` offers one client-bound method.
The strict JWK shape determines the offered method:

| Public JWK                | Offered method |
| ------------------------- | -------------- |
| `kty` `EC`, `crv` `P-256` | `ECDH-P256`    |
| `kty` `RSA`               | `RSA-OAEP`     |

An issuer selects client-bound transport mode only when its endpoint response
agreement permits it, it implements the offered method and the public key passes
that method's admission rules. The response confirms selection with
the presence of `transport` and its `method` member.

An endpoint response agreement that requires client-bound transport mode MUST
fail a request whose offer is missing, malformed, unsupported or fails the
method's admission rules before opening any publisher-supplied key, and MUST NOT
fall back to direct transport mode. Before publisher-envelope opening under
that agreement, the issuer MUST establish the method state needed to wrap a
response. Placement relative to policy remains subject to core processing and
the endpoint failure model. An issuer MUST NOT return a direct response
to a client-bound offer unless its endpoint response agreement permits direct
fallback and the client is known, under that same agreement, to accept it.

## 5. Direct representation

A key entry is the `key` member of one record of `keys.contentKeys`,
`keys.periodKeys` or `keys.chainKeys`. The record's other fields name its
coordinate. A direct response has no `transport`
member. Each of its key entries is the canonical unpadded base64url encoding of
exactly 16 key octets (22 characters).

The client MUST accept a direct key entry only if its endpoint response
agreement permits direct transport mode, the response channel requirements in
Section 2 hold, the coordinate belongs to the associated request's admissible
result set under Section 3 and the key entry satisfies the canonical spelling
and length rules. Otherwise it releases and retains no key from that key entry.

Direct transport mode exposes raw key bytes to the client application; its
confidentiality and integrity come from the response channel. A deployment that
needs non-extractable custody for content and period keys selects an endpoint
response agreement that requires client-bound transport mode (Section 4).

## 6. Client-bound common representation

A client-bound response has:

```json
{
  "keys": { "contentKeys": [] },
  "transport": {
    "method": "METHOD"
  }
}
```

Method-specific members may occur in `transport`, and every delivered key entry
is replaced by one method-specific object under the record's `key` member, for
example `{ "contentName": "bodytext", "key": { "key": "WRAPPED_KEY", "nonce": "NONCE" } }`.
The record keeps its coordinate fields beside it. Absent `transport` means direct
transport; present `transport` selects client-bound transport. Its `method`
MUST name a known method offered by the client and selected by the issuer.
An unknown, missing or mismatched method makes the
whole transport invalid; the client MUST NOT retry its key entries as direct
bytes. Unknown transport members are ignored under the common JSON rules;
they do not select a method or change admission.

The issuer wraps every delivered `contentKeys`, `periodKeys` and
`chainKeys` key entry under the one response transport. A selected profile
may add a response section beside `keys`; the issuer wraps that section's key
entries under the same transport.

Each wrapped key entry has a key kind fixed by its result section:
`keys.contentKeys` is `contentKey`, `keys.periodKeys` is `periodKey`, and
`keys.chainKeys` is `chainKey`. The issuer and client MUST bind that kind into
the cryptographic wrapping and opening operations. The kind context is the UTF-8
encoding of `dca-bind-client-bound-key-kind`, followed by one zero octet, followed by
the UTF-8 encoding of the exact kind string. The issuer uses the section it is
writing; the client uses the admitted section it is reading. Neither peer infers
the kind from key length, caller-requested usage or the ciphertext. A missing or
unsupported kind MUST NOT be opened as another kind. A failed kind check is a
malformed individual key entry; the client MUST NOT retry it with another kind
or with an empty context.

A selected profile that adds a response section names the key kind of each
section it adds, and the same kind context binds it. A profile reuses a base
kind only for the same key use. The
[content groups proposal](spec-profile--content-groups.md) binds
`contentGroupKeys.chainKeys` to `contentGroupChainKey`, `contentGroupKeys.periodKeys`
to `contentGroupPeriodKey` and `contentGroupKeys.contentKeys` to `contentKey`.

The client opens a delivered content key as a non-extractable AES-128-GCM
handle with `decrypt` usage and a delivered period key as one with `unwrapKey`
usage, directly from the key entry; it MUST NOT expose those key bytes through
its application API, and the handles MUST NOT be exportable. A client that
cannot store such a handle with its extractability and usages MUST NOT store it,
and MUST NOT export it, substitute an extractable key or fall back to direct
transport mode instead. The client opens a delivered chain key to usable
16-octet key bytes; its Step operation may expose later chain keys to
application code, and no non-extractability claim applies to chain keys or to
period keys locally derived from them. A profile-defined kind states how the
client opens it. Content-group chain and period keys open to 16 usable key
bytes, because the client derives period keys and item pads from them; no
non-extractability claim applies to them.

If the client cannot admit the transport, it rejects every wrapped key entry in
the response. A malformed or unauthentic individual key entry fails locally and
does not suppress a valid sibling key entry. Neither failure permits direct
fallback within that response.

## 7. ECDH-P256 client-bound method

The method identifier is `ECDH-P256`.

### 7.1. Client offer

The client generates or loads a P-256 ECDH keypair. The private key MUST be
non-extractable and permit ECDH key derivation. The offered public JWK contains
`kty`, `crv`, `x` and `y`; it MUST NOT contain private member `d`.

`kty` is exactly `EC`, `crv` is exactly `P-256`, and `x` and `y` are canonical
unpadded base64url encodings of exactly 32 octets each. The coordinates MUST
form a valid P-256 public point. A producer MUST emit only the four public
members. A consumer MAY ignore or refuse other non-private JWK metadata after
admitting these fields, so a producer relies on neither behavior.

### 7.2. Transport-key agreement

For each response, the issuer generates a fresh P-256 ECDH ephemeral keypair.
It performs ECDH between its ephemeral private key and the admitted client
public key. The client performs the same agreement between its retained private
key and the issuer ephemeral public key.

The ECDH output is the shared x-coordinate. Both sides MUST encode it as an
unsigned big-endian integer at the P-256 field width: exactly 32 octets,
retaining or adding leading zero octets as needed. Those 32 octets are the HKDF
input keying material. Both sides derive one AES-256-GCM transport key with
HKDF-SHA-256 using:

| HKDF input | Value                                                               |
| ---------- | ------------------------------------------------------------------- |
| salt       | empty octet string                                                  |
| info       | UTF-8 octets of `dca-derivation-client-bound-transport` (37 octets) |
| output     | 32-octet AES-GCM key                                                |

The client MUST keep its transport key non-extractable. The issuer's ephemeral
public JWK is carried as `transport.publicKey` in the same strict four-member
form as the client offer. The issuer MUST NOT expose or persist its ephemeral
private key or transport key beyond preparation of that response.

The client MUST keep its derived transport key transient; it MUST NOT cache
or persist that key. The client MUST release its references to the transport
key after opening the response's key entries or completing a later reopening
operation.

To reopen a retained wrapped key entry, the client derives the transport key
again from the original client private-key handle and the retained issuer
ephemeral public key using the same transcript.

### 7.3. Wrapped key entries

For every 16-octet delivered key, the issuer generates a fresh 12-octet nonce
and AES-256-GCM encrypts the key under the response transport key with a
16-octet tag and the Section 6 kind context as `additionalData`. The wrapped key
entry is:

```json
{ "key": "WRAPPED_KEY", "nonce": "NONCE" }
```

`nonce` decodes to exactly 12 octets. `key` decodes to exactly 32 octets: the
16 encrypted key octets followed by the 16-octet tag. Both use canonical
unpadded base64url.

The client opens each wrapped key entry as Section 6 requires; for a chain key
it recovers exactly 16 key octets.

## 8. RSA-OAEP client-bound method

The method identifier is `RSA-OAEP`.

The client generates or loads an RSA-OAEP keypair using SHA-256. The modulus
MUST be at least 2048 bits. The private key MUST be non-extractable and permit
`unwrapKey`; a client selected to receive chain keys MUST also be able to
decrypt their wrapped value to key octets. The offered public JWK has `kty`
exactly `RSA` and canonical
`n` and `e` members encoded as Base64urlUInt values under
[RFC 7518, Section 2](https://www.rfc-editor.org/rfc/rfc7518.html#section-2).
Each is the unpadded base64url encoding of the minimum-length unsigned
big-endian representation, with no leading zero octet. The exponent is a
positive odd integer of at least 3. The JWK contains no private RSA members
and, if `alg` is present, it MUST be exactly `RSA-OAEP-256`. If `use` is
present it MUST be `enc`; if `key_ops` is present it MUST be an array containing
only `encrypt` and `wrapKey` (an empty array is permitted); if `ext` is present
it MUST be a boolean. These metadata checks do not authorize another algorithm.

The response `transport` contains only the common `method` member.
For every 16-octet delivered key, the issuer applies RSAES-OAEP with SHA-256,
MGF1 with SHA-256 and the Section 6 kind context as its label under the
admitted client public key. A deployment selecting this method MUST use
RSA-OAEP implementations that support that label at both the issuer and client.
The label-free RSA construction in
[Sealed Key Envelopes Section 5](spec--sealed-key-envelopes.md#5-rsa-oaep-envelope)
applies only to publisher-to-issuer envelopes. The wrapped key entry is:

```json
{ "key": "WRAPPED_KEY" }
```

`key` is canonical unpadded base64url and decodes to exactly the RSA modulus
width. The client opens it as Section 6 requires; for a chain key it recovers
exactly 16 key octets. An OAEP failure is one malformed key entry and
produces no key.

<a id="9-replay-caching-and-composition"></a>

## 9. Caching and client-key accounting

A shared response cache may reuse a direct response only under an endpoint
profile whose authentication, authorization, freshness and cache-key rules make
that safe; under the HTTPS binding,
[HTTPS endpoint binding Section 3.4](spec--http-binding.md#34-response)
also applies and this section does not relax it. A client-bound response is
recipient-specific. It MUST NOT be served from a shared cache unless the cache
is partitioned by the exact client public key and all other authorization
inputs required by the selected endpoint profile.

An implementation MAY include an opaque original request, including unknown
members, as an additional cache discriminator. This can only refine a partition:
unknown members MUST NOT replace authentication, authorization, freshness,
client-public-key or other partition inputs required by the selected endpoint
profile, and a cache hit MUST still meet that profile's reuse conditions.

An issuer that accounts for or revokes delivery per client key MUST associate
each admitted method and public-key identity with the trusted authorization
context, the granted capability scope and the grant's state. That context may
be an authenticated account or another admitted authorization context, such as
a recipient grant; client-bound delivery does not require an account. These
records are issuer delivery metadata, not BIND inputs. This specification
defines neither a registration wire member nor a public-key fingerprint
algorithm.

Replacement of a key associated with that context MUST be authorized under the
same trusted authorization context. A replacement offer MUST NOT silently
transfer entitlement, reset accounting or widen authority. Redelivery to the
replacement key MUST satisfy current issuer authorization and ordinary response
admission; replacement and redelivery may occur in one transaction. Key
replacement does not make previously wrapped key entries openable with the new
private key and does not promise recovery of previously delivered capability.
Previously retained non-extractable capability handles remain usable within
their original scope. Reopening old wrapped key entries requires the original
client private-key handle and the applicable retained transport context. Key
lifetime, rotation frequency, overlap, recovery and record retention are
deployment policy; revocation stops future delivery and does not revoke
capability already delivered.

## 10. Failures

Sections 3 to 8 state client outcomes; an endpoint binding maps issuer-side
failures to its status classes.
[Core Section 8](spec--core-protocol.md#8-failure-model) limits error detail.
Error detail MUST NOT expose key existence or authorization beyond the core
failure model.

## 11. Security considerations

Non-extractable content and period-key handles raise the cost of portable key
theft; they do not stop authorized decryption, plaintext access, same-origin
script using the handle, or a compromised client. Section 6 states what custody
each key kind has. A profile must not claim DRM, attestation or protection from
code executing in the admitted client context.

The client-bound transcripts bind no request identifier, render, issuer, origin
or coordinate, and they authenticate each wrapped key only under its transport
or RSA key, not the surrounding coordinate fields or metadata. The kind context
separates key roles but does not stop a copied wrapped key entry being replayed
to the same client. Admission against the associated request (Section 3) and the
response channel (Section 2) are therefore mandatory parts of the guarantee: a
replay cannot add an unrequested coordinate, and a replayed key keeps exactly
the reach its own specification defines.

## 12. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [RFC 7518: JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)
- [DCA core protocol](spec--core-protocol.md)
- [DCA content protection](spec--content-protection.md)
- [DCA period-key capabilities](spec-profile--period-keys.md)
- [DCA chain keys: construction and delegation](spec-profile--chain-keys.md)
- [DCA HTTPS endpoint binding](spec--http-binding.md)
- [DCA security model](spec--security-model.md)
