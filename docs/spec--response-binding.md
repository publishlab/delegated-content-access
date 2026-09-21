# DCA issuer-response binding

Status: Public Working Draft

## Abstract

This document specifies how an authorized DCA issuer-core result is delivered
to and admitted by a client. The base direct representation carries key bytes
inside an issuer-authenticated confidential request/response channel. Optional
client-bound methods additionally wrap each key for one client's
non-extractable keypair; they do not replace channel authentication.

<a id="1-scope-and-requirements-language"></a>
## 1. Introduction

This document defines response-binding selection, common client admission, direct
key representation, client-bound key representation, ECDH-P256 and RSA-OAEP
client-bound transcripts and their downgrade and failure rules.

It does not authorize a coordinate, define capability reach, define content
encryption or specify browser Origin/CORS processing. The core produces the
semantic result. Content and period specifications constrain admitted keys. An
endpoint specification says how the deployment provides the authenticated
channel required here.

Every result containing usable keys requires an issuer-authenticated
confidential request/response channel.

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

Every deployment returning usable keys MUST select an endpoint binding that
provides layer 1. TLS, HTTP, CORS and proxy configuration are not inferred by
this document; an applicable endpoint specification must state how it provides
these properties.

Client-bound wrapping supplies additional client-side key custody. It does not
authenticate the issuer: any party that knows a client's public key can produce
a value encrypted to it. It therefore MUST NOT be used without layer 1 and
MUST NOT be described as an issuer signature or response-wide authentication.

Publisher-to-issuer BIND is unrelated to this boundary. It authenticates
publisher-supplied coordinates during issuer opening and does not authenticate
the issuer response.

## 3. Inputs and common response form

The input is the issuer-core result defined by
[spec--core-protocol.md](spec--core-protocol.md#7-baseline-issuer-core-result).
The issuer MUST preserve the core result's `keys` coordinates, complete `errors`
entries and non-key members, including the top-level `periodChain` geometry of
a delivered chain result and the top-level `notDelivered` member of a result that
carries one. It may replace only delivered key leaves with the selected
representation and may add a top-level `transport` member; `transport` is the
only member this binding adds. It MUST NOT turn an error into a key
representation or move a coordinate between `keys` and `errors`.

The issuer MUST NOT add a key coordinate, widen a result, rename a coordinate
or transform one key kind into another. A response contains at most one key
representation. The client admits sections before it judges the representation.
It first rejects or ignores an unsupported section, including
`keys.periodChainKeys` and its `periodChain` geometry beside `transport` under
Section 5.1. It then judges the supported sections. Mixing direct string leaves
and client-bound object leaves among supported sections is malformed.

The response channel MUST preserve one response as the answer to one exact
request. Before it opens or retains a key, the client MUST have:

- the issuer identity and endpoint selected for that request;
- the request version and the presented set of that request;
- the publisher delivery and render to which the request belonged; and
- the response obtained through the selected authenticated channel.

The client MUST ignore or reject every returned coordinate outside the
admissible result set of the associated request. For the core sections that set
is exactly the presented set. For a selected capability extension it is the
deterministically checkable set the extension's specification derives from the
admitted source coordinates: for a period-chain result, a returned cutoff or
projected exact leaf is admissible only for a family the request presented,
under the geometry the request resolved for that family, in the window of a
presented source member and at or below that member's supplied position.
Before it admits or retains a cutoff, the client MUST resolve the response's
geometry pair for that family. The resolved values MUST equal the values the
request resolved for it; JSON placement need not match. A family
whose values differ has no admissible cutoff. A projected exact leaf needs no
response geometry. The client MUST perform these checks before opening a
client-bound leaf or retaining direct bytes. A syntactically valid unsolicited
key grants nothing; a chain cutoff or projected leaf outside its admissible set
is unsolicited.

Before surfacing or using an error, the client MUST admit its error-object
shape and coordinate grammar and associate the coordinate with the presented
set of that request as
[spec--core-protocol.md](spec--core-protocol.md#61-presented-coordinates)
defines. It MUST ignore or reject a malformed, nonconforming or unsolicited
error and MUST NOT use such an entry for control flow. A core error grants no
capability. The core protocol assigns it no retry, sibling-issuer-walk or
terminal-refusal meaning; such control flow requires a
separately selected profile that defines the applicable outcome vocabulary and
complete behavior.

[spec--core-protocol.md](spec--core-protocol.md#72-not-delivered-access-group-families)
defines the `notDelivered` member, which an issuer emits only under such a profile,
and [spec--profiles.md](spec--profiles.md#8-dca-v1-not-delivered-result-profile)
fixes when a client counts as having selected it.

A client that has not selected that profile treats `notDelivered` as an unsupported
section and ignores or rejects it before any control flow. Ignoring it gives
the response the same semantics as a response without the member; rejecting it
gives this binding's visible unsupported-response result. Under
either outcome the client MUST NOT infer a grant, a denial or a fallback
decision from the member.

A client that has selected the profile validates the whole section and its
request association before it uses any entry. Each of these makes the response
visibly malformed: a `notDelivered` member that is an array, an entry that is not an
object, an entry whose `reason` is absent, empty or not defined by the selected
profile, an entry whose
`message` is present and is not a string, an entry naming an access group the
associated request did not present, an entry naming an access group for which
the same response delivers a period capability under the family rule of core
Section 7.2, and an entry whose family a period-coordinate `errors` entry of
the same response belongs to under that rule. Direct content-name results are
independent as core Section 7.2 specifies. The client MUST report a malformed
response and MUST NOT record it as an empty result.

A leaf-local rejection does not discard an otherwise admitted `notDelivered`
section; its entries retain the selected profile's control-flow meaning. A
whole-response rejection produces no admitted `notDelivered` entry.

## 4. Selection and agreement

An issuer endpoint has a declared response profile: direct, client-bound by one
named method, or a profile that permits both according to stated policy. A
client MUST know that profile before it treats the endpoint as usable. This can
be established by a containing deployment profile or authenticated endpoint
metadata; it MUST NOT be an undisclosed local convention whose wire-visible
choice the peer cannot predict.

The optional request member `clientPublicKey` offers one client-bound method.
The strict JWK shape determines the offered method:

| Public JWK | Offered method |
| --- | --- |
| `kty` `EC`, `crv` `P-256` | `ECDH-P256` |
| `kty` `RSA` | `RSA-OAEP` |

Presence of `clientPublicKey` is an offer, not authorization. An issuer selects
client-bound delivery only when its endpoint profile permits it, it implements
the offered method and the public key passes that method's admission rules.
The response confirms selection with `transport.mode` and
`transport.method`.

An endpoint profile that requires client-bound delivery MUST fail a request
without a compatible offer before opening any publisher-supplied key and MUST
NOT fall back to direct delivery. An issuer MUST NOT return a direct response
to a client-bound offer unless its endpoint profile permits direct fallback and
the client is known, under that same profile contract, to accept it.

Until interoperable fallback/profile signaling is specified, a deployment
claiming strict client-bound behavior requires pre-established authenticated
endpoint-profile agreement.

## 5. Direct representation

A direct response has no `transport` member. Each leaf in `keys.contentKeys`,
`keys.periodKeys` or `keys.periodChainKeys` is the canonical unpadded
base64url encoding of exactly 16 key octets (22 characters).
[spec--period-key-chains.md](spec--period-key-chains.md#issuer-decision-and-response)
constrains the optional chain-result section. V1 defines no alternate delivered
width or profile selected by observed length.

The client MUST accept a direct leaf only if its selected endpoint profile
permits direct delivery, the response channel requirements in Section 2 hold,
the coordinate belongs to the associated request's admissible result set under
Section 3 and the leaf satisfies the canonical spelling and length rules.
Otherwise it releases and retains no key from that leaf.

Direct delivery by design exposes raw key bytes to the client application
boundary. Its confidentiality and integrity come from the selected response
channel; absence of `transport` is not cryptographic protection. A deployment
requiring non-extractable browser custody must select a client-bound-only
profile and refuse direct responses before decoding their leaves.

### 5.1. Chain results and transport composition

In v1 a chain result is direct-only. `keys.periodChainKeys` and the top-level
`periodChain` member travel only in a direct response, beside direct
`contentKeys` and `periodKeys` string leaves. An issuer MUST NOT emit
`keys.periodChainKeys` in a response that carries `transport`. When `transport`
is present, a client MUST reject or ignore `keys.periodChainKeys` and its
`periodChain` geometry before it opens any leaf in that section and before it
judges the remaining sections' representation. It MUST NOT reinterpret those
leaves under the transport method. The non-key `periodChain` member is
meaningful only beside a delivered `keys.periodChainKeys`; a client preserves it
with a valid direct chain result and otherwise ignores it. V1 defines no
client-bound representation of chain state. A separately selected profile
would define one.

## 6. Client-bound common representation

A client-bound response has:

```json
{
  "keys": { "contentKeys": {}, "periodKeys": {} },
  "transport": {
    "mode": "client-bound",
    "method": "METHOD"
  }
}
```

Method-specific members may occur in `transport`, and every delivered key leaf
is replaced by one method-specific object. `transport.mode` MUST be exactly
`client-bound`. `transport.method` MUST equal the method offered by the client
and selected by the issuer. Unknown, missing or mismatched values make the
whole transport invalid; the client MUST NOT retry its leaves as direct keys.

Before publisher-envelope opening in a client-bound-required profile, the
issuer MUST admit the offered public key and establish the method state needed
to wrap a response. Its placement relative to policy remains subject to the
core processing and endpoint failure model. A missing, malformed or unsupported
offer fails client-bound selection and MUST NOT silently release raw keys.

The issuer wraps every delivered `contentKeys` and exact `periodKeys` leaf
under the one response transport. It leaves the result's errors and other
non-key members, including `notDelivered`, unchanged.
Chain results never travel client-bound; Section 5.1 states the composition.
Every delivered key below is exactly 16 octets: a `contentKey` or an exact
`periodKey` under `dca-v1-exact-period`. Both client-bound methods support
these canonical capabilities. This does not permit delivery of chain state.

The client opens a delivered content key as a non-extractable AES-128-GCM
handle with `decrypt` usage. It opens an exact period key as a non-extractable
AES-128-GCM handle with `unwrapKey` usage. The returned handle MUST NOT be
exportable. The applicable content or period specification defines its use and
cache scope.

If the client cannot admit the transport, it rejects every wrapped leaf in the response.
A malformed or unauthentic individual leaf fails locally and does not suppress
a valid sibling leaf. Neither failure permits direct fallback within that
response.

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

| HKDF input | Value |
| --- | --- |
| salt | empty octet string |
| info | UTF-8 octets of `DCA-client-bound-transport` |
| output | 32-octet AES-GCM key |

The transport key is non-extractable. The issuer's ephemeral public JWK is
carried as `transport.publicKey` in the same strict four-member form as the
client offer. The issuer MUST NOT expose or persist its ephemeral private key
or transport key beyond preparation of that response.

### 7.3. Delivered leaves

For every 16-octet delivered key, the issuer generates a fresh 12-octet nonce
and AES-256-GCM encrypts the key under the response transport key with a
16-octet tag and no `additionalData`. The leaf is:

```json
{ "key": "WRAPPED_KEY", "nonce": "NONCE" }
```

`nonce` decodes to exactly 12 octets. `key` decodes to exactly 32 octets: the
16 encrypted key octets followed by the 16-octet tag. Both use canonical
unpadded base64url.

The client performs the inverse operation directly into a non-extractable
AES-128-GCM handle with the usage required by the containing key section. It
MUST NOT expose an intermediate plaintext byte string through its application
API.

## 8. RSA-OAEP client-bound method

The method identifier is `RSA-OAEP`.

The client generates or loads an RSA-OAEP keypair using SHA-256. The modulus
MUST be at least 2048 bits. The private key MUST be non-extractable and permit
`unwrapKey`. The offered public JWK has `kty` exactly `RSA` and canonical
`n` and `e` members encoded as Base64urlUInt values under
[RFC 7518, Section 2](https://www.rfc-editor.org/rfc/rfc7518.html#section-2).
Each is the unpadded base64url encoding of the minimum-length unsigned
big-endian representation, with no leading zero octet. The modulus is a
positive RSA modulus of at least 2048 bits and the exponent is a positive odd
integer of at least 3. The JWK contains no private RSA members and, if `alg` is
present, it is compatible with RSA-OAEP using SHA-256.

The response `transport` contains only the common `mode` and `method` members.
For every 16-octet delivered key, the issuer applies RSAES-OAEP with SHA-256,
MGF1 with SHA-256 and the empty label under the admitted client public key. The
leaf is:

```json
{ "key": "WRAPPED_KEY" }
```

`key` is canonical unpadded base64url and decodes to exactly the RSA modulus
width. The client unwraps it directly into a non-extractable AES-128-GCM handle
with the usage required by the containing key section. An OAEP failure is one
malformed leaf and produces no key.

RSA-OAEP encryption is randomized. Conformance vectors may record and open a
ciphertext but do not require two conforming sealers to reproduce identical
ciphertext.

## 9. Replay, caching and composition

The response channel MUST reject substitution of an unrelated response for the
live request. The
client-bound methods add no request identifier, render,
issuer, origin or coordinate to their HKDF info, GCM AAD or OAEP label. They do
not independently prevent a copied leaf from being replayed to the same client.

Client admission against the associated request prevents a replay from
creating an unrequested coordinate. A replayed direct content key or wrapped
content-key handle remains scoped to its associated `(renderId, contentName)`.
An exact period key remains reusable for precisely the reach defined by its
period-capability specification; response processing does not narrow that inherent
reach.

A shared response cache may reuse a direct response only under an endpoint
profile whose authentication, authorization, freshness and cache-key rules make
that safe. A client-bound response is recipient-specific. It MUST NOT be served
from a shared cache unless the cache is partitioned by the exact client public
key and all other authorization inputs required by the selected endpoint
profile.

When the browser and HTTP binding is selected, its response-caching rule owns
the additional HTTP cache-control, Origin partitioning and `Vary` requirements.
Meeting this section's response-binding conditions does not relax that endpoint
rule.

A client may store a non-extractable exact period-key handle or retain the
wrapped leaf plus enough transport context to reopen it with the same client
private key. Cache representation does not change period capability reach.

## 10. Failures

| Condition | Required outcome |
| --- | --- |
| response channel not authenticated, confidential, intact or associated with the request | Reject the whole response; retain no keys |
| response coordinate outside the request's admissible result set | Ignore or reject before opening; retain no key for it |
| mixed direct and client-bound leaves among supported sections | Reject the response representation |
| unknown, missing or mismatched client-bound method/transport | Reject all wrapped leaves; no direct retry |
| missing or malformed required public-key offer for a required client-bound profile | Fail before publisher-envelope opening; no direct downgrade |
| malformed direct leaf | Reject that leaf |
| malformed or unauthentic client-bound leaf | Reject that leaf; valid siblings may remain |
| unsupported section or kind, or a chain section beside `transport` | Reject or ignore it first; never reinterpret it |
| malformed `notDelivered` section under a selected not-delivered-result profile | Reject the whole response as malformed; record no empty result |

An endpoint binding maps these outcomes to its own status and transport
behavior. Error detail MUST NOT expose key existence or authorization beyond
the core failure model.

## 11. Security considerations

The authenticated channel is the issuer-authentication boundary. Client-bound
public-key encryption without it is vulnerable to forged-key responses because
the public key is public by design.

Non-extractable handles raise the cost of portable key theft but do not stop
authorized decryption, plaintext access, same-origin script acting as a key
oracle, browser compromise or a rooted device. A profile must not claim DRM,
attestation or protection from code executing in the admitted client context.

The client-bound methods authenticate each wrapped key only under their
transport key or RSA key. They do not authenticate surrounding coordinate
names or response metadata. Request-associated coordinate admission and the
response channel are mandatory parts of the composed guarantee.

## 12. Dependencies

This specification depends on:

- [spec--core-protocol.md](spec--core-protocol.md) for request coordinates,
  authorization and the semantic issuer result;
- [spec--content-protection.md](spec--content-protection.md) for content-key use
  and handle semantics; and
- [spec--period-keys.md](spec--period-keys.md) when exact reusable keys or
  chain results are delivered.

[spec--browser-http-binding.md](spec--browser-http-binding.md) instantiates the
response channel as HTTPS JSON and defines an optional browser Origin/CORS
profile. The Origin/CORS requirements apply only when that profile is selected.

## 13. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [RFC 7518: JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)
- [DCA core protocol](spec--core-protocol.md)
- [DCA content protection](spec--content-protection.md)
- [DCA exact period-key capabilities](spec--period-keys.md)
- [DCA period-chain construction and delegation](spec--period-key-chains.md)
- [DCA browser and HTTP binding](spec--browser-http-binding.md)
- [DCA security model](spec--security-model.md)

## 14. Informative References

This specification has no additional informative references.
