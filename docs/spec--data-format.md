# DCA page and object data format

Status: Public Working Draft

## Abstract

This document specifies the JSON objects and HTML carriers used to deliver DCA
metadata and ciphertext from a publisher to a client. It defines member
placement, structural processing, identifier spelling and extension handling.

## 1. Introduction

This document specifies the publisher-to-client carrier, placement and
structural requirements. The focused sealed-key envelope specification defines envelope
algorithms and BIND.

This document does not define content cryptography, publisher authentication,
issuer authorization, sealed-key envelope algorithms, BIND, period-key
capability semantics, unlock messages, HTTP, CORS or key delivery.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14) when, and only when, they appear
in all capitals.

## 2. Common JSON rules

A DCA document and each map defined by this document is a JSON object, not an
array.

When a carrier enters as octets, those octets MUST be well-formed UTF-8 JSON.
Malformed UTF-8 is a fatal failure of the complete source before any item,
route, or sibling value is processed; a consumer MUST NOT salvage a partial
document from bytes that do not encode one JSON value.

When a native object rather than parsed JSON enters a consumer, every protocol
member MUST be an own member. An inherited property is absent. A consumer MUST
NOT traverse a prototype or equivalent language-specific inheritance mechanism
to obtain a protocol member.

A producer MUST emit each member name at most once. A consumer MAY reject an
object containing duplicate names. If it accepts the object, it MUST use only
the lexically last occurrence of each duplicated name and MUST NOT merge values
or use an earlier occurrence.

A consumer MUST ignore unknown members while processing objects defined here.
It MAY retain the original parsed object when serializing it again. Unknown
members MUST NOT alter cryptography, key selection, authorization or fields
relayed to an issuer. A member this document names as reserved is not unknown;
its owner document defines its effect.

This rule does not reinterpret publisher-defined `resource.data` or claims in
`resourceJWT`. A same-version addition MUST remain optional when ignored. An
addition that changes cryptography, key selection, authorization or an existing
member's meaning requires an explicit version or extension.

### 2.1. Identifiers

`contentName`, `accessGroup` and `issuerName` use this ASCII grammar:

```text
identifier = ALPHA *( ALPHA / DIGIT / "_" / ":" / "-" )
```

An identifier contains 1 through 64 characters. Comparison is byte-for-byte
and case-sensitive. An identifier is not case-folded, Unicode-normalized or
interpreted as hierarchical.

An `accessGroup` is a publisher-scoped policy-family coordinate. Its spelling
MAY use business vocabulary, but carries no entitlement and MUST NOT encode or
be interpreted as a per-article map of granting issuers.

These identifiers occur as JSON member names. A producer MUST emit only names
that satisfy this section. When a consumer processes a map keyed by one of
these identifiers, it MUST reject that map if any member name violates this
section. It MUST NOT ignore the invalid name while accepting its siblings.

### 2.2. Binary strings

A producer MUST encode binary values as canonical unpadded base64url under
[RFC 4648, Section 5](https://www.rfc-editor.org/rfc/rfc4648.html#section-5).
The spelling uses only `A-Z`, `a-z`, `0-9`, `-` and `_`, contains no `=`, and
has zero unused trailing bits. `aad` is not binary; it is a JSON string.

This spelling applies to ciphertext, nonces, wrapped content-key candidates and
sealed-envelope values. A focused specification may further constrain the
decoded bytes of a field.

A consumer MUST NOT accept another spelling as the value of a binary field. It
MUST reject padding, standard-base64 characters, undecodable input and a
spelling with nonzero unused trailing bits. Failure scope follows the containing
field or focused specification; a rejected spelling never supplies key or
ciphertext bytes.

Unless a focused specification requires a wider failure, an invalid required
binary member makes its item record unusable, an invalid cached-wrap or sealed
envelope leaf makes only that candidate unavailable, and an invalid ciphertext
leaf supplies no ciphertext for that item. A malformed leaf MUST NOT suppress
a valid sibling candidate, issuer or item.

## 3. Markup delivery

A markup delivery carries one DCA instance in the HTML `body`:

```html
<script type="application/json" class="dca-data">...</script>
<script type="application/json" class="dca-sealed-content">...</script>
```

The `dca-data` carrier is required. The `dca-sealed-content` carrier is
optional. They have no ordering, sibling or depth requirement.

A producer MUST use inert `script` elements with
`type="application/json"`. It MUST serialize each JSON value so embedded data
cannot terminate or alter the HTML script-data element. Parsing the carrier
MUST recover the value supplied to the serializer, including strings that
contain `<`.

A consumer parses the carrier text as JSON. A missing or non-object `dca-data`
value is a structural failure. A present `dca-sealed-content` value that is not
a non-array object is a structural failure.

A consumer MUST inspect every element in `body` carrying either reserved class
token. There MUST be exactly one `dca-data` element and at most one
`dca-sealed-content` element. Every such element MUST be a `script` whose
`type` attribute is exactly `application/json`. A duplicate or malformed
reserved carrier is a structural failure; a consumer MUST NOT select the first
one and ignore another.

One element MUST NOT serve as both carriers. An element carrying both reserved
class tokens is a structural failure.

## 4. The `dca-data` object

The `dca-data` object contains:

| Member | Type | Requirement |
| --- | --- | --- |
| `version` | string | Required; value `"1"` in this version |
| `resource` | object | Optional readable publisher metadata |
| `resourceJWT` | string | Required opaque publisher assertion |
| `contentData` | object | Required item inventory |
| `issuerData` | object | Required non-empty issuer map |

The publisher emits `resource` for diagnostics only. This document does not
authenticate it or send it to an issuer. A `resource` member that disagrees
with the claims in `resourceJWT` is not an error, and nothing reconciles the two
copies: the verified claims are the only copy a consumer or an issuer acts on,
as
[spec--core-protocol.md](spec--core-protocol.md#42-verification-and-registration)
states.

The client relays `resourceJWT` unchanged when an unlock protocol requires it.
Its signature, claims, `kid`, `renderId`, origin and authentication failures belong
to the core protocol specification. The canonical 22-character spelling of
`renderId`, and the 16 octets it decodes to, are stated by
[spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md#32-canonical-encoding),
which uses that canonical `renderId` in every envelope's BIND string. A
mismatch makes envelope opening fail.

Before exposing a delivery to request construction or content-key resolution,
a consumer MUST admit the outer object and these own members:

- `version`, a string exactly equal to `"1"`;
- `resourceJWT`, a string;
- `contentData`, a non-array object; and
- `issuerData`, a non-empty non-array object.

If `resource` is present, it MUST be a non-array object. Failure of an outer
requirement is a delivery-wide structural failure. A consumer MAY defer one
item record's detailed admission until that item is used and one issuer block's
detailed admission until that issuer is selected; it MUST complete the
applicable admission before deriving a request or using key or ciphertext
material from that record or block.

### 4.1. `contentData`

`contentData` maps `contentName` to item records. Each record is a non-array
object with these members:

| Member | Type | Requirement |
| --- | --- | --- |
| `contentType` | string | Required content-handling metadata |
| `contentEncodings` | array of strings | Optional ordered representation layers |
| `nonce` | binary string | Required content-decryption nonce |
| `aad` | string | Required opaque content-decryption AAD |
| `keys` | object | Optional cached-wrap map |

If `keys` is absent, the item offers no cached period-key path. If present, it
MUST be a non-empty non-array object mapping `accessGroup` to a non-empty array.
Each array member MUST be a non-array object with string members `t`, `nonce`
and `key`. An own `bind` member on such an entry is reserved:
[spec--content-protection.md](spec--content-protection.md#4-base-exact-period-content-key-wrapping)
defines it, and a client never opens an entry that carries it under the base
transcript.

A missing, non-object or array `contentData` value is a structural failure. When
a named record is missing, the publisher declared no such protected item. A
non-object record or a missing or malformed required `contentType`, `nonce` or
`aad` member is an item record failure when that item is used; it MUST NOT
suppress a valid sibling item or be treated as a cached-candidate miss.

If `contentEncodings` is absent, the item uses the base content
representation. If present, it MUST be a non-empty dense array in which every
member is a non-empty string. Order and repetitions are significant. Encoding
names are opaque, case-sensitive string values and are not normalized. An
empty or malformed array is an item record failure; it is not another spelling
of the base representation. A consumer MUST enforce finite
implementation-defined limits on the number of layers and the aggregate UTF-8
byte length of their names. Exceeding a limit is an item record failure and
MUST NOT suppress a valid sibling item.

This member identifies representation processing defined by
[spec--content-protection.md](spec--content-protection.md). It does not alter
content-key identity, AAD, BIND, issuer selection, authorization or the meaning
of `contentType`.

A present malformed `keys` container or a `keys` map rejected under Section 2.1
supplies no cached routes for that item; it does not suppress an otherwise valid
issuer-mediated route. Within an admitted access-group array, a member that is
not a non-array object with string `t`, `nonce` and `key` members supplies no
candidate. It MUST NOT suppress valid sibling candidates.

An empty `contentData` object is structurally valid at this layer. The core
protocol requires at least one protected item. A producer MUST NOT emit an
empty inventory unless its selected profile defines its meaning.

At this structural layer, `t` is an opaque string. Period-label semantics and
producer grammar belong to the period-key specification.

The `key` member is a content-key wrap under the corresponding exact period
capability. [spec--content-protection.md](spec--content-protection.md) defines
content encryption, nonce sizes, AAD interpretation and unwrap processing.
Capability authority remains outside this document.

### 4.2. `issuerData`

`issuerData` maps `issuerName` to issuer blocks. A producer MUST emit each block
as a non-array object containing:

| Member | Type | Requirement |
| --- | --- | --- |
| `unlockUrl` | string | Required |
| `keyId` | string | Required |
| `sealed` | object | Required |

If present, `sealed.contentKeys` is an object mapping `contentName` to a sealed
binary string. If present, `sealed.periodKeys` is an object mapping
`accessGroup` to an object that maps `t` to a sealed binary string.

These rules define placement only. A selected envelope specification defines
the decoded envelope and opening rules. A selected period-capability
specification defines the authority of period members. Issuer lookup, request
construction, authorization and response handling are outside this document.

For a consumer, a selected issuer block is usable only when the block and its
`sealed` member are non-array objects and its `unlockUrl` and `keyId` members
are strings. A malformed selected block is unusable; it does not suppress a
valid sibling issuer.

If present, `sealed.contentKeys` and `sealed.periodKeys` MUST be non-array
objects. Every `sealed.periodKeys[accessGroup]` value MUST also be a non-array
object. The consumer admits identifier-keyed maps under Section 2.1 before
relaying their leaves. A malformed or rejected route map supplies no route of
that kind, but does not suppress a valid route map in the same issuer block or a
valid sibling issuer. An invalid sealed leaf supplies no candidate at that
coordinate and does not suppress valid sibling leaves.

`unlockUrl` is the publisher-carried default endpoint. A selected core or
endpoint profile MAY supply a different authenticated endpoint for the same
`issuerName` and `keyId`. This document does not define that selection and the
override does not change the carried field's required type.

An issuer map alone does not prove that every item has an opening path.
[spec--core-protocol.md](spec--core-protocol.md#9-delegation-completeness)
states the delegation-completeness invariant; the selected profile completes
it. This format does not infer route semantics from member
placement.

A missing, empty, non-object or array `issuerData` value is a structural
failure. When selecting an issuer, a consumer MUST treat a missing or malformed
issuer block, `sealed`, `keyId` or `unlockUrl` as an unusable issuer and MUST
NOT send a request derived from it. That failure does not suppress a valid
sibling issuer. If no usable issuer-mediated path remains for the requested
item and no applicable cached capability opens it, opening fails.

### 4.3. Period-chain extension members

When an issuer route selects chain supply under the period-chain profile of
[spec--period-key-chains.md](spec--period-key-chains.md), a delivery carries
two further members. Both are extension members under Section 8. A delivery
with no chain-supplied issuer route emits neither member merely because the
publisher privately used the profile's canonical construction to produce its
exact leaves. An exact-only issuer route has no `sealed.periodChainKeys`
collection; the top-level `periodChain` may still serve a sibling chain route.
For a consumer that has not selected chain relay or processing, the members are
unknown under Section 2 and never alter exact processing. A consumer that has
selected the applicable duty follows the compatibility rules the core protocol
states for projected exact leaves and the admissible result set, in
[spec--core-protocol.md](spec--core-protocol.md#7-baseline-issuer-core-result),
and the route-selection rules of
[spec--period-key-chains.md](spec--period-key-chains.md#issuer-decision-and-response).

| Member | Type | Requirement |
| --- | --- | --- |
| `periodChain` | object | Optional top-level geometry context |
| `issuerData[issuerName].sealed.periodChainKeys` | object | Optional chain-capability collection |

`periodChain` is a non-array object with these members:

| Member | Type | Requirement |
| --- | --- | --- |
| `chainsPerDay` | number | Optional document-wide geometry; positive integer |
| `periodMinutes` | number | Optional document-wide geometry; positive integer |
| `accessGroups` | object | Optional map from `accessGroup` to a family override |

A family override is a non-array object carrying both `chainsPerDay` and
`periodMinutes` as positive integers. The document-wide pair and every override
are complete pairs: a producer MUST emit both members of a pair or neither.
Divisibility, the position bound, the resolution order between an override and
the document-wide pair, and every other geometry rule belong to the period-chain
specification.

For these geometry members, a positive integer is a JSON number whose
mathematical value is an integer greater than zero. Admission depends on that
value, not on whether a parser stores it in an integer or floating-point host
type and not on whether the JSON spelling contains a fraction or exponent.
For example, `2`, `2.0` and `2e0` have the same admitted value before the
focused specification applies its bounds. The canonical decimal spelling used
in a cryptographic transcript remains a separate rule of the transcript's
owning specification.

`sealed.periodChainKeys` maps `accessGroup` to a non-array object that maps a
chain coordinate label to a sealed binary string. The label is an opaque string
at this layer; its grammar, grid admission and the one-member-per-window rule
belong to the period-chain specification. Each sealed value is a binary string
under Section 2.2 whose decoded envelope the selected envelope specification
defines.

The structural failure scopes below apply to a consumer that has selected the
profile and reads a delivery or an issuer block.
[spec--core-protocol.md](spec--core-protocol.md#5-baseline-unlock-request) cites
the geometry, bound and leaf scopes for a request and defines request admission,
where a malformed collection or access-group name is a whole-request failure.
The geometry outcomes apply the resolution rule of
[spec--period-key-chains.md](spec--period-key-chains.md#extension-carrier-and-client-relay)
and do not redefine it:

- A consumer ignores an unknown member directly inside `periodChain` under
  Section 2. It selects no geometry, authority, cryptography or fallback
  behavior.
- A consumer treats an unknown member inside a family override as unsupported:
  that family's chain operation fails and does not fall back to a
  lower-precedence value, as
  [spec--period-key-chains.md](spec--period-key-chains.md#extension-carrier-and-client-relay)
  requires.
- A present `periodChain` that is not a non-array object, or a present
  `accessGroups` that is not a non-array object or is rejected under Section
  2.1, supplies no geometry: no chain family in the delivery has a resolvable
  pair. A valid-looking family override inside the rejected map and the
  document-wide pair do not restore geometry for that delivery.
- A malformed document-wide pair (one member absent, or a value that is not a
  positive integer) supplies no document-wide pair. A family with its own
  complete override is unaffected; a family without one depends on the
  document-wide pair and has no resolvable pair.
- A malformed family override (not a non-array object, one member absent, or a
  value that is not a positive integer) leaves that family with no resolvable
  pair. It does not fall back to the document-wide pair and does not affect a
  sibling family.
- A family present in `sealed.periodChainKeys` with no resolvable pair supplies
  no chain candidate. It is a failed family, not an absent one; the period-chain
  specification defines that it selects no exact route by itself.
- A present `sealed.periodChainKeys` that is not a non-array object, or one
  rejected under Section 2.1, supplies no chain route for that issuer block. It
  does not suppress `sealed.contentKeys`, `sealed.periodKeys` or a valid sibling
  issuer at this layer; whether an exact route remains selectable on a
  chain-owned period route belongs to the period-chain specification.
- A family value that is not a non-array object, or an empty family object,
  supplies no chain candidate for that family and does not suppress a valid
  sibling family.
- An invalid sealed leaf under Section 2.2 supplies no candidate at that
  coordinate and does not suppress valid sibling leaves.
- Exceeding the per-family member bound of the period-chain specification fails
  that family. Exceeding its per-message bound fails every chain family in that
  delivery or request.

These rules define placement and structural scope only. Geometry validity,
label admission, capability authority, issuer selection and response handling
are outside this document.

## 5. Sealed-content carrier

The optional `dca-sealed-content` object maps `contentName` to ciphertext binary
strings.

An item declared by `contentData` may have no member in this object. Its
ciphertext is then absent from this delivery. The content-protection
specification defines the cryptographic meaning and any deferred-delivery
invariants; this document defines no retrieval mechanism.

A grammar-valid member not declared by `contentData` is ignored by the core
client. Section 2.1 still rejects the carrier when a member name is not a valid
`contentName`. A missing member, a value that is not a string, or a string that
is not canonical base64url supplies no ciphertext for that item. It does not
invalidate valid ciphertext siblings.

This document does not define ciphertext encryption, decryption or a deferred
content transport. The base cryptographic invariants are defined by
[spec--content-protection.md](spec--content-protection.md).

## 6. Object delivery

An object or API delivery uses the `dca-data` members in one enclosing JSON
object and adds:

| Member | Type | Requirement |
| --- | --- | --- |
| `sealedContent` | object | Optional; same map as `dca-sealed-content` |

An object reader obtains ciphertext from `sealedContent[contentName]`; a markup
reader obtains it from the separate carrier. All other member names, types and
structural rules are identical.

A present `sealedContent` value that is not a non-array object is a structural
failure. A native-object consumer MUST obtain `sealedContent` as an own member;
an inherited value is absent. JSON parse failure and an enclosing array are
delivery-wide structural failures.

## 7. Structural processing

A consumer processes a delivery in this order:

1. Locate every reserved carrier or the selected object, enforce its
   cardinality and element rules, and parse its JSON.
2. Apply the duplicate-member rule.
3. Require the outer object and members in Section 4 before exposing the
   delivery to request construction or key resolution.
4. Admit the identifier keys of `contentData` and `issuerData`; defer detailed
   item-record and selected-issuer-block validation only as Section 4 permits.
5. Read ciphertext only by an own-member lookup of the declared
   `contentName`; apply the missing or deferred rule.
6. Preserve and relay `resourceJWT` unchanged when required.
7. Invoke the selected specifications for authentication, issuer processing,
   envelopes, period capabilities, content decryption and transport.

A structural failure releases no key material through this document. Error
codes, HTTP statuses, partial issuer success and retry behavior are outside its
scope.

## 8. Extensions and retired fields

A v1 consumer MUST use `contentData` as the sole item inventory. It MUST NOT
consult the retired `contentSealData` or top-level `sealedContentKeys` fields.
If either appears beside valid `contentData`, it is an unknown member and MUST
NOT be merged with or preferred over the v1 inventory.

The per-issuer `issuerJWT` proof envelope is retired as well. Each sealed blob
commits to its own coordinate instead, under the BIND of
[spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md#3-bind). A v1
consumer MUST NOT relay `issuerJWT` and MUST NOT read a proof from it; where it
appears it is an unknown member under Section 2.

An extension defines its own members and processing. A base consumer ignores
unknown extension members under Section 2. An extension that changes the
meaning of a base member requires an explicit compatibility rule. The
period-chain members of Section 4.3 are the one selected extension carrier in
this version. The reserved `bind` member of Section 3 marks an entry for an
alternative-wrap profile; no such profile is selected in this version, and the
marked entry stays closed to a client that has not selected one.

## 9. Security considerations

Page input remains untrusted until the applicable authentication and issuer
processing verify the publisher assertion. `resource`, identifier spellings,
`unlockUrl`, `keyId`, ciphertext placement and sealed maps do not grant access.

This format does not authenticate or bind `contentData` to a page location.
Sealed-envelope BIND, publisher verification, registration-scoped opening-key
selection, issuer authorization and browser-origin enforcement are separate
security boundaries.

Malformed page data is not an authorization grant, cache miss or direct-only
fallback.

## 10. Composition and dependencies

This document defines the identifiers and carrier structures the other
specifications use. Its structural conformance does not require understanding
the decoded cryptographic values.

When selected:

- [spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md) constrains
  sealed values and depends on the identifiers defined here;
- [spec--period-keys.md](spec--period-keys.md) constrains exact period
  capability members and [spec--period-key-chains.md](spec--period-key-chains.md)
  constrains chain period capability members;
- [spec--core-protocol.md](spec--core-protocol.md) defines `resourceJWT`,
  publisher verification, registration, issuer processing and unlock messages;
- [spec--content-protection.md](spec--content-protection.md) defines content
  encryption, content-key wrapping, nonces, AAD and decryption failures; and
- [spec--browser-http-binding.md](spec--browser-http-binding.md) and
  [spec--response-binding.md](spec--response-binding.md) define the selected
  HTTP/browser exchange and issuer-to-client result protection.

[spec--security-model.md](spec--security-model.md) remains the mandatory trust
and authorization boundary while those normative composition specifications
are assembled.

## 11. Normative References

- [BCP 14](https://www.rfc-editor.org/info/bcp14), incorporating RFC 2119 and
  RFC 8174 requirements-language interpretation.
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html), Base-N Encodings.
- [DCA core protocol](spec--core-protocol.md).
- [DCA content protection](spec--content-protection.md).
- [DCA sealed-key envelopes](spec--sealed-key-envelopes.md).
- [DCA exact period-key capabilities](spec--period-keys.md).
- [DCA period-chain construction and delegation](spec--period-key-chains.md).
- [DCA browser and HTTP binding](spec--browser-http-binding.md).
- [DCA issuer-response binding](spec--response-binding.md).
- [DCA security model](spec--security-model.md).

## 12. Informative References

- [DCA data-format example](design--data-format--example.md).
