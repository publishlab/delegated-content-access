# DCA page and object data format

Status: Public Working Draft

## Abstract

This document specifies the JSON delivery document and the HTML markup
carriers used to deliver DCA metadata and ciphertext from a publisher to a
client. It defines member placement, structural processing, identifier
spelling and extension handling.

## 1. Introduction

This document specifies the publisher-to-client carrier, placement and
structural requirements; its structural conformance does not require
understanding the decoded cryptographic values. It does not define content
cryptography, publisher authentication, issuer authorization, sealed-key
envelope algorithms, BIND, period-key capability semantics, unlock messages,
HTTP, CORS or key delivery.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14) when, and only when, they appear
in all capitals.

## 2. Common JSON rules

A DCA document and each map defined by this document is a JSON object, not an
array.

When a carrier enters as octets, it MUST be one well-formed UTF-8 JSON value.
A producer MUST NOT emit a byte order mark. A consumer MUST ignore exactly one
initial UTF-8 byte order mark, the octets `EF BB BF` at byte offset zero, when
present; another byte order mark, or one after whitespace, is invalid JSON, and
U+FEFF inside a JSON string remains string data. Malformed UTF-8 or JSON is a
fatal failure of the complete source before any item, issuer block or sibling
value is processed; a consumer MUST NOT salvage a partial document from bytes
that do not encode one JSON value. This rule covers the JSON delivery
(Section 6) and every binding that carries DCA JSON as octets and cites this
section. It does not define byte order mark handling for script-embedded JSON
(Section 3), native-object interfaces or opened item content.

Every protocol-member lookup by a consumer MUST use an own member, whether
the object came from parsed JSON or a native-object interface. An inherited
property is absent. A consumer MUST NOT traverse a prototype or equivalent
language-specific inheritance mechanism to obtain a protocol member.

A producer MUST emit each member name at most once. A consumer MAY reject an
object containing duplicate names. If it accepts the object, it MUST use only
the lexically last occurrence of each duplicated name and MUST NOT merge values
or use an earlier occurrence.

A consumer MUST ignore unknown members while processing objects defined here.
Unknown members MUST NOT alter cryptography, key selection, authorization or
fields relayed to an issuer. A member this document names as reserved is not
unknown; its owner document defines its effect.

This rule does not reinterpret publisher-defined `resource.data` or claims in
`resourceJWT`. A same-version addition MUST remain optional when ignored. An addition that
changes cryptography, key selection, authorization or an existing member's
meaning requires an explicit version or extension.

### 2.1. Identifiers

`contentName`, `accessGroup` and `issuerName` use this ASCII grammar:

```text
identifier = ALPHA *( ALPHA / DIGIT / "_" / ":" / "-" )
```

An identifier contains 1 through 64 characters. Comparison is byte-for-byte
and case-sensitive. An identifier is not case-folded, Unicode-normalized or
interpreted as hierarchical or as a map of issuers.

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
has zero unused trailing bits.

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
envelope entry makes only that candidate unavailable, and an invalid ciphertext
entry supplies no ciphertext for that item.

## 3. Markup delivery

The markup delivery is the carrier of the optional `dca-profile-html-carrier`
profile
([profiles Section 9](spec--profiles.md#9-dca-profile-html-carrier-profile)). A
role that does not claim that profile need not implement this section. The
baseline carrier is the JSON delivery of Section 6.

A markup delivery carries one DCA instance in the HTML `body`:

```html
<script type="application/json" class="dca-data">...</script>
<script type="application/json" class="dca-sealed-content">...</script>
```

The two carriers have no ordering, sibling or depth requirement.

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
Reserved elements outside the parsed document's `body` subtree do not count
as carriers and MUST NOT affect selection, cardinality or validation. A
head-only carrier therefore leaves the required body carrier missing.

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
| `periodGeometry` | object | Complete geometry for selected chain processing; chain keys Section 12.1 |

The publisher emits `resource` for diagnostics only. This document does not
authenticate it or send it to an issuer. A `resource` that disagrees with the
claims in `resourceJWT` is not an error; consumers and issuers act only on the
verified claims.

The client relays `resourceJWT` unchanged when an unlock protocol requires it.
Content protection decodes the token's payload to admit `renderId` as a local
content AAD input; that decoding establishes no authorization
([content protection Section 3.2](spec--content-protection.md#32-content-aad)).
Its signature, claims, `kid`, `renderId`, origin and authentication failures
belong to the core protocol specification.

Before exposing a delivery to request construction or content-key resolution,
a consumer MUST admit the outer object and each required member with its type:
`version` exactly `"1"`, `resourceJWT` a string, `contentData` a non-array
object and `issuerData` a non-empty non-array object. A present `resource` MUST
be a non-array object. Failure of an outer requirement is a delivery-wide
structural failure. A consumer MUST complete an item record's or issuer
block's admission before deriving a request from it or using its key or
ciphertext material.

### 4.1. `contentData`

`contentData` maps `contentName` to item records. Each record is a non-array
object with these members:

| Member | Type | Requirement |
| --- | --- | --- |
| `contentType` | string | Required content-handling metadata |
| `contentEncodings` | array of strings | Optional ordered representation layers |
| `keys` | object | Optional cached-wrap map |

[spec--content-protection.md](spec--content-protection.md) defines content
encryption, nonce sizes, the content AAD built from the delivery and unwrap
processing.

A producer MUST omit `aad` and `nonce` from an item record. A consumer MUST
ignore either carried item member under the unknown-member rule, regardless
of its type. Neither member selects an AAD, nonce procedure or legacy retry.
Wrap-entry `nonce` members below retain their required meaning.

If `keys` is absent, the item offers no period-key-wrap candidates. If present, it
MUST be a non-empty non-array object mapping `accessGroup` to a non-empty array.
Each array member MUST be a non-array object with string members `t`, `nonce`
and `key`. An own `bind` member on such an entry is reserved;
[content protection Section 4](spec--content-protection.md#4-base-period-key-content-key-wrapping)
defines its effect.

When a named record is missing, the publisher declared no such protected item.
A non-object record or a missing or malformed required `contentType`
member is an item record failure when that item is used, not a
cached-candidate miss.

If `contentEncodings` is absent, the item uses the base content
representation. If present, it MUST be a non-empty dense array in which every
member is a non-empty string. Order and repetitions are significant. Encoding
names are opaque, case-sensitive string values and are not normalized. An
empty or malformed array is an item record failure; it is not another spelling
of the base representation. A consumer MUST enforce a finite
implementation-defined limit on the aggregate UTF-8 byte length of the names;
[content protection Section 8.1](spec--content-protection.md#81-ordered-representation-layers)
limits the number of layers and defines the processing this member names.
Exceeding a limit is an item record failure. The member does not alter
content-key identity, BIND, issuer selection, authorization or the meaning of
`contentType`. The content tag does not authenticate this list or `contentType`;
content protection Section 8.1 defines the resulting handling boundary.

A present malformed `keys` container, or a `keys` map rejected under
Section 2.1, supplies no period-key-wrap candidates for that item; an
otherwise valid issuer-mediated item content-key alternative remains. Within
an admitted `keys` map, an access-group value that is not a non-empty array
supplies no candidates for that group, and an array member that is not a
non-array object with string `t`, `nonce` and `key` members supplies no
candidate.

An empty `contentData` object is structurally valid at this layer. The core
protocol requires at least one protected item. A producer MUST NOT emit an
empty inventory unless its selected profile defines its meaning.

At this structural layer, `t` is an opaque string; the period-key
specification owns its grammar. The `key` member is a content-key wrap under
the period key at that `(accessGroup, t)`; content protection Section 4 defines
it.

### 4.2. `issuerData`

`issuerData` maps `issuerName` to issuer blocks. A producer MUST emit each block
as a non-array object containing:

| Member | Type | Requirement |
| --- | --- | --- |
| `keyId` | string | Required |
| `envelope` | string | Optional procedure selector; [compact ECDH profile](spec-profile--compact-ecdh.md#3-wire-selector-and-client-relay) |
| `sealed` | object | Required |
| `sealed.chainKeys` | object | Optional extension member; chain keys Section 12.1 |

If present, `sealed.contentKeys` is an object mapping `contentName` to a sealed
binary string. If present, `sealed.periodKeys` is an object mapping
`accessGroup` to an object that maps `t` to a sealed binary string.

For a consumer, a selected issuer block is usable only when the block and its
`sealed` member are non-array objects and its `keyId` is a non-empty string.
A consumer MUST NOT send a request derived from an unusable issuer block.

A producer MUST omit `unlockUrl`. A consumer MUST ignore a carried `unlockUrl`
under the unknown-member rule, regardless of its type. Its presence or absence
does not change issuer-block admission. It MUST NOT supply an endpoint or a
fallback when client configuration provides no route.

The article identifies the issuer; the client integration supplies its endpoint
and response agreement. The client selects that endpoint from trusted
configuration for the operation's publisher/deployment context and `issuerName`,
as required by [core Section 9](spec--core-protocol.md#9-delegation-completeness)
and [HTTPS binding Section 3.1](spec--http-binding.md#31-endpoint-and-channel).

If present, `sealed.contentKeys` and `sealed.periodKeys` MUST be non-array
objects, and every `sealed.periodKeys[accessGroup]` value a non-empty
non-array object. The consumer admits identifier-keyed maps under Section 2.1
before relaying their entries. A malformed or rejected sealed-key map supplies
no candidates of that kind; a malformed or empty access-group value supplies no
candidate for that group; an invalid sealed entry supplies no candidate at its
coordinate. A client applies these scopes before constructing its issuer
request.

If no usable issuer-mediated key-acquisition alternative remains for the
requested item and no applicable cached capability opens it, opening fails.

## 5. Sealed-content carrier

The optional `dca-sealed-content` object maps `contentName` to ciphertext binary
strings.

An item declared by `contentData` may have no member in this object; its
ciphertext is then absent from this delivery, and this document defines no
retrieval mechanism.

A grammar-valid member not declared by `contentData` is ignored by the core
client. Section 2.1 still rejects the carrier when a member name is not a valid
`contentName`. A missing member, a value that is not a string, or a string that
is not canonical base64url supplies no ciphertext for that item.

## 6. Object delivery

An object or API delivery uses the `dca-data` members in one enclosing JSON
object and adds:

| Member | Type | Requirement |
| --- | --- | --- |
| `sealedContent` | object | Optional; same map as `dca-sealed-content` |

An object reader obtains ciphertext from `sealedContent[contentName]`; a markup
reader obtains it from the separate carrier. All other member names, types and
structural rules are identical.

The **JSON delivery** is the serialized form of this object: the octets of
one UTF-8 JSON document whose value is the enclosing object, read under
Section 2. It is the carrier that the baseline profile requires of publishers
and clients
([profiles Section 3](spec--profiles.md#3-dca-profile-baseline-profile)). A
producer includes in `sealedContent` the ciphertext of every item that the
delivery supplies. The input MUST encode one JSON object.

This document defines no media type, file name, discovery or retrieval
mechanism for the JSON delivery. The publisher's deployment establishes how
its clients obtain the document.

A present `sealedContent` value that is not a non-array object is a structural
failure.

<a id="7-structural-processing"></a>
## 7. Failure scope

A structural failure is delivery-wide unless this document, or the focused
specification that defines the failing member, states a narrower scope. A
failure at a narrower scope (issuer block, map, access group, entry or item)
supplies nothing from that unit and MUST NOT suppress a valid sibling, unless a
focused specification states a wider failure for that unit. A structural
failure releases no key material through the affected scope. Error codes, HTTP
statuses, partial issuer success and retry behavior are outside this
document's scope.

<a id="8-extensions-and-retired-fields"></a>
## 8. Extensions

`periodGeometry` carries both `periodMinutes` and `chainsPerDay` for selected
chain processing; ordinary period-key-only deliveries omit it. The complete
pair and `sealed.chainKeys` form the selected chain extension carrier;
[chain keys Section 12](spec-profile--chain-keys.md#extension-carrier-and-client-relay)
defines chain duties. A period-key-only consumer still uses explicit wrap and
source labels and need not interpret geometry. For a consumer that has not
selected chain relay or processing, `sealed.chainKeys` and `chainsPerDay` have
no chain meaning. The proposed root `renderPeriod`, item `connectors` and
issuer `sealed.contentWindowSeeds` members are
defined by [content groups](spec-profile--content-groups.md) only
when that profile is selected. The reserved `bind` member of
Section 4.1 is defined by content protection Section 4.

## 9. Security considerations

Page input remains untrusted until the applicable authentication and issuer
processing verify the publisher assertion. `resource`, identifier spellings,
`keyId`, ciphertext placement and sealed maps do not grant access. A page-carried
URL supplies no endpoint selection authority.

This format does not authenticate or bind `contentData` to a page location;
[security model Section 8.5](spec--security-model.md#what-opening-proves)
states what each boundary proves.

## 11. Normative References

- [BCP 14](https://www.rfc-editor.org/info/bcp14), incorporating RFC 2119 and
  RFC 8174 requirements-language interpretation.
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html), Base-N Encodings.
- [DCA core protocol](spec--core-protocol.md).
- [DCA content protection](spec--content-protection.md).
- [DCA sealed-key envelopes](spec--sealed-key-envelopes.md).
- [DCA period-key capabilities](spec-profile--period-keys.md).
- [DCA chain keys: construction and delegation](spec-profile--chain-keys.md).
- [DCA HTTPS endpoint binding](spec--http-binding.md).
- [DCA issuer-response binding](spec--response-binding.md).
- [DCA security model](spec--security-model.md).

## 12. Informative References

- [DCA data-format example](design--data-format--example.md).
