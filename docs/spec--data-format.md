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

The current unreleased version-1 draft requires the named-record collection
grammar in this document. Indexed-map collections from earlier unreleased v1
drafts are incompatible and MUST NOT be accepted as an alternate form. Peers
agree on the draft revision outside the protocol; this rule introduces no new
wire selector. The version-change requirements in
[core Section 5.1](spec--core-protocol.md#51-version) still govern incompatible
changes beyond this unreleased draft transition.

A DCA document, each fixed section and each record defined by this document is
a JSON object, not an array. Each collection is a JSON array of records
(Section 2.3).

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

These identifiers occur as identity fields of collection records
(Section 2.3). A producer MUST emit only values that satisfy this section. When
a consumer processes a collection whose records carry one of these identifiers,
it MUST reject that collection if a record's identifier is missing, is not a
string or violates this section. It MUST NOT ignore the invalid record while
accepting its siblings, except for response `keys.contentKeys`,
`keys.periodKeys` and selected `keys.chainKeys`: these admit identifiers per
record as specified in [response binding Section 3](spec--response-binding.md#3-inputs-and-common-response-form).
The clause that defines a collection states how a consumer treats an element
that is not a non-array object.

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

### 2.3. Collections of named records

A collection holds records of one kind in a JSON array. Each record is a
non-array object that carries its identity and coordinates as named fields,
such as `contentName`, `accessGroup`, `issuerName` or `period`. Array position
carries no identity, coordinate or authority, and no cryptographic input uses
it. Fixed sections, such as `keys`, `sealed` and `periodGeometry`, stay objects.

This distinction describes the protocol schema: an object has fields defined
by its specification; an array holds a collection of entries of the specified
type. Each record is itself an object. Lists of scalar values, such as group
names, retain the element type their defining clause specifies.
Publisher-defined metadata inside `resourceJWT` is not constrained to this
record-collection convention.

Examples place identity and coordinate fields before the carried value to make
records easier to read. JSON object member order has no significance: a
consumer MUST NOT infer identity or uniqueness from the first member. A
collection's definition identifies the fields that together identify a record
or key coordinate and states how repetitions are handled. One field may
suffice, such as `contentName`; key coordinates may require several fields.
An identity field is not a promise that its value occurs only once.

Consumers may iterate records or build internal indexes for lookup. An index
must preserve the collection's repetition rules below; indexing by coordinate
must not overwrite distinct material candidates.

A producer emits a required collection as an array even when it holds no
record, for example `"contentKeys": []`. It omits an optional collection under
that collection's own omission rule and does not emit an empty optional
collection for symmetry.

The clause that defines a collection states how a consumer treats several
records with the same identity. This document and the core protocol use two
rules; a profile that adds a collection states its own:

- **Descriptor and status records:** the consumer uses the last whole record
  for that identity. It does not merge fields from several records, and "last"
  does not mean chronologically newer. Identical records give the same result.
  The consumer admits the identity of every record and the remaining members
  of the selected record only.
- **Material and connector records:** several records at one complete
  coordinate are candidate alternatives. They are not several grants, a
  precedence order or added authority. A consumer keeps distinct candidates and
  MAY drop an identical copy; it does not select the first or last record by
  overwriting a lookup entry.

A consumer counts raw records, before it drops copies or selects a record,
against every limit that applies to the collection.

A repeated record is not a duplicate member name. Section 2 still governs a
JSON object that repeats a member name, including a record that repeats one of
its own fields. A repeated record is an ordinary array element and changes
nothing in that rule.

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

For this profile, consumers MUST use the HTML document parsing and tree
construction rules in [HTML](https://html.spec.whatwg.org/multipage/parsing.html),
with scripting enabled for parsing. In particular, a `noscript` element in the
body is parsed as text rather than as an additional carrier subtree. This
parsing requirement does not require executing scripts.

A producer MUST use inert `script` elements with
`type="application/json"`. It MUST serialize each JSON value so embedded data
cannot terminate or alter the HTML script-data element. Parsing the carrier
MUST recover the value supplied to the serializer, including strings that
contain `<`.

A consumer parses the carrier text as JSON. A missing or non-object `dca-data`
value is a structural failure. A present `dca-sealed-content` value that is not
an array is a structural failure.

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
| `contentData` | array | Required item collection |
| `issuerData` | array | Required non-empty issuer collection |
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
`version` exactly `"1"`, `resourceJWT` a string, `contentData` an array and
`issuerData` a non-empty array. A present `resource` MUST
be a non-array object. Failure of an outer requirement is a delivery-wide
structural failure. A consumer MUST complete an item record's or issuer
block's admission before deriving a request from it or using its key or
ciphertext material.

### 4.1. `contentData`

`contentData` is a collection of item records. Each record is a non-array
object with these members:

| Member | Type | Requirement |
| --- | --- | --- |
| `contentName` | string | Required item identity |
| `contentType` | string | Required content-handling metadata |
| `contentEncodings` | array of strings | Optional ordered representation layers |
| `keys` | array | Optional cached-wrap collection |

A publisher emits one record per `contentName`. When several records carry one
`contentName`, the consumer uses the last whole record for that item
(Section 2.3). An element that is not a non-array object names no item: the
consumer skips it, and its siblings stay usable. A record whose `contentName`
is missing, is not a string or is not a valid `contentName` rejects the
collection (Section 2.1).

[spec--content-protection.md](spec--content-protection.md) defines content
encryption, nonce sizes, the content AAD built from the delivery, the wrap
nonce derived from each wrap entry's context and unwrap processing.

A producer MUST omit `aad` and `nonce` from an item record. A consumer MUST
ignore either carried item member under the unknown-member rule, regardless
of its type. Neither member selects an AAD, nonce procedure or legacy retry.
The same holds for wrap entries below: a producer MUST omit `nonce` from a
wrap entry, and a consumer MUST ignore a carried one under the unknown-member
rule, regardless of its type or value
([content protection Section 4.1](spec--content-protection.md#41-wrap-nonce)).

If `keys` is absent, the item offers no period-key-wrap candidates. If present, it
MUST be a non-empty array of wrap entries. Each wrap entry MUST be a non-array
object with an `accessGroup` identifier and string members `period` and `key`.
Several entries at one `(accessGroup, period)` are candidate alternatives
(Section 2.3). An own `bind` member on such an entry is reserved;
[content protection Section 4](spec--content-protection.md#4-base-period-key-content-key-wrapping)
defines its effect. A carried `nonce` member is an unknown member and does not
affect admission.

When no record names an item, the publisher declared no such protected item.
A missing or malformed required `contentType`
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

A present malformed `keys` container, including an empty array, or a `keys`
collection rejected under Section 2.1, supplies no period-key-wrap candidates
for that item; an otherwise valid issuer-mediated item content-key alternative
remains. Within an admitted `keys` collection, an element that is not a
non-array object, or an entry without string `period` and `key` members,
supplies no candidate.

An empty `contentData` array is structurally valid at this layer. The core
protocol requires at least one protected item. A producer MUST NOT emit an
empty inventory unless its selected profile defines its meaning.

At this structural layer, `period` is an opaque string; the period-key
specification owns its grammar and calls the label `t`. The `key` member is a
content-key wrap under the period key at that `(accessGroup, t)`; content
protection Section 4 defines it, including the nonce that publisher and client
derive for it.

### 4.2. `issuerData`

`issuerData` is a collection of issuer blocks. A producer MUST emit each block
as a non-array object containing:

| Member | Type | Requirement |
| --- | --- | --- |
| `issuerName` | string | Required issuer identity |
| `keyId` | string | Required |
| `envelope` | string | Optional procedure selector; [compact ECDH profile](spec-profile--compact-ecdh.md#3-wire-selector-and-client-relay) |
| `sealed` | object | Required |
| `sealed.chainKeys` | array | Optional extension member; chain keys Section 12.1 |

If present, `sealed.contentKeys` is a collection of records
`{contentName, key}` whose `key` is a sealed binary string. If present,
`sealed.periodKeys` is a collection of records `{accessGroup, period, key}`
whose `period` is the label `t` and whose `key` is a sealed binary string.

A publisher emits one block per `issuerName`. When several blocks carry one
`issuerName`, the consumer uses the last whole block (Section 2.3). It MUST
NOT combine one block's `keyId` or `envelope` with another block's sealed
material. An element that is not a non-array object names no issuer: the
consumer skips it, and its siblings stay usable. A block whose `issuerName` is
missing, is not a string or is not a valid `issuerName` rejects the collection
(Section 2.1).

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

If present, `sealed.contentKeys` and `sealed.periodKeys` MUST be arrays. The
consumer admits their identity fields under Section 2.1 before relaying their
records. A malformed or rejected sealed-key collection supplies no candidates
of that kind; an element that is not a non-array object, or a
`sealed.periodKeys` record without a string `period`, supplies no candidate;
an invalid sealed `key` supplies no candidate at its coordinate. Several
records at one coordinate are candidate alternatives (Section 2.3), and a
client relays each one it selects. A client applies these scopes before
constructing its issuer request.

If no usable issuer-mediated key-acquisition alternative remains for the
requested item and no applicable cached capability opens it, opening fails.

## 5. Sealed-content carrier

The optional `dca-sealed-content` value is a collection of records
`{contentName, content}` whose `content` is a ciphertext binary string.

An item declared by `contentData` may have no record in this collection; its
ciphertext is then absent from this delivery, and this document defines no
retrieval mechanism.

A publisher emits one record per `contentName`. When several records carry one
`contentName`, the consumer uses the last whole record (Section 2.3). A
grammar-valid record not declared by `contentData` is ignored by the core
client. The consumer rejects the entire enclosing delivery when a record's own
`contentName` is missing, is not a string or violates Section 2.1. This scope
applies to both markup and object deliveries. An element
that is not a non-array object names no item; the consumer skips it, and its siblings
stay usable. A missing record, a `content` value that is not a string, or a string
that is not canonical base64url supplies no ciphertext for that item.

## 6. Object delivery

An object or API delivery uses the `dca-data` members in one enclosing JSON
object and adds:

| Member | Type | Requirement |
| --- | --- | --- |
| `sealedContent` | array | Optional; same collection as `dca-sealed-content` |

An object reader obtains ciphertext from the `sealedContent` record that names
the item; a markup reader obtains it from the separate carrier.
All other member names, types and
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

A present `sealedContent` value that is not an array is a structural failure.

<a id="7-structural-processing"></a>
## 7. Failure scope

A structural failure is delivery-wide unless this document, or the focused
specification that defines the failing member, states a narrower scope. A
failure at a narrower scope (issuer block, collection, access group, record or item)
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
`keyId`, ciphertext placement, sealed collections and array positions do not
grant access. A page-carried URL supplies no endpoint selection authority.

This format does not authenticate or bind `contentData` to a page location;
[security model Section 8.5](spec--security-model.md#what-opening-proves)
states what each boundary proves.

## 11. Normative References

- [BCP 14](https://www.rfc-editor.org/info/bcp14), incorporating RFC 2119 and
  RFC 8174 requirements-language interpretation.
- [HTML](https://html.spec.whatwg.org/multipage/), document parsing and tree construction.
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
