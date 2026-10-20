# Content description and placement

Status: Proposal

## Abstract

Protected content can be a fragment of a larger document or independently useful data. This
proposal separates the information needed to interpret opened content from the instructions for
placing it. It defines an optional versioned item description and its handoff to a consumer, while
the HTML content-map proposal defines placement. These candidate additions preserve the required
item media type and do not change content protection.

## 1. Purpose

A media type alone supplies neither the context nor the schema a consumer may need: `bodytext` needs
its article and a destination, while a JSON dataset needs an agreed data contract and no placement.
This proposal adds an optional description for application meaning and leaves placement to the [HTML
content-map proposal](spec-proposal--html-content-map.md).

## 2. Separate information

Representation, application meaning, placement and context are separate information ([browser
integration guide](guide--browser-integration.md#what-travels-and-what-stays-local)). An ordinary
article seals its HTML fragment and takes its destination from the integrator's setup, with no
wrapper and no map. An application may instead seal a JSON wrapper of metadata and content under its
own schema; DCA gives that inner schema no shared meaning, and its metadata is readable only after
opening.

The delivery carrier says how the delivery is serialized; it does not say that every item contains
HTML or JSON. The optional `contentEncodings` member lists representation transforms. After
authenticated opening and successful inverse transforms, the consumer still needs the item's media
type and any application agreement. Strict UTF-8 conversion produces text; it establishes neither
HTML meaning nor a safe rendering policy.

## 3. Required item type; optional description

Every `contentData` item keeps its required `contentType` ([data format Section
4.1](spec--data-format.md#41-contentdata)); a description, placement map or host configuration never
replaces it. No new baseline description or placement support is required.

### Description format

The candidate member is `contentData[contentName].contentDescription`. It is optional
for every item, including a mapped item. Omission means no supplied description;
it does not mean an unknown media type. A description-aware consumer selects this
contract through its application configuration, independently of HTML placement.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document are to be
interpreted as described in BCP 14 when, and only when, they appear in all capitals.

A producer selecting this contract MUST emit a non-array object with exactly the
following members. The common JSON and own-member rules of the data format apply,
including its duplicate-member rule; descriptions add no second JSON parser policy.

| Member | Grammar and meaning |
| --- | --- |
| `version` | Required string `"1"`; versions the description grammar and semantics independently of the delivery and the described schema. |
| `schema` | Optional non-empty Unicode scalar string; an opaque identifier for one immutable application schema contract. |
| `description` | Optional non-empty Unicode string, interpreted as plain text. It is explanatory metadata, never markup or executable instructions. |

At least one of `schema` and `description` MUST be present. `null`, an empty object,
unknown members and wrong member types are malformed. `contentType` and
`contentEncodings` MUST NOT appear inside a description. A future description
grammar uses another version; changing an application schema's meaning requires
another schema identifier. Consumers compare schema identifiers exactly as strings,
without trimming, Unicode normalization, percent decoding, case folding or relative
resolution, and MUST NOT infer compatibility from version-looking substrings. A
human description may change without changing the schema contract.

Producers SHOULD choose stable namespaced identifiers, such as URNs or HTTPS URIs,
to avoid collisions between independently authored contracts. Consumers treat the
identifier as opaque and MUST NOT require URI syntax. A URI-shaped identifier
establishes no compatibility beyond an exact registry match.

`schema` identifies the application contract, not a decoder, validator module or
fetch instruction. A consumer resolves it through a trusted, locally configured
registry or a separately established application agreement. The registry states
the schema language and validation behavior, including any required custom rules.
The consumer MUST NOT retrieve or execute anything solely because the delivery
names it. Using an HTTPS URI does not change that rule. For JSON Schema, the
registered schema's dialect and exact referenced schemas form part of that contract.

### Admission and handler handoff

A description-aware consumer MUST enforce and disclose finite limits for description
size and schema-identifier length. The limits are implementation or deployment
choices; peers relying on descriptive support must agree on sufficient limits.
Exceeding a limit is a description failure, never truncation. Count string limits
in Unicode code points and serialized-input limits in UTF-8 octets; a native-object
adapter applies the same string limits and bounds traversal before copying values.

For a selected item, description admission produces exactly one of `absent`,
`available`, `unsupported` or `invalid`. `available` carries the admitted description.
An absent member produces `absent`. Otherwise the consumer first checks that the
value is an object within its limits and has a string `version`; failure produces
`invalid`. An unknown string version then produces `unsupported` without applying
the version-1 member grammar. For version `"1"` only, the consumer checks the exact
grammar above and returns `invalid` or `available`. Thus a bounded object such as
`{"version":"2","newField":true}` is unsupported, not a version-1 unknown-field error.
Only version `"1"` is interpreted by this contract.
These are local handler-handoff states, not issuer results or delivery members.

The consumer supplies the handler with the `contentName`, authoritative `contentType`,
successfully opened and inverse-transformed bytes (or the handler's agreed decoded
value), and the separate description result. It MUST NOT silently strip a malformed
description and present it as `absent`. Before opening, it MAY expose admitted public
metadata separately; metadata admission does not assert content validity or access.

An application handler declares whether it requires a schema and which exact schema
identifiers it supports. A required schema that is absent, unknown, unsupported or
invalid prevents that handler's interpretation of the item; it MUST NOT guess a
schema or report successful validation. Failure is item-local. A handler configured
to consume the media type without a description MAY continue with that explicit
contract, including when the description result is `invalid` or `unsupported`.
An HTML map consumes `contentType` and needs no description support. A baseline
client that does not select descriptions ignores the member under the data format's
unknown-member rules.

### Proposed wire example

One `contentData` item, `measurements`, with the proposed member; the rest of the delivery follows
the current data format.

```json
{
  "contentType": "application/json",
  "contentDescription": {
    "version": "1",
    "schema": "urn:example:measurements:v1",
    "description": "Daily temperature observations in degrees Celsius."
  },
  "contentEncodings": ["gzip"]
}
```

The gzip item needs an intended client that implements the selected
[`dca-profile-content-compression`](spec--profiles.md#6-dca-profile-content-compression-profile)
client duties. Baseline support for processing the encoding list does not require
support for a named transform. After admitting the list, the client opens the
item and reverses the transforms; the handler parses the resulting JSON and
interprets it under the agreed application schema. This example adds no decoder
operation.

### Bounded structured-data support

Evidence for adoption covers ordinary HTML, one JSON document and NDJSON
records. Representation and record framing belong to the declared media type;
record fields, units, discriminators and nested encodings belong to the agreed
application schema. Do not introduce a generic decoder-expression pipeline or a recursive DCA type
system. A plain-text description alone is valid, so no party implements a schema language only to
support descriptions, and a consumer that ignores the member under unknown-member rules has not
established application-level compatibility.

## 4. Placement proposal relationship

The [HTML content-map proposal](spec-proposal--html-content-map.md) defines placement as an
optional delivery-level `contentMap`: a declarative placement recipe alongside
`contentData` in the existing `script.dca-data` JSON value, versioned and selected
independently of descriptions. It reads
each item's `contentType` and needs no description; a description-only consumer needs no map, HTML
document or dummy target. The issuer receives neither addition.

## 5. Security considerations

A description or destination grants no access and authorizes no execution of opened content;
consumers apply their own interpretation and rendering policy. Descriptions are public: they sit outside ciphertext
and content AAD, so successful opening authenticates neither the description nor placement
([content protection Section
7](spec--content-protection.md#7-deferred-ciphertext-and-content-handling)), and it does not
establish publisher provenance ([what opening proves](spec--security-model.md#what-opening-proves)).
A handler relying on a schema MUST select its allowed schema contracts through trusted configuration
and apply its source-provenance policy before acting on the description; the description alone
cannot authorize code, a key request or a new trust relationship. Sensitive application metadata
belongs inside protected content; authenticated portable descriptions would need a separately
specified binding.

## 6. Integrity and adoption boundary

The grammar, selection, handoff and integrity choices above are fixed for the
next candidate implementation. The optional addition is not yet an operative
DCA v1 wire or runtime requirement; independent consumer evidence and
specification adoption remain necessary. Publication for feedback does not
make the new member operative.

### 6.1. Specification changes if adopted

The adoption edit specifies these changes together:

| Destination | Change on adoption |
| --- | --- |
| [Data format](spec--data-format.md), Sections 4.1 and 7 | Define `contentDescription`, its exact grammar, omission and malformed-input behavior. Preserve required `contentType` as the authoritative media type; the description cannot override it. |
| [Content protection](spec--content-protection.md), Sections 5.1 and 7 | State description admission/handling and the interpretation boundary from Sections 3 and 6; no change to authenticated content or AAD. |
| [Profiles](spec--profiles.md), affected publisher/client duties and any selected optional composition | Record optional description-aware publisher/consumer support and its item-local evidence. This metadata adds no separate complete profile or baseline support duty. A selecting application composition states its required schemas. |
| [Browser integration](spec-proposal--browser-integration.md), content-handler contract | Define how descriptions reach handlers and how handlers that require an unsupported schema respond. Keep decoded content values and descriptive information distinguishable. |
| [HTML content-map proposal](spec-proposal--html-content-map.md) | Reconcile description and placement responsibilities and forbid competing authoritative media types. Description adoption alone does not adopt HTML reconstruction or create a second map. |
| This proposal, design explanation and integration guide | Replace open contract questions with the selected rules and rationale, or retain this file as historical proposal evidence. Use consistent ordinary-markup and structured-data examples. |

Producers, consumers and discriminating admission and handling tests change together.

## 7. References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [Content protection](spec--content-protection.md): current item requirements.
- [Data format](spec--data-format.md): item members, including `contentType` and `contentEncodings`.
- [Profiles](spec--profiles.md): baseline and optional composition.
- [HTML content-map proposal](spec-proposal--html-content-map.md): reconstruction candidate.
- [Browser integration](spec-proposal--browser-integration.md): content-handler handoff.
- [Browser integration guide](guide--browser-integration.md): publisher-configured consumption.
