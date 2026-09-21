# Proposal: detached key supply

Status: Proposal
Target: [spec--core-protocol.md Section 3](spec--core-protocol.md#3-core-sequence); [spec--response-binding.md Section 3](spec--response-binding.md#3-inputs-and-common-response-form); [spec--browser-http-binding.md](spec--browser-http-binding.md)

This document has no protocol authority. If the editors accept it, they move
its text into the targets; if they decline it, they remove this file.

## Introduction

This proposal moves the exact `resourceJWT` and issuer blocks into a sidecar
that the client fetches and relays, and adds one-issuer batching for direct
content-key requests. DCA does neither today. The publisher instead puts
`resourceJWT` and a non-empty `issuerData` map in the delivery. The client sends
one request to one issuer, and the issuer returns one response for that request.
The sidecar and batch must preserve issuer decisions, coordinate checks and
BIND (binding). They still need their own batch request and response contract.

## Motivation

Page budget: a publisher may want to keep large issuer material out of every
render. The client can then fetch it only when the material already in the page
does not cover the content it is about to open. DCA currently defines no
sidecar, cache rule or fetch behavior for this.

Requests: batching could reduce repeated calls to the same issuer. The proposal
must still show that batching is useful and define its request and result
semantics.

## Specification

## 1. Change
Lands in: [spec--core-protocol.md Section 3](spec--core-protocol.md#3-core-sequence), [spec--data-format.md Section 4.2](spec--data-format.md#42-issuerdata)

[Data-format Section 4](spec--data-format.md#4-the-dca-data-object) currently
requires the publisher to include a string `resourceJWT` and a non-empty
`issuerData` map in every delivery. Section 4.2 places the issuer blocks, and
the core protocol requires the client to relay the selected values unchanged
in one request. It defines no sidecar.

This proposal puts the exact `resourceJWT` and issuer blocks in the sidecar,
while the delivery keeps the item inventory and ciphertext coordinates. The
client relays the selected sidecar material, so the issuer still does not call
the publisher during an unlock. The publisher still supplies one envelope per
key. Because the base format requires the two inline members, the extension
must say whether it replaces or supplements them.

Decision needed: does the sidecar replace or supplement the delivery's required
`resourceJWT` and `issuerData`, and what is the required behavior when it is
missing or unavailable?

## 2. Pointer
Lands in: [spec--data-format.md Section 4](spec--data-format.md#4-the-dca-data-object)

The current delivery has no sidecar locator. This proposal adds one but leaves
its placement and grammar open. If the delivery retains `resourceJWT`, the
client can match the sidecar by comparing the two compact strings octet for
octet without decoding them. If the sidecar replaces the inline value, the
extension needs another way to match it to the delivery. In either case, it
must define which serialization the client compares and how it handles
duplicate members. The
locator only tells the client where to fetch; changing it must not make the
issuer authorize an unsigned coordinate.

Detached content needs the same locator and fetch layer. The two proposals have
not yet chosen a shared member shape, HTTPS behavior, media type, authorization,
size or freshness limits, cache policy or failure scope. DCA also does not yet
require compact-string equality when matching a sidecar to a delivery.

Decision needed: where does the publisher put the locator, and how does the
client verify that the fetched sidecar belongs to this delivery?

## 3. Sidecar
Lands in: [spec--data-format.md Section 6](spec--data-format.md#6-object-delivery)

The sidecar is an extension object, not another `dca-data` delivery. It carries
`version`, the exact `resourceJWT` and issuer blocks in the
[Section 4.2](spec--data-format.md#42-issuerdata) shape. The proposal still
needs a complete object grammar, duplicate-member rules and a compatibility
rule for `dca-data`. The sidecar adds no content name or access group, and the
client ignores any coordinate that the delivery does not declare.

Without batching, the client still selects one issuer block per request, never
combines sealed values from different blocks, and presents only that request's
coordinates. The sidecar must preserve those rules unless another extension
explicitly replaces them.

Decision needed: which members may appear in a sidecar, and may it introduce
issuer routes for an already declared item or only carry routes already named
by the delivery?

## 4. Batch
Lands in: [spec--core-protocol.md Section 5](spec--core-protocol.md#5-baseline-unlock-request), [spec--browser-http-binding.md Section 3](spec--browser-http-binding.md#3-dca-https-json)

The core protocol and response binding define one request and one response.
They do not define a batch wrapper or connect a batch member to an issuer
result. The browser profile likewise defines one POST. Its observed-Origin
rule applies only to that browser profile, not to every DCA caller.

The first batch form carries only direct content-key requests and returns exact
content keys. Every member addresses one issuer. Under the browser profile,
every verified `resourceJWT.origin` must equal the one observed and admitted
origin. Render-local content names remain separate. Still open: the request
grammar, how replies identify members, whether one member may fail alone,
aggregate limits, issuer counters and malformed-member handling.

Decision needed: how does each reply identify its request, and what happens
when one batch member is malformed?

## 5. Verification
Lands in: [spec--core-protocol.md Section 6.2](spec--core-protocol.md#62-authentication-and-policy), [spec--core-protocol.md Section 6.3](spec--core-protocol.md#63-opening-key-scope-and-bind)

The issuer verifies the signed assertion before it checks policy or opens a
publisher envelope. It intersects policy with the presented set and rebuilds
BIND from the verified `renderId` and exact policy coordinate. Fetching or
relaying a sidecar or batch does not turn its fields into verified claims.

The issuer must apply those checks to every request and coordinate in an
extension. Moving envelope bytes into a sidecar must not widen what the client
presents or what the issuer authorizes under its policy. This proposal keeps
the existing envelope BIND; moving an envelope does not by itself require a new
BIND version. The sidecar may still need a separate way to match the sidecar to
the delivery.

## 6. Evidence
Lands in: undecided

`js/v1/experiments/` holds no detached-key-supply experiment, so no executable
evidence is attached. Once the sidecar and batch contracts are defined, tests
must cover how clients match and validate them, show that an
unsigned coordinate grants nothing, connect each request to its result, and
enforce resource limits.

## 7. Results

Pending.
