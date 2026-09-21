# DCA core protocol

Status: Public Working Draft

## Abstract

This document specifies the transport-independent core of Delegated Content
Access (DCA). A publisher encrypts protected items and delegates opening
authority to issuers. A client uses previously granted capabilities when
possible and otherwise relays publisher material to one issuer. The issuer
authenticates the publisher, authorizes the caller, opens only authorized
material and returns no more capability than its decision permits.

<a id="1-scope-and-requirements-language"></a>
## 1. Introduction

This document defines roles, the signed resource assertion, core unlock
requests and responses, processing order, delegation completeness, failure
classes and extension composition.

It does not define page carriers, content encryption, sealed-envelope
algorithms, period-capability construction, caller authentication, HTTP, CORS,
browser Origin observation or issuer-to-client key protection. Focused
specifications and selected profiles define those mechanisms.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Roles and trust boundaries

### 2.1. Publisher

The publisher creates one protected delivery. It creates or obtains the
content keys, encrypts the items, signs the resource assertion and supplies
each issuer only the opening authority intended for that issuer.

The publisher MUST NOT place a usable plaintext content key or period
capability in the publisher-to-client delivery. Operating an issuer endpoint
does not remove this rule; the publisher is acting in the issuer role at that
boundary.

### 2.2. Client

The client receives untrusted publisher-to-client data. It may use a previously
granted capability whose authenticated scope matches the item. Otherwise it
constructs an unlock request for one issuer.

The client is a relay, not a source of authority. Its selected issuer, member
names, key identifiers, sealed values and extension offers are untrusted
selectors until the applicable issuer processing admits them.

A client MAY verify `resourceJWT` as a local check. Baseline client conformance
does not require that check, and a client that skips it conforms. Such a check
stands beside issuer verification and never replaces it: the issuer verifies the
exact token under the active signing-key entry that its `kid` resolves and that
entry's parent registration, and that verification is what authenticates the
publisher claims.

### 2.3. Issuer

The issuer authenticates the publisher assertion and receives an authenticated
caller principal or an explicit anonymous principal, plus policy context, from
its host environment. It decides which presented coordinates the caller may
receive, then opens only those coordinates.

Signature verification authenticates publisher claims. It does not authorize
the caller. Possession of a sealed value, a `keyId`, an `issuerName` or a
previously unseen member name likewise grants nothing.

## 3. Core sequence

A core unlock proceeds in this order:

1. The publisher emits a conforming protected delivery and signed resource
   assertion.
2. The client tries applicable cached capabilities and identifies unresolved
   items.
3. For one selected issuer, the client constructs one request from that
   issuer's block and only the unresolved items' applicable coordinates.
4. The issuer admits and parses the request once.
5. The issuer checks the wire version and authenticates the publisher assertion.
6. The issuer runs the selected request binding's verified-claim-dependent
   checks.
7. The issuer obtains an authenticated or explicitly anonymous principal and
   policy context from its host boundary.
8. Issuer policy decides among the coordinates the request presented.
9. Only after that decision does the issuer resolve an opening key and open or
   otherwise produce the granted capabilities.
10. The issuer constructs a result containing only successfully produced
   capabilities and permitted per-coordinate failures.
11. The issuer protects and delivers the result under the selected response
    binding. The client admits it and attempts to open the protected item.

An implementation may divide these operations among components, but it MUST
preserve their security-relevant ordering and use one parsed request value
through authentication, policy, key selection and opening.

## 4. Signed resource assertion

### 4.1. Producer form

The publisher MUST produce one compact JWS named `resourceJWT` for each render.
The protected header contains:

| Member | Requirement |
| --- | --- |
| `alg` | Required; exactly `ES256` |
| `typ` | Required producer value; exactly `JWT` |
| `kid` | Required non-empty opaque string |

`resourceJWT` uses ES256 as specified by
[RFC 7518, Section 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4).
The payload is the resource object itself, without a wrapper member. It contains
all of these members:

| Member | Meaning |
| --- | --- |
| `renderId` | Fresh render anchor used by sealed-envelope BIND |
| `origin` | Delivery origin a selected browser binding compares against |
| `issuedAt` | Render timestamp for policy or diagnostics; not an expiry time |
| `resourceId` | Publisher-defined protected-resource identifier |
| `data` | Publisher-defined JSON policy metadata |

These are private DCA claim names, not substitutions for registered JWT claims.
In particular, `issuedAt` is not `iat` and creates no validity window by itself.

`origin` carries the delivery origin that a selected browser binding compares
its observed `Origin` against.
[spec--browser-http-binding.md](spec--browser-http-binding.md) Section 3.2
defines the value's admission and Section 4.3 specifies the point in the
request at which that comparison runs.

For each render, the publisher MUST independently generate `renderId` as 16
uniformly random octets from a cryptographically secure random source and
encode them in the canonical 22-character unpadded base64url form required by
the sealed-envelope specification. It MUST NOT intentionally reuse a
`renderId` or derive it from a resource identifier, timestamp, counter, key or
period coordinate. Freshness is a publisher duty; it does not make `renderId`
an expiry time or an authorization grant.

### 4.2. Verification and registration

An issuer decodes the unverified protected header solely to select a candidate
signing-key entry and its parent publisher registration, and to admit the fixed
header fields. It MUST admit that header in this order.

1. `alg` exactly `ES256` and `typ` exactly `JWT`. The issuer refuses any other
   value at this point, before it looks up a publisher verification key.
2. `kid`, a required non-empty string, resolving exactly one active signing-key
   entry and that entry's parent registration in the issuer's trusted control
   plane. A stable issuer-owned registration contains its policy association,
   opening-key namespace, optional origin limits, extension-material scope and
   a finite, deployment-bounded set of active signing-key entries. A non-empty
   `kid` MUST NOT be active in two registrations. Rotation MAY overlap active
   entries inside one registration without changing those scopes. An unknown,
   ambiguous, inactive or retired `kid` is a whole-request failure before
   signature verification, policy, response-cache lookup, opening-key access
   or extension processing.
3. Verification of the token, as the next paragraph requires.

No other unverified header or payload value has protocol meaning.

The issuer MUST verify the exact compact token under the selected active
signing-key entry before it uses any payload member. A decoded but unverified
payload supplies no policy input, publisher identity, origin or BIND anchor.

An issuer uses JWKS only to retrieve key bytes. Core defines no JWKS URL, cache
or refresh rule, provisioning message, transaction, overlap duration, active-key count,
telemetry field or control-plane encoding. Retrieving key bytes never creates a
registration or assigns, activates or retires its scopes or signing-key entries.

After verification, the issuer MUST require a non-array JSON object containing:

- `renderId`, admitted as required by
  [spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md);
- `origin`, a string admitted under the delivery binding the deployment
  selects, which for a browser binding is
  [spec--browser-http-binding.md](spec--browser-http-binding.md) Section 3.2;
- `issuedAt`, an RFC 3339 date-time string whose offset is `Z`;
- `resourceId`, a non-empty string; and
- `data`, a non-array JSON object whose members are publisher-defined.

A missing or malformed required member is a whole-request failure. The issuer
ignores unknown payload members. It MUST pass only the verified
payload to policy. The readable top-level `resource` member, when present, is
diagnostic and MUST NOT participate in registration lookup, authorization,
BIND, the cache key or partition defined by the selected
[response binding](spec--response-binding.md#9-replay-caching-and-composition) and
[endpoint profile](spec--browser-http-binding.md#34-response), or opening-key
selection.

A readable `resource` mirror that disagrees with the verified claims is not an
error. The issuer never reconciles the two copies and the disagreement changes
nothing it does: the issuer uses the verified payload for every coordinate,
origin and anchor, and the mirror stays page output.

<a id="5-baseline-unlock-request"></a>
## 5. Core unlock request

The client sends one JSON object to one issuer. Common JSON, identifier and
unknown-member handling follows
[spec--data-format.md](spec--data-format.md#2-common-json-rules).

The core request has this structure:

| Member | Type | Requirement |
| --- | --- | --- |
| `version` | string | Required |
| `issuerName` | identifier | Required |
| `resourceJWT` | string | Required; relayed unchanged |
| `keyId` | string | Required non-empty opaque value |
| `sealed` | object | Required |
| `sealed.contentKeys` | object | Required; may be empty beside a non-empty section the receiving issuer selected |
| `sealed.periodKeys` | object | Optional exact-period section |
| `sealed.periodChainKeys` | object | Optional; selected period-chain capability section |
| `periodChain` | object | Optional top-level; selected period-chain geometry context |

`sealed.contentKeys` maps `contentName` to the publisher-supplied sealed value.
`sealed.periodKeys` maps `accessGroup` to a map from `t` to sealed values. A
focused capability specification defines any additional section.

`sealed.periodChainKeys` and `periodChain` are the period-chain extension
members defined by [spec--period-key-chains.md](spec--period-key-chains.md) and placed by
[spec--data-format.md](spec--data-format.md#43-period-chain-extension-members).
A relay client copies them from the selected issuer block and the delivery under
the period-chain rules. An issuer that has not selected period-chain input for
that route treats both as unknown members and ignores them. A request
whose remaining sections are all empty is malformed under the table above; an
otherwise usable exact request is processed as exact-only. Such an issuer
returns no capability when the client supplies only chain members.

An issuer that has not selected exact-period input for that route treats
`sealed.periodKeys` as an unknown member and ignores it. It does not parse the
section's access-group names or period labels. A request whose remaining
sections are all empty is malformed; an otherwise usable direct request is
processed as direct-only.

Before constructing the presented set from `sealed.periodKeys`, an issuer that
has selected exact-period input MUST apply the lexical admission in the exact-
period requirements in
[spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements). An
invalid label is a whole-request structural failure. It MUST NOT reach policy,
BIND construction, envelope opening or a response error coordinate. A selected
period extension defines admission of its own coordinates. For the period-chain
extension that admission is scoped as the data-format and period-chain
specifications define. A family that fails geometry resolution, the
one-member-per-window rule or a member bound yields no capability and no error
entry. A member that fails label admission does the same. Neither failure
makes the request a whole-request failure. For an issuer that has selected the
extension, a `sealed.periodChainKeys` value that is not a non-array object, or
an access-group name in it that fails the identifier rules, is a whole-request
admission failure under the map rule below, like every other request map. The
narrower scopes of
[spec--data-format.md](spec--data-format.md#43-period-chain-extension-members)
apply to the delivery and the issuer block. Finite deployment resource limits
apply to the request as received. Ignored optional members count toward those
limits and may make an exact-only issuer refuse the whole request; they grant
nothing and are never interpreted.

Every named map the issuer processes is a non-array object and applies the
identifier rules of the data-format specification. When exact-period input is
selected, `sealed.periodKeys` is non-empty and each access-group map in it is
non-empty. A conforming client emits every leaf
as a canonical binary string; the applicable envelope or capability
specification constrains its decoded bytes. Issuer leaf type and spelling are
not structural admission checks: they receive the per-coordinate treatment in
Section 7.1 after authorization.

The client MUST copy `version`, `resourceJWT`, `issuerName` and `keyId` from the
selected delivery and issuer block without reinterpreting them. It MUST NOT
combine sealed values from different issuer blocks in one request. It SHOULD
omit coordinates already satisfied by applicable cached capabilities.

For each unresolved item, the client sends the selected issuer's direct sealed
content key when present. It sends a period-capability family only when the
corresponding period profile is selected for that request and the family is an
authored route for one of the item's declared access groups. A client that has
not selected exact-period input does not relay `sealed.periodKeys`; a client
that has not selected period-chain input does not relay the chain members.
Sending both selected routes is permitted; the issuer decides which authorized
capability to return.

At least one direct or selected-profile coordinate MUST be present. An empty
request is a whole-request failure and MUST NOT reach opening-key lookup.

### 5.1. Version

The request `version` is an unsigned syntax selector copied from the delivery.
An issuer MUST compare it exactly with a version it implements before
interpreting version-dependent members or reaching an opening key. Missing,
non-string and unsupported values are whole-request failures. A client claim
that a version is supported grants no capability.

Because this selector is unsigned, an implementation MUST NOT concurrently
admit versions whose authentication, authorization or coordinate meanings
differ unless every affected signed assertion and cryptographic transcript
authenticates or domain-separates the selected version. A new spelling alone
does not create that separation.

Authors need a new `version` when a change alters accepted syntax, the
authenticated transcript, authorization meaning or failure meaning. Clarifying
a v1 rule that was already unambiguous stays a
note inside v1. [spec--data-format.md](spec--data-format.md#2-common-json-rules)
states the same test in format terms.

### 5.2. Optional offers

An optional request member can advertise a client capability. Its presence is
an offer, not a demand and not evidence of authorization. For example,
`clientPublicKey` has no core meaning; only a selected response-binding
profile may interpret it. An issuer without that profile ignores it under the unknown-member
rule and may still use the deployment's selected response binding.

### 5.3. Multiple issuers

One request addresses one issuer block. Requests and results for sibling
issuers are independent. Failure or denial by one issuer MUST NOT grant through,
alter the policy of or suppress a valid attempt to another issuer.

Core item and access-group routes are alternatives: one successfully
obtained content key is sufficient to open the item. No role infers conjunction,
threshold or cross-issuer key combination from several issuer blocks. A profile
that defines such a combination must identify and authenticate it explicitly.

## 6. Issuer processing

### 6.1. Presented coordinates

A presented coordinate is one own member of an admitted key-bearing request
map. The issuer MUST use own-property lookup for every request-selected map and
MUST apply the identifier admission rules before policy.

Request presence grants nothing. The issuer constructs a presented set of
`contentName` coordinates for the direct section and `(accessGroup, t)`
coordinates for a selected exact-period section, plus any coordinates a
selected extension defines.

For the period-chain extension, each admitted family of
`sealed.periodChainKeys` presents its `accessGroup`, and each admitted member
presents its supplied position as the coordinate `(accessGroup, suppliedT)`.
The issuer applies its policy to access groups and supplies the per-group count
defined by
[chain-route `periodCount`](spec--period-key-chains.md#chain-route-periodcount).
Client-carried geometry and labels select which source coordinates the issuer
may open and grant nothing. The coordinates a source member can yield, from its
window start
through its supplied position under the geometry the request resolved, form that
member's admissible result set.

### 6.2. Authentication and policy

Before opening-key lookup or any envelope opening, the issuer MUST:

1. admit the request and enforce finite deployment resource limits;
2. check the version;
3. resolve exactly one active signing-key entry and its parent publisher
   registration from the unverified header `kid`, as Section 4.2 requires;
4. verify and admit the signed resource assertion;
5. complete every pre-policy check required by the request binding the
   deployment selects;
6. obtain an authenticated or explicitly anonymous principal and host-owned
   policy context; and
7. obtain an issuer policy decision over verified publisher claims, issuer
   state and the presented coordinate set.

If an entitlement source times out, is unavailable, refuses to answer or
returns unusable input, the issuer has obtained no policy decision. It MUST
fail closed and return no key material; it MUST NOT substitute a default grant.

The issuer applies policy inside the verified publisher registration, using
the verified origin as its coordinate. It applies its policy only
within the registration whose key verified the assertion, using verified
`resourceJWT.origin` as the origin coordinate. Unsigned `issuerName` and `keyId`
resolve only inside that registration's opening-key namespace, which Section
6.3 requires for key lookup.
The selected policy or profile defines entitlement names, and core defines no
global entitlement namespace, so one entitlement name means whatever the
selected policy says it means. An issuer that also keeps a registered-origin
limit per publisher MAY refuse an origin that registration does not list; that
limit is defense in depth beside the verified-origin comparison, which stays the
check the issuer makes.

The issuer MUST run the binding's verified-claim checks after assertion
verification and before issuer response-cache lookup, policy or
opening-key access. A browser binding, for example, compares the externally
observed Origin with verified `resourceJWT.origin` at this point. The browser
binding specifies the exact comparison and HTTP behavior.

For a core request section, the issuer MUST intersect its policy output with
the presented set. A selected capability extension MUST confine its interpretation of policy
output to admitted, presented source coordinates and the admissible result set
it derives from them. A policy cannot cause a sealed coordinate outside the
presented set to be opened or a capability outside those sets to be returned,
even if the caller would normally be entitled to it. A malformed policy result
is an issuer failure, never a grant.

If the request presents coordinates and the issuer authorizes none under its
policy, it MUST refuse the whole request before opening-key lookup, except when
a selected profile explicitly defines a no-capability core result. The
`dca-v1-not-delivered-result` profile does so when at least one access-group
family is presented: the issuer returns the Section 7.2 `notDelivered` result
for each presented family for which policy delivers no capability, without
opening-key lookup for those families. It omits every denied direct content
coordinate. Partial authorization may continue with only the granted subset;
the issuer omits other denied coordinates and reports no cryptographic failure
for them.

### 6.3. Opening-key scope and BIND

The issuer MUST resolve `issuerName` and `keyId` only within the authenticated
publisher registration. Identical unsigned strings under another publisher
registration select no key here.

For each granted sealed coordinate, the issuer rebuilds BIND from the verified
`renderId` and the exact parsed coordinate it authorized under its policy. The
issuer MUST NOT authorize one label and open under another. Envelope
construction, BIND bytes, algorithm selection and opening failure are defined by
[spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md).

An extension source may produce another representation of an already-granted
capability. The issuer MUST confine that source to the selected coordinates,
and the source MUST NOT gain general access to the issuer opening key. The
period-chain source is such a source: from an opened, authorized chain member
it produces exact leaves or one cutoff state inside that member's admissible
result set, selected by the chain-route rules of
[issuer decision and
response](spec--period-key-chains.md#issuer-decision-and-response). It MUST NOT
produce a coordinate outside that set, in another window or from an absent member.

<a id="7-baseline-issuer-core-result"></a>
## 7. Core issuer result

The issuer core produces this transport-independent semantic document:

```json
{
  "keys": {
    "contentKeys": {}
  }
}
```

`keys` and `keys.contentKeys` are required objects. `keys.periodKeys` is present
only when at least one exact period key is delivered. `errors`, when present,
MUST be a non-empty non-array object. Each member name is an error coordinate,
and each value MUST be a non-array object with a non-empty string `error`
member and an optional string `message` member. Unknown members inside an
error object are ignored. A selected profile may add the top-level `notDelivered`
member of [Section 7.2](#72-not-delivered-access-group-families).

`keys.contentKeys` maps `contentName` to one delivered content key.
`keys.periodKeys` maps `accessGroup` and `t` to delivered exact period keys.
Each core-result leaf is canonical unpadded base64url. A selected response
binding may replace each leaf with its protected carrier before delivery.

When the period-chain response duty is selected, `keys.periodChainKeys` is present
only when at least one chain cutoff is delivered; it maps `accessGroup` and
cutoff label to one delivered chain state at the width the period-chain
profile's canonical construction fixes, as
[spec--period-key-chains.md](spec--period-key-chains.md#canonical-construction)
specifies.
The issuer files the returned chain state under its ordinary canonical
coordinate `t` as the map member's name. There is no separate `cutoffT` field.
Issuer policy selects this returned `t`; the client does not send a cutoff
coordinate. Publisher-supplied
chain input and its `pc` BIND use `suppliedT`, while an exact period-key `p`
BIND continues to use only that exact key's own `t`.
The top-level `periodChain` member is present exactly then and carries a
complete geometry pair for every returned family under the resolution rule of
[spec--period-key-chains.md](spec--period-key-chains.md#windows); the values
that pair resolves to MUST equal the values the request resolved for that
family. The issuer delivers exact leaves projected from chain supply in
`keys.periodKeys`; they carry no marker. A chain family can yield no capability
through admission failure, policy denial or an empty selection, including a
[`periodCount`](spec--period-key-chains.md#chain-route-periodcount) of zero.
The issuer omits that family from `keys` and reports no opening failure for it.
An admitted,
authorized member that cannot be opened follows Section 7.1.

Every delivered capability MUST correspond to a coordinate that was authorized
and successfully produced and that is either a presented core coordinate or a
member of the admissible result set that a selected capability extension
derives from an admitted, presented source coordinate. A response MUST NOT
widen policy reach, return a coordinate outside those sets or expose an issuer
opening key. Host-only policy data MUST NOT appear in the response.

This document does not define a directly sendable response profile. A client
receives the result only through an explicitly selected response binding and
MUST admit that binding before using any key. For a core section it MUST ignore
or reject a delivered coordinate outside the presented set. For a selected
extension it MUST ignore or reject a delivered coordinate outside the
deterministically checkable admissible result set that extension defines. For
a returned chain family it MUST first check that the response's resolved
geometry values equal the values the request resolved for that family; a
family whose values differ has no admissible cutoff. A projected exact leaf
needs no response geometry. The client MUST apply the focused capability
specification before caching reusable authority.

### 7.1. Per-coordinate errors

The issuer may fail one trusted, authorized coordinate and still return its
successful siblings. Its error object contains a stable `error` string and MAY
contain diagnostic `message` text. It contains no key material.

Each core error entry MUST correspond to exactly one admitted request leaf
included in the policy-granted set, and that leaf MUST have produced no
delivered key; a coordinate that an exact member and a chain member share
follows the aggregate-coordinate rule below. A content coordinate is its
`contentName`; an exact-period coordinate is its `(accessGroup, t)` pair.
The coordinate named by an `errors` entry MUST NOT also appear in any `keys`
section in that result. Policy-denied or profile-not-delivered coordinates are
omitted from the core result; they are not reported as opening failures.

A client relays each sealed request leaf as a canonical binary string. An
issuer that encounters a non-string, noncanonical or otherwise malformed leaf
after the request and coordinate are authorized MUST report `unseal_failed` for
that coordinate and MUST NOT decode or open it. That failure does not suppress
successful siblings. Malformed request containers and member names remain
whole-request admission failures.

The error-map key grammar is:

```text
error-coordinate        = contentName / period-error-coordinate
period-error-coordinate = accessGroup "|" t
```

An issuer encodes a period error coordinate only for a `t` the applicable
period-capability specification admits. An empty or malformed `t` and a
group-only spelling such as
`accessGroup "|"` are not core error coordinates. Because `contentName`,
`accessGroup` and admitted `t` exclude `|`, the two forms are unambiguous. The
client treats the key as a coordinate, not free-form diagnostic text.

A supplied chain member that was admitted and authorized but cannot be opened,
or whose opening key is retired, is reported by the issuer at
`accessGroup "|" suppliedT`,
where `suppliedT` is the member's supplied label admitted under the
period-chain profile and excluding `|`. The entry names the
supplied member, not a projected coordinate, and reuses the core error codes.
`accessGroup "|" t` names an aggregate result coordinate. An exact member and a
chain member of one family may share it, and the entry does not identify the
source kind. The issuer emits an opening error at that coordinate only when no
admitted, authorized source sharing it produced a delivered capability and no
key occupies it. When one source succeeded, the issuer omits the error entry for
the other. On a chain-owned period route, [Issuer decision and
response](spec--period-key-chains.md#issuer-decision-and-response) selects exact or
chain for a family, not both; a deployment that selects an exact-and-chain union
defines that union before opening either representation, and this
aggregate-coordinate rule applies to it.

A profile that needs to report policy non-delivery or another decision outcome
defines its representation, selection and client control flow. It MUST NOT encode
that outcome as a malformed core error coordinate or cause a client that did
not select the profile to infer a grant, denial or fallback decision.
[Section 7.2](#72-not-delivered-access-group-families) defines the `notDelivered` member
under that rule.

### 7.2. Not-delivered access-group families

An issuer that selects the `dca-v1-not-delivered-result` profile reports a family
for which it does not deliver a capability by adding one further top-level member to the core
result:

```text
notDelivered = { accessGroup: { reason: <non-empty string>, message: <optional string> } }
```

An issuer that has not selected the profile MUST NOT produce the member.
`notDelivered`, when present, MUST be a non-empty non-array object. Each member name
is an `accessGroup` the associated request presented (Section 6.1), and each
value MUST be a non-array object with a non-empty string `reason` member and an
optional string `message` member. The value contains no key material and names
no `t`. Unknown members inside a `notDelivered` entry are ignored, as inside an
error object. An issuer with no current capability for the `premium` family sends
`"notDelivered": { "premium": { "reason": "no_current_period" } }`.

A client MUST admit only the access groups the associated request presented. A
request presenting `premium` admits `notDelivered.premium`; the client ignores or
rejects `notDelivered.standard` as
[spec--response-binding.md](spec--response-binding.md#3-inputs-and-common-response-form)
requires.

A result that names an access group in `notDelivered` delivers no reusable
period capability for that family: with `notDelivered.premium` present, the
result carries no `keys.periodKeys` entry and no `keys.periodChainKeys` entry
under `premium`.

A direct `keys.contentKeys` entry is instead the result of an independently
authorized `contentName` coordinate. It MAY coexist with
`notDelivered.premium` even when the publisher's delivery also offers a
`premium` period wrap for that content item. The direct key does not become a
capability for the family merely because the client can use either route to
open the same item.

The same result carries no period-coordinate `errors` entry for that family:
no `accessGroup "|" t` coordinate under its name. An error keyed by
`contentName` reports failure of the independent direct coordinate and MAY
coexist with the family report. A per-period-coordinate opening failure belongs
only to a family the result did not name in `notDelivered`.

`notDelivered` is not a core error coordinate and not an opening failure. Section
7.1 fixes the error-map grammar, and this member neither extends that grammar
nor changes what an `errors` entry means.

The top-level name `notDelivered` is reserved. Another profile MUST NOT redefine it.

[spec--profiles.md](spec--profiles.md#8-dca-v1-not-delivered-result-profile)
defines the profile, the role duties it assigns and what an admitted entry means
for a client's route.
[spec--response-binding.md](spec--response-binding.md#3-inputs-and-common-response-form)
defines how a binding carries the member and how a client admits the section.

## 8. Failure model

Core processing distinguishes:

| Class | Scope | Key-material result |
| --- | --- | --- |
| malformed or unsupported request | Whole request | None |
| unauthenticated publisher assertion or unknown, ambiguous, inactive or retired signing `kid` | Whole request | None |
| complete authorization denial | Whole request unless a selected profile defines a no-capability result | None, or the profile-defined result; denied coordinates do not reach opening-key lookup |
| unknown issuer opening key | Whole request | None |
| retired opening key | Per coordinate after a trusted request | `key_retired`; successful siblings may remain |
| envelope/BIND opening failure | Per coordinate after a trusted request | `unseal_failed`; successful siblings may remain |
| chain admission failure | Per family or member, silent | None for it; unrelated members and sections unaffected |
| issuer configuration or internal failure | Whole request | None |

Failure detail MUST NOT turn an untrusted request into a key-existence or policy
oracle beyond what the selected endpoint profile specifies as exposed. HTTP
status, response wording, retry, telemetry and uniform-error profiles are
outside this core specification.

## 9. Delegation completeness

Every publisher delivery MUST contain at least one item in `contentData` and
MUST give every item at least one issuer-mediated opening route permitted by
its [resolved profiles](spec--profiles.md#2-mechanism-selection-states).

A delivery claiming compatibility with a baseline-only client MUST give every
item a direct route: a sealed content-key value for that `contentName` under at
least one conforming usable issuer block. When `dca-v1-exact-period` is
selected, an item MAY instead rely on an exact period route: at least one
content-key wrap under an `(accessGroup, t)` for which a conforming usable
issuer block supplies the matching exact period capability.

When the period-chain profile is additionally selected, its publisher-to-
issuer supply MAY carry positioned chain state from which that same exact leaf
is derivable instead of carrying the exact member. The item's opening path is
still its exact-leaf content-key wrap. Chain supply changes the issuer
capability representation; it does not create a second item-wrap key kind.

A usable issuer block for this core satisfies the data-format requirements for
`issuerName`, `keyId`, `unlockUrl`, `sealed` and the applicable sealed map. Its
`keyId` is non-empty. The route's carried `unlockUrl` or authenticated endpoint
override MUST also be admitted by the selected endpoint profile.

A selected optional profile defines the corresponding evidence for its route.
It MUST end in a capability that opens one of the item's declared content-key
paths and MUST identify the issuers and actor duties required to carry it. For
a chain-supplied period route, that evidence is a chain member in
`sealed.periodChainKeys` of a usable issuer block whose window contains the
item's `(accessGroup, t)` wrap at or below the member's supplied position,
reachable through a request path that selected relay and an issuer selected
for chain input. That structural reach is necessary but not sufficient when
no supplied member reaches the issuer's captured current coordinate:
chain-route selection starts there and cannot jump to an older disconnected
window merely because that window contains the item's wrap. Such an item needs
another complete route. An earlier wrap inside the supplied current window may
remain openable through the returned cutoff's backward reach. This section
defines delegation completeness. The reach a member supplies is defined in
[Capability reach](spec--period-key-chains.md#capability-reach) and the relay path
in [Extension carrier and client relay](spec--period-key-chains.md#extension-carrier-and-client-relay).

This is a publisher authoring and profile-conformance invariant, not a parser's
inference from member names alone. A cached capability can satisfy a later read,
but that authority originated in an earlier issuer grant and does not make the
authored delivery issuerless.

## 10. Extensions and response bindings

An extension or profile MUST define:

- its identifier or unambiguous selection condition;
- its request and response members;
- affected publisher, client and issuer capabilities;
- its authorization and cryptographic reach;
- interaction with baseline routes and fallback;
- malformed, unsupported and partial-failure behavior; and
- conformance evidence for every selected role combination.

An extension MUST NOT reinterpret a base member or cause a base actor to open or
deliver authority beyond both the admitted request and issuer policy. Unknown
extension members remain inert.

Every deployment that returns usable keys MUST select
[a response binding](spec--response-binding.md) that authenticates the issuer
response and protects key confidentiality and integrity. Browser Origin/CORS
enforcement is a separate request/endpoint profile layered on this core;
client-bound key delivery is an optional representation within the response
binding. Neither changes publisher authentication, policy reach or BIND.

## 11. Security considerations

The client controls the unlock request. Therefore unsigned routing and
coordinate fields are selectors only. The issuer authenticates the publisher
by the verified assertion and authorizes the caller by policy; BIND establishes
sealed-value correspondence at the exact authorized coordinate.

The issuer MUST obtain its policy decision before opening-key lookup and before
opening any publisher-supplied envelope, as Section 6.2 requires. Opening first
and denying later has already exercised protected key material for an
unauthenticated or unauthorized request.

Reusable capabilities have the reach defined by their focused specification.
Neither request filtering, `periodCount` nor BIND narrows authority already
delivered to a client. Revocation cannot recover keys or plaintext already
released.

## 12. Composition and dependencies

This specification depends on:

- [spec--data-format.md](spec--data-format.md) for publisher-to-client carriers,
  identifiers and JSON admission;
- [spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md) for envelopes
  and BIND;
- [spec--response-binding.md](spec--response-binding.md) for issuer-to-client
  result protection and admission; and
- [spec--period-keys.md](spec--period-keys.md) when an exact capability profile
  is selected; and
- [spec--period-key-chains.md](spec--period-key-chains.md) when a period-chain
  capability profile is selected.

[spec--content-protection.md](spec--content-protection.md) defines item
encryption, AAD, nonce and content-key wrapping.
[spec--browser-http-binding.md](spec--browser-http-binding.md) defines HTTPS,
observed Origin, CORS, endpoint status and trusted-proxy handling.

## 13. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [RFC 3339: Date and Time on the Internet](https://www.rfc-editor.org/info/rfc3339)
- [RFC 7518: JSON Web Algorithms](https://www.rfc-editor.org/info/rfc7518)
- [DCA data format](spec--data-format.md)
- [DCA sealed key envelopes](spec--sealed-key-envelopes.md)
- [DCA response binding](spec--response-binding.md)
- [DCA exact period-key capabilities](spec--period-keys.md)
- [DCA period-chain construction and delegation](spec--period-key-chains.md)
- [DCA content protection](spec--content-protection.md)
- [DCA browser and HTTP binding](spec--browser-http-binding.md)
- [DCA security model](spec--security-model.md)

## 14. Informative References

This specification has no additional informative references.
