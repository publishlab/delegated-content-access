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
The [overview glossary](spec---overview.md#terms-across-the-specifications)
distinguishes the binding names used across these documents.

It does not define delivery carriers, content encryption, sealed-envelope
algorithms, period-capability construction, caller authentication, HTTP, CORS,
browser Origin observation or issuer-to-client key protection. Focused
specifications and selected profiles define those mechanisms.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD** and **MAY** in
this document are to be interpreted as described in BCP 14 when, and only when,
they appear in all capitals.

## 2. Roles and trust boundaries

### 2.1. Publisher

The publisher creates one protected delivery. It creates or obtains the
content keys, encrypts the items, signs the resource assertion and supplies
each issuer only the opening authority intended for that issuer.

For items selected for period-key access, the publisher assigns access groups
before sealing under
[period-key Section 6.1](spec-profile--period-keys.md#61-assigning-access-groups-before-sealing).
That per-item assignment is distinct from the per-issuer supply selection below.

For each issuer block in a delivery, the publisher MUST select which authored
`contentName` values receive a sealed item `contentKey` and which authored
`accessGroup` values receive period-key capability material before sealing the
block. It MUST seal item `contentKey` values only for the selected content
names and period-key capabilities only for the selected access groups. A
selection that names a content name or access group absent from the delivery
is invalid; the publisher MUST reject it. The publisher MUST have an explicit
selection for each issuer block; an absent selection MUST NOT default to every
`contentName` or `accessGroup`. An explicitly empty selection of one kind
supplies no capability of that kind.

Issuer-name or key-ID aliases whose opening-key entries resolve to the same
private key are one cryptographic entrustment domain. Every holder of that
private key can open the aggregate material sealed to it under any alias;
`issuerName`, `keyId` and the per-block selections above do not partition that
reach. A publisher that intends separate opening authority MUST use distinct
opening keypairs. See the [security model's opening-key trust
boundary](spec--security-model.md#enforcement-boundary).

A supplied period-key capability reaches every item the publisher wrapped
under that `accessGroup`, whatever that item's `contentKey` selections.

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

### 2.2.1. Logical client contexts and pending work

A logical client context is one host-selected isolation domain whose members
are mutually trusted to use its granted keys and opened content. It is not
necessarily a browser, process, issuer or reader identity. A host may run
several independently live contexts at once.

Each pending operation MUST remain associated with the logical client context
and publisher delivery captured when it began, through response admission,
key retention, content opening and delivery of its result. Changing a host's
current-client reference MUST NOT reassign that operation or its result to a
different context. This applies to item content keys and plaintext as well as
to reusable period or chain keys.

Before a successor context uses a shared presenter or other output target, the
host MUST end the predecessor's eligibility for that target. The component
that performs a presentation or other output side effect MUST check the
captured context's continuing eligibility at that side-effect boundary,
after any preceding asynchronous work.

Retained capabilities MUST NOT become eligible to a mutually untrusted
successor merely because it reuses a host, storage backend or output target.
Hosts MUST isolate such contexts' retention domains, including writes that
finish after a context ends. A cache partition still writable by old pending
work MUST NOT be reused for a mutually untrusted successor. Ending one context
MUST NOT implicitly end another independently live context.

The host owns context selection, lifetime and the association of its session
integration with affected contexts; the client implementation owns preserving
the operation's captured context and delivery. Ending a context changes
honest-client eligibility; it does not revoke keys or plaintext already
delivered.

The proposed optional [browser-integration contract](spec-proposal--browser-integration.md) is
one candidate way to coordinate these duties; evaluating it does not replace or weaken
them.

### 2.3. Issuer

The issuer authenticates the publisher assertion and receives an authenticated
caller principal or an explicit anonymous principal, plus policy context, from
its host environment. It decides which presented coordinates the caller may
receive, then opens only those coordinates.

Signature verification authenticates publisher claims. It does not authorize
the caller. Possession of a sealed value, a `keyId`, an `issuerName`, a
previously unseen member name or an array position likewise grants nothing.

### 2.4. Obtaining and delivering keys

This document and the focused specifications keep three choices apart. A
sentence about one of them says nothing about the other two.

A client obtains an item's content key in one of two ways. It **receives the
item's content key from an issuer** when the publisher sealed that `contentKey`
for the issuer and the issuer grants its `contentName`. Or it **unwraps the
item's content key with a period key** when the item carries a
publisher-authored wrap under an `(accessGroup, t)` whose period key the client
already holds, receives from an issuer, or derives from a returned chain key.
The publisher authors these as an **item content-key alternative** and
**period-key-wrap alternatives** for the item. Neither is an HTTP endpoint or
URL; one issuer endpoint can serve both. Section 9 calls an alternative,
together with a usable issuer block and the duties that deliver its key, an
issuer-mediated opening route; "route" there names that completeness chain, not an
endpoint. Each yields the same content key, and one obtained content key is
sufficient to decrypt the item.

The issuer independently chooses item content keys, period capability, or both,
within the presented usable publisher material and its authorization policy.
That grant choice does not prescribe how the client opens an item. The client
can use any applicable capability it holds, including a matching key retained
in its storage, under the scope and admission rules of its selected profiles.
The issuer need not return a new period key for a client that already holds
one. Refusing a new grant does not revoke an earlier key or prevent it opening
matching retained ciphertext.

**Period-key construction** is how the publisher produced a period key's
bytes: independently generated for its coordinate, chain-derived under the
[chain-key profile](spec-profile--chain-keys.md), or another selected
construction. A period key has the same use and reach whichever construction
produced it.

**Transport mode** is how one issuer response carries each authorized key:
**direct transport mode** or **client-bound transport mode**, as
[spec--response-binding.md](spec--response-binding.md#2-layered-security-model)
defines.

## 3. Core sequence

A core unlock proceeds in this order:

1. The publisher emits a conforming protected delivery and signed resource
   assertion (Sections 2.1 and 4.1).
2. The client tries applicable cached capabilities and identifies unresolved
   items.
3. For one selected issuer, the client constructs one request from that
   issuer's block and only the unresolved items' applicable coordinates
   (Section 5).
4. The issuer admits, authenticates and decides as Section 6.2 requires; only
   then does it resolve an opening key and produce the granted capabilities
   (Section 6.3).
5. The issuer constructs the result (Section 7) and delivers it under the
   selected response binding. The client admits it and attempts to open the
   protected item.

## 4. Signed resource assertion

<a id="41-producer-form"></a>
### 4.1. Resource assertion format

The publisher MUST produce one resource assertion, `resourceJWT`, for each
render, and each delivery carries exactly one. A separately emitted copy of
the render MAY carry another valid signature over the identical header and
payload segments; changing either segment makes a new render
([content protection Section 7](spec--content-protection.md#7-deferred-ciphertext-and-content-handling)).
It is a JWS in compact serialization [RFC 7515, Section 3.1] signed
with ES256 [RFC 7518, Section 3.4]. Each of its three segments MUST be
unpadded base64url with no whitespace or other non-alphabet characters, and
its unused trailing bits MUST be zero [RFC 4648, Section 3.5]. The issuer
refuses any other spelling before it looks up a key (Section 4.2).

Protected header:

- `alg`: REQUIRED. Exactly `"ES256"`.
- `typ`: REQUIRED. Exactly `"JWT"`.
- `kid`: REQUIRED. Non-empty opaque string; selects one signing-key entry
  (Section 4.2).

Payload: a JSON object whose members are the resource object itself, with no
wrapper member. The names are private DCA claims, not registered JWT claims.

- `renderId`: REQUIRED. Fresh render anchor: 16 uniformly random octets in
  the canonical 22-character unpadded base64url form
  ([envelopes Section 3.2](spec--sealed-key-envelopes.md#32-canonical-encoding)).
  For each render the publisher MUST draw the octets from a cryptographically
  secure random source, and MUST NOT intentionally reuse a value or derive it
  from a resource identifier, time, a counter, a key or a period coordinate.
  BIND ([envelopes Section 3](spec--sealed-key-envelopes.md#3-bind)) commits
  every sealed-key envelope to this value, so a reused `renderId` lets an
  envelope sealed for one render open in another. Freshness is a publisher
  duty; it makes `renderId` neither an expiry time nor an authorization grant.
- `origin`: REQUIRED. String. The publisher context origin, admitted under the
  selected delivery binding
  ([HTTPS endpoint binding Section 3.2](spec--http-binding.md#32-canonical-signed-origin)).
  Under `dca-profile-browser-origin` it is the calling page's origin that the
  issuer compares with the observed `Origin` header; the origin a delivery
  document was fetched from or stored at does not change it. For non-browser
  use, the signed value remains publisher context and supplies no
  calling-page-origin guarantee.
- `issuedAt`: REQUIRED. Render timestamp for policy or diagnostics, an RFC 3339
  date-time with offset `Z`, for example `2025-10-23T14:00:00.000Z`.
  Fractional seconds and lower-case `t` and `z` are permitted under RFC 3339
  Section 5.6; numeric offsets are not used. It is not `iat` and creates no validity window.
- `resourceId`: REQUIRED. Publisher-defined identifier of the protected
  resource: a non-empty string of Unicode scalar values, used as written
  without normalization or case folding. Any scalar value, including `|`, is
  permitted.
- `data`: REQUIRED. Non-array JSON object of publisher-defined policy metadata.

### 4.2. Verification and registration

Before selecting a signing-key entry, an issuer MUST admit the compact token's
three segments under Section 4.1's base64url rules, including zero unused
trailing bits. Noncanonical spelling is a whole-request refusal; the issuer
MUST NOT repair or normalize a segment before verification. RFC 4648 leaves
this check optional for decoders; DCA requires it.

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

No other unverified header or payload value has protocol meaning at the issuer.
The client separately decodes and admits `renderId` as a local content-opening
label under [content protection Section 3.2](spec--content-protection.md#32-content-aad).
That label and the item name enter content AAD; decoding authenticates no
claim, and the content tag does not bind other JWT claims. Cached opening may
proceed without an issuer call. Every issuer request still requires the
verification and authorization below.

The issuer MUST verify the exact compact token under the selected active
signing-key entry before it uses any payload member. A decoded but unverified
payload supplies no policy input, publisher identity, origin or BIND anchor.

Retrieving key bytes, for example from a JWKS, never creates a registration or
assigns, activates or retires its scopes or signing-key entries.

After verification the issuer MUST require a non-array JSON object whose
members satisfy Section 4.1; a missing or malformed member is a whole-request
failure. The issuer MUST reject a verified `resourceId` with an unpaired
surrogate rather than replace or normalize it. This restriction does not apply
generally to publisher-defined content JSON.

Publisher-specific schemas and size or nesting-depth limits for `data` are
product policy, not DCA core requirements. They do not relax the required
JSON-object shape or verified-payload rule.

The issuer ignores unknown payload members. It MUST pass only the verified
payload to policy. The readable top-level `resource` member, when present, is
diagnostic and MUST NOT participate in registration lookup, authorization,
BIND, the cache key or partition defined by the selected
[response binding](spec--response-binding.md#9-replay-caching-and-composition) and
[endpoint profile](spec--http-binding.md#34-response), or opening-key
selection. A readable `resource` mirror that disagrees with the verified claims
is not an error.

<a id="5-baseline-unlock-request"></a>
## 5. Core unlock request

The client sends one JSON object to one issuer. Common JSON, identifier and
unknown-member handling follows
[spec--data-format.md](spec--data-format.md#2-common-json-rules).

The client builds the request only from the core members and the
selected-profile members specified below. Finite deployment resource limits
apply to the request as received, including ignored optional members; those
members grant nothing and are not interpreted. The issuer counts raw records
against those limits before it drops a copy or merges a selection.

The core request has this structure:

| Member | Type | Requirement |
| --- | --- | --- |
| `version` | string | Required |
| `issuerName` | identifier | Required |
| `resourceJWT` | string | Required; relayed unchanged |
| `keyId` | string | Required non-empty opaque value |
| `envelope` | string | Optional; selected [compact ECDH profile](spec-profile--compact-ecdh.md#32-unlock-request) procedure |
| `sealed` | object | Required |
| `sealed.contentKeys` | array | Required; may be empty beside a non-empty section the receiving issuer selected |
| `sealed.periodKeys` | array | Optional period-key section |
| extension members | object | Optional; defined by a selected capability extension (Section 10) |

`sealed.contentKeys` holds records `{contentName, key}`, where `key` is the
publisher-supplied sealed value. `sealed.periodKeys` holds records
`{accessGroup, period, key}`, where `period` is the label `t`. Both follow the
collection rules of
[data format Section 2.3](spec--data-format.md#23-collections-of-named-records). A
selected capability extension defines any further section or request member and
its relay; for chain keys see
[chain keys Section 12.3](spec-profile--chain-keys.md#request-member).

An issuer that has not selected period-key input for that route ignores
`sealed.periodKeys` as an unknown member and parses none of its names or
labels.

Before constructing the presented set from `sealed.periodKeys`, an issuer that
has selected period-key input MUST apply the lexical admission in the base
period-key requirements in
[spec-profile--period-keys.md](spec-profile--period-keys.md#base-period-key-requirements). An
invalid label is a whole-request structural failure. It MUST NOT reach policy,
BIND construction, envelope opening or a response error coordinate. A selected
period extension defines admission of its own coordinates and the scope of
their failures.

Every collection the issuer processes is an array, and the identity fields of
its records follow the identifier rules of the data-format specification. A
collection that is not an array, or a record whose `contentName` or
`accessGroup` is missing, is not a string or fails those rules, is a
whole-request structural failure. In `sealed.contentKeys`, an element that is
not a non-array object presents no coordinate: the issuer skips it, and its
siblings keep their admission. In `sealed.periodKeys`, such an element is a
whole-request structural failure. When period-key input is selected,
`sealed.periodKeys` is non-empty. A conforming client emits every sealed entry
as a canonical binary string; the applicable envelope or capability
specification constrains its decoded bytes. Sealed `key` presence, type and
spelling are not structural admission checks: they receive the per-coordinate treatment in
Section 7.1 after authorization.

The client MUST copy `version`, `resourceJWT`, `issuerName` and `keyId` from the
selected delivery and issuer block without reinterpreting them. It MUST NOT
combine sealed values from different issuer blocks in one request. It SHOULD
omit item content-key coordinates already resolved using applicable cached
capabilities. For period-key input, it SHOULD omit an access group only when no
still-unresolved item needs a period-key wrap under that group. A still-needed
group follows the complete-label relay rule of
[period keys Section 5.5](spec-profile--period-keys.md#base-period-key-requirements).

For each unresolved item, the client sends the selected issuer's sealed item
content key when present and its `contentName` route identity is eligible for
the selected attempt under Section 5.3. It sends only eligible
period-capability coordinates, and only when the corresponding period profile
is selected for that request and the item carries an authored
period-key-wrap alternative under that `accessGroup`, which is one of the
item's declared access groups. A
client that has not selected period-key input does not relay
`sealed.periodKeys`; a client
that has not selected chain-key input does not relay the chain members.
Sending both selected alternatives is permitted; the issuer decides which
authorized capability to return.

At least one item content-key coordinate or selected-profile coordinate MUST
be present. An empty request is a whole-request failure and MUST NOT reach
opening-key lookup. A selected profile defines which of its inputs count as
presented for this test. Under the chain-key profile, each grammar-valid
`accessGroup` in an admitted `sealed.chainKeys` collection presents an access
group even if its family or records subsequently fail their scoped admission;
an empty collection presents none
([chain keys Sections 12.1 and 12.3](spec-profile--chain-keys.md#123-request-member)).
Unsupported chain fields remain ignored and cannot make an otherwise empty
baseline request usable.

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

The current unreleased v1 draft uses `"1"` for this draft's grammar. Earlier
unreleased drafts that used indexed maps are not compatible with the current
named-record arrays, even if they also used `"1"`. Deployment peers MUST agree
on the same draft revision outside the wire protocol. This transition defines
no dual parser, shape-based retry or additional unsigned selector.

Authors need a new `version` when a change alters accepted syntax, the
authenticated transcript, authorization meaning or failure meaning. Clarifying
a v1 rule that was already unambiguous stays a
note inside v1. [spec--data-format.md](spec--data-format.md#2-common-json-rules)
states the same test in format terms.

### 5.2. Optional offers

An optional request member can advertise a client capability. Its presence is
an offer, not a demand and not evidence of authorization. For example,
`clientPublicKey` has meaning only under a selected client-bound method; an
issuer without one ignores it as an unknown member. When the endpoint response
agreement selects direct mode only, an unrecognized `clientPublicKey` member
does not select client-bound delivery; any returned keys use the agreed direct
representation. A client requiring client-bound delivery MUST NOT treat that
direct-only endpoint as usable under that requirement.

### 5.3. Multiple issuers

One request addresses one issuer block. Requests and results for sibling
issuers are independent. Failure or denial by one issuer MUST NOT grant through,
alter the policy of or suppress a valid attempt to another issuer.

Trusted client configuration makes an attempt to another issuer valid in one
of two ways:

- An **independent attempt** is one the configuration permits whatever the
  earlier issuer answers. The publisher must have authored applicable material
  for that issuer, and that issuer applies its own policy. The earlier issuer's
  result, whether a denial, a partial grant or a family report, neither
  triggers nor cancels it.
- A **conditional fallback attempt** is one the configuration makes only after
  an earlier issuer's outcome, such as a backup issuer tried after a transport
  failure. It is valid only when trusted route configuration classifies that
  outcome as retryable. Listing a backup issuer does not by itself authorize an
  attempt to it.

A client MUST NOT make a conditional fallback attempt after a whole-request
refusal for a definitive policy denial. A selected endpoint binding MUST
distinguish a refusal from an operational failure for each outcome it permits
to trigger conditional fallback; the HTTPS binding assigns their observable
status classes. An indeterminate outcome that could conceal a refusal MUST NOT
trigger conditional fallback. This includes a browser Fetch failure that does
not expose the response status. A client MUST NOT cancel a configured
independent attempt because of an earlier issuer outcome, including a
transport failure that hides the HTTP status; only explicit cancellation of
the whole acquisition or a local configuration or implementation failure MAY
end it. A local circuit-breaker skip is not an issuer response and grants no
conditional fallback eligibility.

Eligibility for a later attempt is scoped by route identity: `contentName` for
an item content-key coordinate and `accessGroup` for a period family. The next
issuer receives only its own publisher-authored sealed coordinates for eligible
route identities, never copied coordinates from the prior issuer. An independent
attempt uses the identities its trusted configuration authorizes. A
conditional attempt uses only unresolved identities whose prior outcome that
configuration classified as retryable. A coordinate-local error qualifies
only that coordinate when a selected profile gives the error retry meaning;
it does not qualify an entire family by itself. A selected profile can give a
family-level outcome retry meaning; period keys Section 5.6 gives the base
`notDelivered` report its retry meaning. Denial, silence and same-family
partial delivery do not themselves qualify. An item content-key coordinate needs its own eligible
outcome or an independent attempt. If no route identity is eligible
for the next issuer, the client skips it.
After applying admitted capabilities, the client MUST recompute unresolved
items before selecting a conditional attempt. Success for another route
identity neither grants nor removes fallback eligibility. A capability that
already opens an item removes that item's retry need. Trusted route
configuration MAY stop the whole attempt after a partial grant by declining
to classify that mixed outcome as retryable.

An item's alternatives stand independently (Section 2.4). No role infers
conjunction, threshold or cross-issuer key combination from several issuer
blocks; a profile that defines such a combination must identify and
authenticate it explicitly.

## 6. Issuer processing

### 6.1. Presented coordinates

A presented coordinate is the coordinate that one record of an admitted
key-bearing request collection names. The issuer MUST read every record field
as an own member and MUST apply the identifier admission rules before policy.
Several records at one coordinate present it once; each record is a source
candidate for it
([data format Section 2.3](spec--data-format.md#23-collections-of-named-records)).
Array position is not part of a coordinate.

The issuer constructs a presented set of `contentName` coordinates for the item
content-key section and `(accessGroup, t)` coordinates for a selected
period-key section, plus the coordinates a selected capability extension
defines for its sections.

The **admissible result set** of a request is its presented set plus, for each
selected capability extension, the deterministically checkable set of
coordinates that extension's specification derives from admitted, presented
source coordinates.

### 6.2. Authentication and policy

An implementation may divide the steps below among components, but it MUST
preserve their security-relevant order and use one parsed request value
through authentication, policy, key selection and opening.

Before opening-key lookup or any envelope opening, the issuer MUST:

1. enforce the request-body resource limits, parse the request carrier and
   admit the common version-selector shape;
2. check that the version is supported before admitting version-dependent
   members and enforcing their finite deployment resource limits;
3. resolve exactly one active signing-key entry and its parent publisher
   registration from the unverified header `kid`, as Section 4.2 requires;
4. verify and admit the signed resource assertion;
5. complete every pre-policy check required by the request binding the
   deployment selects;
6. obtain an authenticated or explicitly anonymous principal and host-owned
   policy context; and
7. obtain an issuer policy decision over verified publisher claims, issuer
   state and the presented coordinate set.

Admission of an offer required by the selected endpoint response agreement
([response binding Section 4](spec--response-binding.md#4-selection-and-agreement))
also MUST precede opening-key lookup and envelope opening.

If an entitlement source times out, is unavailable, refuses to answer or
returns unusable input, the issuer has obtained no policy decision. It MUST
fail closed and return no key material; it MUST NOT substitute a default grant.

The issuer applies its policy only within the registration whose key verified
the assertion, using verified `resourceJWT.origin` as the origin coordinate.
An issuer that also keeps a registered-origin limit per publisher MAY refuse
an origin that registration does not list; that limit is defense in depth
beside the verified-origin comparison, which stays the check the issuer makes.

The issuer MUST run the binding's verified-claim checks after assertion
verification and before issuer response-cache lookup, policy or
opening-key access. Under the selected browser-origin profile, for example,
the issuer compares the externally observed Origin with verified
`resourceJWT.origin` at this point. That profile specifies the exact comparison
and HTTP behavior.

For a core request section, the issuer MUST intersect its policy output with
the presented set. A selected capability extension MUST confine its interpretation of policy
output to admitted, presented source coordinates and the admissible result set
it derives from them. A policy cannot cause a sealed coordinate outside the
presented set to be opened or a capability outside those sets to be returned,
even if the caller would normally be entitled to it. A key-count limit is not
authorization to choose period labels: the issuer MUST independently authorize
each returned label; a count can further limit an already-authorized set.
A malformed policy result
is an issuer failure, never a grant.

The issuer MUST authorize the full reach of each returned capability. Unsigned
client group selectors and article `contentData` are not authenticated evidence
that an article belongs to a group. When a grant depends on that relationship,
the issuer MUST establish it from verified resource claims, trusted
configuration or issuer-held information. Envelope BIND authenticates the
capability coordinate, not article membership. A trusted policy granting a
reader the entire group and applicable period reach can authorize that
capability without reconstructing membership of the requesting article. A
permission limited to one article does not by itself authorize a reusable
group capability; an independently supplied item content-key alternative can
provide the narrower grant.

If the request presents coordinates and the issuer authorizes none under its
policy, it MUST either refuse the whole request before opening-key lookup or
answer with a core result that delivers no key and whose `notDelivered` member
([period keys Section 5.6](spec-profile--period-keys.md#56-family-reports-notdelivered))
names at least one presented access-group family. The issuer builds that result
without opening-key lookup and omits every denied item content-key coordinate
from it. When the request presents no access-group family, or the issuer
chooses to name none, the issuer refuses the whole request. Partial
authorization may continue with only the granted subset and MAY name a denied
family in `notDelivered`.

### 6.3. Opening-key scope and BIND

Trusted receiving-endpoint configuration MUST bind the endpoint's operating
issuer names, policy and registration-scoped opening-key view. Before policy or
opening-key lookup, the endpoint MUST refuse a request whose `issuerName` is not
in that configured scope. A host MAY explicitly configure several operating
names to share one policy and key authority. An unsigned name MUST NOT select a
different authority's key while retaining this endpoint's weaker policy.
Ordinary deployment configures one operating name; an explicit multi-name
composition declares its shared authority.

The issuer MUST resolve `issuerName` and `keyId` only within the authenticated
publisher registration. Identical unsigned strings under another publisher
registration select no key here.

Those selectors choose entries within that registration, not globally
authenticated issuer identities; entries resolving to one opening private key
share the entrustment domain of [Section 2.1](#21-publisher).

The issuer MUST NOT open a sealed coordinate whose use its policy decision
does not permit. It opens a permitted one under BIND rebuilt as
[envelopes Section 3.3](spec--sealed-key-envelopes.md#33-trusted-field-sources)
requires. Envelope construction, BIND bytes, algorithm selection and opening
failure are defined by
[spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md).

When several source records present one permitted coordinate, the issuer
applies that same opening procedure to each usable record. Several records can
open and yield different keys. The issuer carries each distinct key it produced
into the result as a candidate (Section 7); a successful first opening does not
make that key the coordinate's only result. Policy decides the coordinate once,
however many records present it, and each record consumes the applicable finite
work budget.

A selected mechanism may use a trusted issuer source to produce an
already-authorized result. The composed issuer MUST confine both the source's
input use and its returned result to the authorization required by that
mechanism. Authorization to use auxiliary material inside the issuer is
distinct from authorization to deliver that material to the client. An item
grant alone MUST NOT be interpreted as authorization to return a period key or
chain key.

A source reconstructing an item content key MUST select its auxiliary inputs
from the admitted presented coordinates, or from issuer-held material scoped
to the authenticated publisher registration, under verified claims and trusted
issuer policy or configuration. Before opening an auxiliary envelope, it MUST
establish that the selected mechanism permits that coordinate's use for the
granted item. The issuer MUST rebuild the auxiliary envelope's BIND from the
verified `renderId` and that authorized auxiliary coordinate, without replacing
its native coordinate with the served item's name. The source MUST establish,
using the selected mechanism's authenticated binding or trusted issuer-held
information, that its result is the content key of the granted item and
render. It MUST NOT return auxiliary key material as that result. An unsigned
candidate label or a served content name alone establishes neither permission
nor result provenance.

The issuer retains custody of its opening private key. A composed source
receives only the opening operation scoped to this authenticated registration,
verified render and authorized unlock. The source's trusted implementation
owns any mechanism-specific auxiliary selection and reconstruction checks that
the common engine cannot perform.

<a id="7-baseline-issuer-core-result"></a>
## 7. Core issuer result

The issuer core produces this transport-independent semantic document:

```json
{
  "keys": {
    "contentKeys": []
  }
}
```

`keys` is a required object and `keys.contentKeys` a required array that may be
empty. `keys.periodKeys` is present only when at least one period key is
delivered. `errors`, when present, MUST be a non-empty array of error records.
Each error record MUST be a non-array object with a string `coordinate` member
holding an error coordinate (Section 7.1), a non-empty string `error` member
and an optional string `message` member. Unknown members inside an error record
are ignored. The issuer emits one error record per coordinate. A client that
finds several records for one `coordinate` uses the last whole record
([data format Section 2.3](spec--data-format.md#23-collections-of-named-records)).

<a id="72-not-delivered-access-group-families"></a>
The result MAY also carry the top-level member `notDelivered`. It is a base
member of the core result protected by Section 10;
[period keys Section 5.6](spec-profile--period-keys.md#56-family-reports-notdelivered)
defines its grammar and every client's admission duty. Every client admits
`notDelivered` as that section requires.

`keys.contentKeys` holds records `{contentName, key}` and `keys.periodKeys`
holds records `{accessGroup, period, key}`, where `key` is the delivered key.
Several records at one coordinate are candidate keys for it: the issuer emits
each distinct key it produced for an authorized coordinate (Section 6.3), and
the client keeps or tries each admitted candidate within its finite bounds.
Each core-result key entry, the `key` member of a record, is canonical unpadded
base64url. A selected response binding may replace each key entry with its
protected carrier before delivery.

A selected capability extension may add result sections and top-level members;
its specification defines them and the admissible result set they draw from
(Section 10). For chain keys see
[chain keys Section 13.1](spec-profile--chain-keys.md#chain-route-periodcount).

Every delivered capability MUST correspond to a coordinate that was authorized,
successfully produced and in the request's admissible result set (Section 6.1).
A response MUST NOT widen policy reach, return a coordinate outside that set or
expose an issuer opening key. Host-only policy data MUST NOT appear in the
response.

This document defines no response representation of its own. A client
receives the result only through an explicitly selected response binding and
MUST admit that binding and the returned coordinates as
[response binding Section 3](spec--response-binding.md#3-inputs-and-common-response-form)
requires before using any key (for chain results, chain keys Section 9). The
client MUST apply the focused capability specification before caching
reusable authority.

### 7.1. Per-coordinate errors

The issuer may fail one trusted, authorized coordinate and still return its
successful siblings. Its error object contains no key material.

Each core error record MUST correspond to exactly one admitted presented
coordinate included in the policy-granted set, and none of the source records
at that coordinate may have produced a delivered key; a selected capability extension
states how opening failures of
its source members map onto these coordinates, or reports them in an error
grammar of its own result section. A content coordinate is its
`contentName`; a period-key coordinate is its `(accessGroup, t)` pair.
The coordinate named by an `errors` record MUST NOT also appear in any `keys`
section in that result. The issuer omits policy-denied coordinates from `keys`
and `errors` and does not report them as opening failures; period keys Section
5.6 states what a result may carry for a family it names in `notDelivered`.

An issuer that encounters a non-string, noncanonical or otherwise malformed
entry after the request and coordinate are authorized MUST NOT decode or open
it. It MUST report `unseal_failed` for that coordinate when no other record
there produced a delivered key. That failure does not suppress successful siblings.
Malformed request containers, records and identity fields remain
whole-request admission failures.

The `coordinate` grammar is:

```text
error-coordinate        = contentName / period-error-coordinate
period-error-coordinate = accessGroup "|" t
```

An issuer encodes a period error coordinate only for a `t` the applicable
period-capability specification admits. An empty or malformed `t` and a
group-only spelling such as
`accessGroup "|"` are not core error coordinates. Because `contentName`,
`accessGroup` and admitted `t` exclude `|`, the two forms are unambiguous. The
client treats the `coordinate` value as a coordinate, not free-form diagnostic
text.

An issuer reports family-level non-delivery only through the `notDelivered`
member ([period keys Section 5.6](spec-profile--period-keys.md#56-family-reports-notdelivered)).

## 8. Failure model

Core processing distinguishes:

| Class | Scope | Key-material result |
| --- | --- | --- |
| malformed or unsupported request | Whole request | None |
| unauthenticated publisher assertion or unknown, ambiguous, inactive or retired signing `kid` | Whole request | None |
| complete authorization denial | Whole request, or a no-key result naming a presented family in `notDelivered` | None; denied coordinates do not reach opening-key lookup |
| unknown issuer opening key | Whole request | None |
| retired opening key | Per coordinate after a trusted request | `key_retired`; successful siblings may remain |
| envelope/BIND opening failure | Per coordinate after a trusted request | `unseal_failed`; successful siblings may remain |
| chain admission failure | Per family or member, silent | None for it; unrelated members and sections unaffected |
| selected-profile finite output processing limit exceeded | Whole request | None; successful sibling keys are suppressed |
| issuer configuration or internal failure | Whole request | None |

Failure detail MUST NOT turn an untrusted request into a key-existence or policy
oracle beyond what period keys Section 5.6 permits or the selected endpoint
profile specifies as exposed. HTTP status, response wording, retry, telemetry and uniform-error
profiles are outside this core specification.

## 9. Delegation completeness

The publisher and issuer MUST agree through trusted deployment configuration
on the request limits applicable to their selected endpoint and profiles.
A publisher MUST check that the acquisition routes it promises fit those limits,
including combined selected key families and client-added request material.
DCA defines no universal request-size floor and no unauthenticated
limits-discovery mechanism.

Every publisher delivery MUST contain at least one item in `contentData` and
MUST give every item at least one issuer-mediated opening route permitted by
its [resolved profiles](spec--profiles.md#2-mechanism-selection-states).

A delivery claiming compatibility with a baseline-only client MUST author an
item content-key alternative for every item: a sealed content-key value for
that `contentName` under at least one conforming usable issuer block. When
`dca-profile-period-keys` is selected, an item MAY instead rely on a
period-key-wrap alternative: at least one content-key wrap under an
`(accessGroup, t)` for which a conforming usable issuer block supplies the
matching period-key capability.
[Profiles Section 3.6](spec--profiles.md#36-compatibility-with-a-baseline-only-client)
lists the further conditions for a baseline-only client, including the
delivery carrier.

A complete item content-key route satisfies the per-item requirement even
when the item also carries period-key wraps without a matching issuer period
supply route in this delivery. Those wraps allow use of previously held
matching period capability; their presence does not promise acquisition of
that capability from this delivery.

A usable issuer block for this core satisfies the data-format requirements for
`issuerName`, `keyId`, `sealed` and the applicable sealed collection. Its `keyId` is
non-empty. Publisher-side delegation completeness requires suitable sealed
material, not an endpoint URL in the delivery.

Before acquiring a key, the client MUST select an endpoint from trusted client
configuration for the operation's publisher/deployment context and issuer alias.
The same alias in another publisher context MUST NOT select this context's endpoint
or credentials. Decoded, unverified JWT claims and the readable `resource`
mirror MUST NOT establish that trusted context. The endpoint and response
agreement MUST satisfy the selected binding; HTTPS selection is defined in
[HTTPS endpoint binding Section 3.1](spec--http-binding.md#31-endpoint-and-channel).

If trusted client configuration supplies no usable endpoint, or the delivery
has no usable issuer block or applicable sealed material for that issuer, that
issuer attempt sends no request and supplies no conditional fallback permission.
An independent attempt remains possible under Section 5.3. A usable cached
capability may still open the item without endpoint resolution. Client
configuration cannot supply an acquisition alternative for an issuer lacking
applicable publisher-sealed material.

A selected optional profile defines the corresponding evidence for its route.
It MUST end in a capability that yields the item's content key through one of
the item's authored alternatives and MUST identify the issuers and actor duties
required to carry it. For the chain-key profile,
[chain keys Section 9](spec-profile--chain-keys.md#chain-key-role-requirements) states
that evidence.

Delegation completeness is a publisher authoring and profile-conformance
invariant, not a parser's inference from member names alone.

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
response and protects key confidentiality and integrity.

## 11. Security considerations

The client controls the unlock request, so its unsigned routing and
coordinate fields are selectors only (Section 2.3); BIND ties each sealed value
to its coordinate (envelopes Section 3, applied in Section 6.3). Opening an
envelope before the policy decision would exercise protected key material for an unauthenticated or unauthorized
request (Section 6.2).

Reusable capabilities have the reach defined by their focused specification.
Neither request filtering, a future grant horizon nor BIND narrows authority already
delivered to a client. Revocation cannot recover keys or plaintext already
released.

## 12. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [RFC 3339: Date and Time on the Internet](https://www.rfc-editor.org/info/rfc3339)
- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/info/rfc7515)
- [RFC 4648: Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/info/rfc4648)
- [RFC 7518: JSON Web Algorithms](https://www.rfc-editor.org/info/rfc7518)
- [DCA data format](spec--data-format.md)
- [DCA sealed key envelopes](spec--sealed-key-envelopes.md)
- [DCA response binding](spec--response-binding.md)
- [DCA period-key capabilities](spec-profile--period-keys.md)
- [DCA chain keys: construction and delegation](spec-profile--chain-keys.md)
- [DCA content protection](spec--content-protection.md)
- [DCA HTTPS endpoint binding](spec--http-binding.md)
- [DCA security model](spec--security-model.md)
