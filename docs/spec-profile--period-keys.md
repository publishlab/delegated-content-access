# DCA period-key profile: capabilities and duties

Status: Public Working Draft

## Abstract

This section is informative.

DCA encrypts every protected content item with a fresh item-specific
`contentKey`. To avoid a new issuer interaction for every article, a publisher
also creates reusable keys associated with an access group and labeled time
period.

This specification defines the exact form of that reusable authority:
`periodKey[t]` opens content-key wraps for exactly one access group and period
coordinate. The publisher supplies period keys to its issuers, an issuer
returns the period keys it authorizes, and a client caches them for later
matching articles.

The optional chain-key profile ([spec-profile--chain-keys.md](spec-profile--chain-keys.md))
fixes one construction that derives these period keys and adds delegation
through chain keys.

<a id="scope-and-status"></a>
## 1. Introduction

This document defines the base period-key capability, `periodKey[t]`, and the
role duties that the `dca-profile-period-keys`
profile of [spec--profiles.md](spec--profiles.md) compose. [Base period-key
requirements](#base-period-key-requirements) are normative.

[spec-profile--chain-keys.md](spec-profile--chain-keys.md) specifies the optional
chain-key profile and its canonical construction, which derives period keys
from positioned chain keys. That document imports the period-key meaning
defined here. This document does not depend on it, and a period-key-only
issuer or client need not read it.

`periodKey` is the base capability of the period-key profile and the
interoperability floor for every role that implements it. A publisher
may make its period keys by independent random generation or by the canonical
construction fixed by the chain-key profile; issuers and clients
that implement only period-key processing open the same article wraps either
way. A canonical construction is the versioned derivation transcript a profile
fixes, not a second profile kind. Its output at a coordinate is an ordinary
`periodKey[t]`.

This document does not define reader entitlement policy, JWT validation, HTTP
routing, or article encryption beyond the interface to `contentKey`.
[spec--data-format.md](spec--data-format.md) defines carrier placement and
structural admission of the members this document names;
[guide--period-keys.md](guide--period-keys.md) is the readable companion.
The validation rules of Section 5.6 bind every client, whatever profiles it
selects.

### 1.1. Requirements language

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Profile selection and role duties

This optional profile adds reusable period-key delivery and caching. It
depends on `dca-profile-baseline` and selects the period-key content-key
wrapping transcript in
[spec--content-protection.md](spec--content-protection.md).

When selected:

- the publisher produces period keys and wraps as Sections 5 and 6 require;
- the request path relays period-key coordinates as Section 5.5 requires;
- the issuer returns period keys only as
  [core Section 7](spec--core-protocol.md#7-baseline-issuer-core-result)
  permits; and
- the client admits, scopes, stores and attempts period-key candidates
  according to the period and content-protection specifications.

Every affected publisher, issuer and client role MUST implement this profile
before a deployment relies on period-key wraps alone to open an item, as
[core Section 9](spec--core-protocol.md#9-delegation-completeness) permits;
such a delivery is not baseline-compatible.

Selecting the period-key profile selects no chain carrier, relay, issuer chain
processing or chain response, and no content compression, browser CORS or
client-bound custody.

<a id="key-and-capability-model"></a>
## 5. Key and capability model

<a id="period-key-family-generation-and-window-identity"></a>
### 5.1. Period-key family, generation, and window identity

An access group (`accessGroup`) is a grouping of content items, named within
one publisher security namespace, for reusable period-key access. It groups
content, not readers; the issuer separately decides which period-key
capabilities a reader may receive. An item may offer several access-group
alternatives; a capability matching any one alternative opens its corresponding
content-key wrap.

A period-key family is the reusable key lineage for one publisher security
namespace and `accessGroup`. The publisher may keep several cryptographic
generations in that period-key family over its lifetime.

A period-key generation is an immutable cryptographic namespace for the
period-key bytes of one family. Every generation fixes its publisher security
namespace, `accessGroup`, coordinate spellings, its period-key profile and
`periodKey` bytes. A generation made without the canonical chain-key
construction defines no retained derivation input or chain geometry. A
generation that uses a canonical construction also fixes that construction's
inputs, including window identity, as the profile that defines the
construction states. Rotating the family's key material starts a new
generation, even when `(accessGroup, t)` labels remain the same.

Issuer identity, issuer opening-key rotation, render identity, and the
issuer-to-client transport mode do not change period-key bytes.

Base period-key processing carries no generation identifier; authenticated
unwrap, within the trial bound of Section 5.5, tells rival key bytes at one
coordinate apart (Section 10).

<a id="contentkey"></a>
### 5.2. `contentKey`

A `contentKey` is the fresh key of one protected item in one render, as
[content protection Section 3.1](spec--content-protection.md#31-content-key-generation)
defines.

<a id="periodkeyt"></a>
### 5.3. `periodKey[t]`

`periodKey[t]` is the capability for one publisher-scoped period-key
generation, access group, and period coordinate `t`; Section 5.5 fixes its
width. Base period-key processing defines no derivation between coordinates
and no publisher `keyDerivationSecret`.

It can open every content-key candidate wrapped under that same coordinate. It
does not intrinsically mean "articles published during this period." Its reach
is determined by the ciphertexts the publisher actually wrapped with it.

A period-key grant is never render-bound. Reuse across matching articles and
renders is its sole function. Delivering a period key does not reveal
neighboring period keys.

<a id="delivery-is-not-a-time-lock"></a>
### 5.4. Delivery is not a time lock

A future `periodKey[t]` can be issued before period `t`. If matching ciphertext
already exists, the recipient can open it immediately. The publisher or issuer
must schedule access by withholding the capability or ciphertext, or by ensuring
that earlier renders are not wrapped under that coordinate.

<a id="base-period-key-requirements"></a>
### 5.5. Base period-key requirements

This subsection is normative for the `dca-profile-period-keys` profile of
[spec--profiles.md](spec--profiles.md). "Base" below names that profile's
floor: what every publisher, issuer and client implementing it supports. The
`dca-profile-baseline` profile does not include it.

For each access group needed by an unresolved item's period-key wraps, the
client relays every admitted supplied label from the selected issuer block,
even when this render has no wrap under that label. It SHOULD omit an access
group when no item still unresolved after local capability use needs a
period-key wrap under that group.

DCA v1 fixes one period-key width: a period key is 16 octets and period-key
wrapping uses AES-128-GCM, as
[content protection Section 4](spec--content-protection.md#4-base-period-key-content-key-wrapping)
fixes; [envelopes Section 2](spec--sealed-key-envelopes.md#2-envelope-model)
fixes the 16-octet width. A publisher, issuer, or client MUST refuse a period
key or delivered capability that is not exactly 16 octets before storing, using
or returning it. A publisher, issuer, or client MUST check visible raw widths
and carrier shapes before any cryptography; a payload visible only after
authenticated opening MUST be checked immediately afterward, before use,
delivery or retention.

A period-key coordinate consists of an admitted `accessGroup` and `t` under
one publisher security namespace established by the selected delivery or
publisher-authentication binding. A client takes the namespace from its
trusted delivery context (for markup delivery, the page origin; for object
delivery, the origin the deployment supplies with the document), never from
the unverified `resourceJWT`. A publisher, issuer, or client MUST NOT infer
the namespace from `accessGroup`. `accessGroup` uses the identifier grammar in
[spec--data-format.md](spec--data-format.md#21-identifiers). The v1 base
spelling of `t` is:

```abnf
period-t = 6DIGIT "T" 4DIGIT
```

`DIGIT` is the ABNF core rule from
[RFC 5234](https://www.rfc-editor.org/info/rfc5234). `YY` names a year from 2000
through 2099; the remaining fields are month, day, hour and minute. A producer
MUST emit `YYMMDDTHHMM` from the UTC start of the publisher-selected period,
including minute digits for an hourly period. It MUST emit a real Gregorian
date and a time in its ordinary range.

A base period-key consumer performs only lexical admission of `t` against
`period-t`; calendar correctness and field ranges are producer duties it does
not check. After admission, it MUST preserve and compare the ASCII spelling
byte for byte and MUST NOT use its own clock to rewrite, infer or reinterpret
coordinate identity. An issuer MAY use its own captured policy time to decide
entitlement or select among actual supplied coordinates; this does not rewrite
their identity or make request presentation an authorization. The grammar
excludes `|`, so an admitted label is safe in the period-key (`p`) BIND and
error-coordinate grammars.

The publisher configures one shared `periodMinutes` grid across its groups.
It MUST be a positive integer dividing the 1,440 minutes of a UTC day exactly;
a period-key-only grid has no chain-position bound. A delivery selecting only
ordinary period-key processing MUST omit top-level `periodGeometry`: each wrap
and envelope already carries its explicit `t`. A delivery selecting chain
processing, including cached chain opening without fresh chain supply, carries
the complete pair specified by
[chain keys Section 7.2](spec-profile--chain-keys.md#windows). It does not change the
base consumer's label-only admission or require it to parse geometry or derive
keys. When the publisher automatically chooses ordinary period labels from
time, it uses this shared `periodMinutes`; it does not keep a second hidden
period-length default. Explicitly authored subsets and alternatives remain
publisher policy. Every item wrap and period-key envelope keeps its own
explicit `t`, including an intentionally authored next-period alternative. Neither
`renderPeriod` nor `issuedAt` replaces those labels. A content-key-only baseline
delivery needs no `periodGeometry` or period coordinate.

A lexically invalid `t` in publisher-to-client material supplies no period-key
candidate and MUST NOT be relayed; valid sibling coordinates remain usable. An
issuer treats a lexically invalid `t` in a request as
[core Section 5](spec--core-protocol.md#5-baseline-unlock-request) requires.

A conforming period-key publisher MUST provide a period-key-only supply path
that needs no chain input and MUST use it for every issuer selected for a
period-key-only route. A conforming period-key issuer MUST accept `periodKey`
input and provide a period-key result route. A conforming period-key client
MUST accept `periodKey` grants. A selected profile may add another supply or
result route; it does not remove this interoperability floor. The floor applies
when a route is selected as a period-key-only route; it does not require a
chain-key profile route to duplicate chain-key supply with period-key supply.

Within one generation, a publisher MUST use the same `periodKey[t]` for every
matching content-key wrap and issuer envelope at that publisher, `accessGroup`
and `t`, and every issuer route for a render MUST supply or derive those same
bytes. It MUST NOT expose the raw period key in publisher-to-client delivery.

Within one render, one access-group family uses one generation. Every
content-key wrap the publisher offers for that family in a render, and every
issuer envelope in that render that carries the family's period material,
including material at a coordinate the render wraps nothing under, MUST use
period keys from the same family generation. A publisher MUST NOT add a wrap
under another generation's period key to a new render, even at the same
`(accessGroup, t)` and even while a retained render still supplies that other
generation to an issuer. Within one generation this rule restricts nothing: a
key that an issuer grants from a retained render still opens a later render at
the same coordinate (Section 9). The rule applies per family per render. It
does not require every issuer to receive every group or coordinate, and
retained renders and client caches keep rival bytes from other generations
(Section 10).

For every distinct `(accessGroup, t)` in one generation, the publisher MUST
generate an independently random period key or use a selected construction with
equivalent domain separation. Reusing the same key bytes at two coordinates
makes every matching wrap at both coordinates cryptographically openable; a
label, cache partition or client stopping rule cannot narrow that reach.

An issuer MUST treat a successfully opened period-key envelope as sourceable
authority only, not entitlement. It MUST use the same admitted coordinate for
policy and BIND, and return a period key only when that coordinate was
presented, authorized and successfully opened.

A client admits a result under the selected response binding, as
[response binding Section 3](spec--response-binding.md#3-inputs-and-common-response-form)
requires, before retaining key material. It MUST accept only a period key the
width refusal above admits, or a protected representation that opens to a
non-extractable key handle with the required period-key usage. It routes and
files capabilities by publisher security namespace, `accessGroup` and
byte-identical `t`. It MAY perform bounded trial of retained candidates across
labels when authenticated content-key unwrap is the match test; such trial
does not widen the inherent reach of the bytes and MUST NOT be treated as
authorization.

An admitted key MUST remain available to the operation that obtained it until
that operation has attempted every applicable content-key candidate. Later
retention and time-based eviction are host policy: eviction causes an ordinary
cache miss and does not revoke or invalidate the capability bytes. An
implementation MUST place finite bounds on retained rival candidates and
on candidate trials; their values are deployment-selected. Candidate trials
are bounded for one operation. Where selected mechanisms supply more than one
source of ordinary period candidates, the client MUST apply finite combined
rival and trial bounds across those sources and every storage view. A client
tries candidates in the order Section 10 states. Expansion or transfer
between storage views MUST preserve the obtaining operation's first-use
availability.

A reusable cache MUST partition period keys by publisher security namespace
and logical client context
([core Section 2.2.1](spec--core-protocol.md#221-logical-client-contexts-and-pending-work)),
so that mutually untrusted publishers and distinct logical client contexts
cannot consume one another's keys. A profile or deployment MAY partition
further by issuer or response binding. Such additional partitioning changes
lookup eligibility only; it does not narrow the cryptographic reach of a
capability already delivered.

These rules apply to every admitted period key, whatever produced it,
including one derived locally under a selected profile: a client that retains
such a key MUST treat it as an ordinary period capability, and the
derivation's inputs MUST NOT condition its use.

<a id="family-reports-notdelivered"></a>
### 5.6. Family reports (`notDelivered`)

This subsection defines `notDelivered`, a top-level member of the core result
of [core Section 7](spec--core-protocol.md#7-baseline-issuer-core-result). No
profile selects this member. Every client admits it under the validation rules
below, including a client whose request presented no access-group family. The
other client rules of this subsection bind a client whose request presented a
family.

An issuer MAY report a presented access-group family for which it delivers no
capability by adding `notDelivered` to the core result of any request that
presented at least one access-group family:

```text
notDelivered = [ { accessGroup: <identifier>,
                   reason: "denied" / "unavailable",
                   message: <optional string> } ]
```

`notDelivered`, when present, MUST be a non-empty array of report entries.
Each entry MUST be a non-array object whose `accessGroup` is an access group the
associated request presented
([core Section 6.1](spec--core-protocol.md#61-presented-coordinates)), with a
string `reason` member whose value is `denied` or `unavailable`, and an
optional string `message` member. The entry contains no key material and names
no `t`. Unknown members inside a `notDelivered` entry are ignored, as inside a
core error record. The issuer emits one entry per access group. A client that
finds several entries for one `accessGroup` uses the last whole entry
([data format Section 2.3](spec--data-format.md#23-collections-of-named-records))
and then applies the conflict checks below to it.

`reason` takes one of two values:

- `denied` means issuer policy withheld the family from this caller; under
  per-coordinate period policy, it authorized none of the family's presented
  coordinates.
- `unavailable` means policy independently authorizes at least one selected
  desired coordinate, but valid supplied material cannot provide any selected
  capability for that family. Selection can concern an article coordinate or
  an optional future grant that a selected profile defines; an article hint
  is not required. This reason reports availability, not a policy denial or
  response-form incompatibility.

A selected profile that supplies a family through its own representation
states how that family maps to `denied` and `unavailable`.

When an issuer emits an entry for a family its policy denied, it MUST use
`denied`, even when it also has no current capability for that family. It
MUST use `unavailable` only under the independently authorized selection and
valid-supply conditions above. Malformed input, a missing policy decision and
response-form incompatibility MUST NOT produce this reason. An issuer that
obtained no policy decision MUST NOT emit an entry. An authorized period
coordinate that fails to open is a
[core Section 7.1](spec--core-protocol.md#71-per-coordinate-errors) error, not
a `notDelivered` entry.

The issuer MAY omit the entry for any family, for example under its
disclosure policy. A family without an entry stays under the ordinary rules
of core Sections 7 and 7.1, and its silence carries no reason: a client MUST
NOT infer from it a denial, an availability condition or permission to try
another issuer.

An entry discloses to the caller that the issuer delivered no capability for
that family and which reason applied. A `message`, if present, MUST NOT
disclose more than the `reason` does.

A result that names an access group in `notDelivered` delivers no reusable
period capability for that family: with a `notDelivered` entry for `premium`
present, the result carries no `keys.periodKeys` record and no `keys.chainKeys`
record for `premium`.

A `keys.contentKeys` entry, an item content key returned by the issuer, is
instead the result of an independently authorized `contentName` coordinate.
It MAY coexist with the `premium` report entry even when the publisher's delivery
also offers a `premium` period wrap for that content item. That content key
does not become a capability for the family merely because the client could
also unwrap the same item's content key with a `premium` period key.

The same result carries no period-coordinate `errors` record for that family:
no `accessGroup "|" t` coordinate under its name. An error record whose
`coordinate` is a `contentName` reports failure of the independent item content-key coordinate
and MAY coexist with the family report. A per-period-coordinate opening
failure belongs only to a family the result did not name in `notDelivered`.

Every client validates the whole `notDelivered` member and its request
association before it uses a report entry or retains a stock period or chain key
from the response. The report is malformed when:

- the member or an entry violates the grammar above;
- an entry names an access group the associated request did not present,
  including any entry in a response to a request that presented none; or
- an entry names a family for which the same response delivers a period
  capability or carries a period-coordinate `errors` entry, under the family
  rules above.

For the period-coordinate error conflict, the client first applies the
error-entry admission and request association of
[response binding Section 3](spec--response-binding.md#3-inputs-and-common-response-form).
An error entry it ignores under that rule contributes no conflict. An admitted
period-coordinate error for the reported family makes the report malformed.
If the client instead rejects the whole response, no key or `notDelivered`
entry from it is admitted. The key-family conflict below remains a check of the
received structure before individual key-entry admission.

For a malformed report, the client MUST report that failure and MUST NOT admit
any entry from the report or retain any stock period or chain key from that
response. It MUST NOT discard independently admissible item content keys,
item errors or unrelated extension sections solely because the report is
malformed. Existing retained capability is unaffected. Whole-response
representation and transport admission still apply before retaining any key,
including classification of the original supported key collections before suppressing
family grants. The client MUST NOT record the rejected report as an empty
success, infer a denial or availability reason, activate conditional fallback,
or cache a denial from it. An independent later attempt remains a host decision.

For this conflict check, an empty key section carries no key entry and MUST
be treated as delivering no capability. Its presence alone MUST NOT conflict
with a `notDelivered` entry. Producers still omit optional key sections when
they deliver no keys, as core Section 7 requires; the required
`keys.contentKeys` array may be empty. For this check, a family has a key entry
only when the applicable key section is an array holding at least one
non-array object record whose `accessGroup` equals the family name. A present
non-array key section, or an element that is not a non-array object, is
malformed key material; it contributes no key entry to this conflict check and
does not by itself invalidate an otherwise admissible `notDelivered` report.
Its ordinary malformed-container treatment still applies. A record naming the
family conflicts before individual coordinate or key-entry admission, so an
invalid `period`, `cutoff` or `key` value cannot excuse a contradictory
report.

A rejected key entry does not discard an otherwise admitted `notDelivered`
member; its entries keep the meaning this subsection gives them. A
whole-response rejection produces no admitted `notDelivered` entry.

An admitted entry grants no capability and ends that issuer attempt for the
family. A client MUST NOT make a conditional fallback attempt
([core Section 5.3](spec--core-protocol.md#53-multiple-issuers)) for a family
after an admitted `denied` entry for it. Trusted route configuration MAY
classify an `unavailable` entry as retryable for its own family only: the
entry can qualify that family's route identity, not a denied sibling family
or a silently omitted `contentName` route identity.

<a id="content-wrapping-and-rollover"></a>
## 6. Content wrapping and rollover

Implementers must not infer article-overlap policy, issuer supply horizon, or
client grant horizon from one another.

### 6.1. Assigning access groups before sealing

Before sealing an item selected for period-key access, the publisher MUST
assign that item at least one access group and MUST author at least one usable
period-key wrap for each assigned group in the item's `keys` collection, as an
entry naming that `accessGroup`. When the intended access policy
offers several groups as alternatives, the publisher MUST include every
intended group and wrap the item's one `contentKey` under each, as
[content protection Section 4](spec--content-protection.md#4-base-period-key-content-key-wrapping)
requires.

Assignment is per protected item, not necessarily per article. Items in the
same article can have different assignments. The publisher MUST apply and
validate the assignment before sealing, even when an issuer or customer
administers the mapping. The publisher MUST NOT treat the mere availability of
a configured group as an assignment of that group to every item. This
specification defines no classification rule language or local configuration
syntax.

Period-key access is optional: an item using only an item content-key
alternative needs no access group or period-key wrap. Every item needs a
complete issuer-mediated route as
[core Section 9](spec--core-protocol.md#9-delegation-completeness) requires.
Period-key wraps for which this delivery supplies no matching issuer capability
let a client use period capability it already holds; neither those wraps nor a
configured publisher period-key source promise acquisition of that capability
from this delivery.

If the publisher explicitly promises an issuer-mediated period-key acquisition
route for an item, it MUST supply capability for that route that can produce at least one of
the item's offered period keys: a period key, or a selected profile's supply
from which that period key can be derived.
The item wrap itself remains a period-key wrap. Completeness does not promise
that an issuer will authorize a particular reader.

### 6.2. Wrapping and rollover

For an item selected for period-key access, the publisher wraps the item's
`contentKey` under period keys for its assigned groups and period candidates;
how those period keys were made does not change the wrap. Only reusable period
material is regenerated deterministically. Content keys remain fresh and
independent; content encryption uses its implicit fixed nonce, while each
wrap derives its nonce from its wrap context under
[content protection Section 4.1](spec--content-protection.md#41-wrap-nonce).
Nonce uniqueness applies across the aggregate use of one
`periodKey[t]`, independently generated or reproduced by a canonical
construction, including concurrent publisher nodes that regenerate the same
period key.

Distinct wrap contexts are necessary, but not sufficient, for distinct derived
nonces. A compliant producer keeps the contexts of different wraps apart:

- it draws a fresh random render ID for every render
  ([core Section 4.1](spec--core-protocol.md#41-producer-form));
- it draws an independent content key for every item in a render
  ([content protection Section 3.1](spec--content-protection.md#31-content-key-generation)); and
- it never encrypts different key material under one period key in the same
  render, item, access group, period and selected wrap AAD.

Resending a saved wrap, or repeating the identical encryption, is not a new
context. This profile defines no operation that reseals different key
material in an existing render's context.

The wrap nonce is the first 96 bits of a SHA-256 digest. It is not the
RBG-based IV construction of NIST SP 800-38D, and distinct contexts do not
guarantee distinct nonces. Treat the truncated digest of each distinct context
as an independent uniform 96-bit value, and each render ID as an independent
uniform 128-bit value. Two independently authored wraps under one key can
reuse a nonce in two ways: two distinct contexts give equal truncated digests,
or two renders draw the same render ID and so repeat an identical context. For
`q` wraps under one key, and at most `q` renders among them, a union bound puts
the probability of either event at no more than `q*(q-1)/2^97` for the digest
collision plus `q*(q-1)/2^129` for the repeated context. At `q = 2^32` the sum is about
`1.2 * 10^-10`, below `2^-32`; at one million wraps it is about
`6.3 * 10^-18`. The estimate holds under that model and assumes no producer
chooses names or labels by searching for digest collisions; it is not a
proof of collision freedom.

The counting domain is one set of `periodKey` bytes, whichever generation,
producer or regeneration produced it and wherever it ran. Invocations by every
producer, process lifetime, replacement node and backfill job that use those
bytes combine into one count. Rival bytes at one coordinate from different
generations are different keys with separate counts, and counts never combine
across independently generated period keys, access groups or coordinates
merely because their labels or publisher are related. The aggregate count of
wrap encryptions under one set of `periodKey` bytes MUST NOT exceed `2^32`
across all producers; the estimate above stays below `2^-32` at that count. A
deployment SHOULD choose a materially lower local ceiling from its risk
budget and expected volume; `2^32` is a construction limit, not a render
target.

A deployment MUST establish that bound across every producer and backfill user
of a key before any of them wraps under it; this version mandates no mechanism
for doing so. A producer that cannot establish its remaining budget under a
key MUST stop making new wraps under that key and MUST NOT assume that a
restart, a new node or a backfill reset the count.

"Current and next" is a publisher authoring policy that supports cached pages
across one period boundary. Two is not base grammar, a universal minimum, or an
issuer-response entitlement. A publisher may instead wrap only at the render
period when its selected routes meet the item-completeness requirements. A
later period key from an independent chain window cannot open that wrap just
because it is newer; later recovery still needs matching capability through
an authorized route.

Old cached renders remain unlockable through their own supplied capability
material while the issuer accepts it, grants access under its policy and the
selected route can still return a period key matching an item wrap. Passage of
wall-clock time alone does not invalidate a coordinate; client clocks grant
nothing.

<a id="multiple-access-groups-and-issuers"></a>
## 9. Multiple access groups and issuers

For one generation and period, an access group identifies one shared
client-opening set. A delivered `periodKey[accessGroup,t]` has the same reach
regardless of which issuer returned it: every accepted render carrying a
matching content-key wrap is openable. Omitting that coordinate from one
render's issuer carrier does not create a per-render restriction after the
same reusable key has been obtained elsewhere.

The publisher maintains one access-group vocabulary shared by all of its
issuers. Each issuer may be provisioned zero or more groups, and several
issuers may be provisioned the same group. Issuer provisioning changes which
party can grant a capability; it does not change the client-opening set named
by the group.

<a id="generation-identity-and-migration"></a>
## 10. Generation identity and migration

One `(accessGroup, t)` can have several candidate key bytes across separately
rendered documents during key-material rollover or migration; within one
render the family uses one generation (Section 5.5). A response can carry
several candidate records at one `(accessGroup, t)` in `keys.periodKeys`, and
the client cache can retain rival values learned from several responses. AES-GCM authentication selects the
candidate that matches an article wrap. The article's `dca-data` selects the
publisher, access group and coordinate; the client looks up candidates under
the cache partition of Section 5.5 and uses any admitted candidate as
Section 5.5 states.

Trial order is newest candidate first, where newest means most recently filed;
no generation tag exists to order by. Rollover therefore costs a bounded
rare-path trial, and that bound is the reason base period-key processing adds
no generation field to article candidates.

<a id="capability-lifecycle"></a>
## 11. Capability lifecycle

Two lifecycle actions have different effects:

1. **Retiring acceptance of published issuer material** prevents later grants
   through those retained artifacts. Signing-key and issuer-key retirement are
   the levers the wider DCA protocol defines.
2. **Retiring client-held authority is impossible.** Neither retiring
   acceptance nor deleting publisher key material retracts a capability
   already delivered to a client.

The passage of a period boundary does not expire key bytes. Moving new article
wraps to coordinates outside a client's retained keys limits subsequent access;
retained matching ciphertext remains openable.

<a id="security-considerations"></a>
## 12. Security considerations

[spec--security-model.md](spec--security-model.md) is the mandatory security
boundary for this document.

<a id="pre-delivery-and-revocation"></a>
### 12.1. Pre-delivery and revocation

Delivered keys cannot be revoked (Section 11), and delivery is not a time lock
(Section 5.4).

<a id="key-disclosure"></a>
### 12.2. Key disclosure

Disclosure of one period key exposes the items wrapped under it at its
coordinate; base processing derives no other coordinate's key from it
(Section 5.3). A key supplier's compromise has the reach of its own
construction;
[chain keys Section 24.3](spec-profile--chain-keys.md#publisher-and-issuer-compromise)
states that reach for the chain-key profile.

## 13. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [RFC 5234: Augmented BNF for Syntax Specifications](https://www.rfc-editor.org/info/rfc5234)
- [DCA conformance profiles](spec--profiles.md)
- [DCA data format](spec--data-format.md)
- [DCA content protection](spec--content-protection.md)
- [DCA sealed key envelopes](spec--sealed-key-envelopes.md)
- [DCA core protocol](spec--core-protocol.md)
- [DCA response binding](spec--response-binding.md)
- [DCA security model](spec--security-model.md)

## 14. Informative References

- [DCA specification overview](spec---overview.md)
- [DCA chain keys: construction and delegation](spec-profile--chain-keys.md)
- [DCA period-key design companion](guide--period-keys.md)
