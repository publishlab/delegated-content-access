# DCA period-key capabilities

Status: Public Working Draft

## Abstract

This section is informative.

DCA encrypts every protected content item with a fresh item-specific
`contentKey`. To avoid a new issuer interaction for every article, a publisher
also creates reusable keys associated with an access group and labeled time
period.

This specification defines the exact form of that reusable authority:
`periodKey[t]` opens content-key wraps for exactly one access group and period
coordinate. The publisher supplies exact keys to its issuers, an issuer returns
the exact leaves it authorizes, and a client caches them for later matching
articles.

The optional period-chain profile fixes a canonical construction that derives
the same exact leaves from publisher-held chain state and adds compact
delegation over many coordinates. A family generation that does not use that
construction has no chain ancestry defined by this specification.

<a id="scope-and-status"></a>
## 1. Introduction

This document defines the base exact-period capability, `periodKey[t]`, and the
role duties that the `dca-v1-exact-period`
profile of [spec--profiles.md](spec--profiles.md) compose. [Base exact-period
requirements](#base-exact-period-requirements) are normative.

[spec--period-key-chains.md](spec--period-key-chains.md) specifies the optional
period-chain profile and its canonical construction, which derives exact
leaves from positioned chain state. That document imports the leaf meaning
defined here. This document does not depend on it, and an exact-only issuer or
client need not read it.

Exact `periodKey` is the base capability of the exact-period profile and the
interoperability floor for every role that implements it. A publisher
may make its exact keys by independent random generation or by the canonical
construction fixed by the period-chain profile; issuers and clients
that implement only exact processing open the same article wraps either way.
A canonical construction is the versioned derivation transcript a profile
fixes, not a second profile kind. Its output at a coordinate is an ordinary
exact `periodKey[t]`.

[spec--data-format.md](spec--data-format.md) defines carrier placement and
structural admission of the members this document names.
[guide--period-keys.md](guide--period-keys.md) is the readable companion.
[spec--security-model.md](spec--security-model.md) is the mandatory security
boundary.

Unless a section is explicitly labeled informative or editorial, uppercase
BCP 14 words in it state requirements of this specification. Informative and
editorial sections contain no protocol requirements even when they summarize
normative behavior.

### 1.1. Requirements language

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

<a id="design-goals"></a>
## 2. Design goals

This section is informative.

The design aims to balance the following needs rather than maximize only wire
compactness or implementation simplicity:

1. **One stable content representation.** Compatible issuers and client grant
   forms should open the same cached article markup without duplicate key
   families.
2. **A small downstream implementation.** An issuer or client should be able to
   operate entirely on opaque exact leaves without derivation code.
3. **Fail-closed selection.** Unsupported or malformed optional processing must
   not silently turn into a different exact operation.
4. **Future evolvability.** Family and profile identity must leave room for new
   derivation constructions without allowing ambiguous key interpretation.

<a id="non-goals"></a>
## 3. Non-goals

This section is informative.

This focused design does not define:

- reader identity or entitlement policy;
- general JWT validation and HTTP routing;
- the encryption of article bytes beyond the interface to `contentKey`;
- access-group conjunctions; multiple groups remain alternative opening routes;
- a time lock that prevents use of a key delivered before its labeled period;
  or
- recovery of plaintext or keys already delivered to a client.

<a id="actors-and-trust"></a>
## 4. Actors and trust

This section is informative. Normative role duties are stated in [Base
exact-period requirements](#base-exact-period-requirements);
[spec--period-key-chains.md](spec--period-key-chains.md#period-chain-role-requirements)
adds the duties of a role that implements or selects the applicable
period-chain profile path.

<a id="publisher"></a>
### 4.1. Publisher

The publisher is the root cryptographic authority for a period-key family. It
chooses the access group, period length and alignment, key family, and which
capabilities each issuer receives.

The requirement is expressed in externally verifiable terms. A rendering
component need not contain the key generator itself if a trusted publisher key
service supplies conforming outputs.

<a id="issuer"></a>
### 4.2. Issuer

An issuer opens the publisher material addressed to it, verifies the publisher
and render evidence required by the protocol, makes an access decision, and
returns no more key authority than that decision permits.

An issuer is trusted to delegate within the material intentionally supplied to
it. Exact supply can nevertheless attenuate its technical authority. This can
be a publisher policy property as well as defense in depth against issuer key
theft.

<a id="client"></a>
### 4.3. Client

The client carries the selected issuer request, consumes granted keys, opens
content-key alternatives, and may cache reusable authority for its own logical
client context. A client that implements exact processing only is a valid
exact-period client; the period-chain profile is not required.

A logical client context is one host-selected isolation domain whose members
are mutually trusted to reuse retained capabilities, such as one authenticated
reader session. Mutually untrusted contexts MUST use disjoint cache partitions.
Ending or changing a context makes its retained entries ineligible to a later
context; it does not revoke capability bytes already delivered to the earlier
context.

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

A period-key generation is an immutable cryptographic namespace for the exact
key bytes of one family. Every generation fixes its publisher security
namespace, `accessGroup`, coordinate spellings, its exact-period profile and
exact `periodKey` bytes. A generation made without the period-chain canonical
construction defines no retained derivation input or chain geometry. A
generation that uses that construction additionally fixes its inputs;
[spec--period-key-chains.md](spec--period-key-chains.md#generation-and-window-identity)
lists the period-chain profile's additions, and window identity with them: a
window is a subdivision inside one generation that only the period-chain
profile defines. Rotating the family's key material starts a new generation,
even when `(accessGroup, t)` labels remain the same.

Issuer identity, issuer opening-key rotation, render identity, and response
transport do not change exact leaf bytes.

Base exact processing adds no generation identifier. The authors expect
key-material rollover to be rare, and exact-key authentication already permits
a client to retain and try rival candidate bytes at the same coordinate. A public generation
tag would have to appear in article selection as well as issuer capabilities to
avoid that trial, adding permanent common-case wire surface for a rare event.
Base defines no generation tag; a later version may add one as a routing
optimization.

<a id="contentkey"></a>
### 5.2. `contentKey`

A `contentKey` is fresh for one protected item in one render. A direct grant of
that key is the narrowest DCA opening capability and remains orthogonal to
period-key reuse.

<a id="periodkeyt"></a>
### 5.3. `periodKey[t]`

`periodKey[t]` is the exact capability for one publisher-scoped period-key
generation, access group, and period coordinate `t`. It is exactly 16 octets
under `dca-v1-exact-period`. Base exact processing defines no
derivation between coordinates and no publisher `keyDerivationSecret`. A
profile, such as the period-chain profile of
[spec--period-key-chains.md](spec--period-key-chains.md), may fix a canonical
construction whose output at a coordinate is an ordinary exact
`periodKey[t]`.

It can open every content-key candidate wrapped under that same coordinate. It
does not intrinsically mean "articles published during this period." Its reach
is determined by the ciphertexts the publisher actually wrapped with it.

A period-key grant is never render-bound. Reuse across matching articles and
renders is its sole function. Under the ordinary exact-key route, an issuer
returns only a coordinate presented by the associated request. A selected
broader-grant extension may let one presented range or capability coordinate
authorize several returned exact leaves, but it must define and authenticate
that mapping explicitly; it does not infer authority from client-supplied leaf
names. Render- or item-specific access uses a direct `contentKey` grant.

Delivering an exact leaf does not reveal neighboring leaves.
Exact leaves therefore support:

- one-period authority;
- sparse coordinate sets;
- future-coordinate authority without exposing earlier periods;
- exact-only issuers and clients; and
- publisher-controlled attenuation of issuer authority.

<a id="delivery-is-not-a-time-lock"></a>
### 5.4. Delivery is not a time lock

A future `periodKey[t]` can be issued before period `t`. If matching ciphertext
already exists, the recipient can open it immediately. The publisher or issuer
must schedule access by withholding the capability or ciphertext, or by ensuring
that earlier renders are not wrapped under that coordinate.

<a id="base-exact-period-requirements"></a>
### 5.5. Base exact-period requirements

This subsection is normative for the `dca-v1-exact-period` profile of
[spec--profiles.md](spec--profiles.md). "Base" below names an exact-period
profile's floor: what every publisher, issuer and client implementing that
profile supports before any optional period-chain path. The
`dca-v1-direct-https` baseline of the profile specification does not include it.
A selected profile, such as the period-chain profile of
[spec--period-key-chains.md](spec--period-key-chains.md), adds routes to this
floor and removes nothing from it.

DCA v1 fixes one exact-period width: `dca-v1-exact-period` uses a 16-octet
exact leaf and AES-128-GCM exact wrapping. The per-item `contentKey` is also
16 octets and content encryption uses AES-128-GCM;
[spec--content-protection.md](spec--content-protection.md#4-base-exact-period-content-key-wrapping)
specifies the wrap transcript.

Trusted publisher configuration may choose independent exact generation or the
period-chain profile's canonical construction for a family generation. Route
configuration separately chooses exact supply, chain supply or both under the
applicable profiles. Neither choice selects key width. Every issuer route for a
render MUST supply or derive the same exact leaf bytes for a coordinate and
open the same content-key wrap. A publisher, issuer, or client MUST NOT select
a DCA version, profile or key kind from an observed length.

A publisher, issuer, or client MUST refuse an exact leaf or delivered capability
that is not exactly 16 octets before storing, using or returning it. A publisher,
issuer, or client MUST check visible raw widths and carrier shapes before any
cryptography; a
payload visible only after authenticated opening MUST be checked immediately
afterward, before use, delivery or retention. A publisher, issuer, or client
MUST NOT retry another width, accept a retired width profile or infer a profile
from payload or envelope length.
Rival-candidate trial remains available for different admitted key bytes at one
coordinate, not alternative widths.
[spec--sealed-key-envelopes.md](spec--sealed-key-envelopes.md#2-envelope-model)
states the matching rule for a sealed payload and its carrier.

An exact period coordinate consists of an admitted `accessGroup` and `t` under
one publisher security namespace established by the selected delivery or
publisher-authentication binding. A publisher, issuer, or client MUST NOT infer
the namespace from `accessGroup`. `accessGroup` uses the identifier grammar in
[spec--data-format.md](spec--data-format.md#21-identifiers). The v1 base
spelling of `t` is:

```abnf
exact-t = 6DIGIT "T" 2DIGIT [2DIGIT]
```

`DIGIT` is the ABNF core rule from
[RFC 5234](https://www.rfc-editor.org/info/rfc5234). `YY` names a year from 2000
through 2099; the remaining fields are month, day, hour and optional minute. A
producer derives them from the UTC start of the publisher-selected period and
emits `YYMMDDTHH` when the period length is an integral number of hours unless
the family generation uses a canonical construction that fixes an admitted
alternative spelling; it emits `YYMMDDTHHMM` otherwise. It MUST emit a real
Gregorian date and a time in its ordinary range. The two forms are distinct
coordinates; a publisher, issuer, or client MUST NOT normalize, alias or infer
one from the other. How a producer
aligns its periods to the clock is the producer's choice and is outside the
exact-key contract; a consumer sees only the label.

An exact-period consumer performs only lexical admission of `t`. After admission,
it MUST preserve and compare the ASCII spelling byte for byte and MUST NOT use
its own clock to reinterpret or authorize the coordinate. The grammar excludes
`|`, so an admitted label is safe in the exact BIND and error-coordinate
grammars. The period-chain profile of
[spec--period-key-chains.md](spec--period-key-chains.md#coordinate-labels)
imposes its own fixed eleven-character spelling, calendar and geometry
admission on a family generation that uses its canonical construction. That
period-chain label exception does not change the base labels this paragraph
admits.

For an exact-period consumer, an invalid `t` is one that fails the `exact-t`
ABNF.
Calendar correctness and ordinary time ranges are producer-conformance duties;
base consumers do not parse them. A lexically invalid `t` in
publisher-to-client material supplies no exact candidate and MUST NOT be
relayed. Valid sibling coordinates remain usable. An issuer that receives a
lexically invalid `t` rejects the request as malformed before policy, BIND or
opening-key work; it MUST NOT copy that label into a per-coordinate error key.

A conforming exact-period publisher MUST provide an exact-only supply path that
needs no chain input and MUST use it for every issuer selected for an exact-only
route. A conforming exact-period issuer MUST accept exact `periodKey` input and
provide an exact-result route. A conforming exact-period client MUST accept
exact `periodKey` grants. A selected profile may add another supply or result
route; it does not remove this interoperability floor. The floor applies when
a route is selected as an exact-only route; it does not require a chain-profile
route to duplicate chain supply with exact supply.

Within one generation, a publisher MUST use the same `periodKey[t]`, at the
fixed 16-octet width, for every matching content-key wrap and issuer
envelope at that publisher, `accessGroup` and `t`. It MUST NOT expose the raw
period key in publisher-to-client delivery. A publisher selecting an
exact-only route MUST supply every applicable issuer with the matching exact
capabilities needed to complete that route.

For every distinct `(accessGroup, t)` in one generation, the publisher MUST
generate an independently random exact key or use a selected construction with
equivalent domain separation. Reusing the same key bytes at two coordinates
makes every matching wrap at both coordinates cryptographically openable; a
label, cache partition or client stopping rule cannot narrow that reach.

An issuer MUST treat a successfully opened exact envelope as sourceable
authority only, not entitlement. It MUST use the same admitted coordinate for
policy and BIND, and return an exact capability only when that coordinate was
presented, authorized and successfully opened. The core protocol specifies
request association, partial success and result shape; the envelope
specification specifies BIND and opening; the content-protection specification
specifies exact-key use.

A client MUST admit the selected response binding and reject or ignore every
unrequested result coordinate before retaining key material. It MUST accept
only an exact capability the width refusal above admits, or a protected
representation that opens to a non-extractable key handle with the required
exact-key usage. It routes and files capabilities by publisher namespace,
`accessGroup` and byte-identical `t`. It MAY perform bounded trial of retained
candidates across labels when authenticated content-key unwrap is the match
test; such trial does not widen the inherent reach of the bytes and MUST NOT be
treated as authorization.

An admitted key MUST remain available to the operation that obtained it until
that operation has attempted every applicable content-key candidate. Later
retention and time-based eviction are host policy: eviction causes an ordinary
cache miss and does not revoke or invalidate the capability bytes. An
implementation MUST place a finite bound on retained rival candidates and on
candidate trials; the exact value is deployment-selected. The period-chain
profile likewise treats rival retention and trial counts as finite local policy
in [spec--period-key-chains.md](spec--period-key-chains.md#local-retention-policy).

A reusable cache MUST partition exact capabilities so mutually untrusted
publishers and distinct logical client contexts cannot consume one another's
keys. A capability's exact-period profile belongs to its family generation, so
the client applies the same width check at cache lookup: a stored capability is
a candidate only under its own profile. A profile or deployment MAY partition
further by issuer or response binding. Such additional partitioning changes
lookup eligibility only; it does not narrow the cryptographic reach of a
capability already delivered.

<a id="content-wrapping-and-rollover"></a>
## 6. Content wrapping and rollover

Every protected item has a fresh `contentKey`. The publisher wraps it under one
or more exact leaves associated with the article's access groups and period
candidates. How the publisher made those leaves, by independent generation or by
a selected construction, does not change the wrap.

A publisher regenerates only reusable period material deterministically. Every
render still uses fresh item content keys and a fresh nonce for every AES-GCM wrap.
Nonce uniqueness applies across the aggregate use of one `periodKey[t]`,
independently generated or reproduced by a canonical construction, including
concurrent publisher nodes that regenerate the same leaf. Regeneration,
process restart, node
replacement, and later backfill do not reset that key's cumulative nonce and
invocation accounting. Deterministic leaves never imply deterministic nonces or
content keys.

The counting domain is one set of exact `periodKey` bytes, whichever
generation, producer or regeneration produced it and wherever it ran.
When several producers regenerate the same key bytes, their invocations
combine into one count. Rival bytes at one coordinate from different
generations are different keys with separate counts, and counts never combine
across independently generated period keys, access groups or coordinates merely
because their labels or publisher are related. Under the RBG-based IV
construction that aggregate MUST NOT exceed `2^32` invocations, the absolute
limit stated in
[spec--content-protection.md](spec--content-protection.md#33-content-encryption).
A deployment SHOULD choose a materially lower local ceiling from its risk
budget and expected volume; `2^32` is a construction limit, not a render
target.

A deployment MUST establish that bound across every producer and backfill user
of a key before any of them wraps under it. It MAY partition a conservative
budget statically among producers, coordinate a quota, or use another
mechanism that establishes the same bound. This version mandates no nonce
registry, distributed counter or configuration shape. A producer that cannot
establish its remaining budget under a key MUST stop making new wraps under
that key and MUST NOT assume that a restart, a new node or a backfill reset
the count. Deterministic regeneration of a period key never regenerates a
nonce. A nonce collision is not by itself a DCA authorization grant, and a
redistributing subscriber has cheaper paths than exploiting one. Neither fact
makes reuse cryptographically safe or relaxes the limit.

In the reference implementation, the JS publisher
(`js/v1/core-publisher/Sealer.js`) draws one fresh 12-octet nonce per wrap from
an injected random source and keeps no invocation count. It conforms inside a
deployment that supplies the budget mechanism around it; it does not enforce a
deployment-wide quota.

Multiple access groups are OR alternatives. Possession of any matching group
key can open the item. A future AND policy would require another construction.

"Current and next" is a publisher authoring policy that supports cached pages
across one period boundary. Two is not base grammar, a universal minimum, or an
issuer-response entitlement.

Shared cached article markup cannot vary by client capability. The issuer
response selected later cannot retrospectively change the number of wraps in the
page.

Three coordinate sets remain independent:

1. **Article wrap alternatives** identify the exact leaves that can open this
   item's content key.
2. **Publisher-supplied issuer authority** is the union of capabilities made
   available to that issuer.
3. **Returned client authority** is the reach selected by issuer policy from the
   supplied ceiling.

Implementers must not infer article-overlap policy, issuer supply horizon, or
client grant horizon from one another.

Every protected item advertised as unlockable through period keys must have at
least one complete issuer route whose supplied authority can produce one of
that item's offered exact leaves, subject to issuer authorization. Old cached
renders can remain unlockable through their own supplied capability material
while the issuer accepts that material and grants access under its policy;
passage of wall-clock time alone does not invalidate a coordinate or key.
Client clocks grant nothing, and issuer time affects access only when issuer
policy deliberately uses it.

<a id="compatibility-boundary"></a>
## 7. Compatibility boundary

The exact `periodKey` capability is the adaptation seam for systems that use a
reusable AES key per access group and labeled period.

Exact-role conformance and private construction choice are distinct. A
publisher that produces suitable exact keys conforms to the exact-period
profile. Its exact keys are usable by every recipient that implements the
exact-key contract. An exact-only issuer or client conforms fully to its role.

Semantic correspondence is not native wire, derivation, envelope, or trust
compatibility. Renaming fields cannot convert one authenticated protocol object
into another.

Using the same suitable exact key bytes in both target publications allows
adaptation at the AES-GCM content-key wrap layer. Adaptation still has to
satisfy the target schema, authenticated evidence, sealing, and binding rules; a
gateway issuing a new target publication takes responsibility for its trust and
policy mapping.

<a id="worked-examples"></a>
## 8. Worked examples

This section is informative.

<a id="exact-issuer-and-exact-client"></a>
### 8.1. Exact issuer and exact client

The publisher generates exact keys for two adjacent coordinates, seals both to
issuer A, and wraps an article content key under both coordinates for a chosen
rollover policy. Issuer A returns the earlier one. The client caches it and can
open other matching group/period articles.

No chain processing is involved. Whether the publisher generated the leaves
independently or derived them from a selected construction is invisible to
issuer A and to the client.

<a id="multiple-access-groups-and-issuers"></a>
## 9. Multiple access groups and issuers

Every access group has an independent period-key family.

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

Multiple groups on one content item are OR alternatives. The client tries
matching candidates; one successful unwrap obtains the shared item-specific
content key.

An exact key delivered by one issuer has the same reach whichever issuer
returned it. The base requirements partition a reusable cache by publisher and
logical client context and permit a further issuer partition; that partition
changes lookup eligibility only.

<a id="generation-identity-and-migration"></a>
## 10. Generation identity and migration

One `(accessGroup, t)` can temporarily have several candidate key bytes across
separately rendered documents during key-material rollover or migration. The exact
response shape has one value at `periodKeys[accessGroup][t]` in one response,
while the client cache can retain an array of rival values learned from several
responses. AES-GCM authentication selects the candidate matching a particular
article wrap.

For each article candidate, the article's `dca-data` selects the publisher,
access group and coordinate. The client considers exact candidates under the
base `(publisher, accessGroup, t)` cache boundary. Exact leaves returned by an
issuer remain ordinary base exact candidates whatever supply produced them at
the issuer.

Trial order is newest candidate first, where newest means most recently filed;
no generation tag exists to order by. Rollover therefore costs a bounded
rare-path trial, and that bound is the reason base exact processing adds no
generation field to article candidates.

<a id="capability-lifecycle"></a>
## 11. Capability lifecycle

Two lifecycle actions have different effects:

1. **Retiring acceptance of published issuer material** prevents later grants
   through those retained artifacts. Signing-key and issuer-key retirement are
   the levers the wider DCA protocol defines today; a denylist is issuer
   deployment policy, and a maximum render age needs a format decision first.
2. **Retiring client-held authority is impossible.** Neither retiring
   acceptance nor deleting publisher key material retracts a capability
   already delivered to a client.

The passage of a period boundary does not expire key bytes. Moving new article
wraps to coordinates outside a client's retained keys limits subsequent access;
retained matching ciphertext remains openable.

What a reader can still open depends on both delivered capability reach and
retained published artifacts, including CDN or page-cache retention.

<a id="security-considerations"></a>
## 12. Security considerations

<a id="pre-delivery-and-revocation"></a>
### 12.1. Pre-delivery and revocation

Whoever holds the key bytes can open matching ciphertext. An issuer cannot
revoke keys that a client retained. New content moving to later, ungranted
coordinates limits continued reuse;
the passage of a period boundary itself does not erase prior ciphertext,
plaintext, or key material.

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
- [DCA period-chain construction and delegation](spec--period-key-chains.md)
- [DCA period-key design companion](guide--period-keys.md)
