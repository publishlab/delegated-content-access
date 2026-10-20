# Period keys

Status: Informative Draft

This document explains period keys. The normative owner is
[spec-profile--period-keys.md](spec-profile--period-keys.md). The optional chain construction
is explained separately in
[guide--chain-keys.md](guide--chain-keys.md).
For a source-and-JSON walkthrough, see
[guide--integration--period-keys.md](guide--integration--period-keys.md).

## The reusable layer

Each protected item has a fresh `contentKey`. A publisher may wrap that key
under a `periodKey` so a client that already holds the period key can
open another matching item without contacting an issuer again.

The client therefore obtains an item's content key in one of two ways: it
receives the item's content key from an issuer, or it unwraps the item's content
key with a period key. The publisher authors an item content-key alternative, a
period-key-wrap alternative or both for each item. Neither is an endpoint; the
[core protocol](spec--core-protocol.md#24-obtaining-and-delivering-keys) defines
both, together with the separate period-key construction and transport-mode
choices.

The [integration guide's observable path](guide--integration--period-keys.md#the-result-to-preserve)
lists what each role does.

A period key is capability for one publisher-scoped family and period
coordinate. It may open every retained item wrap made under those same key
bytes. It is not entitlement metadata, an issuer identity, or a one-use token.

The design keeps one cached article representation that every compatible
issuer and client can open, and leaves room for new derivation constructions
without ambiguous key interpretation. A rendering component need not contain
the key generator if a trusted publisher key service supplies conforming period
keys. Supplying an issuer only some period keys limits what it can grant, as
publisher policy and as defense against issuer key theft. The period-key
specification states each role's normative duties in its
[base requirements](spec-profile--period-keys.md#base-period-key-requirements); the
[chain-key profile](spec-profile--chain-keys.md#chain-key-role-requirements) adds the
duties of a role that implements or selects it.

## Assign items before sealing

The publisher assigns groups to each item selected for period-key access
before it creates the wraps. Available configured groups are candidates for
assignment; including all of them on every article gives every matching group key access to every
such item. An issuer cannot undo that reach by refusing a later unlock. Fresh
item content keys keep items cryptographically distinct but do not narrow the
reach of a period key used to wrap them.

Items in one article may have different assignments. Several groups on an
item are OR alternatives: one matching group key opens the shared item content
key. An item using only the issuer-returned item content-key path needs no group
or period-key wrap. Every item still needs a complete issuer-mediated opening
route ([core Section 9](spec--core-protocol.md#9-delegation-completeness)); an
item-key alternative can satisfy it, and a wrap alone is not a group-key
acquisition route.

The [assignment requirements](spec-profile--period-keys.md#61-assigning-access-groups-before-sealing)
define these duties. The integration guide's
[business modelling example](guide--integration--period-keys.md#modelling-access-for-a-publisher)
shows a single premium group, occasional readers using the same sealed item,
and distinct A/B/C assignments.

## Period keys are opaque

Base period-key processing defines no `periodSecret` and no derivation
between periods. The publisher supplies period keys through an
application-owned source. That source may generate independent values or use
the canonical chain-key construction.

Once supplied, an independently generated period key and a period key derived
from a chain key have the same meaning. An issuer or client that implements
only period keys treats either as opaque AES key material and cannot continue a
chain from it. Construction origin matters to publisher regeneration and to
whether a distinct chain key can later be supplied, not to opening a
period-key wrap.

Because one period key reveals no other, a publisher can grant one period, a
sparse set or a future coordinate without exposing earlier ones.

DCA v1 fixes period keys and chain keys at 16 octets and period-key wrapping at
AES-128-GCM. A family generation or issuer route cannot choose another width.
The per-item content key is also 16 octets; the issuer-returned content key and
every period-key wrap yield its one canonical representation. A different
delivered width requires a new specification version.

## Coordinates and alternatives

`accessGroup` selects the reusable family and `t` the period within it; the
item carries both. Several group or period candidates on an item are
alternatives: the client tries them and identifies the match when an unwrap
authenticates. Clients match `t` exactly as supplied and preserve admitted
labels byte for byte; they take no authority, expiry or entitlement from their
clock or the label's calendar look. The period-key specification fixes the
spelling as `period-t = 6DIGIT "T" 4DIGIT`; a selected chain-key profile adds
its geometry checks.

The publisher may include overlapping period candidates so a cached render
survives a boundary. The number and spacing of candidates are publisher
choices within protocol bounds. Examples using hours do not make hourly
periods mandatory.

Three coordinate sets stay independent: the article's wrap alternatives name
the period keys that can open this item's content key; the publisher-supplied
issuer authority is the union of capabilities made available to that issuer;
the returned client authority is the reach issuer policy selects from that
supplied ceiling. Do not infer article-overlap policy, issuer supply horizon or
client grant horizon from one another.

An item may also carry both an item content-key alternative and period-key-wrap
alternatives; either one opens it. When the issuer returns the item's content
key, delivered reach narrows to one item and render. With a period-key wrap the
publisher trades granularity for reuse across matching renders.

## Reach, retention, and revocation

A period label names a coordinate; moving past its wall-clock interval does not
erase delivered key bytes or make retained ciphertext stop authenticating.
Revocation can refuse a later acquisition but cannot claw back key capability
or plaintext already delivered.

Starting a new family generation is how a publisher ends the reach of
old-generation material over new-generation content: keys that issuers grant
from retained renders, and old-generation key bytes anyone already holds. An
old-generation wrap in a new render would restore that reach.

A reader can open ciphertext only when it is still available and falls within
the key's coordinate authority. Cache eviction can reduce what remains
conveniently obtainable; it does not narrow the cryptographic capability.

Random 96-bit nonces make repeat wrapping under one period key safe only within
the selected profile's aggregate invocation bound. The count spans all
publishers, nodes, restarts, replacements, and backfill jobs that reuse those
key bytes. A key supplier must coordinate that bound or rotate the family
generation before it is exhausted. `2^32` is a construction limit, not a render
target: choose a local ceiling well below `2^32` from your risk budget and
expected volume. A deployment can partition a conservative budget statically
among producers, coordinate a quota, or use another mechanism that establishes
the same bound; DCA mandates no nonce registry, distributed counter or
configuration shape.

## Client storage

A reusable-key cache must keep apart who received the capability, which
publisher it belongs to, and which group and period it covers. Concretely,
within its logical client context the client files capability by publisher
security namespace, access group and period coordinate. For markup delivery
the trusted context supplies the page-origin namespace; a shared page origin
alone establishes no separation between mutually untrusted publishers. The
client never takes that namespace from the unverified `resourceJWT`.
[Period keys §5.5](spec-profile--period-keys.md#55-base-period-key-requirements)
owns cache admission and publisher and logical-context isolation. Reusable cache
partitions must satisfy those requirements, including any further issuer or
response-binding partition the deployment selects. Independent logical clients
do not share a cache.
Period keys and chain keys remain distinct because one can open only its own
coordinate and the other can derive a bounded prefix.

After a response in direct transport mode, the client may store admitted
bytes. After a response in client-bound transport mode it may store a
non-extractable handle. Both represent the same period-key capability, whether
the publisher generated the key independently or derived it from a chain; the
storage representation does not change its reach.

Base period-key processing carries no generation tag. Key-material rollover is
expected to be rare, and authenticated unwrap already lets a client retain and
try rival candidate bytes at one coordinate. A public tag would have to appear
in article selection as well as in issuer capabilities to avoid that trial,
adding permanent common-case wire surface for a rare event.

Cache size, eviction time, and persistence are host choices.

## Adapting other systems

Role conformance and private construction choice are distinct. A publisher that
produces suitable period keys conforms to the period-key profile, and its
period keys are usable by every recipient that implements the period-key
contract. A period-key-only issuer or client conforms fully to its role; it
needs no chain-key profile.

The `periodKey` capability is the adaptation seam for systems that use a
reusable AES key per access group and labeled period. Semantic correspondence
is not native wire, derivation, envelope or trust compatibility: renaming fields
cannot convert one authenticated protocol object into another. Using the same
suitable period-key bytes in both target publications allows adaptation at the
AES-GCM content-key wrap layer. Adaptation still has to satisfy the target
schema, authenticated evidence, sealing and binding rules; a gateway issuing a
new target publication takes responsibility for its trust and policy mapping.
