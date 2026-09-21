# Period keys

Status: Informative Draft

This document explains exact period capability. The normative owner is
[spec--period-keys.md](spec--period-keys.md). The optional chain construction
is explained separately in
[guide--period-key-chains.md](guide--period-key-chains.md).
For a source-and-JSON walkthrough, see
[guide--integration--exact-period.md](guide--integration--exact-period.md).

## The reusable layer

Each protected item has a fresh `contentKey`. A publisher may wrap that key
under an exact `periodKey` so a client that already holds the period key can
open another matching item without contacting an issuer again.

```text
publisher
  creates contentKey for one item and render
  obtains exact periodKey for one accessGroup and t
  wraps contentKey under that periodKey
  seals the periodKey separately to each issuer allowed to offer the route

issuer
  verifies the publisher
  authenticates the reader when required
  or handles the request as explicitly anonymous
  decides which presented coordinate to grant
  opens and returns only the selected exact period key

client
  admits and caches returned capability
  matches accessGroup and t from the item wrap
  opens contentKey, then opens the item
```

An exact period key is capability for one publisher-scoped family and period
coordinate. It may open every retained item wrap made under those same key
bytes. It is not entitlement metadata, an issuer identity, or a one-use token.

## Exact keys are opaque

Base exact-period processing defines no `periodSecret` and no derivation
between periods. The publisher supplies exact key material through an
application-owned source. That source may generate independent values or use
the canonical period-chain construction.

Once supplied, an independently generated leaf and a chain-derived leaf have
the same exact-period meaning. An exact-only issuer or client treats either as
opaque AES key material and cannot continue a chain from it. Construction
origin matters to publisher regeneration and to whether a distinct chain
capability can later be supplied, not to opening an exact wrap.

DCA v1 fixes exact leaves and chain states at 16 octets and exact wrapping at
AES-128-GCM. A family generation or issuer route cannot choose another width.
The per-item content key is also 16 octets; all routes open its one canonical
representation. A different delivered width requires a new specification version.

## Coordinates and alternatives

`accessGroup` selects the reusable family and `t` selects the period within it.
The item carries those coordinates; the client does not calculate authority
from its wall clock. Several group or period candidates on an item are
alternatives. The client tries them and identifies the matching candidate when
an unwrap authenticates.

Clients match `t` exactly as the publisher supplied it; they do not derive
authority from their clock or interpret the label as key expiry. The base
profile treats the label as opaque but admits its ASCII spelling and excludes
delimiter bytes used by BIND and error coordinates. Implementations keep the
admitted spelling byte for byte, so labels never alias. Calendar conformance remains
a producer duty, and a selected period-chain profile separately applies its
stricter calendar and geometry checks.

The publisher may include overlapping period candidates so a cached render
survives a boundary. The number and spacing of candidates are publisher
choices within protocol bounds. Examples using hours do not make hourly
periods mandatory.

A direct content-key route and an exact-period route are also alternatives.
The direct route narrows delivered reach to one item and render. With the exact
route the publisher trades granularity for reuse across matching renders.

## Reach, retention, and revocation

A period label names a coordinate; moving past its wall-clock interval does not
erase delivered key bytes or make retained ciphertext stop authenticating.
Revocation can refuse a later acquisition but cannot claw back key capability
or plaintext already delivered.

A reader can open ciphertext only when it is still available and falls within
the key's coordinate authority. Cache eviction can reduce what remains
conveniently obtainable; it does not narrow the cryptographic capability.

Random 96-bit nonces make repeat wrapping under one exact key safe only within
the selected profile's aggregate invocation bound. The count spans all
publishers, nodes, restarts, replacements, and backfill jobs that reuse those
key bytes. A key supplier must coordinate that bound or rotate the family
generation before it is exhausted.

## Client storage

A reusable-key cache must keep apart who received the capability, which
publisher it belongs to, which period model is in use, and which group and
period it covers. Concretely, the client partitions capability by logical
client, publisher registration or equivalent publisher namespace, profile, access
group, and period coordinate. Independent logical clients do not share a cache.
Exact keys and chain states remain distinct because one can open only its own
coordinate and the other can derive a bounded prefix.

Direct transport may store admitted bytes. A selected client-bound profile may
store a non-extractable handle. Both represent the same exact capability; the
storage representation does not change its reach.

Cache size, eviction time, and persistence are host choices. Before retaining a
capability, a client must admit it and partition its cache by the relevant
profile, so a value from another publisher, profile, or response cannot collide
with the intended key.
